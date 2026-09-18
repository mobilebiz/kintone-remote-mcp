import { errors } from "oidc-provider";

import type { SecretCipher } from "./crypto.js";
import { specFor, type ModelSpec } from "./modelSpec.js";
import type { ConsumeResult, Storage, StoredDocument } from "./storage.js";

/**
 * `oidc-provider` の Adapter。
 *
 * ## この層が背負っている責務
 *
 * ライブラリに任せても**自動では手に入らない**ものが2つある。
 *
 * 1. **保存されるトークンが平文にならないこと** (§4.10)
 *    provider はクライアントに渡す値そのもの (`jti`) を文書 ID と payload の
 *    両方に入れて渡してくる。そのまま保存すると、DB が漏れた時点で
 *    Bearer トークンが使える。
 *
 * 2. **同じコード・同じリフレッシュトークンで二重に成功しないこと** (§4.10)
 *    provider の実装は「検索 → 使用済み判定 → consume() → 新トークン保存」と
 *    別々の操作なので、同時に来た2要求が**両方とも未使用を読む**。
 *    `consume` を「未使用を条件にした更新」にして、そこで初めて勝敗を決める。
 *
 * ## 競合したときの振る舞い
 *
 * ⚠ **例外を投げるだけでは足りない。** provider の失効処理は
 * 「取得済みオブジェクトの `consumed` が真」のときにしか走らないため、
 * `consume()` が投げても**先行要求のトークンは生き残る**。
 * → 競合を検知したら `revokeConnection` で**接続 grant の失効を先に確定させ**、
 *   そのうえで例外を投げる。順序を逆にすると失効が巻き戻る。
 *
 * ⚠ **provider 自身が検知する通常の再使用は `consume()` を通らない。**
 * 逐次の再使用は provider が `consumed` を見て処理し、`revokeByGrantId()` を呼ぶ。
 * そちらの経路も失効につなぐ（外部レビューで取りこぼしを指摘された）。
 */

export type AdapterDependencies = {
  storage: Storage;
  cipher: SecretCipher;
  /**
   * 接続を失効させる。
   *
   * **3つの経路すべてからここへ集める** (§4.10):
   *  - こちらが検知した競合（`consume` の敗者）
   *  - **provider 自身が検知した通常の再使用**（`revokeByGrantId` を呼んでくる）
   *  - ユーザーによる切断
   *
   * 競合検知の経路では、**戻るまで待ってから例外を投げる**
   * （失効を確定させてから拒否する）。
   */
  revokeByGrantId?: (grantId: string) => Promise<void>;
  /** 失効済みの接続かどうか。**保存の前にも、利用のたびにも**確かめる */
  isConnectionRevoked?: (accountId: string) => Promise<boolean>;
  /** テスト用の時計。エポック秒 */
  now?: () => number;
};

/**
 * 再使用を検知したときに投げる。
 *
 * **`errors.InvalidGrant` を継承する。** 普通の `Error` だと provider は
 * `server_error`(500) として扱い、クライアントは「サーバーが壊れた」と読む。
 * 実際には認可が無効になったので `invalid_grant` でなければならない。
 */
export class TokenReuseError extends errors.InvalidGrant {
  constructor(readonly model: string) {
    super("使用済みのトークンが再び使われました");
  }
}

const epochSeconds = (): number => Math.floor(Date.now() / 1000);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

/**
 * AAD。暗号文を別モデル・別レコードへ移し替える細工を検出する。
 *
 * キーを含めるので、**復号にはその文書のキーが要る**。
 * 二次索引から引いたときも組み立てられるよう、
 * 文書は自分のキーを持っている（`StoredDocument.key`）。
 */
const aadFor = (model: string, key: string): string => `${model}:${key}`;

/** 秘密フィールドを封じる（保存用のコピーを返す。元は壊さない） */
const sealSecrets = (
  payload: Record<string, unknown>,
  spec: ModelSpec,
  cipher: SecretCipher,
  aad: string,
): Record<string, unknown> => {
  const result: Record<string, unknown> = { ...payload };

  for (const field of spec.secretFields) {
    if (field.kind === "top") {
      const value = result[field.field];
      if (typeof value === "string") result[field.field] = cipher.seal(value, aad);
    } else {
      const parent = result[field.parent];
      if (isRecord(parent)) {
        const value = parent[field.field];
        if (typeof value === "string") {
          result[field.parent] = { ...parent, [field.field]: cipher.seal(value, aad) };
        }
      }
    }
  }

  // find(id) から復元できるものは、そもそも保存しない。
  if (spec.restoreJtiFromKey) delete result.jti;

  return result;
};

/** 秘密フィールドを開ける。復号できないものは undefined を返して「見つからない」扱いにする */
const openSecrets = (
  payload: Record<string, unknown>,
  spec: ModelSpec,
  cipher: SecretCipher,
  aad: string,
): Record<string, unknown> | undefined => {
  const result: Record<string, unknown> = { ...payload };

  try {
    for (const field of spec.secretFields) {
      if (field.kind === "top") {
        const value = result[field.field];
        if (typeof value === "string") result[field.field] = cipher.open(value, aad);
      } else {
        const parent = result[field.parent];
        if (isRecord(parent)) {
          const value = parent[field.field];
          if (typeof value === "string") {
            result[field.parent] = { ...parent, [field.field]: cipher.open(value, aad) };
          }
        }
      }
    }
  } catch {
    // 改ざん・鍵の入れ替え・別レコードからの移し替え。
    // provider には「見つからなかった」として返す（理由を外に出さない）。
    return undefined;
  }

  return result;
};

const readString = (payload: Record<string, unknown>, key: string): string | undefined => {
  const value = payload[key];
  return typeof value === "string" ? value : undefined;
};

/** `oidc-provider` が要求する Adapter の形 */
export type OidcAdapter = {
  upsert(id: string, payload: Record<string, unknown>, expiresIn: number): Promise<void>;
  find(id: string): Promise<Record<string, unknown> | undefined>;
  findByUserCode(userCode: string): Promise<Record<string, unknown> | undefined>;
  findByUid(uid: string): Promise<Record<string, unknown> | undefined>;
  consume(id: string): Promise<void>;
  destroy(id: string): Promise<void>;
  revokeByGrantId(grantId: string): Promise<void>;
};

export type AdapterFactory = (modelName: string) => OidcAdapter;

export const createAdapterFactory = (deps: AdapterDependencies): AdapterFactory => {
  const { storage, cipher } = deps;
  const now = deps.now ?? epochSeconds;

  /**
   * grantId から失効へ橋渡しする。
   *
   * ⚠ **Grant 文書から `accountId` を引かない。**
   * provider の `helpers/revoke.js` は各モデルの `revokeByGrantId()` と
   * Grant 文書の削除を `Promise.all` で並行実行するため、
   * Grant が先に消えると主体を引けず、**失効が黙って飛ぶ**（レビューで再現された）。
   * 対応は Grant とは独立したレコードで持つ（`revocation.ts`）。
   */
  const revokeConnectionForGrant = async (grantId: string | undefined): Promise<void> => {
    if (!grantId || !deps.revokeByGrantId) return;
    await deps.revokeByGrantId(grantId);
  };

  return (modelName: string): OidcAdapter => {
    const spec = specFor(modelName);

    /**
     * 保存済みの文書を provider が扱える payload に戻す。
     *
     * @param restoreJti `find(id)` で引いたときの `id`。索引経由なら undefined
     */
    const rehydrate = (
      document: StoredDocument,
      restoreJti: string | undefined,
    ): Record<string, unknown> | undefined => {
      const opened = openSecrets(
        document.payload,
        spec,
        cipher,
        aadFor(modelName, document.key),
      );
      if (!opened) return undefined;

      // find(id) で引いた場合は、引数そのものが jti。
      // これを戻さないと provider が別の jti を生成してしまう
      // （base_model の instantiate は payload の jti をそのまま使う）。
      if (spec.restoreJtiFromKey) {
        if (restoreJti === undefined) {
          // restoreJtiFromKey のモデルを索引から引くことはない。
          // 起きたら規則の取り違えなので、黙って壊れた値を返さない。
          return undefined;
        }
        opened.jti = restoreJti;
      }

      // consume の記録は provider 側のプロパティ名に合わせる。
      if (document.consumedAt !== undefined) opened.consumed = document.consumedAt;

      return opened;
    };

    return {
      async upsert(id, payload, expiresIn) {
        // 失効した接続に対して新しいトークンを保存しない。
        // 失効処理と発行が競合したとき、失効の後にトークンが作られると
        // 接続が実質的に復活する。
        const accountId = readString(payload, "accountId");
        if (accountId !== undefined && deps.isConnectionRevoked) {
          if (await deps.isConnectionRevoked(accountId)) {
            throw new errors.InvalidGrant("この接続は失効しています");
          }
        }

        const key = cipher.hash(id);
        const aad = aadFor(modelName, key);

        const uid = readString(payload, "uid");
        const userCode = readString(payload, "userCode");

        await storage.upsert(modelName, key, {
          payload: sealSecrets(payload, spec, cipher, aad),
          expiresAt: expiresIn ? now() + expiresIn : undefined,
          grantId: readString(payload, "grantId"),
          uidHash: spec.indexes.includes("uid") && uid !== undefined ? cipher.hash(uid) : undefined,
          userCodeHash:
            spec.indexes.includes("userCode") && userCode !== undefined
              ? cipher.hash(userCode)
              : undefined,
        });
      },

      async find(id) {
        const document = await storage.find(modelName, cipher.hash(id));
        if (!document) return undefined;

        const rehydrated = rehydrate(document, id);
        if (!rehydrated) return undefined;

        // ⚠ **保存時の確認だけでは足りない。**
        // 「失効を確認した直後に切断され、そのあと保存される」順序があるため、
        // 保存の可否だけで守ろうとすると隙間が残る。
        // **使うときにも見る**ことで、その隙間を通ったトークンも無効になる。
        const accountId = readString(rehydrated, "accountId");
        if (accountId !== undefined && deps.isConnectionRevoked) {
          if (await deps.isConnectionRevoked(accountId)) return undefined;
        }

        return rehydrated;
      },

      async findByUid(uid) {
        // 索引から引くと元の jti が手元に無い。
        // Session はそのために jti を暗号化して保存してある (modelSpec)。
        // 復号に必要な AAD は document.key から組み立てる。
        const document = await storage.findByIndex(modelName, "uidHash", cipher.hash(uid));
        if (!document) return undefined;
        return rehydrate(document, undefined);
      },

      async findByUserCode(userCode) {
        const document = await storage.findByIndex(
          modelName,
          "userCodeHash",
          cipher.hash(userCode),
        );
        if (!document) return undefined;
        return rehydrate(document, undefined);
      },

      async consume(id) {
        const key = cipher.hash(id);
        const result: ConsumeResult = await storage.consume(modelName, key, now());

        if (result === "consumed") return;

        // ⚠ ここで即座に投げない。provider は「取得済みオブジェクトの consumed が真」
        // のときにしか系列を失効させないので、競合で負けた側が投げるだけでは
        // 先行要求のトークンが生き残る。失効を先に確定させてから拒否する。
        const document =
          result === "already-consumed" ? await storage.find(modelName, key) : undefined;
        await revokeConnectionForGrant(document?.grantId);
        throw new TokenReuseError(modelName);
      },

      async destroy(id) {
        await storage.destroy(modelName, cipher.hash(id));
      },

      async revokeByGrantId(grantId) {
        // provider は自分で再使用を検知したときもここを呼ぶ。
        // その経路を取りこぼすと、**接続 grant（kintone のトークン）が生き残る**。
        // 先に失効を確定させてから、provider のレコードを消す。
        await revokeConnectionForGrant(grantId);
        await storage.revokeByGrantId(grantId);
      },
    };
  };
};

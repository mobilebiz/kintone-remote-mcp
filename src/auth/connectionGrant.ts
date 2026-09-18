import type { SecretCipher } from "./crypto.js";
import type { Storage } from "./storage.js";
import type { CybozuTokens } from "./cybozuOAuth.js";

/**
 * 接続 grant — kintone のトークンの置き場。
 *
 * provider が管理するトークン（Claude に渡すもの）とは**別物**で、寿命も違う。
 * ユーザーが切断するまで生きる (§4.9)。
 *
 * - **kintone のトークンは AEAD で暗号化して保存する。** AAD に主体を入れ、
 *   別レコードへの移し替えを検出する
 * - **失効フラグは永続的に持つ。** 保存時にも利用時にも照合し、
 *   「失効処理の後にレコードが作られる」経路を塞ぐ (§4.10)
 * - **cybozu のリフレッシュ応答には新しいリフレッシュトークンが含まれない**ので、
 *   アクセストークンだけを差し替える口を分けてある
 */

const MODEL = "ConnectionGrant";

/**
 * 期限の記録が無い接続を、いつまで生かすか（エポック秒）。
 *
 * ⚠ **絶対期限を足しただけでは、既存の接続に届かない。**
 * 期限が付くのは、これ以降に作られた接続だけ。
 * 記録の無いレコードは `expiresAt` を持たないので、
 * **401日後でも資格情報を復号でき、失効もしなかった**
 * （外部レビューで再現された）。数は少なくても、
 * 「使われなくなった接続を永遠に残さない」が成立していないことに変わりはない。
 *
 * → **移行の時点で作られたものとみなす。** いつ作られたかは記録が無いので
 * 分からないが、移行より前であることだけは確かなので、上限としては正しい。
 * 値は 2026-09-17（移行日）+ 400日。
 *
 * ⚠ **`LEGACY_CONSENTED_TOOLS` と同じで、これは過去の記録。**
 * 新しい接続はこれを使わない。動かす理由はもう無い。
 */
export const LEGACY_CONNECTION_EXPIRES_AT = Math.floor(Date.UTC(2027, 9, 22) / 1000);

/** この接続がいつ切れるか。記録が無ければ移行時点で作られたものとみなす */
const deadlineOf = (document: { expiresAt: number | undefined }): number =>
  document.expiresAt ?? LEGACY_CONNECTION_EXPIRES_AT;

export type ConnectionGrant = {
  /** 接続ごとの内部主体。provider の accountId と同じ値 */
  accountId: string;
  accessToken: string;
  refreshToken: string;
  /** アクセストークンの失効時刻（エポック秒） */
  expiresAt: number;
  scope: string;
};

/**
 * 接続の状態。失効確認と同意の確認を**1回の読み出し**で済ませる。
 *
 * ⚠ 同意の情報を `load()` には載せない。**読む場所を1つにする。**
 * 両方に持たせると、片方だけ壊れても気づけない（実際、載せたが誰も読まず、
 * 壊しても全件通る死んだコードになっていた）。
 */
export type ConnectionState = {
  revoked: boolean;
  /**
   * 同意した時点で公開されていたツール。
   *
   * ⚠ **実行時の設定をそのまま使ってはいけない。**
   * `ALLOW_DESTRUCTIVE` を後から有効にすると、
   * **削除に同意していない既存の接続に削除権限が付く**
   * （外部レビューで再現された）。kintone の書き込みスコープは削除も許すので、
   * 上流のスコープ検証でも止まらない。
   *
   * 実行時は**現在の設定との積**で公開する。
   * 記録が無い接続（機能を入れる前のもの）は `undefined`。
   */
  consentedTools: string[] | undefined;
  /**
   * 同意した時点の対象アプリ。
   *
   * ⚠ **ツール名だけでは境界の変更を止められない。**
   * 許可リストを変えてもツール名は同じなので、積では止まらない。
   * 「対象アプリ: 1」で同意した接続が、設定を `2` に変えた途端に
   * アプリ2へ届いていた（外部レビューで再現された）。
   */
  consentedAppIds: string | undefined;
  /**
   * 接続の絶対期限（エポック秒）。
   *
   * ⚠ **provider の Grant に期限を付けただけでは足りない。**
   * Grant が切れても、こちらに保管した **cybozu のリフレッシュトークンは
   * 復号できるまま**で、接続も失効しなかった（外部レビューで再現された）。
   * 「使われなくなった接続を永遠に残さない」目的を果たせていない。
   */
  expiresAt: number | undefined;
  /**
   * 同意した連携用ユーザー。**同意画面に出したものを、そのまま記録する。**
   *
   * ⚠ **これが無いと、設定を変えるだけで既存の接続の権限が広がる。**
   * 連携機能を無効のまま認可したトークンが、有効化した途端に
   * スペース操作を実行できてしまう（外部レビューで再現された）。
   * 主体が入れ替わることに同意していないので、これは同意の偽装になる。
   *
   * 記録が無い接続（機能を入れる前に作られたもの）は、
   * **同意していない**ものとして扱う。使うには繋ぎ直しが要る。
   */
  integrationConsent: { username: string } | undefined;
};

export class GrantRevokedError extends Error {
  constructor() {
    super("この接続はすでに失効しています");
    this.name = "GrantRevokedError";
  }
}

export type ConnectionGrantStoreOptions = {
  storage: Storage;
  cipher: SecretCipher;
  now?: () => number;
};

const aadFor = (accountId: string): string => `${MODEL}:${accountId}`;

export const createConnectionGrantStore = (options: ConnectionGrantStoreOptions) => {
  const { storage, cipher } = options;
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));

  const keyFor = (accountId: string): string => cipher.hash(accountId);

  return {
    /**
     * 新しい接続を保存する。
     *
     * ⚠ **生存確認と保存を同一の不可分操作で行う。**
     * 以前は「確認 → 保存」を別々にしていたため、
     * `create()` と `revoke()` を同時に走らせると**失効が取り消されて
     * 接続が復活した**（外部レビューで再現された）。
     */
    async create(
      accountId: string,
      tokens: CybozuTokens,
      /** 同意画面に出した連携用ユーザー。出していなければ渡さない */
      consent: {
        toolNames?: string[] | undefined;
        integrationUser?: { username: string } | undefined;
        allowedAppIds?: string | undefined;
        /** 接続の絶対期限（エポック秒） */
        expiresAt?: number | undefined;
      } = {},
    ): Promise<void> {
      const aad = aadFor(accountId);
      const result = await storage.update(MODEL, keyFor(accountId), (current) => {
        // 失効済みの状態は、後続の保存で元に戻せない。
        if (current?.payload.revoked === true) return "abort";
        return {
          payload: {
            accountId,
            accessToken: cipher.seal(tokens.accessToken, aad),
            refreshToken: cipher.seal(tokens.refreshToken, aad),
            expiresAt: tokens.expiresAt,
            scope: tokens.scope,
            revoked: false,
            // ⚠ 同意画面に出したものだけを記録する。設定を後から読み直さない
            ...(consent.integrationUser
              ? { integrationUsername: consent.integrationUser.username }
              : {}),
            ...(consent.toolNames ? { consentedTools: consent.toolNames } : {}),
            ...(consent.allowedAppIds !== undefined
              ? { consentedAppIds: consent.allowedAppIds }
              : {}),
          },
          /**
           * ⚠ **絶対期限を付ける。**
           * 付けないと、使われなくなった接続の資格情報が永遠に残り、
           * 失効の手立てが切断だけになる。
           * TTL で自動的に消えるので、掃除を別に作らなくてよい。
           */
          expiresAt: consent.expiresAt,
          grantId: undefined,
          uidHash: undefined,
          userCodeHash: undefined,
        };
      });

      if (result === "aborted") throw new GrantRevokedError();
    },

    /** 読み出す。失効済み・復号不能なら undefined（= 接続が無い） */
    async load(accountId: string): Promise<ConnectionGrant | undefined> {
      const document = await storage.find(MODEL, keyFor(accountId));
      if (!document) return undefined;
      if (document.payload.revoked === true) return undefined;
      // ⚠ **TTL による削除は掃除であって、認可の判定ではない** (§4.9)。
      // 消えていなくても、使うときに自分で期限を見る
      if (deadlineOf(document) <= now()) return undefined;

      const aad = aadFor(accountId);
      const sealedAccess = document.payload.accessToken;
      const sealedRefresh = document.payload.refreshToken;
      const expiresAt = document.payload.expiresAt;
      const scope = document.payload.scope;

      if (
        typeof sealedAccess !== "string" ||
        typeof sealedRefresh !== "string" ||
        typeof expiresAt !== "number" ||
        typeof scope !== "string"
      ) {
        return undefined;
      }

      try {
        return {
          accountId,
          accessToken: cipher.open(sealedAccess, aad),
          refreshToken: cipher.open(sealedRefresh, aad),
          expiresAt,
          scope,
        };
      } catch {
        // 改ざん・別レコードからの移し替え。理由は外に出さない。
        return undefined;
      }
    },

    /**
     * アクセストークンだけを差し替える。
     *
     * **リフレッシュトークンは触らない。** cybozu のリフレッシュ応答には
     * 新しいリフレッシュトークンが含まれないので、既存の値を保持し続ける (§4.9)。
     */
    async updateAccessToken(
      accountId: string,
      accessToken: string,
      expiresAt: number,
      scope: string,
    ): Promise<void> {
      // ⚠ ここも「読み取り → 更新」を分けない。
      // 分けると「旧レコード取得 → revoke 完了 → 更新保存」で失効が消える。
      const result = await storage.update(MODEL, keyFor(accountId), (current) => {
        if (!current || current.payload.revoked === true) return "abort";
        return {
          payload: {
            ...current.payload,
            accessToken: cipher.seal(accessToken, aadFor(accountId)),
            expiresAt,
            scope,
          },
          expiresAt: current.expiresAt,
          grantId: current.grantId,
          uidHash: current.uidHash,
          userCodeHash: current.userCodeHash,
        };
      });

      if (result === "aborted") throw new GrantRevokedError();
    },

    /**
     * 失効させる。
     *
     * **レコードを消さずに失効フラグを立てる。** 消してしまうと、
     * 競合した保存が「新しい接続」として通ってしまう。
     */
    async revoke(accountId: string): Promise<void> {
      // 失効は不可分に立てる。立てた後は create / updateAccessToken が abort する。
      await storage.update(MODEL, keyFor(accountId), (current) => ({
        // トークンは残さない。失効の印だけを残す。
        // ⚠ ただし **providerGrantId は残す**。消すと、切断が途中で失敗したときに
        // 再試行しても対象の Grant を見失い、provider 側のトークンが残り続ける。
        payload: {
          accountId,
          revoked: true,
          revokedAt: now(),
          ...(current?.payload.providerGrantId !== undefined
            ? { providerGrantId: current.payload.providerGrantId }
            : {}),
        },
        expiresAt: undefined,
        grantId: current?.grantId,
        uidHash: undefined,
        userCodeHash: undefined,
      }));
    },

    /**
     * provider の Grant を接続に結び付ける。
     *
     * 切断のとき、**接続 grant（kintone のトークン）と provider の Grant の
     * 両方を失効させる**必要がある (§4.10)。片方だけだと、
     * kintone のトークンは消えたのに Claude のトークンが生き続ける、
     * あるいはその逆になる。
     */
    async attachProviderGrant(accountId: string, grantId: string): Promise<void> {
      const result = await storage.update(MODEL, keyFor(accountId), (current) => {
        if (!current || current.payload.revoked === true) return "abort";
        return {
          payload: { ...current.payload, providerGrantId: grantId },
          expiresAt: current.expiresAt,
          // ⚠ 保存層の `grantId` には入れない。
          // `revokeByGrantId` は grantId が一致するレコードを**削除**するので、
          // ここに入れると**接続 grant が失効フラグごと消える**。
          // 消えると `isRevoked` が false に戻り、失効が無かったことになる。
          grantId: current.grantId,
          uidHash: current.uidHash,
          userCodeHash: current.userCodeHash,
        };
      });
      if (result === "aborted") throw new GrantRevokedError();
    },

    /** 接続に結び付いた provider の Grant ID */
    async providerGrantId(accountId: string): Promise<string | undefined> {
      const document = await storage.find(MODEL, keyFor(accountId));
      const grantId = document?.payload.providerGrantId;
      return typeof grantId === "string" ? grantId : undefined;
    },

    /** 失効しているか */
    /**
     * 接続の状態を**1回の読み出しで**返す。
     *
     * 失効確認と同意の確認を別々に読むと、要求ごとに保存層へ2回行くことになる。
     */
    async inspect(accountId: string): Promise<ConnectionState> {
      const document = await storage.find(MODEL, keyFor(accountId));
      // ⚠ **`isRevoked` と同じ意味にする。** 文書が無いことは「失効」ではない
      // （接続が無いので、この先のトークン読み出しで落ちる）。
      // ここで意味を変えると、応答の理由が入れ替わる
      if (!document) {
        return {
          revoked: false,
          integrationConsent: undefined,
          consentedTools: undefined,
          consentedAppIds: undefined,
          expiresAt: undefined,
        };
      }

      // 期限切れは失効と同じ扱い。消えるのを待たない
      const expired = deadlineOf(document) <= now();

      const username = document.payload.integrationUsername;
      const tools = document.payload.consentedTools;
      return {
        revoked: document.payload.revoked === true || expired,
        expiresAt: deadlineOf(document),
        integrationConsent: typeof username === "string" ? { username } : undefined,
        // 読めない形なら「何にも同意していない」扱い。広げる方向に倒さない
        consentedTools: Array.isArray(tools)
          ? tools.filter((name): name is string => typeof name === "string")
          : undefined,
        consentedAppIds:
          typeof document.payload.consentedAppIds === "string"
            ? document.payload.consentedAppIds
            : undefined,
      };
    },

    async isRevoked(accountId: string): Promise<boolean> {
      const document = await storage.find(MODEL, keyFor(accountId));
      return document?.payload.revoked === true;
    },
  };
};

export type ConnectionGrantStore = ReturnType<typeof createConnectionGrantStore>;

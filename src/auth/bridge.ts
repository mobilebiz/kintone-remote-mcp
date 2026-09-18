import { randomBytes } from "node:crypto";

import type { SecretCipher } from "./crypto.js";
import { safeEqual } from "./crypto.js";
import type { Storage } from "./storage.js";

/**
 * 二段の認可を結ぶブリッジ。
 *
 * ## なぜ独自の state が要るか
 *
 * PKCE が守るのは **Claude ↔ こちら**の区間だけで、**こちら ↔ cybozu** の区間は守らない。
 * cybozu からの callback が「**このブラウザで、この接続に同意した結果**」であることは、
 * 別の仕組みで保証する必要がある (§4.5)。
 *
 * - Claude から来た `state` は provider が扱う。こちらは触らない
 * - cybozu へ送る `state` は**別に生成した乱数**
 * - その state を、**短命なブラウザ Cookie** と**承認済みの認可トランザクション**に束縛する
 *
 * **「DB にその state が存在する」だけでは不足。** それでは別ブラウザからの
 * 持ち込みを通してしまう。callback では **一致・期限内・未使用** の3つを確かめる。
 */

/** 保存層で使うモデル名 */
const MODEL = "AuthorizationTransaction";
/**
 * 同意画面に**出した内容**を置く場所。
 *
 * ⚠ **表示と承認を別々の設定から作ってはいけない。**
 * 画面を出したインスタンスと、承認を受けるインスタンスは別でありうる
 * （デプロイをまたぐ、複数インスタンス）。承認側で作り直すと、
 * **出していない内容に同意したことになる**（外部レビューで再現された）。
 */
const CONSENT_MODEL = "ConsentSnapshot";

export type BridgeTransaction = {
  /** provider の interaction UID。callback 後にここへ戻る */
  interactionUid: string;
  /** 接続ごとの内部主体。kintone のユーザー名ではない (§4.10) */
  accountId: string;
  /**
   * **同意画面に出した内容**。認可の途中で固定する。
   *
   * ⚠ **callback 側の設定から作り直してはいけない。**
   * 同意した瞬間と cybozu から戻る瞬間の間に設定が変わることがあり、
   * 複数インスタンスなら**別の設定のインスタンスが callback を受ける**。
   * そのまま作り直すと、**画面に出していない内容に同意したことになる**
   * （外部レビューで再現された）。
   */
  consent: ConsentSnapshot;
};

/**
 * 同意の内容。
 *
 * ⚠ **連携ユーザーの名前だけでは足りない。**
 * 名前は「誰として実行するか」しか表さず、
 * 「参照に同意した」のか「削除に同意した」のかを区別できない。
 * 設定で削除を後から有効にすると、**同意していない削除が既存の接続に付く**
 * （外部レビューで再現された）。
 *
 * **公開したツールの名前をそのまま残す。** 判断に使ったものと同じ形なので、
 * 後から「何に同意したか」を言い換える必要がない。
 */
export type ConsentSnapshot = {
  /** 同意画面に出した時点で公開されていたツール */
  toolNames: string[];
  /** 同意画面に出した連携用ユーザー。出していなければ undefined */
  integrationUser: { username: string } | undefined;
  /**
   * 同意画面に出した対象アプリ（`ALLOWED_APP_IDS` の正規化済みの値）。
   *
   * ⚠ **ツール名だけでは足りない。** 許可リストを変えても
   * ツール名は同じなので、積では止まらない。
   * 「対象アプリ: 1」で同意した接続が、設定を `2` に変えた途端に
   * アプリ2へ届いていた（外部レビューで再現された）。
   */
  allowedAppIds: string | undefined;
};

/** ブラウザに渡す値。Cookie に入れる */
export type BridgeSecret = string;

export type StartedTransaction = {
  /** cybozu へ送る state */
  state: string;
  /** ブラウザ Cookie に入れる値。**これが無い callback は通さない** */
  browserSecret: BridgeSecret;
};

export type ConsumeFailure =
  | "unknown-state"
  | "already-used"
  | "expired"
  | "browser-mismatch";

export type ConsumeOutcome =
  | { ok: true; transaction: BridgeTransaction }
  | { ok: false; reason: ConsumeFailure };

export type BridgeOptions = {
  storage: Storage;
  cipher: SecretCipher;
  /** トランザクションの寿命（秒）。cybozu のログインに要する時間ぶんだけ */
  ttlSeconds?: number;
  now?: () => number;
};

const DEFAULT_TTL = 10 * 60;

export const createBridge = (options: BridgeOptions) => {
  const { storage, cipher } = options;
  const ttl = options.ttlSeconds ?? DEFAULT_TTL;
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));

  return {
    /** 同意が済んだ時点で呼ぶ。cybozu へ飛ばす直前 */
    async start(transaction: BridgeTransaction): Promise<StartedTransaction> {
      const state = randomBytes(32).toString("base64url");
      const browserSecret = randomBytes(32).toString("base64url");
      const key = cipher.hash(state);

      await storage.upsert(MODEL, key, {
        payload: {
          interactionUid: transaction.interactionUid,
          accountId: transaction.accountId,
          // 同意した内容をここで固定する。callback 側で作り直さない
          consentToolNames: transaction.consent.toolNames,
          ...(transaction.consent.integrationUser
            ? { consentIntegrationUsername: transaction.consent.integrationUser.username }
            : {}),
          ...(transaction.consent.allowedAppIds !== undefined
            ? { consentAllowedAppIds: transaction.consent.allowedAppIds }
            : {}),
          // ブラウザ Cookie の値は、保存側ではハッシュで持つ。
          // 保存物が漏れても Cookie を偽造できないようにする。
          browserSecretHash: cipher.hash(browserSecret),
        },
        expiresAt: now() + ttl,
        grantId: undefined,
        uidHash: undefined,
        userCodeHash: undefined,
      });

      return { state, browserSecret };
    },

    /**
     * 同意画面に出した内容を覚える。**画面を出すときに呼ぶ。**
     *
     * CSRF トークンに束縛するので、同じ画面から出た承認だけが取り出せる。
     */
    async rememberConsent(
      interactionUid: string,
      csrfToken: string,
      consent: ConsentSnapshot,
    ): Promise<void> {
      await storage.upsert(CONSENT_MODEL, cipher.hash(`${interactionUid}:${csrfToken}`), {
        payload: {
          toolNames: consent.toolNames,
          ...(consent.integrationUser
            ? { integrationUsername: consent.integrationUser.username }
            : {}),
          ...(consent.allowedAppIds !== undefined
            ? { allowedAppIds: consent.allowedAppIds }
            : {}),
        },
        expiresAt: now() + ttl,
        grantId: undefined,
        uidHash: undefined,
        userCodeHash: undefined,
      });
    },

    /**
     * 覚えておいた同意内容を取り出す。**承認を受けたときに呼ぶ。**
     *
     * ⚠ **無ければ承認しない。** 画面を出していない承認になるため。
     *
     * ## 使い捨てにしていない
     *
     * `consume` を使えば1回限りにできる。外部レビューでも
     * 「同じ POST を並行して送ると、どちらも通って認可トランザクションが2件できる」
     * と指摘された。**そうしていない。**
     *
     * 増えるのは**同じ内容の**トランザクションで、
     * 最後まで進めるのは1つだけ（完了レコードの consume が不可分）。
     * 残りは使われないまま期限で消える。**権限は広がらない。**
     *
     * 一方、1回限りにすると**スマホでの二度押しが必ず失敗する**。
     * 1回目のリダイレクトが飛んでいる最中に2回目が届くと、
     * 「最初からやり直してください」になる。
     * 実害の無い重複を防ぐために、実際に起きる操作を壊すことはしない。
     */
    async takeConsent(
      interactionUid: string,
      csrfToken: string,
    ): Promise<ConsentSnapshot | undefined> {
      const key = cipher.hash(`${interactionUid}:${csrfToken}`);
      const document = await storage.find(CONSENT_MODEL, key);
      if (!document) return undefined;
      if (document.expiresAt !== undefined && document.expiresAt <= now()) return undefined;

      const toolNames = document.payload.toolNames;
      const integrationUsername = document.payload.integrationUsername;
      const allowedAppIds = document.payload.allowedAppIds;

      return {
        // 読めない形なら「何にも同意していない」扱い。広げる方向に倒さない
        toolNames: Array.isArray(toolNames)
          ? toolNames.filter((name): name is string => typeof name === "string")
          : [],
        integrationUser:
          typeof integrationUsername === "string" ? { username: integrationUsername } : undefined,
        allowedAppIds: typeof allowedAppIds === "string" ? allowedAppIds : undefined,
      };
    },

    /**
     * cybozu からの callback で呼ぶ。
     *
     * **一致・期限内・未使用・同一ブラウザ**の4つを確かめる。
     * どれか1つでも欠けたら通さない。
     */
    async consume(state: string, browserSecret: string | undefined): Promise<ConsumeOutcome> {
      const key = cipher.hash(state);
      const document = await storage.find(MODEL, key);
      if (!document) return { ok: false, reason: "unknown-state" };

      // TTL は掃除であって認可判定ではない (§4.9)。使うたびに自分で見る。
      if (document.expiresAt !== undefined && document.expiresAt <= now()) {
        return { ok: false, reason: "expired" };
      }

      const expectedHash = document.payload.browserSecretHash;
      if (typeof expectedHash !== "string") return { ok: false, reason: "unknown-state" };
      if (browserSecret === undefined) return { ok: false, reason: "browser-mismatch" };
      if (!safeEqual(cipher.hash(browserSecret), expectedHash)) {
        return { ok: false, reason: "browser-mismatch" };
      }

      // 使用済みへの更新は、未使用を条件にした原子的な操作 (§4.10)。
      // 同じ callback が2回来ても、通るのは1回だけ。
      const consumed = await storage.consume(MODEL, key, now());
      if (consumed !== "consumed") {
        return { ok: false, reason: consumed === "already-consumed" ? "already-used" : "unknown-state" };
      }

      const interactionUid = document.payload.interactionUid;
      const accountId = document.payload.accountId;
      if (typeof interactionUid !== "string" || typeof accountId !== "string") {
        return { ok: false, reason: "unknown-state" };
      }

      const toolNames = document.payload.consentToolNames;
      const integrationUsername = document.payload.consentIntegrationUsername;
      const consentAllowedAppIds = document.payload.consentAllowedAppIds;

      return {
        ok: true,
        transaction: {
          interactionUid,
          accountId,
          consent: {
            // 読めない形なら「何にも同意していない」扱い。広げる方向に倒さない
            toolNames: Array.isArray(toolNames)
              ? toolNames.filter((name): name is string => typeof name === "string")
              : [],
            integrationUser:
              typeof integrationUsername === "string"
                ? { username: integrationUsername }
                : undefined,
            allowedAppIds:
              typeof consentAllowedAppIds === "string" ? consentAllowedAppIds : undefined,
          },
        },
      };
    },
  };
};

export type Bridge = ReturnType<typeof createBridge>;

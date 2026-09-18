import type { ConnectionGrantStore } from "./connectionGrant.js";
import type { SecretCipher } from "./crypto.js";
import type { Storage } from "./storage.js";

/**
 * 失効の一点集約。
 *
 * 失効が要る場面は3つあり、**どれか1つでも別経路で書くと必ず穴になる** (§4.10)。
 *
 *  - ユーザーによる切断
 *  - リフレッシュトークンの再使用検知
 *  - cybozu のリフレッシュトークンが無効になった（`invalid_grant`）
 *
 * ## 何を消すのか
 *
 * ⚠ **`grant.destroy()` は Grant 文書を消すだけで、そこから出たトークンは消さない。**
 * v9.12.2 の `Grant` は `BaseToken` を継承していて、`destroy()` は
 * `adapter.destroy(this.jti)` に過ぎない。実際、切断後も
 * `provider.AccessToken.find(token)?.isValid === true` になる（レビューで再現された）。
 *
 * → 系列のトークンを**明示的に**消す。
 *
 * ## grantId → accountId の対応を Grant 文書に依存させない
 *
 * ⚠ provider の `helpers/revoke.js` は、各モデルの `revokeByGrantId()` と
 * **Grant 文書の削除を `Promise.all` で並行実行する**。
 * Grant の削除が先に終わると、そこから `accountId` を引こうとしても取れず、
 * **接続の失効が黙って飛ぶ**。
 *
 * → 独立した対応レコードを持ち、**Grant が消えても引けるようにする**。
 */

/** grantId → accountId の対応を保つモデル。Grant 文書とは別に生きる */
const OWNER_MODEL = "GrantOwner";

export type RevocationOptions = {
  storage: Storage;
  cipher: SecretCipher;
  grants: ConnectionGrantStore;
  /** 失効をサーバー側に残すフック。**秘密は渡らない** */
  onRevoke?: (info: { accountId: string; reason: RevocationReason }) => void;
};

/**
 * 失効の理由。
 *
 * | 値 | 意味 |
 * | --- | --- |
 * | `disconnect` | 利用者がこちらの切断口を叩いた |
 * | `upstream-revoked` | cybozu 側でリフレッシュトークンが死んでいた |
 * | `provider-revoked` | **provider に言われて失効させた**（理由は分からない） |
 *
 * ⚠ **`provider-revoked` を「盗用」と読まないこと。**
 * provider は、再使用を検知したときも利用者が切断したときも同じ口を呼ぶ。
 * どちらだったかは、経路の分かる provider のイベント側で記録している
 * （`httpServer.ts` の `grant.revoked`）。
 */
export type RevocationReason =
  | "disconnect"
  | "upstream-revoked"
  | "provider-revoked";

export const createRevoker = (options: RevocationOptions) => {
  const { storage, cipher, grants } = options;

  const ownerKey = (grantId: string): string => cipher.hash(grantId);

  return {
    /** provider の Grant を接続に結び付ける。**Grant 文書とは別に記録する** */
    /**
     * @param expiresAt 接続と**同じ絶対期限**（エポック秒）。
     *   省略したときは期限なしになるが、本番では必ず渡す
     */
    async rememberGrantOwner(
      grantId: string,
      accountId: string,
      expiresAt?: number,
    ): Promise<void> {
      await storage.upsert(OWNER_MODEL, ownerKey(grantId), {
        payload: { accountId },
        /**
         * ⚠ **接続と同じ絶対期限で消す。**
         *
         * 以前は期限なしにしていた（「接続が続く限り必要」）。
         * だが接続そのものに400日の期限を入れた以上、対応表だけが
         * **永久に残る**のは筋が通らない。実際、切れた接続の対応表が
         * 1件残っているのを見つけた。
         *
         * 中身は `accountId` だけで資格情報は入っていないが、
         * 「使われなくなった接続を永遠に残さない」という方針から漏れている。
         *
         * ⚠ **接続より短くしてはいけない。** 先に消えると、
         * 切断のときに provider の Grant の持ち主を見失う。
         */
        expiresAt,
        // ⚠ 保存層の grantId には入れない。
        // revokeByGrantId はこれが一致するレコードを削除するので、
        // 入れると**対応表が失効処理の途中で消える**。
        grantId: undefined,
        uidHash: undefined,
        userCodeHash: undefined,
      });
    },

    /** grantId から接続の主体を引く。Grant 文書が消えていても引ける */
    async ownerOf(grantId: string): Promise<string | undefined> {
      const document = await storage.find(OWNER_MODEL, ownerKey(grantId));
      const accountId = document?.payload.accountId;
      return typeof accountId === "string" ? accountId : undefined;
    },

    /**
     * 接続をすべての面から失効させる。
     *
     * **何度呼んでも安全**（切断が途中で失敗しても、再試行で続きを行える）。
     */
    async revokeConnection(accountId: string, reason: RevocationReason): Promise<void> {
      // 1. 接続 grant を失効させる。これ以降の発行と更新が止まる。
      //    ⚠ providerGrantId は消さない。消すと再試行で対象を見失う。
      const providerGrantId = await grants.providerGrantId(accountId);
      await grants.revoke(accountId);

      if (!providerGrantId) {
        options.onRevoke?.({ accountId, reason });
        return;
      }

      // 2. 系列のトークンを消す。Grant を消すだけでは残る。
      await storage.revokeByGrantId(providerGrantId);

      // 3. Grant 文書そのものを消す。
      //    （Grant の jti が grantId なので、revokeByGrantId では消えない）
      await storage.destroy("Grant", cipher.hash(providerGrantId));

      options.onRevoke?.({ accountId, reason });
    },

    /** provider から grantId だけ渡されたときの入口 */
    async revokeByGrantId(grantId: string, reason: RevocationReason): Promise<void> {
      const accountId = await this.ownerOf(grantId);
      if (!accountId) return;
      await this.revokeConnection(accountId, reason);
    },
  };
};

export type Revoker = ReturnType<typeof createRevoker>;

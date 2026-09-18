import type { ConnectionGrantStore } from "./connectionGrant.js";
import { GrantRevokedError } from "./connectionGrant.js";
import type { CybozuOAuthClient } from "./cybozuOAuth.js";
import { CybozuOAuthError } from "./cybozuOAuth.js";
import type { Revoker } from "./revocation.js";

/**
 * kintone のアクセストークンを、必要なら更新して返す。
 *
 * cybozu のアクセストークンは**1時間で切れる**。Claude 側のトークンとは寿命が違うので、
 * 「Claude のトークンは有効なのに kintone を叩けない」状態が普通に起きる。
 * ここで吸収する。
 *
 * ## kintone の期限切れを Claude の認可切れにしない (§7.4)
 *
 * こちらがリフレッシュすれば済む状態で 401 を返すと、ユーザーに再ログインを
 * 強いることになる。**リフレッシュできる限りは黙って更新する。**
 * 再認可が要るのは、cybozu のリフレッシュトークンまで無効になったときだけ。
 */

export class KintoneAuthRequiredError extends Error {
  constructor() {
    super("kintone の再認可が必要です");
    this.name = "KintoneAuthRequiredError";
  }
}

export type KintoneTokenProviderOptions = {
  grants: ConnectionGrantStore;
  cybozu: CybozuOAuthClient;
  /**
   * 失効の一点集約 (§4.10)。
   *
   * ⚠ `grants.revoke()` だけでは足りない。provider の Grant と
   * アクセストークンが残り、しかも対応が失われるので、
   * 後から切断しても回収できなくなる。
   */
  revoker: Revoker;
  /** 期限の何秒前から先回りして更新するか */
  refreshSkewSeconds?: number;
  now?: () => number;
  /** 更新の結果をサーバー側に残すフック。**トークンは渡らない** */
  onRefresh?: (info: { accountId: string; outcome: "refreshed" | "reauth-required" }) => void;
};

const DEFAULT_SKEW = 120;

/**
 * 更新を待っている相手がいなくなったので、始めずにやめた。
 *
 * **失敗ではない。** 呼び出し側は、応答を返さずに終わってよい
 * （締め切りか切断で、すでに応答は決着している）。
 */
export class KintoneRequestAbandonedError extends Error {
  constructor() {
    super("要求が打ち切られました");
    this.name = "KintoneRequestAbandonedError";
  }
}

/** 更新中のもの。**待ち手を持つ**ので、開始側が諦めても他が待てる */
type InFlight = {
  promise: Promise<string>;
  /** 待っている相手が「諦めたか」を返す関数の集まり */
  waiters: Set<() => boolean>;
};

export const createKintoneTokenProvider = (options: KintoneTokenProviderOptions) => {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const skew = options.refreshSkewSeconds ?? DEFAULT_SKEW;

  /**
   * 同一プロセス内で同じ接続の更新が重ならないようにする。
   *
   * **インスタンスをまたぐ重複は防げない。** cybozu 側は同じリフレッシュトークンでの
   * 更新を許すので実害は小さいが、リフレッシュトークンは
   * 1ユーザーあたり10個までなので、無駄打ちは避けたい。
   */
  const inFlight = new Map<string, InFlight>();

  const refresh = async (accountId: string, refreshToken: string): Promise<string> => {
    try {
      const refreshed = await options.cybozu.refresh(refreshToken);
      // ⚠ リフレッシュトークンは触らない。cybozu の応答には含まれない (§4.9)。
      await options.grants.updateAccessToken(
        accountId,
        refreshed.accessToken,
        refreshed.expiresAt,
        refreshed.scope,
      );
      options.onRefresh?.({ accountId, outcome: "refreshed" });
      return refreshed.accessToken;
    } catch (error) {
      if (error instanceof GrantRevokedError) {
        // 更新中に切断された。競合の正しい結果なので、そのまま再認可へ。
        options.onRefresh?.({ accountId, outcome: "reauth-required" });
        throw new KintoneAuthRequiredError();
      }

      if (error instanceof CybozuOAuthError && error.upstreamError === "invalid_grant") {
        // リフレッシュトークンが死んでいる。この接続はもう使えない。
        // **接続・provider の Grant・系列のトークンをまとめて失効させる**
        // （放置すると毎回ここで失敗し続けるうえ、Claude 側のトークンが生き残る）。
        await options.revoker.revokeConnection(accountId, "upstream-revoked");
        options.onRefresh?.({ accountId, outcome: "reauth-required" });
        throw new KintoneAuthRequiredError();
      }

      // 一時的な障害。接続は失効させない (§7.4)。
      throw error;
    }
  };

  return {
    /**
     * 使えるアクセストークンを返す。
     *
     * @throws {KintoneAuthRequiredError} 再認可が必要なとき
     */
    async getAccessToken(
      accountId: string,
      callOptions: { isAbandoned?: () => boolean } = {},
    ): Promise<string> {
      // 呼び出し側が生きているかを見る関数。省略時は常に生きている扱い
      const alive = callOptions.isAbandoned ?? (() => false);

      const existing = inFlight.get(accountId);
      if (existing) {
        // ⚠ **待ち手として登録する。** 更新を始めた側が途中で諦めても、
        // こちらが待っている限り更新は続けなければならない
        existing.waiters.add(alive);
        return existing.promise;
      }

      const waiters = new Set<() => boolean>([alive]);

      // ⚠ **`await` を挟む前に登録する。**
      // 読み込みを待ってから登録すると、同時に来た呼び出しが全部
      // 同期チェックを通り抜けて、それぞれ cybozu を叩く（実際にそうなっていた）。
      const promise = (async () => {
        const grant = await options.grants.load(accountId);
        if (!grant) throw new KintoneAuthRequiredError();

        if (grant.expiresAt - skew > now()) return grant.accessToken;

        // ⚠ **ここから cybozu を呼ぶ。待っている相手が1人もいないなら始めない。**
        //
        // 読み込みの間に締め切りを過ぎていることがある。そのまま進むと、
        // **結果を受け取る相手がいないのに cybozu を呼ぶ**ことになる
        // （リフレッシュトークンは1ユーザー10個までなので、無駄打ちは避けたい）。
        //
        // ⚠ **「呼び出した本人が諦めたか」で判断しない。**
        // 更新は共有なので、本人が諦めても**他が待っていれば続ける**必要がある。
        // ⚠ **ここから cybozu を呼ぶ。待っている相手が1人もいないなら始めない。**
        //
        // 読み込みの間に締め切りを過ぎていることがある。そのまま進むと、
        // **結果を受け取る相手がいないのに cybozu を呼ぶ**ことになる
        // （リフレッシュトークンは1ユーザー10個までなので、無駄打ちは避けたい）。
        //
        // ⚠ **「呼び出した本人が諦めたか」で判断しない。**
        // 更新は共有なので、本人が諦めても**他が待っていれば続ける**必要がある。
        if ([...waiters].every((isAbandoned) => isAbandoned())) {
          throw new KintoneRequestAbandonedError();
        }

        return refresh(accountId, grant.refreshToken);
      })();

      inFlight.set(accountId, { promise, waiters });

      try {
        return await promise;
      } finally {
        inFlight.delete(accountId);
      }
    },
  };
};

export type KintoneTokenProvider = ReturnType<typeof createKintoneTokenProvider>;

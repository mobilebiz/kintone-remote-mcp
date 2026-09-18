import type { Revoker } from "./revocation.js";

/**
 * 接続の切断。
 *
 * 実体は `revocation.ts` の一点集約に委ねる。
 * **切断・再使用検知・上流の失効で処理を分けない** — 分けた結果、
 * 「切断したのにアクセストークンが生き残る」状態を作ってしまった (§4.10)。
 */

export type DisconnectOptions = {
  revoker: Revoker;
};

export const createDisconnector = (options: DisconnectOptions) => ({
  async disconnect(accountId: string): Promise<void> {
    await options.revoker.revokeConnection(accountId, "disconnect");
  },
});

export type Disconnector = ReturnType<typeof createDisconnector>;

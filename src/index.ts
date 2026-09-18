import { createServer } from "node:http";

import { ConfigError, loadConfig } from "./config.js";
import { resolveEncryptionKey } from "./auth/kms.js";
import { buildServer } from "./httpServer.js";

/**
 * エントリポイント。
 *
 * ## 設定の検証で落とす
 *
 * 不正な設定は、**1つでもリクエストを受ける前に**落とす (§2.3)。
 * 「動いているように見えて挙動がおかしい」のがいちばん調査に時間がかかる。
 *
 * ## SIGTERM
 *
 * Cloud Run は停止前に SIGTERM を送る。**新規受付を止めてから、
 * 処理中のリクエストを終わらせる** (§7.3)。
 * 即座に落とすと、書き込みの途中で切れて「結果不明」を増やす。
 */

const main = async (): Promise<void> => {
  let config;
  try {
    config = loadConfig();
  } catch (error) {
    if (error instanceof ConfigError) {
      // 問題はまとめて出す。1つ直すたびに再起動して次が出る、を避ける
      console.error(`[FATAL] ${error.message}`);
      process.exit(1);
    }
    throw error;
  }

  /**
   * 鍵を用意する。
   *
   * ⚠ **取り出せなければ起動しない。** 鍵が無いまま動くと、
   * 保存済みのトークンを1つも読めないサーバーが
   * 「正常に起動した」ことになる。
   */
  let tokenEncryptionKey: Buffer;
  try {
    tokenEncryptionKey = await resolveEncryptionKey(config.encryptionKeySource);
  } catch (error) {
    console.error(`[FATAL] ${error instanceof Error ? error.message : "鍵を用意できません"}`);
    process.exit(1);
  }

  if (config.encryptionKeySource.kind === "plain") {
    // 気づかないまま生の鍵で本番を動かさないために、必ず出す
    console.warn(
      JSON.stringify({
        severity: "WARNING",
        type: "config.plain_key",
        message:
          "トークン暗号鍵を環境変数のまま使っています。KMS で包んでください（KMS_KEY_NAME と TOKEN_ENCRYPTION_KEY_CIPHERTEXT）",
      }),
    );
  }

  const { app, shutdown } = buildServer({ config: { ...config, tokenEncryptionKey } });
  const server = createServer(app);

  server.listen(config.port, config.bindHost, () => {
    console.log(
      JSON.stringify({
        severity: "INFO",
        type: "startup",
        issuer: config.issuer,
        resource: config.resource,
        tenant: new URL(config.kintoneBaseUrl).hostname,
        // 生の鍵で動いていることに気づけるようにする
        encryptionKey: config.encryptionKeySource.kind,
        // 何が有効かは起動時に見えるようにする。
        // 「ツールが出てこない」の原因がここであることが多い
        capabilities: config.capabilities,
        allowedAppIds: config.allowedAppIds ?? "(制限なし)",
      }),
    );
  });

  let shuttingDown = false;
  const stop = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(JSON.stringify({ severity: "INFO", type: "shutdown", signal }));

    const startedAt = Date.now();
    /** 停止のどこで時間を使ったかを残す。無いと推測で直すことになる */
    const mark = (stage: string): void =>
      console.log(
        JSON.stringify({
          severity: "INFO",
          type: "shutdown.progress",
          stage,
          elapsedMs: Date.now() - startedAt,
        }),
      );

    // 新規の接続を受けなくする。処理中のものは走り切らせる
    server.close(() => {
      mark("connections-drained");
      void shutdown().finally(() => {
        mark("resources-released");
        process.exit(0);
      });
    });



    // 走り切らないものがあっても、いつかは落とす。
    //
    // ⚠ **Cloud Run の SIGTERM 後の猶予は10秒**。
    // 20秒にしていたが、それでは猶予を超えて強制終了されるので意味が無かった。
    setTimeout(() => process.exit(0), 8_000).unref();
  };

  process.on("SIGTERM", () => stop("SIGTERM"));
  process.on("SIGINT", () => stop("SIGINT"));
};

void main();

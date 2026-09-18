import { describe, expect, it } from "vitest";

import { isSingleJsonRpcMessage, kintoneClientOptions } from "../../src/mcpEndpoint.js";

/**
 * SDK に本文を読み直させないための判定 (P1-1 の第2層)。
 *
 * ⚠ **この層は、HTTP 越しには単独で試せない。**
 * 手前に Content-Type の限定があるので、外から叩くと常にそちらで止まる。
 * 層を1つ壊しても、もう1つが拾ってテストが通ってしまう
 * （実際、最初に書いた HTTP 経由のテストは body-parser 自身の拒否を見ていて、
 * この判定を壊しても通った）。
 *
 * → **判定そのものを直接試す。**
 *
 * ## 呼び出し側は HTTP 越しに試している
 *
 * | 経路 | 試し方 |
 * | --- | --- |
 * | 配列（バッチ） | `express.json` が解析するので判定まで届く（`server.test.ts`） |
 * | 未解析（`undefined`） | **本文を持たない POST**（`limits.test.ts`） |
 *
 * ⚠ **後者を「到達できない」と書いていたが、誤りだった。**
 * `Content-Length` も `Transfer-Encoding` も無い POST は、
 * Content-Type が `application/json` でも body-parser が解析を省略し、
 * `req.body` が `undefined` のままになる。
 * 手前の Content-Type 限定を緩めなくても、外から叩ける（外部レビューで指摘）。
 */
describe("解析済みの単一メッセージだけを通す", () => {
  it("Express が解析していない本文を通さない", () => {
    // これが真になると、SDK が本文を読み直し、
    // バッチ拒否もサイズ上限も迂回される
    expect(isSingleJsonRpcMessage(undefined), "未解析の本文が通っている").toBe(false);
  });

  it("配列（バッチ）を通さない", () => {
    expect(isSingleJsonRpcMessage([{ jsonrpc: "2.0", id: 1, method: "tools/list" }])).toBe(false);
    expect(isSingleJsonRpcMessage([])).toBe(false);
  });

  it("オブジェクト以外を通さない", () => {
    expect(isSingleJsonRpcMessage(null)).toBe(false);
    expect(isSingleJsonRpcMessage("just a string")).toBe(false);
    expect(isSingleJsonRpcMessage(42)).toBe(false);
  });

  it("単一のメッセージは通す", () => {
    expect(isSingleJsonRpcMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" })).toBe(true);
    // 中身の検証は SDK の仕事。ここは「形」だけを見る
    expect(isSingleJsonRpcMessage({})).toBe(true);
  });
});

/**
 * 本番の kintone クライアント設定。
 *
 * ⚠ **HTTP 経由のテストでは確かめられない。**
 * クライアント生成をスタブに差し替えているので、本番側の設定を消しても
 * テストは通る（実際、`socketTimeout` を消しても全件通った）。
 * 設定を作る関数を直接呼ぶ。
 */
describe("kintone クライアントの設定", () => {
  const options = kintoneClientOptions({
    baseUrl: "https://example.cybozu.com",
    auth: { oAuthToken: "token" },
    userAgent: "kintone-remote-mcp@test",
    deadlineMs: 55_000,
  });

  it("通信に期限を与える", () => {
    // 無いと、相手が黙り込んだときに同時実行の枠を握ったままになる
    expect(options.socketTimeout, "通信の期限が無い").toBe(55_000);
  });

  it("接続プールを共有する", () => {
    // クライアントは要求ごとに作り直すので、これが無いと毎回 TLS から張り直す
    expect(options.httpsAgent).toBeDefined();
  });

  it("cybozu 由来のトークンで認証する", () => {
    expect(options.auth).toEqual({ oAuthToken: "token" });
  });

  it("連携ユーザーの資格情報と混ざらない", () => {
    // ⚠ **kintone はパスワード認証を OAuth より優先する。**
    // 1つのクライアントに両方載せると、すべての操作が
    // 連携ユーザーとして実行されてしまう
    const asIntegration = kintoneClientOptions({
      baseUrl: "https://example.cybozu.com",
      auth: { username: "integration", password: "pw" },
      userAgent: "kintone-remote-mcp@test",
      deadlineMs: 55_000,
    });

    expect(asIntegration.auth).toEqual({ username: "integration", password: "pw" });
    expect(asIntegration.auth, "OAuth の資格情報が混ざっている").not.toHaveProperty("oAuthToken");
    expect(options.auth, "パスワードが混ざっている").not.toHaveProperty("password");
  });
});

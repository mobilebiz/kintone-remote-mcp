import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { KintoneRestAPIClient } from "@kintone/rest-api-client";

import { createAuditLogger } from "../../src/observability/audit.js";
import { redactHeaders, redactUrl, summarizeError, tenantOf } from "../../src/observability/redact.js";
import { createRemoteServer } from "../../src/adapter/createRemoteServer.js";
import { DEFAULT_CAPABILITIES } from "../../src/adapter/toolPolicy.js";
import { parseAllowedAppIds } from "../../src/adapter/appScope.js";

/**
 * 監査ログ (§7.5)。
 *
 * このモジュールの本体は「**何を出すか**」ではなく「**何を出さないか**」。
 * 秘密が1つでも混ざれば、Cloud Logging に永続化されて回収できない。
 */

const SECRET = "SECRET_VALUE_should_never_appear_9f3a";

describe("伏せ方", () => {
  it("URL からクエリを落とす", () => {
    // `code` と `state` は URL に載る。Cloud Logging の requestUrl はクエリを含む。
    expect(redactUrl(`https://mcp.example.com/oauth/callback?code=${SECRET}&state=x`)).toBe(
      "/oauth/callback",
    );
  });

  it("解釈できない URL でも秘密を返さない", () => {
    expect(redactUrl(`::::${SECRET}`)).not.toContain(SECRET);
  });

  it("ヘッダーは許可したものだけ通す", () => {
    const result = redactHeaders({
      "content-type": "application/json",
      authorization: `Bearer ${SECRET}`,
      cookie: `session=${SECRET}`,
      "x-cybozu-api-token": SECRET,
      // ⚠ 認可のリダイレクト先には code が載る
      location: `https://claude.ai/api/mcp/auth_callback?code=${SECRET}`,
    });

    expect(result).toEqual({ "content-type": "application/json" });
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });

  it("例外から message を出さない", () => {
    // kintone クライアントの例外にはリクエスト設定（= 資格情報）が入りうる。
    const error = Object.assign(new Error(`failed: ${SECRET}`), { status: 403 });

    const summary = summarizeError(error);

    expect(summary.kind).toBe("Error");
    expect(summary.status).toBe(403);
    expect(JSON.stringify(summary)).not.toContain(SECRET);
  });

  it("スタックはコード位置だけを出す（値は出さない）", () => {
    // ⚠ 種別だけでは原因に辿り着けない。実際、provider の 500 を追ったときに
    // {"kind":"Error"} しか残らず調査ができなかった。
    // コード位置はデータではないので出してよい。
    const error = new Error(SECRET);

    const summary = summarizeError(error);

    expect(summary.at, "コード位置が無いと診断できない").toBeTruthy();
    expect(summary.at).toMatch(/:\d+:\d+$/);
    // 絶対パスは環境の情報なので末尾だけ
    expect(summary.at).not.toContain("/Users/");
    expect(JSON.stringify(summary)).not.toContain(SECRET);
  });

  it("getter が投げる例外でも落ちない", () => {
    const evil = {};
    Object.defineProperty(evil, "status", {
      get() {
        throw new Error(SECRET);
      },
      enumerable: true,
    });

    expect(() => summarizeError(evil)).not.toThrow();
    expect(JSON.stringify(summarizeError(evil))).not.toContain(SECRET);
  });

  it("テナントはホスト名だけ", () => {
    expect(tenantOf("https://example.cybozu.com/k/v1/records.json?app=1")).toBe(
      "example.cybozu.com",
    );
  });
});

describe("監査ログの出力", () => {
  const capture = () => {
    const entries: Record<string, unknown>[] = [];
    const audit = createAuditLogger({
      sink: (entry) => entries.push(entry),
      kintoneBaseUrl: "https://example.cybozu.com",
      now: () => "2026-09-16T00:00:00.000Z",
    });
    return { audit, entries };
  };

  it("認可イベントに相関 ID とテナントが入る", () => {
    const { audit, entries } = capture();

    audit.auth("connection_created", { correlationId: "corr-1", accountId: "acct-1" });

    expect(entries[0]).toMatchObject({
      severity: "INFO",
      type: "auth.connection_created",
      tenant: "example.cybozu.com",
      correlationId: "corr-1",
      accountId: "acct-1",
    });
  });

  it("拒否と再認可要求は WARNING", () => {
    const { audit, entries } = capture();

    audit.auth("bridge_rejected", { correlationId: "c" }, { reason: "browser-mismatch" });
    audit.auth("reauth_required", { correlationId: "c" });

    expect(entries.map((e) => e.severity)).toEqual(["WARNING", "WARNING"]);
  });

  it("想定外の失敗は例外を渡しても秘密が出ない", () => {
    // 呼び出し側に「安全な形に直してから渡せ」と要求すると、いつか忘れる。
    const { audit, entries } = capture();

    audit.unexpected({ correlationId: "c", where: "oauth/callback" }, new Error(SECRET));

    expect(JSON.stringify(entries[0])).not.toContain(SECRET);
    expect(entries[0]).toMatchObject({ severity: "ERROR", where: "oauth/callback" });
  });

  it("流量制限で止めた事実を残す", () => {
    // 止めた記録が無いと、詰まりの原因が分からない。
    const { audit, entries } = capture();

    audit.rateLimited({ correlationId: "c", scope: "pre-auth", limit: 60 });

    expect(entries[0]).toMatchObject({ type: "rate_limit.blocked", scope: "pre-auth", limit: 60 });
  });
});

describe("ツール実行の監査", () => {
  const clientThatFails = {
    record: {
      getRecords: async () => {
        throw Object.assign(new Error(SECRET), { status: 403 });
      },
    },
  } as unknown as KintoneRestAPIClient;

  const clientThatWorks = {
    record: {
      getRecords: async () => ({ records: [], totalCount: "0" }),
    },
  } as unknown as KintoneRestAPIClient;

  const connect = async (client: KintoneRestAPIClient, allowed?: string) => {
    const outcomes: Array<Record<string, unknown>> = [];
    const server = createRemoteServer({
      name: "t",
      version: "0",
      client,
      authMode: "oauth",
      capabilities: DEFAULT_CAPABILITIES,
      appScope: { allowedAppIds: parseAllowedAppIds(allowed) },
      onToolOutcome: (outcome) => outcomes.push({ ...outcome }),
    });
    const mcp = new Client({ name: "t", version: "0" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(st), mcp.connect(ct)]);
    return {
      mcp,
      outcomes,
      close: async () => {
        await mcp.close();
        await server.close();
      },
    };
  };

  it("成功も記録される", async () => {
    // 失敗だけ記録すると、呼ばれた回数も所要時間も分からない。
    const { mcp, outcomes, close } = await connect(clientThatWorks);

    await mcp.callTool({ name: "kintone-get-records", arguments: { app: "10" } });

    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]).toMatchObject({ toolName: "kintone-get-records", ok: true });
    expect(outcomes[0]!.durationMs).toBeTypeOf("number");
    await close();
  });

  it("対象のアプリ ID が記録される（本文は入らない）", async () => {
    const { mcp, outcomes, close } = await connect(clientThatWorks);

    await mcp.callTool({ name: "kintone-get-records", arguments: { app: "10" } });

    expect(outcomes[0]!.targets).toEqual(["10"]);
    await close();
  });

  it("失敗は分類と相関 ID つきで記録され、秘密は入らない", async () => {
    const { mcp, outcomes, close } = await connect(clientThatFails);

    const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "10" } });

    expect(outcomes[0]).toMatchObject({ ok: false, failureKind: "forbidden" });
    expect(outcomes[0]!.correlationId).toBeTruthy();
    expect(JSON.stringify(outcomes[0])).not.toContain(SECRET);
    // クライアントへの応答と同じ相関 ID で突き合わせられる
    expect(JSON.stringify(result)).toContain(outcomes[0]!.correlationId as string);
    await close();
  });

  it("応答に返す相関 ID は、リクエストのものと同じ", async () => {
    // ⚠ **境界が独自に作ると、ログと突き合わせられない ID を返すことになる。**
    // 監査ログ側はリクエストの ID を書くので、
    // 利用者が伝えてきた ID で検索しても**何も出てこない**（実測で確認）。
    const outcomes: Array<Record<string, unknown>> = [];
    const server = createRemoteServer({
      name: "t",
      version: "0",
      client: clientThatFails,
      authMode: "oauth",
      capabilities: DEFAULT_CAPABILITIES,
      correlationId: "corr-from-request",
      onToolOutcome: (outcome) => outcomes.push({ ...outcome }),
    });
    const mcp = new Client({ name: "t", version: "0" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(st), mcp.connect(ct)]);

    const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "10" } });

    expect(JSON.stringify(result), "応答の ID がリクエストのものと違う").toContain(
      "corr-from-request",
    );
    expect(outcomes[0]!.correlationId).toBe("corr-from-request");

    await mcp.close();
    await server.close();
  });

  it("kintone のエラーコードと ID を記録する", async () => {
    // 分類だけでは、サイボウズへ問い合わせるときの手がかりにならない。
    // ⚠ 本文は載せない。**識別子だけ**
    const failures: Array<Record<string, unknown>> = [];
    const client = {
      record: {
        getRecords: async () => {
          throw Object.assign(new Error(SECRET), {
            status: 520,
            code: "CB_NO02",
            id: "abcdef1234567890",
          });
        },
      },
    } as unknown as KintoneRestAPIClient;

    const server = createRemoteServer({
      name: "t",
      version: "0",
      client,
      authMode: "oauth",
      capabilities: DEFAULT_CAPABILITIES,
      onToolFailure: (failure) => failures.push({ ...failure }),
    });
    const mcp = new Client({ name: "t", version: "0" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(st), mcp.connect(ct)]);

    await mcp.callTool({ name: "kintone-get-records", arguments: { app: "10" } });

    expect(failures[0]).toMatchObject({ kintoneCode: "CB_NO02", kintoneId: "abcdef1234567890" });
    expect(JSON.stringify(failures[0]), "本文が混ざっている").not.toContain(SECRET);

    await mcp.close();
    await server.close();
  });

  it("アプリ境界で止めた呼び出しも記録される", async () => {
    // 止めた記録が無いと、「呼ばれていない」のか「止めた」のか分からない。
    const { mcp, outcomes, close } = await connect(clientThatWorks, "10");

    await mcp.callTool({ name: "kintone-get-records", arguments: { app: "99" } });

    expect(outcomes[0]).toMatchObject({ ok: false, failureKind: "app_not_allowed" });
    expect(outcomes[0]!.targets).toEqual(["99"]);
    await close();
  });

  it("監査フックが投げても応答は壊れない", async () => {
    const server = createRemoteServer({
      name: "t",
      version: "0",
      client: clientThatWorks,
      authMode: "oauth",
      capabilities: DEFAULT_CAPABILITIES,
      onToolOutcome: () => {
        throw new Error(SECRET);
      },
    });
    const mcp = new Client({ name: "t", version: "0" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(st), mcp.connect(ct)]);

    const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "10" } });

    expect(result.isError).toBeFalsy();
    expect(JSON.stringify(result)).not.toContain(SECRET);
    await mcp.close();
    await server.close();
  });
});

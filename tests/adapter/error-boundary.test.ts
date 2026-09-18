import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { KintoneRestAPIClient } from "@kintone/rest-api-client";

import { createRemoteServer, selectTools } from "../../src/adapter/createRemoteServer.js";
import { DEFAULT_CAPABILITIES, type ToolCapabilities } from "../../src/adapter/toolPolicy.js";
import type { ToolFailure } from "../../src/adapter/errorBoundary.js";

/**
 * ツール実行の境界テスト。
 *
 * 契約テスト (upstream-contract) は `tools/call` を実行しないため、
 * **例外経路の漏えいを検出できなかった**。実際、外部レビューで
 * 「callback が投げた秘密がそのまま MCP 応答に出る」ことを指摘され、再現した。
 * ここはその再発を止めるためにある。
 */

/** 資格情報が例外に混ざる、という現実的な失敗を模す */
const SENTINEL = "SECRET_SENTINEL_X-Cybozu-API-Token_abc123";

const clientThatThrows = (error: unknown): KintoneRestAPIClient =>
  ({
    record: {
      getRecords: async () => {
        throw error;
      },
    },
  }) as unknown as KintoneRestAPIClient;

const connect = async (client: KintoneRestAPIClient, failures: ToolFailure[] = []) => {
  const server = createRemoteServer({
    name: "kintone-remote-mcp",
    version: "0.1.0",
    client,
    authMode: "oauth",
    capabilities: DEFAULT_CAPABILITIES,
    onToolFailure: (f) => failures.push(f),
  });
  const mcp = new Client({ name: "test", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), mcp.connect(clientTransport)]);
  return {
    mcp,
    close: async () => {
      await mcp.close();
      await server.close();
    },
  };
};

const connectWithThrowingHook = async (hookError: unknown) => {
  const server = createRemoteServer({
    name: "kintone-remote-mcp",
    version: "0.1.0",
    client: clientThatThrows(new Error("boom")),
    authMode: "oauth",
    capabilities: DEFAULT_CAPABILITIES,
    onToolFailure: () => {
      throw hookError;
    },
  });
  const mcp = new Client({ name: "test", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), mcp.connect(clientTransport)]);
  return {
    mcp,
    close: async () => {
      await mcp.close();
      await server.close();
    },
  };
};

describe("ツール例外の詰め替え", () => {
  it("例外に含まれる秘密が MCP 応答に出ない", async () => {
    const error = new Error(`kintone API failed: X-Cybozu-API-Token=${SENTINEL}`);
    const { mcp, close } = await connect(clientThatThrows(error));

    const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "1" } });

    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).not.toContain(SENTINEL);
    await close();
  });

  it("未知の文字列を一切外に出さない（形式が正しく見える値も含む）", async () => {
    // 正規表現で形を縛る方式は、形に合う秘密を通してしまう。
    // 現在の方針は「HTTP ステータスと固定の分類と相関 ID しか出さない」。
    const kintoneError = Object.assign(new Error("x"), {
      status: 403,
      code: "CB_NO02",
      id: "Abc123SecretToken",
    });
    const failures: ToolFailure[] = [];
    const { mcp, close } = await connect(clientThatThrows(kintoneError), failures);

    const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "1" } });
    const serialized = JSON.stringify(result);

    // 出すのは分類とステータスと相関 ID だけ
    expect(serialized).toContain("forbidden");
    expect(serialized).toContain("403");
    // kintone のコードや ID は出さない
    expect(serialized).not.toContain("CB_NO02");
    expect(serialized).not.toContain("Abc123SecretToken");

    // サーバー側のログには残す（突き合わせに要る）
    expect(failures[0]?.kintoneCode).toBe("CB_NO02");
    expect(failures[0]?.kintoneId).toBe("Abc123SecretToken");
    expect(failures[0]?.correlationId).toBeTruthy();
    await close();
  });

  it("HTTP ステータスから分類が決まる", async () => {
    for (const [status, kind] of [
      [401, "unauthorized"],
      [403, "forbidden"],
      [404, "not_found"],
      [429, "rate_limited"],
      [503, "kintone_unavailable"],
      [400, "invalid_request"],
    ] as const) {
      const { mcp, close } = await connect(
        clientThatThrows(Object.assign(new Error("x"), { status })),
      );
      const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "1" } });
      expect(JSON.stringify(result), `status=${status}`).toContain(kind);
      await close();
    }
  });

  it("ログ用フックが投げても応答に出さない", async () => {
    // 境界自身の例外が境界を素通りしていた。フックの失敗は応答から隔離する。
    const server = await connect(clientThatThrows(new Error("boom")));
    await server.close();

    const { mcp, close } = await connectWithThrowingHook(new Error(SENTINEL));
    const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "1" } });

    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).not.toContain(SENTINEL);
    await close();
  });

  it("例外のプロパティ getter が投げても漏らさない", async () => {
    const evil: Record<string, unknown> = {};
    Object.defineProperty(evil, "status", {
      get() {
        throw new Error(SENTINEL);
      },
      enumerable: true,
    });
    const { mcp, close } = await connect(clientThatThrows(evil));

    const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "1" } });

    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).not.toContain(SENTINEL);
    await close();
  });

  it("文字列など Error ですらない値を投げられても漏らさない", async () => {
    const { mcp, close } = await connect(clientThatThrows(SENTINEL));

    const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "1" } });

    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).not.toContain(SENTINEL);
    await close();
  });
});

describe("capability の広告", () => {
  it("listChanged を広告しない", async () => {
    // registerTool() が listChanged: true を立てるので、明示的に打ち消す必要がある。
    // ステートレス構成では通知を送れないため、送れないものを広告してはいけない。
    const { mcp, close } = await connect({} as KintoneRestAPIClient);

    expect(mcp.getServerCapabilities()?.tools).toEqual({ listChanged: false });
    await close();
  });
});

describe("上流フィルタとの併用", () => {
  it("API トークン認証では上流が除外する7ツールを公開しない", async () => {
    // 上流の shouldEnableTool を通しているかの確認。
    // kintone-get-apps は API トークンでは実行できない。
    const all: ToolCapabilities = {
      recordRead: true, recordWrite: true, appRead: true, appWrite: true,
      spaceRead: true, spaceWrite: true, search: true, fileDownload: true,
      allowDestructive: true,
    };
    const apiToken = selectTools("apiToken", all).map((t) => t.name);
    const password = selectTools("password", all).map((t) => t.name);

    expect(apiToken).not.toContain("kintone-get-apps");
    expect(apiToken).not.toContain("kintone-add-app");
    expect(password).toContain("kintone-get-apps");
  });
});

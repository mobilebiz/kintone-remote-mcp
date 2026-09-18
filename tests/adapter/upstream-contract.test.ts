import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { KintoneRestAPIClient } from "@kintone/rest-api-client";

import { tools, createToolCallback } from "@kintone/mcp-server/dist/tools/index.js";
import { shouldEnableTool } from "@kintone/mcp-server/dist/server/tool-filters.js";
import { buildToolDefinition } from "@kintone/mcp-server/dist/server/tool-definitions.js";

import {
  createRemoteServer,
  selectTools,
  toolDefinitionWithAnnotations,
} from "../../src/adapter/createRemoteServer.js";
import {
  CLASSIFIED_TOOL_NAMES,
  DEFAULT_CAPABILITIES,
  DESTRUCTIVE_TOOL_NAMES,
  LEGACY_CONSENTED_TOOLS,
  OAUTH_UNSUPPORTED_TOOL_NAMES,
  shouldExposeTool,
  type ToolCapabilities,
} from "../../src/adapter/toolPolicy.js";

/**
 * 上流 `@kintone/mcp-server` との契約テスト。
 *
 * この構成は**フォークではなく deep import** で成り立っているので、
 * 上流が形を変えたら黙って壊れる。Renovate の更新 PR がここで落ちるようにしてある。
 *
 * 「27件 import できる」だけでは足りない。設計が依存している**具体的な性質**を
 * 1つずつ確かめる。
 */

const ALL_ENABLED: ToolCapabilities = {
  recordRead: true,
  recordWrite: true,
  appRead: true,
  appWrite: true,
  spaceRead: true,
  spaceWrite: true,
  search: true,
  fileDownload: true,
  allowDestructive: true,
};

/** テスト用のダミー。ツールを実行しないので中身は要らない */
const fakeClient = {} as KintoneRestAPIClient;

describe("上流 dist からの deep import", () => {
  it("4つのシンボルがすべて取得できる", () => {
    expect(Array.isArray(tools)).toBe(true);
    expect(typeof createToolCallback).toBe("function");
    expect(typeof shouldEnableTool).toBe("function");
    expect(typeof buildToolDefinition).toBe("function");
  });

  it("import しても上流の設定検証を踏まない", () => {
    // このテストは環境変数を一切設定せずに走る。上流の config/index.ts は
    // モジュールロード時に KINTONE_BASE_URL などを検証して throw するので、
    // それを踏む経路があればここまで到達できない。
    expect(process.env.KINTONE_BASE_URL).toBeUndefined();
    expect(tools.length).toBeGreaterThan(0);
  });

  it("ツール名の集合が、こちらの分類と完全に一致する", () => {
    // 上流がツールを追加・改名したら落ちる。落ちたら toolPolicy に分類を足す。
    // 分類の無いツールは公開されない（shouldExposeTool が false を返す）ので、
    // 「気づかないうちに公開される」ことは無いが、「気づかないうちに使えない」は起きる。
    const upstream = [...tools.map((t) => t.name)].sort();
    const classified = [...CLASSIFIED_TOOL_NAMES].sort();
    expect(upstream).toEqual(classified);
  });

  it("上流の shouldEnableTool は OAuth を知らない", () => {
    // isApiTokenAuth: false（= OAuth もここに落ちる）だと、上流はスペース系や
    // search も「有効」と判定する。だからこちらでフィルタする必要がある。
    for (const name of OAUTH_UNSUPPORTED_TOOL_NAMES) {
      expect(shouldEnableTool(name, { isApiTokenAuth: false })).toBe(true);
    }
  });

  it("buildToolDefinition は annotations を返さない", () => {
    // これが設計の前提。上流が annotations を返すようになったら、
    // こちらのマージが二重になっていないか確認する。
    const first = tools[0];
    expect(first).toBeDefined();
    const definition = buildToolDefinition(first!);
    expect(Object.keys(definition).sort()).toEqual([
      "description",
      "inputSchema",
      "name",
      "outputSchema",
      "title",
    ]);
  });

  it("入力スキーマが JSON Schema 2020-12 で出る", () => {
    // SDK 既定の draft-07 ではなく 2020-12 であることが、上流を借りる理由のひとつ。
    const first = tools[0];
    const definition = buildToolDefinition(first!);
    expect(definition.inputSchema.$schema).toBe(
      "https://json-schema.org/draft/2020-12/schema",
    );
  });
});

describe("ツール公開ポリシー", () => {
  it("OAuth ではスペース系4つと search を公開しない", () => {
    const exposed = selectTools("oauth", ALL_ENABLED).map((t) => t.name);
    for (const name of OAUTH_UNSUPPORTED_TOOL_NAMES) {
      expect(exposed).not.toContain(name);
    }
    expect(exposed).toHaveLength(tools.length - OAUTH_UNSUPPORTED_TOOL_NAMES.length);
  });

  it("パスワード認証ならすべて公開しうる", () => {
    expect(selectTools("password", ALL_ENABLED)).toHaveLength(tools.length);
  });

  it("既定の capability では読み取りだけが公開される", () => {
    // 設計 §5 の「既定ポリシーで公開されるのは9」を固定する。
    const exposed = selectTools("oauth", DEFAULT_CAPABILITIES).map((t) => t.name).sort();
    expect(exposed).toEqual([
      "kintone-get-app",
      "kintone-get-app-deploy-status",
      "kintone-get-apps",
      "kintone-get-form-fields",
      "kintone-get-form-layout",
      "kintone-get-general-settings",
      "kintone-get-process-management",
      "kintone-get-record-comments",
      "kintone-get-records",
    ]);
  });

  it("削除系は capability を満たしても ALLOW_DESTRUCTIVE なしでは公開しない", () => {
    const withoutDestructive: ToolCapabilities = { ...ALL_ENABLED, allowDestructive: false };
    for (const name of DESTRUCTIVE_TOOL_NAMES) {
      expect(shouldExposeTool(name, "password", ALL_ENABLED)).toBe(true);
      expect(shouldExposeTool(name, "password", withoutDestructive)).toBe(false);
    }
  });

  it("未知のツール名は公開しない", () => {
    expect(shouldExposeTool("kintone-something-new", "password", ALL_ENABLED)).toBe(false);
  });

  it("一覧に載る定義に annotations が付く", () => {
    const definition = toolDefinitionWithAnnotations(tools[0]!);
    expect(definition.annotations).toBeDefined();
    expect(definition.annotations).toHaveProperty("readOnlyHint");
    expect(definition.annotations).toHaveProperty("destructiveHint");
  });
});

describe("createRemoteServer の tools/list", () => {
  /** 実際に MCP クライアントを繋いで tools/list を取る */
  const listTools = async (capabilities: ToolCapabilities) => {
    const server = createRemoteServer({
      name: "kintone-remote-mcp",
      version: "0.1.0",
      client: fakeClient,
      authMode: "oauth",
      capabilities,
    });
    const client = new Client({ name: "test", version: "0.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const result = await client.listTools();
    await client.close();
    await server.close();
    return result.tools;
  };

  it("annotations が実際の応答に載る", async () => {
    // registerTool の config に渡すだけでは消える（一覧ハンドラを上書きしているため）。
    // 「マージしたつもり」で落ちないよう、応答そのものを見る。
    const listed = await listTools(DEFAULT_CAPABILITIES);
    expect(listed.length).toBeGreaterThan(0);
    for (const tool of listed) {
      expect(tool.annotations, `${tool.name} に annotations が無い`).toBeDefined();
    }
  });

  it("読み取り専用ツールに readOnlyHint が立つ", async () => {
    const listed = await listTools(DEFAULT_CAPABILITIES);
    const getRecords = listed.find((t) => t.name === "kintone-get-records");
    expect(getRecords?.annotations?.readOnlyHint).toBe(true);
    expect(getRecords?.annotations?.destructiveHint).toBe(false);
  });

  it("ポリシーで落としたツールは一覧に出ない", async () => {
    const listed = await listTools(DEFAULT_CAPABILITIES);
    expect(listed.map((t) => t.name)).not.toContain("kintone-delete-records");
    expect(listed.map((t) => t.name)).not.toContain("kintone-search");
  });

  it("ツールが0件でも tools/list がエラーにならない", async () => {
    // capability を全部 false にすると registerTool が1度も呼ばれない。
    // capability 宣言を自前で入れていないと "Method not found" になる。
    const none: ToolCapabilities = {
      recordRead: false, recordWrite: false, appRead: false, appWrite: false,
      spaceRead: false, spaceWrite: false, search: false, fileDownload: false,
      allowDestructive: false,
    };
    await expect(listTools(none)).resolves.toEqual([]);
  });
});

describe("同意の記録が無い接続に許す範囲", () => {
  /**
   * ⚠ **分類表から導出すると、上流がツールを追加するたびに増える。**
   *
   * `Object.keys(CAPABILITY_OF)` から作っていたので、
   * 書き込みツールを1件足すと旧接続の許可集合にも入った
   * （外部レビューで再現された）。それは「移行時点で確定した範囲」ではなく、
   * 形を変えた白紙同意になる。
   *
   * ここは**過去の記録**なので、名前を直に並べてある。
   * このテストが守るのは、その記録が**動かないこと**。
   */
  it("移行時点の20件から動いていない", () => {
    expect([...LEGACY_CONSENTED_TOOLS].sort()).toEqual(
      [
        "kintone-add-app",
        "kintone-add-form-fields",
        "kintone-add-record-comment",
        "kintone-add-records",
        "kintone-deploy-app",
        "kintone-download-file",
        "kintone-get-app",
        "kintone-get-app-deploy-status",
        "kintone-get-apps",
        "kintone-get-form-fields",
        "kintone-get-form-layout",
        "kintone-get-general-settings",
        "kintone-get-process-management",
        "kintone-get-record-comments",
        "kintone-get-records",
        "kintone-update-form-fields",
        "kintone-update-form-layout",
        "kintone-update-general-settings",
        "kintone-update-records",
        "kintone-update-statuses",
      ].sort(),
    );
  });

  it("削除と、連携ユーザーとして動くものを含まない", () => {
    // 復旧不能な操作と、主体が入れ替わる操作は、繋ぎ直して同意し直す
    for (const name of [...DESTRUCTIVE_TOOL_NAMES, ...OAUTH_UNSUPPORTED_TOOL_NAMES]) {
      expect(LEGACY_CONSENTED_TOOLS, `${name} が旧接続に許されている`).not.toContain(name);
    }
  });

  it("上流に存在しない名前が残っていない", () => {
    // 改名されると、記録した名前が誰にも当たらなくなる。
    // その場合の正しい対応は「新しい名前を足す」ではなく、繋ぎ直させること
    for (const name of LEGACY_CONSENTED_TOOLS) {
      expect(CLASSIFIED_TOOL_NAMES, `${name} は上流に無い`).toContain(name);
    }
  });
});

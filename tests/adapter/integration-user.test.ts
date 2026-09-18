import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { KintoneRestAPIClient } from "@kintone/rest-api-client";

import { createRemoteServer } from "../../src/adapter/createRemoteServer.js";
import {
  DEFAULT_CAPABILITIES,
  executesAsIntegrationUser,
  shouldExposeTool,
} from "../../src/adapter/toolPolicy.js";
import { parseAllowedAppIds } from "../../src/adapter/appScope.js";

/**
 * OAuth で実行できない5ツールを、連携用ユーザーとして実行する (§5)。
 *
 * ⚠ **主体が入れ替わる。** これらは接続した本人ではなく、
 * 設定された連携ユーザーの権限で動く。
 * 本人が見られないものにも手が届くので、境界を間違えると権限昇格になる。
 */

const SPACE_TOOLS = [
  "kintone-get-space",
  "kintone-update-space",
  "kintone-delete-space",
  "kintone-add-space-from-template",
];

const withSpaces = {
  ...DEFAULT_CAPABILITIES,
  spaceRead: true,
  spaceWrite: true,
  search: true,
  allowDestructive: true,
};

describe("どちらの資格情報で実行するか", () => {
  it("OAuth で実行できない5ツールだけが連携ユーザー", () => {
    for (const name of [...SPACE_TOOLS, "kintone-search"]) {
      expect(executesAsIntegrationUser(name, "oauth"), name).toBe(true);
    }
  });

  it("それ以外は本人のまま", () => {
    // ⚠ ここが崩れると、**通常の操作まで連携ユーザーの権限で動く**
    for (const name of ["kintone-get-records", "kintone-add-records", "kintone-get-apps"]) {
      expect(executesAsIntegrationUser(name, "oauth"), name).toBe(false);
    }
  });
});

describe("公開するかどうか", () => {
  it("連携ユーザーがいなければ、5ツールは出さない", () => {
    for (const name of [...SPACE_TOOLS, "kintone-search"]) {
      expect(shouldExposeTool(name, "oauth", withSpaces), name).toBe(false);
    }
  });

  it("連携ユーザーがいれば出す", () => {
    for (const name of SPACE_TOOLS) {
      expect(shouldExposeTool(name, "oauth", withSpaces, { integrationUser: true }), name).toBe(
        true,
      );
    }
  });

  it("capability が無ければ、連携ユーザーがいても出さない", () => {
    // 連携ユーザーを置いただけで勝手に増えない
    expect(
      shouldExposeTool("kintone-get-space", "oauth", DEFAULT_CAPABILITIES, {
        integrationUser: true,
      }),
    ).toBe(false);
  });

  it("削除は ALLOW_DESTRUCTIVE が無ければ出さない", () => {
    const noDestructive = { ...withSpaces, allowDestructive: false };

    expect(
      shouldExposeTool("kintone-delete-space", "oauth", noDestructive, { integrationUser: true }),
    ).toBe(false);
  });

  it("アプリを絞っているときは、連携ユーザーのツールを1つも出さない", () => {
    // ⚠ **検索だけを止めても足りなかった**（外部レビューで指摘）。
    //
    // - `get-space` は `attachedApps` に**許可外アプリの名前と説明**を返す
    // - `delete-space` は**スペースに置かれた許可外アプリごと**使えなくする
    //
    // 最後のものは読み取りの漏れでは済まない。許可していないアプリのデータが失われる。
    for (const name of [...SPACE_TOOLS, "kintone-search"]) {
      expect(
        shouldExposeTool(name, "oauth", withSpaces, { integrationUser: true, appScoped: true }),
        `${name} がアプリ境界を越えられる`,
      ).toBe(false);
    }

    // 絞っていなければ出る
    for (const name of [...SPACE_TOOLS, "kintone-search"]) {
      expect(shouldExposeTool(name, "oauth", withSpaces, { integrationUser: true }), name).toBe(
        true,
      );
    }
  });

  it("アプリを絞っても、本人のツールは出る", () => {
    // 連携ユーザーのものだけを止める。通常の操作まで巻き込まない
    expect(
      shouldExposeTool("kintone-get-records", "oauth", withSpaces, {
        integrationUser: true,
        appScoped: true,
      }),
    ).toBe(true);
  });

});

describe("実際にどちらのクライアントが呼ばれるか", () => {
  const connect = async (options: { appScoped?: boolean } = {}) => {
    const calls: Array<{ by: "user" | "integration"; tool: string }> = [];
    const outcomes: Array<Record<string, unknown>> = [];

    const clientFor = (by: "user" | "integration") =>
      ({
        record: {
          getRecords: async () => {
            calls.push({ by, tool: "get-records" });
            return { records: [], totalCount: "0" };
          },
        },
        space: {
          getSpace: async () => {
            calls.push({ by, tool: "get-space" });
            return { id: "1", name: "s" };
          },
          updateSpace: async () => {
            calls.push({ by, tool: "update-space" });
            return {};
          },
        },
      }) as unknown as KintoneRestAPIClient;

    const server = createRemoteServer({
      name: "t",
      version: "0",
      client: clientFor("user"),
      integrationClient: clientFor("integration"),
      authMode: "oauth",
      capabilities: withSpaces,
      appScope: { allowedAppIds: parseAllowedAppIds(options.appScoped ? "10" : undefined) },
      // 同意の記録が無い接続はスペース操作を許さないので、明示する
      consentedTools: [...SPACE_TOOLS, "kintone-search", "kintone-get-records"],
      onToolOutcome: (outcome) => outcomes.push({ ...outcome }),
    });

    const mcp = new Client({ name: "t", version: "0" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(st), mcp.connect(ct)]);
    return {
      mcp,
      calls,
      outcomes,
      close: async () => {
        await mcp.close();
        await server.close();
      },
    };
  };

  it("公開範囲の変更は、kintone に届く前に止める", async () => {
    /**
     * ⚠ **述語の試験だけでは足りない。**
     * `assertArgumentsAllowed` が正しくても、ツールの実行経路に
     * 繋いでいなければ素通りする。**実際に呼んで、届いていないことを見る。**
     */
    const { mcp, calls, outcomes, close } = await connect();

    const result = await mcp.callTool({
      name: "kintone-update-space",
      arguments: { id: "1", isPrivate: false },
    });

    expect(result.isError, "公開範囲の変更が通っている").toBe(true);
    expect(calls, "kintone に届いている").toEqual([]);
    expect(
      outcomes.at(-1)?.failureKind,
      "許可リストの拒否と混ざっている（直し方が違う）",
    ).toBe("forbidden_argument");
    await close();
  });

  it("公開範囲以外の変更は通る", async () => {
    // 名前の変更まで巻き込まない。スペース名と公開範囲は別物
    const { mcp, calls, close } = await connect();

    await mcp.callTool({
      name: "kintone-update-space",
      arguments: { id: "1", name: "新しい名前" },
    });

    expect(calls, "通常の設定変更まで止めている").toEqual([
      { by: "integration", tool: "update-space" },
    ]);
    await close();
  });

  it("スペース操作は連携ユーザーのクライアントを使う", async () => {
    const { mcp, calls, close } = await connect();

    await mcp.callTool({ name: "kintone-get-space", arguments: { id: "1" } });

    expect(calls, "本人の資格情報でスペースを叩いている").toEqual([
      { by: "integration", tool: "get-space" },
    ]);
    await close();
  });

  it("通常のツールは本人のクライアントを使う", async () => {
    // ⚠ ここが崩れると、**全部が連携ユーザーの権限で動く**
    const { mcp, calls, close } = await connect();

    await mcp.callTool({ name: "kintone-get-records", arguments: { app: "10" } });

    expect(calls, "連携ユーザーの資格情報で通常の操作をしている").toEqual([
      { by: "user", tool: "get-records" },
    ]);
    await close();
  });

  it("監査ログに、対象のスペースが残る", async () => {
    // ⚠ **`targets: []` だった。** 共有の連携ユーザーが実行するのに、
    // 何を消したのかがログから分からない状態だった
    const { mcp, outcomes, close } = await connect();

    await mcp.callTool({ name: "kintone-get-space", arguments: { id: "42" } });

    expect(outcomes[0]!.targets, "対象のスペースが残っていない").toEqual(["space:42"]);
    await close();
  });

  it("アプリ ID とスペース ID を混ぜない", async () => {
    // 見分けがつかないと、監査で追うときに別物を追うことになる
    const { mcp, outcomes, close } = await connect();

    await mcp.callTool({ name: "kintone-get-records", arguments: { app: "42" } });

    expect(outcomes[0]!.targets).toEqual(["42"]);
    await close();
  });

  it("監査ログに、誰として実行したかが残る", async () => {
    // kintone 側の監査で連携ユーザーの操作を見たとき、
    // 誰の依頼だったのかを辿れるようにする
    const { mcp, outcomes, close } = await connect();

    await mcp.callTool({ name: "kintone-get-space", arguments: { id: "1" } });
    await mcp.callTool({ name: "kintone-get-records", arguments: { app: "10" } });

    expect(outcomes.map((o) => [o.toolName, o.identity])).toEqual([
      ["kintone-get-space", "integration"],
      ["kintone-get-records", "user"],
    ]);
    await close();
  });

  it("アプリを絞ると、連携ユーザーのツールは一覧に出ない", async () => {
    const { mcp, close } = await connect({ appScoped: true });

    const listed = await mcp.listTools();
    const names = listed.tools.map((t) => t.name);

    for (const name of [...SPACE_TOOLS, "kintone-search"]) {
      expect(names, `${name} が一覧に出ている`).not.toContain(name);
    }
    // 本人のツールは残る
    expect(names).toContain("kintone-get-records");
    await close();
  });
});

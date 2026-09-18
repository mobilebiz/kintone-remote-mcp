import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { KintoneRestAPIClient } from "@kintone/rest-api-client";

import { createRemoteServer } from "../../src/adapter/createRemoteServer.js";
import {
  CLASSIFIED_TOOL_NAMES,
  DEFAULT_CAPABILITIES,
  shouldExposeTool,
} from "../../src/adapter/toolPolicy.js";
import {
  assertArgumentsAllowed,
  enforcesAppBoundary,
  ForbiddenArgumentError,
  parseAllowedAppIds,
} from "../../src/adapter/appScope.js";

/**
 * アプリ単位の境界 (§5)。
 *
 * OAuth のスコープは操作種別の区分でしかないので、本人が見られる全アプリが
 * Claude に開く。初版では「アプリ単位の API トークンがこの制御を担う」と
 * 書いていたが、OAuth への変更でその前提は消えた。
 *
 * 引数名が `appId` / `app` / `apps[]` の3種類あり、`kintone-get-apps` は
 * 引数を持たない。**どれか1つでも見落とすと迂回経路になる。**
 */

const ALLOWED = parseAllowedAppIds("10,20");

/** 上流の出力スキーマを満たす最小のアプリ情報 */
const appInfo = (appId: string, name: string) => ({
  appId,
  code: "",
  name,
  description: "",
  spaceId: null,
  threadId: null,
  createdAt: "2026-01-01T00:00:00Z",
  creator: { code: "u", name: "u" },
  modifiedAt: "2026-01-01T00:00:00Z",
  modifier: { code: "u", name: "u" },
});

/** 呼ばれた引数を記録しつつ、固定の結果を返すダミー */
const makeClient = (calls: Array<{ method: string; args: unknown }>) =>
  ({
    record: {
      getRecords: async (args: unknown) => {
        calls.push({ method: "getRecords", args });
        return { records: [], totalCount: "0" };
      },
      getRecordComments: async (args: unknown) => {
        calls.push({ method: "getRecordComments", args });
        return { comments: [], older: false, newer: false };
      },
    },
    app: {
      getApp: async (args: unknown) => {
        calls.push({ method: "getApp", args });
        return appInfo("10", "許可されたアプリ");
      },
      getApps: async (args: unknown) => {
        calls.push({ method: "getApps", args });
        return { apps: [appInfo("10", "許可"), appInfo("99", "許可外")] };
      },
      getDeployStatus: async (args: unknown) => {
        calls.push({ method: "getDeployStatus", args });
        return { apps: [] };
      },
      deployApp: async (args: unknown) => {
        calls.push({ method: "deployApp", args });
        return {};
      },
      getFormFields: async (args: unknown) => {
        calls.push({ method: "getFormFields", args });
        return { properties: {}, revision: "1" };
      },
    },
  }) as unknown as KintoneRestAPIClient;

/** 書き込みまで含めた capability（deploy-app を試すため） */
const ALL_ENABLED = {
  recordRead: true,
  recordWrite: true,
  appRead: true,
  appWrite: true,
  spaceRead: false,
  spaceWrite: false,
  search: false,
  fileDownload: false,
  allowDestructive: false,
};

const connect = async (
  allowedAppIds: ReadonlySet<string> | undefined,
  capabilities = DEFAULT_CAPABILITIES,
) => {
  const calls: Array<{ method: string; args: unknown }> = [];
  const server = createRemoteServer({
    name: "kintone-remote-mcp",
    version: "0.1.0",
    client: makeClient(calls),
    authMode: "oauth",
    capabilities,
    appScope: { allowedAppIds },
  });
  const mcp = new Client({ name: "test", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), mcp.connect(clientTransport)]);
  return {
    mcp,
    calls,
    close: async () => {
      await mcp.close();
      await server.close();
    },
  };
};

describe("引数のアプリ ID", () => {
  it("`app` を使うツールで許可外を拒否する", async () => {
    const { mcp, calls, close } = await connect(ALLOWED);

    const result = await mcp.callTool({
      name: "kintone-get-records",
      arguments: { app: "99" },
    });

    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain("app_not_allowed");
    // **kintone に問い合わせていないこと**。拒否したのに叩いていたら意味がない
    expect(calls).toHaveLength(0);
    await close();
  });

  it("`appId` を使うツール（kintone-get-app）でも拒否する", async () => {
    // `app` だけを見る実装にすると、ここが素通りする。
    const { mcp, calls, close } = await connect(ALLOWED);

    const result = await mcp.callTool({
      name: "kintone-get-app",
      arguments: { appId: "99" },
    });

    expect(result.isError).toBe(true);
    expect(calls).toHaveLength(0);
    await close();
  });

  it("`apps[]` を使うツールは全要素を見る", async () => {
    // 1つでも許可外なら拒否する。混ぜれば通る、を作らない。
    const { mcp, calls, close } = await connect(ALLOWED);

    const result = await mcp.callTool({
      name: "kintone-get-app-deploy-status",
      arguments: { apps: ["10", "99"] },
    });

    expect(result.isError, "許可内と許可外を混ぜたら通ってしまった").toBe(true);
    expect(calls).toHaveLength(0);
    await close();
  });

  it("`apps[].app`（オブジェクトの配列）を使う deploy-app でも拒否する", async () => {
    // ⚠ `get-app-deploy-status` と同じ `apps` という名前だが、
    // `deploy-app` は [{app:"99"}] というオブジェクトの配列。
    // 文字列・数値だけを見る実装だと**素通りする**（実際にそうなっていた）。
    const { mcp, calls, close } = await connect(ALLOWED, ALL_ENABLED);

    const result = await mcp.callTool({
      name: "kintone-deploy-app",
      arguments: { apps: [{ app: "10" }, { app: "99" }] },
    });

    expect(result.isError, "オブジェクト配列が素通りしている").toBe(true);
    expect(JSON.stringify(result)).toContain("app_not_allowed");
    expect(calls, "拒否したのに kintone を叩いている").toHaveLength(0);
    await close();
  });

  it("deploy-app で許可されたアプリだけなら通る", async () => {
    const { mcp, calls, close } = await connect(ALLOWED, ALL_ENABLED);

    const result = await mcp.callTool({
      name: "kintone-deploy-app",
      arguments: { apps: [{ app: "10" }, { app: "20" }] },
    });

    expect(result.isError).toBeFalsy();
    expect(calls).toHaveLength(1);
    await close();
  });

  it("kintone-get-apps の `ids[]` を問い合わせ前に検査する", async () => {
    // 「引数が無い」という前提が誤りだった。結果の絞り込みだけに頼ると、
    // 「許可外は問い合わせる前に拒否する」が成立しない。
    const { mcp, calls, close } = await connect(ALLOWED);

    const result = await mcp.callTool({
      name: "kintone-get-apps",
      arguments: { ids: ["10", "99"] },
    });

    expect(result.isError).toBe(true);
    expect(calls, "許可外 ID を上流へ送っている").toHaveLength(0);
    await close();
  });

  it("kintone-get-apps は ids を省略すれば結果側で絞る", async () => {
    const { mcp, calls, close } = await connect(ALLOWED);

    const result = await mcp.callTool({ name: "kintone-get-apps", arguments: {} });

    expect(result.isError).toBeFalsy();
    expect(calls).toHaveLength(1);
    await close();
  });

  it("許可されたアプリは通る", async () => {
    const { mcp, calls, close } = await connect(ALLOWED);

    const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "10" } });

    expect(result.isError).toBeFalsy();
    expect(calls).toHaveLength(1);
    await close();
  });

  it("数値で指定されても同じ判定になる", async () => {
    const { mcp, close } = await connect(ALLOWED);

    const denied = await mcp.callTool({
      name: "kintone-get-app-deploy-status",
      arguments: { apps: [99] },
    });

    expect(denied.isError).toBe(true);
    await close();
  });

  it("許可リスト未設定なら制限しない", async () => {
    const { mcp, calls, close } = await connect(undefined);

    const result = await mcp.callTool({ name: "kintone-get-records", arguments: { app: "99" } });

    expect(result.isError).toBeFalsy();
    expect(calls).toHaveLength(1);
    await close();
  });
});

describe("一覧の結果", () => {
  it("kintone-get-apps の結果を許可リストで絞る", async () => {
    // 引数にアプリ ID が無いので、結果側で絞るしかない。
    const { mcp, close } = await connect(ALLOWED);

    const result = await mcp.callTool({ name: "kintone-get-apps", arguments: {} });
    const structured = result.structuredContent as { apps: Array<{ appId: string }> };

    expect(structured.apps.map((a) => a.appId)).toEqual(["10"]);
    await close();
  });

  it("structuredContent と content[].text の両方が絞られる", async () => {
    // ⚠ 上流は同じデータを両方に入れて返す。片方だけ絞ると、もう片方から漏れる。
    const { mcp, close } = await connect(ALLOWED);

    const result = await mcp.callTool({ name: "kintone-get-apps", arguments: {} });
    const text = (result.content as Array<{ type: string; text: string }>)[0]!.text;

    expect(text).not.toContain("許可外");
    expect(text).not.toContain('"99"');
    expect(text).toContain("許可");
    await close();
  });

  it("許可リスト未設定なら絞らない", async () => {
    const { mcp, close } = await connect(undefined);

    const result = await mcp.callTool({ name: "kintone-get-apps", arguments: {} });
    const structured = result.structuredContent as { apps: Array<{ appId: string }> };

    expect(structured.apps.map((a) => a.appId)).toEqual(["10", "99"]);
    await close();
  });
});

describe("許可リストの解釈", () => {
  it("カンマ区切りを読み、空白を落とす", () => {
    expect([...parseAllowedAppIds("10, 20 ,30")!]).toEqual(["10", "20", "30"]);
  });

  it("未設定と空文字は「制限なし」", () => {
    // 空文字を「1つも許可しない」と読むと、設定ミスで全ツールが黙って死ぬ。
    // 制限なしとして扱い、その旨をドキュメントに書く方針 (§5)。
    expect(parseAllowedAppIds(undefined)).toBeUndefined();
    expect(parseAllowedAppIds("")).toBeUndefined();
    expect(parseAllowedAppIds("  ,  ")).toBeUndefined();
  });
});

describe("境界を課せないツール", () => {
  /**
   * ⚠ **`assertAppAllowed` は、取り出し方の定義が無いツールを素通りさせる。**
   *
   * 拒否しているように見えて、実際には何も見ていない。
   * 連携ユーザーのものだけを止めていたので、次の2つが漏れていた
   * （外部レビューで再現された）:
   *
   * - `kintone-add-app`: 許可リストが `{"1"}` でも、**積が空でも**アプリを作れた
   * - `kintone-download-file`: `fileKey` だけで**どのアプリの添付でも**落とせた
   */
  const ALL_ON = {
    ...DEFAULT_CAPABILITIES,
    recordWrite: true,
    appWrite: true,
    spaceRead: true,
    spaceWrite: true,
    search: true,
    fileDownload: true,
    allowDestructive: true,
  };

  /** 境界を課せないもの。**増えるときは、必ずここに現れる** */
  const UNBOUNDED = [
    "kintone-add-app",
    "kintone-download-file",
    "kintone-get-space",
    "kintone-update-space",
    "kintone-add-space-from-template",
    "kintone-delete-space",
    "kintone-search",
  ];

  it("境界を課せるものと課せないものが、意図どおりに分かれている", () => {
    const unbounded = CLASSIFIED_TOOL_NAMES.filter((name) => !enforcesAppBoundary(name));

    expect([...unbounded].sort(), "分類が変わっている。意図した変更か確かめること").toEqual(
      [...UNBOUNDED].sort(),
    );
  });

  it("アプリを絞っているときは、1つも公開しない", () => {
    for (const name of UNBOUNDED) {
      expect(
        shouldExposeTool(name, "oauth", ALL_ON, { integrationUser: true, appScoped: true }),
        `${name} がアプリ境界を越えられる`,
      ).toBe(false);
    }
  });

  it("絞っていなければ公開する", () => {
    // 境界が無いときまで止めない。止めると「絞ると機能が増える」ことになる
    for (const name of UNBOUNDED) {
      expect(shouldExposeTool(name, "oauth", ALL_ON, { integrationUser: true }), name).toBe(true);
    }
  });

  it("課せるものは、絞っていても公開する", () => {
    for (const name of CLASSIFIED_TOOL_NAMES.filter((n) => enforcesAppBoundary(n))) {
      expect(
        shouldExposeTool(name, "oauth", ALL_ON, { integrationUser: true, appScoped: true }),
        `${name} まで巻き込んでいる`,
      ).toBe(true);
    }
  });
});

describe("引数そのものを拒否する", () => {
  /**
   * ⚠ **「書き込み」をひとかたまりで扱えない例。**
   *
   * `kintone-update-space` は `isPrivate` を受け取るので、
   * **非公開スペースを公開に切り替えられる**。削除ではないので
   * `ALLOW_DESTRUCTIVE` では止まらず、`ENABLE_SPACE_WRITE=true` に含まれてしまう。
   *
   * データは消えないが、**見えなかったものが全社に見えるようになる**。
   * 消えるより気づきにくい。
   */
  it("公開範囲の変更を拒否する", () => {
    expect(() =>
      assertArgumentsAllowed("kintone-update-space", { id: "1", isPrivate: false }),
    ).toThrow(ForbiddenArgumentError);
  });

  it("非公開にする方向も拒否する", () => {
    // ⚠ **値では分けない。** 「非公開にするのは安全」とすると、
    // 現在値を読まないと影響が分からず、説明も試験も複雑になる
    expect(() =>
      assertArgumentsAllowed("kintone-update-space", { id: "1", isPrivate: true }),
    ).toThrow(ForbiddenArgumentError);
  });

  it("他の設定変更は通す", () => {
    // 名前の変更まで巻き込まない。スペース名と公開範囲は別物
    expect(() =>
      assertArgumentsAllowed("kintone-update-space", { id: "1", name: "新しい名前" }),
    ).not.toThrow();
  });

  it("指定されていなければ通す", () => {
    // 明示的な undefined は「変更の意図が無い」
    expect(() =>
      assertArgumentsAllowed("kintone-update-space", { id: "1", isPrivate: undefined }),
    ).not.toThrow();
  });

  it("他のツールの同名引数は巻き込まない", () => {
    // 作成時の isPrivate は、既存の公開範囲を変えるものではない
    expect(() =>
      assertArgumentsAllowed("kintone-add-space-from-template", { id: "1", isPrivate: false }),
    ).not.toThrow();
  });
});

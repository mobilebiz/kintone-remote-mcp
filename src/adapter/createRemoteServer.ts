import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { Tool as McpTool } from "@modelcontextprotocol/sdk/types.js";
import type { KintoneRestAPIClient } from "@kintone/rest-api-client";

import { tools, createToolCallback } from "@kintone/mcp-server/dist/tools/index.js";
import type { UpstreamTool } from "@kintone/mcp-server/dist/tools/index.js";
import { shouldEnableTool } from "@kintone/mcp-server/dist/server/tool-filters.js";
import { buildToolDefinition } from "@kintone/mcp-server/dist/server/tool-definitions.js";

import {
  withErrorBoundary,
  type ToolFailure,
  type ToolOutcome,
} from "./errorBoundary.js";
import {
  assertAppAllowed,
  assertArgumentsAllowed,
  extractTargets,
  filterAppListResult,
  type AppScope,
} from "./appScope.js";

import {
  annotationsFor,
  executesAsIntegrationUser,
  LEGACY_CONSENTED_TOOLS,
  shouldExposeTool,
  type ExposureContext,
  type KintoneAuthMode,
  type ToolCapabilities,
} from "./toolPolicy.js";

/**
 * リモート用の McpServer を組み立てる。
 *
 * **上流の `createServer()` は使わない。**
 * あれは内部で `getKintoneClient()` を呼ぶが、その実装が
 * プロセス単位のシングルトンで、2回目以降は渡した設定を無視する:
 *
 *   let client = null;
 *   export const getKintoneClient = (config) => { if (client) return client; ... }
 *
 * 接続ごとに別の資格情報で kintone を叩くこの構成では、
 * **2人目以降が1人目のトークンで API を叩く**ことになる。
 * したがってクライアントは呼び出し側で生成して渡す。
 *
 * 借りるのは上流のツール定義と JSON Schema 生成だけで、
 * 組み立てはこちらで持つ。
 */
export type RemoteServerOptions = {
  name: string;
  version: string;
  /** 呼び出し側が生成した kintone クライアント。接続ごとに別インスタンス */
  client: KintoneRestAPIClient;
  /**
   * 連携用ユーザー（パスワード認証）のクライアント。
   *
   * OAuth では実行できない5ツールだけがこれを使う。
   *
   * ⚠ **本人のクライアントと必ず別インスタンスにする。**
   * kintone は認証方式に優先順位があり、**パスワード認証が OAuth より優先**される。
   * 1つのクライアントに両方のヘッダーを載せると、
   * **すべての操作が連携ユーザーとして実行される**ことになる。
   *
   * ⚠ **これを使うツールは、接続した本人の権限では動かない。**
   */
  integrationClient?: KintoneRestAPIClient;
  /** kintone への認証方式。公開するツールが変わる */
  authMode: KintoneAuthMode;
  capabilities: ToolCapabilities;
  /**
   * アプリ単位の境界 (§5)。
   *
   * OAuth のスコープは操作種別の区分でしかないので、
   * 「どのアプリまで」はここで絞る。未設定なら**本人が触れる全アプリが対象**。
   */
  appScope?: AppScope;
  /**
   * この接続が**同意した**ツール。
   *
   * ⚠ **現在の設定との積を取る。** 設定を後から広げても、
   * 同意していない操作が既存の接続に付いてはいけない
   * （`ALLOW_DESTRUCTIVE` を有効にすると、削除に同意していない接続に
   * 削除権限が付いていた。外部レビューで再現された）。
   *
   * `undefined` は「記録が無い接続」。同意の仕組みを入れる前に作られたもの。
   * **現在の設定をそのまま受け入れない** — それは将来追加する権限への
   * 白紙同意になる。`LEGACY_CONSENTED_TOOLS`（移行時点で確定した範囲）を使う。
   */
  consentedTools?: string[] | undefined;
  /** ツール失敗をサーバー側のログに残すフック。秘密は渡らない (errorBoundary) */
  onToolFailure?: (failure: ToolFailure) => void;
  /** 応答とログで**同じ** ID を使うために、リクエストの相関 ID を渡す */
  correlationId?: string;
  /**
   * ツール実行の結果を監査ログへ渡すフック (§7.5)。
   *
   * **成否によらず1回呼ばれる。** 失敗だけを記録すると、
   * 「何回呼ばれたか」も「どれだけ時間がかかったか」も分からない。
   * `targets` には対象のアプリ ID を入れる（**本文は入れない**）。
   */
  onToolOutcome?: (
    outcome: ToolOutcome & {
      targets: string[];
      /**
       * 誰として実行されたか。
       *
       * `integration` は**接続した本人ではなく連携ユーザー**として実行されたもの。
       * 後から切り分けられないと、kintone 側の監査と突き合わせられない。
       */
      identity: "user" | "integration";
    },
  ) => void;
};

/**
 * 公開するツール定義を組み立てる（一覧とハンドラで同じ集合を使う）。
 *
 * 上流の `shouldEnableTool` も通す。あれは API トークン認証で実行できない
 * 7ツールを知っているので、こちらで二重に持たない。
 * ただし**あれは OAuth を知らない**（`isApiTokenAuth: false` に落ちる）ので、
 * OAuth で実行できない5ツールの除外は `shouldExposeTool` 側が担う。
 */
export const selectTools = (
  authMode: KintoneAuthMode,
  capabilities: ToolCapabilities,
  context: ExposureContext = {},
): UpstreamTool[] =>
  tools.filter(
    (tool) =>
      shouldEnableTool(tool.name, { isApiTokenAuth: authMode === "apiToken" }) &&
      shouldExposeTool(tool.name, authMode, capabilities, context),
  );

/**
 * `tools/list` に載せる定義。
 *
 * 上流の `buildToolDefinition` は annotations を落とすので、ここでマージする。
 * これを忘れると、クライアントは全ツールを「破壊的かどうか不明」として扱う。
 */
export const toolDefinitionWithAnnotations = (tool: UpstreamTool): McpTool => ({
  ...buildToolDefinition(tool),
  annotations: annotationsFor(tool.name),
});

export const createRemoteServer = (options: RemoteServerOptions): McpServer => {
  const server = new McpServer({ name: options.name, version: options.version });
  const allowedNow = selectTools(options.authMode, options.capabilities, {
    integrationUser: options.integrationClient !== undefined,
    appScoped: options.appScope?.allowedAppIds !== undefined,
  });

  /**
   * 同意した範囲との積。
   *
   * ⚠ **設定を広げても、既存の接続には及ばない。**
   * 記録が無い接続だけは、現在の設定のまま扱う（機能を入れる前のもの）。
   */
  // 記録が無い接続は、移行時点で確定した範囲まで。現在の設定を丸ごと渡さない
  const consented = options.consentedTools ?? LEGACY_CONSENTED_TOOLS;
  const enabled = allowedNow.filter((tool) => consented.includes(tool.name));

  const appScope: AppScope = options.appScope ?? { allowedAppIds: undefined };

  /**
   * 監査ログへ渡す対象 ID の受け渡し。
   *
   * このサーバーは**接続ごとに作られ、1本のトランスポートしか持たない**ので、
   * ツール名をキーに直前の呼び出しを覚えておけば足りる。
   * 複数接続で共有される構造になったら、この前提は崩れる。
   */
  const lastTargets = new Map<string, string[]>();

  for (const tool of enabled) {
    // ⚠ ツールごとに、どちらの資格情報で実行するかを決める。
    // 混ぜない（片方のクライアントに両方のヘッダーを載せない）
    const asIntegration = executesAsIntegrationUser(tool.name, options.authMode);
    const client = asIntegration ? options.integrationClient : options.client;
    if (!client) {
      /**
       * 公開の判断と食い違っている。**黙って本人の資格情報で実行しない。**
       *
       * ⚠ **いまは到達しない。** 公開の判断 (`selectTools`) も、ここでの選択も、
       * `options.integrationClient` の有無という同じ条件から導いているため、
       * 片方だけが真になることがない。
       * したがって**この分岐を落とすテストは書けない**（変異検査で確認）。
       *
       * それでも残すのは、2つの判断が将来ずれたときに、
       * **静かに権限が広がるのではなく、はっきり壊れてほしい**から。
       */
      throw new Error(`連携用のクライアントが無いまま ${tool.name} を公開しようとしました`);
    }
    const run = createToolCallback(tool.callback, { client });

    // アプリ境界は**呼び出しの前後**に挟む。
    // 前: 引数で指定されたアプリが許可されているか
    // 後: 一覧系の結果を絞る（引数にアプリ ID が無いため）
    const scoped = async (args: Record<string, unknown>) => {
      // 監査ログの対象 ID。境界の判定と同じ抽出を使う（2箇所で書かない）
      lastTargets.set(tool.name, extractTargets(tool.name, args));
      // ⚠ **境界より先に見る。** 公開範囲の変更は、アプリを絞っていなくても通さない
      assertArgumentsAllowed(tool.name, args);
      assertAppAllowed(tool.name, args, appScope);
      const result = await run(args);
      return filterAppListResult(tool.name, result, appScope);
    };

    server.registerTool(
      tool.name,
      tool.config as never,
      // 例外をここで詰め替える。包まないと、kintone クライアントの例外に
      // 含まれる資格情報が MCP の応答としてクライアントへ返る。
      withErrorBoundary(tool.name, scoped, {
        onFailure: options.onToolFailure,
        correlationId: options.correlationId,
        onOutcome: options.onToolOutcome
          ? (outcome) =>
              options.onToolOutcome?.({
                ...outcome,
                targets: lastTargets.get(tool.name) ?? [],
                // 誰として実行されたか。連携ユーザーの操作を後から切り分けられるようにする
                identity: asIntegration ? "integration" : "user",
              })
          : undefined,
      }) as never,
    );
  }

  /**
   * 一覧のハンドラを上書きする。
   *
   * 理由は2つあり、どちらも外せない:
   *  - SDK の `registerTool` は draft-07 の JSON Schema を出すが、
   *    SEP-1613 のクライアントは 2020-12 を要求する（上流が同じ理由で上書きしている）
   *  - annotations をここでマージする
   *
   * **ツールが0件でも tools capability を宣言する。** 宣言しないと
   * `tools/list` が "Method not found" になり、疎通確認がプロトコルエラーで死ぬ。
   *
   * **`listChanged` は明示的に false にする。** `registerTool()` が
   * `{ tools: { listChanged: true } }` を立てており、あとから `{ tools: {} }` を
   * マージしても消えない（initialize 応答で `{"tools":{"listChanged":true}}` が
   * 出ることを確認済み）。この構成はステートレスで通知を送れないので、
   * 送れないものを広告してはいけない。
   */
  server.server.registerCapabilities({ tools: { listChanged: false } });
  server.server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: enabled.map(toolDefinitionWithAnnotations),
  }));

  return server;
};

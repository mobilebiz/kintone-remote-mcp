/**
 * 上流 `@kintone/mcp-server` の dist に対する型宣言。
 *
 * 上流は `tsconfig.json` の `"declaration": true` をコメントアウトしたままなので、
 * **配布物に `.d.ts` が入っていない**（node_modules で確認済み）。
 * strict な TypeScript から deep import するには、こちらで宣言を置くしかない。
 *
 * `package.json` に `exports` フィールドが無いため deep import 自体は可能で、
 * `dist/tools/index.js` を読んでも上流の `config/index.ts`（モジュールロード時に
 * 環境変数を検証して throw する）は踏まない。これは実測で確認している
 * （環境変数を一切設定せずに import が通る）。
 *
 * **この宣言は上流の実装に依存する。** ズレたら `tests/adapter/upstream-contract.test.ts`
 * が落ちるようにしてある。宣言を足すときは必ず対応する検証も足すこと。
 */

declare module "@kintone/mcp-server/dist/tools/index.js" {
  import type { KintoneRestAPIClient } from "@kintone/rest-api-client";
  import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

  /** 上流のツール callback に渡される実行時オプション */
  export type ToolCallbackOptions = {
    client: KintoneRestAPIClient;
    attachmentsDir?: string;
  };

  /**
   * ツール定義。
   *
   * `config.inputSchema` / `outputSchema` は Zod の raw shape
   * （`ZodRawShape` = Record<string, ZodType>）で、SDK の `registerTool` と
   * 上流の `buildToolDefinition` の両方がこれを受け取る。
   * こちらは中身を解釈しないので `unknown` のまま通す。
   */
  export type UpstreamTool = {
    name: string;
    config: {
      title: string;
      description: string;
      inputSchema: Record<string, unknown>;
      outputSchema: Record<string, unknown>;
    };
    callback: (
      args: Record<string, unknown>,
      extra: ToolCallbackOptions,
    ) => CallToolResult | Promise<CallToolResult>;
  };

  export const tools: UpstreamTool[];

  export function createToolCallback(
    callback: UpstreamTool["callback"],
    options: ToolCallbackOptions,
  ): (args: Record<string, unknown>) => CallToolResult | Promise<CallToolResult>;
}

declare module "@kintone/mcp-server/dist/server/tool-filters.js" {
  /**
   * 上流のフィルタ条件。
   *
   * **見ているのは `isApiTokenAuth` だけ。** OAuth という概念を持たないので、
   * OAuth 接続では `false` になり、上流は27ツールすべてを有効と判定する。
   * OAuth で実行できない5ツールの除外は、こちらの `toolPolicy` が担う。
   */
  export type Condition = { isApiTokenAuth: boolean };
  export function shouldEnableTool(toolName: string, condition: Condition): boolean;
}

declare module "@kintone/mcp-server/dist/server/tool-definitions.js" {
  import type { Tool as McpTool } from "@modelcontextprotocol/sdk/types.js";
  import type { UpstreamTool } from "@kintone/mcp-server/dist/tools/index.js";

  /**
   * JSON Schema 2020-12 でツール定義を組み立てる。
   *
   * **返すのは name / title / description / inputSchema / outputSchema の5つだけで、
   * `annotations` は落ちる。** 実測で確認済み。
   * `registerTool` の config に annotations を渡しても、一覧を上書きする以上
   * ここの戻り値しか外には出ない。→ `toolPolicy.annotationsFor()` でマージする。
   */
  export function buildToolDefinition(tool: UpstreamTool): McpTool;
}

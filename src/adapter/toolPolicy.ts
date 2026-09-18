import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

import { enforcesAppBoundary } from "./appScope.js";

/**
 * どのツールを公開するかを決める層。
 *
 * 判断は3つの掛け合わせで、**どれか1つでも落ちれば公開しない**。
 *
 *   1. kintone の認証方式で技術的に実行できるか (§4.10)
 *   2. サーバーの capability 設定で許可されているか (§5)
 *   3. 破壊的操作なら ALLOW_DESTRUCTIVE があるか (§5)
 *
 * 最終的に何ができるかを決めるのは kintone 側の権限で、ここはその手前に置く上限。
 */

/** kintone への認証方式。上流の `isApiTokenAuth` より細かく持つ必要がある */
export type KintoneAuthMode = "oauth" | "apiToken" | "password";

/** capability フラグ。既定はすべて読み取りのみ (§5) */
export type ToolCapabilities = {
  recordRead: boolean;
  recordWrite: boolean;
  appRead: boolean;
  appWrite: boolean;
  spaceRead: boolean;
  spaceWrite: boolean;
  search: boolean;
  fileDownload: boolean;
  allowDestructive: boolean;
};

export const DEFAULT_CAPABILITIES: ToolCapabilities = {
  recordRead: true,
  recordWrite: false,
  appRead: true,
  appWrite: false,
  spaceRead: false,
  spaceWrite: false,
  search: false,
  fileDownload: false,
  allowDestructive: false,
};

export type Capability = Exclude<keyof ToolCapabilities, "allowDestructive">;

/** ツール名 → 必要な capability。上流の27ツールを漏れなく分類する */
const CAPABILITY_OF: Record<string, Capability> = {
  "kintone-get-records": "recordRead",
  "kintone-get-record-comments": "recordRead",

  "kintone-add-records": "recordWrite",
  "kintone-update-records": "recordWrite",
  "kintone-update-statuses": "recordWrite",
  "kintone-add-record-comment": "recordWrite",
  "kintone-delete-records": "recordWrite",

  "kintone-get-app": "appRead",
  "kintone-get-apps": "appRead",
  "kintone-get-form-fields": "appRead",
  "kintone-get-form-layout": "appRead",
  "kintone-get-general-settings": "appRead",
  "kintone-get-process-management": "appRead",
  "kintone-get-app-deploy-status": "appRead",

  "kintone-add-app": "appWrite",
  "kintone-add-form-fields": "appWrite",
  "kintone-update-form-fields": "appWrite",
  "kintone-update-form-layout": "appWrite",
  "kintone-update-general-settings": "appWrite",
  "kintone-deploy-app": "appWrite",
  "kintone-delete-form-fields": "appWrite",

  "kintone-get-space": "spaceRead",
  "kintone-update-space": "spaceWrite",
  "kintone-add-space-from-template": "spaceWrite",
  "kintone-delete-space": "spaceWrite",

  "kintone-search": "search",
  "kintone-download-file": "fileDownload",
};

/**
 * 復旧不能な削除。
 *
 * capability を満たしていても `allowDestructive` が無ければ公開しない。
 * 「書き込みを許可した」ことと「消してよい」ことは別の判断 (§5)。
 */
const DESTRUCTIVE = new Set([
  "kintone-delete-records",
  "kintone-delete-form-fields",
  "kintone-delete-space",
]);

/**
 * OAuth では実行できないツール。
 *
 * **スコープが無いからではない。** これらの API は
 * パスワード認証／セッション認証しか受け付けない (§4.10)。
 * 上流の `shouldEnableTool` は `isApiTokenAuth` しか見ないため、
 * OAuth のときに27ツールすべてを通してしまう。ここで落とす。
 */
const OAUTH_UNSUPPORTED = new Set([
  "kintone-get-space",
  "kintone-update-space",
  "kintone-delete-space",
  "kintone-add-space-from-template",
  "kintone-search",
]);

/** 読み取り専用のツール（annotations 用） */
const READ_ONLY = new Set(
  Object.entries(CAPABILITY_OF)
    .filter(([, cap]) => cap === "recordRead" || cap === "appRead" || cap === "spaceRead" || cap === "search")
    .map(([name]) => name),
);

/**
 * 公開の判断に影響する、接続以外の事情。
 */
export type ExposureContext = {
  /**
   * 連携用ユーザー（パスワード認証）が設定されているか。
   *
   * OAuth で実行できない5ツールは、**このユーザーとして**実行される。
   * 接続した本人ではない。
   */
  integrationUser?: boolean;
  /** `ALLOWED_APP_IDS` でアプリを絞っているか */
  appScoped?: boolean;
};

/**
 * 連携用ユーザーとして実行されるツールか。
 *
 * ⚠ **これに該当するものは、接続した本人の権限では動かない。**
 * 連携ユーザーの権限で動くので、本人が見られないものにも手が届く。
 * 同意画面で明示し、監査ログにも実行主体を残す。
 */
export const executesAsIntegrationUser = (toolName: string, mode: KintoneAuthMode): boolean =>
  mode === "oauth" && OAUTH_UNSUPPORTED.has(toolName);

/** その認証方式で技術的に実行できるか */
export const isSupportedByAuthMode = (
  toolName: string,
  mode: KintoneAuthMode,
  context: ExposureContext = {},
): boolean => {
  if (mode !== "oauth") return true;
  if (!OAUTH_UNSUPPORTED.has(toolName)) return true;
  // 連携ユーザーがいれば、その資格情報で実行できる
  return context.integrationUser === true;
};

/**
 * 公開してよいツールか。
 *
 * **未知のツール名は公開しない。** 上流がツールを追加したとき、
 * 分類を忘れたものが黙って公開されるのを防ぐ（契約テストでも検出する）。
 */
export const shouldExposeTool = (
  toolName: string,
  mode: KintoneAuthMode,
  capabilities: ToolCapabilities,
  context: ExposureContext = {},
): boolean => {
  if (!isSupportedByAuthMode(toolName, mode, context)) return false;

  const capability = CAPABILITY_OF[toolName];
  if (capability === undefined) return false;
  if (!capabilities[capability]) return false;

  if (DESTRUCTIVE.has(toolName) && !capabilities.allowDestructive) return false;

  /**
   * ⚠ **アプリを絞っているときは、境界を課せないツールを1つも出さない。**
   *
   * `assertAppAllowed` は**引数からアプリ ID を取り出せないツールを素通りさせる**。
   * 拒否しているように見えて、実際には何も見ていない。
   * 「どのツールなら課せるか」は `appScope` が知っているので、そちらに訊く。
   * ここで名前を並べ直すと、取り出し方を足したときに片方だけ古くなる。
   *
   * 具体的に何が漏れるか（すべて外部レビューで再現された）:
   *
   * | ツール | 起きること |
   * | --- | --- |
   * | `kintone-search` | 許可外アプリのレコードが返る |
   * | `kintone-get-space` | `attachedApps` に**許可外アプリの名前と説明**が返る |
   * | `kintone-delete-space` | **スペースに置かれた許可外アプリごと**使えなくなる |
   * | `kintone-add-app` | 許可リストが `{"1"}` でも、**積が空でも**アプリを作れる |
   * | `kintone-download-file` | `fileKey` だけで**どのアプリの添付でも落とせる** |
   *
   * 3つめは読み取りの漏れでは済まない。**許可していないアプリのデータが
   * 失われる。** 返す情報と操作の影響範囲の両方を絞れるようになるまで、出さない。
   *
   * ⚠ **連携ユーザーの5ツールもこれに含まれる**（どれも引数にアプリ ID を持たない）。
   * 以前は連携ユーザーかどうかで判定していたが、それでは
   * `add-app` と `download-file` が漏れた。**主体ではなく、境界を課せるかで決める。**
   */
  if (context.appScoped === true && !enforcesAppBoundary(toolName)) return false;

  return true;
};

/**
 * ツールの annotations。
 *
 * 上流は annotations を持たず、`buildToolDefinition` も返さないので、
 * 一覧を組み立てる側でマージする (§2.1)。
 *
 * **これはクライアントへのヒントであって強制力は無い** (§5)。
 * 実際の制御は `shouldExposeTool` と kintone 側の権限で行う。
 */
export const annotationsFor = (toolName: string): ToolAnnotations => {
  const readOnly = READ_ONLY.has(toolName);
  return {
    readOnlyHint: readOnly,
    destructiveHint: DESTRUCTIVE.has(toolName),
    // kintone のドメイン内で閉じており、任意の外部へ出ていくことはない
    openWorldHint: false,
  };
};

/** そのツールが必要とする capability。未知なら undefined */
export const capabilityOf = (toolName: string): Capability | undefined => CAPABILITY_OF[toolName];

/** 復旧不能な削除か */
export const isDestructive = (toolName: string): boolean => DESTRUCTIVE.has(toolName);

/**
 * 同意の記録が無い接続に、それでも許す範囲。
 *
 * ⚠ **「現在の設定をすべて受け入れる」にしてはいけない。**
 * それは**将来追加する権限への白紙同意**になる。
 * 操作に同意していない接続に、後から書き込みや削除を有効にすると、
 * そのまま届いてしまう（外部レビューで再現された）。
 *
 * ⚠ **かといって「何も許さない」にもできない。**
 * 同意の仕組みを入れる前に繋いだ利用者が、全員その場で使えなくなる。
 *
 * → **移行時点で確定した範囲**を固定で持つ。
 * 復旧不能な操作（削除）と、主体が入れ替わる操作（連携ユーザー）は含めない。
 * それらを使うには繋ぎ直して同意し直す。
 *
 * ⚠ **分類表から導出してはいけない。名前を直に並べる。**
 * `Object.keys(CAPABILITY_OF)` から作っていたので、**上流がツールを追加すると
 * 旧接続の同意に自動で入った**（外部レビューで再現された）。
 * これは「移行時点で確定した範囲」ではなく、また別の形の白紙同意になる。
 *
 * ここは**過去の記録**であって、現在の分類の写しではない。
 * 増やしてよいのは、同じ日に繋いだ利用者が実際に使えていたものだけで、
 * それはもう増えない。
 */
export const LEGACY_CONSENTED_TOOLS: readonly string[] = [
  "kintone-get-records",
  "kintone-get-record-comments",
  "kintone-add-records",
  "kintone-update-records",
  "kintone-update-statuses",
  "kintone-add-record-comment",
  "kintone-get-app",
  "kintone-get-apps",
  "kintone-get-form-fields",
  "kintone-get-form-layout",
  "kintone-get-general-settings",
  "kintone-get-process-management",
  "kintone-get-app-deploy-status",
  "kintone-add-app",
  "kintone-add-form-fields",
  "kintone-update-form-fields",
  "kintone-update-form-layout",
  "kintone-update-general-settings",
  "kintone-deploy-app",
  "kintone-download-file",
];

/** 分類済みのツール名（契約テストが上流との差分を検出するのに使う） */
export const CLASSIFIED_TOOL_NAMES: readonly string[] = Object.keys(CAPABILITY_OF);
export const OAUTH_UNSUPPORTED_TOOL_NAMES: readonly string[] = [...OAUTH_UNSUPPORTED];
export const DESTRUCTIVE_TOOL_NAMES: readonly string[] = [...DESTRUCTIVE];

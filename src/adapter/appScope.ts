import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

/**
 * アプリ単位の境界。
 *
 * ## なぜ要るか
 *
 * OAuth のスコープは**操作種別の区分であって、対象アプリの区分ではない**。
 * `k:app_record:read` を許可すると、**その人が見られる全アプリのレコード**が
 * Claude に開く。
 *
 * 初版では「アプリ単位で発行される API トークンがこの制御を担う」と書いていたが、
 * OAuth へ変更した時点でその前提は消えた (§5)。代わりがこれ。
 *
 * ## 引数名が3種類ある
 *
 * 上流のツールを実際に読んで確かめたところ、アプリ ID の運ばれ方が揃っていない。
 * `app` だけを見る実装にすると、**既定の9ツールのうち2つで素通りする**。
 *
 * | ツール | アプリ ID の在り処 | 形 |
 * | --- | --- | --- |
 * | `kintone-get-app` | `appId` | 単数 |
 * | `kintone-get-form-fields` ほか5つ | `app` | 単数 |
 * | `kintone-get-app-deploy-status` | `apps[]` | **文字列／数値の配列** |
 * | `kintone-deploy-app` | `apps[].app` | ⚠ **オブジェクトの配列** |
 * | `kintone-get-apps` | `ids[]` + 結果の絞り込み | 配列（省略可） |
 *
 * ⚠ **同じ `apps` という名前で形が違う。**
 * `get-app-deploy-status` は `["10","99"]`、
 * `deploy-app` は `[{app:"10"},{app:"99"}]`。
 * 一方の形だけを見る実装にすると、**もう一方が素通りする**
 * （実際に `deploy-app` が迂回できる状態になっていた）。
 *
 * ⚠ **`get-apps` は「引数が無い」わけではない。** `ids[]` で明示できる。
 * 結果の絞り込みだけに頼ると、「許可外は問い合わせる前に拒否する」が成立しない。
 */

/** 許可リスト。空（未設定）なら制限しない */
export type AppScope = {
  /** 許可するアプリ ID。`undefined` なら制限なし */
  allowedAppIds: ReadonlySet<string> | undefined;
};

export class ForbiddenArgumentError extends Error {
  constructor(readonly toolName: string, readonly argument: string) {
    super(`この操作はこのサーバーからはできません (${argument})`);
    this.name = "ForbiddenArgumentError";
  }
}

export class AppNotAllowedError extends Error {
  constructor(readonly appId: string) {
    super("このアプリは許可されていません");
    this.name = "AppNotAllowedError";
  }
}

/** アプリ ID の取り出し方 */
type Extraction =
  /** `args[name]` が単数の ID */
  | { name: string; kind: "value" }
  /** `args[name]` が ID の配列 */
  | { name: string; kind: "values" }
  /** `args[name]` がオブジェクトの配列で、その `field` が ID */
  | { name: string; kind: "objects"; field: string };

const single = (name: string): Extraction => ({ name, kind: "value" });

/** ツール名 → アプリ ID の取り出し方 */
const APP_ID_ARGUMENT: Record<string, Extraction> = {
  "kintone-get-app": single("appId"),
  "kintone-get-form-fields": single("app"),
  "kintone-get-form-layout": single("app"),
  "kintone-get-general-settings": single("app"),
  "kintone-get-process-management": single("app"),
  "kintone-get-records": single("app"),
  "kintone-get-record-comments": single("app"),
  "kintone-add-records": single("app"),
  "kintone-update-records": single("app"),
  "kintone-delete-records": single("app"),
  "kintone-update-statuses": single("app"),
  "kintone-add-record-comment": single("app"),
  "kintone-add-form-fields": single("app"),
  "kintone-update-form-fields": single("app"),
  "kintone-delete-form-fields": single("app"),
  "kintone-update-form-layout": single("app"),
  "kintone-update-general-settings": single("app"),
  // 文字列／数値の配列
  "kintone-get-app-deploy-status": { name: "apps", kind: "values" },
  // ⚠ オブジェクトの配列。上と同じ `apps` という名前だが形が違う
  "kintone-deploy-app": { name: "apps", kind: "objects", field: "app" },
  // 省略可。指定されていればそれを検査し、省略時は結果側で絞る
  "kintone-get-apps": { name: "ids", kind: "values" },
};

/** 結果を絞る必要があるツール（引数にアプリ ID が無いもの） */
const FILTERS_RESULT = new Set(["kintone-get-apps"]);

/**
 * このツールにアプリ境界を課せるか。
 *
 * ⚠ **課せないものは、アプリを絞っているときに公開してはいけない。**
 * `assertAppAllowed` は取り出し方の定義が無いツールを**素通りさせる**。
 * 拒否しているように見えて、実際には何も見ていない。
 *
 * 素通りしていたもの（外部レビューで再現された）:
 *
 * | ツール | 起きること |
 * | --- | --- |
 * | `kintone-add-app` | 許可リストが `{"1"}` でも、**積が空でも**アプリを新規作成できる |
 * | `kintone-download-file` | `fileKey` しか受け取らないので、**どのアプリの添付でも落とせる** |
 *
 * ⚠ **ここは `APP_ID_ARGUMENT` から導出する。** 別に一覧を持つと、
 * 取り出し方を足したときに片方だけ古くなる。
 */
export const enforcesAppBoundary = (toolName: string): boolean =>
  toolName in APP_ID_ARGUMENT || FILTERS_RESULT.has(toolName);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const toAppId = (value: unknown): string | undefined => {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
};

/**
 * 引数からアプリ ID を取り出す。
 *
 * 境界の判定と**監査ログの対象 ID** (§7.5) の両方で使う。
 * 2箇所で別々に書くと、片方だけ形の違いに追随できなくなる。
 */
/**
 * スペース操作の対象。
 *
 * ⚠ **アプリ ID とは別に持つ。** アプリ境界の判定に混ぜると、
 * スペース ID をアプリ ID として検査してしまう。
 * ここで作るのは**監査ログのため**だけ。
 */
const SPACE_ID_ARGUMENT: Record<string, string> = {
  "kintone-get-space": "id",
  "kintone-update-space": "id",
  "kintone-delete-space": "id",
  // テンプレートからの作成は、作る前なのでスペース ID が無い。元のテンプレートを残す
  "kintone-add-space-from-template": "id",
};

/**
 * 監査ログに残す対象。
 *
 * ⚠ **アプリ ID だけでは足りない。** スペース操作は引数にアプリ ID を持たないので、
 * `targets: []` になっていた。共有の連携ユーザーが実行するのに、
 * **何を消したのかがログから分からない**状態だった（外部レビューで指摘）。
 */
export const extractTargets = (
  toolName: string,
  args: Record<string, unknown>,
): string[] => {
  const appIds = extractAppIds(toolName, args);
  if (appIds.length > 0) return appIds;

  const spaceArg = SPACE_ID_ARGUMENT[toolName];
  if (!spaceArg) return [];
  const raw = args[spaceArg];
  if (typeof raw === "string" || typeof raw === "number") return [`space:${String(raw)}`];
  return [];
};

export const extractAppIds = (
  toolName: string,
  args: Record<string, unknown>,
): string[] => {
  const spec = APP_ID_ARGUMENT[toolName];
  if (!spec) return [];

  const raw = args[spec.name];
  const candidates: unknown[] =
    spec.kind === "value"
      ? [raw]
      : Array.isArray(raw)
        ? spec.kind === "objects"
          ? raw.map((item) => (isRecord(item) ? item[spec.field] : undefined))
          : raw
        : [];

  return candidates.map(toAppId).filter((id): id is string => id !== undefined);
};

/**
 * 引数のアプリ ID が許可されているか確かめる。
 *
 * **複数指定は全要素を見る。** 1つでも許可外なら拒否する
 * （「許可内と許可外を混ぜれば通る」を作らない）。
 */
export const assertAppAllowed = (
  toolName: string,
  args: Record<string, unknown>,
  scope: AppScope,
): void => {
  if (!scope.allowedAppIds) return;

  const spec = APP_ID_ARGUMENT[toolName];
  if (!spec) return;

  for (const appId of extractAppIds(toolName, args)) {
    if (!scope.allowedAppIds.has(appId)) throw new AppNotAllowedError(appId);
  }
};

/**
 * 引数そのものを拒否する。
 *
 * ⚠ **「書き込み」をひとかたまりで扱えない場合がある。**
 *
 * `kintone-update-space` は `isPrivate` を受け取る。つまり
 * **非公開スペースを公開に切り替えられる**。削除ではないので
 * `ALLOW_DESTRUCTIVE` では止まらず、`ENABLE_SPACE_WRITE=true` に含まれてしまう。
 *
 * データは消えないが、**見えなかったものが全社に見えるようになる**。
 * 消えるより気づきにくい。スペース名の変更と公開範囲の変更は、
 * 利用者にとって別物なので、**同じ許可でまとめない**。
 *
 * ⚠ **値では分けない。** 「非公開にするのは安全だから通す」とすると、
 * 現在値を読まないと影響が分からないうえ、説明も試験も複雑になる。
 * **この引数が来たら通さない**、で一貫させる。
 */
const FORBIDDEN_ARGUMENTS: Record<string, readonly string[]> = {
  "kintone-update-space": ["isPrivate"],
};

export const assertArgumentsAllowed = (
  toolName: string,
  args: Record<string, unknown>,
): void => {
  for (const name of FORBIDDEN_ARGUMENTS[toolName] ?? []) {
    // ⚠ 値ではなく**指定されたかどうか**で見る。
    // `undefined` を明示的に渡された場合は、変更の意図が無いので通す
    if (args[name] !== undefined) throw new ForbiddenArgumentError(toolName, name);
  }
};

/**
 * 一覧系の結果を許可リストで絞る。
 *
 * ⚠ **上流は同じデータを `structuredContent` と `content[].text` の両方に返す。**
 * 片方だけ絞ると、もう片方から漏れる。絞った後の同一データから両方を組み立て直す。
 */
export const filterAppListResult = (
  toolName: string,
  result: CallToolResult,
  scope: AppScope,
): CallToolResult => {
  if (!scope.allowedAppIds || !FILTERS_RESULT.has(toolName)) return result;

  const structured = result.structuredContent;
  if (!isRecord(structured) || !Array.isArray(structured.apps)) return result;

  const allowed = structured.apps.filter((app) => {
    if (!isRecord(app)) return false;
    const appId = toAppId(app.appId);
    return appId !== undefined && scope.allowedAppIds!.has(appId);
  });

  const filtered = { ...structured, apps: allowed };

  return {
    ...result,
    structuredContent: filtered,
    // 同じデータから作り直す。元の text を使い回さない。
    content: [{ type: "text", text: JSON.stringify(filtered, null, 2) }],
  };
};

/** 許可リストを環境変数の値から組み立てる。空なら制限なし */
export const parseAllowedAppIds = (value: string | undefined): ReadonlySet<string> | undefined => {
  if (value === undefined) return undefined;
  const ids = value
    .split(",")
    .map((id) => id.trim())
    .filter((id) => id.length > 0);
  return ids.length > 0 ? new Set(ids) : undefined;
};

/** 許可リストが適用されるツールかどうか（ドキュメント生成とテスト用） */
export const APP_SCOPED_TOOLS: readonly string[] = [
  ...Object.keys(APP_ID_ARGUMENT),
  ...FILTERS_RESULT,
];

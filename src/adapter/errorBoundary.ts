import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

/**
 * ツール実行の例外を、外に出してよい形に詰め替える境界。
 *
 * **これが無いと秘密がクライアントまで届く。** MCP SDK はツールが投げた例外の
 * `message` をそのまま結果に載せるので、kintone クライアントの例外に含まれる
 * `X-Cybozu-API-Token` などが MCP の応答に出る。HTTP 層でヘッダーをマスクしても
 * この経路は塞がらない。
 *
 * ## 設計の要点 — 3度作り直している
 *
 * 1. 最初は例外の `message` をそのまま返していた → 秘密が漏れた
 * 2. 次に `status` / `code` / `id` だけを通した → **`code` の中身が検証されておらず、
 *    そこに入れた文字列がそのまま出た**
 * 3. 次に `code` / `id` の形を正規表現で縛った → **形に合う秘密は通る**し、
 *    **境界自身（分類処理とログ用フック）の例外が境界を素通りした**
 *
 * 今の方針は「**未知の文字列を一切外に出さない**」。
 * 出すのは HTTP ステータスと、そこから決まる固定の分類、そして相関 ID だけ。
 * kintone のエラーコードや ID は**サーバー側のログにだけ**残す。
 */

/** HTTP ステータスから決まる固定の分類。未知の文字列を含まない */
export type FailureKind =
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "invalid_request"
  | "rate_limited"
  | "kintone_unavailable"
  /** サーバーの許可リストで止めた。kintone には問い合わせていない (§5) */
  | "app_not_allowed"
  /** その引数はこのサーバーからは使わせない。kintone には問い合わせていない */
  | "forbidden_argument"
  | "unknown";

/** サーバー側のログに残す情報。ここには生の値を入れてよいが、呼び出し側が扱いを誤らないよう型で分ける */
export type ToolFailure = {
  toolName: string;
  kind: FailureKind;
  status: number | undefined;
  /** クライアントにも返す相関 ID。ログと突き合わせるためのもの */
  correlationId: string;
  /** kintone が返したエラーコード。**クライアントには返さない** */
  kintoneCode: string | undefined;
  /** kintone が返したエラー ID。**クライアントには返さない** */
  kintoneId: string | undefined;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const classify = (status: number | undefined): FailureKind => {
  if (status === undefined) return "unknown";
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "kintone_unavailable";
  if (status >= 400) return "invalid_request";
  return "unknown";
};

const DESCRIPTION: Record<FailureKind, string> = {
  unauthorized: "kintone の認証に失敗しました。接続を作り直してください。",
  forbidden: "kintone のアクセス権がありません。対象のアプリやレコードの権限を確認してください。",
  not_found: "対象が見つかりません。アプリ ID やレコード ID を確認してください。",
  invalid_request: "リクエストの内容が kintone に受け付けられませんでした。引数を確認してください。",
  rate_limited: "kintone の API 制限に達しました。しばらく待ってから再試行してください。",
  kintone_unavailable: "kintone 側でエラーが発生しました。時間をおいて再試行してください。",
  app_not_allowed:
    "このサーバーで許可されていないアプリです。接続の設定 (ALLOWED_APP_IDS) を確認してください。",
  forbidden_argument:
    "この操作はこのサーバーからはできません。kintone の画面から行ってください。",
  unknown: "ツールの実行に失敗しました。",
};


/**
 * プロパティの取得そのものが失敗しうる。
 *
 * 例外オブジェクトの getter が投げると、分類処理の中で例外が起き、
 * それが境界の外へ出る（再現済み）。触る操作は必ず包む。
 */
const safeRead = (source: Record<string, unknown>, key: string): unknown => {
  try {
    return source[key];
  } catch {
    return undefined;
  }
};

/**
 * サーバー側の許可リストで止めた失敗かどうか。
 *
 * `instanceof` を使わないのは、**ビルドの都合で別インスタンスのクラスになりうる**ため。
 * 名前で判定する。
 */
const isAppNotAllowed = (error: unknown): boolean =>
  isRecord(error) && safeRead(error, "name") === "AppNotAllowedError";

/** 引数そのものを拒否した失敗かどうか。判定の理由は `isAppNotAllowed` と同じ */
const isForbiddenArgument = (error: unknown): boolean =>
  isRecord(error) && safeRead(error, "name") === "ForbiddenArgumentError";

const readStatus = (error: unknown): number | undefined => {
  if (!isRecord(error)) return undefined;
  const value = safeRead(error, "status");
  return typeof value === "number" && Number.isInteger(value) ? value : undefined;
};

const readString = (error: unknown, key: string): string | undefined => {
  if (!isRecord(error)) return undefined;
  const value = safeRead(error, key);
  return typeof value === "string" ? value : undefined;
};

/** 相関 ID。秘密ではないので生成に失敗しない */
const newCorrelationId = (): string => globalThis.crypto.randomUUID();

/**
 * ツールの callback を境界で包む。
 *
 * @param onFailure サーバー側のログに残すためのフック。
 *   **このフックが投げても応答には出さない。** フックの失敗は応答から隔離する。
 */
/** 成否によらず1回呼ばれる。監査ログ (§7.5) に使う */
export type ToolOutcome = {
  toolName: string;
  ok: boolean;
  failureKind: FailureKind | undefined;
  correlationId: string | undefined;
  durationMs: number;
};

export type ErrorBoundaryHooks = {
  onFailure?: ((failure: ToolFailure) => void) | undefined;
  onOutcome?: ((outcome: ToolOutcome) => void) | undefined;
  /**
   * 応答に載せる相関 ID。
   *
   * ⚠ **渡さないと、ログと突き合わせられない ID を利用者に返すことになる。**
   * ここで独自に作ると、監査ログ側はリクエストの ID を書くので、
   * 利用者が伝えてきた ID でログを検索しても**何も出てこない**（実測で確認）。
   * リクエストの ID をそのまま使う。バッチは受け付けないので、
   * 1リクエスト = 1ツール実行で一意に対応する。
   */
  correlationId?: string | undefined;
};

export const withErrorBoundary = <Args>(
  toolName: string,
  callback: (args: Args) => CallToolResult | Promise<CallToolResult>,
  hooks: ErrorBoundaryHooks = {},
): ((args: Args) => Promise<CallToolResult>) => {
  const { onFailure, onOutcome } = hooks;

  return async (args: Args): Promise<CallToolResult> => {
    const startedAt = Date.now();

    /** 観測そのものが失敗しても応答に影響させない */
    const observe = (outcome: ToolOutcome): void => {
      try {
        onOutcome?.(outcome);
      } catch {
        // ここで投げると、せっかく詰め替えた応答が壊れる
      }
    };

    try {
      const result = await callback(args);
      observe({
        toolName,
        ok: result.isError !== true,
        // ツールが自分で isError を立てた場合は分類が取れない
        failureKind: result.isError === true ? "unknown" : undefined,
        correlationId: undefined,
        durationMs: Date.now() - startedAt,
      });
      return result;
    } catch (error) {
      // ここから先で投げると、その例外が SDK 経由でクライアントへ出る。
      // 分類もフック呼び出しも、すべて失敗しうる前提で書く。
      let correlationId = "unavailable";
      let kind: FailureKind = "unknown";
      let status: number | undefined;

      try {
        correlationId = hooks.correlationId ?? newCorrelationId();

        if (isAppNotAllowed(error)) {
          // kintone には問い合わせていないので status は無い。
          // 「権限がない」ではなく「このサーバーが止めた」と伝える。
          kind = "app_not_allowed";
        } else if (isForbiddenArgument(error)) {
          // ⚠ **`app_not_allowed` と混ぜない。**
          // 直し方が違う。あちらは設定で許可できるが、こちらはできない
          kind = "forbidden_argument";
        } else {
          status = readStatus(error);
          kind = classify(status);
        }

        try {
          onFailure?.({
            toolName,
            kind,
            status,
            correlationId,
            kintoneCode: readString(error, "code"),
            kintoneId: readString(error, "id"),
          });
        } catch {
          // ログ用フックの失敗は応答に影響させない
        }
      } catch {
        // 分類そのものが失敗したら、固定の汎用エラーに戻す
        kind = "unknown";
        status = undefined;
      }

      observe({
        toolName,
        ok: false,
        failureKind: kind,
        correlationId,
        durationMs: Date.now() - startedAt,
      });

      const result: CallToolResult = {
        isError: true,
        content: [
          {
            type: "text",
            text: `${DESCRIPTION[kind]} (correlationId: ${correlationId})`,
          },
        ],
        structuredContent: {
          kind,
          correlationId,
          ...(status !== undefined ? { status } : {}),
        },
      };
      return result;
    }
  };
};

/**
 * ログに出してよい形へ落とす。
 *
 * ## 方針: 許可したものだけを出す
 *
 * 「危ないものを消す」方式は、**新しい秘密が増えるたびに漏れる**。
 * 消し忘れは気づけないが、出し忘れはすぐ気づく。
 *
 * ## 何が秘密か
 *
 * 認可の経路では、**URL のクエリに秘密が載る** (§7.4)。
 * `code` と `state` はまさにそれで、Cloud Logging の `httpRequest.requestUrl` は
 * クエリを含むため、**アプリ側で伏せても基盤側に残る**。
 * ここで落とすのはアプリのログについてだけで、
 * 基盤のリクエストログは sink の除外設定で対処する（別作業）。
 */

/**
 * URL から秘密を落とす。パスだけを残す。
 *
 * ⚠ **ベース URL を与えて `new URL()` に投げてはいけない。**
 * ほとんどの文字列が相対パスとして「解釈できてしまう」ため、
 * 壊れた入力がそのまま `pathname` に載って出てくる
 * （`::::SECRET` が `/::::SECRET` になった）。
 * 絶対 URL か、先頭が `/` のパスだけを受け付ける。
 */
export const redactUrl = (url: string): string => {
  try {
    // クエリもフラグメントも落とす。`code` / `state` / `code_verifier` が載る
    return new URL(url).pathname;
  } catch {
    // 絶対 URL ではない
  }

  if (url.startsWith("/")) {
    const end = Math.min(
      ...[url.indexOf("?"), url.indexOf("#")].filter((i) => i >= 0).concat([url.length]),
    );
    return url.slice(0, end);
  }

  return "(解釈できない URL)";
};

/**
 * ヘッダー名の集合のうち、**値を出してよいもの**。
 *
 * `authorization` / `cookie` / `x-cybozu-*` は当然として、
 * **`location` も出さない**（認可のリダイレクト先に `code` が載る）。
 */
const LOGGABLE_HEADERS = new Set(["content-type", "content-length", "user-agent", "accept"]);

export const redactHeaders = (
  headers: Record<string, unknown>,
): Record<string, string> => {
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (!LOGGABLE_HEADERS.has(lower)) continue;
    if (typeof value === "string") result[lower] = value;
  }
  return result;
};

/**
 * 例外から、ログに出してよい形を作る。
 *
 * **`message` も `stack` も出さない。** kintone クライアントの例外には
 * リクエスト設定（= 資格情報）が入りうる (§7.4)。
 * 出すのは種別と、あれば HTTP ステータスだけ。
 */
export type SafeErrorSummary = {
  kind: string;
  status: number | undefined;
  /**
   * スタックの先頭のコード位置（`file.js:12:34`）。
   *
   * ⚠ **これが無いと、種別だけでは原因に辿り着けない。**
   * 実際、`oidc-provider` の 500 を追ったときに
   * `{"kind":"Error"}` しか残らず、調査ができなかった。
   *
   * コード位置は**データではない**ので出してよい。
   * メッセージ（値が入りうる）は依然として出さない。
   */
  at: string | undefined;
};

/**
 * スタックから最初のコード位置だけを抜く。
 *
 * ⚠ **メッセージ行を見ない。** スタックの1行目は `Error: <message>` なので、
 * そこも走査すると**メッセージの中身が拾われる**。
 * 実際、`new Error("failed SECRET:12:34")` から `SECRET:12:34` が出た。
 * `    at ` で始まる行だけを対象にする。
 */
const firstFrame = (stack: unknown): string | undefined => {
  if (typeof stack !== "string") return undefined;
  for (const line of stack.split("\n")) {
    const trimmed = line.trim();
    // V8 のスタックフレームは必ず "at " で始まる
    if (!trimmed.startsWith("at ")) continue;
    const match = /\(?([^()\s]+:\d+:\d+)\)?$/.exec(trimmed);
    if (!match?.[1]) continue;
    // 絶対パスは環境の情報なので、末尾2つだけにする
    return match[1].split("/").slice(-2).join("/");
  }
  return undefined;
};

export const summarizeError = (error: unknown): SafeErrorSummary => {
  if (typeof error !== "object" || error === null) {
    return { kind: typeof error, status: undefined, at: undefined };
  }

  let kind = "Error";
  let status: number | undefined;
  let at: string | undefined;

  try {
    const name = (error as Record<string, unknown>).name;
    if (typeof name === "string") kind = name;
    const raw = (error as Record<string, unknown>).status;
    if (typeof raw === "number" && Number.isInteger(raw)) status = raw;
    at = firstFrame((error as Record<string, unknown>).stack);
  } catch {
    // getter が投げることがある。そのときは既定のまま
  }

  return { kind, status, at };
};

/**
 * テナントの識別子。
 *
 * **ホスト名だけを出す。** 資格情報はもちろん、パスも出さない (§7.5)。
 */
export const tenantOf = (baseUrl: string): string => {
  try {
    return new URL(baseUrl).hostname;
  } catch {
    return "(解釈できない baseUrl)";
  }
};

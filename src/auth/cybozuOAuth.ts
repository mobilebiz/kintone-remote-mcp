/**
 * cybozu.com の OAuth クライアント。
 *
 * 認可コードグラント / Confidential Client。エンドポイントは**サブドメイン固有**なので、
 * 1デプロイ1ドメインの前提 (§4.8) でベース URL を固定して使う。
 *
 * 公式仕様で確認した重要な点:
 *
 * - アクセストークンの有効期間は1時間
 * - **リフレッシュ応答に新しいリフレッシュトークンは含まれない**
 *   （`access_token` / `token_type` / `expires_in` / `scope` のみ）
 *   → 既存のリフレッシュトークンを保持し続ける。provider 側のローテーションとは別処理 (§4.9)
 * - リフレッシュトークンに期限は無いが、1クライアントあたり1ユーザー10個まで
 * - トークンエンドポイントは Basic 認証（`client_id:client_secret` の base64）
 */

export type CybozuOAuthConfig = {
  /** `https://example.cybozu.com`。末尾スラッシュ無し */
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  /** こちらの `/oauth/callback`。cybozu 側のクライアント設定に登録した値と一致させる */
  redirectUri: string;
  /** 要求するスコープ。フェーズ1 は読み取りのみ (§4.7) */
  scopes: string[];
  /**
   * トークンエンドポイントへの通信を諦めるまで（ミリ秒）。
   *
   * ⚠ **これが無いと、相手が黙り込んだときに止められない。**
   * `fetch` に既定のタイムアウトは無い。リクエスト側の締め切りで
   * HTTP を切っても**この通信は走り続け**、更新は単一飛行なので
   * **その接続の後続リクエストがまとめて詰まる**。
   */
  timeoutMs?: number;
};

/** 認可コードと引き換えに得たもの */
export type CybozuTokens = {
  accessToken: string;
  refreshToken: string;
  /** アクセストークンの失効時刻（エポック秒） */
  expiresAt: number;
  scope: string;
};

/** リフレッシュで得たもの。**リフレッシュトークンは返ってこない** */
export type CybozuRefreshedTokens = {
  accessToken: string;
  expiresAt: number;
  scope: string;
};

export class CybozuOAuthError extends Error {
  constructor(
    message: string,
    readonly status: number | undefined,
    /** cybozu が返した error コード。ログ用。**クライアントには返さない** */
    readonly upstreamError: string | undefined,
    /**
     * 応答の**形**（フィールド名と型だけ）。
     *
     * ⚠ **値は入れない。** アクセストークンが入っているので、
     * 値を1つでも載せるとログに永続化されて回収できない。
     *
     * これが無いと、「必要な値がありません」だけが残って、
     * **何が足りなかったのか分からない**（実際にそうなった）。
     */
    readonly shape: string | undefined = undefined,
  ) {
    super(message);
    this.name = "CybozuOAuthError";
  }
}

/** 応答の形を、値を含めずに書き出す */
const shapeOf = (parsed: Record<string, unknown>): string =>
  Object.entries(parsed)
    .map(([key, value]) => `${key}:${value === null ? "null" : typeof value}`)
    .sort()
    .join(",");

/**
 * `expires_in` を秒数として読む。
 *
 * ⚠ **数値とは限らない。** RFC 6749 は数値と定めているが、
 * 文字列で返す実装がある。`typeof !== "number"` で弾いていたため、
 * **正しい応答を拒否する**可能性があった。
 */
const readSeconds = (value: unknown): number | undefined => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
};

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** cybozu のトークンエンドポイントを諦めるまで。リクエストの締め切りより短く取る */
const DEFAULT_TIMEOUT_MS = 10_000;

export type CybozuOAuthClient = {
  /** ユーザーを飛ばす先。`state` は呼び出し側が生成して渡す */
  buildAuthorizationUrl(state: string): string;
  exchangeCode(code: string): Promise<CybozuTokens>;
  refresh(refreshToken: string): Promise<CybozuRefreshedTokens>;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const readString = (source: Record<string, unknown>, key: string): string | undefined => {
  const value = source[key];
  return typeof value === "string" ? value : undefined;
};

export const createCybozuOAuthClient = (
  config: CybozuOAuthConfig,
  deps: { fetch?: FetchLike; now?: () => number } = {},
): CybozuOAuthClient => {
  const doFetch = deps.fetch ?? ((input, init) => fetch(input, init));
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));

  const authorizationEndpoint = `${config.baseUrl}/oauth2/authorization`;
  const tokenEndpoint = `${config.baseUrl}/oauth2/token`;
  const basic = Buffer.from(`${config.clientId}:${config.clientSecret}`, "utf8").toString("base64");

  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const postToken = async (body: URLSearchParams): Promise<Record<string, unknown>> => {
    let response: Response;
    try {
      response = await doFetch(tokenEndpoint, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${basic}`,
        },
        body: body.toString(),
        // ⚠ **相手が応答を返さない場合を、こちらから終わらせる。**
        // 期限切れの扱いは「一時障害」でなければならない。
        // `invalid_grant` と同じ扱いにすると、**繋がらなかっただけで
        // 接続を失効させて**しまい、利用者に再認可を強いる
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      // status を付けない = 一時障害。呼び出し側は失効させない (§7.4)
      throw new CybozuOAuthError(
        error instanceof Error && error.name === "TimeoutError"
          ? "cybozu への接続が時間内に完了しませんでした"
          : "cybozu への接続に失敗しました",
        undefined,
        undefined,
      );
    }

    let parsed: unknown;
    try {
      parsed = await response.json();
    } catch {
      throw new CybozuOAuthError("cybozu のトークン応答を解釈できません", response.status, undefined);
    }

    if (!isRecord(parsed)) {
      throw new CybozuOAuthError("cybozu のトークン応答が不正です", response.status, undefined);
    }

    if (!response.ok) {
      // error_description は秘密を含みうるので載せない。ログ側で扱う。
      throw new CybozuOAuthError(
        "cybozu のトークン取得に失敗しました",
        response.status,
        readString(parsed, "error"),
        shapeOf(parsed),
      );
    }

    return parsed;
  };

  return {
    buildAuthorizationUrl(state) {
      const url = new URL(authorizationEndpoint);
      url.search = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        response_type: "code",
        state,
        scope: config.scopes.join(" "),
      }).toString();
      return url.toString();
    },

    async exchangeCode(code) {
      const parsed = await postToken(
        new URLSearchParams({
          grant_type: "authorization_code",
          redirect_uri: config.redirectUri,
          code,
        }),
      );

      const accessToken = readString(parsed, "access_token");
      const refreshToken = readString(parsed, "refresh_token");
      const expiresIn = readSeconds(parsed.expires_in);

      if (!accessToken || !refreshToken || expiresIn === undefined) {
        throw new CybozuOAuthError(
          "cybozu のトークン応答に必要な値がありません",
          undefined,
          undefined,
          shapeOf(parsed),
        );
      }

      return {
        accessToken,
        refreshToken,
        expiresAt: now() + expiresIn,
        scope: readString(parsed, "scope") ?? "",
      };
    },

    async refresh(refreshToken) {
      const parsed = await postToken(
        new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }),
      );

      const accessToken = readString(parsed, "access_token");
      const expiresIn = readSeconds(parsed.expires_in);

      if (!accessToken || expiresIn === undefined) {
        throw new CybozuOAuthError(
          "cybozu のトークン応答に必要な値がありません",
          undefined,
          undefined,
          shapeOf(parsed),
        );
      }

      // ⚠ ここで refresh_token を読もうとしない。公式仕様では返ってこない。
      // 呼び出し側は既存のリフレッシュトークンを保持し続ける。
      return {
        accessToken,
        expiresAt: now() + expiresIn,
        scope: readString(parsed, "scope") ?? "",
      };
    },
  };
};

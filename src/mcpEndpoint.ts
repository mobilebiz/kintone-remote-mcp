import { KintoneRestAPIClient } from "@kintone/rest-api-client";
import { Agent } from "node:https";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Request, Response } from "express";
import type Provider from "oidc-provider";

import { createRemoteServer } from "./adapter/createRemoteServer.js";
import type { ToolFailure } from "./adapter/errorBoundary.js";
import { parseAllowedAppIds } from "./adapter/appScope.js";
import type { ToolCapabilities } from "./adapter/toolPolicy.js";
import {
  KintoneAuthRequiredError,
  KintoneRequestAbandonedError,
  type KintoneTokenProvider,
} from "./auth/kintoneToken.js";
import type { ConnectionGrantStore } from "./auth/connectionGrant.js";
import type { AuditLogger } from "./observability/audit.js";
import type { ConcurrencyLimiter, RateLimiter } from "./observability/rateLimit.js";

/**
 * MCP のエンドポイント。
 *
 * ## 受信トークンの検証は provider 任せにしない (§4.10)
 *
 * 「provider が発行したから正しい」で済ませない。MCP 仕様は受信側での検証を
 * 要求している。確かめるのは次の5つ。
 *
 * | 検証 | 落とす理由 |
 * | --- | --- |
 * | 種別が `AccessToken` | **リフレッシュトークンを Bearer として投げ込まれても通さない** |
 * | 期限 | 期限切れ |
 * | audience | 別の resource 宛のトークンを受け取らない |
 * | scope | 足りなければ 403 |
 * | 接続 grant の生存 | 切断済みなら 401 |
 *
 * ## ステートレス
 *
 * リクエストごとに `McpServer` と トランスポートを作り、`res.on("close")` で捨てる。
 * セッションを持つとインスタンス間で状態が割れる (§2.2)。
 */

/** HTTPS Agent はプロセスで共有する。クライアントを作り直してもプールは維持される */
const sharedAgent = new Agent({ keepAlive: true });

export type McpEndpointOptions = {
  provider: Provider;
  kintoneTokens: KintoneTokenProvider;
  grants: ConnectionGrantStore;
  audit: AuditLogger;
  /** `https://HOST/mcp`。トークンの audience と突き合わせる */
  resource: string;
  kintoneBaseUrl: string;
  capabilities: ToolCapabilities;
  allowedAppIds: string | undefined;
  /**
   * 連携用ユーザー。**OAuth で実行できない5ツール専用**。
   *
   * ⚠ これを渡すと、スペース操作と検索は**接続した本人ではなく
   * このユーザーとして**実行される。
   */
  integrationUser?: { username: string; password: string } | undefined;
  /** grant 単位の流量制限 (§7.2) */
  rateLimiter: RateLimiter;
  /** grant（接続）単位の同時実行 */
  concurrency: ConcurrencyLimiter;
  /**
   * インスタンス全体の同時実行。**kintone ドメインを守るための枠** (§7.2)。
   *
   * ⚠ grant 単位の枠とは目的が違う。前者は「1接続が独占しないこと」、
   * こちらは「上流に同時に何本出すか」。接続が増えれば前者の合計は増えるので、
   * 前者だけでは上流の上限にならない。
   */
  totalConcurrency: ConcurrencyLimiter;
  /** リクエストの締め切り（ミリ秒） */
  deadlineMs: number;
  /** アクセストークンに必要な scope。足りなければ 403 */
  requiredScopes: string[];
  userAgent: string;
  /**
   * kintone クライアントの生成。
   *
   * テストから差し替えるための口。**既定の実装がそのまま本番で使われる**ので、
   * ここを差し替えないと「実際に kintone へどんなトークンが渡るか」を
   * 確かめようがない。
   */
  /**
   * kintone クライアントの生成。
   *
   * ⚠ **受け取るのは「本番が実際に渡す設定そのもの」。**
   * 以前はトークン文字列だけを渡していたため、
   * **呼び出し側で資格情報を混ぜてもテストから見えなかった**
   * （外部レビューで指摘。kintone はパスワード認証を OAuth より優先するので、
   * 混ざると全操作が連携ユーザーとして実行される）。
   */
  createKintoneClient?: (options: KintoneClientOptions) => KintoneRestAPIClient;
};

type Denial = { status: 401 | 403 | 429 | 503; error: string; description: string };

const wwwAuthenticate = (resourceMetadataUrl: string, error?: string): string => {
  const parts = [`Bearer resource_metadata="${resourceMetadataUrl}"`];
  if (error) parts.push(`error="${error}"`);
  return parts.join(", ");
};

/** Bearer トークンを取り出す。`Bearer ` 以外の方式は「無い」のと同じ扱い */
const bearerFrom = (header: unknown): string | undefined => {
  if (typeof header !== "string") return undefined;
  const match = /^Bearer (.+)$/.exec(header.trim());
  return match?.[1];
};

/**
 * 本番の kintone クライアントに渡す設定。
 *
 * ⚠ **関数に切り出してあるのは、テストから確かめるため。**
 * HTTP 経由のテストはクライアント生成をスタブに差し替えるので、
 * ここを直接書いていると**本番の設定を消してもテストが通る**
 * （実際、`socketTimeout` を消しても187件すべて通った）。
 */
export type KintoneClientOptions = ReturnType<typeof kintoneClientOptions>;

export const kintoneClientOptions = (input: {
  baseUrl: string;
  /**
   * 認証。
   *
   * ⚠ **どちらか一方だけを渡す。** kintone は認証方式に優先順位があり、
   * **パスワード認証が OAuth より優先**される。両方のヘッダーが載ると、
   * すべての操作がパスワード側の主体として実行される。
   * 混ざりようが無いように、呼び出し側で選んだものをそのまま受け取る。
   */
  auth: { oAuthToken: string } | { username: string; password: string };
  userAgent: string;
  deadlineMs: number;
}) => ({
  baseUrl: input.baseUrl,
  auth: input.auth,
  userAgent: input.userAgent,
  // ⚠ Agent は共有する。クライアントを作り直しても接続プールは維持される。
  httpsAgent: sharedAgent,
  // ⚠ **通信そのものに期限を与える。** 指定しないと既定の期限は無く、
  // 相手が黙り込むと**同時実行の枠を握ったまま**になる。
  // HTTP を切っても上流の呼び出しは止まらないので、止められる手段はここしかない
  socketTimeout: input.deadlineMs,
});

/**
 * **Express が解析し終えた、単一の JSON-RPC メッセージ**であることを確かめる。
 *
 * これが偽なら SDK に渡してはいけない。渡すと SDK が本文を読み直し、
 * こちらの検査と上限をすべて迂回される。
 */
export const isSingleJsonRpcMessage = (body: unknown): body is Record<string, unknown> =>
  typeof body === "object" && body !== null && !Array.isArray(body);

export const createMcpEndpoint = (options: McpEndpointOptions) => {
  const resourceMetadataUrl = `${new URL(options.resource).origin}/.well-known/oauth-protected-resource`;
  const configuredAppIds = parseAllowedAppIds(options.allowedAppIds);

  const deny = (res: Response, denial: Denial, correlationId: string): void => {
    // 締め切りが先に 504 を返している場合がある。二重に書かない
    if (res.headersSent) return;
    res.setHeader(
      "WWW-Authenticate",
      wwwAuthenticate(resourceMetadataUrl, denial.status === 401 ? "invalid_token" : undefined),
    );
    res.status(denial.status).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: denial.description, data: { correlationId } },
      id: null,
    });
  };

  const handle = async (req: Request, res: Response): Promise<void> => {
    const correlationId = globalThis.crypto.randomUUID();
    res.setHeader("Cache-Control", "no-store");

    /**
     * 締め切りは**ここから**数える。
     *
     * ⚠ **ツール実行の直前に始めると、そこまでの時間が計れない。**
     * トークンの照会（Firestore）と kintone トークンの更新（cybozu への通信）は
     * 締め切りの**前**にあり、そこで詰まると応答は永遠に始まらない。
     * 実際、更新を止めると締め切りを過ぎても応答が始まらず、
     * 後続のリクエストが同時実行の枠切れで 429 になった。
     *
     * ⚠ **締め切りで枠は返さない** (§7.3)。HTTP を切っても
     * kintone への呼び出しは走り続ける（上流はキャンセルを受け取らない）。
     * ここで返すと、タイムアウトの連鎖で上流への同時接続が上限を超える。
     */
    /**
     * **もうこの要求のために新しい仕事を始めない**という印。
     *
     * ⚠ **締め切りで応答を返しても、処理は止まらない。**
     * `await` から戻ったところは「まだ何も始めていない」地点なので、
     * そのまま進むと、**結果を届けられない相手のために上流を呼ぶ**ことになる。
     * 読み取りでも kintone の API 枠を無駄に消費し、書き込みを有効にすれば
     * **利用者が結果を確認した後に書き込みが走る**。
     *
     * 既に走り出している処理は止められない（上流はキャンセルを受け取らない）。
     * ここで止めるのは**未着手のもの**だけ。枠の扱いは変えない。
     *
     * ## 置く場所は「外へ出る直前」だけ
     *
     * この印は、**外部呼び出しの直前2か所**でしか見ない。
     *
     * | 位置 | 止まるもの |
     * | --- | --- |
     * | kintone トークンの更新の前 | cybozu への通信 |
     * | ツール実行の前 | kintone への通信 |
     *
     * 認証の途中（トークン照会の後・失効確認の後）にも置いていたが、外した。
     * **止めても外からは何も変わらない**（節約できるのは保存層の読み取りだけ）ため、
     * 壊してもテストが落ちず、**壊れていることに気づけないコード**になっていた。
     */
    let abandoned = false;

    const deadline = setTimeout(() => {
      abandoned = true;
      if (res.headersSent) return;
      options.audit.unexpected(
        { correlationId, where: "deadline" },
        new Error("deadline exceeded"),
      );
      res.status(504).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          // 「失敗した」と言い切らない。書き込みは通っているかもしれない
          message:
            "時間内に完了しませんでした。書き込み操作の場合、kintone 側では完了している可能性があります。再実行の前に結果を確認してください。",
          data: { correlationId },
        },
        id: null,
      });
    }, options.deadlineMs);
    // 応答が終わるか、接続が切れたら止める。
    // 早期 return の経路が多いので、個別に消して回らない
    res.on("close", () => {
      clearTimeout(deadline);
      // 切断された相手のために上流を呼ばない。
      //
      // ⚠ **締め切り側の代入と重複している。** 504 を返すと応答が閉じるので、
      // 今はどちらか一方だけでも同じ結果になる（両方消したときだけテストが落ちる）。
      // それでも両方残すのは、応答を途中まで返している状態では
      // 締め切り側が早期 return するため、そちらだけでは足りないから。
      // 「片方は要らない」と見えるが、**消すなら両方の経路を確かめること**。
      abandoned = true;
    });

    // ステートレスなので GET(SSE) と DELETE(セッション終了) は提供しない (§2.2)。
    // 提供しないものは明示的に断る。
    if (req.method !== "POST") {
      res.status(405).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "POST のみ受け付けます" },
        id: null,
      });
      return;
    }

    // ⚠ **JSON-RPC のバッチを受け付けない。**
    // SDK は配列内の要求を**並列に実行する**ので、
    // 1リクエストぶんの流量・同時実行の枠で、いくつでも上流呼び出しを開始できる。
    // 枠をツール実行ごとに消費する作りにするまでは、配列そのものを断る。
    //
    // ⚠ **配列だけを見るのでは足りない。** SDK は `parsedBody` が `undefined` だと
    // **自分で本文を読み直す**。つまり「Express が解析しなかった要求」は、
    // このバッチ検査も `express.json` のサイズ上限も**素通りする**。
    // Content-Type の判定が両者で食い違うため、これは実際に起こる:
    //
    // | Content-Type                  | express.json | SDK  |
    // | ----------------------------- | ------------ | ---- |
    // | `application/json`            | 解析する     | 受理 |
    // | `application/json-patch+json` | **しない**   | 受理 | ← 隙間
    //
    // SDK 側は `ct.includes("application/json")` の**部分一致**なので、
    // 前方一致する型名すべてが該当する。
    // → **解析済みの単一オブジェクト以外は SDK に渡さない。**
    //   Content-Type の限定は httpServer 側でも行うが、
    //   ここが「SDK に本文を読み直させない」最後の砦になる。
    if (!isSingleJsonRpcMessage(req.body)) {
      res.status(400).json({
        jsonrpc: "2.0",
        error: {
          code: -32600,
          message: Array.isArray(req.body)
            ? "バッチ要求は受け付けません"
            : "要求の本文を解釈できません",
          data: { correlationId },
        },
        id: null,
      });
      return;
    }

    const token = bearerFrom(req.headers.authorization);
    if (!token) {
      // 資格情報がまったく無い要求は「異常」ではなく認可フローの1歩目 (RFC 6750 3.1)
      res.setHeader("WWW-Authenticate", wwwAuthenticate(resourceMetadataUrl));
      res.status(401).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "認証が必要です" },
        id: null,
      });
      return;
    }

    // ⚠ **種別を確かめる。** RefreshToken を Bearer として投げ込まれても通さない。
    const accessToken = await options.provider.AccessToken.find(token);
    if (!accessToken) {
      deny(res, { status: 401, error: "invalid_token", description: "トークンが無効です" }, correlationId);
      return;
    }

    if (accessToken.isExpired) {
      deny(res, { status: 401, error: "invalid_token", description: "トークンの期限が切れています" }, correlationId);
      return;
    }

    // audience。**欠落も拒否する。**
    // 「あれば一致を見る」だと、audience の無いトークンが素通りする。
    const audience = (accessToken as unknown as { aud?: string }).aud;
    if (audience !== options.resource) {
      deny(res, { status: 401, error: "invalid_token", description: "このリソース宛のトークンではありません" }, correlationId);
      return;
    }

    // scope。足りなければ **403**（401 ではない。トークンは有効だが権限が足りない）
    const granted = new Set(
      String((accessToken as unknown as { scope?: string }).scope ?? "")
        .split(" ")
        .filter((item) => item.length > 0),
    );
    const missing = options.requiredScopes.filter((scope) => !granted.has(scope));
    if (missing.length > 0) {
      res.setHeader(
        "WWW-Authenticate",
        `${wwwAuthenticate(resourceMetadataUrl, "insufficient_scope")}, scope="${options.requiredScopes.join(" ")}"`,
      );
      res.status(403).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "権限が足りません", data: { correlationId } },
        id: null,
      });
      return;
    }

    const accountId = accessToken.accountId;
    const grantId = accessToken.grantId;
    if (typeof accountId !== "string") {
      deny(res, { status: 401, error: "invalid_token", description: "トークンが無効です" }, correlationId);
      return;
    }

    // 接続 grant の生存。切断済みなら、トークンが残っていても通さない。
    //
    // > **これは二重防御である。** Adapter の `find` も失効を照合するので、
    // > この判定を外してもテストは落ちない（ミューテーション検査で確認済み）。
    // > 保存層の実装を差し替えたときに、ここが最後の砦になる。
    // 失効確認と、同意の確認を**1回の読み出しで**行う
    const connection = await options.grants.inspect(accountId);
    if (connection.revoked) {
      deny(res, { status: 401, error: "invalid_token", description: "この接続は解除されています" }, correlationId);
      return;
    }

    // 認証後の流量制限は **grant 単位** (§7.2)。
    // トークン単位にすると、更新のたびに枠がリセットされる。
    const limitKey = grantId ?? accountId;
    const decision = options.rateLimiter.check(limitKey);
    if (!decision.allowed) {
      options.audit.rateLimited({ correlationId, accountId, grantId, scope: "grant", limit: decision.limit });
      res.setHeader("Retry-After", String(decision.retryAfterSeconds));
      res.status(429).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "リクエストが多すぎます", data: { correlationId } },
        id: null,
      });
      return;
    }

    // 同時実行の制限。kintone 側の同時実行を超えると相手のドメイン全体に響く
    const tooBusy = (scope: string): void => {
      options.audit.rateLimited({ correlationId, accountId, grantId, scope, limit: 0 });
      res.setHeader("Retry-After", "1");
      res.status(429).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "同時実行が多すぎます", data: { correlationId } },
        id: null,
      });
    };

    const releaseGrant = options.concurrency.acquire(limitKey);
    if (!releaseGrant) {
      tooBusy("concurrency");
      return;
    }

    // ⚠ **接続単位の枠を取れても、上流の枠が空いているとは限らない。**
    // 接続が増えるほど前者の合計は増えるので、ここが無いと
    // kintone への同時実行が接続数に比例して伸びる
    const releaseTotal = options.totalConcurrency.acquire("all");
    if (!releaseTotal) {
      releaseGrant();
      tooBusy("concurrency-total");
      return;
    }

    /** 2つの枠は必ず一緒に返す。片方だけ返すと枠が漏れる */
    const release = (): void => {
      releaseTotal();
      releaseGrant();
    };

    /**
     * ⚠ **枠を取ったら、何があっても返す。**
     *
     * ここから先には、明示的な解放を書き忘れやすい経路がある。
     * `new KintoneRestAPIClient()` は引数の検証で投げるし、
     * サーバーやトランスポートの組み立ても投げうる。投げると
     * 外側の catch が 500 を返すが、**枠は握られたまま**になる。
     *
     * インスタンス全体の枠は既定8本しかないので、これを8回踏むと
     * **そのインスタンスは 429 しか返さなくなる**（再起動するまで戻らない）。
     * 経路ごとに書かず、`finally` で一括して返す。
     */
    try {
      // ⚠ **ここから先は上流を呼ぶ。** 相手が受け取れないなら始めない
      if (abandoned) return;

      let kintoneAccessToken: string;
      try {
        // ⚠ **中でも見てもらう。** 保存層の読み取りを挟むので、
        // ここに入った時点では生きていても、cybozu を呼ぶ直前には
        // 締め切りを過ぎていることがある
        kintoneAccessToken = await options.kintoneTokens.getAccessToken(accountId, {
          isAbandoned: () => abandoned,
        });
      } catch (error) {
        // 打ち切りは失敗ではない。応答はすでに決着している
        if (error instanceof KintoneRequestAbandonedError) return;
        if (error instanceof KintoneAuthRequiredError) {
          options.audit.auth("reauth_required", { correlationId, accountId, grantId });
          deny(res, { status: 401, error: "invalid_token", description: "kintone の再認可が必要です" }, correlationId);
          return;
        }
        // ⚠ **kintone の一時障害を認可切れとして返さない** (§7.4)。
        // 401 にすると、ユーザーは不要な再ログインをすることになる。
        options.audit.unexpected({ correlationId, accountId, grantId, where: "kintone-token" }, error);
        res.status(503).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "kintone との連携に失敗しました", data: { correlationId } },
          id: null,
        });
        return;
      }

      /**
       * ⚠ **同意した対象アプリとの積を取る。**
       *
       * 許可リストを変えてもツール名は同じなので、ツールの積では止まらない。
       * 「対象アプリ: 1」で同意した接続が、設定を `2` に変えた途端に
       * アプリ2へ届いていた（外部レビューで再現された）。
       *
       * どちらかが絞っていれば、**両方の積**まで絞る。
       */
      const consentedAppIds = parseAllowedAppIds(connection.consentedAppIds);
      const effectiveAppIds =
        configuredAppIds === undefined
          ? consentedAppIds
          : consentedAppIds === undefined
            ? configuredAppIds
            : new Set([...configuredAppIds].filter((id) => consentedAppIds.has(id)));

      /** 本番と同じ設定を1か所で作り、生成だけ差し替えられるようにする */
      const buildClient = (
        auth: { oAuthToken: string } | { username: string; password: string },
      ): KintoneRestAPIClient => {
        const clientOptions = kintoneClientOptions({
          baseUrl: options.kintoneBaseUrl,
          auth,
          userAgent: options.userAgent,
          deadlineMs: options.deadlineMs,
        });
        return options.createKintoneClient?.(clientOptions) ?? new KintoneRestAPIClient(clientOptions);
      };

      const client = buildClient({ oAuthToken: kintoneAccessToken });

      /**
       * 連携用ユーザーのクライアント。
       *
       * ⚠ **本人のクライアントとは別に作る。**
       * kintone は**パスワード認証を OAuth より優先**するので、
       * 1つのクライアントに両方の資格情報を載せると、
       * すべての操作が連携ユーザーとして実行されてしまう。
       */
      /**
       * ⚠ **設定されているだけでは使わせない。**
       *
       * この接続が**その連携ユーザーに同意しているか**を確かめる。
       * 確かめないと、連携機能を無効のまま認可したトークンが、
       * 有効化した途端にスペース操作を実行できてしまう
       * （主体が入れ替わることに同意していないので、同意の偽装になる）。
       *
       * 名前まで一致させるのは、**連携ユーザーを別人に差し替えたとき**にも
       * 同意し直してほしいから。権限の範囲が変わる。
       */
      const consented =
        options.integrationUser !== undefined &&
        connection.integrationConsent?.username === options.integrationUser.username;

      const integrationClient =
        consented && options.integrationUser
          ? buildClient({
              username: options.integrationUser.username,
              password: options.integrationUser.password,
            })
          : undefined;

      /**
       * 直前の失敗の詳細。
       *
       * `onFailure` は `onOutcome` より前に呼ばれるので、ここで受けて
       * 監査ログにまとめて載せる。バッチを受け付けないので、
       * 1リクエストに1回しか実行されない
       */
      let lastFailure: ToolFailure | undefined;

      const server = createRemoteServer({
        name: "kintone-remote-mcp",
        version: "0.1.0",
        client,
        authMode: "oauth",
        capabilities: options.capabilities,
        appScope: { allowedAppIds: effectiveAppIds },
        // ⚠ 同意した範囲との積を取る。設定を広げても既存の接続には及ばない
        consentedTools: connection.consentedTools,
        ...(integrationClient ? { integrationClient } : {}),
        // ⚠ **応答とログで同じ ID を使う。** 渡さないと境界が独自の ID を作り、
        // 利用者が伝えてきた ID でログを検索しても何も出てこない
        correlationId,
        // ⚠ **繋がないと、kintone のエラーコードと ID がどこにも残らない。**
        // 分類だけでは、サイボウズへ問い合わせるときの手がかりにならない
        onToolFailure: (failure) => {
          lastFailure = failure;
        },
        onToolOutcome: (outcome) =>
          options.audit.toolCall({
            correlationId,
            accountId,
            grantId,
            toolName: outcome.toolName,
            targets: outcome.targets,
            identity: outcome.identity,
            ok: outcome.ok,
            failureKind: outcome.failureKind,
            kintoneCode: lastFailure?.kintoneCode,
            kintoneId: lastFailure?.kintoneId,
            status: lastFailure?.status,
            durationMs: outcome.durationMs,
          }),
      });

      // SDK の型は `sessionIdGenerator` を省略可能として宣言していないため、
      // `exactOptionalPropertyTypes` 下では明示的な undefined を渡せない。
      // 実行時の意味は「セッション ID を発行しない」= ステートレス (§2.2)。
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      } as never);

      /**
       * 後始末。
       *
       * ⚠ **同時実行の枠は、HTTP の終了では解放しない。**
       * 504 を返した後も、クライアントが切断した後も、
       * **kintone への呼び出しは走り続ける**（上流はキャンセルを受け取らない）。
       * ここで解放すると、タイムアウトの連鎖で実際の同時接続が上限を超える。
       * 枠を返すのは、処理そのものが決着してから（下の finally）。
       */

      try {
        // トークンの更新で締め切りを超えていることがある。
        // **ツールの実行はここから始まる**ので、その前に打ち切る
        if (abandoned) return;
        await server.connect(transport as never);
        await transport.handleRequest(req, res, req.body);
      } catch (error) {
        options.audit.unexpected({ correlationId, accountId, grantId, where: "mcp" }, error);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: "2.0",
            error: { code: -32603, message: "内部エラー", data: { correlationId } },
            id: null,
          });
        }
      } finally {
        // ここまで来た時点でツールの実行は終わっている（handleRequest が待つ）。
        // 枠を返してよいのはこの時点（外側の finally で返す）。
        void transport.close();
        void server.close();
      }
    } finally {
      clearTimeout(deadline);
      // ⚠ **ここが枠を返す唯一の場所。** ツールの実行は
      // `handleRequest` が待ち切っているので、この時点で返してよい
      release();
    }
  };

  /**
   * 例外を1つも外へ出さない。
   *
   * ⚠ `void handler(req, res)` のままだと、**認証段階の例外**
   * （`AccessToken.find()` や `isRevoked()` が保存層の障害で投げる）が
   * try の外にあるため未処理の Promise 拒否になり、
   * 応答を返さないままプロセスが落ちうる。
   */
  return async (req: Request, res: Response): Promise<void> => {
    try {
      await handle(req, res);
    } catch (error) {
      options.audit.unexpected({ correlationId: "-", where: "mcp/outer" }, error);
      if (!res.headersSent) {
        res.status(503).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "一時的に処理できません" },
          id: null,
        });
      }
    }
  };
};

import { Firestore } from "@google-cloud/firestore";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import type Provider from "oidc-provider";

import { createAdapterFactory } from "./auth/adapter.js";
import { createBridge } from "./auth/bridge.js";
import { createBridgeRoutes } from "./auth/bridgeRoutes.js";
import { createConnectionGrantStore } from "./auth/connectionGrant.js";
import { createSecretCipher } from "./auth/crypto.js";
import { createCybozuOAuthClient } from "./auth/cybozuOAuth.js";
import { FirestoreStorage } from "./auth/firestoreStorage.js";
import { createKintoneTokenProvider } from "./auth/kintoneToken.js";
import { createProvider, DEFAULT_GRANT_TTL } from "./auth/provider.js";
import { createRevoker } from "./auth/revocation.js";
import type { Storage } from "./auth/storage.js";
import { withStorageTimeout } from "./auth/storageTimeout.js";
import type { ServerConfig } from "./config.js";
import { createMcpEndpoint } from "./mcpEndpoint.js";
import type { ConsentSnapshot } from "./auth/bridge.js";
import { withRequestDeadline } from "./auth/requestDeadline.js";
import { selectTools } from "./adapter/createRemoteServer.js";
import {
  capabilityOf,
  executesAsIntegrationUser,
  isDestructive,
} from "./adapter/toolPolicy.js";
import { createAuditLogger } from "./observability/audit.js";
import { createConcurrencyLimiter, createRateLimiter } from "./observability/rateLimit.js";
import { redactUrl } from "./observability/redact.js";

/**
 * HTTP サーバー。
 *
 * 組み立てだけを行い、判断はそれぞれのモジュールに任せる。
 *
 * ## ミドルウェアの順序が意味を持つ
 *
 * ```
 * Host 検証 → Origin 検証 → 認証前の流量制限 → ボディのパース → 各ルート
 * ```
 *
 * ⚠ **認証前の流量制限は、ボディのパースより前**に置く (§7.2)。
 * パースしてから弾くと、上限までのボディを読む作業だけは通してしまう。
 *
 * ⚠ **`/health` は検証の前**に置く。Cloud Run のヘルスチェックは
 * `Host` にサービスのホスト名を入れてくるとは限らない。
 */

export type BuildOptions = {
  config: ServerConfig;
  /** テストから差し替える。既定は Firestore */
  storage?: Storage;
  /** テストから差し替える */
  fetch?: typeof fetch;
  /** テストから差し替える。kintone へ実際に何が渡るかを確かめるための口 */
  /** テストから差し替える。**本番が実際に渡す設定そのもの**を受け取る */
  createKintoneClient?: (
    options: import("./mcpEndpoint.js").KintoneClientOptions,
  ) => import("@kintone/rest-api-client").KintoneRestAPIClient;
  /** 接続が作られたときに呼ばれる。主体はサーバー内部で生成されるので、外から知る手段が要る */
  onConnectionCreated?: (accountId: string) => void;
  /**
   * 監査ログの出力先。テストから差し替える。
   *
   * ⚠ **これが無いと「ログに何が出るか」を外から確かめられない。**
   * 相関 ID の受け渡しや kintone のエラーコードは、
   * ログに出て初めて意味がある。配線を外しても気づけない状態だった。
   */
  auditSink?: import("./observability/audit.js").AuditSink;
};

export type BuiltServer = {
  app: Express;
  /**
   * 組み立てた provider。
   *
   * テストから**異常なトークンを作る**ために要る。
   * 正常系だけでは「audience 欠落を拒否する」「scope 不足を拒否する」が
   * 一度も実行されない（ミューテーション検査で判明した）。
   */
  provider: Provider;
  /** 終了時に呼ぶ。Firestore の接続を閉じる */
  shutdown: () => Promise<void>;
};

const VERSION = "0.1.0";

/** アクセストークンに載せる scope。`/mcp` はこれを要求する */
const MCP_SCOPE = "kintone:read";

/** MCP の経路。登録と、期限の除外判定の**両方がここを使う** */
const MCP_PATH = "/mcp";

/**
 * MCP の経路か。
 *
 * ⚠ **`req.path === "/mcp"` で比べてはいけない。**
 * Express の既定は**大小文字を区別せず、末尾のスラッシュも無視する**ので、
 * `app.all("/mcp")` には `/mcp/` も `/MCP` も届く。
 * 一致だけで除外していたため、**その2つの綴りには認可用の短い予算が掛かった**
 * （同じ無効トークンで `/mcp` は401、`/mcp/` は503になることを外部レビューが再現）。
 *
 * 経路の綴りで、認証と更新に許される時間が変わってはいけない。
 * **ルーターの照合と同じ規則で判定する。**
 */
export const isMcpPath = (path: string): boolean =>
  path.toLowerCase().replace(/\/$/, "") === MCP_PATH;

export const buildServer = (options: BuildOptions): BuiltServer => {
  const { config } = options;
  const audit = createAuditLogger({
    kintoneBaseUrl: config.kintoneBaseUrl,
    ...(options.auditSink ? { sink: options.auditSink } : {}),
  });

  // ⚠ 環境変数 FIRESTORE_DATABASE は SDK が読まない。明示的に渡す。
  const firestore = options.storage
    ? undefined
    : new Firestore(
        config.firestoreDatabaseId ? { databaseId: config.firestoreDatabaseId } : {},
      );
  /**
   * ⚠ **保存層には必ず期限を掛ける。**
   *
   * 掛けないと、Firestore が黙ったときに `/token` や `/auth` が
   * **いつまでも応答を返さない**（`/mcp` の締め切りはここには効かない）。
   * 差し替え可能な口の外側で包むので、**テストの実装にも同じ期限が掛かる**。
   */
  const storage: Storage = withStorageTimeout(
    options.storage ??
      new FirestoreStorage({ firestore: firestore!, collection: config.firestoreCollection }),
    config.limits.storageTimeoutMs,
  );

  const cipher = createSecretCipher(config.tokenEncryptionKey);
  const grants = createConnectionGrantStore({ storage, cipher });
  const revoker = createRevoker({
    storage,
    cipher,
    grants,
    onRevoke: (info) =>
      audit.auth("connection_revoked", { correlationId: "-", accountId: info.accountId }, {
        reason: info.reason,
      }),
  });

  const provider = createProvider({
    issuer: config.issuer,
    adapter: createAdapterFactory({
      storage,
      cipher,
      // ⚠ **ここで理由は分からない。** provider は
      // 「再使用を検知したとき」も「利用者が切断したとき」も同じ口を呼ぶ。
      // 決め打ちで `token-reuse` と記録していたため、
      // **正常な切断が盗用の疑いとして残っていた**（外部レビューで指摘）。
      // 理由は、経路が分かる provider のイベント側で記録する。
      revokeByGrantId: (grantId) => revoker.revokeByGrantId(grantId, "provider-revoked"),
      isConnectionRevoked: (accountId) => grants.isRevoked(accountId),
    }),
    resource: { resource: config.resource, scopes: [MCP_SCOPE] },
    cookieKeys: config.cookieKeys,
    secureCookies: config.secureCookies,
    cimdAllowedHosts: config.cimdAllowedHosts,
    ...(config.jwks ? { jwks: config.jwks } : {}),
  });

  /**
   * ⚠ **provider のエラーを取りこぼさない。**
   *
   * `oidc-provider` は失敗をイベントで通知し、応答には
   * 「oops! something went wrong」しか出さない。購読していないと、
   * **500 が出ている事実だけ見えて理由がどこにも残らない**（実際にそうなった）。
   */
  /**
   * 正常系も記録する。
   *
   * ⚠ **失敗だけ記録しても、何が起きたかは分からない。**
   * 認可を完走しても監査ログが空だったので、
   * 「誰がいつ繋いだか」を後から言えなかった（外部レビューで指摘）。
   */
  provider.on("grant.success", (ctx) => {
    const grantType = (ctx as { oidc?: { params?: { grant_type?: unknown } } }).oidc?.params
      ?.grant_type;
    audit.auth(
      grantType === "refresh_token" ? "token_refreshed" : "token_issued",
      { correlationId: "-" },
      // ⚠ トークンそのものは絶対に載せない。種別だけ
      { reason: typeof grantType === "string" ? grantType : "unknown" },
    );
  });

  /**
   * 失効の**理由**は、ここでしか分からない。
   *
   * アダプタ側は provider に呼ばれるだけで、
   * 「再使用の検知」か「利用者の切断」かを区別できない。
   * 経路 (`ctx.oidc.route`) を見て記録する。
   *
   * | 経路 | 意味 |
   * | --- | --- |
   * | `revocation` | 利用者が切断した（正常） |
   * | `token` | **リフレッシュトークンの再使用を検知した**（異常） |
   */
  provider.on("grant.revoked", (ctx, grantId) => {
    const route = (ctx as { oidc?: { route?: unknown } }).oidc?.route;
    const reason =
      route === "revocation"
        ? "revocation-request"
        : route === "token"
          ? "token-reuse"
          : `provider:${typeof route === "string" ? route : "unknown"}`;
    audit.auth("connection_revoked", { correlationId: "-", grantId }, { reason });
  });

  provider.on("server_error", (_ctx, error) => {
    audit.unexpected({ correlationId: "-", where: "oidc-provider" }, error);
  });
  provider.on("authorization.error", (_ctx, error) => {
    audit.unexpected({ correlationId: "-", where: "oidc-provider/authorization" }, error);
  });
  provider.on("grant.error", (_ctx, error) => {
    audit.unexpected({ correlationId: "-", where: "oidc-provider/grant" }, error);
  });

  const cybozu = createCybozuOAuthClient(
    {
      baseUrl: config.kintoneBaseUrl,
      clientId: config.cybozuClientId,
      clientSecret: config.cybozuClientSecret,
      redirectUri: `${config.issuer.replace(/\/$/, "")}/oauth/callback`,
      scopes: config.cybozuScopes,
      timeoutMs: config.limits.cybozuTimeoutMs,
    },
    options.fetch ? { fetch: options.fetch as never } : {},
  );

  const kintoneTokens = createKintoneTokenProvider({
    grants,
    cybozu,
    revoker,
    onRefresh: (info) =>
      audit.auth(info.outcome === "refreshed" ? "token_refreshed" : "reauth_required", {
        correlationId: "-",
        accountId: info.accountId,
      }),
  });

  const preAuthLimiter = createRateLimiter({
    windowSeconds: 60,
    limit: config.limits.preAuthPerMinute,
  });
  /**
   * 認証前の**総量**。
   *
   * ⚠ **送信元ごとの制限は、総量の上限にならない。**
   * 送信元は詐称でも分散でも増やせるので、「1つあたり60回/分」は
   * 「全体で60回/分」を意味しない。`X-Forwarded-For` の扱いを
   * 間違えていれば、1つの接続元からでも枠を増やせる。
   * **送信元に依存しない枠**を1つ置いて、Firestore と KMS を守る。
   */
  const preAuthTotalLimiter = createRateLimiter({
    windowSeconds: 60,
    limit: config.limits.preAuthTotalPerMinute,
  });
  const grantLimiter = createRateLimiter({
    windowSeconds: 60,
    limit: config.limits.grantPerMinute,
  });
  const concurrency = createConcurrencyLimiter(config.limits.concurrentPerGrant);
  /**
   * kintone ドメイン全体を守る枠 (§7.2)。
   *
   * ⚠ **grant 単位の枠だけでは足りない。** 接続が増えるほど枠も増えるので、
   * 上流への同時実行は接続数に比例して伸びる。kintone はドメインあたり
   * 100同時要求が上限で、超えると**同じドメインの他の利用にも響く**。
   */
  const totalConcurrency = createConcurrencyLimiter(config.limits.concurrentTotal);

  const app = express();
  app.disable("x-powered-by");

  // Cloud Run は TLS を手前で終端する。設定しないと `req.ip` が
  // 利用者の IP にならず、**同じプロキシ経由の全員が枠を共有する**。
  //
  // ⚠ **`true` にしてはいけない。** Express は `true` だと
  // `X-Forwarded-For` の**左端**を採るが、そこは送信者が自由に書ける。
  // Cloud Run は既存の値を検証も削除もせず実 IP を**末尾に追記**するので、
  // 左端を信じると、ヘッダーを1行足すだけで送信元ごとの枠を増やせる。
  // ホップ数を指定すると Express は**右から数えて**信頼する (config.ts)。
  app.set("trust proxy", config.trustedProxyHops);

  /**
   * ヘルスチェック。**認証も Host 検証も掛けない。**
   *
   * デプロイしたものが動いているかを、認証なしで確かめられるようにする。
   * version を返すのは、古いリビジョンが動いていることに気づかないまま
   * 調査を続ける事故を防ぐため。
   */
  app.get("/health", (_req, res) => {
    res.json({ status: "ok", version: VERSION });
  });

  /**
   * Host 検証（DNS rebinding 対策）。
   *
   * ⚠ **未設定なら素通しにしない。** 設定の読み込み時点で必須にしてある (config.ts)。
   * 「未設定なら全部許可」にすると、設定を忘れた状態で公開される。
   */
  app.use((req: Request, res: Response, next: NextFunction) => {
    const host = req.headers.host;
    const hostname = typeof host === "string" ? host.split(":")[0] : undefined;
    if (!hostname || !config.allowedHosts.includes(hostname)) {
      res.status(403).json({ error: "Forbidden: host not allowed" });
      return;
    }
    next();
  });

  /**
   * Origin 検証。
   *
   * CORS ヘッダーを付けない方式は「ブラウザに応答を読ませない」だけで、
   * **リクエストの実行は止まらない** (§2.3)。MCP 仕様が求めるのは拒否なので、
   * 許可外の Origin は 403 にする。
   *
   * ⚠ **全ルートに掛けてはいけない。** 同意画面のフォーム送信は
   * ブラウザが**自分自身の Origin** を付けてくるので、
   * `ALLOWED_ORIGINS` が空の状態で全体に掛けると
   * **自分の同意 POST が 403 になる**（実ブラウザでのみ起きる）。
   *
   * → **`/mcp` にだけ掛ける。** 同意フォームは CSRF トークンで守る (§4.6)。
   * 自分自身の Origin は常に許可する。
   */
  /**
   * 認可まわりの要求に、**全体の予算**を掛ける。
   *
   * ⚠ **保存層の操作ごとの期限では足りない。**
   * 操作のたびにタイマーが始まり直すので、1回4秒の読み取りを6回すれば
   * 個別の期限に一度も掛からないまま24秒かかる（外部レビューで実測された）。
   *
   * `/mcp` は自前の締め切りを持っているので、ここでは掛けない。
   */
  const withAuthDeadline = (req: Request, _res: Response, next: NextFunction): void => {
    /**
     * ⚠ **`/mcp` には掛けない。**
     *
     * あちらは自前の締め切り（既定55秒）を持っている。
     * ここで認可用の予算（既定10秒）を被せると、**ツール実行が
     * 途中で切られる**。登録の順序に頼ると、あとから経路を足したときに
     * 静かに巻き込むので、経路そのもので判断する。
     */
    if (isMcpPath(req.path)) {
      next();
      return;
    }
    withRequestDeadline(config.limits.authRequestDeadlineMs, () => next());
  };

  const selfOrigin = new URL(config.issuer).origin;
  const originGuard = (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin;
    if (
      typeof origin === "string" &&
      origin !== selfOrigin &&
      !config.allowedOrigins.includes(origin)
    ) {
      res.status(403).json({ error: "Forbidden: origin not allowed" });
      return;
    }
    next();
  };

  /**
   * 認証前の流量制限 (§7.2)。
   *
   * ⚠ **ボディのパースより前、Firestore と KMS に触る前**に置く。
   * `/auth` の乱打で認可トランザクションを量産されたり、
   * でたらめな Bearer で Firestore 照会と KMS 復号を誘発されたりするのを防ぐ。
   */
  app.use((req: Request, res: Response, next: NextFunction) => {
    /**
     * ⚠ **送信元の判定が先。総量はそのあと。**
     *
     * 逆にすると、**送信元制限で既に拒否されている相手が、
     * 送り続けるだけで総量枠を使い切れる**。総量枠は全利用者で共有なので、
     * 1つの送信元が他の全員を締め出せることになる（実測で確認）。
     * 既定値なら、同じ送信元からの600要求でそのインスタンスが止まる。
     *
     * 総量を「拒否しなかった要求」だけで数えれば、
     * 攻撃者が消費できるのは自分の送信元枠（既定60/分）までに収まる。
     */
    const source = req.ip ?? "unknown";
    const decision = preAuthLimiter.check(source);
    if (!decision.allowed) {
      audit.rateLimited({ correlationId: "-", scope: "pre-auth", limit: decision.limit });
      res.setHeader("Retry-After", String(decision.retryAfterSeconds));
      res.status(429).json({ error: "Too Many Requests" });
      return;
    }

    // 送信元を分散されると上の枠は効かない。**送信元を見ない枠**で受け止める
    const total = preAuthTotalLimiter.check("all");
    if (!total.allowed) {
      audit.rateLimited({ correlationId: "-", scope: "pre-auth-total", limit: total.limit });
      res.setHeader("Retry-After", String(total.retryAfterSeconds));
      res.status(429).json({ error: "Too Many Requests" });
      return;
    }
    next();
  });

  /**
   * RFC 9728 の保護リソースメタデータ。
   *
   * **認証不要。** クライアントはトークンを持っていない状態でここを読む。
   * `resource` は**ユーザーが Claude に入力する URL と完全一致**させる。
   */
  /**
   * ⚠ **2か所で返す。RFC 9728 の場所と、ルート。**
   *
   * RFC 9728 は、リソース識別子のパスを
   * **`/.well-known/oauth-protected-resource` の後ろに差し込む**と定めている。
   * このサーバーのリソースは `https://host/mcp` なので、
   * 仕様どおりの場所は **`/.well-known/oauth-protected-resource/mcp`**。
   *
   * ルートにしか置いていなかった。Claude はルートに後退して拾うので
   * 気づかなかったが、**ChatGPT は仕様どおりの場所を先に見て 404 を受け**、
   * 認可に進まずに探索を繰り返していた（実測）。
   *
   * ルート側も残す。落とすと、後退でしか拾わないクライアントが繋がらなくなる。
   */
  const protectedResourceMetadata = (_req: Request, res: Response): void => {
    res.setHeader("Cache-Control", "no-store");
    res.json({
      resource: config.resource,
      authorization_servers: [config.issuer],
      scopes_supported: [MCP_SCOPE],
      bearer_methods_supported: ["header"],
    });
  };

  // 仕様どおりの場所。リソースのパス（既定では `/mcp`）を後ろに付ける
  app.get(
    `/.well-known/oauth-protected-resource${new URL(config.resource).pathname}`,
    protectedResourceMetadata,
  );
  // 後退して拾うクライアント向け
  app.get("/.well-known/oauth-protected-resource", protectedResourceMetadata);

  // 同意画面と cybozu からの戻り
  /**
   * ⚠ **ここから下すべてに予算を掛ける。**
   *
   * 同意画面・cybozu からの戻り・provider（`/auth` `/token` `/revocation`）が
   * 対象。`/mcp` は上で登録済みで、自前の締め切りを持っているので掛からない。
   *
   * 掛ける場所を1つにする。2か所に書くと、片方を消しても
   * もう片方が覆ってしまい、**壊れていることに気づけない**（変異検査で判明）。
   */
  app.use(withAuthDeadline);

  app.use(
    createBridgeRoutes({
      provider,
      bridge: createBridge({ storage, cipher }),
      cybozu,
      // ⚠ **記録はテスト用のフックと無関係に行う。**
      // フックが渡されたときだけ包む作りだったので、
      // **本番では接続の作成がどこにも残らなかった**
      grants: {
        ...grants,
        // ⚠ **引数を全部渡す。** 2つしか受けていなかったため、
        // **同意が一度も保存されていなかった**（外部レビューで判明）。
        // テストのハーネスで同じ間違いを直しながら、ここを見落としていた
        create: async (...args) => {
          await grants.create(...args);
          audit.auth("connection_created", { correlationId: "-", accountId: args[0] });
          options.onConnectionCreated?.(args[0]);
        },
      },
      revoker,
      storage,
      cipher,
      kintoneHost: new URL(config.kintoneBaseUrl).hostname,
      /**
       * 同意画面に出す内容。
       *
       * ⚠ **`consent()` は同意画面を出すときに呼ばれる。**
       * そこで確定した内容が保存され、承認・callback ではそれを使う。
       * 表示と保存が同じ値から出るので、ずれようがない
       */
      // ⚠ provider の Grant と同じ寿命にする。片方だけ切れると、
      // 認可は切れているのに資格情報が残る状態になる
      connectionTtlSeconds: DEFAULT_GRANT_TTL,
      consent: () => {
        const { permissions, consent } = describeConsent(config);
        return { ...consent, permissions };
      },
      resource: config.resource,
      resourceScopes: [MCP_SCOPE],
      secureCookies: config.secureCookies,
      onFailure: (info) =>
        audit.auth(
          "bridge_rejected",
          { correlationId: "-" },
          {
            reason: `${info.stage}:${info.reason}`,
            // 秘密を含まない診断。無いと「失敗した」しか残らない
            ...(info.detail ? { detail: info.detail } : {}),
          },
        ),
    }),
  );

  // MCP 本体
  const mcp = createMcpEndpoint({
    provider,
    kintoneTokens,
    grants,
    audit,
    resource: config.resource,
    kintoneBaseUrl: config.kintoneBaseUrl,
    capabilities: config.capabilities,
    ...(config.integrationUser ? { integrationUser: config.integrationUser } : {}),
    allowedAppIds: config.allowedAppIds,
    rateLimiter: grantLimiter,
    concurrency,
    totalConcurrency,
    requiredScopes: [MCP_SCOPE],
    deadlineMs: config.limits.deadlineMs,
    userAgent: `kintone-remote-mcp@${VERSION}`,
    ...(options.createKintoneClient ? { createKintoneClient: options.createKintoneClient } : {}),
  });
  /**
   * Content-Type を `application/json` **だけ**に限る。
   *
   * ⚠ **`express.json` に任せてはいけない。** 既定の型判定は
   * `application/json` に**厳密一致**するが、MCP SDK 側は
   * `ct.includes("application/json")` の**部分一致**で受理する。
   * この食い違いが、検査を丸ごと飛ばす抜け道になる:
   *
   * `Content-Type: application/json-patch+json` を付けると、
   * Express は解析せず `req.body` が未定義のまま素通りし、
   * SDK が自分で本文を読む。結果、**バッチ拒否も
   * `limit` によるサイズ上限も効かない**（実測で確認）。
   *
   * ここで型名を確定させ、`mcpEndpoint` 側で
   * 「解析済みの単一オブジェクトか」をもう一度見る。
   * どちらか片方でも欠けると迂回できる。
   */
  const jsonOnlyGuard = (req: Request, res: Response, next: NextFunction): void => {
    // POST 以外は本文を持たない。405 は MCP のエンドポイントが返す
    if (req.method !== "POST") {
      next();
      return;
    }
    const header = req.headers["content-type"];
    const mediaType =
      typeof header === "string" ? (header.split(";")[0] ?? "").trim().toLowerCase() : "";
    if (mediaType !== "application/json") {
      res.status(415).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Content-Type は application/json のみ受け付けます" },
        id: null,
      });
      return;
    }
    next();
  };

  app.all(
    MCP_PATH,
    originGuard,
    jsonOnlyGuard,
    express.json({ limit: config.limits.maxBodyBytes }),
    (req, res, next) => {
      // ⚠ Promise を投げっぱなしにしない。
      // 認証段階の例外が未処理の Promise 拒否になり、プロセスが落ちうる。
      mcp(req, res).catch(next);
    },
  );

  // provider（discovery / /auth / /token / revocation）
  app.use(provider.callback());

  /**
   * 最外周のエラーハンドラ。
   *
   * ⚠ **例外をそのまま返さない。** 参考にした実装は `error.message` を
   * 応答に載せていたが、それをすると資格情報が外に出る (§7.4)。
   */
  app.use((error: unknown, req: Request, res: Response, _next: NextFunction) => {
    // body-parser の拒否は「想定外」ではない。500 で返すと、
    // 送った側は原因が分からず、こちらのログは異常として溜まる
    const type = (error as { type?: unknown } | null)?.type;
    if (type === "entity.too.large") {
      if (!res.headersSent) res.status(413).json({ error: "Payload Too Large" });
      return;
    }
    if (type === "entity.parse.failed") {
      if (!res.headersSent) res.status(400).json({ error: "Bad Request" });
      return;
    }

    audit.unexpected({ correlationId: "-", where: redactUrl(req.originalUrl) }, error);
    if (res.headersSent) return;
    res.status(500).json({ error: "Internal Server Error" });
  });

  return {
    app,
    provider,
    shutdown: async () => {
      await firestore?.terminate();
    },
  };
};

/** 同意画面に出す権限の説明。**有効な capability から導く** (§4.7) */
/**
 * 同意画面に出すものと、接続に記録するものを**同じ場所から作る**。
 *
 * ⚠ **別々に作ってはいけない。** 画面に出していない連携ユーザーを
 * 記録すると、「利用者が見ていないものに同意した」ことになる。
 * 逆に、出したのに記録しないと、繋ぎ直しても使えない。
 */
export const describeConsent = (
  config: ServerConfig,
): { permissions: string[]; consent: ConsentSnapshot } => {
  const exposed = exposedToolNames(config);
  const permissions = describePermissions(config);
  const disclosed = permissions.some((line) => line.includes("あなたではなく"));
  return {
    permissions,
    consent: {
      // ⚠ **公開したツールをそのまま残す。** capability フラグでは、
      // 「削除に同意したか」を後から言い換えることになる
      toolNames: exposed,
      integrationUser:
        disclosed && config.integrationUser
          ? { username: config.integrationUser.username }
          : undefined,
      // 画面に出した対象アプリも固定する。ツール名だけでは境界の変更を止められない
      allowedAppIds: config.allowedAppIds,
    },
  };
};

/** いまの設定で公開されるツール。表示・記録・実行の判断をここ1つに寄せる */
const exposedToolNames = (config: ServerConfig): string[] =>
  selectTools("oauth", config.capabilities, {
    integrationUser: config.integrationUser !== undefined,
    appScoped: config.allowedAppIds !== undefined,
  }).map((tool) => tool.name);

/**
 * 同意画面に出す説明を、**実際に公開するツールから作る**。
 *
 * ⚠ **手で並べた一覧にしない。** 以前は capability フラグを直接見ていたため、
 * **削除を有効にしても画面の表示が変わらなかった**（外部レビューで指摘）。
 * 「スペースの作成・変更」とだけ書かれた画面で、削除に同意したことになっていた。
 *
 * 公開の判断 (`selectTools`) と同じ入力から作れば、
 * **出したものと許可したものがずれない**。
 */
const describePermissions = (config: ServerConfig): string[] => {
  const exposed = exposedToolNames(config);

  /** capability と「削除かどうか」の組に対する説明 */
  const LABEL: Record<string, string> = {
    "recordRead:false": "レコードの参照",
    "recordWrite:false": "レコードの登録・更新",
    "recordWrite:true": "レコードの削除（**元に戻せません**）",
    "appRead:false": "アプリ設定の参照",
    "appWrite:false": "アプリ設定の変更・本番反映",
    "appWrite:true": "フィールドの削除（**元に戻せません**）",
    "fileDownload:false": "添付ファイルの取得",
    "spaceRead:false": "スペースの参照",
    "spaceWrite:false": "スペースの作成・変更",
    "spaceWrite:true": "スペースの削除（**置かれているアプリごと使えなくなります**）",
    "search:false": "横断検索",
  };

  const seen = new Set<string>();
  const forUser: string[] = [];
  const forIntegration: string[] = [];

  for (const name of exposed) {
    const capability = capabilityOf(name);
    if (!capability) continue;
    const key = `${capability}:${isDestructive(name)}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const label = LABEL[key];
    if (!label) continue;
    // 連携ユーザーとして動くものは、分けて見せる
    (executesAsIntegrationUser(name, "oauth") ? forIntegration : forUser).push(label);
  }

  const permissions = [...forUser];

  if (config.allowedAppIds) {
    permissions.push(`対象アプリ: ${config.allowedAppIds}`);
  } else {
    permissions.push("対象: あなたがアクセスできるすべてのアプリ");
  }

  /**
   * ⚠ **連携ユーザーとして実行されることを、必ず見せる。**
   *
   * 見えないところで主体が入れ替わるのは、利用者が予期できない。
   *
   * ⚠ **仕組みだけでなく、結果を書く。**
   * 「連携用ユーザーとして実行されます」だけだと、
   * 「裏方が代わりにやるのだろう」としか読めない。
   * 実際に起きるのは**あなたの視界が広がること**で、
   * 実環境で確認済み: 第三者が管理する非公開スペースに
   * 連携ユーザーだけが参加している状態で、**非メンバーの本人に中身が返った**。
   * 同意を求める以上、同意する内容を書く。
   */
  if (forIntegration.length > 0 && config.integrationUser) {
    permissions.push(
      `${forIntegration.join("・")}（⚠ あなたではなく連携用ユーザー「${config.integrationUser.username}」として実行されます。` +
        // ⚠ **ここは HTML になる。Markdown の強調は効かない。**
        // `**` を書いたら、同意画面にアスタリスクがそのまま出た（実物を描いて気づいた）
        `そのため、あなたが参加していない非公開スペースの内容も読めます）`,
    );
  }

  return permissions;
};

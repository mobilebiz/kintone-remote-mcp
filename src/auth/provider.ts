import Provider, { errors, interactionPolicy } from "oidc-provider";
import type { Configuration } from "oidc-provider";

import type { AdapterFactory } from "./adapter.js";

/**
 * Claude から見た認可サーバー。
 *
 * 実際の認可は cybozu.com へ委譲し、ここは「Claude に対する OAuth の顔」になる (§4.4)。
 * **中核は `oidc-provider` に任せ、自前で書くのはブリッジと保管だけ**という方針。
 *
 * ただし**既定値のまま使うと成立しない**ものがいくつもある。
 * v9.12.2 のソースで確認したうえで、ひとつずつ潰す。
 */

/** 保護リソース（この MCP サーバー自身）の識別子と、そこで使う scope */
export type ResourceConfig = {
  /** `https://HOST/mcp`。**Claude に入力してもらう URL と完全一致させる** */
  resource: string;
  /** アクセストークンに束縛する scope */
  scopes: string[];
};

export type ProviderOptions = {
  /** `https://HOST`。パスは付けない (§4.6) */
  issuer: string;
  adapter: AdapterFactory;
  resource: ResourceConfig;
  /** Cookie 署名鍵。**全インスタンスで共有する**（インスタンスごとに違うと interaction が壊れる） */
  cookieKeys: string[];
  /** アクセストークンの寿命（秒） */
  accessTokenTtl?: number;
  /** リフレッシュトークンの寿命（秒） */
  refreshTokenTtl?: number;
  /**
   * 接続そのものの寿命（秒）。
   *
   * ⚠ **更新では延びない。** これを過ぎると、使い続けていても
   * 認可をやり直すことになる。
   */
  grantTtl?: number;
  /**
   * id_token の署名鍵。
   *
   * **本番では必ず渡す。** 省略すると provider が起動のたびに開発用の鍵を作り、
   * 「quick start development-only signing keys are used」と警告する。
   * インスタンスごとに鍵が変わるので、複数インスタンスでは整合しない。
   */
  jwks?: { keys: Record<string, unknown>[] };
  /**
   * Cookie に `Secure` を付けるか。既定 true。
   * ローカルの平文 HTTP で試すときだけ false にする。
   */
  secureCookies?: boolean;
  /**
   * 信頼できるリバースプロキシの配下か。既定は `secureCookies` と同じ。
   *
   * ⚠ **`Secure` を明示するだけでは足りない。**
   * `Provider` は Koa を継承していて `provider.proxy`（既定 `false`）を持つ。
   * これが false のままだと、TLS を手前で終端した構成では `ctx.secure` が false になり、
   * Cookie の発行が **`Cannot send secure cookie over unencrypted connection`**
   * で失敗する。
   *
   * 「v9 に proxy 設定は無い」と一度結論したが、**設定オブジェクトの項目ではなく
   * インスタンスのプロパティ**だった。Cloud Run では true にする。
   */
  trustProxy?: boolean;
};

/** hosted Claude（スマホ／Claude.ai／Desktop）用のクライアント ID */
export const CLAUDE_HOSTED_CLIENT_ID = "claude-hosted";

/**
 * hosted Claude の転送先。
 *
 * Claude.ai / Desktop / mobile / Cowork はすべてこの1つ。
 * **Claude Code のループバック転送先はフェーズ1 では登録しない** (§4.6)。
 */
const CLAUDE_HOSTED_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";

const DEFAULT_ACCESS_TOKEN_TTL = 60 * 60;
const DEFAULT_REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30;

/**
 * 接続そのものの寿命。
 *
 * ⚠ **リフレッシュトークンの寿命とは別物。**
 * リフレッシュのたびにトークンは更新されるが、**親の Grant は延びない**。
 * 同じ値にしていたため、**使い続けていても初回の認可から30日で
 * 更新できなくなっていた**（外部レビューで、29日目は成功・31日目は
 * `invalid_grant` になることを実測された）。
 *
 * 接続は「切断するまで生きる」設計 (§4.9) なので、
 * ここはトークンの寿命よりずっと長く取る。
 * それでも上限はある。**無期限にはしない** —
 * 使われなくなった接続が永遠に残ると、失効の手立てが切断だけになる。
 */
export const DEFAULT_GRANT_TTL = 60 * 60 * 24 * 400;

/**
 * 新規の認可要求では、必ずブリッジ（同意 → cybozu 認可）を通す。
 *
 * 既定の login プロンプトは「セッションに主体があれば飛ばす」ので、
 * ブラウザに前回のセッションが残っていると **cybozu の認可を経ずに
 * トークンが出てしまう**。接続ごとに kintone のトークンを持つ設計が崩れる。
 *
 * この認可要求の中でブリッジを終えた（= `result.login` がある）ときだけ通す。
 */
const buildInteractionPolicy = (): interactionPolicy.DefaultPolicy => {
  const policy = interactionPolicy.base();

  const bridgeCheck = new interactionPolicy.Check(
    "kintone_bridge_required",
    "kintone の認可が必要です",
    (ctx) =>
      ctx.oidc.result?.login
        ? interactionPolicy.Check.NO_NEED_TO_PROMPT
        : interactionPolicy.Check.REQUEST_PROMPT,
  );

  const loginPrompt = policy.get("login");
  if (!loginPrompt) throw new Error("login プロンプトが見つかりません");
  loginPrompt.checks.add(bridgeCheck);

  return policy;
};

export const createProvider = (options: ProviderOptions): Provider => {
  const accessTokenTtl = options.accessTokenTtl ?? DEFAULT_ACCESS_TOKEN_TTL;
  const refreshTokenTtl = options.refreshTokenTtl ?? DEFAULT_REFRESH_TOKEN_TTL;
  const grantTtl = options.grantTtl ?? DEFAULT_GRANT_TTL;
  const secureCookies = options.secureCookies ?? true;

  const configuration: Configuration = {
    adapter: options.adapter,

    clients: [
      {
        client_id: CLAUDE_HOSTED_CLIENT_ID,
        redirect_uris: [CLAUDE_HOSTED_REDIRECT_URI],
        // public client。シークレットを持たない。
        // → v9.12.2 の pkceRequired は clientAuthMethod === 'none' で true を返すので、
        //   PKCE はこの指定だけで必須になる。
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        /**
         * ⚠ ここに書けるのは **AS がサポートする scope だけ**。
         * kintone 向けの `kintone:read` などを混ぜると、provider は
         * `invalid_client_metadata: scope must only contain Authorization Server
         * supported scope values` でクライアントの読み込み自体に失敗する（再現済み）。
         *
         * リソース側の scope は `resourceIndicators.getResourceServerInfo` が持ち、
         * grant には `addResourceScope()` で付ける。**別系統**である。
         */
        /**
         * ⚠ ここに書けるのは **AS がサポートする scope だけ**（`scopes` 設定）。
         * リソース側の scope（`kintone:read` など）を混ぜると
         * `invalid_client_metadata` でクライアントの読み込み自体が失敗する。
         *
         * ⚠ 逆に、`scopes` 設定に足して**両方に載せてもいけない**。
         * OIDC scope として扱われ、同意の判定対象になるため、
         * `addOIDCScope` していないと**interaction が無限に繰り返される**。
         *
         * リソース側の scope は `getResourceServerInfo` と
         * `addResourceScope` が持つ**別系統**。要求パラメータに載せても
         * ここでは弾かれない。
         */
        scope: "openid",
      },
    ],

    features: {
      // ⚠ 既定は有効。開発用のログイン画面が本番に残る。
      devInteractions: { enabled: false },

      // ⚠ 既定は無効。切断（接続の取り消し）を実装するのに要る。
      revocation: { enabled: true },

      resourceIndicators: {
        enabled: true,
        // 既定の getResourceServerInfo は「必ず差し替えろ」と例外を投げる。
        getResourceServerInfo: (_ctx, resourceIndicator) => {
          if (resourceIndicator !== options.resource.resource) {
            // 自分宛でない resource へのトークンは発行しない。
            // **通常の Error を投げると server_error(500) になる。**
            // これはクライアントの入力の問題なので、OAuth のエラーとして返す。
            throw new errors.InvalidTarget("この resource には発行できません");
          }
          return {
            scope: options.resource.scopes.join(" "),
            audience: options.resource.resource,
            // JWT にすると失効できない。不透明トークンにして Adapter で管理する。
            accessTokenFormat: "opaque",
            accessTokenTTL: accessTokenTtl,
          };
        },
        // resource の指定が無い要求でも、この1つに解決する。
        defaultResource: () => options.resource.resource,
        useGrantedResource: () => true,
      },
    },

    /**
     * ⚠ **既定のままではリフレッシュトークンが一度も発行されない。**
     *
     * v9.12.2 の既定は `source.scopes.has('offline_access')` を要求するが、
     * その `offline_access` は `prompt=consent` を含まない認可要求で
     * `lib/actions/authorization/scopes.js` により除去される。
     * Claude がそのパラメータを送る保証は無い。
     *
     * → **`offline_access` に依存せず、このクライアントには常に発行する** (§4.10)。
     * scope に現れない以上、継続アクセスの同意は同意画面で伝える責任がこちらにある。
     */
    issueRefreshToken: async (_ctx, client) =>
      client.clientId === CLAUDE_HOSTED_CLIENT_ID && client.grantTypeAllowed("refresh_token"),

    // public client なのでローテーションする (RFC 9700 §4.14)。
    // 既定の実装は系列の総寿命が約1年を超えると false を返すので、明示的に常に true。
    rotateRefreshToken: true,

    ttl: {
      AccessToken: accessTokenTtl,
      RefreshToken: refreshTokenTtl,
      AuthorizationCode: 60,
      Interaction: 60 * 10,
      Session: 60 * 10,
      // ⚠ **リフレッシュトークンと同じにしない。** Grant は更新で延びないので、
      // 同じにすると使い続けていても初回の認可から切れる
      Grant: grantTtl,
    },

    // ブラウザのセッションが切れても接続を維持する。
    // スマホから使うので、ブラウザが登場するのは認可のときだけ。
    expiresWithSession: async () => false,

    cookies: {
      keys: options.cookieKeys,
      long: { signed: true, sameSite: "lax", secure: secureCookies, httpOnly: true },
      short: { signed: true, sameSite: "lax", secure: secureCookies, httpOnly: true },
    },

    // 同意画面は自前 (§4.6)。provider の interaction からここへ飛ばす。
    interactions: {
      url: (_ctx, interaction) => `/interaction/${interaction.uid}`,
      policy: buildInteractionPolicy(),
    },

    /**
     * ⚠ **既存のセッションから Grant を拾わない。**
     *
     * v9.12.2 の既定はこうなっている:
     *
     *   const grantId = ctx.oidc.result?.consent?.grantId
     *     || ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId);
     *
     * 後半のフォールバックがあると、**同じブラウザで2回目の認可をしたとき、
     * 同意も cybozu の認可も飛ばして、1回目と同じ accountId のトークンが出る**
     * （外部レビューで再現された）。接続ごとに主体と kintone トークンを持つ
     * この設計では成立しない。
     *
     * → **この認可要求の中でブリッジを完了したときにだけ** Grant を使う。
     *
     * > **これは二重防御である。** `buildInteractionPolicy()` の「ブリッジ必須」
     * > チェックが先に効くので、この差し替えを既定に戻してもテストは落ちない
     * > （ミューテーション検査で確認済み）。片方だけに頼らないために両方置く。
     */
    loadExistingGrant: async (ctx) => {
      // ⚠ **セッションへのフォールバックを消してはいけない。**
      //
      // 当初は `result.consent.grantId` だけを使うようにしていたが、
      // **応答を組み立てる段階では `ctx.oidc.result` が既に無い**ため、
      // grant が見つからず、**アクセストークンの scope が空になった**
      // （resource scope は grant から引かれる）。
      //
      // 「2回目の接続でブリッジを飛ばさない」保証は、
      // interaction policy の「ブリッジ必須」チェックが担っている。
      // ここでの重複した防御は、副作用のほうが大きかった。
      const grantId =
        ctx.oidc.result?.consent?.grantId ??
        ctx.oidc.session?.grantIdFor(ctx.oidc.client!.clientId);
      return grantId ? ctx.oidc.provider.Grant.find(grantId) : undefined;
    },

    /**
     * 主体はこちらで作る。
     *
     * cybozu の token 応答にユーザー識別子が含まれないので、
     * kintone のユーザー名は使えない (§4.10)。接続ごとのランダム値を主体にし、
     * ここでは kintone を一切叩かない。
     */
    findAccount: async (_ctx, sub) => ({
      accountId: sub,
      claims: async () => ({ sub }),
    }),

    claims: { openid: ["sub"] },
    // AS としてサポートする scope。**リソース側の scope は載せない**
    // （載せると同意の判定対象になり、interaction が繰り返される）
    scopes: ["openid"],
    ...(options.jwks ? { jwks: options.jwks } : {}),

    // 発行するトークンは不透明。JWT にすると失効できない。
    enabledJWA: {},
  };

  const provider = new Provider(options.issuer, configuration);

  // Koa 由来のインスタンスプロパティ。設定オブジェクトには無い。
  provider.proxy = options.trustProxy ?? secureCookies;

  return provider;
};

import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { loadConfig, ConfigError } from "../../src/config.js";
import { buildServer, describeConsent } from "../../src/httpServer.js";
import { MemoryStorage } from "../../src/auth/storage.js";
import { createConnectionGrantStore } from "../../src/auth/connectionGrant.js";
import { createSecretCipher } from "../../src/auth/crypto.js";

/**
 * HTTP サーバーの統合テスト。
 *
 * **実物を組み立てて、外から叩く。** ここまでのテストは部品ごとだったので、
 * 「配線を間違えている」類の間違いを拾えていない。
 *
 * cybozu と kintone だけスタブにする。
 */

const HOST = "127.0.0.1";
const KINTONE_TOKEN = "kintone-access-token-from-cybozu";
const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";

const base64url = (input: Buffer): string => input.toString("base64url");

/**
 * `Host` ヘッダーを指定して叩く。
 *
 * ⚠ **`fetch` では `Host` を設定できない**（禁止ヘッダーなので無視される）。
 * Host 検証を試すには生の HTTP クライアントが要る。
 * これに気づかないと「テストは通るが検証していない」状態になる。
 */
const requestWithHost = (
  url: string,
  host: string,
  extraHeaders: Record<string, string> = {},
): Promise<{ status: number; body: string }> => {
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        method: "GET",
        headers: { host, ...extraHeaders },
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("error", reject);
    req.end();
  });
};

/** Cookie を持ち回る最小のクライアント */
class Browser {
  readonly #cookies = new Map<string, string>();

  async fetch(url: string | URL, init: RequestInit = {}): Promise<Response> {
    const response = await fetch(url, {
      ...init,
      redirect: "manual",
      headers: {
        ...(init.headers ?? {}),
        host: HOST,
        cookie: [...this.#cookies].map(([k, v]) => `${k}=${v}`).join("; "),
      },
    });
    for (const raw of response.headers.getSetCookie?.() ?? []) {
      const pair = raw.split(";")[0]!;
      const index = pair.indexOf("=");
      const name = pair.slice(0, index);
      const value = pair.slice(index + 1);
      if (value === "") this.#cookies.delete(name);
      else this.#cookies.set(name, value);
    }
    return response;
  }
}

describe("同意画面に出すものと、記録するもの", () => {
  /**
   * ⚠ **別々に作ってはいけない。**
   * 画面に出していない連携ユーザーを記録すると、
   * 「利用者が見ていないものに同意した」ことになる。
   */
  const withIntegration = (extra: Record<string, string> = {}) =>
    loadConfig({
      ...validEnv(),
      TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
      KINTONE_INTEGRATION_USERNAME: "kintone-integration",
      KINTONE_INTEGRATION_PASSWORD: "pw",
      ...extra,
    });

  it("空のアプリ許可リストは「制限なし」にそろえる", () => {
    // ⚠ **そろえないと、同意画面は「絞っている」・実行側は「制限なし」と
    // 判断が割れる**（外部レビューで再現された）。
    // 割れると、必要な同意が記録されないまま接続ができてしまう
    for (const value of ["", "   ", ",", " , , "]) {
      const config = loadConfig({
        ...validEnv(),
        TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
        ALLOWED_APP_IDS: value,
      });

      expect(config.allowedAppIds, `${JSON.stringify(value)} が制限として扱われている`).toBeUndefined();
    }
  });

  it("アプリ許可リストの余分な空白を落とす", () => {
    const config = loadConfig({
      ...validEnv(),
      TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
      ALLOWED_APP_IDS: " 10 , 20 ,, ",
    });

    expect(config.allowedAppIds).toBe("10,20");
  });

  it("空のアプリ許可リストで、同意画面と実行側の判断がそろう", () => {
    // 表示と実行が同じ値を見ていること
    const config = loadConfig({
      ...validEnv(),
      TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
      KINTONE_INTEGRATION_USERNAME: "kintone-integration",
      KINTONE_INTEGRATION_PASSWORD: "pw",
      ENABLE_SEARCH: "true",
      ALLOWED_APP_IDS: "",
    });
    const { permissions, consent } = describeConsent(config);

    expect(permissions.join("\n"), "制限なしなのに検索を隠している").toContain("横断検索");
    expect(consent.toolNames).toContain("kintone-search");
  });

  it("削除を許可したら、同意画面に削除と書く", () => {
    // ⚠ **以前は書かれなかった。** capability フラグを直接見ていたため、
    // 削除を有効にしても「レコードの登録・更新」のままだった。
    // 削除に同意した覚えのない画面で、削除が許可されていた
    const { permissions } = describeConsent(
      loadConfig({
        ...validEnv(),
        TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
        ENABLE_RECORD_WRITE: "true",
        ALLOW_DESTRUCTIVE: "true",
      }),
    );

    expect(permissions.join("\n"), "削除が説明されていない").toContain("レコードの削除");
    expect(permissions.join("\n")).toContain("元に戻せません");
  });

  it("削除を許可していなければ、削除とは書かない", () => {
    const { permissions } = describeConsent(
      loadConfig({
        ...validEnv(),
        TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
        ENABLE_RECORD_WRITE: "true",
      }),
    );

    expect(permissions.join("\n")).toContain("レコードの登録・更新");
    expect(permissions.join("\n"), "許可していない削除を出している").not.toContain("レコードの削除");
  });

  it("スペースの削除は、アプリへの影響まで書く", () => {
    // スペースを消すと、置かれているアプリのデータが使えなくなる。
    // 「スペースの削除」だけでは、何が失われるか分からない
    const { permissions } = describeConsent(
      loadConfig({
        ...validEnv(),
        TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
        KINTONE_INTEGRATION_USERNAME: "kintone-integration",
        KINTONE_INTEGRATION_PASSWORD: "pw",
        ENABLE_SPACE_WRITE: "true",
        ALLOW_DESTRUCTIVE: "true",
      }),
    );

    const text = permissions.join("\n");
    expect(text).toContain("スペースの削除");
    expect(text, "アプリへの影響が書かれていない").toContain("置かれているアプリごと");
    expect(text).toContain("あなたではなく");
  });

  it("スペースも検索も無効なら、記録しない", () => {
    // 連携ユーザーを設定しただけでは、同意画面に何も出ない。
    // 出していないものに同意したことにしない
    const { permissions, consent } = describeConsent(withIntegration());

    expect(permissions.join("\n")).not.toContain("あなたではなく");
    expect(consent.integrationUser, "画面に出していないのに記録している").toBeUndefined();
  });

  it("スペースを有効にしたら、出して記録する", () => {
    const { permissions, consent } = describeConsent(
      withIntegration({ ENABLE_SPACE_READ: "true" }),
    );

    expect(permissions.join("\n")).toContain("あなたではなく");
    /**
     * ⚠ **仕組みだけでは足りない。結果が書かれていること。**
     *
     * 「連携用ユーザーとして実行されます」だけだと
     * 「裏方が代わりにやるのだろう」としか読めない。
     * 実環境で確認したのは、**非メンバーの本人に非公開スペースの中身が返る**こと。
     * 同意を求める以上、同意する内容を書く。
     */
    expect(
      permissions.join("\n"),
      "視界が広がることが書かれていない",
    ).toContain("参加していない非公開スペース");
    // ⚠ **ここは HTML になる。** Markdown の強調を書くと、
    // 同意画面にアスタリスクがそのまま出る（実物を描かせて気づいた）
    expect(permissions.join("\n"), "Markdown の記法が混ざっている").not.toContain("**");
    expect(consent.integrationUser).toEqual({ username: "kintone-integration" });
    // 同意したツールも固定される
    expect(consent.toolNames, "同意したツールが残っていない").toContain("kintone-get-space");
  });

  it("アプリを絞ると検索は公開しないので、検索だけでは記録しない", () => {
    const { permissions, consent } = describeConsent(
      withIntegration({ ENABLE_SEARCH: "true", ALLOWED_APP_IDS: "10" }),
    );

    expect(permissions.join("\n")).not.toContain("横断検索");
    expect(consent.integrationUser, "公開しないものに同意したことにしている").toBeUndefined();
    expect(consent.toolNames).not.toContain("kintone-search");
  });
});

describe("設定の検証", () => {
  it("問題をまとめて報告する", () => {
    // 1つ直すたびに再起動して次が出る、を避ける
    const error = (() => {
      try {
        loadConfig({});
        return undefined;
      } catch (e) {
        return e as ConfigError;
      }
    })();

    expect(error).toBeInstanceOf(ConfigError);
    expect(error!.problems.length).toBeGreaterThan(3);
    expect(error!.problems.join("\n")).toContain("OAUTH_ISSUER");
    expect(error!.problems.join("\n")).toContain("ALLOWED_HOSTS");
  });

  it("ALLOWED_HOSTS の未設定は起動を止める", () => {
    // 「未設定なら全部許可」にすると、設定を忘れた状態で公開される
    const env = validEnv();
    delete env.ALLOWED_HOSTS;

    expect(() => loadConfig(env)).toThrowError(/ALLOWED_HOSTS/);
  });

  it("issuer にパスを付けると止める", () => {
    // well-known の配置が変わってしまう
    expect(() => loadConfig({ ...validEnv(), OAUTH_ISSUER: "https://example.com/mcp" })).toThrowError(
      /パスを付けないで/,
    );
  });

  it("スキームを大文字にしても、https としての要求が外れない", () => {
    // ⚠ `startsWith("https://")` で判定していたため、
    // **`HTTPS://` にするだけで署名鍵の必須化と Secure Cookie の強制が外れた**。
    // その状態で起動すると、oidc-provider は
    // **パッケージに秘密鍵ごと同梱された固定鍵**で id_token に署名する
    const env = validEnv();
    delete env.OIDC_JWKS;

    expect(() =>
      loadConfig({ ...env, OAUTH_ISSUER: "HTTPS://mcp.example.com" }),
    ).toThrowError(/OIDC_JWKS/);

    expect(() =>
      loadConfig({ ...validEnv(), OAUTH_ISSUER: "HTTPS://mcp.example.com", SECURE_COOKIES: "false" }),
    ).toThrowError(/SECURE_COOKIES/);
  });

  it("issuer は正規化して持つ", () => {
    // resource は「Claude に入力してもらう URL」と完全一致させる必要がある。
    // 大文字のまま持つと、入力された小文字の URL と食い違う
    const config = loadConfig({ ...validEnv(), OAUTH_ISSUER: "HTTPS://MCP.example.com" });

    expect(config.issuer).toBe("https://mcp.example.com");
    expect(config.resource).toBe("https://mcp.example.com/mcp");
  });

  it("資格情報の前後の空白を落とす", () => {
    // ⚠ **本番で踏んだ。** Secret Manager に貼り付けたシークレットの末尾に
    // 改行が1バイト入っており、`clientId:secret\n` を Basic 認証に載せていた。
    // cybozu は **401 invalid_client** を返し、同意画面のあとで止まった。
    //
    // ⚠ 調べるときシェルの `$( )` を使うと**末尾の改行が落ちる**ので、
    // 手で叩くと通ってしまい、原因が見えなかった。
    const config = loadConfig({
      ...validEnv(),
      CYBOZU_OAUTH_CLIENT_SECRET: "the-secret\n",
      CYBOZU_OAUTH_CLIENT_ID: "  the-client  ",
    });

    expect(config.cybozuClientSecret, "末尾の改行が残っている").toBe("the-secret");
    expect(config.cybozuClientId).toBe("the-client");
  });

  it("空白だけの値は未設定として扱う", () => {
    // 落とした結果が空になるなら、設定されていないのと同じ
    expect(() =>
      loadConfig({ ...validEnv(), CYBOZU_OAUTH_CLIENT_SECRET: "   " }),
    ).toThrowError(/CYBOZU_OAUTH_CLIENT_SECRET/);
  });

  it("暗号鍵の長さが違えば止める", () => {
    expect(() =>
      loadConfig({ ...validEnv(), TOKEN_ENCRYPTION_KEY: Buffer.alloc(16).toString("base64") }),
    ).toThrowError(/32バイト/);
  });

  it("COOKIE_KEYS の未設定は起動を止める", () => {
    // インスタンスごとに違う鍵になると認可が壊れる
    const env = validEnv();
    delete env.COOKIE_KEYS;

    expect(() => loadConfig(env)).toThrowError(/COOKIE_KEYS/);
  });

  it("連携ユーザーは、両方そろわないと止める", () => {
    expect(() =>
      loadConfig({ ...validEnv(), KINTONE_INTEGRATION_USERNAME: "u" }),
    ).toThrowError(/KINTONE_INTEGRATION_PASSWORD/);
    expect(() =>
      loadConfig({ ...validEnv(), KINTONE_INTEGRATION_PASSWORD: "p" }),
    ).toThrowError(/KINTONE_INTEGRATION_USERNAME/);
  });

  it("連携ユーザーは既定では設定されない", () => {
    // 置いただけで有効にならないこと。設定しない限り5ツールは出ない
    expect(loadConfig(validEnv()).integrationUser).toBeUndefined();
  });

  it("既定は読み取り専用", () => {
    const config = loadConfig(validEnv());

    expect(config.capabilities).toMatchObject({
      recordRead: true,
      appRead: true,
      recordWrite: false,
      appWrite: false,
      allowDestructive: false,
    });
  });
});

/**
 * テスト用の署名鍵。**本番は Secret Manager から渡す**（docs/deployment.md）。
 *
 * ⚠ 形だけ整えた偽の鍵では provider の起動時検証を通らない
 * (`jwks.keys[0].p configuration must be a non-empty string`)。実際に生成する。
 */
const TEST_JWKS = (() => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return JSON.stringify({ keys: [{ ...privateKey.export({ format: "jwk" }), kid: "test" }] });
})();

const validEnv = (): Record<string, string | undefined> => ({
  OAUTH_ISSUER: "https://mcp.example.com",
  OIDC_JWKS: TEST_JWKS,
  KINTONE_BASE_URL: "https://example.cybozu.com",
  CYBOZU_OAUTH_CLIENT_ID: "client",
  CYBOZU_OAUTH_CLIENT_SECRET: "secret",
  TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
  COOKIE_KEYS: "cookie-key",
  ALLOWED_HOSTS: "mcp.example.com",
});

describe("HTTP サーバー", () => {
  let server: Server;
  let origin: string;
  let kintoneCalls: Array<{ url: string; authorization: string | null }>;
  /** 監査ログに実際に出た内容。**出力先を差し替えないと外から見えない** */
  const auditEntries: Array<Record<string, unknown>> = [];
  let storage: MemoryStorage;
  /** 接続の主体は同意処理の中で作られるので、保存時に控える */
  let lastAccountId = "";
  let revokeConnection: (accountId: string) => Promise<void>;
  /** 本番の組み立てで、接続に何が保存されたかを見る */
  let inspectConnection: (
    accountId: string,
  ) => Promise<{ consentedTools: string[] | undefined; integrationConsent: unknown }>;
  /** 認可を一周してトークン一式を得る */
  let completeAuthorization: () => Promise<Record<string, string>>;
  /** 得たトークンで tools/list を叩く */
  let callTools: (accessToken: string) => Promise<Response>;
  /** 異常なトークンを作るために provider を触る */
  let provider: import("oidc-provider").default;

  beforeEach(() => {
    kintoneCalls = [];
    auditEntries.length = 0;
  });

  beforeAll(async () => {
    // ⚠ **空きポートを調べてから listen し直さない。**
    // 調べてから掴むまでの間に、並行して走る別のテストが同じポートを取れる。
    // `listen` の失敗を受ける相手がいないと、テストは「失敗」ではなく**固まる**。
    // **先に listen して、決まったポートで組み立てる。**
    server = createServer();
    await new Promise<void>((resolve) => server.listen(0, HOST, resolve));
    const { port } = server.address() as AddressInfo;
    origin = `http://${HOST}:${port}`;

    storage = new MemoryStorage();

    /** cybozu と kintone をまとめてスタブにする */
    const stubFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();

      if (url.endsWith("/oauth2/token")) {
        return new Response(
          JSON.stringify({
            access_token: KINTONE_TOKEN,
            refresh_token: "kintone-refresh-token",
            token_type: "bearer",
            expires_in: 3600,
            scope: "k:app_record:read",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      kintoneCalls.push({
        url,
        authorization: new Headers(init?.headers ?? {}).get("authorization"),
      });
      return new Response(JSON.stringify({ records: [], totalCount: "0" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    const encryptionKey = randomBytes(32).toString("base64");
    const cipher = createSecretCipher(Buffer.from(encryptionKey, "base64"));
    const grants = createConnectionGrantStore({ storage, cipher });
    revokeConnection = (accountId) => grants.revoke(accountId);
    inspectConnection = (accountId) => grants.inspect(accountId);

    const config = loadConfig({
      ...validEnv(),
      TOKEN_ENCRYPTION_KEY: encryptionKey,
      OAUTH_ISSUER: origin,
      ALLOW_INSECURE_ISSUER: "true",
      // 平文 HTTP で試すので Secure を外す（本番は既定の true）
      SECURE_COOKIES: "false",
      ALLOWED_HOSTS: HOST,
      PORT: String(port),
      // このサーバーは認可を何周も回す。既定の60回/分だと、
      // **試したい内容とは無関係に 429 で落ちる**。
      // 流量制限そのものは専用のサーバーを立てて試す（後段の describe）
      RATE_LIMIT_PRE_AUTH_PER_MINUTE: "100000",
    });

    const built: { app: import("express").Express; provider: import("oidc-provider").default; shutdown: () => Promise<void> } = buildServer({
      config,
      storage,
      fetch: stubFetch,
      auditSink: (entry) => auditEntries.push(entry),
      // kintone クライアントは実ネットワークに出る。
      // ここを差し替えないと「実際に何が渡るか」を確かめられない。
      onConnectionCreated: (accountId: string) => {
        lastAccountId = accountId;
      },
      createKintoneClient: (clientOptions) =>
        ({
          record: {
            getRecords: async (args: unknown) => {
              // ⚠ **本番が実際に組み立てた設定**から作る。
              // トークン文字列だけを受けていた頃は、
              // 呼び出し側で資格情報を混ぜてもここから見えなかった
              const auth = clientOptions.auth as Record<string, string>;
              kintoneCalls.push({
                url: "record/getRecords",
                authorization:
                  "oAuthToken" in auth ? `Bearer ${auth.oAuthToken}` : `Password ${auth.username}`,
              });
              void args;
              return { records: [], totalCount: "0" };
            },
          },
        }) as never,
    });
    provider = built.provider;
    server.on("request", built.app);

    // --- テストから使うヘルパー ---

    completeAuthorization = async () => {
      const browser = new Browser();
      const verifier = base64url(randomBytes(32));
      const challenge = base64url(createHash("sha256").update(verifier).digest());

      const authorizeUrl = new URL(`${origin}/auth`);
      authorizeUrl.search = new URLSearchParams({
        client_id: "claude-hosted",
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        // Claude は保護リソースメタデータの scopes_supported を要求する
        scope: "openid kintone:read",
        resource: `${origin}/mcp`,
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }).toString();

      let response = await browser.fetch(authorizeUrl);
      let location = response.headers.get("location");
      let hops = 0;
      while (
        location &&
        !/\/interaction\/[^/]+$/.test(new URL(location, origin).pathname) &&
        hops < 6
      ) {
        response = await browser.fetch(new URL(location, origin));
        location = response.headers.get("location");
        hops += 1;
      }
      const consentUrl = new URL(location!, origin);
      const page = await (await browser.fetch(consentUrl)).text();
      const csrf = /name="csrf" value="([^"]+)"/.exec(page)?.[1];

      const consent = await browser.fetch(consentUrl, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ csrf: csrf!, decision: "allow" }).toString(),
      });
      const state = new URL(consent.headers.get("location")!).searchParams.get("state")!;

      response = await browser.fetch(
        `${origin}/oauth/callback?code=cybozu-code&state=${encodeURIComponent(state)}`,
      );
      location = response.headers.get("location");
      hops = 0;
      const chain: string[] = [];
      while (location && !location.startsWith(REDIRECT_URI) && hops < 8) {
        response = await browser.fetch(new URL(location, origin));
        location = response.headers.get("location");
        chain.push(location ?? `(${response.status}) ${(await response.clone().text()).slice(0, 250)}`);
        hops += 1;
      }
      if (!location?.startsWith(REDIRECT_URI)) throw new Error(`到達せず:\n${chain.join("\n")}`);
      const code = new URL(location).searchParams.get("code")!;

      const tokenResponse = await fetch(`${origin}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          client_id: "claude-hosted",
          code_verifier: verifier,
          resource: `${origin}/mcp`,
        }).toString(),
      });
      return (await tokenResponse.json()) as Record<string, string>;
    };

    callTools = (accessToken: string) =>
      fetch(`${origin}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("/health は認証不要で version を返す", async () => {
    // 古いリビジョンが動いていることに気づかないまま調査を続ける事故を防ぐ
    const response = await fetch(`${origin}/health`);

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: "ok", version: "0.1.0" });
  });

  it("保護リソースのメタデータは、RFC 9728 の場所にある", async () => {
    /**
     * ⚠ **ルートに置くだけでは足りない。**
     *
     * RFC 9728 は、リソース識別子のパスを
     * `/.well-known/oauth-protected-resource` の**後ろに差し込む**と定めている。
     * リソースが `https://host/mcp` なら `/.well-known/oauth-protected-resource/mcp`。
     *
     * ルートにしか置いていなかった。Claude は後退して拾うので気づかなかったが、
     * **ChatGPT は仕様どおりの場所を先に見て 404 を受け**、認可に進まず
     * 探索を繰り返していた（本番で実測）。
     */
    const spec = await fetch(`${origin}/.well-known/oauth-protected-resource/mcp`);

    expect(spec.status, "RFC 9728 の場所に無い").toBe(200);
    expect(await spec.json()).toMatchObject({ resource: `${origin}/mcp` });
  });

  it("ルートでも返す（後退して拾うクライアント向け）", async () => {
    // 落とすと、仕様どおりの場所を見ないクライアントが繋がらなくなる
    const root = await fetch(`${origin}/.well-known/oauth-protected-resource`);

    expect(root.status).toBe(200);
    expect(await root.json()).toMatchObject({ resource: `${origin}/mcp` });
  });

  it("許可外の Host は 403", async () => {
    const response = await requestWithHost(
      `${origin}/.well-known/oauth-protected-resource`,
      "evil.example",
    );

    expect(response.status, "DNS rebinding 対策が効いていない").toBe(403);
  });

  it("許可された Host なら通る", async () => {
    const response = await requestWithHost(
      `${origin}/.well-known/oauth-protected-resource`,
      HOST,
    );

    expect(response.status).toBe(200);
  });

  it("/health は許可外の Host でも通る", async () => {
    // Cloud Run のヘルスチェックは Host にサービス名を入れてくるとは限らない
    const response = await requestWithHost(`${origin}/health`, "unknown.example");

    expect(response.status).toBe(200);
  });

  it("/mcp への許可外 Origin は 403（CORS ヘッダーを付けないだけでは足りない）", async () => {
    const response = await fetch(`${origin}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://evil.example" },
      body: "{}",
    });

    expect(response.status).toBe(403);
  });

  it("自分自身の Origin は許可する", async () => {
    // ⚠ 全ルートに Origin 検証を掛けると、**同意画面のフォーム送信が 403 になる**。
    // ブラウザは自分自身の Origin を付けてくるため。
    const response = await fetch(`${origin}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", origin },
      body: "{}",
    });

    // Origin では弾かれない（トークンが無いので 401 になる）
    expect(response.status).toBe(401);
  });

  it("バッチ要求は受け付けない", async () => {
    // ⚠ SDK は配列内の要求を**並列に実行する**ので、
    // 1リクエストぶんの枠で、いくつでも上流呼び出しを開始できてしまう。
    const tokens = await completeAuthorization();

    const response = await fetch(`${origin}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify([
        { jsonrpc: "2.0", id: 1, method: "tools/list" },
        { jsonrpc: "2.0", id: 2, method: "tools/list" },
      ]),
    });

    expect(response.status, "バッチが通っている").toBe(400);
  });

  it("Content-Type を変えてもバッチは通らない（SDK に本文を読み直させない）", async () => {
    // ⚠ **配列の検査だけでは足りなかった。**
    // `express.json` は `application/json` に厳密一致したときだけ解析するが、
    // MCP SDK は `ct.includes("application/json")` の**部分一致**で受理し、
    // `req.body` が未定義なら**自分で本文を読む**。
    // この食い違いで、バッチ検査もサイズ上限も素通りしていた（実測）。
    const tokens = await completeAuthorization();
    const before = kintoneCalls.length;

    const response = await fetch(`${origin}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json-patch+json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify([
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "kintone-get-records", arguments: { app: "1" } } },
        { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "kintone-get-records", arguments: { app: "1" } } },
        { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "kintone-get-records", arguments: { app: "1" } } },
      ]),
    });

    expect(response.status, "Content-Type の隙間からバッチが通っている").toBe(415);
    // ステータスだけでは足りない。**上流を呼んでいないこと**が本題
    expect(kintoneCalls.length - before, "上流への呼び出しが発生している").toBe(0);
  });

  it("上限を超える本文は、型名を変えても止まる", async () => {
    // 迂回できると、1リクエスト分の枠で上限（既定1MB）を超える本文を送れる。
    // SDK 自身の上限は 4MB なので、こちらの設定が効かなくなる
    const tokens = await completeAuthorization();
    const huge = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: { padding: "x".repeat(1_100_000) },
    });

    const withJson = await fetch(`${origin}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${tokens.access_token}`,
      },
      body: huge,
    });
    const withOtherType = await fetch(`${origin}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json-patch+json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${tokens.access_token}`,
      },
      body: huge,
    });

    expect(withJson.status, "サイズ上限が効いていない").toBe(413);
    expect(withOtherType.status, "型名を変えるとサイズ上限を抜けられる").toBe(415);
  });

  describe("監査ログ", () => {
    /**
     * ⚠ **失敗だけ記録しても、何が起きたかは分からない。**
     * 認可を完走しても監査ログが空で、「誰がいつ繋いだか」を
     * 後から言えなかった（外部レビューで指摘）。
     */
    const typesOf = () => auditEntries.map((entry) => entry.type);

    it("本番の組み立てで、同意した範囲が接続に保存される", async () => {
      // ⚠ **ここが抜けていた。** 本番のラッパーが `grants.create` の
      // 第3引数を捨てていたため、**同意が一度も保存されていなかった**
      // （外部レビューで判明）。テストのハーネスで同じ間違いを直しながら、
      // 本番側を見落としていた。
      //
      // ブリッジ単体のテストは別のラッパーを使うので、ここは通らない。
      // **本番の `buildServer` で認可を一周する**のが唯一の確かめ方。
      await completeAuthorization();

      const state = await inspectConnection(lastAccountId);

      expect(state.consentedTools, "同意した範囲が保存されていない").toBeDefined();
      expect(state.consentedTools).toContain("kintone-get-records");
      // 既定では公開していないものは入らない
      expect(state.consentedTools).not.toContain("kintone-add-records");
    });

    it("保存した範囲が、そのまま tools/list に効く", async () => {
      const tokens = await completeAuthorization();

      const response = await callTools(tokens.access_token!);
      const body = (await response.json()) as {
        result: { tools: Array<{ name: string }> };
      };
      const names = body.result.tools.map((t) => t.name);

      expect(names).toContain("kintone-get-records");
      expect(names).not.toContain("kintone-add-records");
    });

    it("認可を完走すると、接続の作成と発行が残る", async () => {
      await completeAuthorization();

      expect(typesOf(), "接続の作成が残っていない").toContain("auth.connection_created");
      expect(typesOf(), "トークンの発行が残っていない").toContain("auth.token_issued");
      // ⚠ 秘密は絶対に載せない
      const dump = JSON.stringify(auditEntries);
      expect(dump).not.toContain("cybozu-code");
      expect(dump).not.toContain(KINTONE_TOKEN);
    });

    it("正常な切断を、盗用の疑いとして記録しない", async () => {
      // ⚠ **provider は、再使用の検知でも利用者の切断でも同じ口を呼ぶ。**
      // 決め打ちで `token-reuse` と記録していたため、
      // **正常な操作と盗用をログで区別できなかった**
      const tokens = await completeAuthorization();

      const response = await fetch(`${origin}/token/revocation`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          token: tokens.refresh_token!,
          token_type_hint: "refresh_token",
          client_id: "claude-hosted",
        }).toString(),
      });
      expect(response.status).toBe(200);

      const revoked = auditEntries.filter((entry) => entry.type === "auth.connection_revoked");
      expect(revoked, "切断が記録されていない").not.toHaveLength(0);
      for (const entry of revoked) {
        expect(entry.reason, "正常な切断が盗用として記録されている").not.toBe("token-reuse");
      }
    });

    it("リフレッシュトークンの再使用は、そうと分かる形で残る", async () => {
      const tokens = await completeAuthorization();
      const refreshOnce = () =>
        fetch(`${origin}/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: tokens.refresh_token!,
            client_id: "claude-hosted",
            resource: `${origin}/mcp`,
          }).toString(),
        });

      expect((await refreshOnce()).status).toBe(200);
      // 同じものをもう一度 = 盗用の疑い
      expect((await refreshOnce()).status).toBe(400);

      const revoked = auditEntries.filter((entry) => entry.type === "auth.connection_revoked");
      expect(
        revoked.some((entry) => entry.reason === "token-reuse"),
        "再使用が、正常な切断と区別できない",
      ).toBe(true);
    });

    it("更新は、発行とは別の種別で残る", async () => {
      const tokens = await completeAuthorization();

      await fetch(`${origin}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token!,
          client_id: "claude-hosted",
          resource: `${origin}/mcp`,
        }).toString(),
      });

      expect(typesOf()).toContain("auth.token_refreshed");
    });
  });

  it("保護リソースメタデータを認証なしで配る", async () => {
    const response = await fetch(`${origin}/.well-known/oauth-protected-resource`, {
      headers: { host: HOST },
    });
    const metadata = (await response.json()) as Record<string, unknown>;

    expect(metadata.resource).toBe(`${origin}/mcp`);
    expect(metadata.authorization_servers).toEqual([origin]);
  });

  describe("/mcp の認証", () => {
    it("トークンが無ければ 401 と WWW-Authenticate", async () => {
      const response = await fetch(`${origin}/mcp`, {
        method: "POST",
        headers: { host: HOST, "content-type": "application/json" },
        body: "{}",
      });

      expect(response.status).toBe(401);
      // ここが discovery の起点。無いとクライアントは繋ぎようがない
      expect(response.headers.get("www-authenticate")).toContain(
        "resource_metadata=",
      );
    });

    it("でたらめなトークンは 401", async () => {
      const response = await fetch(`${origin}/mcp`, {
        method: "POST",
        headers: {
          host: HOST,
          "content-type": "application/json",
          authorization: "Bearer not-a-real-token",
        },
        body: "{}",
      });

      expect(response.status).toBe(401);
    });

    it("リフレッシュトークンを Bearer として受け付けない", async () => {
      // ⚠ **種別を確かめないと通ってしまう。** provider が発行したものである点は
      // アクセストークンと同じなので、「find できたか」だけでは区別できない。
      const tokens = await completeAuthorization();

      const response = await fetch(`${origin}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${tokens.refresh_token}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      });

      expect(response.status, "リフレッシュトークンで MCP を叩けてしまう").toBe(401);
    });

    it("切断された接続のトークンは通さない", async () => {
      // トークン自体はまだ生きている状態で、接続だけが失効しているケース。
      const tokens = await completeAuthorization();

      // 使える状態であることを先に確かめる
      const before = await callTools(tokens.access_token!);
      expect(before.status).toBe(200);

      // 接続を失効させる
      const accountId = lastAccountId;
      expect(accountId).toBeTruthy();
      await revokeConnection(accountId);

      const after = await callTools(tokens.access_token!);
      expect(after.status, "切断後もトークンが通っている").toBe(401);
    });

    it("audience の無いトークンは拒否する", async () => {
      // ⚠ 「あれば一致を見る」だと、audience の無いトークンが素通りする。
      // 正常系のトークンには必ず aud が入るので、ここを作らないと一度も試されない。
      //
      // ⚠ **実在する接続の主体を使う。** 架空の主体だと
      // 「kintone の接続が無い」で 401 になり、**audience の判定に到達しない**
      // （最初に書いたテストはそれで通っていた）。
      await completeAuthorization();
      const accountId = lastAccountId;
      expect(accountId).toBeTruthy();

      const token = new provider.AccessToken({
        accountId,
        client: await provider.Client.find("claude-hosted"),
        grantId: "grant-no-aud",
        scope: "kintone:read",
      } as never);
      const value = await token.save();

      const response = await callTools(value);

      expect(response.status, "audience の無いトークンが通っている").toBe(401);
    });

    it("scope が足りないトークンは 403", async () => {
      // 401 ではない。トークンは有効だが権限が足りない。
      const token = new provider.AccessToken({
        accountId: "acct-no-scope",
        client: await provider.Client.find("claude-hosted"),
        grantId: "grant-no-scope",
        aud: `${origin}/mcp`,
        scope: "",
      } as never);
      const value = await token.save();

      const response = await callTools(value);

      expect(response.status, "scope 不足が通っている").toBe(403);
      expect(response.headers.get("www-authenticate")).toContain("insufficient_scope");
    });

    it("GET は 405（SSE を提供しない）", async () => {
      const response = await fetch(`${origin}/mcp`, { headers: { host: HOST } });

      expect(response.status).toBe(405);
    });
  });

  it("認可を一周して、kintone のツールを実際に呼べる", async () => {
    const browser = new Browser();
    const verifier = base64url(randomBytes(32));
    const challenge = base64url(createHash("sha256").update(verifier).digest());

    // 1. 認可要求 → 同意画面
    const authorizeUrl = new URL(`${origin}/auth`);
    authorizeUrl.search = new URLSearchParams({
      client_id: "claude-hosted",
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      // Claude は保護リソースメタデータの scopes_supported を要求する
      scope: "openid kintone:read",
      resource: `${origin}/mcp`,
      state: "s",
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();

    let response = await browser.fetch(authorizeUrl);
    let location = response.headers.get("location");
    const chain: string[] = [`${response.status} ${location ?? (await response.clone().text()).slice(0, 300)}`];
    let hops = 0;
    while (location && !/\/interaction\/[^/]+$/.test(new URL(location, origin).pathname) && hops < 6) {
      response = await browser.fetch(new URL(location, origin));
      location = response.headers.get("location");
      chain.push(`${response.status} ${location ?? (await response.clone().text()).slice(0, 300)}`);
      hops += 1;
    }
    if (!location) throw new Error(`同意画面に到達せず:\n${chain.join("\n")}`);
    const consentUrl = new URL(location!, origin);

    // 2. 同意画面に、有効な capability から導いた権限が出ている
    const pageResponse = await browser.fetch(consentUrl);
    const page = await pageResponse.text();
    // 失敗したときに原因が分かるようにしておく（500 を黙って通さない）
    expect(pageResponse.status, `同意画面が ${pageResponse.status}: ${page.slice(0, 200)}`).toBe(200);
    expect(page).toContain("レコードの参照");
    expect(page).toContain("アプリ設定の参照");
    expect(page, "既定で書き込みが表示されている").not.toContain("レコードの登録・更新");
    const csrf = /name="csrf" value="([^"]+)"/.exec(page)?.[1];

    // 3. 許可 → cybozu へ
    const consent = await browser.fetch(consentUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf: csrf!, decision: "allow" }).toString(),
    });
    const state = new URL(consent.headers.get("location")!).searchParams.get("state")!;

    // 4. cybozu からの戻り → redirect_uri まで
    response = await browser.fetch(
      `${origin}/oauth/callback?code=cybozu-code&state=${encodeURIComponent(state)}`,
    );
    location = response.headers.get("location");
    let guard = 0;
    while (location && !location.startsWith(REDIRECT_URI) && guard < 8) {
      response = await browser.fetch(new URL(location, origin));
      location = response.headers.get("location");
      guard += 1;
    }
    const code = new URL(location!).searchParams.get("code")!;

    // 5. トークン交換
    const tokenResponse = await fetch(`${origin}/token`, {
      method: "POST",
      headers: { host: HOST, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: "claude-hosted",
        code_verifier: verifier,
        resource: `${origin}/mcp`,
      }).toString(),
    });
    const tokens = (await tokenResponse.json()) as Record<string, string>;
    expect(tokenResponse.status, JSON.stringify(tokens)).toBe(200);

    // 6. MCP で tools/list
    const listResponse = await fetch(`${origin}/mcp`, {
      method: "POST",
      headers: {
        host: HOST,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    const listed = (await listResponse.json()) as {
      result: { tools: Array<{ name: string; annotations?: unknown }> };
    };

    expect(listResponse.status, JSON.stringify(listed)).toBe(200);
    const names = listed.result.tools.map((t) => t.name);
    // 既定は読み取りのみ (§5)
    expect(names).toContain("kintone-get-records");
    expect(names).not.toContain("kintone-add-records");
    // OAuth では実行できない5ツール
    expect(names).not.toContain("kintone-search");
    expect(names).not.toContain("kintone-get-space");
    // annotations が実際の応答に載る
    expect(listed.result.tools[0]!.annotations).toBeDefined();

    // 7. ツールを実行 → **kintone に cybozu 由来のトークンで届く**
    const callResponse = await fetch(`${origin}/mcp`, {
      method: "POST",
      headers: {
        host: HOST,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "kintone-get-records", arguments: { app: "10" } },
      }),
    });
    const called = (await callResponse.json()) as { result: { isError?: boolean } };

    expect(callResponse.status, JSON.stringify(called)).toBe(200);
    expect(called.result.isError).toBeFalsy();
    expect(kintoneCalls, "kintone が呼ばれていない").toHaveLength(1);
    expect(
      kintoneCalls[0]!.authorization,
      "kintone へ cybozu 由来のトークンが渡っていない",
    ).toBe(`Bearer ${KINTONE_TOKEN}`);
  });
});

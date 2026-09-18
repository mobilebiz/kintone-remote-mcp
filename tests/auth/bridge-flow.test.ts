import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { createAdapterFactory } from "../../src/auth/adapter.js";
import { createBridge } from "../../src/auth/bridge.js";
import { createBridgeRoutes } from "../../src/auth/bridgeRoutes.js";
import { createConnectionGrantStore } from "../../src/auth/connectionGrant.js";
import { createSecretCipher } from "../../src/auth/crypto.js";
import { createCybozuOAuthClient } from "../../src/auth/cybozuOAuth.js";
import { createDisconnector } from "../../src/auth/disconnect.js";
import { createRevoker } from "../../src/auth/revocation.js";
import { CLAUDE_HOSTED_CLIENT_ID, createProvider } from "../../src/auth/provider.js";
import { MemoryStorage } from "../../src/auth/storage.js";

/**
 * ブリッジを通した認可フローの統合テスト。
 *
 * cybozu.com はスタブに差し替えるが、**provider・Adapter・ブリッジ・接続 grant は実物**。
 * 設計 §4.5 の「二段の認可を結ぶ state とブラウザ束縛」が実際に効いているかを見る。
 */

const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
const CYBOZU_BASE = "https://example.cybozu.com";
const KINTONE_ACCESS_TOKEN = "kintone-access-token-secret";
const KINTONE_REFRESH_TOKEN = "kintone-refresh-token-secret";

const base64url = (input: Buffer): string => input.toString("base64url");

/** Cookie を持ち回る最小のクライアント */
class Browser {
  readonly #cookies = new Map<string, string>();

  collect(response: Response): void {
    for (const raw of response.headers.getSetCookie?.() ?? []) {
      const [pair] = raw.split(";");
      const index = pair!.indexOf("=");
      const name = pair!.slice(0, index);
      const value = pair!.slice(index + 1);
      if (value === "" ) this.#cookies.delete(name);
      else this.#cookies.set(name, value);
    }
  }

  header(): string {
    return [...this.#cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  async fetch(url: string | URL, init: RequestInit = {}): Promise<Response> {
    const response = await fetch(url, {
      ...init,
      redirect: "manual",
      headers: { ...(init.headers ?? {}), cookie: this.header() },
    });
    this.collect(response);
    return response;
  }

  drop(name: string): void {
    this.#cookies.delete(name);
  }
}

describe("ブリッジを通した認可フロー", () => {
  let server: Server;
  let origin: string;
  let resource: string;
  let storage: MemoryStorage;
  let grants: ReturnType<typeof createConnectionGrantStore>;
  let disconnector: ReturnType<typeof createDisconnector>;
  let revoker: ReturnType<typeof createRevoker>;
  let cipher: ReturnType<typeof createSecretCipher>;
  /** 接続の主体は bridgeRoutes の中で生成されるので、保存時に控える */
  let lastAccountId = "";
  /**
   * ⚠ **callback と finish を「別の瞬間」にできるようにする。**
   *
   * 2つの期限を別々に数えている欠陥は、その間が空かないと現れない。
   * 実際の流れでは redirect 1回ぶんしか空かないので、
   * **finish の入口（完了レコードの consume）で時計を進める**。
   */
  let clockSkew = 0;
  let skewOnFinish = 0;
  const testNow = (): number => Math.floor(Date.now() / 1000) + clockSkew;
  /** `consent()` が何回呼ばれたか。callback で呼び直していないことを見る */
  let consentCalls = 0;
  let provider: ReturnType<typeof createProvider>;
  let exchangeCalls: number;
  let failures: Array<{ stage: string; reason: string }>;
  const revokedAccounts: string[] = [];

  /** cybozu のトークンエンドポイントを模す */
  const cybozuFetch = vi.fn(async (_input: string, _init: RequestInit) => {
    exchangeCalls += 1;
    return new Response(
      JSON.stringify({
        access_token: KINTONE_ACCESS_TOKEN,
        refresh_token: KINTONE_REFRESH_TOKEN,
        token_type: "bearer",
        expires_in: 3600,
        scope: "k:app_record:read",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  });

  beforeEach(() => {
    exchangeCalls = 0;
    failures = [];
    clockSkew = 0;
    skewOnFinish = 0;
  });

  beforeAll(async () => {
    storage = new MemoryStorage();
    cipher = createSecretCipher(randomBytes(32));

    // ⚠ `Object.create(storage, ...)` で包むと private フィールドで落ちる。
    // 束縛したメソッドを持つ別のオブジェクトにする
    const skewedStorage = {
      find: (...args: Parameters<MemoryStorage["find"]>) => storage.find(...args),
      findByIndex: (...args: Parameters<MemoryStorage["findByIndex"]>) =>
        storage.findByIndex(...args),
      upsert: (...args: Parameters<MemoryStorage["upsert"]>) => storage.upsert(...args),
      destroy: (...args: Parameters<MemoryStorage["destroy"]>) => storage.destroy(...args),
      consume: (...args: Parameters<MemoryStorage["consume"]>) => {
        // 完了レコードを消費するのは finish の入口だけ
        if (args[0] === "BridgeCompletion") clockSkew += skewOnFinish;
        return storage.consume(...args);
      },
      revokeByGrantId: (...args: Parameters<MemoryStorage["revokeByGrantId"]>) =>
        storage.revokeByGrantId(...args),
      update: (...args: Parameters<MemoryStorage["update"]>) => storage.update(...args),
    };

    // ⚠ **空きポートを調べてから listen し直さない。**
    // 調べてから掴むまでの間に、並行して走る別のテストが同じポートを取れる。
    // `listen` の失敗を受ける相手がいないと、テストは「失敗」ではなく**固まる**。
    // **先に listen して、決まったポートで組み立てる。**
    server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;

    origin = `http://127.0.0.1:${port}`;
    resource = `${origin}/mcp`;

    grants = createConnectionGrantStore({ storage, cipher });
    revoker = createRevoker({
      storage,
      cipher,
      grants,
      onRevoke: (info) => revokedAccounts.push(info.accountId),
    });

    provider = createProvider({
      issuer: origin,
      // 再使用検知・provider 側の失効・切断を、すべて接続 grant の失効へつなぐ
      adapter: createAdapterFactory({
        storage: skewedStorage,
        cipher,
        // ⚠ ブリッジと**同じ時計**を使う。別々だと、進めた時計が片方にしか効かない
        now: testNow,
        revokeByGrantId: (grantId) => revoker.revokeByGrantId(grantId, "token-reuse"),
        isConnectionRevoked: (accountId) => grants.isRevoked(accountId),
      }),
      resource: { resource, scopes: ["kintone:read"] },
      cookieKeys: ["test-cookie-key"],
      secureCookies: false,
      /**
       * ⚠ **接続の寿命（400日）とわざと違う値にしてある。**
       *
       * 同じにすると、Grant の期限を**接続から取っているのか、
       * provider の設定から数え直しているのか区別が付かない**。
       * 本番は同じ値なので、ここでずらさないと試験が何も見ない。
       */
      grantTtl: 300 * 24 * 60 * 60,
    });

    const cybozu = createCybozuOAuthClient(
      {
        baseUrl: CYBOZU_BASE,
        clientId: "cybozu-client-id",
        clientSecret: "cybozu-client-secret",
        redirectUri: `${origin}/oauth/callback`,
        scopes: ["k:app_record:read"],
      },
      { fetch: cybozuFetch },
    );

    disconnector = createDisconnector({ revoker });

    const app = express();
    app.use(
      createBridgeRoutes({
        provider,
        bridge: createBridge({ storage, cipher }),
        cybozu,
        revoker,
        grants: {
          ...grants,
          // ⚠ **引数を全部渡す。** 落とすと、同意の記録が本当に書かれたかを
          // 確かめられない（実際、第3引数を捨てていて変異を見逃した）
          create: async (...args) => {
            lastAccountId = args[0];
            await grants.create(...args);
          },
        },
        storage: skewedStorage,
        cipher,
        // ⚠ adapter と**同じ時計**。別々だと、進めた時計が片方にしか効かない
        now: testNow,
        kintoneHost: "example.cybozu.com",
        permissions: ["レコードの参照", "アプリ設定の参照"],
        /**
         * 同意画面に出す内容。**画面を出すときに呼ばれる**。
         *
         * ⚠ 2回目以降は**別の内容**を返す。承認や callback で呼び直していたら、
         * 保存されるものが変わるので気づける
         */
        // 接続の絶対期限。provider の Grant と同じ寿命にする
        connectionTtlSeconds: 400 * 24 * 60 * 60,
        consent: () => {
          consentCalls += 1;
          return consentCalls === 1
            ? {
                permissions: ["レコードの参照", "アプリ設定の参照"],
                toolNames: ["kintone-get-records", "kintone-get-space"],
                integrationUser: { username: "kintone-integration" },
                allowedAppIds: undefined,
              }
            : {
                permissions: ["レコードの削除"],
                toolNames: ["kintone-delete-records"],
                integrationUser: { username: "someone-else" },
                allowedAppIds: "99",
              };
        },
        resource,
        resourceScopes: ["kintone:read"],
        secureCookies: false,
        onFailure: (info) => failures.push(info),
      }),
    );
    app.use(provider.callback());

    server.on("request", app);
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  /** 認可要求を出して、同意画面まで辿り着く */
  const reachConsent = async (browser: Browser) => {
    const verifier = base64url(randomBytes(32));
    const challenge = base64url(createHash("sha256").update(verifier).digest());

    const authorizeUrl = new URL(`${origin}/auth`);
    authorizeUrl.search = new URLSearchParams({
      client_id: CLAUDE_HOSTED_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid",
      resource,
      state: "claude-state",
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();

    let response = await browser.fetch(authorizeUrl);
    let location = response.headers.get("location");
    let guard = 0;
    while (location && !/\/interaction\/[^/]+$/.test(new URL(location, origin).pathname) && guard < 5) {
      response = await browser.fetch(new URL(location, origin));
      location = response.headers.get("location");
      guard += 1;
    }
    expect(location, "同意画面に辿り着いていない").toBeTruthy();

    const consentUrl = new URL(location!, origin);
    const page = await browser.fetch(consentUrl);
    const html = await page.text();
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1];

    return { verifier, consentUrl, html, csrf };
  };

  it("同意画面に、接続先・転送先・権限・継続アクセスが表示される", async () => {
    const browser = new Browser();
    const { html } = await reachConsent(browser);

    expect(html).toContain("example.cybozu.com");
    expect(html).toContain("claude.ai");
    expect(html).toContain("レコードの参照");
    // 継続アクセスは scope に現れないので、画面で伝える (§4.10)
    expect(html).toContain("ブラウザを閉じた後も有効です");
    expect(html).toContain("claude-hosted");
  });

  it("許可すると cybozu へ飛び、戻ってトークンまで一周する", async () => {
    const browser = new Browser();
    const { verifier, consentUrl, csrf } = await reachConsent(browser);
    expect(csrf).toBeTruthy();

    // 同意 → cybozu へのリダイレクト
    const consent = await browser.fetch(consentUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf: csrf!, decision: "allow" }).toString(),
    });
    const cybozuUrl = new URL(consent.headers.get("location")!);
    expect(cybozuUrl.origin + cybozuUrl.pathname).toBe(`${CYBOZU_BASE}/oauth2/authorization`);
    expect(cybozuUrl.searchParams.get("scope")).toBe("k:app_record:read");

    // cybozu がユーザーを戻してくる
    const state = cybozuUrl.searchParams.get("state")!;
    let response = await browser.fetch(
      `${origin}/oauth/callback?code=cybozu-code&state=${encodeURIComponent(state)}`,
    );
    expect(exchangeCalls).toBe(1);

    // finish → redirect_uri まで辿る
    const location = await followUntilRedirectUri(browser, response);
    const code = new URL(location).searchParams.get("code");
    expect(code).toBeTruthy();

    const tokenResponse = await fetch(`${origin}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: REDIRECT_URI,
        client_id: CLAUDE_HOSTED_CLIENT_ID,
        code_verifier: verifier,
        resource,
      }).toString(),
    });
    const tokens = (await tokenResponse.json()) as Record<string, unknown>;
    expect(tokenResponse.status, JSON.stringify(tokens)).toBe(200);
    expect(tokens.refresh_token).toBeTruthy();

    // kintone のトークンが平文で保存されていない
    const dumped = JSON.stringify(storage.dump());
    expect(dumped).not.toContain(KINTONE_ACCESS_TOKEN);
    expect(dumped).not.toContain(KINTONE_REFRESH_TOKEN);
  });

  it("CSRF トークンが無い同意は拒否される", async () => {
    const browser = new Browser();
    const { consentUrl } = await reachConsent(browser);

    const response = await browser.fetch(consentUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ decision: "allow" }).toString(),
    });

    expect(response.status).toBe(400);
    expect(failures.map((f) => f.reason)).toContain("csrf-mismatch");
  });

  it("別のブラウザから callback を持ち込んでも通らない", async () => {
    // これが state をブラウザに束縛している理由。
    // 「DB にその state が存在する」だけで通してしまうと、ここが素通りする。
    const browser = new Browser();
    const { consentUrl, csrf } = await reachConsent(browser);
    const consent = await browser.fetch(consentUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf: csrf!, decision: "allow" }).toString(),
    });
    const state = new URL(consent.headers.get("location")!).searchParams.get("state")!;

    const attacker = new Browser();
    const response = await attacker.fetch(
      `${origin}/oauth/callback?code=cybozu-code&state=${encodeURIComponent(state)}`,
    );

    expect(response.status).toBe(400);
    expect(failures.map((f) => f.reason)).toContain("browser-mismatch");
    expect(exchangeCalls, "拒否したのに token 交換を行っている").toBe(0);
  });

  it("同じ callback を2回使っても2回目は通らない", async () => {
    const browser = new Browser();
    const { consentUrl, csrf } = await reachConsent(browser);
    const consent = await browser.fetch(consentUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf: csrf!, decision: "allow" }).toString(),
    });
    const state = new URL(consent.headers.get("location")!).searchParams.get("state")!;
    const callbackUrl = `${origin}/oauth/callback?code=cybozu-code&state=${encodeURIComponent(state)}`;

    // ⚠ callback は応答でブリッジ Cookie を消す。
    // そのまま2回目を投げると「Cookie が無い」で弾かれ、
    // **再使用防止ではなく Cookie 削除のおかげで通ってしまう**。
    // 再使用の経路そのものを試すため、Cookie を控えて手で付け直す。
    const bridgeCookie = browser.header();

    const first = await browser.fetch(callbackUrl);
    expect(first.status).toBe(302);

    const second = await fetch(callbackUrl, {
      redirect: "manual",
      headers: { cookie: bridgeCookie },
    });
    expect(second.status).toBe(400);
    expect(failures.map((f) => f.reason), "already-used で弾かれていない").toContain("already-used");
    expect(exchangeCalls, "2回目でも token 交換を行っている").toBe(1);
  });

  /**
   * `redirect_uri` に着くまでリダイレクトを辿る。
   *
   * ⚠ 途中に **`form_post` の自動送信ページ**が挟まることがある。
   * 2接続目は `accountId` が変わるため、provider が
   * `resume.js` の次の分岐でアカウント切替の確認を入れる:
   *
   *   if (result?.login && session.accountId && session.accountId !== result.login.accountId)
   *
   * 実ブラウザは JS でこのフォームを自動送信する。ここでも同じことをする。
   */
  const followUntilRedirectUri = async (browser: Browser, first: Response): Promise<string> => {
    let response = first;
    const chain: string[] = [];

    for (let guard = 0; guard < 10; guard += 1) {
      const location = response.headers.get("location");
      if (location?.startsWith(REDIRECT_URI)) return location;

      if (location) {
        chain.push(location);
        response = await browser.fetch(new URL(location, origin));
        continue;
      }

      // form_post の自動送信ページ
      const html = await response.text();
      const action = /<form[^>]*action="([^"]+)"/.exec(html)?.[1];
      if (!action) throw new Error(`辿れないページ (status ${response.status})\n${chain.join("\n")}`);

      const fields = new URLSearchParams();
      for (const [, name, value] of html.matchAll(
        /<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"/g,
      )) {
        fields.set(name!, value!);
      }
      chain.push(`form_post -> ${action}`);
      response = await browser.fetch(new URL(action.replaceAll("&amp;", "&"), origin), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: fields.toString(),
      });
    }

    throw new Error(`redirect_uri に到達せず:\n${chain.join("\n")}`);
  };

  /** 認可を最後まで通し、トークン一式を得る */
  const completeConnection = async (browser: Browser) => {
    const { verifier, consentUrl, csrf } = await reachConsent(browser);
    const consent = await browser.fetch(consentUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf: csrf!, decision: "allow" }).toString(),
    });
    const state = new URL(consent.headers.get("location")!).searchParams.get("state")!;

    let response = await browser.fetch(
      `${origin}/oauth/callback?code=cybozu-code&state=${encodeURIComponent(state)}`,
    );
    const location = await followUntilRedirectUri(browser, response);
    const code = new URL(location).searchParams.get("code")!;

    const tokenResponse = await fetch(`${origin}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLAUDE_HOSTED_CLIENT_ID,
        code_verifier: verifier,
        resource,
      }).toString(),
    });
    const issued = (await tokenResponse.json()) as Record<string, unknown>;
    // ⚠ **状態を確かめずに返さない。** 交換が失敗していても
    // 「cybozu を何回呼んだか」だけを見るテストは通ってしまう
    expect(tokenResponse.status, JSON.stringify(issued)).toBe(200);
    expect(issued.access_token, "アクセストークンが発行されていない").toBeTypeOf("string");
    return issued;
  };

  it("同じブラウザで2回目の接続をしても、同意と cybozu 認可を飛ばさない", async () => {
    // 既定の loadExistingGrant はセッションから Grant を拾うため、
    // 2回目は同意0回・cybozu 交換0回で1回目と同じ accountId のトークンが出ていた。
    // 接続ごとに kintone のトークンを持つ設計が崩れる。
    const browser = new Browser();
    await completeConnection(browser);
    expect(exchangeCalls).toBe(1);
    const firstAccountId = lastAccountId;

    // 同じブラウザ（= セッションを持ったまま）でもう一度
    await completeConnection(browser);

    expect(exchangeCalls, "2回目が cybozu を経由していない").toBe(2);
    // ⚠ **回数だけでは足りない。** cybozu を呼んでいても、
    // 2つの接続が同じ主体を指していれば、**片方を切ると両方が落ちる**。
    // 接続ごとに kintone のトークンを持つ設計そのものが崩れる
    expect(lastAccountId, "2つの接続が同じ主体を指している").not.toBe(firstAccountId);
    expect(firstAccountId).toBeTruthy();
  });

  it("2つの接続は互いに独立している（片方を切ってももう片方は生きる）", async () => {
    // 主体が分かれていても、失効が共有されていれば意味が無い。
    // 「別々の接続である」ことの実質はここ
    const first = new Browser();
    await completeConnection(first);
    const firstAccountId = lastAccountId;

    const second = new Browser();
    const secondTokens = await completeConnection(second);
    const secondAccountId = lastAccountId;
    expect(secondAccountId).not.toBe(firstAccountId);

    // 1つ目だけを切る
    await disconnector.disconnect(firstAccountId);

    // 2つ目のリフレッシュは通り続ける
    const refreshed = await fetch(`${origin}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: secondTokens.refresh_token as string,
        client_id: CLAUDE_HOSTED_CLIENT_ID,
        resource,
      }).toString(),
    });

    expect(refreshed.status, "片方の切断がもう片方を巻き込んでいる").toBe(200);
  });

  it("リフレッシュトークンの再使用が接続の失効につながる", async () => {
    const browser = new Browser();
    const tokens = await completeConnection(browser);
    const refreshToken = tokens.refresh_token as string;

    const refreshOnce = () =>
      fetch(`${origin}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: CLAUDE_HOSTED_CLIENT_ID,
          resource,
        }).toString(),
      });

    revokedAccounts.length = 0;
    const first = await refreshOnce();
    expect(first.status).toBe(200);

    // 同じリフレッシュトークンをもう一度
    const second = await refreshOnce();
    const body = (await second.json()) as Record<string, unknown>;
    expect(second.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_grant");

    // 接続 grant（kintone のトークン）まで失効していること
    expect(revokedAccounts, "接続の失効が呼ばれていない").not.toHaveLength(0);
    for (const accountId of revokedAccounts) {
      expect(await grants.isRevoked(accountId)).toBe(true);
      expect(await grants.load(accountId), "失効後も kintone トークンを読み出せる").toBeUndefined();
    }

    // 1回目のリフレッシュで得たトークンも使えない
    const rotated = (await first.json()) as Record<string, unknown>;
    const afterRevoke = await fetch(`${origin}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: rotated.refresh_token as string,
        client_id: CLAUDE_HOSTED_CLIENT_ID,
        resource,
      }).toString(),
    });
    expect(afterRevoke.status, "失効後もリフレッシュできている").toBe(400);
  });

  it("切断すると kintone のトークンも Claude のトークンも使えなくなる", async () => {
    // 片方だけだと、kintone のリフレッシュトークンが残り続けるか、
    // Claude のトークンが生きたまま kintone を叩けなくなる。
    const browser = new Browser();
    const tokens = await completeConnection(browser);
    revokedAccounts.length = 0;

    // 接続の主体を特定する（実運用では管理画面から選ぶ）
    const accountId = lastAccountId;
    expect(await grants.load(accountId)).toBeDefined();

    const providerGrantId = await grants.providerGrantId(accountId);
    expect(providerGrantId, "provider の Grant が接続に紐づいていない").toBeTruthy();
    expect(await provider.Grant.find(providerGrantId!)).toBeDefined();

    // 切断前に発行済みのアクセストークンを控える
    const accessToken = tokens.access_token as string;
    expect(await provider.AccessToken.find(accessToken), "AT が発行されていない").toBeDefined();

    await disconnector.disconnect(accountId);

    // ⚠ **発行済みのアクセストークンが無効になっていること。**
    // grant.destroy() は Grant 文書を消すだけで、系列のトークンは残る。
    // 「リフレッシュが 400 になる」だけでは、この状態を検出できない。
    expect(
      await provider.AccessToken.find(accessToken),
      "切断後もアクセストークンが有効なまま残っている",
    ).toBeUndefined();

    // ⚠ **保存層を直接見る。**
    // `provider.AccessToken.find()` や `provider.Grant.find()` は、
    // 利用時の失効照合 (adapter.find) でも undefined になる。
    // 二重防御が互いにテストを隠すので、「本当に消えているか」は
    // 保存層で確かめないと分からない（ミューテーション検査で判明）。
    expect(
      storage.dump().some((d) => d.grantId === providerGrantId),
      "系列のトークンが保存層に残っている",
    ).toBe(false);
    // モデルを指定して見る。dump() はモデル名を持たないので、
    // キーだけで判定すると、意図的に残している GrantOwner を拾ってしまう。
    expect(
      await storage.find("Grant", cipher.hash(providerGrantId!)),
      "Grant 文書が保存層に残っている",
    ).toBeUndefined();

    // kintone のトークンは読み出せない
    expect(await grants.load(accountId)).toBeUndefined();
    expect(await grants.isRevoked(accountId)).toBe(true);

    // Claude のリフレッシュトークンも使えない
    const response = await fetch(`${origin}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token as string,
        client_id: CLAUDE_HOSTED_CLIENT_ID,
        resource,
      }).toString(),
    });
    expect(response.status, "切断後もリフレッシュできている").toBe(400);
  });

  it("知らない state は拒否される", async () => {
    const browser = new Browser();
    const response = await browser.fetch(`${origin}/oauth/callback?code=x&state=unknown-state`);

    expect(response.status).toBe(400);
    expect(failures.map((f) => f.reason)).toContain("unknown-state");
  });

  it("許可しなかった場合は access_denied で戻る", async () => {
    const browser = new Browser();
    const { consentUrl, csrf } = await reachConsent(browser);

    const response = await browser.fetch(consentUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf: csrf!, decision: "deny" }).toString(),
    });

    const location = await followUntilRedirectUri(browser, response);

    expect(location).toContain("error=access_denied");
    expect(exchangeCalls).toBe(0);
  });

  describe("同意の記録", () => {
    it("認可の途中で固定した内容が保存される（callback 側で作り直さない）", async () => {
      // ⚠ **同意した瞬間と cybozu から戻る瞬間の間に、設定が変わりうる。**
      // 複数インスタンスなら、別の設定のインスタンスが callback を受ける。
      // 作り直すと、**画面に出していない内容に同意したことになる**
      // （外部レビューで再現された）
      consentCalls = 0;
      const browser = new Browser();
      await completeConnection(browser);

      const state = await grants.inspect(lastAccountId);

      expect(state.consentedTools, "callback 側の内容で上書きされている").toEqual([
        "kintone-get-records",
        "kintone-get-space",
      ]);
      expect(state.integrationConsent).toEqual({ username: "kintone-integration" });
      expect(consentCalls, "同意画面を出すとき以外にも呼んでいる").toBe(1);
    });

    it("接続に絶対期限が付く", async () => {
      // ⚠ **provider の Grant に期限を付けただけでは足りない。**
      // Grant が切れても、こちらに保管した cybozu の資格情報は
      // 復号できるままだった（外部レビューで再現された）
      consentCalls = 0;
      const browser = new Browser();
      await completeConnection(browser);

      const state = await grants.inspect(lastAccountId);

      expect(state.expiresAt, "接続に期限が付いていない").toBeDefined();
      expect(state.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000) + 399 * 24 * 60 * 60);
    });

    it("provider の Grant と接続が、同じ瞬間に切れる", async () => {
      /**
       * ⚠ **別々に数えると、callback から finish までの時間だけずれる。**
       *
       * 接続は callback、Grant は finish で計算していたので、
       * finish を90秒遅らせると期限も90秒ずれた（外部レビューで再現された）。
       * 同じ瞬間に切れるべきものが、別の時刻を持っていた。
       */
      // callback と finish の間を90秒空ける
      skewOnFinish = 90;

      const browser = new Browser();
      await completeConnection(browser);

      const state = await grants.inspect(lastAccountId);
      const grantId = await grants.providerGrantId(lastAccountId);
      expect(grantId, "Grant が接続に結び付いていない").toBeDefined();

      const document = await storage.find("Grant", cipher.hash(grantId!));

      /**
       * ⚠ **対応表にも同じ期限を付ける。**
       *
       * 以前は期限なしにしていた（「接続が続く限り必要」）。
       * だが接続に400日の期限を入れた以上、対応表だけが**永久に残る**のは
       * 筋が通らない。実際、切れた接続の対応表が残っているのを見つけた。
       */
      const owner = await storage.find("GrantOwner", cipher.hash(grantId!));
      expect(owner?.expiresAt, "対応表に期限が無い（永久に残る）").toBe(state.expiresAt);

      expect(document?.expiresAt, "Grant に期限が無い").toBeDefined();
      // 秒の丸めで1秒ずれることはある。それ以上は別々に数えている証拠
      expect(
        Math.abs(document!.expiresAt! - state.expiresAt!),
        "Grant の期限を provider の設定から数え直している",
      ).toBeLessThanOrEqual(1);
    });

    it("同意画面に出した連携ユーザーが、接続に記録される", async () => {
      consentCalls = 0;
      // ⚠ **これが無いと、設定を変えるだけで既存の接続の権限が広がる。**
      // 連携機能を無効のまま認可したトークンが、有効化した途端に
      // スペース操作を実行できてしまう（外部レビューで再現された）
      const browser = new Browser();
      await completeConnection(browser);

      const state = await grants.inspect(lastAccountId);

      expect(state.integrationConsent, "同意が記録されていない").toEqual({
        username: "kintone-integration",
      });
    });
  });
});

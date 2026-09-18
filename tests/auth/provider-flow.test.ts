import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Firestore } from "@google-cloud/firestore";

import { createAdapterFactory } from "../../src/auth/adapter.js";
import { createSecretCipher } from "../../src/auth/crypto.js";
import { FirestoreStorage } from "../../src/auth/firestoreStorage.js";
import { MemoryStorage, type Storage } from "../../src/auth/storage.js";
import { CLAUDE_HOSTED_CLIENT_ID, createProvider } from "../../src/auth/provider.js";

/**
 * 認可コードフローを実物の `oidc-provider` で一周させる統合テスト。
 *
 * 設計 (§4.10) で「既定のままでは成立しない」と書いた項目は、
 * **ソースを読んだ結論**であって、動かして確かめたものではなかった。
 * ここで実際に確かめる。特に:
 *
 *  - `issueRefreshToken` を差し替えないとリフレッシュトークンが発行されないこと
 *  - 自前 Adapter が provider と噛み合い、保存物に平文のトークンが残らないこと
 *  - 認可コードが1回しか使えないこと
 *
 * 同意画面は cybozu への委譲を含むが、ここでは**ブリッジが完了した後**を模して
 * すぐ `interactionFinished` する。実装の足場も兼ねる。
 */

const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
const ACCOUNT_ID = "internal-subject-for-this-connection";

const base64url = (input: Buffer): string => input.toString("base64url");

/**
 * ⚠ **保存層を差し替えて、同じフローを2回流す。**
 *
 * エミュレータが動いていても MemoryStorage でしか試していなかったため、
 * 「provider が実際に保存しようとする payload が Firestore に書けるか」を
 * 確かめられていなかった。実際、`AccessToken` の `payload.extra: undefined` で
 * Firestore の検証に落ちるバグがこの組み合わせでしか出なかった。
 */
const emulatorHost = process.env.FIRESTORE_EMULATOR_HOST;
const firestoreClients: Firestore[] = [];

type StorageFactory = { name: string; create: () => Storage };

const storageFactories: StorageFactory[] = [
  { name: "MemoryStorage", create: () => new MemoryStorage() },
];

if (emulatorHost) {
  storageFactories.push({
    name: "FirestoreStorage (エミュレータ)",
    create: () => {
      const firestore = new Firestore({ projectId: "kintone-remote-mcp-test" });
      firestoreClients.push(firestore);
      return new FirestoreStorage({ firestore, collection: `flow-${Date.now()}` });
    },
  });
}

describe.each(storageFactories)("認可コードフロー: $name", ({ create }) => {
  let server: Server;
  let origin: string;
  let storage: Storage;
  let resource: string;

  beforeAll(async () => {
    storage = create();
    const cipher = createSecretCipher(randomBytes(32));
    const adapter = createAdapterFactory({ storage, cipher });

    // 待ち受けポートが決まらないと issuer を決められないので、先に listen する。
    //
    // ⚠ **調べてから閉じて、同じポートで開き直さない。**
    // その隙間で、並行して走る別のテストが同じポートを取れる。
    // `listen` の失敗を受ける相手がいないと、テストは「失敗」ではなく**固まる**。
    // **最初に開いたサーバーへ、あとからハンドラを付ける。**
    server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;

    origin = `http://127.0.0.1:${port}`;
    resource = `${origin}/mcp`;

    const provider = createProvider({
      issuer: origin,
      adapter,
      resource: { resource, scopes: ["kintone:read"] },
      cookieKeys: ["test-cookie-key"],
      // 平文 HTTP で試すので Secure を外す（本番は既定の true）
      secureCookies: false,
    });

    const callback = provider.callback();

    server.on("request", (req, res) => {
      const url = new URL(req.url ?? "/", origin);
      const match = /^\/interaction\/([^/]+)$/.exec(url.pathname);

      if (match) {
        // ブリッジ（cybozu への委譲）が完了した後を模す。
        // 実装では、ここに来る前に cybozu の認可と token 交換が終わっている。
        void (async () => {
          try {
            const details = await provider.interactionDetails(req, res);
            const grant = new provider.Grant({
              accountId: ACCOUNT_ID,
              clientId: CLAUDE_HOSTED_CLIENT_ID,
            });
            grant.addOIDCScope("openid");
            grant.addResourceScope(resource, "kintone:read");
            const grantId = await grant.save();

            await provider.interactionFinished(
              req,
              res,
              {
                login: { accountId: ACCOUNT_ID },
                consent: { grantId },
              },
              { mergeWithLastSubmission: false },
            );
            void details;
          } catch (error) {
            res.writeHead(500, { "content-type": "text/plain" });
            res.end(String(error));
          }
        })();
        return;
      }

      void callback(req, res);
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await Promise.all(firestoreClients.splice(0).map((client) => client.terminate()));
  });

  /** 認可を一周して、未使用の認可コードと verifier を得る */
  const authorizeAndGetCode = async (): Promise<{ code: string; verifier: string }> => {
    const verifier = base64url(randomBytes(32));
    const challenge = base64url(createHash("sha256").update(verifier).digest());

    const authorizeUrl = new URL(`${origin}/auth`);
    authorizeUrl.search = new URLSearchParams({
      client_id: CLAUDE_HOSTED_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid",
      resource,
      state: "state-value",
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();

    const cookies: string[] = [];
    const collect = (response: Response) => {
      for (const cookie of response.headers.getSetCookie?.() ?? []) {
        cookies.push(cookie.split(";")[0]!);
      }
    };

    let response = await fetch(authorizeUrl, { redirect: "manual" });
    collect(response);
    let location = response.headers.get("location");
    let guard = 0;
    while (location && !location.startsWith(REDIRECT_URI) && guard < 10) {
      response = await fetch(new URL(location, origin), {
        redirect: "manual",
        headers: { cookie: cookies.join("; ") },
      });
      collect(response);
      location = response.headers.get("location");
      guard += 1;
    }

    const code = new URL(location!).searchParams.get("code");
    if (!code) throw new Error("認可コードを取得できませんでした");
    return { code, verifier };
  };

  it("discovery が MCP クライアントの要求を満たす", async () => {
    const response = await fetch(`${origin}/.well-known/openid-configuration`);
    const metadata = (await response.json()) as Record<string, unknown>;

    // Claude は常に S256 の PKCE を送る。広告が無いと仕様準拠クライアントが降りる。
    expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
    // 既定のパスは /auth。/authorize ではない (§4.6)
    expect(metadata.authorization_endpoint).toBe(`${origin}/auth`);
    expect(metadata.token_endpoint).toBe(`${origin}/token`);
    // 切断のために revocation を有効にしてある（既定は無効）
    expect(metadata.revocation_endpoint).toBe(`${origin}/token/revocation`);
    expect(metadata.issuer).toBe(origin);
  });

  it("認可からトークンまで一周し、リフレッシュトークンが発行される", async () => {
    const verifier = base64url(randomBytes(32));
    const challenge = base64url(createHash("sha256").update(verifier).digest());

    const authorizeUrl = new URL(`${origin}/auth`);
    authorizeUrl.search = new URLSearchParams({
      client_id: CLAUDE_HOSTED_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid",
      resource,
      state: "state-value",
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();

    // Cookie を持ち回る。provider の interaction は Cookie に依存する。
    const cookies: string[] = [];
    const collect = (response: Response) => {
      const header = response.headers.getSetCookie?.() ?? [];
      for (const cookie of header) cookies.push(cookie.split(";")[0]!);
    };
    const cookieHeader = () => cookies.join("; ");

    let response = await fetch(authorizeUrl, { redirect: "manual", headers: {} });
    collect(response);

    // /auth → /interaction/:uid → /auth/:uid → redirect_uri の順に辿る
    let location = response.headers.get("location");
    let guard = 0;
    while (location && !location.startsWith(REDIRECT_URI) && guard < 10) {
      const next = new URL(location, origin);
      response = await fetch(next, {
        redirect: "manual",
        headers: { cookie: cookieHeader() },
      });
      collect(response);
      location = response.headers.get("location");
      guard += 1;
    }

    expect(location, "redirect_uri まで辿り着いていない").toContain(REDIRECT_URI);

    const code = new URL(location!).searchParams.get("code");
    const state = new URL(location!).searchParams.get("state");
    expect(code).toBeTruthy();
    expect(state).toBe("state-value");

    // トークン交換。form-urlencoded であること自体が要件 (§4.6)
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
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.token_type).toBe("Bearer");

    // ⚠ ここが本題。既定の issueRefreshToken は offline_access を要求し、
    // その offline_access は prompt=consent の無い要求で除去される。
    // 差し替えていなければ、ここが undefined になる。
    expect(
      tokens.refresh_token,
      "リフレッシュトークンが発行されていない（issueRefreshToken の差し替えが効いていない）",
    ).toBeTruthy();

    // 保存物に生のトークンが無いこと。
    // find() は鍵付きハッシュで引くので、生の値では**引けないはず**。
    expect(
      await storage.find("AccessToken", tokens.access_token as string),
      "生のトークン値がそのままキーになっている",
    ).toBeUndefined();
    if (storage instanceof MemoryStorage) {
      const dumped = JSON.stringify(storage.dump());
      expect(dumped).not.toContain(tokens.access_token as string);
      expect(dumped).not.toContain(tokens.refresh_token as string);
      expect(dumped).not.toContain(code!);
    }

    // 認可コードは1回限り
    const replay = await fetch(`${origin}/token`, {
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
    const replayBody = (await replay.json()) as Record<string, unknown>;
    expect(replay.status).toBe(400);
    expect(replayBody.error).toBe("invalid_grant");
  });

  it("PKCE の verifier が違えば拒否される", async () => {
    // ⚠ 存在しないコードを送ると「コードが無い」で落ちるだけで、
    // **verifier の検証に到達しない**。有効な未使用コードと、
    // 形式は正しい別の verifier を使う。
    const { code } = await authorizeAndGetCode();

    const response = await fetch(`${origin}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLAUDE_HOSTED_CLIENT_ID,
        // 形式は正しいが、この認可要求のものではない
        code_verifier: base64url(randomBytes(32)),
        resource,
      }).toString(),
    });
    const body = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
  });

  it("正しい verifier なら同じコードで通る（上のテストが別の理由で通っていないことの確認）", async () => {
    const { code, verifier } = await authorizeAndGetCode();

    const response = await fetch(`${origin}/token`, {
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

    expect(response.status).toBe(200);
  });
});

describe("接続の寿命", () => {
  /**
   * ⚠ **リフレッシュトークンの寿命と Grant の寿命は別物。**
   *
   * リフレッシュのたびにトークンは更新されるが、**親の Grant は延びない**。
   * 同じ値にしていたため、使い続けていても初回の認可から30日で
   * 更新できなくなっていた（外部レビューで、29日目は成功・31日目は
   * `invalid_grant` になることを実測された）。
   *
   * 接続は「切断するまで生きる」設計 (§4.9) なので、
   * Grant はトークンよりずっと長く取る。
   *
   * ⚠ 設定値は provider の内部にしか無いので、そこを読む。
   * 実際に保存して測る方法は使えない（`save(ttl)` が TTL を引数で受け取るため、
   * こちらが渡した値を測り返すだけになる）。
   */
  const ttlOf = async (): Promise<Record<string, number>> => {
    const { default: instance } = await import("oidc-provider/lib/helpers/weak_cache.js");
    const provider = createProvider({
      issuer: "https://mcp.example.com",
      adapter: (() => ({})) as never,
      resource: { resource: "https://mcp.example.com/mcp", scopes: ["kintone:read"] },
      cookieKeys: ["test-cookie-key"],
    });
    return (instance as (p: unknown) => { configuration: { ttl: Record<string, number> } })(
      provider,
    ).configuration.ttl;
  };

  it("Grant は、リフレッシュトークンよりずっと長く生きる", async () => {
    const ttl = await ttlOf();

    expect(
      ttl.Grant,
      "Grant がリフレッシュトークンと同じかそれより短い（使い続けても認可が切れる）",
    ).toBeGreaterThan(ttl.RefreshToken!);
  });

  it("Grant の寿命は1年を超える", async () => {
    // 「切断するまで生きる」に近づける。短いと、使い続けていても
    // ある日突然つながらなくなる
    const ttl = await ttlOf();

    expect(ttl.Grant).toBeGreaterThan(60 * 60 * 24 * 365);
  });

  it("それでも無期限にはしない", async () => {
    // 使われなくなった接続が永遠に残ると、失効の手立てが切断だけになる
    const ttl = await ttlOf();

    expect(ttl.Grant).toBeLessThan(60 * 60 * 24 * 365 * 3);
  });
});

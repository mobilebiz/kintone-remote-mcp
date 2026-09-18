import { createServer, request as httpRequest, type Server } from "node:http";
import { connect as netConnect } from "node:net";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { loadConfig } from "../../src/config.js";
import { buildServer } from "../../src/httpServer.js";
import { MemoryStorage, type Storage } from "../../src/auth/storage.js";
import { createConnectionGrantStore } from "../../src/auth/connectionGrant.js";
import { createSecretCipher } from "../../src/auth/crypto.js";

/**
 * 上限の検証 (§7.2)。
 *
 * **専用のサーバーを立てる。** 他のテストと同じサーバーを使うと、
 * 上限を低くした途端に無関係なテストが 429 で落ちる。
 *
 * ここで確かめたいのは次の2つ。どちらも「守っているつもり」で
 * 実際には守れていなかった箇所。
 *
 * 1. **送信元を詐称しても枠が増えないこと**
 * 2. **接続が増えても上流への同時実行が増えないこと**
 */

const HOST = "127.0.0.1";

const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const TEST_JWKS = JSON.stringify({
  keys: [{ ...privateKey.export({ format: "jwk" }), kid: "test", alg: "RS256", use: "sig" }],
});

/**
 * `X-Forwarded-For` を指定して叩く。
 *
 * ⚠ 生の HTTP クライアントを使う。`fetch` では設定できないヘッダーがあり、
 * 「設定したつもりで無視されている」と、テストは通るが何も検証していない状態になる。
 */
const get = (
  origin: string,
  path: string,
  headers: Record<string, string> = {},
): Promise<{ status: number }> => {
  const parsed = new URL(origin);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path,
        method: "GET",
        headers: { host: HOST, ...headers },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
      },
    );
    req.on("error", reject);
    req.end();
  });
};

/**
 * 生のソケットで、**本文を持たない POST** を送る。
 *
 * ⚠ `fetch` でも Node の `http.request` でも作れない。
 * どちらも `Content-Length: 0` か `Transfer-Encoding` を必ず付けるが、
 * **どちらも無いとき**にだけ body-parser は解析を省略し、
 * `req.body` が `undefined` のままになる。
 */
const rawPostWithoutBody = (
  origin: string,
  path: string,
  headers: Record<string, string>,
): Promise<{ status: number }> => {
  const url = new URL(origin);
  return new Promise((resolve, reject) => {
    const socket = netConnect(Number(url.port), url.hostname, () => {
      const lines = [
        `POST ${path} HTTP/1.1`,
        `Host: ${url.host}`,
        ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
        "Connection: close",
        "",
        "",
      ];
      socket.write(lines.join("\r\n"));
    });
    let raw = "";
    socket.on("data", (chunk) => (raw += chunk.toString()));
    socket.on("error", reject);
    socket.on("end", () => {
      const match = /^HTTP\/1\.1 (\d{3})/.exec(raw);
      resolve({ status: match ? Number(match[1]) : 0 });
    });
  });
};

type Harness = {
  origin: string;
  server: Server;
  callTool: (
    token: string,
    params?: { name: string; arguments?: Record<string, unknown> },
  ) => Promise<Response>;
  /** 経路の綴りを変えて呼ぶ */
  callToolAt: (
    path: string,
    token: string,
    params?: { name: string; arguments?: Record<string, unknown> },
  ) => Promise<Response>;
  /** 接続を作り、その主体のアクセストークンを発行する */
  mintToken: (
    accountId: string,
    options?: {
      expired?: boolean;
      consentedIntegrationUser?: string;
      consentedTools?: string[];
      consentedAppIds?: string;
    },
  ) => Promise<string>;
  releaseKintone: () => void;
  /** ここから保存層を止める。準備が終わってから呼ぶ */
  stall: () => void;
  /** 止めた保存層を再開させる（後片付けを待たずに） */
  resume: () => void;
  /** 保存層を読んだ回数。**積み重なりを見る試験が空振りしていないか**を確かめる */
  storageFinds: () => number;
  /** kintone を呼んだ回数。**呼ばれていないこと**を確かめるために要る */
  kintoneCalls: () => number;
  /** cybozu のトークンエンドポイントを呼んだ回数 */
  cybozuCalls: () => number;
  /** 監査ログに実際に出た内容 */
  auditEntries: () => Array<Record<string, unknown>>;
  /** どちらの資格情報で kintone を叩いたか */
  usedCredentials: () => Array<{ by: "user" | "integration"; tool: string }>;
  /** クライアントに実際に渡された認証情報 */
  authsPassed: () => Array<Record<string, unknown>>;
  shutdown: () => Promise<void>;
};

type ServerOptions = {
  /**
   * cybozu のトークンエンドポイントを黙らせる。
   *
   * **応答を返さない相手**を再現する。`fetch` に既定の期限は無いので、
   * これを止められるかどうかが「詰まるか」の分かれ目になる
   */
  silentCybozu?: boolean;
  /**
   * 保存層の読み取りを**止める**。
   *
   * ⚠ **これが無いと、締め切りそのものを試せない。**
   * cybozu を黙らせる方法では、cybozu 側の期限が先に拾ってしまい、
   * **締め切りを丸ごと止めてもテストが通る**（実際に通った）。
   * 保存層は締め切り以外に止める手段が無いので、ここで詰まらせる。
   *
   * ⚠ 時間で解ける形（`setTimeout`）にしない。
   * 「十分に長い遅延」と「テストの制限時間」の綱引きになり、
   * 実行環境が混んでいるだけで落ちるテストになる（実際に落ちた）。
   * **後片付けで解く**形にすれば、時間に依存しない。
   */
  stallStorage?: boolean;
  /**
   * 止めるモデルを絞る。
   *
   * ⚠ **絞らないと、打ち切りの判定を1か所しか試せない。**
   * 判定は3か所（トークン照会の後・失効確認の後・ツール実行の前）にあるが、
   * すべての `find` を止めると**いちばん手前で必ず止まる**ので、
   * 後ろの2つを消してもテストが通る（変異検査で判明）。
   */
  stallModels?: string[];
  /** cybozu のトークン更新を、指定ミリ秒だけ遅らせる（中断はしない） */
  slowCybozuMs?: number;
  /**
   * kintone クライアントの組み立てで投げる。
   *
   * 枠を取ったあとに例外が出る経路を再現する。
   * **枠を返し忘れると、インスタンス全体が 429 しか返さなくなる**
   */
  brokenKintoneClient?: boolean;
  /** kintone の呼び出しをこの例外で失敗させる */
  kintoneError?: unknown;
};

/** 上限だけを変えたサーバーを立てる */
const startServer = async (
  env: Record<string, string>,
  serverOptions: ServerOptions = {},
): Promise<Harness> => {
  // ⚠ **空きポートを調べてから listen し直さない。**
  // 調べてから掴むまでの間に、並行して走る別のテストが同じポートを取れる。
  // `listen` の失敗を受ける相手がいないと、テストは「失敗」ではなく**固まる**
  // （実際、たまに固まって原因を探すことになった）。
  // **先に listen して、決まったポートで組み立てる。**
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, HOST, resolve));
  const { port } = server.address() as AddressInfo;
  const origin = `http://${HOST}:${port}`;

  const encryptionKey = randomBytes(32).toString("base64");
  const memory = new MemoryStorage();
  // ⚠ **準備の間は止めない。** トークンの発行も保存層を通るので、
  // 最初から止めると準備が終わらない
  let stallActive = false;
  let kintoneCallCount = 0;
  let cybozuCallCount = 0;
  const usedCredentials: Array<{ by: "user" | "integration"; tool: string }> = [];
  const clientOptionsSeen: Array<Record<string, unknown>> = [];
  const auditEntries: Array<Record<string, unknown>> = [];
  let releaseStall: () => void = () => {};
  const stalled = new Promise<void>((resolve) => {
    releaseStall = resolve;
  });
  // ⚠ `Object.create(memory, ...)` で包むと壊れる。
  // MemoryStorage は private フィールドを使うので、
  // プロトタイプ経由の呼び出しは `Receiver must be an instance of` で落ちる。
  // **束縛したメソッドを持つ別のオブジェクト**にする
  /**
   * ⚠ **読み取りの回数を数える。**
   * 予算が「積み重なる」ことを確かめる試験は、**実際に2回以上読んでいなければ
   * 何も確かめていない**。1回しか読まない要求で書いてしまい、
   * 残り時間を毎回戻す変異を見逃していた（外部レビューで再現された）。
   */
  let storageFindCount = 0;
  const storage: Storage = {
    find: async (model, key) => {
      storageFindCount += 1;
      const target = serverOptions.stallModels?.includes(model) ?? true;
      if (stallActive && target) await stalled;
      if (serverOptions.slowStorageMs) {
        await new Promise((resolve) => setTimeout(resolve, serverOptions.slowStorageMs));
      }
      return memory.find(model, key);
    },
    findByIndex: (...args) => memory.findByIndex(...args),
    upsert: (...args) => memory.upsert(...args),
    destroy: (...args) => memory.destroy(...args),
    consume: (...args) => memory.consume(...args),
    revokeByGrantId: (...args) => memory.revokeByGrantId(...args),
    update: (...args) => memory.update(...args),
  };

  // kintone の応答を**こちらから止められる**ようにする。
  // 止められないと、同時実行を試すための「重なり」を作れない
  let unblock: () => void = () => {};
  const blocked = new Promise<void>((resolve) => {
    unblock = resolve;
  });

  const config = loadConfig({
    OAUTH_ISSUER: origin,
    ALLOW_INSECURE_ISSUER: "true",
    SECURE_COOKIES: "false",
    OIDC_JWKS: TEST_JWKS,
    KINTONE_BASE_URL: "https://example.cybozu.com",
    CYBOZU_OAUTH_CLIENT_ID: "client",
    CYBOZU_OAUTH_CLIENT_SECRET: "secret",
    TOKEN_ENCRYPTION_KEY: encryptionKey,
    COOKIE_KEYS: "cookie-key",
    ALLOWED_HOSTS: HOST,
    ...env,
  });

  const built = buildServer({
    config,
    storage,
    auditSink: (entry) => auditEntries.push(entry),
    // cybozu を黙らせる。AbortSignal が効いていれば、ここで止まったままにならない
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      cybozuCallCount += 1;
      if (serverOptions.slowCybozuMs) {
        // 中断はしない。**締め切りだけが応答を返せる**状況を作る
        await new Promise((resolve) => setTimeout(resolve, serverOptions.slowCybozuMs));
        return new Response(
          JSON.stringify({
            access_token: "refreshed",
            token_type: "bearer",
            expires_in: 3600,
            scope: "k:app_record:read",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (serverOptions.silentCybozu) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(init.signal?.reason ?? new Error("aborted")),
          );
        });
      }
      void input;
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch,
    // ⚠ **本番が実際に渡す設定そのもの**を受け取る。
    // トークン文字列だけを受けていた頃は、呼び出し側で資格情報を混ぜても
    // テストから見えなかった（外部レビューで指摘）
    createKintoneClient: (clientOptions) => {
      if (serverOptions.brokenKintoneClient) throw new Error("client construction failed");
      clientOptionsSeen.push(clientOptions.auth);
      const by = "username" in clientOptions.auth ? "integration" : "user";
      return ({
        record: {
          getRecords: async () => {
            kintoneCallCount += 1;
            usedCredentials.push({ by, tool: "get-records" });
            if (serverOptions.kintoneError) throw serverOptions.kintoneError;
            await blocked;
            return { records: [], totalCount: "0" };
          },
        },
        space: {
          getSpace: async () => {
            usedCredentials.push({ by, tool: "get-space" });
            return { id: "1", name: "s" };
          },
        },
      }) as never;
    },
  });

  server.on("request", built.app);

  const grants = createConnectionGrantStore({
    storage: memory,
    cipher: createSecretCipher(Buffer.from(encryptionKey, "base64")),
  });

  return {
    origin,
    server,
    releaseKintone: () => unblock(),
    stall: () => {
      stallActive = true;
    },
    resume: () => {
      stallActive = false;
      releaseStall();
    },
    storageFinds: () => storageFindCount,
    kintoneCalls: () => kintoneCallCount,
    cybozuCalls: () => cybozuCallCount,
    auditEntries: () => auditEntries,
    usedCredentials: () => usedCredentials,
    authsPassed: () => clientOptionsSeen,
    mintToken: async (accountId: string, tokenOptions = {}) => {
      // 接続が無いと、同時実行の判定より手前で 401 になる
      await grants.create(
        accountId,
        {
          accessToken: "kintone-token",
          refreshToken: "kintone-refresh",
          // 期限切れにすると、ツール実行の**前に** cybozu への更新が走る
          expiresAt: Math.floor(Date.now() / 1000) + (tokenOptions.expired ? -60 : 3600),
          scope: "k:app_record:read",
        },
        {
          ...(tokenOptions.consentedIntegrationUser
            ? { integrationUser: { username: tokenOptions.consentedIntegrationUser } }
            : {}),
          ...(tokenOptions.consentedTools ? { toolNames: tokenOptions.consentedTools } : {}),
          ...(tokenOptions.consentedAppIds !== undefined
            ? { allowedAppIds: tokenOptions.consentedAppIds }
            : {}),
        },
      );
      const token = new built.provider.AccessToken({
        accountId,
        client: await built.provider.Client.find("claude-hosted"),
        grantId: `grant-${accountId}`,
        aud: `${origin}/mcp`,
        scope: "kintone:read",
      } as never);
      return token.save();
    },
    /** ⚠ 綴りを変えられるようにしておく。ルーターは `/mcp/` も `/MCP` も受ける */
    callToolAt: (
      path: string,
      token: string,
      params?: { name: string; arguments?: Record<string, unknown> },
    ) =>
      fetch(`${origin}${path}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: params ?? { name: "kintone-get-records", arguments: { app: "1" } },
        }),
      }),
    callTool: (token: string, params?: { name: string; arguments?: Record<string, unknown> }) =>
      fetch(`${origin}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: params ?? { name: "kintone-get-records", arguments: { app: "1" } },
        }),
      }),
    shutdown: async () => {
      unblock();
      releaseStall();
      // ⚠ **`close()` だけでは終わらない。** 処理中のリクエストが残っていると、
      // 後片付けがそこで止まり、テストは「失敗」ではなく「固まる」。
      // 固まった原因を追うのは、落ちた原因を追うよりずっと時間がかかる
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await built.shutdown();
    },
  };
};

let harness: Harness | undefined;

afterEach(async () => {
  await harness?.shutdown();
  harness = undefined;
});

describe("認証前の流量制限", () => {
  it("X-Forwarded-For の左側を足しても枠は増えない", async () => {
    // ⚠ **`trust proxy = true` だと増えた。**
    // Express は `true` だと `X-Forwarded-For` の**左端**を `req.ip` にするが、
    // そこは送信者が自由に書ける。Cloud Run は既存の値を検証も削除もせず、
    // **実 IP を末尾に追記するだけ**なので、左端を信じると
    // ヘッダー1行で送信元ごとの枠を作り直せる（実測）。
    //
    // ⚠ **素の接続で試すと、この差は出ない。**
    // 手前にプロキシが無いと、末尾の値も送信者が書いたものになる。
    // Cloud Run の形（詐称された値 ... 実 IP）を**こちらで組み立てて**渡す。
    harness = await startServer({
      RATE_LIMIT_PRE_AUTH_PER_MINUTE: "2",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const path = "/.well-known/oauth-protected-resource";
    /** Cloud Run が付けるのは**末尾**。前半は送信者が書いた値 */
    const asCloudRun = (realIp: string, forged?: string) => ({
      "x-forwarded-for": forged ? `${forged}, ${realIp}` : realIp,
    });

    expect((await get(harness.origin, path, asCloudRun("203.0.113.1"))).status).toBe(200);
    expect((await get(harness.origin, path, asCloudRun("203.0.113.1"))).status).toBe(200);
    expect(
      (await get(harness.origin, path, asCloudRun("203.0.113.1"))).status,
      "枠が効いていない",
    ).toBe(429);

    // 同じ送信元が、左側に値を足して枠を作り直そうとする
    const forged = await get(harness.origin, path, asCloudRun("203.0.113.1", "198.51.100.9"));
    expect(forged.status, "左端を信じているので枠を作り直せる").toBe(429);

    // 何段重ねても同じ
    const deeper = await get(
      harness.origin,
      path,
      asCloudRun("203.0.113.1", "198.51.100.1, 198.51.100.2"),
    );
    expect(deeper.status, "段数を増やすと抜けられる").toBe(429);
  });

  it("送信元が本当に違えば別の枠になる", async () => {
    // 詐称を防ぐつもりで「ヘッダーを一切見ない」にすると、
    // **同じプロキシ経由の全員が1つの枠を共有する**ことになり、
    // 利用者が1人増えるたびに互いを締め出す
    harness = await startServer({
      RATE_LIMIT_PRE_AUTH_PER_MINUTE: "2",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const path = "/.well-known/oauth-protected-resource";

    await get(harness.origin, path, { "x-forwarded-for": "203.0.113.1" });
    await get(harness.origin, path, { "x-forwarded-for": "203.0.113.1" });
    expect((await get(harness.origin, path, { "x-forwarded-for": "203.0.113.1" })).status).toBe(429);

    const other = await get(harness.origin, path, { "x-forwarded-for": "203.0.113.2" });
    expect(other.status, "送信元を区別できていない").toBe(200);
  });

  it("送信元の枠で拒否した要求は、総量の枠を減らさない", async () => {
    // ⚠ **総量を先に数えると、拒否済みの相手が全員を締め出せる。**
    // 総量枠は全利用者で共有なので、1つの送信元が送り続けるだけで
    // そのインスタンスの認可・更新・MCP 利用を止められる（実測で確認）。
    harness = await startServer({
      RATE_LIMIT_PRE_AUTH_PER_MINUTE: "2",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "4",
    });
    const path = "/.well-known/oauth-protected-resource";
    const attacker = { "x-forwarded-for": "203.0.113.1" };

    // 攻撃者は自分の枠(2)を使い切り、そのあとも送り続ける
    for (let i = 0; i < 6; i += 1) await get(harness.origin, path, attacker);

    // 別の利用者はまだ通れなければならない
    const other = await get(harness.origin, path, { "x-forwarded-for": "198.51.100.7" });

    expect(other.status, "拒否された送信元が総量枠を食い潰している").toBe(200);
  });

  it("送信元に関係なく効く総量の枠がある", async () => {
    // 送信元ごとの枠は、送信元を分散されると意味を失う。
    // **送信元を見ない枠**が無いと、Firestore と KMS を守れない
    harness = await startServer({
      RATE_LIMIT_PRE_AUTH_PER_MINUTE: "1000",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "2",
    });
    const path = "/.well-known/oauth-protected-resource";

    // 送信元はすべて別（詐称されている前提で、そもそも見ない）
    expect((await get(harness.origin, path, { "x-forwarded-for": "198.51.100.1" })).status).toBe(200);
    expect((await get(harness.origin, path, { "x-forwarded-for": "198.51.100.2" })).status).toBe(200);
    const third = await get(harness.origin, path, { "x-forwarded-for": "198.51.100.3" });

    expect(third.status, "総量の枠が無い").toBe(429);
  });
});

describe("kintone への同時実行", () => {
  it("接続単位の枠が空いていても、全体の枠を超えたら断る", async () => {
    // ⚠ **grant 単位の枠だけでは上流を守れない。**
    // 接続が増えるほど枠の合計が増えるので、
    // kintone への同時実行は接続数に比例して伸びる。
    // ここでは接続単位を4、全体を1にして、
    // **接続単位に余裕があるのに全体で止まる**ことを確かめる
    harness = await startServer({
      MAX_CONCURRENT_PER_GRANT: "4",
      MAX_CONCURRENT_TOTAL: "1",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const token = await harness.mintToken("acct-1");

    // 1本目は kintone の中で止まったまま
    const first = harness.callTool(token);
    // 1本目が枠を取るまで待つ
    await new Promise((resolve) => setTimeout(resolve, 50));
    const second = await harness.callTool(token);

    expect(second.status, "全体の枠が効いていない").toBe(429);

    harness.releaseKintone();
    expect((await first).status).toBe(200);
  });

  it("別の接続でも、全体の枠を超えたら断る", async () => {
    // ⚠ **同じ接続だけで試すと、全体の枠の意味が確かめられない。**
    // キーを grant 単位にしてしまっても、1接続なら区別がつかない。
    // **全体の枠の目的は「接続をまたいで効くこと」**なので、
    // 別々の接続で試さないと、何も検証していないのと同じ
    harness = await startServer({
      MAX_CONCURRENT_PER_GRANT: "4",
      MAX_CONCURRENT_TOTAL: "1",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const first = await harness.mintToken("acct-1");
    const second = await harness.mintToken("acct-2");

    // 1つ目の接続が唯一の枠を握る
    const inFlight = harness.callTool(first);
    await new Promise((resolve) => setTimeout(resolve, 50));

    // **別の接続**が断られること
    const blocked = await harness.callTool(second);
    expect(blocked.status, "接続が違うと全体の枠が効いていない").toBe(429);

    harness.releaseKintone();
    expect((await inFlight).status).toBe(200);
  });

  it("全体の枠で断ったとき、接続ごとの枠は返す", async () => {
    // ⚠ **巻き戻しを忘れると、断るたびに接続の枠が減る。**
    // 全体が混んでいるだけで断られた接続は、空いたあとに使えなければならない。
    // 忘れると、**混雑を経験した接続だけが永久に使えなくなる**
    harness = await startServer({
      MAX_CONCURRENT_PER_GRANT: "2",
      MAX_CONCURRENT_TOTAL: "1",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const first = await harness.mintToken("acct-1");
    const second = await harness.mintToken("acct-2");

    const inFlight = harness.callTool(first);
    await new Promise((resolve) => setTimeout(resolve, 50));

    // 2つ目の接続は、全体の枠が無いので断られる。
    // 接続ごとの枠(2)を超える回数だけ繰り返す
    for (let i = 0; i < 3; i += 1) {
      const blocked = await harness.callTool(second);
      expect(blocked.status).toBe(429);
    }

    // 1つ目が終われば、2つ目は使えなければならない
    harness.releaseKintone();
    expect((await inFlight).status).toBe(200);

    const after = await harness.callTool(second);
    expect(after.status, "断るたびに接続ごとの枠が漏れている").toBe(200);
  });

  it("全体の枠は、処理が終われば戻る", async () => {
    harness = await startServer({
      MAX_CONCURRENT_PER_GRANT: "4",
      MAX_CONCURRENT_TOTAL: "1",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const token = await harness.mintToken("acct-1");

    const first = harness.callTool(token);
    await new Promise((resolve) => setTimeout(resolve, 50));
    harness.releaseKintone();
    expect((await first).status).toBe(200);

    // 枠が返っていなければ、ここが 429 になる
    const second = await harness.callTool(token);
    expect(second.status, "枠が返っていない").toBe(200);
  });
});

describe("締め切り", () => {
  it("kintone トークンの更新で詰まっても、締め切りで応答が返る", async () => {
    // ⚠ **締め切りがツール実行の直前から始まっていると、ここは返らない。**
    // トークンの更新は締め切りの手前にあり、cybozu が黙ると
    // 応答が始まらないまま枠を握り続ける（実測で確認）。
    harness = await startServer(
      {
        REQUEST_DEADLINE_MS: "300",
        CYBOZU_TIMEOUT_MS: "200",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { silentCybozu: true },
    );
    const token = await harness.mintToken("acct-slow", { expired: true });

    const response = await harness.callTool(token);

    // 504（締め切り）か 503（cybozu の期限切れ）。**どちらでも「返る」ことが本題**
    expect([503, 504], `応答が ${response.status}`).toContain(response.status);
  }, 20_000);

  it("cybozu が黙っても、接続を失効させない", async () => {
    // ⚠ **繋がらなかっただけで再認可を要求してはいけない** (§7.4)。
    // 401 を返すと、利用者は不要なログインをすることになる
    harness = await startServer(
      {
        REQUEST_DEADLINE_MS: "1000",
        CYBOZU_TIMEOUT_MS: "200",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { silentCybozu: true },
    );
    const token = await harness.mintToken("acct-transient", { expired: true });

    const response = await harness.callTool(token);

    expect(response.status, "一時障害を認可切れとして返している").not.toBe(401);
    expect(response.status).toBe(503);
  }, 20_000);
});

describe("締め切りは認証の段階から数える", () => {
  it("保存層が詰まっても応答が返る", async () => {
    // ⚠ **締め切りがツール実行の直前から始まっていると、ここは返らない。**
    // トークンの照会は締め切りの手前にあり、保存層が黙ると
    // 応答が始まらないまま同時実行の枠を握り続ける。
    //
    // ⚠ cybozu を黙らせる方法では、この欠陥を拾えない。
    // cybozu 側の期限が先に応答を作るので、**締め切りを止めても通る**
    harness = await startServer(
      {
        REQUEST_DEADLINE_MS: "300",
        CYBOZU_TIMEOUT_MS: "200",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { stallStorage: true },
    );
    const token = await harness.mintToken("acct-stuck");
    harness.stall();

    // ⚠ **壁時計で「○秒以内に返ること」を測らない。**
    // 他のテストと並行で走ると、正しく動いていても実時間は数秒ぶれる。
    // 測ると、**直っているのに落ちるテスト**になる（実際に3割ほど落ちた）。
    // 締め切りが効いていなければ保存層は永久に返さないので、
    // 「返るかどうか」だけを見れば、判定は時間に依存しない。
    const response = await harness.callTool(token);

    expect(response.status, "締め切りが認証の段階を覆っていない").toBe(504);
  }, 20_000);
});

describe("枠の解放", () => {
  it("枠を取ったあとに例外が出ても、枠は戻る", async () => {
    // ⚠ **これを取りこぼすと、インスタンスが死ぬ。**
    // 枠は全体で既定8本しかないので、組み立てで投げる不具合があると
    // 8回で使い切り、**そのインスタンスは以後 429 しか返さない**
    // （再起動するまで戻らない）。
    //
    // 枠を「接続ごと」だけにしていた頃は、被害がその接続に閉じていた。
    // 全体の枠を入れたことで、**1つの接続の不具合が全員に波及する**ようになった
    harness = await startServer(
      {
        MAX_CONCURRENT_PER_GRANT: "4",
        MAX_CONCURRENT_TOTAL: "1",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { brokenKintoneClient: true },
    );
    const token = await harness.mintToken("acct-1");

    // 想定外の失敗は 503（一時的に処理できません）
    const first = await harness.callTool(token);
    expect(first.status).toBe(503);

    // 枠が返っていなければ、ここが 429 になる
    const second = await harness.callTool(token);
    expect(second.status, "例外の経路で枠が漏れている").toBe(503);
  });
});

describe("締め切りを過ぎたら、新しい仕事を始めない", () => {
  /**
   * ⚠ **打ち切りの判定は3か所にある。1つの試験ではまとめて確かめられない。**
   *
   * | 判定の位置 | 詰まらせる場所 |
   * | --- | --- |
   * | トークン照会の後 | `AccessToken` の読み取り |
   * | 失効確認の後 | `ConnectionGrant` の読み取り |
   * | ツール実行の前 | cybozu のトークン更新 |
   *
   * すべての読み取りをまとめて止めると**いちばん手前で必ず止まる**ので、
   * 後ろ2つを消してもテストが通ってしまう（変異検査で判明）。
   * **止める場所を1つずつ変えて、判定を1つずつ試す。**
   */
  const expectNoUpstreamCall = async (token: string) => {
    const response = await harness!.callTool(token);
    expect(response.status).toBe(504);

    // 詰まりが解けても、この要求のために上流を呼んではいけない
    harness!.resume();
    await new Promise((resolve) => setTimeout(resolve, 500));

    // ⚠ **2つを別々に見る。** 判定は外部呼び出しごとに置いてあるので、
    // 片方だけ見ていると、もう片方の判定を消しても気づけない
    expect(harness!.cybozuCalls(), "締め切り後に cybozu を呼んでいる").toBe(0);
    expect(harness!.kintoneCalls(), "締め切り後に kintone を呼んでいる").toBe(0);
  };

  it("トークン照会で詰まったとき", async () => {
    harness = await startServer(
      {
        REQUEST_DEADLINE_MS: "300",
        CYBOZU_TIMEOUT_MS: "200",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { stallStorage: true, stallModels: ["AccessToken"] },
    );
    // ⚠ **期限切れにする。** 期限内だと更新が走らず、
    // 「cybozu を呼んでいない」が**何も検証していない**状態になる
    const token = await harness.mintToken("acct-1", { expired: true });
    harness.stall();

    await expectNoUpstreamCall(token);
  }, 20_000);

  it("失効確認で詰まったとき", async () => {
    harness = await startServer(
      {
        REQUEST_DEADLINE_MS: "300",
        CYBOZU_TIMEOUT_MS: "200",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { stallStorage: true, stallModels: ["ConnectionGrant"] },
    );
    const token = await harness.mintToken("acct-1", { expired: true });
    harness.stall();

    await expectNoUpstreamCall(token);
  }, 20_000);

  it("kintone トークンの更新で詰まったとき", async () => {
    // ⚠ cybozu 側の期限は**長く**取る。短いと中断が先に応答を作ってしまい、
    // 締め切りの判定に到達しない
    harness = await startServer(
      {
        REQUEST_DEADLINE_MS: "300",
        CYBOZU_TIMEOUT_MS: "290",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { slowCybozuMs: 800 },
    );
    const token = await harness.mintToken("acct-1", { expired: true });

    const response = await harness.callTool(token);
    // 締め切り(300ms)が cybozu の中断(290ms)より後なので、
    // どちらが先に応答を作るかは実装次第。**上流を呼ばないこと**が本題
    expect([503, 504]).toContain(response.status);

    await new Promise((resolve) => setTimeout(resolve, 1_200));
    expect(harness.kintoneCalls(), "締め切り後に上流を呼んでいる").toBe(0);
  }, 20_000);

  it("504 を返したあとに kintone を呼ばない", async () => {
    // ⚠ **応答を返すだけでは足りない。**
    // 締め切りのタイマーは応答を返すが、処理は止めない。
    // 待機から戻った地点は「まだ何も始めていない」ので、
    // そのまま進むと**結果を届けられない相手のために上流を呼ぶ**。
    //
    // 読み取りでも kintone の API 枠を無駄に使う。書き込みを有効にすれば、
    // **利用者が結果を確認した後に書き込みが走る**ことになる。
    harness = await startServer(
      {
        REQUEST_DEADLINE_MS: "300",
        CYBOZU_TIMEOUT_MS: "200",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { stallStorage: true },
    );
    const token = await harness.mintToken("acct-late");
    harness.stall();

    const response = await harness.callTool(token);
    expect(response.status).toBe(504);
    expect(harness.kintoneCalls(), "締め切り前に呼んでいる").toBe(0);

    // 詰まりが解けても、この要求のために上流を呼んではいけない
    harness.resume();
    await new Promise((resolve) => setTimeout(resolve, 500));

    expect(harness.kintoneCalls(), "締め切り後に上流を呼んでいる").toBe(0);
  }, 20_000);
});

describe("監査ログの配線", () => {
  /**
   * ⚠ **アダプタ単体のテストでは、配線を外しても気づけない。**
   * テスト側が相関 ID をアダプタへ直接渡していたので、
   * **エンドポイントからの受け渡しを消しても通った**。
   * ここでは HTTP から叩いて、実際にログへ出た内容を見る。
   */
  const failing = Object.assign(new Error("boom"), {
    status: 520,
    code: "CB_NO02",
    id: "abcdef1234567890",
  });

  it("利用者に返す相関 ID で、ログを引ける", async () => {
    harness = await startServer(
      { RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000" },
      { kintoneError: failing },
    );
    const token = await harness.mintToken("acct-1");

    const response = await harness.callTool(token);
    const body = await response.text();

    const toolCall = harness.auditEntries().find((entry) => entry.type === "tool.call");
    expect(toolCall, "ツール実行が記録されていない").toBeDefined();

    const logged = toolCall!.correlationId as string;
    expect(logged).toBeTruthy();
    expect(body, "応答の相関 ID でログを引けない").toContain(logged);

    // ⚠ **`structuredContent` だけでは足りない。**
    // 利用者が見て伝えてくるのは**文章のほう**。
    // 文章から ID を落としても、本文全体を見るだけの検査は通ってしまう
    const parsed = JSON.parse(body) as {
      result: { content: Array<{ type: string; text?: string }> };
    };
    const text = parsed.result.content.map((part) => part.text ?? "").join("");
    expect(text, "利用者に見える文章に相関 ID が無い").toContain(logged);
  });

  it("kintone のエラーコードと ID がログに出る", async () => {
    // 分類だけでは、サイボウズへ問い合わせるときの手がかりにならない
    harness = await startServer(
      { RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000" },
      { kintoneError: failing },
    );
    const token = await harness.mintToken("acct-1");

    await harness.callTool(token);

    const toolCall = harness.auditEntries().find((entry) => entry.type === "tool.call");
    expect(toolCall).toMatchObject({
      ok: false,
      kintoneCode: "CB_NO02",
      kintoneId: "abcdef1234567890",
    });
    expect(JSON.stringify(toolCall), "例外の本文が混ざっている").not.toContain("boom");
  });
});

describe("本文を持たない POST", () => {
  it("SDK に本文を読み直させない（呼び出し側の検査）", async () => {
    // ⚠ **「到達できない」と書いていたが、誤りだった。**
    // `Content-Length` も `Transfer-Encoding` も無い POST は、
    // Content-Type が `application/json` でも body-parser が解析を省略し、
    // `req.body` は `undefined` のままになる。
    //
    // つまり**手前の Content-Type 限定を緩めなくても**、
    // この経路は外から叩ける。判定関数の単体試験だけでなく、
    // **呼び出し側**をここで確かめる。
    harness = await startServer({ RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000" });

    // ⚠ **資格情報を付けない。** 付けると、ガードを外しても
    // SDK が空の本文で 400 を返すので、**区別がつかない**
    // （最初に書いたテストはそれで、変異を見逃した）。
    // 本文ガードは認証より**手前**にあるので、
    // 資格情報なしなら 400（ガード）と 401（認証）で見分けられる。
    const response = await rawPostWithoutBody(harness.origin, "/mcp", {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    });

    expect(response.status, "本文ガードを素通りしている").toBe(400);
  });
});

describe("本文を持たない POST", () => {
  it("SDK に本文を読み直させない（呼び出し側の検査）", async () => {
    // ⚠ **「到達できない」と書いていたが、誤りだった。**
    // `Content-Length` も `Transfer-Encoding` も無い POST は、
    // Content-Type が `application/json` でも body-parser が解析を省略し、
    // `req.body` は `undefined` のままになる。
    //
    // つまり**手前の Content-Type 限定を緩めなくても**、
    // この経路は外から叩ける。判定関数の単体試験だけでなく、
    // **呼び出し側**をここで確かめる。
    harness = await startServer({ RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000" });

    // ⚠ **資格情報を付けない。** 付けると、ガードを外しても
    // SDK が空の本文で 400 を返すので、**区別がつかない**
    // （最初に書いたテストはそれで、変異を見逃した）。
    // 本文ガードは認証より**手前**にあるので、
    // 資格情報なしなら 400（ガード）と 401（認証）で見分けられる。
    const response = await rawPostWithoutBody(harness.origin, "/mcp", {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    });

    expect(response.status, "本文ガードを素通りしている").toBe(400);
  });
});


describe("保存層が黙ったとき", () => {
  it("/token が期限内に応答する", async () => {
    // ⚠ **`/mcp` の締め切りは、認可エンドポイントには効かない。**
    // 保存層が黙ると、認可コードの引き換えが**いつまでも応答を返さなかった**
    // （11秒後も未応答であることを外部レビューで実測された）。
    // 設計では token を10秒以内としている。
    harness = await startServer(
      { STORAGE_TIMEOUT_MS: "300", RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000" },
      { stallStorage: true },
    );
    harness.stall();

    const started = Date.now();
    const response = await fetch(`${harness.origin}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "does-not-exist",
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        client_id: "claude-hosted",
        code_verifier: "x".repeat(43),
      }).toString(),
    });
    const elapsed = Date.now() - started;

    // 何を返すかは provider 次第。**返ってくること**が本題
    expect(response.status, "応答が返っていない").toBeGreaterThanOrEqual(400);
    expect(elapsed, "保存層の期限が効いていない").toBeLessThan(5_000);
  }, 20_000);

  it("期限切れは、応答だけ打ち切る形にしない", async () => {
    // 期限切れのあとに発行処理が進むと、**渡していないトークンが生きている**
    // 状態になる。こちらの流れが確実に止まることを、例外の型で確かめる
    const { withStorageTimeout, StorageTimeoutError } = await import(
      "../../src/auth/storageTimeout.js"
    );
    const never = new Promise<never>(() => {});
    const wrapped = withStorageTimeout(
      {
        find: () => never,
        findByIndex: () => never,
        upsert: () => never,
        destroy: () => never,
        consume: () => never,
        revokeByGrantId: () => never,
        update: () => never,
      } as never,
      50,
    );

    await expect(wrapped.find("AccessToken", "k")).rejects.toBeInstanceOf(StorageTimeoutError);
    await expect(wrapped.upsert("AccessToken", "k", {} as never)).rejects.toBeInstanceOf(
      StorageTimeoutError,
    );
  });
});

/** 認可を開始して、同意画面の HTML を取る */
const consentPageHtml = async (origin: string): Promise<string> => {
  const jar: string[] = [];
  const first = await fetch(
    `${origin}/auth?client_id=claude-hosted&redirect_uri=${encodeURIComponent(
      "https://claude.ai/api/mcp/auth_callback",
    )}&response_type=code&scope=openid%20kintone%3Aread&resource=${encodeURIComponent(
      `${origin}/mcp`,
    )}&state=s&code_challenge=${"a".repeat(43)}&code_challenge_method=S256`,
    { redirect: "manual" },
  );
  for (const c of first.headers.getSetCookie()) jar.push(c.split(";")[0]!);
  const page = await fetch(new URL(first.headers.get("location")!, origin), {
    headers: { cookie: jar.join("; ") },
    redirect: "manual",
  });
  return page.text();
};

describe("連携ユーザーの開示", () => {
  it("同意画面に「あなたではない」と出る", async () => {
    // ⚠ **主体が入れ替わることを、見えないまま進めない。**
    // スペース操作は接続した本人ではなく連携ユーザーの権限で動く
    harness = await startServer({
      KINTONE_INTEGRATION_USERNAME: "kintone-integration",
      KINTONE_INTEGRATION_PASSWORD: "pw",
      ENABLE_SPACE_READ: "true",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });

    const jar: string[] = [];
    const first = await fetch(
      `${harness.origin}/auth?client_id=claude-hosted&redirect_uri=${encodeURIComponent(
        "https://claude.ai/api/mcp/auth_callback",
      )}&response_type=code&scope=openid%20kintone%3Aread&resource=${encodeURIComponent(
        `${harness.origin}/mcp`,
      )}&state=s&code_challenge=${"a".repeat(43)}&code_challenge_method=S256`,
      { redirect: "manual" },
    );
    for (const c of first.headers.getSetCookie()) jar.push(c.split(";")[0]!);
    const page = await fetch(new URL(first.headers.get("location")!, harness.origin), {
      headers: { cookie: jar.join("; ") },
      redirect: "manual",
    });
    const html = await page.text();

    expect(html, "同意画面に到達していない").toContain("スペースの参照");
    expect(html, "主体が入れ替わることが書かれていない").toContain("あなたではなく");
    expect(html).toContain("kintone-integration");
  });

  it("アプリを絞っているときは、検索を同意画面に出さない", async () => {
    // ⚠ 公開しないものを同意画面に出すと、**許可した覚えのないものが
    // 許可されたことになる**。実際には `kintone-search` は公開されない
    harness = await startServer({
      KINTONE_INTEGRATION_USERNAME: "kintone-integration",
      KINTONE_INTEGRATION_PASSWORD: "pw",
      ENABLE_SEARCH: "true",
      ALLOWED_APP_IDS: "10",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });

    const html = await consentPageHtml(harness.origin);

    expect(html, "公開しない検索を同意画面に出している").not.toContain("横断検索");
  });

  it("アプリを絞っていなければ、検索は同意画面に出る", async () => {
    harness = await startServer({
      KINTONE_INTEGRATION_USERNAME: "kintone-integration",
      KINTONE_INTEGRATION_PASSWORD: "pw",
      ENABLE_SEARCH: "true",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });

    const html = await consentPageHtml(harness.origin);

    expect(html).toContain("横断検索");
  });

  it("連携ユーザーが無ければ、その行は出ない", async () => {
    harness = await startServer({
      ENABLE_SPACE_READ: "true",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });

    const jar: string[] = [];
    const first = await fetch(
      `${harness.origin}/auth?client_id=claude-hosted&redirect_uri=${encodeURIComponent(
        "https://claude.ai/api/mcp/auth_callback",
      )}&response_type=code&scope=openid%20kintone%3Aread&resource=${encodeURIComponent(
        `${harness.origin}/mcp`,
      )}&state=s&code_challenge=${"a".repeat(43)}&code_challenge_method=S256`,
      { redirect: "manual" },
    );
    for (const c of first.headers.getSetCookie()) jar.push(c.split(";")[0]!);
    const page = await fetch(new URL(first.headers.get("location")!, harness.origin), {
      headers: { cookie: jar.join("; ") },
      redirect: "manual",
    });
    const html = await page.text();

    expect(html).not.toContain("あなたではなく");
  });
});

describe("連携ユーザーの配線（HTTP 越し）", () => {
  /**
   * ⚠ **アダプタ単体では配線の抜けを拾えない。**
   * エンドポイントが連携用クライアントを渡し忘れても、
   * `identity` をログに渡し忘れても、アダプタのテストは通る
   * （変異検査で実際にすり抜けた）。ここは HTTP から叩いて確かめる。
   */
  const enabled = {
    KINTONE_INTEGRATION_USERNAME: "kintone-integration",
    KINTONE_INTEGRATION_PASSWORD: "pw",
    ENABLE_SPACE_READ: "true",
    RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
  };

  it("スペース操作が連携ユーザーの資格情報で実行される", async () => {
    harness = await startServer(enabled);
    const token = await harness.mintToken("acct-1", {
      consentedIntegrationUser: "kintone-integration",
      consentedTools: ["kintone-get-records", "kintone-get-space"],
    });

    const response = await harness.callTool(token, {
      name: "kintone-get-space",
      arguments: { id: "1" },
    });

    expect(response.status).toBe(200);
    expect(
      harness.usedCredentials(),
      "本人の資格情報でスペースを叩いている（連携用クライアントが渡っていない）",
    ).toEqual([{ by: "integration", tool: "get-space" }]);
  });

  it("通常のツールは本人の資格情報のまま", async () => {
    harness = await startServer(enabled);
    const token = await harness.mintToken("acct-1");
    // この試験の getRecords は止めない（同時実行の試験で使う仕掛け）
    harness.releaseKintone();

    await harness.callTool(token);

    expect(harness.usedCredentials()).toEqual([{ by: "user", tool: "get-records" }]);
  });

  it("監査ログに identity が残る", async () => {
    harness = await startServer(enabled);
    const token = await harness.mintToken("acct-1", {
      consentedIntegrationUser: "kintone-integration",
      consentedTools: ["kintone-get-records", "kintone-get-space"],
    });

    await harness.callTool(token, { name: "kintone-get-space", arguments: { id: "1" } });

    const toolCall = harness.auditEntries().find((e) => e.type === "tool.call");
    expect(toolCall?.identity, "誰として実行したかが残っていない").toBe("integration");
  });

  it("連携ユーザーが無ければ、スペース操作は一覧に出ない", async () => {
    harness = await startServer({
      ENABLE_SPACE_READ: "true",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const token = await harness.mintToken("acct-1");

    const listed = await fetch(`${harness.origin}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    const body = (await listed.json()) as { result: { tools: Array<{ name: string }> } };

    expect(body.result.tools.map((t) => t.name)).not.toContain("kintone-get-space");
  });
});

describe("同意していない接続に、連携権限を与えない", () => {
  /**
   * ⚠ **設定を変えるだけで既存の接続の権限が広がってはいけない。**
   *
   * 連携機能を無効のまま認可したトークンが、有効化した途端に
   * スペース操作を実行できていた（外部レビューで再現された）。
   * 主体が入れ替わることに同意していないので、これは同意の偽装になる。
   */
  const enabled = {
    KINTONE_INTEGRATION_USERNAME: "kintone-integration",
    KINTONE_INTEGRATION_PASSWORD: "pw",
    ENABLE_SPACE_READ: "true",
    RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
  };

  it("同意の記録が無い接続では、スペース操作が公開されない", async () => {
    harness = await startServer(enabled);
    // 連携ユーザーに同意していない接続（機能を入れる前に作られたもの）
    const token = await harness.mintToken("acct-old");

    const listed = await fetch(`${harness.origin}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    const body = (await listed.json()) as { result: { tools: Array<{ name: string }> } };

    expect(
      body.result.tools.map((t) => t.name),
      "同意していない接続にスペース操作が出ている",
    ).not.toContain("kintone-get-space");
  });

  it("同意の記録が無ければ、呼んでも実行されない", async () => {
    harness = await startServer(enabled);
    const token = await harness.mintToken("acct-old");

    const response = await harness.callTool(token, {
      name: "kintone-get-space",
      arguments: { id: "1" },
    });
    const body = (await response.json()) as { error?: unknown; result?: { isError?: boolean } };

    // 公開していないツールなので、実行そのものが失敗する
    expect(body.error ?? body.result?.isError, "同意していない操作が実行された").toBeTruthy();
    expect(
      harness.usedCredentials().filter((c) => c.by === "integration"),
      "連携ユーザーの資格情報が使われた",
    ).toEqual([]);
  });

  it("連携ユーザーを別人に差し替えたら、同意し直しが要る", async () => {
    // 権限の範囲が変わるので、同じ「連携ユーザーに同意した」では足りない
    harness = await startServer(enabled);
    const token = await harness.mintToken("acct-1", {
      consentedIntegrationUser: "someone-else",
    });

    await harness.callTool(token, { name: "kintone-get-space", arguments: { id: "1" } });

    // ⚠ **応答の成否で判定しない。** スタブの戻り値が上流の期待と合わないと
    // ツール自体が失敗するので、同意の確認と無関係に「失敗」になる
    // （最初に書いたテストはそれで、変異を見逃した）。
    // **実際にどちらの資格情報が使われたか**を見る
    expect(
      harness.usedCredentials().filter((c) => c.by === "integration"),
      "別人の連携ユーザーの資格情報が使われた",
    ).toEqual([]);
  });
});

describe("本番のクライアントに渡す認証情報", () => {
  /**
   * ⚠ **kintone はパスワード認証を OAuth より優先する。**
   * 1つのクライアントに両方載ると、すべての操作が連携ユーザーとして実行される。
   * 呼び出し側で混ぜても見えない状態だった（外部レビューで指摘）。
   */
  it("本人のクライアントには OAuth だけを渡す", async () => {
    harness = await startServer({
      KINTONE_INTEGRATION_USERNAME: "kintone-integration",
      KINTONE_INTEGRATION_PASSWORD: "pw",
      ENABLE_SPACE_READ: "true",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const token = await harness.mintToken("acct-1", {
      consentedIntegrationUser: "kintone-integration",
    });
    harness.releaseKintone();

    await harness.callTool(token);

    const auths = harness.authsPassed();
    expect(auths.length).toBeGreaterThan(0);
    for (const auth of auths) {
      const keys = Object.keys(auth).sort().join(",");
      expect(
        ["oAuthToken", "password,username"],
        `認証情報が混ざっている: ${keys}`,
      ).toContain(keys);
    }
    // 本人のものには必ず OAuth が1つある
    expect(auths.some((a) => "oAuthToken" in a && !("password" in a))).toBe(true);
  });

  it("設定した値がそのまま渡る（形だけでなく中身を見る）", async () => {
    // ⚠ **キーの形だけを見ていると、値を取り違えても気づけない。**
    // 「要求を通したこと」と「正しい要求を渡したこと」は別（外部レビューで指摘）
    harness = await startServer({
      KINTONE_INTEGRATION_USERNAME: "the-integration-user",
      KINTONE_INTEGRATION_PASSWORD: "the-integration-password",
      ENABLE_SPACE_READ: "true",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const token = await harness.mintToken("acct-1", {
      consentedIntegrationUser: "the-integration-user",
      consentedTools: ["kintone-get-records", "kintone-get-space"],
    });

    await harness.callTool(token, { name: "kintone-get-space", arguments: { id: "1" } });

    const auths = harness.authsPassed();
    expect(auths, "連携ユーザーの資格情報が渡っていない").toContainEqual({
      username: "the-integration-user",
      password: "the-integration-password",
    });
    // 本人のほうには、保存してある kintone のトークンがそのまま渡る
    expect(auths, "本人のトークンが渡っていない").toContainEqual({
      oAuthToken: "kintone-token",
    });
  });
});

describe("同意していない操作は、設定を広げても付かない", () => {
  /**
   * ⚠ **実行時の設定をそのまま使ってはいけない。**
   *
   * `ALLOW_DESTRUCTIVE` を後から有効にすると、
   * **削除に同意していない既存の接続に削除権限が付いていた**
   * （外部レビューで再現された）。
   *
   * kintone の書き込みスコープは削除も許すので、
   * **上流のスコープ検証でも止まらない**。こちらで止めるしかない。
   */
  const listToolsWith = async (token: string): Promise<string[]> => {
    const response = await fetch(`${harness!.origin}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    const body = (await response.json()) as { result: { tools: Array<{ name: string }> } };
    return body.result.tools.map((t) => t.name);
  };

  it("削除を後から有効にしても、同意済みの接続には出ない", async () => {
    // 削除を許可した状態のサーバー
    harness = await startServer({
      ENABLE_RECORD_WRITE: "true",
      ALLOW_DESTRUCTIVE: "true",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    // 削除が無かった頃に同意した接続
    const token = await harness.mintToken("acct-old", {
      consentedTools: ["kintone-get-records", "kintone-add-records", "kintone-update-records"],
    });

    const names = await listToolsWith(token);

    expect(names, "同意していない削除が公開されている").not.toContain("kintone-delete-records");
    // 同意した範囲は使える
    expect(names).toContain("kintone-add-records");
  });

  it("同意していても、設定で止めていれば出ない", async () => {
    // 積であること。同意が設定を上書きしてはいけない
    harness = await startServer({ RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000" });
    const token = await harness.mintToken("acct-1", {
      consentedTools: ["kintone-get-records", "kintone-delete-records"],
    });

    const names = await listToolsWith(token);

    expect(names, "設定で止めたものが同意で復活している").not.toContain("kintone-delete-records");
  });

  it("記録の無い接続でも、移行時点の範囲までは使える", async () => {
    // ここを「何も許さない」にすると、同意の仕組みを入れる前に繋いだ
    // 利用者が全員その場で使えなくなる
    harness = await startServer({
      ENABLE_RECORD_WRITE: "true",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const token = await harness.mintToken("acct-old");

    const names = await listToolsWith(token);

    expect(names).toContain("kintone-add-records");
  });

  it("記録の無い接続に、削除は付かない", async () => {
    // ⚠ **「現在の設定をすべて受け入れる」は将来の権限への白紙同意になる。**
    // 操作に同意していない接続に、後から削除を有効にすると届いていた
    // （外部レビューで再現された）
    harness = await startServer({
      ENABLE_RECORD_WRITE: "true",
      ALLOW_DESTRUCTIVE: "true",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const token = await harness.mintToken("acct-old");

    const names = await listToolsWith(token);

    expect(names, "同意していない削除が付いている").not.toContain("kintone-delete-records");
    expect(names).toContain("kintone-add-records");
  });

  it("記録の無い接続に、連携ユーザーの操作は付かない", async () => {
    // 主体が入れ替わる操作。同意していない接続に付けてはいけない
    harness = await startServer({
      KINTONE_INTEGRATION_USERNAME: "kintone-integration",
      KINTONE_INTEGRATION_PASSWORD: "pw",
      ENABLE_SPACE_READ: "true",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    const token = await harness.mintToken("acct-old");

    const names = await listToolsWith(token);

    expect(names, "同意していないスペース操作が付いている").not.toContain("kintone-get-space");
  });

  it("同意した対象アプリを超えて届かない", async () => {
    // ⚠ **ツール名の積では止まらない。** 許可リストを変えても名前は同じ
    harness = await startServer({
      ALLOWED_APP_IDS: "2",
      RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
    });
    harness.releaseKintone();
    // 「対象アプリ: 1」で同意した接続
    const token = await harness.mintToken("acct-1", {
      consentedTools: ["kintone-get-records"],
      consentedAppIds: "1",
    });

    const response = await harness.callTool(token, {
      name: "kintone-get-records",
      arguments: { app: "2" },
    });
    const body = (await response.json()) as { result?: { isError?: boolean } };

    expect(body.result?.isError, "同意していないアプリへ届いている").toBe(true);
    expect(harness.usedCredentials()).toEqual([]);
  });
});

describe("認可まわりの要求全体の期限", () => {
  /**
   * ⚠ **操作ごとの期限では足りない。**
   *
   * 保存層の操作それぞれに期限を掛けていたが、**操作のたびに
   * タイマーが始まり直す**。読み取りを毎回4秒遅らせると、
   * 個別の期限には一度も掛からないまま**6回で約24秒**かかった
   * （外部レビューで実測された）。設計では `/token` は10秒以内。
   */
  it("/mcp のツール実行は、認可の予算に巻き込まれない", async () => {
    // ⚠ `/mcp` は自前の締め切り（既定55秒）を持っている。
    // 認可用の短い予算を被せると、**ツール実行が途中で切られる**
    harness = await startServer(
      {
        AUTH_REQUEST_DEADLINE_MS: "300",
        REQUEST_DEADLINE_MS: "10000",
        CYBOZU_TIMEOUT_MS: "5000",
        STORAGE_TIMEOUT_MS: "5000",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      // 認可の予算より長く、MCP の締め切りより短い
      { slowStorageMs: 600 },
    );
    const token = await harness.mintToken("acct-1");
    harness.releaseKintone();

    const response = await harness.callTool(token);

    expect(response.status, "ツール実行が認可の予算で切られている").toBe(200);
  }, 20_000);

  it("経路の綴りが違っても、認可の予算に巻き込まれない", async () => {
    /**
     * ⚠ **`req.path === "/mcp"` で比べてはいけない。**
     *
     * Express の既定は大小文字を区別せず、末尾のスラッシュも無視するので、
     * `app.all("/mcp")` には `/mcp/` も `/MCP` も届く。
     * 一致だけで除外していたため、**この2つの綴りには認可用の短い予算が掛かった**
     * （同じ無効トークンで `/mcp` は401、`/mcp/` は503になることを外部レビューが再現）。
     *
     * 綴りで、認証と更新に許される時間が変わってはいけない。
     */
    harness = await startServer(
      {
        AUTH_REQUEST_DEADLINE_MS: "300",
        REQUEST_DEADLINE_MS: "10000",
        CYBOZU_TIMEOUT_MS: "5000",
        STORAGE_TIMEOUT_MS: "5000",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { slowStorageMs: 600 },
    );
    const token = await harness.mintToken("acct-1");
    harness.releaseKintone();

    for (const path of ["/mcp", "/mcp/", "/MCP"]) {
      const response = await harness.callToolAt(path, token);

      expect(response.status, `${path} が認可の予算で切られている`).toBe(200);
    }
  }, 30_000);

  it("読み取りが積み重なっても、予算を超えない", async () => {
    /**
     * ⚠ **1回しか読まない要求では、何も確かめられない。**
     *
     * 最初に書いたのは存在しない認可コードを `/token` へ投げるもので、
     * 読み取りは**1回**だった。それでは「操作ごとの期限」と
     * 「要求全体の予算」の区別が付かず、**残り時間を毎回戻す変異が通った**
     * （外部レビューで再現された）。
     *
     * `/revocation` に `token_type_hint=refresh_token` を付けると、
     * まず RefreshToken を読み、外れてから AccessToken を読む。
     * **2回目が順番に来る**ので、積み重なりが観測できる。
     *
     * 個別の期限(5秒)には一度も掛からない。予算(0.45秒)だけが効く:
     *
     * | 読み取り | 掛かる時間 | 残り予算 |
     * | --- | --- | --- |
     * | 1回目 | 0.3秒 | 0.15秒 |
     * | 2回目 | 0.15秒で打ち切り | 0 |
     *
     * 予算が積み重ならなければ、2回目も 0.45 秒もらえるので通ってしまう。
     */
    harness = await startServer(
      {
        STORAGE_TIMEOUT_MS: "5000",
        AUTH_REQUEST_DEADLINE_MS: "450",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { slowStorageMs: 300 },
    );

    const before = harness.storageFinds();
    const response = await fetch(`${harness.origin}/token/revocation`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: "does-not-exist",
        token_type_hint: "refresh_token",
        client_id: "claude-hosted",
      }).toString(),
    });
    const reads = harness.storageFinds() - before;

    // ⚠ 読み取りが1回しか起きていないなら、この試験は何も見ていない
    expect(reads, "順番に読む経路でなくなっている。試験が空振りしている").toBeGreaterThanOrEqual(
      2,
    );
    expect(response.status, "予算を使い切っても読み続けている").toBe(500);
  }, 20_000);

  it("予算の範囲に収まる読み取りは通す", async () => {
    // ⚠ **「常に落ちる」でも上の試験は通る。** 予算を無視して
    // 毎回 RequestDeadlineExceeded を投げる実装と区別が付かない
    harness = await startServer(
      {
        STORAGE_TIMEOUT_MS: "5000",
        AUTH_REQUEST_DEADLINE_MS: "5000",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { slowStorageMs: 300 },
    );

    const response = await fetch(`${harness.origin}/token/revocation`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: "does-not-exist",
        token_type_hint: "refresh_token",
        client_id: "claude-hosted",
      }).toString(),
    });

    // 失効は「知らないトークンでも成功」を返す (RFC 7009)
    expect(response.status, "予算内なのに打ち切られている").toBe(200);
  }, 20_000);

  it("要求ごとに予算は戻る", async () => {
    // 使い切ったまま次の要求まで引きずると、2回目以降が全部落ちる
    harness = await startServer(
      {
        STORAGE_TIMEOUT_MS: "5000",
        AUTH_REQUEST_DEADLINE_MS: "5000",
        RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE: "1000",
      },
      { slowStorageMs: 300 },
    );

    for (const attempt of [1, 2, 3]) {
      const response = await fetch(`${harness.origin}/token/revocation`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          token: "does-not-exist",
          token_type_hint: "refresh_token",
          client_id: "claude-hosted",
        }).toString(),
      });

      expect(response.status, `${attempt} 回目で予算が戻っていない`).toBe(200);
    }
  }, 20_000);
});

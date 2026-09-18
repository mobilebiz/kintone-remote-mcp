import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import { createBridge } from "../../src/auth/bridge.js";
import { createConnectionGrantStore, GrantRevokedError } from "../../src/auth/connectionGrant.js";
import { createCybozuOAuthClient, CybozuOAuthError } from "../../src/auth/cybozuOAuth.js";
import { createSecretCipher } from "../../src/auth/crypto.js";
import { MemoryStorage, type Storage } from "../../src/auth/storage.js";

const CONFIG = {
  baseUrl: "https://example.cybozu.com",
  clientId: "client-id",
  clientSecret: "client-secret",
  redirectUri: "https://mcp.example.com/oauth/callback",
  scopes: ["k:app_record:read", "k:app_settings:read"],
};

const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

describe("cybozu OAuth クライアント", () => {
  it("認可 URL に必要なパラメータが揃う", () => {
    const client = createCybozuOAuthClient(CONFIG);
    const url = new URL(client.buildAuthorizationUrl("state-value"));

    expect(url.origin + url.pathname).toBe("https://example.cybozu.com/oauth2/authorization");
    expect(url.searchParams.get("client_id")).toBe("client-id");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("state")).toBe("state-value");
    expect(url.searchParams.get("redirect_uri")).toBe(CONFIG.redirectUri);
    expect(url.searchParams.get("scope")).toBe("k:app_record:read k:app_settings:read");
  });

  it("トークン交換は Basic 認証と form-urlencoded で行う", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        access_token: "at",
        refresh_token: "rt",
        token_type: "bearer",
        expires_in: 3600,
        scope: "k:app_record:read",
      }),
    );
    const client = createCybozuOAuthClient(CONFIG, { fetch: fetchMock, now: () => 1000 });

    const tokens = await client.exchangeCode("the-code");

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://example.cybozu.com/oauth2/token");
    expect((init.headers as Record<string, string>)["content-type"]).toBe(
      "application/x-www-form-urlencoded",
    );
    expect((init.headers as Record<string, string>).authorization).toBe(
      `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`,
    );
    expect(String(init.body)).toContain("grant_type=authorization_code");
    expect(tokens).toEqual({
      accessToken: "at",
      refreshToken: "rt",
      expiresAt: 1000 + 3600,
      scope: "k:app_record:read",
    });
  });

  it("リフレッシュ応答に refresh_token は含まれない前提で扱う", async () => {
    // 公式仕様の応答は access_token / token_type / expires_in / scope のみ。
    // ここで refresh_token を期待する実装にすると、更新のたびに接続が壊れる。
    const fetchMock = vi.fn(async () =>
      jsonResponse({ access_token: "new-at", token_type: "bearer", expires_in: 3600, scope: "s" }),
    );
    const client = createCybozuOAuthClient(CONFIG, { fetch: fetchMock, now: () => 2000 });

    const refreshed = await client.refresh("rt");

    expect(refreshed).toEqual({ accessToken: "new-at", expiresAt: 2000 + 3600, scope: "s" });
    expect(refreshed).not.toHaveProperty("refreshToken");
  });

  it("エラー応答の詳細を外に持ち出さない", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        { error: "invalid_grant", error_description: "SECRET_DETAIL_should_not_leak" },
        400,
      ),
    );
    const client = createCybozuOAuthClient(CONFIG, { fetch: fetchMock });

    const error = await client.exchangeCode("bad").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(CybozuOAuthError);
    expect(String(error)).not.toContain("SECRET_DETAIL_should_not_leak");
    // 分類はログのために保持する
    expect((error as CybozuOAuthError).upstreamError).toBe("invalid_grant");
  });
});

describe("ブリッジの state", () => {
  const setup = (now: () => number) => {
    const storage = new MemoryStorage();
    const cipher = createSecretCipher(randomBytes(32));
    // ⚠ **consume の呼び出しを数えられるようにする。**
    // 結果だけを見ていると「期限切れで弾いた」と「使用済みにしてから弾いた」の
    // 区別がつかず、実装をどちらに変えてもテストが通る（実際に通った）
    const consumeCalls: Array<{ model: string; key: string }> = [];
    const watched: Storage = {
      find: (...args) => storage.find(...args),
      findByIndex: (...args) => storage.findByIndex(...args),
      upsert: (...args) => storage.upsert(...args),
      destroy: (...args) => storage.destroy(...args),
      consume: (model, key, at) => {
        consumeCalls.push({ model, key });
        return storage.consume(model, key, at);
      },
      revokeByGrantId: (...args) => storage.revokeByGrantId(...args),
      update: (...args) => storage.update(...args),
    };
    return Object.assign(createBridge({ storage: watched, cipher, ttlSeconds: 600, now }), {
      consumeCalls,
    });
  };

  it("期限内なら通る", async () => {
    let clock = 1000;
    const bridge = setup(() => clock);
    const started = await bridge.start({
      interactionUid: "uid-1",
      accountId: "acct-1",
      consent: {
        toolNames: ["kintone-get-records"],
        integrationUser: undefined,
        allowedAppIds: undefined,
      },
    });

    clock = 1000 + 599;
    const outcome = await bridge.consume(started.state, started.browserSecret);

    expect(outcome.ok).toBe(true);
  });

  it("期限を過ぎた state は拒否される", async () => {
    // TTL による自動削除は掃除であって認可判定ではない (§4.9)。
    // 消えていなくても、使うときに自分で期限を見る。
    let clock = 1000;
    const bridge = setup(() => clock);
    const started = await bridge.start({
      interactionUid: "uid-1",
      accountId: "acct-1",
      consent: {
        toolNames: ["kintone-get-records"],
        integrationUser: undefined,
        allowedAppIds: undefined,
      },
    });

    clock = 1000 + 601;
    const outcome = await bridge.consume(started.state, started.browserSecret);

    expect(outcome).toEqual({ ok: false, reason: "expired" });
  });

  it("期限切れの state は消費もされない", async () => {
    // 期限切れで弾いたのに使用済みにしてしまうと、
    // 「期限切れ」と「再使用」の区別がつかなくなる。
    //
    // ⚠ **2回目も expired になることを見るだけでは足りない。**
    // 使用済みにしてから弾く実装でも、期限の判定が先にあれば
    // 2回目はやはり expired を返す。**保存層に手が伸びたかどうか**を見る
    let clock = 1000;
    const bridge = setup(() => clock);
    const started = await bridge.start({
      interactionUid: "uid-1",
      accountId: "acct-1",
      consent: {
        toolNames: ["kintone-get-records"],
        integrationUser: undefined,
        allowedAppIds: undefined,
      },
    });

    clock = 1000 + 601;
    await bridge.consume(started.state, started.browserSecret);

    expect(bridge.consumeCalls, "期限切れなのに使用済みにしている").toHaveLength(0);

    clock = 1000 + 602;
    const again = await bridge.consume(started.state, started.browserSecret);
    expect(again).toEqual({ ok: false, reason: "expired" });
  });

  it("期限内なら、通したときだけ消費する", async () => {
    // 上の裏返し。「一度も消費しない」実装でも上のテストは通るので、
    // **正常系で消費していること**を別に確かめる
    let clock = 1000;
    const bridge = setup(() => clock);
    const started = await bridge.start({
      interactionUid: "uid-1",
      accountId: "acct-1",
      consent: {
        toolNames: ["kintone-get-records"],
        integrationUser: undefined,
        allowedAppIds: undefined,
      },
    });

    // ブラウザが違えば、消費せずに弾く
    await bridge.consume(started.state, "wrong-secret");
    expect(bridge.consumeCalls, "検証前に消費している").toHaveLength(0);

    await bridge.consume(started.state, started.browserSecret);
    expect(bridge.consumeCalls, "通したのに消費していない").toHaveLength(1);
  });
});

describe("接続 grant", () => {
  const setup = () => {
    const storage = new MemoryStorage();
    const cipher = createSecretCipher(randomBytes(32));
    return { storage, store: createConnectionGrantStore({ storage, cipher }) };
  };

  const tokens = {
    accessToken: "kintone-access-token",
    refreshToken: "kintone-refresh-token",
    expiresAt: 9999,
    scope: "k:app_record:read",
  };

  it("kintone のトークンが平文で保存されない", async () => {
    const { storage, store } = setup();
    await store.create("acct-1", tokens);

    const dumped = JSON.stringify(storage.dump());
    expect(dumped).not.toContain(tokens.accessToken);
    expect(dumped).not.toContain(tokens.refreshToken);
  });

  it("保存したトークンを取り出せる", async () => {
    const { store } = setup();
    await store.create("acct-1", tokens);

    expect(await store.load("acct-1")).toEqual({ accountId: "acct-1", ...tokens });
  });

  it("別の主体の暗号文は復号できない", async () => {
    // AAD に主体を入れているので、レコードの移し替えは検出できる。
    const { storage, store } = setup();
    await store.create("acct-1", tokens);
    await store.create("acct-2", { ...tokens, accessToken: "other" });

    const [first, second] = storage.dump();
    await storage.upsert("ConnectionGrant", second!.key, {
      payload: { ...second!.payload, accessToken: first!.payload.accessToken },
      expiresAt: undefined,
      grantId: undefined,
      uidHash: undefined,
      userCodeHash: undefined,
    });

    expect(await store.load("acct-2")).toBeUndefined();
  });

  it("アクセストークンだけを差し替えてもリフレッシュトークンが残る", async () => {
    // cybozu のリフレッシュ応答に refresh_token が無いため、既存の値を保持し続ける。
    const { store } = setup();
    await store.create("acct-1", tokens);

    await store.updateAccessToken("acct-1", "renewed-access-token", 12345, "k:app_record:read");

    const loaded = await store.load("acct-1");
    expect(loaded?.accessToken).toBe("renewed-access-token");
    expect(loaded?.refreshToken).toBe(tokens.refreshToken);
    expect(loaded?.expiresAt).toBe(12345);
  });

  it("失効させると読み出せなくなる", async () => {
    const { store } = setup();
    await store.create("acct-1", tokens);

    await store.revoke("acct-1");

    expect(await store.load("acct-1")).toBeUndefined();
    expect(await store.isRevoked("acct-1")).toBe(true);
  });

  it("失効済みの主体には保存も更新もできない", async () => {
    // 失効処理と保存が競合したとき、失効の後にレコードが作られると接続が復活する。
    const { store } = setup();
    await store.revoke("acct-1");

    await expect(store.create("acct-1", tokens)).rejects.toBeInstanceOf(GrantRevokedError);
    await expect(store.updateAccessToken("acct-1", "x", 1, "s")).rejects.toBeInstanceOf(
      GrantRevokedError,
    );
  });
});

describe("トークン応答の読み取り", () => {
  /**
   * ⚠ **本番で最初に踏んだ問題がこれ。**
   * 同意画面のあと「kintone との連携に失敗しました」で止まり、
   * ログには `token-exchange-failed` しか残っていなかった。
   * 例外を `catch {}` で捨てていたので、**cybozu が何を返したのか分からなかった**。
   */
  const SECRET_TOKEN = "cybozu-access-token-must-not-appear";

  it("expires_in が文字列でも受け付ける", async () => {
    // ⚠ RFC 6749 は数値と定めているが、文字列で返す実装がある。
    // `typeof !== "number"` で弾いていたため、**正しい応答を拒否しうる**
    const client = createCybozuOAuthClient(CONFIG, {
      fetch: async () =>
        jsonResponse({
          access_token: "at",
          refresh_token: "rt",
          token_type: "bearer",
          expires_in: "3600",
          scope: "k:app_record:read",
        }),
      now: () => 1000,
    });

    const tokens = await client.exchangeCode("the-code");

    expect(tokens.expiresAt, "文字列の expires_in を拒否している").toBe(4600);
  });

  it("足りない値があったとき、何が来たのかを残す", async () => {
    // 「必要な値がありません」だけでは、原因に辿り着けない
    const client = createCybozuOAuthClient(CONFIG, {
      fetch: async () =>
        jsonResponse({ access_token: SECRET_TOKEN, token_type: "bearer", expires_in: 3600 }),
    });

    const error = await client.exchangeCode("the-code").catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(CybozuOAuthError);
    const shape = (error as CybozuOAuthError).shape;
    expect(shape, "応答の形が残っていない").toBeTruthy();
    // 何が来て、何が来なかったかが分かる
    expect(shape).toContain("access_token:string");
    expect(shape).toContain("expires_in:number");
    expect(shape, "refresh_token が無いことが分かるべき").not.toContain("refresh_token");
    // ⚠ **値は1つも載せない**
    expect(JSON.stringify(shape)).not.toContain(SECRET_TOKEN);
  });

  it("上流のエラーでも、ステータスとコードを残す", async () => {
    const client = createCybozuOAuthClient(CONFIG, {
      fetch: async () =>
        jsonResponse(
          { error: "invalid_grant", error_description: SECRET_TOKEN },
          400,
        ),
    });

    const error = (await client
      .exchangeCode("the-code")
      .catch((caught: unknown) => caught)) as CybozuOAuthError;

    expect(error.status).toBe(400);
    expect(error.upstreamError).toBe("invalid_grant");
    // error_description は秘密を含みうるので、形だけ
    expect(error.shape).toContain("error_description:string");
    expect(JSON.stringify({ ...error, message: error.message })).not.toContain(SECRET_TOKEN);
  });
});

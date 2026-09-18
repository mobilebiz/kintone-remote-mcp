import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { randomBytes } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";

import { createAdapterFactory } from "../../src/auth/adapter.js";
import { createSecretCipher } from "../../src/auth/crypto.js";
import { MemoryStorage } from "../../src/auth/storage.js";
import { createProvider, isAllowedCimdHost } from "../../src/auth/provider.js";
import { renderConsentPage } from "../../src/auth/consentPage.js";
import { loadConfig } from "../../src/config.js";

/**
 * 事前登録していないクライアントを受け入れる (CIMD)。
 *
 * `client_id` が HTTPS の URL になり、provider がそれを取りに行って
 * 返ってきた文書をクライアントの定義に使う。
 *
 * ⚠ **これは「知らない相手を受け入れる」という決定**なので、
 * 誰を受け入れるかと、利用者に誰だと見せるかの2つが要点になる。
 */

const ALLOWED = new Set(["chatgpt.com"]);

describe("受け入れるホストの判定", () => {
  it("許可したホストは通す", () => {
    expect(isAllowedCimdHost("https://chatgpt.com/connector/metadata.json", ALLOWED)).toBe(true);
  });

  it("許可リストが空なら、何も通さない", () => {
    // ⚠ **「誰でも登録できる」を既定にしない。**
    // 設定を忘れたときに開くのではなく、閉じる
    expect(isAllowedCimdHost("https://chatgpt.com/x.json", new Set())).toBe(false);
  });

  it("後方一致で化けられない", () => {
    // ⚠ `endsWith` で書くと、これが通ってしまう
    expect(isAllowedCimdHost("https://evil-chatgpt.com/x.json", ALLOWED)).toBe(false);
    expect(isAllowedCimdHost("https://chatgpt.com.example.net/x.json", ALLOWED)).toBe(false);
  });

  it("サブドメインは別のホスト", () => {
    // 許可したのは chatgpt.com であって、その配下ではない
    expect(isAllowedCimdHost("https://a.chatgpt.com/x.json", ALLOWED)).toBe(false);
  });

  it("大小文字は揃えて見る", () => {
    expect(isAllowedCimdHost("https://ChatGPT.com/x.json", ALLOWED)).toBe(true);
  });

  it("https 以外は通さない", () => {
    expect(isAllowedCimdHost("http://chatgpt.com/x.json", ALLOWED)).toBe(false);
  });

  it("URL として読めないものは通さない", () => {
    expect(isAllowedCimdHost("chatgpt.com", ALLOWED)).toBe(false);
    expect(isAllowedCimdHost("claude-hosted", ALLOWED)).toBe(false);
    expect(isAllowedCimdHost("", ALLOWED)).toBe(false);
  });

  it("認証情報付きの URL では、ホストを偽装できない", () => {
    // https://chatgpt.com@evil.example/ の host は evil.example
    expect(isAllowedCimdHost("https://chatgpt.com@evil.example/x.json", ALLOWED)).toBe(false);
  });
});

describe("設定の読み込み", () => {
  const base = (): Record<string, string | undefined> => ({
    OAUTH_ISSUER: "https://mcp.example.com",
    OIDC_JWKS: JSON.stringify({ keys: [] }),
    KINTONE_BASE_URL: "https://example.cybozu.com",
    CYBOZU_OAUTH_CLIENT_ID: "c",
    CYBOZU_OAUTH_CLIENT_SECRET: "s",
    TOKEN_ENCRYPTION_KEY: Buffer.alloc(32).toString("base64"),
    COOKIE_KEYS: "k",
    ALLOWED_HOSTS: "mcp.example.com",
  });

  it("未設定なら空（= CIMD 無効）", () => {
    expect(loadConfig(base()).cimdAllowedHosts).toEqual([]);
  });

  it("カンマ区切りで読み、小文字に揃える", () => {
    expect(loadConfig({ ...base(), CIMD_ALLOWED_HOSTS: "ChatGPT.com, example.org" })
      .cimdAllowedHosts).toEqual(["chatgpt.com", "example.org"]);
  });

  it("URL やポートを書いたら止める", () => {
    // ⚠ 黙って受け取ると、パスまで一致を見るのか曖昧なまま動く
    expect(() => loadConfig({ ...base(), CIMD_ALLOWED_HOSTS: "https://chatgpt.com/x" }))
      .toThrowError(/ホスト名だけ/);
    expect(() => loadConfig({ ...base(), CIMD_ALLOWED_HOSTS: "chatgpt.com:443" }))
      .toThrowError(/ホスト名だけ/);
  });
});

describe("同意画面での見せ方", () => {
  const view = (overrides: Partial<Parameters<typeof renderConsentPage>[0]>) =>
    renderConsentPage({
      clientName: "Claude",
      clientNameSource: "registered",
      clientId: "claude-hosted",
      kintoneHost: "example.cybozu.com",
      redirectHost: "claude.ai",
      permissions: ["レコードの参照"],
      formAction: "/x",
      csrfToken: "t",
      ...overrides,
    });

  it("事前登録のクライアントは、名前だけを出す", () => {
    const html = view({});

    expect(html).toContain("Claude");
    expect(html).not.toContain("と名乗っています");
  });

  it("CIMD のクライアントは、照合済みのホストを出し、名前は自称と断る", () => {
    /**
     * ⚠ **ここを怠ると、名乗るだけで化けられる。**
     * CIMD では `client_id` の URL を用意できる者が名前を自由に決められる。
     * 「Claude」と名乗るのは誰にでもできる。
     */
    const html = view({
      clientName: "Claude",
      clientNameSource: "self-asserted",
      clientId: "https://evil.example/metadata.json",
    });

    expect(html, "照合済みのホストが出ていない").toContain("evil.example");
    expect(html, "自称であることが書かれていない").toContain("と名乗っています");
  });

  it("自称の名前も HTML として escape する", () => {
    const html = view({
      clientName: '<img src=x onerror="alert(1)">',
      clientNameSource: "self-asserted",
      clientId: "https://chatgpt.com/m.json",
    });

    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img");
  });
});

describe("広告されるかどうか（本物の provider で確かめる）", () => {
  /**
   * ⚠ **述語だけでは足りない。**
   * `isAllowedCimdHost` が正しくても、provider の設定に繋いでいなければ
   * 機能そのものが無効のままになる。**discovery に出るかで確かめる。**
   */
  const servers: Server[] = [];

  afterAll(async () => {
    for (const s of servers) await new Promise<void>((r) => s.close(() => r()));
  });

  const start = async (cimdAllowedHosts: string[]): Promise<string> => {
    const server = createServer();
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as AddressInfo;
    const origin = `http://127.0.0.1:${port}`;

    const provider = createProvider({
      issuer: origin,
      adapter: createAdapterFactory({
        storage: new MemoryStorage(),
        cipher: createSecretCipher(randomBytes(32)),
      }),
      resource: { resource: `${origin}/mcp`, scopes: ["kintone:read"] },
      cookieKeys: ["k"],
      secureCookies: false,
      cimdAllowedHosts,
    });
    const callback = provider.callback();
    server.on("request", callback);
    return origin;
  };

  const metadataOf = async (origin: string): Promise<Record<string, unknown>> =>
    (await (await fetch(`${origin}/.well-known/openid-configuration`)).json()) as Record<
      string,
      unknown
    >;

  it("ホストを挙げると、CIMD が広告される", async () => {
    const metadata = await metadataOf(await start(["chatgpt.com"]));

    expect(metadata.client_id_metadata_document_supported, "CIMD が有効になっていない").toBe(
      true,
    );
  });

  it("挙げなければ、広告されない", async () => {
    // ⚠ **できないことを広告しない。** 広告すると、クライアントは
    // 繋がる前提で来て、原因の分からない失敗になる
    const metadata = await metadataOf(await start([]));

    expect(metadata.client_id_metadata_document_supported).toBeUndefined();
  });

  it("動的クライアント登録は、どちらでも無効のまま", async () => {
    // ⚠ **CIMD と DCR は別物。** CIMD を入れたからといって
    // 「誰でも登録できる口」を開けたわけではない
    const withCimd = await metadataOf(await start(["chatgpt.com"]));
    const without = await metadataOf(await start([]));

    expect(withCimd.registration_endpoint, "DCR の口が開いている").toBeUndefined();
    expect(without.registration_endpoint).toBeUndefined();
  });
});

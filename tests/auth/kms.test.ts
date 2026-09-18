import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import {
  decrypterUsing,
  defaultKmsClient,
  KeyUnwrapError,
  plaintextFrom,
  resolveEncryptionKey,
} from "../../src/auth/kms.js";
import { loadConfig } from "../../src/config.js";

/**
 * トークン暗号鍵のエンベロープ暗号化 (§4.9)。
 *
 * 包む前は、32バイトの鍵が**そのまま環境変数に載っていた**。
 * Cloud Run の設定を読める者は、そのまま鍵を手に入れられる。
 */

const KEY = randomBytes(32);
const KEY_B64 = KEY.toString("base64");
const KEY_NAME = "projects/p/locations/l/keyRings/r/cryptoKeys/k";

const validEnv = (): Record<string, string | undefined> => ({
  OAUTH_ISSUER: "https://mcp.example.com",
  OIDC_JWKS: JSON.stringify({ keys: [] }),
  KINTONE_BASE_URL: "https://example.cybozu.com",
  CYBOZU_OAUTH_CLIENT_ID: "client",
  CYBOZU_OAUTH_CLIENT_SECRET: "secret",
  COOKIE_KEYS: "cookie-key",
  ALLOWED_HOSTS: "mcp.example.com",
});

describe("鍵の出所を決める", () => {
  it("生の鍵を指定できる", () => {
    const config = loadConfig({ ...validEnv(), TOKEN_ENCRYPTION_KEY: KEY_B64 });

    expect(config.encryptionKeySource.kind).toBe("plain");
    expect(config.tokenEncryptionKey.equals(KEY)).toBe(true);
  });

  it("KMS で包んだ鍵を指定できる", () => {
    const config = loadConfig({
      ...validEnv(),
      KMS_KEY_NAME: KEY_NAME,
      TOKEN_ENCRYPTION_KEY_CIPHERTEXT: Buffer.from("wrapped").toString("base64"),
    });

    expect(config.encryptionKeySource).toMatchObject({ kind: "kms", keyName: KEY_NAME });
  });

  it("両方を同時に設定させない", () => {
    // どちらを使っているのか分からない状態にしない
    expect(() =>
      loadConfig({
        ...validEnv(),
        TOKEN_ENCRYPTION_KEY: KEY_B64,
        KMS_KEY_NAME: KEY_NAME,
        TOKEN_ENCRYPTION_KEY_CIPHERTEXT: "d3JhcHBlZA==",
      }),
    ).toThrowError(/同時に設定できません/);
  });

  it("片方だけでは止める", () => {
    expect(() => loadConfig({ ...validEnv(), KMS_KEY_NAME: KEY_NAME })).toThrowError(
      /TOKEN_ENCRYPTION_KEY_CIPHERTEXT/,
    );
    expect(() =>
      loadConfig({ ...validEnv(), TOKEN_ENCRYPTION_KEY_CIPHERTEXT: "d3JhcHBlZA==" }),
    ).toThrowError(/KMS_KEY_NAME/);
  });

  it("どちらも無ければ止める", () => {
    expect(() => loadConfig(validEnv())).toThrowError(/TOKEN_ENCRYPTION_KEY/);
  });
});

/**
 * ⚠ **差し替えるのは「KMS を呼ぶところ」だけ。**
 * 復号関数まるごとを差し替えられる形にしていたので、
 * `resolveEncryptionKey` の**本番の既定経路が1行も実行されなかった**
 * （外部レビューで指摘）。ここを口にすれば、応答の読み取りも例外の包み方も
 * base64 の読み方も本番と同じものが動く。
 */
const clientReturning = (plaintext: unknown) => {
  const requests: Array<{ name: string; ciphertext: Buffer }> = [];
  return {
    requests,
    client: {
      decrypt: async (request: { name: string; ciphertext: Buffer }) => {
        requests.push(request);
        return [{ plaintext }] as [{ plaintext?: unknown }];
      },
    },
  };
};

describe("鍵を取り出す", () => {
  it("包んだ鍵を KMS で戻す", async () => {
    // ⚠ **包む前と同じ鍵が戻らなければ、保存済みのトークンを1つも読めない**
    const { client, requests } = clientReturning(Buffer.from(KEY_B64, "utf8"));

    const key = await resolveEncryptionKey(
      { kind: "kms", keyName: KEY_NAME, ciphertext: Buffer.from("wrapped") },
      () => client,
    );

    expect(key.equals(KEY), "元の鍵と違う").toBe(true);
    expect(requests).toHaveLength(1);
    expect(requests[0]!.name).toBe(KEY_NAME);
    expect(requests[0]!.ciphertext.equals(Buffer.from("wrapped"))).toBe(true);
  });

  it("生の鍵はそのまま使う（KMS を呼ばない）", async () => {
    // ⚠ クライアントを**作ることすら**しない。作るだけで認証情報を探しにいく
    const created = vi.fn(() => clientReturning(Buffer.from(KEY_B64, "utf8")).client);

    const key = await resolveEncryptionKey({ kind: "plain", key: KEY }, created);

    expect(key.equals(KEY)).toBe(true);
    expect(created).not.toHaveBeenCalled();
  });

  it("末尾に改行が付いていても読める", async () => {
    // Secret Manager に入れるときに混ざりやすい（cybozu のシークレットで実際に踏んだ）。
    //
    // ⚠ これは base64 の復号が空白を無視するから通る。**こちらは何もしていない。**
    // 自前で落とす処理を入れたが、外しても結果が変わらなかったので消した。
    // 将来この形式を base64 以外に変えるなら、ここが効かなくなる
    const { client } = clientReturning(Buffer.from(`${KEY_B64}\n`, "utf8"));

    const key = await resolveEncryptionKey(
      { kind: "kms", keyName: KEY_NAME, ciphertext: Buffer.from("w") },
      () => client,
    );

    expect(key.equals(KEY)).toBe(true);
  });

  it("長さが違えば止める", async () => {
    const { client } = clientReturning(
      Buffer.from(randomBytes(16).toString("base64"), "utf8"),
    );

    await expect(
      resolveEncryptionKey(
        { kind: "kms", keyName: KEY_NAME, ciphertext: Buffer.from("w") },
        () => client,
      ),
    ).rejects.toBeInstanceOf(KeyUnwrapError);
  });

  it("KMS の例外から message を持ち出さない", async () => {
    // KMS のエラーには要求の詳細が入りうる
    const secret = "SECRET_IN_KMS_ERROR_9f3a";
    const client = {
      decrypt: async (): Promise<[{ plaintext?: unknown }]> => {
        throw new Error(secret);
      },
    };

    const error = await resolveEncryptionKey(
      { kind: "kms", keyName: KEY_NAME, ciphertext: Buffer.from("w") },
      () => client,
    ).catch((caught: unknown) => caught as Error);

    expect(error).toBeInstanceOf(KeyUnwrapError);
    expect(error.message).not.toContain(secret);
  });

  it("既定では本物の KMS クライアントを作る", () => {
    /**
     * ⚠ **ここを確かめないと、既定を「固定の鍵を返す」に変えても全件通る**
     * （外部レビューで再現された）。差し替えの口を下げても、
     * その口の**既定値**を見ていなければ同じことになる。
     *
     * 構築するだけでは KMS を呼ばないので、資格情報が無くても通る。
     */
    const client = defaultKmsClient();

    expect(client.constructor.name).toBe("KeyManagementServiceClient");
    expect(typeof client.decrypt).toBe("function");
  });
});

describe("KMS の応答の読み取り（本番の経路）", () => {
  /**
   * ⚠ **要求の中身を捨てない。**
   * 要求を無視していたため、KMS へ渡す鍵名や暗号文を
   * 誤った固定値に変えても14件すべて通った（外部レビューで指摘）。
   * 「要求を通したこと」と「正しい要求を渡したこと」は別。
   */

  it("応答の平文を実際に使う（固定の鍵を返さない）", async () => {
    const { client } = clientReturning(Buffer.from(KEY_B64, "utf8"));

    const key = await resolveEncryptionKey(
      { kind: "kms", keyName: KEY_NAME, ciphertext: Buffer.from("w") },
      () => client,
    );

    expect(key.equals(KEY), "応答と違う鍵が返っている").toBe(true);
    // 組み立ての途中だけを取り出しても、同じ結果になること
    expect(
      (await decrypterUsing(client)({ name: KEY_NAME, ciphertext: Buffer.from("w") })).toString(
        "utf8",
      ),
    ).toBe(KEY_B64);
  });

  it("KMS へ、設定の鍵名と暗号文をそのまま渡す", async () => {
    // ⚠ 本番ではここを取り違えると**起動できない**。
    // 注入した関数への引数だけを見ていると、その先の転送を確かめられない
    const { client, requests } = clientReturning(Buffer.from(KEY_B64, "utf8"));
    const ciphertext = Buffer.from("the-wrapped-key");

    await resolveEncryptionKey({ kind: "kms", keyName: KEY_NAME, ciphertext }, () => client);

    expect(requests).toHaveLength(1);
    expect(requests[0]!.name, "鍵名が渡っていない").toBe(KEY_NAME);
    expect(requests[0]!.ciphertext.equals(ciphertext), "暗号文が渡っていない").toBe(true);
  });

  it("平文が base64 文字列で返っても読める", () => {
    // KMS の REST 表現は base64 文字列。gRPC は Uint8Array
    const asString = plaintextFrom({ plaintext: Buffer.from(KEY_B64, "utf8").toString("base64") });

    expect(asString.toString("utf8")).toBe(KEY_B64);
  });

  it("平文が無ければ、そうと分かる理由で止める", () => {
    // ⚠ **型が違うのと、そもそも返ってこないのは別の話。**
    // どちらも「止まる」だけを見ると、後段の throw に吸収されて
    // この判定を消しても気づけない（変異検査で判明）。
    // 起動時のログに出る文言なので、診断の手がかりとして区別する
    expect(() => plaintextFrom({})).toThrowError(/平文がありません/);
    expect(() => plaintextFrom({ plaintext: null })).toThrowError(/平文がありません/);
  });

  it("解釈できない形なら、そうと分かる理由で止める", () => {
    // 黙って空の鍵で動き出さないこと
    expect(() => plaintextFrom({ plaintext: 42 })).toThrowError(/解釈できません/);
  });
});

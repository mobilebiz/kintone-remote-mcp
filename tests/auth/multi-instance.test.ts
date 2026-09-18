import { randomBytes } from "node:crypto";
import { Firestore } from "@google-cloud/firestore";
import { afterAll, describe, expect, it } from "vitest";

import { Timestamp } from "@google-cloud/firestore";

import { createAdapterFactory } from "../../src/auth/adapter.js";
import { createConnectionGrantStore } from "../../src/auth/connectionGrant.js";
import { createSecretCipher } from "../../src/auth/crypto.js";
import { FirestoreStorage } from "../../src/auth/firestoreStorage.js";
import { createKintoneTokenProvider } from "../../src/auth/kintoneToken.js";
import { createRevoker } from "../../src/auth/revocation.js";
import type { CybozuOAuthClient } from "../../src/auth/cybozuOAuth.js";

/**
 * 複数インスタンスでの振る舞い。
 *
 * Cloud Run は複数のインスタンスで動く。**片方で切断したら、もう片方でも
 * 使えなくならなければならない。** メモリ実装ではこれを確かめようがないので、
 * 共有ストレージ（Firestore エミュレータ）で実証する。
 *
 * `FIRESTORE_EMULATOR_HOST` が無い環境では飛ばす。
 */

const emulatorHost = process.env.FIRESTORE_EMULATOR_HOST;
const clients: Firestore[] = [];

afterAll(async () => {
  await Promise.all(clients.map((client) => client.terminate()));
});

const tokens = {
  accessToken: "kintone-access",
  refreshToken: "kintone-refresh",
  expiresAt: 10_000,
  scope: "k:app_record:read",
};

/**
 * 同じ Firestore を見る、独立した2つのインスタンスを組み立てる。
 *
 * **オブジェクトを共有しない。** 共有してしまうと、
 * 「同一プロセス内で動いているから通った」のか
 * 「保存層を通じて伝わったから通った」のかが区別できない。
 */
const buildInstances = (collection: string) => {
  const key = randomBytes(32);

  const make = () => {
    const firestore = new Firestore({ projectId: "kintone-remote-mcp-test" });
    clients.push(firestore);
    const storage = new FirestoreStorage({ firestore, collection });
    // 鍵は共有する（同じサーバーの別インスタンスなので、本番も Secret Manager 由来の同一鍵）
    const cipher = createSecretCipher(key);
    const grants = createConnectionGrantStore({ storage, cipher });
    const revoker = createRevoker({ storage, cipher, grants });
    const adapter = createAdapterFactory({
      storage,
      cipher,
      revokeByGrantId: (grantId) => revoker.revokeByGrantId(grantId, "token-reuse"),
      isConnectionRevoked: (accountId) => grants.isRevoked(accountId),
    });
    return { storage, cipher, grants, revoker, adapter };
  };

  return { a: make(), b: make() };
};

describe.skipIf(!emulatorHost)("複数インスタンス（共有 Firestore）", () => {
  it("片方で切断すると、もう片方でもアクセストークンが使えない", async () => {
    const { a, b } = buildInstances(`multi-${Date.now()}-1`);
    const accountId = "acct-multi-1";
    const grantId = "grant-multi-1";
    const token = "access-token-multi-1";

    // インスタンス A で接続を作り、トークンを発行する
    await a.grants.create(accountId, tokens);
    await a.grants.attachProviderGrant(accountId, grantId);
    await a.revoker.rememberGrantOwner(grantId, accountId);
    await a.adapter("AccessToken").upsert(
      token,
      { jti: token, kind: "AccessToken", accountId, grantId },
      3600,
    );

    // インスタンス B からも見える
    expect(await b.adapter("AccessToken").find(token), "B からトークンが見えない").toBeDefined();
    expect(await b.grants.load(accountId)).toBeDefined();

    // A で切断する
    await a.revoker.revokeConnection(accountId, "disconnect");

    // ⚠ **B でも使えなくなっていること**
    expect(
      await b.adapter("AccessToken").find(token),
      "切断が別インスタンスに効いていない",
    ).toBeUndefined();
    expect(await b.grants.load(accountId), "B から kintone トークンが読み出せる").toBeUndefined();
    expect(await b.grants.isRevoked(accountId)).toBe(true);
  });

  it("片方で再使用を検知すると、もう片方でも接続が失効する", async () => {
    const { a, b } = buildInstances(`multi-${Date.now()}-2`);
    const accountId = "acct-multi-2";
    const grantId = "grant-multi-2";
    const refreshToken = "refresh-token-multi-2";

    await a.grants.create(accountId, tokens);
    await a.grants.attachProviderGrant(accountId, grantId);
    await a.revoker.rememberGrantOwner(grantId, accountId);
    await a.adapter("RefreshToken").upsert(
      refreshToken,
      { jti: refreshToken, kind: "RefreshToken", accountId, grantId },
      3600,
    );

    // A で1回使う
    await a.adapter("RefreshToken").consume(refreshToken);

    // B で同じものを使おうとする（= 再使用）
    await expect(b.adapter("RefreshToken").consume(refreshToken)).rejects.toThrow();

    // 接続が失効し、A から見ても使えない
    expect(await a.grants.isRevoked(accountId), "再使用検知が別インスタンスに効いていない").toBe(
      true,
    );
  });

  it("同じ認可コードを2つのインスタンスで同時に使っても、成功は1回だけ", async () => {
    // Cloud Run では、同じコードの交換が別インスタンスに振り分けられうる。
    const { a, b } = buildInstances(`multi-${Date.now()}-3`);
    const code = "authorization-code-multi-3";

    await a.adapter("AuthorizationCode").upsert(code, { jti: code, kind: "AuthorizationCode" }, 60);

    const results = await Promise.allSettled([
      a.adapter("AuthorizationCode").consume(code),
      b.adapter("AuthorizationCode").consume(code),
    ]);

    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
  });

  it("TTL ポリシー用に Timestamp 型のフィールドを書く", async () => {
    // ⚠ Firestore の TTL ポリシーは**日時型のフィールドしか見ない**。
    // エポック秒の数値だけでは、ポリシーを設定しても文書が消えずに溜まる。
    const collection = `multi-${Date.now()}-5`;
    const { a } = buildInstances(collection);
    await a.storage.upsert("AccessToken", "ttl-key", {
      payload: {},
      expiresAt: 1_800_000_000,
      grantId: undefined,
      uidHash: undefined,
      userCodeHash: undefined,
    });

    // 保存層の抽象を通さず、生の文書を見る
    const raw = await new Firestore({ projectId: "kintone-remote-mcp-test" })
      .collection(collection)
      .doc("AccessToken|ttl-key")
      .get();

    const ttlAt = raw.data()?.ttlAt;
    expect(ttlAt, "TTL 用のフィールドが無い").toBeInstanceOf(Timestamp);
    expect((ttlAt as Timestamp).seconds).toBe(1_800_000_000);
    // 判定に使う数値も残っている（TTL は掃除であって認可判定ではない）
    expect(raw.data()?.expiresAt).toBe(1_800_000_000);
  });

  it("期限の無いレコードには TTL 用フィールドを書かない", async () => {
    // 接続 grant は切断するまで生きる。TTL で消えてはいけない。
    const collection = `multi-${Date.now()}-6`;
    const { a } = buildInstances(collection);
    await a.storage.upsert("ConnectionGrant", "no-ttl", {
      payload: {},
      expiresAt: undefined,
      grantId: undefined,
      uidHash: undefined,
      userCodeHash: undefined,
    });

    const raw = await new Firestore({ projectId: "kintone-remote-mcp-test" })
      .collection(collection)
      .doc("ConnectionGrant|no-ttl")
      .get();

    expect(raw.data()?.ttlAt, "期限が無いのに TTL が設定されている").toBeUndefined();
  });

  it("【既知の制約】トークン更新の単一飛行はインスタンスをまたがない", async () => {
    // これは直っていない、という事実をテストで固定する。
    // cybozu は同じリフレッシュトークンでの更新を許すので実害は小さいが、
    // リフレッシュトークンは1ユーザーあたり10個までなので無駄打ちは避けたい。
    // 厳密にやるなら共有ロックが要る (§7.2)。
    const { a, b } = buildInstances(`multi-${Date.now()}-4`);
    const accountId = "acct-multi-4";

    let refreshCalls = 0;
    const cybozu: CybozuOAuthClient = {
      buildAuthorizationUrl: () => "https://example.cybozu.com/oauth2/authorization",
      exchangeCode: async () => tokens,
      refresh: async () => {
        refreshCalls += 1;
        return { accessToken: "renewed", expiresAt: 20_000, scope: "s" };
      },
    };

    const now = () => 9_950; // 期限直前
    await a.grants.create(accountId, tokens);

    const providerA = createKintoneTokenProvider({ grants: a.grants, cybozu, revoker: a.revoker, now });
    const providerB = createKintoneTokenProvider({ grants: b.grants, cybozu, revoker: b.revoker, now });

    await Promise.all([providerA.getAccessToken(accountId), providerB.getAccessToken(accountId)]);

    expect(refreshCalls, "インスタンスをまたいで重複排除できている（想定外）").toBe(2);
  });
});

describe("複数インスタンスの検証", () => {
  it(
    emulatorHost
      ? "エミュレータで実証した"
      : "スキップ: FIRESTORE_EMULATOR_HOST が未設定のため「切断が全インスタンスに効く」は未実証",
    () => {
      expect(true).toBe(true);
    },
  );
});

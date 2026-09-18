import { randomBytes } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createSecretCipher } from "../../src/auth/crypto.js";
import { createAdapterFactory, TokenReuseError } from "../../src/auth/adapter.js";
import { MemoryStorage } from "../../src/auth/storage.js";
import { KNOWN_MODELS, specFor } from "../../src/auth/modelSpec.js";

/**
 * Adapter の契約テスト。
 *
 * ここは設計上いちばん危ないところ (§4.10)。外部レビューで前回・前々回と
 * 続けて指摘された箇所でもある:
 *
 *  - 不透明トークンの値は jti そのもので、文書 ID にも payload にも入る
 *  - consume の競合を「例外を投げる」だけで済ませると先行要求が生き残る
 *  - 全モデル共通の jti 除去では findByUid が成立しない
 *
 * 実装ではなく**性質**を固定する。
 */

const SESSION_JTI = "session-jti-secret-value";
const SESSION_UID = "session-uid-secret-value";

describe("トークンの保存", () => {
  let storage: MemoryStorage;
  let factory: ReturnType<typeof createAdapterFactory>;

  beforeEach(() => {
    storage = new MemoryStorage();
    factory = createAdapterFactory({ storage, cipher: createSecretCipher(randomBytes(32)) });
  });

  it("Bearer トークンの値が、文書 ID にも本文にも平文で残らない", async () => {
    const adapter = factory("AccessToken");
    const token = "opaque-access-token-value";

    await adapter.upsert(token, { jti: token, kind: "AccessToken", accountId: "acct" }, 3600);

    const dumped = JSON.stringify(storage.dump());
    expect(dumped).not.toContain(token);
  });

  it("find(id) で jti が復元される", async () => {
    // 落としたまま返すと、provider が別の jti を新規生成してしまう。
    const adapter = factory("AccessToken");
    const token = "opaque-access-token-value";

    await adapter.upsert(token, { jti: token, kind: "AccessToken" }, 3600);
    const found = await adapter.find(token);

    expect(found?.jti).toBe(token);
    expect(found?.kind).toBe("AccessToken");
  });

  it("別の鍵では復号できず「見つからない」になる", async () => {
    const adapter = factory("Session");
    await adapter.upsert(SESSION_JTI, { jti: SESSION_JTI, uid: SESSION_UID, kind: "Session" }, 3600);

    const otherFactory = createAdapterFactory({
      storage,
      cipher: createSecretCipher(randomBytes(32)),
    });
    // ハッシュも鍵付きなので、そもそもキーが一致しない
    expect(await otherFactory("Session").find(SESSION_JTI)).toBeUndefined();
  });

  it("暗号文を別レコードへ移し替えると復号に失敗する", async () => {
    // AAD にモデル名とキーを入れているので、持ち込みは検出できる。
    const adapter = factory("Session");
    await adapter.upsert(SESSION_JTI, { jti: SESSION_JTI, uid: SESSION_UID, kind: "Session" }, 3600);
    await adapter.upsert("other-jti", { jti: "other-jti", uid: "other-uid", kind: "Session" }, 3600);

    const [first, second] = storage.dump();
    expect(first && second).toBeTruthy();
    // 片方の暗号文をもう片方へ差し替える
    await storage.upsert("Session", second!.key, {
      payload: { ...second!.payload, jti: first!.payload.jti },
      expiresAt: second!.expiresAt,
      grantId: second!.grantId,
      uidHash: second!.uidHash,
      userCodeHash: second!.userCodeHash,
    });

    expect(await adapter.find("other-jti")).toBeUndefined();
  });
});

describe("Session の二次索引", () => {
  it("findByUid でも jti と uid が復元される", async () => {
    // find(id) と違い、索引経由では元の jti が手元に無い。
    // Session だけは jti を落とさず暗号化して保存している。
    const storage = new MemoryStorage();
    const adapter = createAdapterFactory({
      storage,
      cipher: createSecretCipher(randomBytes(32)),
    })("Session");

    await adapter.upsert(
      SESSION_JTI,
      { jti: SESSION_JTI, uid: SESSION_UID, kind: "Session", accountId: "acct" },
      3600,
    );

    const found = await adapter.findByUid(SESSION_UID);

    expect(found?.jti).toBe(SESSION_JTI);
    expect(found?.uid).toBe(SESSION_UID);
    expect(found?.accountId).toBe("acct");
  });

  it("uid も平文で保存されない", async () => {
    const storage = new MemoryStorage();
    const adapter = createAdapterFactory({
      storage,
      cipher: createSecretCipher(randomBytes(32)),
    })("Session");

    await adapter.upsert(SESSION_JTI, { jti: SESSION_JTI, uid: SESSION_UID, kind: "Session" }, 3600);

    expect(JSON.stringify(storage.dump())).not.toContain(SESSION_UID);
  });

  it("findByUid → 更新 → 削除 が一周する", async () => {
    const storage = new MemoryStorage();
    const adapter = createAdapterFactory({
      storage,
      cipher: createSecretCipher(randomBytes(32)),
    })("Session");

    await adapter.upsert(SESSION_JTI, { jti: SESSION_JTI, uid: SESSION_UID, kind: "Session" }, 3600);
    await adapter.upsert(
      SESSION_JTI,
      { jti: SESSION_JTI, uid: SESSION_UID, kind: "Session", accountId: "updated" },
      3600,
    );

    expect((await adapter.findByUid(SESSION_UID))?.accountId).toBe("updated");

    await adapter.destroy(SESSION_JTI);
    expect(await adapter.findByUid(SESSION_UID)).toBeUndefined();
  });
});

describe("Interaction のネストした秘密", () => {
  it("session.cookie（Session の生 jti）が平文で残らず、復元される", async () => {
    // interaction.js のコンストラクタが session.cookie に Session の jti を入れる。
    // トップレベルだけ見ていると取りこぼす。
    const storage = new MemoryStorage();
    const adapter = createAdapterFactory({
      storage,
      cipher: createSecretCipher(randomBytes(32)),
    })("Interaction");

    const uid = "interaction-uid";
    await adapter.upsert(
      uid,
      {
        jti: uid,
        kind: "Interaction",
        session: { accountId: "acct", uid: SESSION_UID, cookie: SESSION_JTI },
      },
      600,
    );

    expect(JSON.stringify(storage.dump())).not.toContain(SESSION_JTI);
    expect(JSON.stringify(storage.dump())).not.toContain(SESSION_UID);

    const found = await adapter.find(uid);
    expect((found?.session as Record<string, unknown>).cookie).toBe(SESSION_JTI);
    expect((found?.session as Record<string, unknown>).uid).toBe(SESSION_UID);
    expect(found?.jti).toBe(uid);
  });
});

describe("consume の競合", () => {
  const setup = () => {
    const storage = new MemoryStorage();
    const revoked: string[] = [];
    // 実運用では revocation.ts の一点集約に繋ぐ。
    // ここでは「grantId が渡ってくること」だけを固定する。
    const revokeByGrantId = vi.fn(async (grantId: string) => { revoked.push(grantId); });
    const factory = createAdapterFactory({
      storage,
      cipher: createSecretCipher(randomBytes(32)),
      revokeByGrantId,
    });
    return { storage, adapter: factory("RefreshToken"), grantAdapter: factory("Grant"), revokeByGrantId, revoked };
  };

  it("同じトークンの同時消費で、成功するのは片方だけ", async () => {
    const { adapter } = setup();
    const token = "refresh-token-value";
    await adapter.upsert(token, { jti: token, kind: "RefreshToken", grantId: "g1" }, 3600);

    const results = await Promise.allSettled([adapter.consume(token), adapter.consume(token)]);
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
  });

  it("再使用の検知が、失効処理に grantId を渡す", async () => {
    // provider の失効処理は「取得済みオブジェクトの consumed が真」のときしか走らない。
    // 競合で負けた側が投げるだけでは先行要求のトークンが生き残るので、
    // 接続そのものを失効させてから拒否する必要がある。
    const { adapter, revoked } = setup();
    const token = "refresh-token-value";
    await adapter.upsert(token, { jti: token, kind: "RefreshToken", grantId: "g1" }, 3600);

    await adapter.consume(token);
    await expect(adapter.consume(token)).rejects.toBeInstanceOf(TokenReuseError);

    expect(revoked, "失効処理が呼ばれていない").toEqual(["g1"]);
  });

  it("provider 側の失効 (revokeByGrantId) も失効処理につながる", async () => {
    // 逐次の再使用は consume() を通らず、provider が revokeByGrantId() を呼ぶ。
    // この経路を取りこぼすと kintone のトークンが生き残る。
    const { adapter, revoked } = setup();

    await adapter.revokeByGrantId("g2");

    expect(revoked).toEqual(["g2"]);
  });

  it("主体の解決を Grant 文書に依存しない", async () => {
    // provider の helpers/revoke.js は revokeByGrantId と Grant 削除を
    // Promise.all で並行実行する。Grant が先に消えても失効は走らねばならない。
    const { adapter, storage, revoked } = setup();

    // Grant 文書が存在しない状態で呼ぶ
    expect(await storage.find("Grant", "any")).toBeUndefined();
    await adapter.revokeByGrantId("g3");

    expect(revoked, "Grant が無いと失効が飛んでいる").toEqual(["g3"]);
  });

  it("消えたトークンの消費も再使用として扱う", async () => {
    const { adapter } = setup();

    await expect(adapter.consume("never-existed")).rejects.toBeInstanceOf(TokenReuseError);
  });

  it("再保存しても使用済みの印が消えない", async () => {
    // provider は同じレコードを再保存することがある。
    // そこで consumed が消えると、一度使ったコードがまた使えてしまう。
    const { adapter } = setup();
    const token = "refresh-token-value";
    await adapter.upsert(token, { jti: token, kind: "RefreshToken" }, 3600);
    await adapter.consume(token);

    await adapter.upsert(token, { jti: token, kind: "RefreshToken", extra: 1 }, 3600);

    expect((await adapter.find(token))?.consumed).toBeDefined();
    await expect(adapter.consume(token)).rejects.toBeInstanceOf(TokenReuseError);
  });
});

describe("失効した接続への発行", () => {
  it("失効した接続に対しては新しいトークンを保存しない", async () => {
    // 失効処理とトークン発行が競合したとき、失効の後にトークンが作られると
    // 接続が実質的に復活する。upsert の時点で止める。
    const storage = new MemoryStorage();
    const revokedAccounts = new Set(["acct-revoked"]);
    const adapter = createAdapterFactory({
      storage,
      cipher: createSecretCipher(randomBytes(32)),
      isConnectionRevoked: async (accountId) => revokedAccounts.has(accountId),
    })("AccessToken");

    await expect(
      adapter.upsert("t1", { jti: "t1", kind: "AccessToken", accountId: "acct-revoked" }, 3600),
    ).rejects.toThrow();

    expect(await adapter.find("t1")).toBeUndefined();
  });

  it("保存済みのトークンでも、接続が失効していれば見つからない", async () => {
    // ⚠ 保存時の確認だけでは隙間が残る。
    // 「失効を確認した直後に切断され、そのあと保存される」順序があるため、
    // **使うときにも照合する**必要がある。
    // ここでは保存が済んだ後に失効させ、利用時の照合だけを試す。
    const storage = new MemoryStorage();
    const revokedAccounts = new Set<string>();
    const adapter = createAdapterFactory({
      storage,
      cipher: createSecretCipher(randomBytes(32)),
      isConnectionRevoked: async (accountId) => revokedAccounts.has(accountId),
    })("AccessToken");

    await adapter.upsert("t3", { jti: "t3", kind: "AccessToken", accountId: "acct-x" }, 3600);
    expect(await adapter.find("t3")).toBeDefined();

    // 保存の後で失効させる（レコードはまだ保存層に残っている）
    revokedAccounts.add("acct-x");

    expect(await storage.find("AccessToken", (await storage.dump())[0]!.key)).toBeDefined();
    expect(await adapter.find("t3"), "失効後も利用できてしまう").toBeUndefined();
  });

  it("生きている接続には保存できる", async () => {
    const storage = new MemoryStorage();
    const adapter = createAdapterFactory({
      storage,
      cipher: createSecretCipher(randomBytes(32)),
      isConnectionRevoked: async () => false,
    })("AccessToken");

    await adapter.upsert("t2", { jti: "t2", kind: "AccessToken", accountId: "acct-live" }, 3600);

    expect(await adapter.find("t2")).toBeDefined();
  });
});

describe("grantId による失効", () => {
  it("同じ grant のレコードがまとめて消える", async () => {
    const storage = new MemoryStorage();
    const factory = createAdapterFactory({
      storage,
      cipher: createSecretCipher(randomBytes(32)),
    });
    const access = factory("AccessToken");
    const refresh = factory("RefreshToken");

    await access.upsert("a1", { jti: "a1", kind: "AccessToken", grantId: "g1" }, 3600);
    await refresh.upsert("r1", { jti: "r1", kind: "RefreshToken", grantId: "g1" }, 3600);
    await access.upsert("a2", { jti: "a2", kind: "AccessToken", grantId: "g2" }, 3600);

    await access.revokeByGrantId("g1");

    expect(await access.find("a1")).toBeUndefined();
    expect(await refresh.find("r1")).toBeUndefined();
    expect(await access.find("a2")).toBeDefined();
  });
});

describe("モデル規則", () => {
  it("未知のモデルは安全側（jti を暗号化し、索引も張る）に倒す", () => {
    const spec = specFor("SomeNewModelUpstreamAdded");
    expect(spec.restoreJtiFromKey).toBe(false);
    expect(spec.secretFields).toContainEqual({ kind: "top", field: "jti" });
  });

  it("規則を持つモデルに Session と Interaction が含まれる", () => {
    expect(KNOWN_MODELS).toContain("Session");
    expect(KNOWN_MODELS).toContain("Interaction");
    expect(KNOWN_MODELS).toContain("AccessToken");
  });
});

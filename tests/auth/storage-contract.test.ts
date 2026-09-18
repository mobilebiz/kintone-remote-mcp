import { Firestore } from "@google-cloud/firestore";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { FirestoreStorage } from "../../src/auth/firestoreStorage.js";
import { MemoryStorage, type Storage, type UpsertInput } from "../../src/auth/storage.js";

/**
 * 保存層の契約テスト。
 *
 * **同じテストを MemoryStorage と FirestoreStorage の両方に流す。**
 * 片方だけで確かめても意味が無い — 本番は Firestore で動くのに、
 * 検証はメモリ実装でしか行っていない、という状態を避ける。
 *
 * Firestore はエミュレータに繋ぐ。`FIRESTORE_EMULATOR_HOST` が無い環境では
 * その組だけ飛ばす（**黙って飛ばさず、飛ばしたことが出力に残る**）。
 *
 * ```sh
 * gcloud emulators firestore start --host-port=127.0.0.1:8080
 * FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 npx vitest --run
 * ```
 */

const emulatorHost = process.env.FIRESTORE_EMULATOR_HOST;

const input = (overrides: Partial<UpsertInput> = {}): UpsertInput => ({
  payload: { hello: "world" },
  expiresAt: undefined,
  grantId: undefined,
  uidHash: undefined,
  userCodeHash: undefined,
  ...overrides,
});

const firestoreClients: Firestore[] = [];

/** 実装ごとにまっさらな Storage を作る */
type Factory = { name: string; create: () => Promise<Storage> };

const factories: Factory[] = [
  { name: "MemoryStorage", create: async () => new MemoryStorage() },
];

if (emulatorHost) {
  let counter = 0;
  factories.push({
    name: "FirestoreStorage (エミュレータ)",
    create: async () => {
      const firestore = new Firestore({ projectId: "kintone-remote-mcp-test" });
      firestoreClients.push(firestore);
      counter += 1;
      // テストごとにコレクションを分ける（前のテストの残骸を持ち込まない）
      return new FirestoreStorage({ firestore, collection: `oidc-test-${Date.now()}-${counter}` });
    },
  });
}

afterAll(async () => {
  await Promise.all(firestoreClients.map((client) => client.terminate()));
});

describe.each(factories)("保存層の契約: $name", ({ create }) => {
  let storage: Storage;

  beforeEach(async () => {
    storage = await create();
  });

  it("保存したものを取り出せる", async () => {
    await storage.upsert("AccessToken", "k1", input({ payload: { a: 1 } }));

    const found = await storage.find("AccessToken", "k1");

    expect(found?.payload).toEqual({ a: 1 });
    expect(found?.key).toBe("k1");
  });

  it("モデルが違えば別のレコードになる", async () => {
    await storage.upsert("AccessToken", "same-key", input({ payload: { which: "access" } }));
    await storage.upsert("RefreshToken", "same-key", input({ payload: { which: "refresh" } }));

    expect((await storage.find("AccessToken", "same-key"))?.payload).toEqual({ which: "access" });
    expect((await storage.find("RefreshToken", "same-key"))?.payload).toEqual({ which: "refresh" });
  });

  it("モデル名と key の境界が混ざらない", async () => {
    // 区切り文字を `__` にしていたとき、この2つが同じ文書 ID になった。
    // key は base64url なので `_` を含みうる。
    await storage.upsert("Access", "Token__k1", input({ payload: { which: "A" } }));
    await storage.upsert("Access__Token", "k1", input({ payload: { which: "B" } }));

    expect((await storage.find("Access", "Token__k1"))?.payload).toEqual({ which: "A" });
    expect((await storage.find("Access__Token", "k1"))?.payload).toEqual({ which: "B" });
  });

  it("payload に undefined が混ざっても落ちず、両実装で同じになる", async () => {
    // Firestore は undefined を保存できない。浅く落とすだけでは
    // payload の中の undefined で落ち、メモリ実装とだけ挙動が割れる。
    await storage.upsert(
      "AccessToken",
      "k-undef",
      input({ payload: { kept: 1, dropped: undefined, nested: { a: undefined, b: 2 } } }),
    );

    expect((await storage.find("AccessToken", "k-undef"))?.payload).toEqual({
      kept: 1,
      nested: { b: 2 },
    });
  });

  it("無いものは undefined", async () => {
    expect(await storage.find("AccessToken", "missing")).toBeUndefined();
  });

  it("消したら見つからない", async () => {
    await storage.upsert("AccessToken", "k1", input());
    await storage.destroy("AccessToken", "k1");

    expect(await storage.find("AccessToken", "k1")).toBeUndefined();
  });

  it("二次索引で引ける", async () => {
    await storage.upsert("Session", "k1", input({ uidHash: "uid-hash" }));

    const found = await storage.findByIndex("Session", "uidHash", "uid-hash");

    expect(found?.key, "索引から引いたときに key が戻らない").toBe("k1");
  });

  it("二次索引はモデルをまたがない", async () => {
    await storage.upsert("Session", "k1", input({ uidHash: "shared" }));

    expect(await storage.findByIndex("Interaction", "uidHash", "shared")).toBeUndefined();
  });

  describe("consume の原子性", () => {
    it("未使用なら consumed", async () => {
      await storage.upsert("AuthorizationCode", "c1", input());

      expect(await storage.consume("AuthorizationCode", "c1", 100)).toBe("consumed");
    });

    it("2回目は already-consumed", async () => {
      await storage.upsert("AuthorizationCode", "c1", input());
      await storage.consume("AuthorizationCode", "c1", 100);

      expect(await storage.consume("AuthorizationCode", "c1", 200)).toBe("already-consumed");
    });

    it("無いものは not-found", async () => {
      expect(await storage.consume("AuthorizationCode", "missing", 100)).toBe("not-found");
    });

    it("同時に消費しても成功は1回だけ", async () => {
      // ここが崩れると、同じ認可コードで2回トークンが出る。
      await storage.upsert("AuthorizationCode", "c1", input());

      const results = await Promise.all([
        storage.consume("AuthorizationCode", "c1", 100),
        storage.consume("AuthorizationCode", "c1", 100),
        storage.consume("AuthorizationCode", "c1", 100),
      ]);

      expect(results.filter((r) => r === "consumed")).toHaveLength(1);
    });

    it("再保存しても使用済みの印が消えない", async () => {
      // provider は同じレコードを再保存する。ここで consumed が消えると、
      // 一度使ったコードがまた使えてしまう。
      await storage.upsert("RefreshToken", "r1", input());
      await storage.consume("RefreshToken", "r1", 100);

      await storage.upsert("RefreshToken", "r1", input({ payload: { updated: true } }));

      expect((await storage.find("RefreshToken", "r1"))?.consumedAt).toBe(100);
      expect(await storage.consume("RefreshToken", "r1", 200)).toBe("already-consumed");
    });
  });

  describe("update の原子性", () => {
    it("mutator の戻り値で置き換わる", async () => {
      await storage.upsert("ConnectionGrant", "g1", input({ payload: { revoked: false } }));

      const result = await storage.update("ConnectionGrant", "g1", (current) => ({
        ...input({ payload: { ...current?.payload, extra: 1 } }),
      }));

      expect(result).toBe("updated");
      expect((await storage.find("ConnectionGrant", "g1"))?.payload).toEqual({
        revoked: false,
        extra: 1,
      });
    });

    it("abort すると書き込まれない", async () => {
      await storage.upsert("ConnectionGrant", "g1", input({ payload: { revoked: true } }));

      const result = await storage.update("ConnectionGrant", "g1", (current) =>
        current?.payload.revoked === true ? "abort" : input(),
      );

      expect(result).toBe("aborted");
      expect((await storage.find("ConnectionGrant", "g1"))?.payload).toEqual({ revoked: true });
    });

    it("存在しないレコードには undefined が渡る", async () => {
      let seen: unknown = "not called";
      await storage.update("ConnectionGrant", "missing", (current) => {
        seen = current;
        return input();
      });

      expect(seen).toBeUndefined();
    });

    it("失効と保存が競合しても、失効が取り消されない", async () => {
      // 「確認 → 保存」を別操作にしていたとき、この順序で失効が消えていた。
      await storage.upsert("ConnectionGrant", "g1", input({ payload: { revoked: false } }));

      await Promise.all([
        // 失効させる
        storage.update("ConnectionGrant", "g1", () => input({ payload: { revoked: true } })),
        // 同時に「失効していなければ書く」
        storage.update("ConnectionGrant", "g1", (current) =>
          current?.payload.revoked === true ? "abort" : input({ payload: { revoked: false } }),
        ),
      ]);

      // どちらの順序でも、最終状態が revoked:false になってはいけない
      const final = await storage.find("ConnectionGrant", "g1");
      expect(final?.payload.revoked, "失効が取り消されている").toBe(true);
    });
  });

  describe("grantId による一括失効", () => {
    it("300件を超えても残らず消える", async () => {
      // バッチの上限を超える件数でも、失効は取りこぼしてはいけない。
      const count = 320;
      for (let i = 0; i < count; i += 1) {
        await storage.upsert("AccessToken", `bulk-${i}`, input({ grantId: "g-bulk" }));
      }

      await storage.revokeByGrantId("g-bulk");

      expect(await storage.find("AccessToken", "bulk-0")).toBeUndefined();
      expect(await storage.find("AccessToken", `bulk-${count - 1}`)).toBeUndefined();
    }, 30_000);


    it("同じ grant のレコードがまとめて消える", async () => {
      await storage.upsert("AccessToken", "a1", input({ grantId: "g1" }));
      await storage.upsert("RefreshToken", "r1", input({ grantId: "g1" }));
      await storage.upsert("AccessToken", "a2", input({ grantId: "g2" }));

      await storage.revokeByGrantId("g1");

      expect(await storage.find("AccessToken", "a1")).toBeUndefined();
      expect(await storage.find("RefreshToken", "r1")).toBeUndefined();
      expect(await storage.find("AccessToken", "a2")).toBeDefined();
    });

    it("grantId を持たないレコードは巻き込まれない", async () => {
      // GrantOwner の対応表はここで消えてはいけない (§4.10)。
      await storage.upsert("GrantOwner", "o1", input({ payload: { accountId: "acct" } }));
      await storage.upsert("AccessToken", "a1", input({ grantId: "g1" }));

      await storage.revokeByGrantId("g1");

      expect(await storage.find("GrantOwner", "o1"), "対応表まで消えている").toBeDefined();
    });
  });
});

describe("Firestore の検証", () => {
  it(
    emulatorHost
      ? "エミュレータに接続して契約テストを実行した"
      : "スキップ: FIRESTORE_EMULATOR_HOST が未設定のため Firestore の検証は行っていない",
    () => {
      // 「メモリ実装でしか確かめていない」状態を、通過した風に見せないための印。
      expect(factories.map((f) => f.name)).toContain("MemoryStorage");
      if (emulatorHost) {
        expect(factories.map((f) => f.name)).toContain("FirestoreStorage (エミュレータ)");
      }
    },
  );
});

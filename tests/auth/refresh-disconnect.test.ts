import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import {
  createConnectionGrantStore,
  LEGACY_CONNECTION_EXPIRES_AT,
} from "../../src/auth/connectionGrant.js";
import { createSecretCipher } from "../../src/auth/crypto.js";
import { CybozuOAuthError, type CybozuOAuthClient } from "../../src/auth/cybozuOAuth.js";
import {
  createKintoneTokenProvider,
  KintoneAuthRequiredError,
} from "../../src/auth/kintoneToken.js";
import { createRevoker } from "../../src/auth/revocation.js";
import { MemoryStorage } from "../../src/auth/storage.js";

/**
 * kintone トークンの更新と、接続の切断。
 *
 * cybozu のアクセストークンは1時間で切れる。Claude 側のトークンとは寿命が違うので、
 * 「Claude のトークンは有効なのに kintone を叩けない」状態が普通に起きる。
 */

const ACCOUNT = "acct-1";

const initialTokens = {
  accessToken: "access-1",
  refreshToken: "refresh-1",
  expiresAt: 10_000,
  scope: "k:app_record:read",
};

/**
 * 保存層のキーを得る。
 *
 * `revoker` は `cipher.hash(grantId)` をキーに Grant 文書を消すので、
 * テスト側でも同じ計算をしないと「置いたつもりのレコード」が別の場所に行く。
 */
const cipherKeyOf = (storage: MemoryStorage, grantId: string): string => {
  void storage;
  return sharedCipher.hash(grantId);
};

let sharedCipher: ReturnType<typeof createSecretCipher>;

const setup = (overrides: Partial<CybozuOAuthClient> = {}, now = () => 5_000) => {
  const storage = new MemoryStorage();
  const cipher = createSecretCipher(randomBytes(32));
  sharedCipher = cipher;
  const grants = createConnectionGrantStore({ storage, cipher, now });

  const cybozu: CybozuOAuthClient = {
    buildAuthorizationUrl: () => "https://example.cybozu.com/oauth2/authorization",
    exchangeCode: async () => initialTokens,
    refresh: async () => ({ accessToken: "access-2", expiresAt: 20_000, scope: "s" }),
    ...overrides,
  };

  const revoker = createRevoker({ storage, cipher, grants });

  const refreshes: Array<{ accountId: string; outcome: string }> = [];
  const provider = createKintoneTokenProvider({
    grants,
    cybozu,
    revoker,
    now,
    onRefresh: (info) => refreshes.push(info),
  });

  return { storage, grants, cybozu, provider, refreshes, revoker };
};

describe("失効の一点集約", () => {
  it("切断が途中で失敗しても、再試行で続きを行える", async () => {
    // revoke() が providerGrantId を消してしまうと、再試行で対象を見失い、
    // provider 側のトークンが残り続ける。
    const { grants, revoker, storage } = setup();
    await grants.create(ACCOUNT, initialTokens);
    await grants.attachProviderGrant(ACCOUNT, "grant-1");
    await revoker.rememberGrantOwner("grant-1", ACCOUNT);

    // 実際に消えるべきレコードを置く。
    // これが無いと「失効済みなら即 return」に変えても気づけない。
    await storage.upsert("AccessToken", "at-1", {
      payload: { kind: "AccessToken" },
      expiresAt: undefined,
      grantId: "grant-1",
      uidHash: undefined,
      userCodeHash: undefined,
    });
    await storage.upsert("Grant", cipherKeyOf(storage, "grant-1"), {
      payload: { kind: "Grant" },
      expiresAt: undefined,
      grantId: undefined,
      uidHash: undefined,
      userCodeHash: undefined,
    });

    // 1回目: 系列トークンの削除で失敗させる
    const original = storage.revokeByGrantId.bind(storage);
    storage.revokeByGrantId = async () => {
      throw new Error("一時障害");
    };
    await expect(revoker.revokeConnection(ACCOUNT, "disconnect")).rejects.toThrow();

    // 接続の失効自体は済んでいる
    expect(await grants.isRevoked(ACCOUNT)).toBe(true);
    // **対象の Grant を見失っていない**
    expect(await grants.providerGrantId(ACCOUNT)).toBe("grant-1");
    // まだ消えていない
    expect(storage.dump().some((d) => d.grantId === "grant-1")).toBe(true);

    // 2回目: 復旧後に再試行して、**実際に消えること**
    storage.revokeByGrantId = original;
    await revoker.revokeConnection(ACCOUNT, "disconnect");

    expect(
      storage.dump().some((d) => d.grantId === "grant-1"),
      "再試行しても系列トークンが残っている",
    ).toBe(false);
  });

  it("Grant が消えていても grantId から主体を引ける", async () => {
    // provider の helpers/revoke.js は revokeByGrantId と Grant 削除を
    // Promise.all で並行実行する。Grant が先に消えても失効は走らねばならない。
    const { grants, revoker, storage } = setup();
    await grants.create(ACCOUNT, initialTokens);
    await revoker.rememberGrantOwner("grant-2", ACCOUNT);

    // Grant 文書は存在しない
    expect(await storage.find("Grant", "whatever")).toBeUndefined();

    await revoker.revokeByGrantId("grant-2", "token-reuse");

    expect(await grants.isRevoked(ACCOUNT), "Grant が無いと失効が飛んでいる").toBe(true);
  });

  it("上流の失効が provider 側のトークンまで届く", async () => {
    // grants.revoke() だけだと provider の Grant と AT が残り、
    // しかも対応が失われて後から回収できなくなる。
    const { grants, provider, revoker, storage } = setup(
      {
        refresh: async () => {
          throw new CybozuOAuthError("失効", 400, "invalid_grant");
        },
      },
      () => 9_950,
    );
    await grants.create(ACCOUNT, initialTokens);
    await grants.attachProviderGrant(ACCOUNT, "grant-3");
    await revoker.rememberGrantOwner("grant-3", ACCOUNT);
    await storage.upsert("AccessToken", "at-key", {
      payload: { kind: "AccessToken" },
      expiresAt: undefined,
      grantId: "grant-3",
      uidHash: undefined,
      userCodeHash: undefined,
    });

    await expect(provider.getAccessToken(ACCOUNT)).rejects.toBeInstanceOf(
      KintoneAuthRequiredError,
    );

    expect(
      storage.dump().some((d) => d.grantId === "grant-3"),
      "provider 側のトークンが残っている",
    ).toBe(false);
  });
});

describe("kintone アクセストークンの更新", () => {
  it("期限に余裕があれば更新しない", async () => {
    const refresh = vi.fn();
    const { grants, provider } = setup({ refresh: refresh as never });
    await grants.create(ACCOUNT, initialTokens);

    expect(await provider.getAccessToken(ACCOUNT)).toBe("access-1");
    expect(refresh).not.toHaveBeenCalled();
  });

  it("期限が近づいたら先回りして更新する", async () => {
    // 期限ちょうどまで待つと、その瞬間の呼び出しが失敗する。
    const { grants, provider } = setup({}, () => 9_950);
    await grants.create(ACCOUNT, initialTokens);

    expect(await provider.getAccessToken(ACCOUNT)).toBe("access-2");
  });

  it("更新してもリフレッシュトークンは変わらない", async () => {
    // cybozu の応答に refresh_token は含まれない。既存の値を保持し続ける (§4.9)。
    const { grants, provider } = setup({}, () => 9_950);
    await grants.create(ACCOUNT, initialTokens);

    await provider.getAccessToken(ACCOUNT);

    expect((await grants.load(ACCOUNT))?.refreshToken).toBe("refresh-1");
  });

  it("同時に呼ばれても cybozu への更新は1回だけ", async () => {
    // リフレッシュトークンは1ユーザーあたり10個までなので、無駄打ちを避ける。
    const refresh = vi.fn(async () => ({
      accessToken: "access-2",
      expiresAt: 20_000,
      scope: "s",
    }));
    const { grants, provider } = setup({ refresh }, () => 9_950);
    await grants.create(ACCOUNT, initialTokens);

    const results = await Promise.all([
      provider.getAccessToken(ACCOUNT),
      provider.getAccessToken(ACCOUNT),
      provider.getAccessToken(ACCOUNT),
    ]);

    expect(results).toEqual(["access-2", "access-2", "access-2"]);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("リフレッシュトークンが死んでいたら接続を失効させて再認可へ", async () => {
    const refresh = async () => {
      throw new CybozuOAuthError("失敗", 400, "invalid_grant");
    };
    const { grants, provider, refreshes } = setup({ refresh }, () => 9_950);
    await grants.create(ACCOUNT, initialTokens);

    await expect(provider.getAccessToken(ACCOUNT)).rejects.toBeInstanceOf(
      KintoneAuthRequiredError,
    );

    // 放置すると毎回ここで失敗し続けるので、接続そのものを畳む
    expect(await grants.isRevoked(ACCOUNT)).toBe(true);
    expect(refreshes).toEqual([{ accountId: ACCOUNT, outcome: "reauth-required" }]);
  });

  it("一時的な障害では接続を失効させない", async () => {
    // ここで失効させると、cybozu が一時的に落ちただけで全接続が切れる。
    const refresh = async () => {
      throw new CybozuOAuthError("一時障害", 503, undefined);
    };
    const { grants, provider } = setup({ refresh }, () => 9_950);
    await grants.create(ACCOUNT, initialTokens);

    await expect(provider.getAccessToken(ACCOUNT)).rejects.toBeInstanceOf(CybozuOAuthError);
    expect(await grants.isRevoked(ACCOUNT)).toBe(false);
  });

  it("失効済みの接続は再認可を要求する", async () => {
    const { grants, provider } = setup();
    await grants.create(ACCOUNT, initialTokens);
    await grants.revoke(ACCOUNT);

    await expect(provider.getAccessToken(ACCOUNT)).rejects.toBeInstanceOf(
      KintoneAuthRequiredError,
    );
  });

  it("更新中に切断されたら再認可へ", async () => {
    // 更新と切断の競合。切断が勝つのが正しい。
    const { grants, provider } = setup(
      {
        refresh: async () => {
          await grants.revoke(ACCOUNT);
          return { accessToken: "access-2", expiresAt: 20_000, scope: "s" };
        },
      },
      () => 9_950,
    );
    await grants.create(ACCOUNT, initialTokens);

    await expect(provider.getAccessToken(ACCOUNT)).rejects.toBeInstanceOf(
      KintoneAuthRequiredError,
    );
    expect(await grants.isRevoked(ACCOUNT)).toBe(true);
  });
});

describe("諦めた要求のために更新しない", () => {
  /**
   * ⚠ **`getAccessToken()` に入る前の判定だけでは足りない。**
   * 中で保存層を読むので、入った時点では生きていても、
   * cybozu を呼ぶ直前には締め切りを過ぎていることがある。
   *
   * リフレッシュトークンは**1ユーザーあたり10個まで**なので、
   * 受け取る相手がいない更新は打ちたくない。
   */

  /** 期限切れの grant を置く。`now=5000`、skew=120 なので 5000 より前なら更新が走る */
  const expiredTokens = { ...initialTokens, expiresAt: 4_000 };

  it("待っている相手が1人もいなければ、cybozu を呼ばない", async () => {
    const refresh = vi.fn(async () => ({ accessToken: "access-2", expiresAt: 20_000, scope: "s" }));
    const { grants, provider } = setup({ refresh });
    await grants.create(ACCOUNT, expiredTokens);

    let abandoned = false;
    const pending = provider.getAccessToken(ACCOUNT, { isAbandoned: () => abandoned });
    // 保存層の読み込みを待っている間に締め切りが来る
    abandoned = true;

    await expect(pending).rejects.toThrowError(/打ち切/);
    expect(refresh, "受け取る相手がいないのに cybozu を呼んでいる").not.toHaveBeenCalled();
  });

  it("他が待っていれば、始めた側が諦めても更新する", async () => {
    // ⚠ **更新は共有されている。** 始めた側の都合で止めると、
    // **同じ接続の別の要求まで巻き添えになる**
    const refresh = vi.fn(async () => ({ accessToken: "access-2", expiresAt: 20_000, scope: "s" }));
    const { grants, provider } = setup({ refresh });
    await grants.create(ACCOUNT, expiredTokens);

    let firstAbandoned = false;
    const first = provider.getAccessToken(ACCOUNT, { isAbandoned: () => firstAbandoned });
    // 同じ更新を待つ、生きている要求
    const second = provider.getAccessToken(ACCOUNT, { isAbandoned: () => false });

    firstAbandoned = true;

    await expect(second, "生きている要求まで巻き添えにしている").resolves.toBe("access-2");
    await expect(first).resolves.toBe("access-2");
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("諦めていなければ、これまでどおり更新する", async () => {
    const refresh = vi.fn(async () => ({ accessToken: "access-2", expiresAt: 20_000, scope: "s" }));
    const { grants, provider } = setup({ refresh });
    await grants.create(ACCOUNT, expiredTokens);

    await expect(provider.getAccessToken(ACCOUNT)).resolves.toBe("access-2");
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("期限内なら、諦めていても保存済みのトークンを返す", async () => {
    // 更新が要らないなら、打ち切る理由も無い（cybozu を呼ばないので）
    const refresh = vi.fn();
    const { grants, provider } = setup({ refresh: refresh as never });
    await grants.create(ACCOUNT, initialTokens);

    await expect(
      provider.getAccessToken(ACCOUNT, { isAbandoned: () => true }),
    ).resolves.toBe("access-1");
    expect(refresh).not.toHaveBeenCalled();
  });
});

describe("接続の状態を読む（inspect）", () => {
  /**
   * ⚠ **エンドポイント越しには確かめられない。**
   * 失効を見落としても、後続のトークン読み出しが `undefined` を返して
   * 同じ 401 になる。**どちらの理由で止まったかが応答から区別できない**ので、
   * 判定を消しても全件通る（変異検査で確認）。
   *
   * 保存層を直接見る。ここが最後の砦。
   */
  it("失効していない接続は revoked=false", async () => {
    const { grants } = setup();
    await grants.create(ACCOUNT, initialTokens);

    expect(await grants.inspect(ACCOUNT)).toEqual({
      revoked: false,
      integrationConsent: undefined,
      consentedTools: undefined,
      consentedAppIds: undefined,
      // 期限の記録が無いものは、移行時点で作られたものとみなす
      expiresAt: LEGACY_CONNECTION_EXPIRES_AT,
    });
  });

  it("失効した接続は revoked=true", async () => {
    const { grants, revoker } = setup();
    await grants.create(ACCOUNT, initialTokens);
    await revoker.revokeConnection(ACCOUNT, "disconnect");

    expect((await grants.inspect(ACCOUNT)).revoked, "失効を見落としている").toBe(true);
  });

  it("同意した連携ユーザーを読み出せる", async () => {
    const { grants } = setup();
    await grants.create(ACCOUNT, initialTokens, {
      integrationUser: { username: "kintone-integration" },
    });

    expect((await grants.inspect(ACCOUNT)).integrationConsent).toEqual({
      username: "kintone-integration",
    });
  });

  it("同意していない接続は undefined", async () => {
    // 機能を入れる前に作られた接続。設定を変えただけで権限が広がってはいけない
    const { grants } = setup();
    await grants.create(ACCOUNT, initialTokens);

    expect((await grants.inspect(ACCOUNT)).integrationConsent).toBeUndefined();
  });

  it("接続が無ければ、同意も無い", async () => {
    const { grants } = setup();

    expect(await grants.inspect("never-connected")).toEqual({
      revoked: false,
      integrationConsent: undefined,
    });
  });

  it("失効した接続は、同意していたことにならない", async () => {
    // ⚠ 失効時に残すのは**失効の印だけ**（`revoke` は他を消す）。
    // 切断した接続の同意が残り続けると、繋ぎ直さずに使える余地ができる。
    // 「何に同意していたか」は監査ログ側に残す
    const { grants, revoker } = setup();
    await grants.create(ACCOUNT, initialTokens, {
      integrationUser: { username: "kintone-integration" },
    });
    await revoker.revokeConnection(ACCOUNT, "disconnect");

    const state = await grants.inspect(ACCOUNT);

    expect(state.revoked).toBe(true);
    expect(state.integrationConsent, "失効後も同意が残っている").toBeUndefined();
  });
});

describe("接続の絶対期限", () => {
  /**
   * ⚠ **provider の Grant に期限を付けただけでは足りない。**
   *
   * Grant が切れても、こちらに保管した **cybozu のリフレッシュトークンは
   * 復号できるまま**で、接続も失効しなかった（外部レビューで再現された）。
   * 「使われなくなった接続を永遠に残さない」目的を果たせていない。
   */
  const expiredTokens = { ...initialTokens };

  it("期限が来たら、資格情報を読み出せない", async () => {
    let clock = 10_000;
    const storage = new MemoryStorage();
    const cipher = createSecretCipher(randomBytes(32));
    const grants = createConnectionGrantStore({ storage, cipher, now: () => clock });
    await grants.create(ACCOUNT, expiredTokens, { expiresAt: 20_000 });

    // 期限内なら読める
    expect(await grants.load(ACCOUNT)).toBeDefined();

    clock = 20_001;

    expect(await grants.load(ACCOUNT), "期限切れでも資格情報が読める").toBeUndefined();
  });

  it("期限が来たら、失効として扱う", async () => {
    // ⚠ **TTL による削除を待たない。** 消えていなくても、
    // 使うときに自分で期限を見る (§4.9)
    let clock = 10_000;
    const storage = new MemoryStorage();
    const cipher = createSecretCipher(randomBytes(32));
    const grants = createConnectionGrantStore({ storage, cipher, now: () => clock });
    await grants.create(ACCOUNT, expiredTokens, { expiresAt: 20_000 });

    expect((await grants.inspect(ACCOUNT)).revoked).toBe(false);

    clock = 20_001;

    expect((await grants.inspect(ACCOUNT)).revoked, "期限切れが失効として扱われない").toBe(true);
  });

  it("保存層の TTL にも期限が載る（自動で消える）", async () => {
    const storage = new MemoryStorage();
    const cipher = createSecretCipher(randomBytes(32));
    const grants = createConnectionGrantStore({ storage, cipher, now: () => 10_000 });
    await grants.create(ACCOUNT, expiredTokens, { expiresAt: 20_000 });

    // 掃除を別に作らなくて済むように、保存層の期限として持たせる
    expect((await grants.inspect(ACCOUNT)).expiresAt).toBe(20_000);
  });

  /**
   * ⚠ **期限を足しただけでは、既にある接続に届かない。**
   *
   * 期限が付くのは、これ以降に作られた接続だけ。記録の無いレコードを置いて
   * 時計を401日進めても、**資格情報を復号でき、失効もしなかった**
   * （外部レビューで再現された）。
   */
  const withoutRecordedExpiry = async (clock: () => number) => {
    const storage = new MemoryStorage();
    const cipher = createSecretCipher(randomBytes(32));
    const grants = createConnectionGrantStore({ storage, cipher, now: clock });
    // 期限を渡さない = 機能を入れる前に作られた形
    await grants.create(ACCOUNT, expiredTokens);
    return grants;
  };

  it("期限の記録が無い接続も、いつかは切れる", async () => {
    let clock = 10_000;
    const grants = await withoutRecordedExpiry(() => clock);

    expect(await grants.load(ACCOUNT), "移行前の接続が最初から読めない").toBeDefined();

    clock = LEGACY_CONNECTION_EXPIRES_AT + 1;

    expect(
      await grants.load(ACCOUNT),
      "記録の無い接続の資格情報が、いつまでも読める",
    ).toBeUndefined();
    expect((await grants.inspect(ACCOUNT)).revoked, "記録の無い接続が失効しない").toBe(true);
  });

  it("期限の記録が無い接続の期限は、移行時点から数える", async () => {
    const grants = await withoutRecordedExpiry(() => 10_000);

    // いつ作られたかの記録は無い。移行より前であることだけは確かなので、
    // 移行時点で作られたものとみなす
    expect((await grants.inspect(ACCOUNT)).expiresAt).toBe(LEGACY_CONNECTION_EXPIRES_AT);
  });

  it("移行時点の期限は、400日ぶんに収まっている", () => {
    // ⚠ 値を書き換えて「実質無期限」にできないようにする。
    // 2026-09-17（移行日）+ 400日
    expect(LEGACY_CONNECTION_EXPIRES_AT).toBe(Math.floor(Date.UTC(2027, 9, 22) / 1000));
  });
});

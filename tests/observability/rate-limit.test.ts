import { describe, expect, it } from "vitest";

import {
  createConcurrencyLimiter,
  createRateLimiter,
} from "../../src/observability/rateLimit.js";

/**
 * 流量制限 (§7.2)。
 *
 * これは**インスタンス単位でしか効かない**。実効的な上限は
 * 制限値 × インスタンス数で、再起動でも枠が戻る。
 * 「上限」ではなく「目安」であることを前提に、性質だけを固定する。
 */

describe("固定窓の流量制限", () => {
  const setup = (limit = 3, windowSeconds = 60) => {
    let clock = 1000;
    const limiter = createRateLimiter({ limit, windowSeconds, now: () => clock });
    return { limiter, advance: (seconds: number) => (clock += seconds) };
  };

  it("上限まで通し、超えたら止める", () => {
    const { limiter } = setup(3);

    expect(limiter.check("a").allowed).toBe(true);
    expect(limiter.check("a").allowed).toBe(true);
    expect(limiter.check("a").allowed).toBe(true);
    expect(limiter.check("a").allowed).toBe(false);
  });

  it("止めたときは待ち時間と上限を返す", () => {
    // 止めた理由が分からないと、詰まりの調査ができない。
    const { limiter, advance } = setup(1, 60);
    limiter.check("a");
    advance(10);

    const decision = limiter.check("a");

    expect(decision).toEqual({ allowed: false, retryAfterSeconds: 50, limit: 1 });
  });

  it("キーが違えば別勘定", () => {
    const { limiter } = setup(1);
    expect(limiter.check("a").allowed).toBe(true);
    expect(limiter.check("b").allowed).toBe(true);
  });

  it("窓が変われば戻る", () => {
    const { limiter, advance } = setup(1, 60);
    limiter.check("a");
    expect(limiter.check("a").allowed).toBe(false);

    advance(61);

    expect(limiter.check("a").allowed).toBe(true);
  });

  it("キーを変え続けてもメモリが際限なく増えない", () => {
    // ⚠ これが無いと、制限そのものが攻撃対象になる。
    // 送信元をキーにすると、送信元を変えるだけでメモリを食い潰せる。
    let clock = 1000;
    const limiter = createRateLimiter({
      limit: 10,
      windowSeconds: 60,
      maxKeys: 50,
      now: () => clock,
    });

    for (let i = 0; i < 500; i += 1) {
      limiter.check(`key-${i}`);
      clock += 1;
    }

    expect(limiter.size()).toBeLessThanOrEqual(50);
  });
});

describe("同時実行数の制限", () => {
  it("上限まで取れ、超えたら取れない", () => {
    const limiter = createConcurrencyLimiter(2);

    expect(limiter.acquire("t")).toBeTypeOf("function");
    expect(limiter.acquire("t")).toBeTypeOf("function");
    expect(limiter.acquire("t")).toBeUndefined();
  });

  it("解放すれば取り直せる", () => {
    const limiter = createConcurrencyLimiter(1);
    const release = limiter.acquire("t")!;

    expect(limiter.acquire("t")).toBeUndefined();
    release();

    expect(limiter.acquire("t")).toBeTypeOf("function");
  });

  it("二重解放が、他の実行中の枠を巻き込まない", () => {
    // 「応答を返したとき」と「処理が終わったとき」の両方で解放しがち。
    //
    // ⚠ 枠が1本しか出ていない状況では、二重解放しても数は 0 のままなので
    // 違いが出ない。**2本出ている状況**で初めて、片方の二重解放が
    // もう片方の枠まで返してしまうことが分かる。
    const limiter = createConcurrencyLimiter(2);
    const releaseFirst = limiter.acquire("t")!;
    limiter.acquire("t"); // 2本目は保持したまま

    expect(limiter.current("t")).toBe(2);

    releaseFirst();
    releaseFirst();

    expect(limiter.current("t"), "二重解放が実行中の枠まで返している").toBe(1);
    // 空いているのは1本だけ
    expect(limiter.acquire("t")).toBeTypeOf("function");
    expect(limiter.acquire("t")).toBeUndefined();
  });

  it("キーが違えば別勘定", () => {
    const limiter = createConcurrencyLimiter(1);
    expect(limiter.acquire("a")).toBeTypeOf("function");
    expect(limiter.acquire("b")).toBeTypeOf("function");
  });
});

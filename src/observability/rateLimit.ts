/**
 * 流量制限 (§7.2)。
 *
 * ## 認証前と認証後で単位を分ける
 *
 * | 区間 | 単位 | 適用する位置 |
 * | --- | --- | --- |
 * | 認証前（`/auth` / `/token` / 無効な Bearer） | 送信元 + サービス全体の総量 | **Firestore を引く前・KMS を呼ぶ前** |
 * | 認証後（`/mcp`） | grant（接続）単位 | ツール実行前 |
 *
 * 未認証のリクエストには grant が無い。
 * **トークンを単位にしない** — こちらのアクセストークンは更新されるので、
 * 更新のたびに枠がリセットされる。grant は接続が続く限り同一。
 *
 * ## これはインスタンス単位でしか効かない
 *
 * プロセス内メモリなので、実効的な上限は **制限値 × インスタンス数**。
 * 再起動でも枠が戻る。**これは「上限」ではなく「目安」である。**
 *
 * 「課金が直撃しないから緩くてよい」という説明は、
 * Firestore と KMS を導入した時点で成り立たない。
 * 許容できるかは `--max-instances` を掛けた最悪値で判断する。
 */

export type RateLimitDecision =
  | { allowed: true; remaining: number }
  | { allowed: false; retryAfterSeconds: number; limit: number };

export type RateLimitOptions = {
  /** 窓の長さ（秒） */
  windowSeconds: number;
  /** 窓あたりの上限 */
  limit: number;
  /**
   * 覚えておくキーの上限。
   *
   * ⚠ **これが無いと制限そのものが攻撃対象になる。**
   * 送信元をキーにすると、送信元を変え続けるだけでメモリが際限なく増える。
   */
  maxKeys?: number;
  now?: () => number;
};

const DEFAULT_MAX_KEYS = 10_000;

type Window = { count: number; resetAt: number };

/**
 * 固定窓カウンタ。
 *
 * トークンバケットにしないのは、**上限が目安である**以上、
 * 厳密さより「詰まった理由が分かること」を優先したいため。
 */
export const createRateLimiter = (options: RateLimitOptions) => {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
  const windows = new Map<string, Window>();

  /** 期限切れを掃除する。全部見ないのは、掃除が重くなると本末転倒なため */
  const evictIfNeeded = (at: number): void => {
    if (windows.size < maxKeys) return;

    for (const [key, window] of windows) {
      if (window.resetAt <= at) windows.delete(key);
    }

    // それでも溢れるなら、古いものから落とす（Map は挿入順）
    while (windows.size >= maxKeys) {
      const oldest = windows.keys().next();
      if (oldest.done) break;
      windows.delete(oldest.value);
    }
  };

  return {
    /** 1回ぶん消費して、通してよいかを返す */
    check(key: string): RateLimitDecision {
      const at = now();
      const window = windows.get(key);

      if (!window || window.resetAt <= at) {
        evictIfNeeded(at);
        windows.set(key, { count: 1, resetAt: at + options.windowSeconds });
        return { allowed: true, remaining: options.limit - 1 };
      }

      if (window.count >= options.limit) {
        return {
          allowed: false,
          retryAfterSeconds: Math.max(1, window.resetAt - at),
          limit: options.limit,
        };
      }

      window.count += 1;
      return { allowed: true, remaining: options.limit - window.count };
    },

    /** 覚えているキーの数（テストと監視用） */
    size(): number {
      return windows.size;
    },
  };
};

export type RateLimiter = ReturnType<typeof createRateLimiter>;

/**
 * 同時実行数の制限。
 *
 * 流量（単位時間あたり）とは別に、**同時に何本 kintone を叩くか**を抑える。
 * kintone 側の同時実行制限を超えると、相手のドメイン全体に影響する (§7.2)。
 *
 * ⚠ **HTTP 応答を返しても、裏の呼び出しが続いている間は枠を解放しない。**
 * 解放すると、タイムアウトの連鎖で上流への同時接続が上限を超える。
 */
export const createConcurrencyLimiter = (maxInFlight: number) => {
  const inFlight = new Map<string, number>();

  return {
    /** 枠を取れたら解放用の関数を返す。取れなければ undefined */
    acquire(key: string): (() => void) | undefined {
      const current = inFlight.get(key) ?? 0;
      if (current >= maxInFlight) return undefined;

      inFlight.set(key, current + 1);
      let released = false;

      return () => {
        // 二重解放で枠が増えないようにする
        if (released) return;
        released = true;
        const next = (inFlight.get(key) ?? 1) - 1;
        if (next <= 0) inFlight.delete(key);
        else inFlight.set(key, next);
      };
    },

    current(key: string): number {
      return inFlight.get(key) ?? 0;
    },
  };
};

export type ConcurrencyLimiter = ReturnType<typeof createConcurrencyLimiter>;

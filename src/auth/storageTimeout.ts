import type { Storage } from "./storage.js";
import { remainingMs, RequestDeadlineExceeded } from "./requestDeadline.js";

/**
 * 保存層に期限を与える。
 *
 * ## なぜ要るか
 *
 * `/mcp` には締め切りを入れたが、**`/token` や `/auth` には何も無かった**。
 * 保存層が黙ると、認可コードの引き換えが**いつまでも応答を返さない**
 * （11秒後も未応答であることを外部レビューで実測された）。
 * 設計では「token は10秒以内」としているので、これを満たせていない。
 *
 * ## 何を止めていて、何を止めていないか
 *
 * ⚠ **止まるのはこちらの処理であって、Firestore への呼び出しではない。**
 * `Promise` を拒否するだけなので、裏側の通信は続く。
 *
 * それでも意味があるのは、**こちらの流れが確実に止まる**から。
 * 「応答だけ打ち切って、裏でトークンの発行が進む」状態にはならない。
 *
 * ⚠ **書き込みが期限切れになったときは「結果不明」。**
 * 拒否したあとに Firestore 側で成功していることがある。
 * 認可まわりで起きても、残るのは**使われないまま期限切れになるレコード**なので
 * 実害は無い（利用者にはエラーが返り、トークンは渡らない）。
 */

export class StorageTimeoutError extends Error {
  constructor(readonly operation: string) {
    // ⚠ キーやモデル名を入れない。ログに出たときに中身が漏れる
    super(`保存層の応答がありません (${operation})`);
    this.name = "StorageTimeoutError";
  }
}

const withDeadline = async <T>(
  operation: string,
  timeoutMs: number,
  run: () => Promise<T>,
): Promise<T> => {
  /**
   * ⚠ **要求全体の残り時間と、小さいほうを使う。**
   *
   * 操作ごとの期限だけだと、**操作のたびにタイマーが始まり直す**。
   * 1回4秒の読み取りを6回すれば、個別の期限に一度も掛からないまま
   * 24秒かかる（外部レビューで実測された）。
   */
  const remaining = remainingMs();
  if (remaining !== undefined && remaining <= 0) {
    throw new RequestDeadlineExceeded(operation);
  }
  const effectiveMs = remaining === undefined ? timeoutMs : Math.min(timeoutMs, remaining);

  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      run(),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () =>
            reject(
              remainingMs() !== undefined && remainingMs()! <= 0
                ? new RequestDeadlineExceeded(operation)
                : new StorageTimeoutError(operation),
            ),
          effectiveMs,
        );
      }),
    ]);
  } finally {
    // 残すとプロセスが終わらない
    if (timer) clearTimeout(timer);
  }
};

/**
 * すべての操作に同じ期限を掛けた保存層を返す。
 *
 * ⚠ **包み忘れを防ぐため、1か所でまとめて包む。**
 * 呼び出し側ごとに期限を書くと、必ずどこかが漏れる。
 */
export const withStorageTimeout = (storage: Storage, timeoutMs: number): Storage => ({
  find: (model, key) => withDeadline("find", timeoutMs, () => storage.find(model, key)),
  findByIndex: (model, index, value) =>
    withDeadline("findByIndex", timeoutMs, () => storage.findByIndex(model, index, value)),
  upsert: (model, key, input) =>
    withDeadline("upsert", timeoutMs, () => storage.upsert(model, key, input)),
  destroy: (model, key) => withDeadline("destroy", timeoutMs, () => storage.destroy(model, key)),
  consume: (model, key, at) =>
    withDeadline("consume", timeoutMs, () => storage.consume(model, key, at)),
  revokeByGrantId: (grantId) =>
    withDeadline("revokeByGrantId", timeoutMs, () => storage.revokeByGrantId(grantId)),
  update: (model, key, mutate) =>
    withDeadline("update", timeoutMs, () => storage.update(model, key, mutate)),
});

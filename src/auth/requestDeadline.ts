import { AsyncLocalStorage } from "node:async_hooks";

/**
 * 要求1つぶんの残り時間 (§7.3)。
 *
 * ## なぜ操作ごとの期限では足りないか
 *
 * 保存層の操作それぞれに5秒の期限を掛けていたが、
 * **操作のたびにタイマーが始まり直す**。
 * 読み取りを毎回4秒遅らせると、個別の期限には一度も掛からないまま、
 * **6回で約24秒**かかった（外部レビューで実測された）。
 * 設計では `/token` は10秒以内としているので、これを満たせていない。
 *
 * → **要求の入口で予算を決め、以降の操作がそれを分け合う。**
 *
 * ## なぜ AsyncLocalStorage か
 *
 * 保存層は `oidc-provider` の奥から呼ばれる。
 * 引数で引き回すには、provider の内部を通す必要があって現実的でない。
 * 非同期の境界を越えて値を運べる仕組みを使う。
 */

const deadlines = new AsyncLocalStorage<number>();

export class RequestDeadlineExceeded extends Error {
  constructor(readonly operation: string) {
    // ⚠ 鍵やキーに触れない。ログに出る
    super(`要求の期限を過ぎました (${operation})`);
    this.name = "RequestDeadlineExceeded";
  }
}

/** この要求の予算を決めて実行する */
export const withRequestDeadline = <T>(budgetMs: number, run: () => T): T =>
  deadlines.run(Date.now() + budgetMs, run);

/**
 * 残り時間（ミリ秒）。予算が無ければ `undefined`。
 *
 * ⚠ **0 以下も返す。** 呼び出し側が「使い切った」ことを判断できるようにする。
 */
export const remainingMs = (): number | undefined => {
  const deadline = deadlines.getStore();
  return deadline === undefined ? undefined : deadline - Date.now();
};

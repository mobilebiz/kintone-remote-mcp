import { Timestamp } from "@google-cloud/firestore";
import type { CollectionReference, Firestore } from "@google-cloud/firestore";

import type { ConsumeResult, Storage, StoredDocument, UpsertInput } from "./storage.js";

/**
 * Firestore を使った保存層。
 *
 * ## なぜ単一コレクションか
 *
 * モデルごとにコレクションを分けると、`revokeByGrantId()` が
 * **全モデルを横断して検索**することになる。失効は「その grant から出たものを
 * 残らず消す」処理なので、取りこぼしが即セキュリティの穴になる。
 * 単一コレクションにして `grantId` の等価検索1回で済ませる。
 *
 * 文書 ID は `<model>|<key>`。
 *
 * ⚠ **区切り文字は、モデル名にも key にも現れないものを使う。**
 * 最初 `__` にしていたところ、`("Access", "Token__k1")` と
 * `("Access__Token", "k1")` が**同じ文書 ID になった**（エミュレータで再現）。
 * key は base64url なので `_` を含みうる。`|` は base64url にもモデル名にも現れない。
 *
 * ## 原子性
 *
 * `consume()` と `update()` は **transaction 内で読んで書く**。
 * Firestore の transaction は競合時に**コールバックを再実行する**ので、
 * その中で外部 API を呼んではいけない。`Storage` の契約で
 * mutator を同期関数に限っているのはこのため (§4.10)。
 *
 * ## 必要な索引
 *
 * 単一フィールドの等価検索は既定の索引で足りる（`uidHash` / `userCodeHash` /
 * `grantId`）。**複合索引は不要。**
 * ## TTL
 *
 * ⚠ **Firestore の TTL ポリシーは日時型のフィールドしか見ない。**
 * `expiresAt` をエポック秒の数値で持つだけでは、ポリシーを設定しても
 * **期限切れの文書が消えずに溜まり続ける**。
 * 判定用の `expiresAt`（数値）とは別に、TTL ポリシー用の `ttlAt`（`Timestamp`）を書く。
 *
 * TTL ポリシーは `ttlAt` に対して設定する。
 * **TTL は掃除であって認可判定ではない** — 期限は使うたびにコード側で見る (§4.9)。
 */

const DEFAULT_COLLECTION = "oidc";

type StoredFields = Omit<StoredDocument, "key"> & {
  model: string;
  /** TTL ポリシー用。判定には使わない */
  ttlAt: Timestamp | undefined;
};

export type FirestoreStorageOptions = {
  firestore: Firestore;
  /** コレクション名。既定 `oidc` */
  collection?: string;
};

const SEPARATOR = "|";

const documentId = (model: string, key: string): string => `${model}${SEPARATOR}${key}`;

/**
 * Firestore は `undefined` を保存できない。
 *
 * ⚠ **浅く落とすだけでは足りない。** `payload` の中の `undefined` でも
 * `Cannot use "undefined" as a Firestore value` で落ちる（エミュレータで再現）。
 * メモリ実装は素通しするので、**2つの実装で挙動が割れる**。
 * 入れ子まで落として揃える。
 */
const stripUndefined = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(stripUndefined);

  // ⚠ **素のオブジェクトだけを開く。**
  // `Timestamp` や `Date` まで `Object.entries` で分解すると、
  // ただのプロパティの入れ物に化けて型が失われる。
  if (isPlainObject(value)) {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (v !== undefined) result[k] = stripUndefined(v);
    }
    return result;
  }

  return value;
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

const toFields = (fields: StoredFields): Record<string, unknown> =>
  stripUndefined(fields) as Record<string, unknown>;

/** TTL ポリシー用の日時。期限が無いものには書かない（永久に消さない） */
const toTimestamp = (expiresAt: number | undefined): Timestamp | undefined =>
  expiresAt === undefined ? undefined : Timestamp.fromMillis(expiresAt * 1000);

const toStored = (data: Record<string, unknown> | undefined, key: string): StoredDocument | undefined => {
  if (!data) return undefined;
  return {
    key,
    payload: (data.payload as Record<string, unknown> | undefined) ?? {},
    expiresAt: typeof data.expiresAt === "number" ? data.expiresAt : undefined,
    grantId: typeof data.grantId === "string" ? data.grantId : undefined,
    uidHash: typeof data.uidHash === "string" ? data.uidHash : undefined,
    userCodeHash: typeof data.userCodeHash === "string" ? data.userCodeHash : undefined,
    consumedAt: typeof data.consumedAt === "number" ? data.consumedAt : undefined,
  };
};

export class FirestoreStorage implements Storage {
  readonly #collection: CollectionReference;
  readonly #firestore: Firestore;

  constructor(options: FirestoreStorageOptions) {
    this.#firestore = options.firestore;
    this.#collection = options.firestore.collection(options.collection ?? DEFAULT_COLLECTION);
  }

  #doc(model: string, key: string) {
    return this.#collection.doc(documentId(model, key));
  }

  async find(model: string, key: string): Promise<StoredDocument | undefined> {
    const snapshot = await this.#doc(model, key).get();
    return toStored(snapshot.data(), key);
  }

  async findByIndex(
    model: string,
    index: "uidHash" | "userCodeHash",
    value: string,
  ): Promise<StoredDocument | undefined> {
    const snapshot = await this.#collection
      .where("model", "==", model)
      .where(index, "==", value)
      .limit(1)
      .get();

    const first = snapshot.docs[0];
    if (!first) return undefined;
    // 文書 ID から key を戻す（`<model>|<key>`）
    return toStored(first.data(), first.id.slice(model.length + SEPARATOR.length));
  }

  async upsert(model: string, key: string, input: UpsertInput): Promise<void> {
    const ref = this.#doc(model, key);

    // **使用済みの印を消さない**（契約）。
    // provider は同じレコードを再保存することがあり、そこで consumed が
    // 消えると「一度使ったコードがまた使える」状態になる。
    await this.#firestore.runTransaction(async (tx) => {
      const snapshot = await tx.get(ref);
      const consumedAt = snapshot.data()?.consumedAt;

      const fields: StoredFields = {
        model,
        payload: input.payload,
        expiresAt: input.expiresAt,
        ttlAt: toTimestamp(input.expiresAt),
        grantId: input.grantId,
        uidHash: input.uidHash,
        userCodeHash: input.userCodeHash,
        consumedAt: typeof consumedAt === "number" ? consumedAt : undefined,
      };
      tx.set(ref, toFields(fields));
    });
  }

  async destroy(model: string, key: string): Promise<void> {
    await this.#doc(model, key).delete();
  }

  async consume(model: string, key: string, at: number): Promise<ConsumeResult> {
    const ref = this.#doc(model, key);

    return this.#firestore.runTransaction<ConsumeResult>(async (tx) => {
      const snapshot = await tx.get(ref);
      const data = snapshot.data();
      if (!data) return "not-found";
      if (typeof data.consumedAt === "number") return "already-consumed";

      // transaction の中で読んで書くので、2つ同時に来ても片方しか通らない。
      tx.update(ref, { consumedAt: at });
      return "consumed";
    });
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    // 失効は取りこぼしが穴になるので、**残らず消えるまで繰り返す**。
    // 1回のバッチ上限を超える件数でも確実に消す。
    const BATCH = 300;

    for (;;) {
      const snapshot = await this.#collection.where("grantId", "==", grantId).limit(BATCH).get();
      if (snapshot.empty) return;

      const batch = this.#firestore.batch();
      for (const doc of snapshot.docs) batch.delete(doc.ref);
      await batch.commit();

      if (snapshot.size < BATCH) return;
    }
  }

  async update(
    model: string,
    key: string,
    mutator: (current: StoredDocument | undefined) => UpsertInput | "abort",
  ): Promise<"updated" | "aborted"> {
    const ref = this.#doc(model, key);

    return this.#firestore.runTransaction<"updated" | "aborted">(async (tx) => {
      const snapshot = await tx.get(ref);
      const current = toStored(snapshot.data(), key);

      // ⚠ mutator は同期関数。**ここで外部 API を呼ばない。**
      // transaction は競合時にこのコールバックごと再実行されるため、
      // 副作用のある処理を入れると多重に走る。
      const next = mutator(current);
      if (next === "abort") return "aborted";

      const fields: StoredFields = {
        model,
        payload: next.payload,
        expiresAt: next.expiresAt,
        ttlAt: toTimestamp(next.expiresAt),
        grantId: next.grantId,
        uidHash: next.uidHash,
        userCodeHash: next.userCodeHash,
        consumedAt: current?.consumedAt,
      };
      tx.set(ref, toFields(fields));
      return "updated";
    });
  }
}

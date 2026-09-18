/**
 * Adapter が使う保存層の抽象。
 *
 * Firestore を直接触らずにここを挟むのは、**原子性の契約をテストで固定するため**。
 * `consume` の競合は設計上いちばん危ないところ (§4.10) で、
 * 実際の Firestore が無いと試せない作りにすると、その部分だけ検証されないまま残る。
 */

export type StoredDocument = {
  /**
   * この文書のキー（= トークン値のハッシュ）。
   *
   * **文書自身がキーを持つ。** 二次索引から引いたときに、
   * 復号に必要な AAD を組み立てられないと困るため
   * （AAD はキーを含む。→ `adapter.ts`）。
   */
  key: string;
  /** 暗号化・ハッシュ済みの本文 */
  payload: Record<string, unknown>;
  /** 失効判定に使う。エポック秒。TTL は掃除であって認可判定ではない (§4.9) */
  expiresAt: number | undefined;
  /** 失効の一括適用に使う */
  grantId: string | undefined;
  /** 二次索引（ハッシュ済み） */
  uidHash: string | undefined;
  userCodeHash: string | undefined;
  /** 使用済みの時刻。エポック秒 */
  consumedAt: number | undefined;
};

/** `consume` の結果。**競合を呼び出し側が区別できる形で返す** */
export type ConsumeResult = "consumed" | "already-consumed" | "not-found";

/** 保存時に渡す値。`key` と `consumedAt` は保存層が管理する */
export type UpsertInput = Omit<StoredDocument, "key" | "consumedAt">;

export interface Storage {
  find(model: string, key: string): Promise<StoredDocument | undefined>;
  findByIndex(
    model: string,
    index: "uidHash" | "userCodeHash",
    value: string,
  ): Promise<StoredDocument | undefined>;
  /**
   * 保存する。
   *
   * **既存の `consumedAt` は保持する。** provider は同じレコードに対して
   * 再保存を行うことがあり、そこで使用済みの印が消えると
   * 「一度使ったコードがまた使える」状態になる。
   */
  upsert(model: string, key: string, input: UpsertInput): Promise<void>;
  destroy(model: string, key: string): Promise<void>;
  /**
   * **未使用であることを条件に使用済みへ更新する。**
   * 同時に2つ来ても、成功するのは片方だけでなければならない。
   */
  consume(model: string, key: string, at: number): Promise<ConsumeResult>;
  /** grantId に紐づく全モデルのレコードを消す */
  revokeByGrantId(grantId: string): Promise<void>;
  /**
   * **読み取りと書き込みを不可分に行う。**
   *
   * 「読んで、条件を確かめて、書く」を別々の操作でやると、その間に
   * 失効が挟まったときに**失効を取り消してしまう**。
   * mutator は同期関数に限る（await を挟ませない）。
   *
   * @returns mutator が `"abort"` を返したら `"aborted"`
   */
  update(
    model: string,
    key: string,
    mutator: (current: StoredDocument | undefined) => UpsertInput | "abort",
  ): Promise<"updated" | "aborted">;
}

/**
 * テストと単一インスタンスの検証に使うメモリ実装。
 *
 * **本番では使わない。** プロセスが落ちれば全接続が切れる。
 */
export class MemoryStorage implements Storage {
  readonly #documents = new Map<string, StoredDocument>();

  #id(model: string, key: string): string {
    return `${model} ${key}`;
  }

  async find(model: string, key: string): Promise<StoredDocument | undefined> {
    return this.#documents.get(this.#id(model, key));
  }

  async findByIndex(
    model: string,
    index: "uidHash" | "userCodeHash",
    value: string,
  ): Promise<StoredDocument | undefined> {
    const prefix = `${model} `;
    for (const [id, document] of this.#documents) {
      if (id.startsWith(prefix) && document[index] === value) return document;
    }
    return undefined;
  }

  async upsert(model: string, key: string, input: UpsertInput): Promise<void> {
    const id = this.#id(model, key);
    const existing = this.#documents.get(id);
    this.#documents.set(id, {
      ...input,
      key,
      // 使用済みの印を消さない（契約）
      consumedAt: existing?.consumedAt,
    });
  }

  async destroy(model: string, key: string): Promise<void> {
    this.#documents.delete(this.#id(model, key));
  }

  async consume(model: string, key: string, at: number): Promise<ConsumeResult> {
    const id = this.#id(model, key);
    const document = this.#documents.get(id);
    if (!document) return "not-found";
    // 単一スレッドの Map なので、読み取りと書き込みの間に他が割り込むことはない。
    // Firestore 実装では transaction の前提条件で同じ性質を作る。
    if (document.consumedAt !== undefined) return "already-consumed";
    this.#documents.set(id, { ...document, consumedAt: at });
    return "consumed";
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    for (const [id, document] of this.#documents) {
      if (document.grantId === grantId) this.#documents.delete(id);
    }
  }

  async update(
    model: string,
    key: string,
    mutator: (current: StoredDocument | undefined) => UpsertInput | "abort",
  ): Promise<"updated" | "aborted"> {
    const id = this.#id(model, key);
    const current = this.#documents.get(id);
    // mutator は同期なので、ここに他の操作が割り込む余地は無い。
    // Firestore 実装では transaction で同じ性質を作る。
    const next = mutator(current);
    if (next === "abort") return "aborted";
    this.#documents.set(id, { ...next, key, consumedAt: current?.consumedAt });
    return "updated";
  }

  /** テスト用。保存されている生データを覗く */
  dump(): StoredDocument[] {
    return [...this.#documents.values()];
  }
}

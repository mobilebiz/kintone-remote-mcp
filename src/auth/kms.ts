import { KeyManagementServiceClient } from "@google-cloud/kms";

/**
 * トークン暗号鍵を、Cloud KMS で包んだ形から取り出す (§4.9)。
 *
 * ## 何が変わるか
 *
 * 包む前は、32バイトの鍵が**そのまま環境変数に載っていた**。
 * Cloud Run の設定を読める者は、そのまま鍵を手に入れられる。
 *
 * 包んだあとは、設定に載るのは**KMS で暗号化された鍵**だけ。
 * 取り出すには KMS の復号権限が要る。
 *
 * ## 何を守らないか
 *
 * ⚠ **復号権限を持つ実行サービスアカウントの侵害は防がない** (§4.9)。
 * その SA を奪えば、KMS を呼んで鍵を取り出せる。
 * **守るのは「保存されている設定やデータだけが漏れた場合」**であって、
 * それ以上ではない。
 *
 * ⚠ **KMS の利用を監査に残すには、Data Access audit logs の有効化が要る**
 * （既定では無効）。有効にしていなければ、鍵が使われた記録は残らない。
 *
 * ## 起動時に1回だけ復号する
 *
 * 要求ごとに KMS を呼ばない。呼ぶと、**でたらめな Bearer を投げるだけで
 * KMS の課金と流量を誘発できる** (§7.2)。
 * 取り出した鍵はプロセスのメモリに置く。
 */

export type EncryptionKeySource =
  | { kind: "plain"; key: Buffer }
  | { kind: "kms"; keyName: string; ciphertext: Buffer };

export class KeyUnwrapError extends Error {
  constructor(cause: string) {
    // ⚠ 鍵にも暗号文にも触れない。ログに出る
    super(`トークン暗号鍵を KMS から取り出せません: ${cause}`);
    this.name = "KeyUnwrapError";
  }
}

/** KMS を呼ぶところ。組み立ての途中を差し替えるためだけにある */
export type KmsDecrypter = (input: {
  name: string;
  ciphertext: Buffer;
}) => Promise<Buffer>;

/**
 * KMS の応答から平文を取り出す。
 *
 * ⚠ **ここを切り出してあるのは、テストから通すため。**
 * 復号関数まるごとを差し替えると、**この読み取りが1行も実行されない**。
 * 応答を無視して固定の鍵を返す変異が、全件通過した（外部レビューで指摘）。
 */
export const plaintextFrom = (response: { plaintext?: unknown }): Buffer => {
  const plaintext = response.plaintext;
  if (plaintext === null || plaintext === undefined) {
    throw new KeyUnwrapError("応答に平文がありません");
  }
  if (typeof plaintext === "string") return Buffer.from(plaintext, "base64");
  if (plaintext instanceof Uint8Array) return Buffer.from(plaintext);
  throw new KeyUnwrapError("応答の平文を解釈できません");
};

/** KMS を呼ぶ部分だけの口。テストはここを差し替えて、上の読み取りは本番のまま通す */
export type KmsClient = {
  decrypt(request: { name: string; ciphertext: Buffer }): Promise<[{ plaintext?: unknown }]>;
};

export const decrypterUsing =
  (client: KmsClient): KmsDecrypter =>
  async ({ name, ciphertext }) => {
    const [response] = await client.decrypt({ name, ciphertext });
    return plaintextFrom(response);
  };

/**
 * 本番で使う KMS クライアント。
 *
 * ⚠ **差し替えの口はここまで下げる。**
 * 以前は復号関数まるごとを差し替えられる形にしていたので、
 * **本番の既定経路が1行も実行されなかった**。
 * 「KMS を呼ばず固定の鍵を返す」に書き換えても全件通過した（外部レビューで指摘）。
 * 鍵の取り違えは、起動しないか、保存済みのトークンを1つも読めないかのどちらかで、
 * どちらも試験で気づけないまま本番に出る種類の壊れ方になる。
 *
 * ここを口にすれば、`decrypterUsing` も `plaintextFrom` も
 * 例外の包み方も base64 の読み方も、**本番と同じ経路が動く**。
 * 試験が通らないのは `new KeyManagementServiceClient()` の1行だけになる。
 */
export const defaultKmsClient = (): KmsClient =>
  new KeyManagementServiceClient() as unknown as KmsClient;

/**
 * 使う鍵を決める。
 *
 * ⚠ **取り出せなければ起動しない。** 鍵が無いまま動かすと、
 * 保存済みのトークンを1つも読めないサーバーが「正常に起動した」ことになる。
 */
export const resolveEncryptionKey = async (
  source: EncryptionKeySource,
  createClient: () => KmsClient = defaultKmsClient,
): Promise<Buffer> => {
  if (source.kind === "plain") return source.key;

  let key: Buffer;
  try {
    key = await decrypterUsing(createClient())({
      name: source.keyName,
      ciphertext: source.ciphertext,
    });
  } catch (error) {
    // ⚠ 例外の message を混ぜない。KMS のエラーには要求の詳細が入りうる
    throw new KeyUnwrapError(error instanceof Error ? error.name : "unknown");
  }

  // 包む前と同じ形（base64 の文字列）で保存しているので、同じように読む。
  // ⚠ **同じ鍵でなければ、保存済みのトークンを1つも復号できない。**
  //
  // 末尾の改行は自分で落とさない。base64 の復号が空白を無視するので、
  // 落としても落とさなくても結果が同じ（外して確かめた）。
  // 観測できない処理は置かない。
  const decoded = Buffer.from(key.toString("utf8"), "base64");
  if (decoded.length !== 32) {
    throw new KeyUnwrapError(`鍵の長さが32バイトではありません (${decoded.length})`);
  }
  return decoded;
};

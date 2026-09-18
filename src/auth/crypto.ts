import { createHash, createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * 保存前の秘密の扱い。
 *
 * ## なぜ必要か
 *
 * `oidc-provider` の不透明トークンは、**クライアントに渡す値そのものが `jti`** で、
 * それが Adapter へ次の形で渡ってくる（v9.12.2 のソースで確認）:
 *
 *   const IN_PAYLOAD = ['iat', 'exp', 'jti', 'kind'];
 *   await this.adapter.upsert(this.jti, payload, ttl);   // 文書 ID = jti
 *   return { value: token.jti, payload };                // クライアントが持つ値 = jti
 *
 * つまり**素直に保存すると、Bearer トークンが文書 ID にも本文にも平文で残る。**
 * データベースだけが漏れた場合にトークンをそのまま使われる。
 *
 * ## 方針
 *
 * - **検索キーはハッシュ**。呼び出し側が生値を持っているので復元は不要
 * - **生値を戻す必要があるものは AEAD で暗号化**（Session の `jti` / `uid` など。
 *   `findByUid` には元の `jti` が渡らないので、除去すると復元できない）
 * - **AAD に「どのモデルのどのレコードか」を入れる**。暗号文を別レコードへ
 *   移し替える細工を検出するため
 *
 * 鍵は当面 `TOKEN_ENCRYPTION_KEY`（32バイトの base64）から取る。
 * Cloud KMS によるエンベロープ暗号化はフェーズ4c で差し替える。
 */

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

export type SecretCipher = {
  /** 保存用に封をする */
  seal: (plaintext: string, aad: string) => string;
  /** 読み出し時に開ける。改ざん・別レコードへの移し替えは例外にする */
  open: (sealed: string, aad: string) => string;
  /** 検索キー用のハッシュ。鍵付きにして、DB だけから逆引きできないようにする */
  hash: (value: string) => string;
};

export class CipherError extends Error {}

/**
 * @param key 32バイト。`TOKEN_ENCRYPTION_KEY` を base64 デコードしたもの
 */
export const createSecretCipher = (key: Buffer): SecretCipher => {
  if (key.length !== 32) {
    throw new CipherError(`暗号鍵は32バイトである必要があります (実際: ${key.length})`);
  }

  return {
    seal: (plaintext, aad) => {
      const iv = randomBytes(IV_LENGTH);
      const cipher = createCipheriv(ALGORITHM, key, iv);
      cipher.setAAD(Buffer.from(aad, "utf8"));
      const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64");
    },

    open: (sealed, aad) => {
      let raw: Buffer;
      try {
        raw = Buffer.from(sealed, "base64");
      } catch {
        throw new CipherError("暗号文を復号できません");
      }
      if (raw.length < IV_LENGTH + TAG_LENGTH) {
        throw new CipherError("暗号文を復号できません");
      }

      const iv = raw.subarray(0, IV_LENGTH);
      const tag = raw.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
      const body = raw.subarray(IV_LENGTH + TAG_LENGTH);

      try {
        const decipher = createDecipheriv(ALGORITHM, key, iv);
        decipher.setAAD(Buffer.from(aad, "utf8"));
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
      } catch {
        // AAD 不一致（= 別レコードの暗号文を持ち込まれた）もここに来る。
        // 理由を外に出さない。
        throw new CipherError("暗号文を復号できません");
      }
    },

    // 鍵付きハッシュ。鍵を知らなければ、トークン値からキーを計算できない。
    hash: (value) => createHash("sha256").update(key).update("\\0").update(value, "utf8").digest("base64url"),
  };
};

/** 文字列の定数時間比較。長さが違えば false */
export const safeEqual = (a: string, b: string): boolean => {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
};

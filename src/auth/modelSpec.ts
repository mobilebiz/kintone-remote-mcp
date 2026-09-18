/**
 * モデルごとの保存・復元の規則。
 *
 * **全モデルを同じ扱いにはできない。** v9.12.2 のソースで確認した事情:
 *
 * - `find(id)` しか使わないモデルは、`id` から `jti` を復元できるので
 *   保存時に落としてよい
 * - **`Session` は `findByUid(uid)` でも引かれる。** そこには `jti` が渡らないので、
 *   落とすと復元できない。provider 側は `jti` が無いと**別の値を新規生成してしまう**
 *   （`instantiate(payload)` の挙動）
 * - **`Interaction` は `session.cookie` に Session の生 `jti` を入れる**
 *   （`lib/models/interaction.js` のコンストラクタ）。トップレベルだけ見ても取りこぼす
 */

/** 保存時に暗号化し、読み出し時に復号するフィールドの指定 */
export type SecretField =
  /** トップレベルのフィールド */
  | { kind: "top"; field: string }
  /** 1段ネストしたフィールド */
  | { kind: "nested"; parent: string; field: string };

export type ModelSpec = {
  /**
   * `find(id)` の引数から `jti` を復元できるか。
   * できるなら保存時に落とす（= DB に平文のトークン値を残さない）。
   */
  restoreJtiFromKey: boolean;
  /** 暗号化して保存するフィールド */
  secretFields: SecretField[];
  /** 二次索引を張るフィールド（値はハッシュして索引にする） */
  indexes: Array<"uid" | "userCode">;
};

const TOKEN_LIKE: ModelSpec = {
  restoreJtiFromKey: true,
  secretFields: [],
  indexes: [],
};

/**
 * `Session`: `jti` はセッション Cookie の値そのもの、`uid` は別の識別子。
 * どちらも `find` / `findByUid` の両経路で必要になるため、**落とさずに暗号化する**。
 */
const SESSION: ModelSpec = {
  restoreJtiFromKey: false,
  secretFields: [
    { kind: "top", field: "jti" },
    { kind: "top", field: "uid" },
  ],
  indexes: ["uid"],
};

/**
 * `Interaction`: `uid` は `jti` と同じ値で、URL に出る（`/interaction/:uid`）。
 * 検索は `find(uid)` だけなので `jti` は落とせるが、
 * **`session.cookie` に別モデル（Session）の生 `jti` が入る**ので、そこを暗号化する。
 */
const INTERACTION: ModelSpec = {
  restoreJtiFromKey: true,
  secretFields: [
    { kind: "nested", parent: "session", field: "cookie" },
    { kind: "nested", parent: "session", field: "uid" },
  ],
  indexes: [],
};

const SPECS: Record<string, ModelSpec> = {
  AccessToken: TOKEN_LIKE,
  RefreshToken: TOKEN_LIKE,
  AuthorizationCode: TOKEN_LIKE,
  ClientCredentials: TOKEN_LIKE,
  InitialAccessToken: TOKEN_LIKE,
  RegistrationAccessToken: TOKEN_LIKE,
  PushedAuthorizationRequest: TOKEN_LIKE,
  BackchannelAuthenticationRequest: TOKEN_LIKE,
  Grant: TOKEN_LIKE,
  Session: SESSION,
  Interaction: INTERACTION,
  // DeviceCode / PreAuthorizedCode はこの構成では使わない。
  // 万一有効になったら「未知のモデル」として安全側に倒す（下記 specFor）。
};

/**
 * 未知のモデルは**最も厳しい規則**で扱う。
 * 上流がモデルを増やしたときに、規則の無いものが平文で保存されるのを防ぐ。
 */
const UNKNOWN: ModelSpec = {
  restoreJtiFromKey: false,
  secretFields: [{ kind: "top", field: "jti" }],
  indexes: ["uid", "userCode"],
};

export const specFor = (modelName: string): ModelSpec => SPECS[modelName] ?? UNKNOWN;

/** 規則を持っているモデル名（テストが上流との差分を検出するのに使う） */
export const KNOWN_MODELS: readonly string[] = Object.keys(SPECS);

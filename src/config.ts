/**
 * 環境変数の読み取りと検証。
 *
 * **起動時に検証して、不正なら1つでもツールを登録する前に落とす** (§2.3)。
 * 設定の誤りが「動いているように見えて挙動がおかしい」形で出ると、
 * 原因に辿り着くまでが長い。
 *
 * 問題は**まとめて**報告する。1つ直すたびに再起動して次が出る、を避ける。
 */

import type { EncryptionKeySource } from "./auth/kms.js";

export type ServerConfig = {
  port: number;
  /** 待ち受けアドレス。Cloud Run は 0.0.0.0 */
  bindHost: string;
  /** `https://HOST`。パスは付けない (§4.6) */
  issuer: string;
  /** `https://HOST/mcp`。**Claude に入力してもらう URL と完全一致させる** */
  resource: string;
  /** Host ヘッダーの許可リスト。DNS rebinding 対策 */
  allowedHosts: string[];
  /** Origin の許可リスト。空なら Origin 付きのリクエストをすべて拒否 */
  allowedOrigins: string[];
  /**
   * 事前登録していないクライアントを受け入れるホスト（CIMD）。
   *
   * ⚠ **空なら CIMD ごと無効。** 「誰でも登録できる」を既定にしない。
   */
  cimdAllowedHosts: string[];
  /**
   * 信頼するプロキシのホップ数。
   *
   * ⚠ **`true`（全面信頼）にしてはいけない。** Express は `true` だと
   * `X-Forwarded-For` の**左端**を `req.ip` にするが、そこは
   * **送信者が自由に書ける**。Cloud Run は既存の値を検証も削除もせず、
   * 実 IP を**末尾に追記**するだけなので、左端を信じると
   * 送信元ごとの制限が1行の細工で無効になる（実測で確認）。
   *
   * ホップ数を指定すると、Express は**右から数えて**信頼する。
   * `1` = 末尾の1つ（Cloud Run が付けた実 IP）を採る。
   *
   * ⚠ **前段に外部 HTTPS ロードバランサを置くと 2 になる。**
   * 構成を変えたら実際のヘッダーで確かめること。
   */
  trustedProxyHops: number;

  /** `https://example.cybozu.com` */
  kintoneBaseUrl: string;
  cybozuClientId: string;
  cybozuClientSecret: string;
  /** cybozu に要求するスコープ。フェーズ1 は読み取りのみ */
  cybozuScopes: string[];

  /**
   * トークン暗号化鍵（32バイト）。
   *
   * ⚠ **KMS で包んでいる場合、起動時に取り出すまで空**。
   * `resolveEncryptionKey()` の結果を入れてから `buildServer` に渡す。
   */
  tokenEncryptionKey: Buffer;
  /**
   * 鍵をどこから得るか。
   *
   * 環境変数に生の鍵を置くと、Cloud Run の設定を読める者がそのまま鍵を得る。
   * KMS で包めば、取り出すのに復号権限が要る (§4.9)。
   */
  encryptionKeySource: EncryptionKeySource;
  /** Cookie 署名鍵。**全インスタンスで共有する** */
  cookieKeys: string[];

  /** Firestore のコレクション名 */
  firestoreCollection: string;
  /**
   * Firestore のデータベース ID。
   *
   * ⚠ **環境変数 `FIRESTORE_DATABASE` は SDK が読まない。**
   * `new Firestore()` は常に `(default)` に繋がる（実測で確認）。
   * 専用データベースを使うには、ここで読んで `databaseId` として渡す必要がある。
   */
  firestoreDatabaseId: string | undefined;
  /**
   * id_token の署名鍵（JWKS）。
   *
   * ⚠ **未設定だと、`oidc-provider` は同梱の固定鍵を使う。**
   * `kid: "keystore-CHANGE-ME"` の鍵で、**秘密鍵がパッケージに入っている**。
   * 起動ごとのランダム鍵ですらないので、誰でも署名を偽造できる。
   * 本番では必須。
   */
  jwks: { keys: Record<string, unknown>[] } | undefined;

  /**
   * Cookie に `Secure` を付けるか。**本番では必ず true**。
   *
   * ⚠ false にできるのは、ローカルの平文 HTTP で試すときだけ。
   * true のまま HTTP で動かすと、Cookie の発行が
   * `Cannot send secure cookie over unencrypted connection` で失敗し、
   * **`/auth` が 500 になる**（実際に踏んだ）。
   */
  secureCookies: boolean;

  /**
   * 許可するアプリ ID。未設定なら制限なし。
   *
   * ⚠ **読み込み時に正規化する。** 空文字・空白・`,` だけのときは
   * `undefined` にそろえる。そろえないと、
   * **同意画面は「絞っている」、実行側は「制限なし」**と判断が割れる
   * （外部レビューで再現された）。
   */
  allowedAppIds: string | undefined;

  /**
   * 連携用ユーザー。**OAuth で実行できない5ツール専用**。
   *
   * ⚠ **これを設定すると、スペース操作と検索は「接続した本人」ではなく
   * 「このユーザー」として実行されます。** 本人が見られないものにも手が届きます。
   *
   * ⚠ **パスワード認証にはスコープがありません。** このユーザーができること全部が
   * できてしまうので、**権限を絞った専用ユーザー**を用意してください。
   * サイボウズ自身も連携用の専用ユーザーを勧めています。
   *
   * ⚠ **2要素認証を有効にしたユーザーでは使えません**（REST API が実行できません）。
   */
  integrationUser: { username: string; password: string } | undefined;

  /** capability フラグ */
  capabilities: {
    recordRead: boolean;
    recordWrite: boolean;
    appRead: boolean;
    appWrite: boolean;
    spaceRead: boolean;
    spaceWrite: boolean;
    search: boolean;
    fileDownload: boolean;
    allowDestructive: boolean;
  };

  /** 上限 (§7.2) */
  limits: {
    preAuthPerMinute: number;
    /**
     * 認証前の**総量**。送信元に関係なく、このインスタンス全体で数える。
     *
     * ⚠ **送信元ごとの制限だけでは守れない。** 送信元は詐称でも分散でも
     * いくらでも増やせるので、「1つあたりの上限」は総量の上限にならない。
     */
    preAuthTotalPerMinute: number;
    grantPerMinute: number;
    concurrentPerGrant: number;
    /**
     * このインスタンスから kintone へ同時に出す本数の上限。
     *
     * ⚠ **grant 単位の制限では上流を守れない。** 接続が増えれば
     * 枠も増えるので、上流への同時実行は青天井になる。
     * kintone はドメインあたり100同時要求が上限で、
     * 超過は**同じドメインの他の利用にも響く**。
     * `--max-instances` を掛けた最悪値で判断すること。
     */
    concurrentTotal: number;
    /** リクエストの締め切り（ミリ秒）。Cloud Run の --timeout より短くする */
    deadlineMs: number;
    /**
     * cybozu のトークンエンドポイントを諦めるまで（ミリ秒）。
     *
     * ⚠ **リクエストの締め切りより短くする。** 同じにすると、
     * 更新で詰まったときに締め切りが先に来て、通信だけが残る。
     */
    cybozuTimeoutMs: number;
    /**
     * 保存層の1操作を諦めるまで（ミリ秒）。
     *
     * ⚠ **`/token` の応答時間はこれで決まる。** `/mcp` の締め切りは
     * 認可エンドポイントには効かないので、保存層が黙ったときに
     * 応答を返せる唯一の仕組みがこれ。
     * 設計では token を10秒以内としているので、それより短くする。
     */
    storageTimeoutMs: number;
    /**
     * 認可まわりの要求1つぶんの予算（ミリ秒）。
     *
     * ⚠ **操作ごとの期限では足りない。** 操作のたびにタイマーが始まり直すので、
     * 個別の期限に一度も掛からないまま全体が長引く（実測で24秒）。
     * 設計では `/token` を10秒以内としている。
     */
    authRequestDeadlineMs: number;
    /** リクエストボディの上限 */
    maxBodyBytes: number;
  };
};

export class ConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(`設定に問題があります:\n- ${problems.join("\n- ")}`);
    this.name = "ConfigError";
  }
}

type Env = Record<string, string | undefined>;

const bool = (value: string | undefined, fallback: boolean): boolean => {
  if (value === undefined || value === "") return fallback;
  return value === "true" || value === "1";
};

const int = (value: string | undefined, fallback: number): number => {
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : Number.NaN;
};

const list = (value: string | undefined): string[] =>
  (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

export const loadConfig = (env: Env = process.env): ServerConfig => {
  const problems: string[] = [];

  /** 前後の空白を落とした値と、落とす前後で変わったかどうか */
  const trimmedNames: string[] = [];
  const required = (name: string): string => {
    const value = env[name];
    // ⚠ **空かどうかは、空白を落としてから見る。**
    // 先に見ると、空白だけの値が「設定されている」ことになって素通りする
    if (value === undefined || value.trim() === "") {
      problems.push(`${name} が未設定です`);
      return "";
    }
    /**
     * ⚠ **前後の空白を落とす。**
     *
     * Secret Manager に値を入れるとき、末尾に改行が1バイト混ざることがある
     * （ターミナルで貼り付けて Enter を押すと入る）。
     *
     * これを落とさないと `clientId:secret\n` を Basic 認証に載せることになり、
     * cybozu は **401 invalid_client** を返す。
     * 本番で実際に起きて、同意画面のあとで止まった。
     *
     * ⚠ **落としたことは起動時に知らせる。** 黙って直すと、
     * 保存されている値が間違っていることに誰も気づかない。
     */
    const trimmed = value.trim();
    if (trimmed !== value) trimmedNames.push(name);
    return trimmed;
  };

  let issuer = required("OAUTH_ISSUER");
  const kintoneBaseUrl = required("KINTONE_BASE_URL");
  const cybozuClientId = required("CYBOZU_OAUTH_CLIENT_ID");
  const cybozuClientSecret = required("CYBOZU_OAUTH_CLIENT_SECRET");
  // 生の鍵か、KMS で包んだ鍵か。どちらか一方
  const encodedKey = env.TOKEN_ENCRYPTION_KEY?.trim() ?? "";
  const wrappedKey = env.TOKEN_ENCRYPTION_KEY_CIPHERTEXT?.trim() ?? "";
  const kmsKeyName = env.KMS_KEY_NAME?.trim() ?? "";
  const cookieKeys = list(env.COOKIE_KEYS);

  /**
   * issuer は https で、パスを持たないこと (§4.6)。
   *
   * ⚠ **`startsWith("https://")` で判定しない。** スキームは
   * 大文字小文字を区別しないので、`HTTPS://mcp.example.com` は
   * 正しい https の URL だが、その文字列比較は偽になる。
   * 署名鍵の必須化と Secure Cookie の強制がこの判定にぶら下がっているため、
   * **1文字大文字にするだけで両方とも外れていた**（実測で確認）。
   * 解釈した `protocol` で見る。
   */
  let issuerIsHttps = false;
  if (issuer) {
    try {
      const parsed = new URL(issuer);
      issuerIsHttps = parsed.protocol === "https:";
      if (!issuerIsHttps && !bool(env.ALLOW_INSECURE_ISSUER, false)) {
        problems.push("OAUTH_ISSUER は https である必要があります");
      }
      if (parsed.pathname !== "/") {
        problems.push("OAUTH_ISSUER にパスを付けないでください（well-known の配置が変わります）");
      }
      // 大文字のスキームやホストのまま使うと、resource が
      // Claude に入力してもらう URL と一致しなくなる。ここで正規化する
      issuer = parsed.origin;
    } catch {
      problems.push("OAUTH_ISSUER が URL として解釈できません");
    }
  }

  if (kintoneBaseUrl) {
    try {
      const parsed = new URL(kintoneBaseUrl);
      if (parsed.protocol !== "https:") {
        problems.push("KINTONE_BASE_URL は https である必要があります");
      }
    } catch {
      problems.push("KINTONE_BASE_URL が URL として解釈できません");
    }
  }

  let tokenEncryptionKey = Buffer.alloc(0);
  let encryptionKeySource: EncryptionKeySource = { kind: "plain", key: tokenEncryptionKey };

  if (wrappedKey || kmsKeyName) {
    // KMS で包む形。両方そろっていないと取り出せない
    if (!wrappedKey) problems.push("TOKEN_ENCRYPTION_KEY_CIPHERTEXT が未設定です");
    if (!kmsKeyName) problems.push("KMS_KEY_NAME が未設定です");
    if (encodedKey) {
      // どちらを使っているのか分からない状態にしない
      problems.push(
        "TOKEN_ENCRYPTION_KEY と TOKEN_ENCRYPTION_KEY_CIPHERTEXT は同時に設定できません",
      );
    }
    if (wrappedKey && kmsKeyName) {
      const ciphertext = Buffer.from(wrappedKey, "base64");
      if (ciphertext.length === 0) {
        problems.push("TOKEN_ENCRYPTION_KEY_CIPHERTEXT が base64 として解釈できません");
      }
      encryptionKeySource = { kind: "kms", keyName: kmsKeyName, ciphertext };
    }
  } else if (encodedKey) {
    tokenEncryptionKey = Buffer.from(encodedKey, "base64");
    if (tokenEncryptionKey.length !== 32) {
      problems.push(
        `TOKEN_ENCRYPTION_KEY は base64 で32バイトである必要があります (実際: ${tokenEncryptionKey.length}バイト)`,
      );
    }
    encryptionKeySource = { kind: "plain", key: tokenEncryptionKey };
  } else {
    problems.push(
      "TOKEN_ENCRYPTION_KEY または TOKEN_ENCRYPTION_KEY_CIPHERTEXT + KMS_KEY_NAME が未設定です",
    );
  }

  if (cookieKeys.length === 0) {
    problems.push(
      "COOKIE_KEYS が未設定です（全インスタンスで共有する必要があります。インスタンスごとに違うと認可が壊れます）",
    );
  }

  // 連携用ユーザー。片方だけでは意味が無い
  const integrationUsername = env.KINTONE_INTEGRATION_USERNAME?.trim() ?? "";
  const integrationPassword = env.KINTONE_INTEGRATION_PASSWORD?.trim() ?? "";
  let integrationUser: { username: string; password: string } | undefined;
  if (integrationUsername || integrationPassword) {
    if (!integrationUsername) problems.push("KINTONE_INTEGRATION_USERNAME が未設定です");
    if (!integrationPassword) problems.push("KINTONE_INTEGRATION_PASSWORD が未設定です");
    if (integrationUsername && integrationPassword) {
      integrationUser = { username: integrationUsername, password: integrationPassword };
    }
  }

  /**
   * アプリの許可リストは**ここで一度だけ正規化する**。
   * 表示・保存・実行が同じ値を見るようにする。
   */
  /**
   * CIMD で受け入れるホスト。
   *
   * ⚠ **ホスト名だけを書かせる。** URL を書かれると、
   * パスまで一致を見るのか曖昧になる。ここで形を確かめて弾く。
   */
  const cimdAllowedHosts = list(env.CIMD_ALLOWED_HOSTS).map((host) => host.toLowerCase());
  for (const host of cimdAllowedHosts) {
    if (host.includes("/") || host.includes(":")) {
      problems.push(
        `CIMD_ALLOWED_HOSTS にはホスト名だけを書いてください（URL やポートは不可）: ${host}`,
      );
    }
  }

  const normalizedAppIds = list(env.ALLOWED_APP_IDS);
  const allowedAppIds = normalizedAppIds.length > 0 ? normalizedAppIds.join(",") : undefined;

  const port = int(env.PORT, 8080);
  if (Number.isNaN(port)) problems.push("PORT が正の整数ではありません");

  // 0 を許すので int() は使えない（0 は「プロキシを信頼しない」の意味）
  const rawHops = env.TRUSTED_PROXY_HOPS;
  const trustedProxyHops = rawHops === undefined || rawHops === "" ? 1 : Number(rawHops);
  if (!Number.isInteger(trustedProxyHops) || trustedProxyHops < 0) {
    problems.push("TRUSTED_PROXY_HOPS は0以上の整数である必要があります");
  }

  const limits = {
    preAuthPerMinute: int(env.RATE_LIMIT_PRE_AUTH_PER_MINUTE, 60),
    preAuthTotalPerMinute: int(env.RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE, 600),
    grantPerMinute: int(env.RATE_LIMIT_GRANT_PER_MINUTE, 120),
    concurrentPerGrant: int(env.MAX_CONCURRENT_PER_GRANT, 4),
    concurrentTotal: int(env.MAX_CONCURRENT_TOTAL, 8),
    deadlineMs: int(env.REQUEST_DEADLINE_MS, 55_000),
    cybozuTimeoutMs: int(env.CYBOZU_TIMEOUT_MS, 10_000),
    storageTimeoutMs: int(env.STORAGE_TIMEOUT_MS, 5_000),
    authRequestDeadlineMs: int(env.AUTH_REQUEST_DEADLINE_MS, 10_000),
    maxBodyBytes: int(env.MAX_BODY_BYTES, 1_000_000),
  };
  for (const [name, value] of Object.entries(limits)) {
    if (Number.isNaN(value)) problems.push(`${name} が正の整数ではありません`);
  }

  const allowedHosts = list(env.ALLOWED_HOSTS);
  if (allowedHosts.length === 0) {
    // **公開前に必ず設定する。** 未設定のまま公開すると DNS rebinding に無防備。
    problems.push(
      "ALLOWED_HOSTS が未設定です（DNS rebinding 対策。デプロイで URL が確定してから設定します）",
    );
  }

  // 署名鍵。本番（https の issuer）では必須
  let jwks: { keys: Record<string, unknown>[] } | undefined;
  if (env.OIDC_JWKS) {
    try {
      const parsed: unknown = JSON.parse(env.OIDC_JWKS);
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        Array.isArray((parsed as { keys?: unknown }).keys)
      ) {
        jwks = parsed as { keys: Record<string, unknown>[] };
      } else {
        problems.push("OIDC_JWKS の形式が不正です（{ keys: [...] } である必要があります）");
      }
    } catch {
      problems.push("OIDC_JWKS が JSON として解釈できません");
    }
  } else if (issuerIsHttps) {
    problems.push(
      "OIDC_JWKS が未設定です（未設定だと oidc-provider に同梱された公開済みの固定鍵で署名します）",
    );
  }

  // 通信の期限がリクエストの締め切り以上だと、締め切りが先に来て通信だけが残る
  if (
    !Number.isNaN(limits.cybozuTimeoutMs) &&
    !Number.isNaN(limits.deadlineMs) &&
    limits.cybozuTimeoutMs >= limits.deadlineMs
  ) {
    problems.push("CYBOZU_TIMEOUT_MS は REQUEST_DEADLINE_MS より短くしてください");
  }

  // https の issuer で Secure を切るのは、ほぼ確実に設定ミス
  if (issuerIsHttps && !bool(env.SECURE_COOKIES, true)) {
    problems.push("SECURE_COOKIES=false は https の OAUTH_ISSUER と併用できません");
  }

  if (problems.length > 0) throw new ConfigError(problems);

  if (trimmedNames.length > 0) {
    // 落として動かしているが、保存されている値は直すべきなので必ず出す
    console.warn(
      JSON.stringify({
        severity: "WARNING",
        type: "config.trimmed",
        message: "前後の空白を落として読み込みました。保存されている値を直してください",
        names: trimmedNames,
      }),
    );
  }

  return {
    port,
    bindHost: env.BIND_HOST ?? "0.0.0.0",
    issuer,
    resource: `${issuer.replace(/\/$/, "")}/mcp`,
    allowedHosts,
    allowedOrigins: list(env.ALLOWED_ORIGINS),
    cimdAllowedHosts: cimdAllowedHosts,
    trustedProxyHops,
    kintoneBaseUrl,
    cybozuClientId,
    cybozuClientSecret,
    cybozuScopes: list(env.CYBOZU_OAUTH_SCOPES).length
      ? list(env.CYBOZU_OAUTH_SCOPES)
      : ["k:app_record:read", "k:app_settings:read"],
    tokenEncryptionKey,
    encryptionKeySource,
    cookieKeys,
    firestoreCollection: env.FIRESTORE_COLLECTION ?? "oidc",
    firestoreDatabaseId: env.FIRESTORE_DATABASE,
    jwks,
    secureCookies: bool(env.SECURE_COOKIES, true),
    allowedAppIds: allowedAppIds,
    integrationUser,
    capabilities: {
      // 既定は読み取りのみ (§5)
      recordRead: bool(env.ENABLE_RECORD_READ, true),
      recordWrite: bool(env.ENABLE_RECORD_WRITE, false),
      appRead: bool(env.ENABLE_APP_READ, true),
      appWrite: bool(env.ENABLE_APP_WRITE, false),
      spaceRead: bool(env.ENABLE_SPACE_READ, false),
      spaceWrite: bool(env.ENABLE_SPACE_WRITE, false),
      search: bool(env.ENABLE_SEARCH, false),
      fileDownload: bool(env.ENABLE_FILE_DOWNLOAD, false),
      allowDestructive: bool(env.ALLOW_DESTRUCTIVE, false),
    },
    limits,
  };
};

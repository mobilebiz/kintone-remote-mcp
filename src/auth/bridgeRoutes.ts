import { randomBytes } from "node:crypto";
import cookieParser from "cookie-parser";
import express, { type Request, type Response, type Router } from "express";
import type Provider from "oidc-provider";

import type { Bridge, ConsentSnapshot } from "./bridge.js";
import type { ConnectionGrantStore } from "./connectionGrant.js";
import type { Revoker } from "./revocation.js";
import { CybozuOAuthError, type CybozuOAuthClient } from "./cybozuOAuth.js";
import { renderConsentPage } from "./consentPage.js";
import { safeEqual, type SecretCipher } from "./crypto.js";
import type { Storage } from "./storage.js";

/**
 * 同意画面と cybozu からの戻りを受けるルート。
 *
 * provider の interaction からここへ飛んできて、cybozu を一周して、
 * `interactionFinished` で provider へ戻す (§4.5)。
 *
 * ## 経路が3つに分かれている理由
 *
 * ⚠ **`/oauth/callback` では provider の interaction Cookie が届かない。**
 * provider はそれを interaction のパスに限定して発行するため、
 * 管理外のパスである callback では `interactionDetails()` が使えない。
 *
 * → callback では**確認と保存だけ**を行い、
 *   provider の Cookie が届く `/interaction/:uid/finish` へ戻してから
 *   `interactionFinished()` を呼ぶ。
 *
 * ```
 *  GET  /interaction/:uid          同意画面（副作用なし）
 *  POST /interaction/:uid          同意 → cybozu へリダイレクト
 *  GET  /oauth/callback            state 検証 → token 交換 → 保存 → finish へ
 *  GET  /interaction/:uid/finish   provider へ結果を返す
 * ```
 *
 * ## Cookie を2つ使う理由
 *
 * provider の interaction Cookie は届かないので、
 * **独立したブリッジ Cookie** を発行し、Path を callback に届く範囲にする (§4.10)。
 */

const BRIDGE_COOKIE = "kintone_bridge";
const CSRF_COOKIE = "kintone_consent_csrf";

/** callback と finish の間で結果を受け渡すための保存モデル */
const COMPLETION_MODEL = "BridgeCompletion";
const COMPLETION_TTL = 120;

export type BridgeRoutesOptions = {
  provider: Provider;
  bridge: Bridge;
  cybozu: CybozuOAuthClient;
  grants: ConnectionGrantStore;
  revoker: Revoker;
  storage: Storage;
  cipher: SecretCipher;
  /** 同意画面に出す kintone のホスト名 */
  kintoneHost: string;
  /** 同意画面に出す権限の説明 */
  /**
   * 同意画面に出す内容を作る。
   *
   * ⚠ **表示と記録を同じ値から作る。** 別々にすると、
   * 「画面に出していないものに同意したことになる」状態を作れる。
   *
   * ⚠ **呼ぶのは同意画面を出すときだけ。** callback で呼び直すと、
   * その間に設定が変わっていたり、別の設定のインスタンスが受けたりして、
   * 出していない内容に同意したことになる。
   */
  consent: () => ConsentSnapshot & { permissions: string[] };
  /**
   * 接続の寿命（秒）。
   *
   * ⚠ provider の `Grant` と**同じ値にする**。片方だけ切れると、
   * 「認可は切れているのに資格情報は残っている」状態になる。
   */
  connectionTtlSeconds: number;
  /**
   * このサーバー自身の resource と、アクセストークンに載せる scope。
   *
   * ⚠ **クライアントが要求した scope をそのまま付けない。**
   * Claude が送ってくるのは OIDC の `openid` で、
   * これを resource scope として付けると `/mcp` の scope 検証で落ちる。
   * 付けるのは**このサーバーが定義した scope**。
   */
  resource: string;
  resourceScopes: string[];
  /** Cookie に Secure を付けるか。既定 true */
  secureCookies?: boolean;
  /** 失敗をサーバー側に残すフック。**秘密は渡らない** */
  /**
   * 失敗の記録。
   *
   * `detail` は**秘密を含まない診断**（上流のステータス・エラーコード・
   * 応答のフィールド名と型）。これが無いと「失敗した」しか残らず、
   * **原因に辿り着けない**（実際に辿り着けなかった）。
   */
  onFailure?: (info: { stage: string; reason: string; detail?: string }) => void;
  now?: () => number;
};

/**
 * 上流の失敗を、秘密を含まない形で1行にする。
 *
 * ⚠ **`message` を載せない。** 例外にはリクエスト設定（= 資格情報）が
 * 入っていることがある。載せてよいのは、こちらで組み立てた値だけ。
 */
const describeUpstream = (error: unknown): string => {
  if (error instanceof CybozuOAuthError) {
    const parts = [
      error.status === undefined ? undefined : `status=${error.status}`,
      error.upstreamError === undefined ? undefined : `error=${error.upstreamError}`,
      error.shape === undefined ? undefined : `shape=${error.shape}`,
    ].filter((part): part is string => part !== undefined);
    return parts.length > 0 ? parts.join(" ") : "cybozu-error";
  }
  // 種別だけ。これも値ではない
  return error instanceof Error ? `kind=${error.name}` : "kind=unknown";
};

/** 応答からの参照元漏れを防ぐ。`code` / `state` が URL に載るため */
const applySecurityHeaders = (res: Response): void => {
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cache-Control", "no-store");
};

const cookieOptions = (secure: boolean, path: string) => ({
  httpOnly: true,
  secure,
  sameSite: "lax" as const,
  path,
});

/** ユーザーに見せる汎用の失敗ページ。理由は載せない */
const fail = (res: Response, status: number, message: string): void => {
  applySecurityHeaders(res);
  res.status(status).type("text/plain; charset=utf-8").send(message);
};

const readCookie = (req: Request, name: string): string | undefined => {
  const value = (req.cookies as Record<string, unknown> | undefined)?.[name];
  return typeof value === "string" ? value : undefined;
};

export const createBridgeRoutes = (options: BridgeRoutesOptions): Router => {
  const router = express.Router();
  const secure = options.secureCookies ?? true;
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));

  router.use(cookieParser());
  // 同意フォームの POST を読むため。JSON は受けない。
  router.use(express.urlencoded({ extended: false, limit: "16kb" }));

  /** 同意画面。**GET では何も起こさない** */
  router.get("/interaction/:uid", async (req: Request, res: Response) => {
    applySecurityHeaders(res);

    let details;
    try {
      details = await options.provider.interactionDetails(req, res);
    } catch {
      options.onFailure?.({ stage: "interaction", reason: "details-unavailable" });
      fail(res, 400, "この認可リクエストは期限切れです。最初からやり直してください。");
      return;
    }

    const csrfToken = randomBytes(32).toString("base64url");
    res.cookie(CSRF_COOKIE, csrfToken, cookieOptions(secure, `/interaction/${details.uid}`));

    /**
     * ⚠ **ここで同意の内容を確定する。**
     *
     * 画面を出したインスタンスと、承認を受けるインスタンスは別でありうる
     * （デプロイをまたぐ、複数インスタンス）。承認側で作り直すと、
     * **出していない内容に同意したことになる**（外部レビューで再現された）。
     *
     * CSRF トークンに束縛するので、**この画面から出た承認だけ**が取り出せる。
     */
    const snapshot = options.consent();
    await options.bridge.rememberConsent(details.uid, csrfToken, snapshot);

    const clientId = String(details.params.client_id ?? "");
    const client = await options.provider.Client.find(clientId);
    const redirectUri = String(details.params.redirect_uri ?? "");

    res.type("text/html; charset=utf-8").send(
      renderConsentPage({
        clientName: client?.clientName ?? clientId ?? "不明なクライアント",
        /**
         * ⚠ **CIMD で来たクライアントの名前は、相手の自称。**
         * provider はその場合だけ `clientIdMetadataDocument` を立てる。
         * 事前登録のものと同じ見た目で出すと、名乗るだけで化けられる。
         */
        clientNameSource:
          (client as { clientIdMetadataDocument?: boolean } | undefined)
            ?.clientIdMetadataDocument === true
            ? "self-asserted"
            : "registered",
        clientId,
        kintoneHost: options.kintoneHost,
        redirectHost: redirectUri ? new URL(redirectUri).host : "不明",
        // ⚠ 表示と保存を**同じ値**から作る。別々にすると意味が無い
        permissions: snapshot.permissions,
        formAction: `/interaction/${details.uid}`,
        csrfToken,
      }),
    );
  });

  /** 同意の受け付け。**ここで初めて cybozu へ飛ばす** */
  router.post("/interaction/:uid", async (req: Request, res: Response) => {
    applySecurityHeaders(res);

    const body = req.body as Record<string, unknown> | undefined;
    const submitted = typeof body?.csrf === "string" ? body.csrf : "";
    const expected = readCookie(req, CSRF_COOKIE);
    if (expected === undefined || !safeEqual(submitted, expected)) {
      options.onFailure?.({ stage: "consent", reason: "csrf-mismatch" });
      fail(res, 400, "フォームの送信が正しくありません。最初からやり直してください。");
      return;
    }

    let details;
    try {
      details = await options.provider.interactionDetails(req, res);
    } catch {
      options.onFailure?.({ stage: "consent", reason: "details-unavailable" });
      fail(res, 400, "この認可リクエストは期限切れです。最初からやり直してください。");
      return;
    }

    if (body?.decision !== "allow") {
      await options.provider.interactionFinished(req, res, {
        error: "access_denied",
        error_description: "ユーザーが許可しませんでした",
      });
      return;
    }

    /**
     * ⚠ **画面に出した内容を取り出す。ここで作り直さない。**
     *
     * 無ければ承認しない。画面を出していない承認になるため。
     */
    const consent = await options.bridge.takeConsent(details.uid, expected);
    if (!consent) {
      options.onFailure?.({ stage: "consent", reason: "consent-not-found" });
      fail(res, 400, "同意の内容を確認できませんでした。最初からやり直してください。");
      return;
    }

    // 接続ごとの内部主体。kintone のユーザー名ではない (§4.10)。
    // 再接続でも新しい値を作るので、既存の接続の資格情報を上書きしない。
    const accountId = randomBytes(24).toString("base64url");
    const started = await options.bridge.start({
      interactionUid: details.uid,
      accountId,
      consent,
    });

    // ブリッジ Cookie。provider の interaction Cookie とは別物で、
    // callback に届く必要があるので Path をルートにする。
    res.cookie(BRIDGE_COOKIE, started.browserSecret, cookieOptions(secure, "/"));

    res.redirect(302, options.cybozu.buildAuthorizationUrl(started.state));
  });

  /**
   * cybozu からの戻り。
   *
   * **一致・期限内・未使用・同一ブラウザ**の4つを確かめてから token 交換する。
   * provider の Cookie はここには届かないので、`interactionFinished` は呼べない。
   */
  router.get("/oauth/callback", async (req: Request, res: Response) => {
    applySecurityHeaders(res);
    res.clearCookie(BRIDGE_COOKIE, { path: "/" });

    const state = typeof req.query.state === "string" ? req.query.state : undefined;
    const code = typeof req.query.code === "string" ? req.query.code : undefined;

    if (!state || !code) {
      options.onFailure?.({ stage: "callback", reason: "missing-parameters" });
      fail(res, 400, "認可の応答が正しくありません。最初からやり直してください。");
      return;
    }

    const outcome = await options.bridge.consume(state, readCookie(req, BRIDGE_COOKIE));
    if (!outcome.ok) {
      options.onFailure?.({ stage: "callback", reason: outcome.reason });
      fail(res, 400, "認可の応答を確認できませんでした。最初からやり直してください。");
      return;
    }

    let tokens;
    try {
      tokens = await options.cybozu.exchangeCode(code);
    } catch (error) {
      // ⚠ 上流の交換に失敗。無理に再交換せず、再認可に戻す (§4.10)。
      //
      // ⚠ **例外を捨てない。** `catch {}` にしていたため、
      // cybozu が何を返したのかがどこにも残らなかった。
      // 値は載せない。**ステータス・エラーコード・応答の形**だけ。
      options.onFailure?.({
        stage: "callback",
        reason: "token-exchange-failed",
        detail: describeUpstream(error),
      });
      fail(res, 502, "kintone との連携に失敗しました。最初からやり直してください。");
      return;
    }

    /**
     * この接続の絶対期限。**ここで1度だけ決める。**
     *
     * ⚠ **接続と provider の Grant で別々に計算してはいけない。**
     * 接続は callback、Grant は finish で計算していたので、
     * その間が延びるとそのぶんずれた（90秒遅らせると90秒ずれることを
     * 外部レビューが再現）。**同じ瞬間に切れるべきものが、別の時刻を持つ。**
     */
    const connectionExpiresAt = now() + options.connectionTtlSeconds;

    try {
      // ⚠ **認可の途中で固定したものを、そのまま記録する。**
      // ここで設定を読み直すと、利用者が同意していない権限が付く
      await options.grants.create(outcome.transaction.accountId, tokens, {
        ...outcome.transaction.consent,
        // ⚠ **接続にも絶対期限を付ける。** provider の Grant だけに付けても、
        // こちらに保管した cybozu の資格情報が残り続ける
        expiresAt: connectionExpiresAt,
      });
    } catch {
      // 上流の交換は成功したのに保存に失敗した状態。
      // リフレッシュトークンは発行済みだが手元に無い。再認可に戻すしかない。
      options.onFailure?.({ stage: "callback", reason: "grant-save-failed" });
      fail(res, 500, "接続の保存に失敗しました。最初からやり直してください。");
      return;
    }

    // 結果を finish へ引き渡す。URL には載せない（ログに残るため）。
    await options.storage.upsert(
      COMPLETION_MODEL,
      options.cipher.hash(outcome.transaction.interactionUid),
      {
        // finish 側で Grant の寿命を合わせるために、決めた期限を運ぶ
        payload: {
          accountId: outcome.transaction.accountId,
          connectionExpiresAt,
        },
        expiresAt: now() + COMPLETION_TTL,
        grantId: undefined,
        uidHash: undefined,
        userCodeHash: undefined,
      },
    );

    res.redirect(302, `/interaction/${encodeURIComponent(outcome.transaction.interactionUid)}/finish`);
  });

  /**
   * provider へ結果を返す。
   *
   * このパスなら provider の interaction Cookie が届く。
   */
  router.get("/interaction/:uid/finish", async (req: Request, res: Response) => {
    applySecurityHeaders(res);

    let details;
    try {
      details = await options.provider.interactionDetails(req, res);
    } catch {
      options.onFailure?.({ stage: "finish", reason: "details-unavailable" });
      fail(res, 400, "この認可リクエストは期限切れです。最初からやり直してください。");
      return;
    }

    const key = options.cipher.hash(details.uid);
    const completion = await options.storage.find(COMPLETION_MODEL, key);
    const accountId = completion?.payload.accountId;

    // TTL は掃除であって認可判定ではない (§4.9)。使うたびに自分で見る。
    const expired = completion?.expiresAt !== undefined && completion.expiresAt <= now();
    if (typeof accountId !== "string" || expired) {
      options.onFailure?.({ stage: "finish", reason: "no-completion" });
      fail(res, 400, "認可の結果を確認できませんでした。最初からやり直してください。");
      return;
    }

    // ⚠ **検索と削除を分けない。**
    // 分けると、同じ Cookie で finish を並行実行したときに両方が通り、
    // Grant が2個作られる（外部レビューで再現された）。
    // 未使用を条件にした更新で、勝者だけを先へ進める。
    // 消さずに「使用済み」で残すのは、遅れて届いた保存による再生成も防ぐため。
    const consumed = await options.storage.consume(COMPLETION_MODEL, key, now());
    if (consumed !== "consumed") {
      options.onFailure?.({ stage: "finish", reason: "completion-already-used" });
      fail(res, 400, "この認可はすでに完了しています。最初からやり直してください。");
      return;
    }

    /**
     * ⚠ **接続と同じ絶対期限で切る。**
     *
     * 設定の値からここで数え直すと、callback から finish までの時間だけ
     * 長くなる。接続が切れているのに Grant だけ生きている状態を作らない
     * （その逆も作らない）。記録が無ければ設定の値に戻す。
     */
    const connectionExpiresAt = completion?.payload.connectionExpiresAt;
    const grantExpiresIn =
      typeof connectionExpiresAt === "number"
        ? Math.max(1, connectionExpiresAt - now())
        : options.connectionTtlSeconds;

    /**
     * ⚠ **型定義に `expiresIn` が無いが、`BaseToken` の constructor は受け取る**
     * (`oidc-provider/lib/models/base_token.js`)。
     * 省くと `ttl.Grant` から**保存する瞬間に**数え直される。
     * 効いていることは、保存されたレコードの期限を見るテストで確かめている。
     */
    const grantInput: ConstructorParameters<typeof options.provider.Grant>[0] & {
      expiresIn: number;
    } = {
      accountId,
      clientId: String(details.params.client_id ?? ""),
      expiresIn: grantExpiresIn,
    };

    const grant = new options.provider.Grant(grantInput);
    grant.addOIDCScope("openid");
    // resource scope は**こちらが決めた値**。クライアントの要求をそのまま使わない。
    grant.addResourceScope(options.resource, options.resourceScopes.join(" "));
    const grantId = await grant.save();

    // 切断のときに provider の Grant と接続 grant の両方を失効させる必要がある。
    // 接続側に grantId を控え、**Grant 文書とは独立した対応レコードも**残す
    // （provider の失効処理は Grant を並行して消すため）。
    await options.grants.attachProviderGrant(accountId, grantId);
    // ⚠ 接続・Grant と**同じ絶対期限**。対応表だけが残らないようにする
    await options.revoker.rememberGrantOwner(
      grantId,
      accountId,
      typeof connectionExpiresAt === "number" ? connectionExpiresAt : undefined,
    );

    await options.provider.interactionFinished(req, res, {
      login: { accountId },
      consent: { grantId },
    });
  });

  return router;
};

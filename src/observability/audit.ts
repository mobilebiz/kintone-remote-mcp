import { summarizeError, tenantOf } from "./redact.js";

/**
 * 監査ログ (§7.5)。
 *
 * ## kintone 側の監査には頼れない
 *
 * 当初は「OAuth にすれば kintone 側で誰が操作したか分かる」と考えていたが、
 * **cybozu の token 応答にユーザー識別子が含まれない**ため、
 * こちらは kintone のユーザー名を知らない (§4.10)。
 *
 * → **確実に取れるものだけを記録する。**
 * `client_id` / grant ID / 相関 ID は必ず取れる。
 * kintone のユーザー名は「取得手段が確認できたら足す」扱いにして、
 * 取れないものを記録するつもりになっている状態を作らない。
 *
 * ## 出力形式
 *
 * Cloud Logging が構造化ログとして拾えるよう、**1行1 JSON** で標準出力へ出す。
 * `severity` は Cloud Logging の予約フィールド。
 */

export type Severity = "INFO" | "WARNING" | "ERROR";

/** 認可の経路で起きたこと */
export type AuthEvent =
  | "authorization_started"
  | "consent_granted"
  | "consent_denied"
  | "bridge_rejected"
  | "connection_created"
  | "token_issued"
  | "token_refreshed"
  | "reauth_required"
  | "connection_revoked";

type BaseRecord = {
  /** リクエストを貫通させる。ユーザーへの応答にも同じ値を返す */
  correlationId: string;
  /** 接続の内部主体。kintone のユーザー名ではない */
  accountId?: string | undefined;
  /** provider のクライアント */
  clientId?: string | undefined;
  /** provider の Grant */
  grantId?: string | undefined;
};

export type AuditSink = (entry: Record<string, unknown>) => void;

export type AuditOptions = {
  /** 出力先。既定は標準出力へ1行1 JSON */
  sink?: AuditSink;
  /** 接続先の kintone。ホスト名だけを記録する */
  kintoneBaseUrl?: string;
  now?: () => string;
};

const defaultSink: AuditSink = (entry) => {
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(entry));
};

export const createAuditLogger = (options: AuditOptions = {}) => {
  const sink = options.sink ?? defaultSink;
  const now = options.now ?? (() => new Date().toISOString());
  const tenant = options.kintoneBaseUrl ? tenantOf(options.kintoneBaseUrl) : undefined;

  const emit = (
    severity: Severity,
    type: string,
    record: BaseRecord,
    extra: Record<string, unknown> = {},
  ): void => {
    sink({
      severity,
      time: now(),
      type,
      tenant,
      ...record,
      ...extra,
    });
  };

  return {
    /** 認可の経路。**`code` / `state` / `code_verifier` は絶対に渡さない** */
    auth(
      event: AuthEvent,
      record: BaseRecord,
      /** `detail` は**秘密を含まない診断**に限る（上流のステータス・コード・応答の形） */
      extra: { reason?: string; detail?: string } = {},
    ): void {
      const severity: Severity =
        event === "bridge_rejected" || event === "reauth_required" ? "WARNING" : "INFO";
      emit(severity, `auth.${event}`, record, extra);
    },

    /**
     * ツールの実行結果。
     *
     * **`isError: true` も失敗として集計する。** MCP はツールの失敗を
     * HTTP 200 で返すので、ステータスだけ見ていると失敗が見えない (§7.5)。
     */
    toolCall(
      record: BaseRecord & {
        toolName: string;
        /** 対象のアプリ ID など。**本文は入れない** */
        targets?: string[] | undefined;
        ok: boolean;
        /** 失敗の分類。errorBoundary の FailureKind */
        failureKind?: string | undefined;
        /** kintone が返したエラーコード。**問い合わせるときの手がかりになる** */
        kintoneCode?: string | undefined;
        /** kintone が返したエラー ID。サイボウズへの問い合わせで使う */
        kintoneId?: string | undefined;
        /** 上流の HTTP ステータス */
        status?: number | undefined;
        /**
         * 誰として実行されたか。
         *
         * ⚠ `integration` は**接続した本人ではなく連携ユーザー**として実行されたもの。
         * これが残っていないと、kintone 側の監査で連携ユーザーの操作を見たときに、
         * **誰の依頼だったのかを辿れない**。
         */
        identity?: "user" | "integration" | undefined;
        durationMs: number;
      },
    ): void {
      const {
        toolName,
        targets,
        ok,
        failureKind,
        kintoneCode,
        kintoneId,
        status,
        identity,
        durationMs,
        ...base
      } = record;
      emit(ok ? "INFO" : "WARNING", "tool.call", base, {
        toolName,
        targets,
        ok,
        failureKind,
        kintoneCode,
        kintoneId,
        status,
        identity,
        durationMs,
      });
    },

    /** 流量制限で止めたこと。**止めた事実を残さないと、詰まりの原因が分からない** */
    rateLimited(record: BaseRecord & { scope: string; limit: number }): void {
      const { scope, limit, ...base } = record;
      emit("WARNING", "rate_limit.blocked", base, { scope, limit });
    },

    /**
     * 想定外の失敗。
     *
     * **例外そのものを渡してよい。** ここで種別とステータスだけに落とす。
     * 呼び出し側が「安全な形に直してから渡す」運用にすると、いつか忘れる。
     */
    unexpected(record: BaseRecord & { where: string }, error: unknown): void {
      const { where, ...base } = record;
      emit("ERROR", "unexpected", base, { where, error: summarizeError(error) });
    },
  };
};

export type AuditLogger = ReturnType<typeof createAuditLogger>;

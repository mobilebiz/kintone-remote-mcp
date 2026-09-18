/**
 * 同意画面。
 *
 * **CSRF トークン付きの POST で受ける** (§4.6)。GET で副作用を起こさない。
 *
 * 表示する内容は設計で決めた4つ:
 * 登録済みクライアント名 / 接続先の kintone ドメイン / 要求する権限 / 転送先ホスト。
 *
 * **継続アクセスへの同意もここで伝える。** `offline_access` に依存せず
 * リフレッシュトークンを発行する方針 (§4.10) を採ったため、
 * scope の表示だけではユーザーに伝わらない。
 */

/** HTML の文脈に値を埋めるときのエスケープ */
export const escapeHtml = (value: string): string =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

export type ConsentView = {
  /**
   * クライアント名。
   *
   * ⚠ **事前登録のものだけとは限らない。**
   * CIMD で来たクライアントの名前は、`client_id` の URL の先にある文書から
   * 取ったもの、つまり**相手が自分で名乗った文字列**である。
   * `clientNameSource` で区別すること。
   */
  clientName: string;
  /**
   * その名前の出所。
   *
   * - `registered`: 運用者が設定に書いた（信用してよい）
   * - `self-asserted`: 相手の文書から取った（**信用できない**）
   */
  clientNameSource: "registered" | "self-asserted";
  /**
   * `client_id`。CIMD のときは HTTPS の URL。
   *
   * ⚠ **自称の名前より、こちらが身元に近い。**
   * URL のホストは許可リストと照合済みで、文書はそこから取っている。
   */
  clientId: string;
  /** 接続先の kintone ドメイン（ホスト名） */
  kintoneHost: string;
  /** 認可後に飛ぶ先のホスト */
  redirectHost: string;
  /** 要求する権限の説明 */
  permissions: string[];
  /** フォームの POST 先 */
  formAction: string;
  csrfToken: string;
};

/**
 * 接続元の表示。
 *
 * ⚠ **自称の名前を、登録済みのものと同じ見た目で出さない。**
 * CIMD では、`client_id` の URL を用意できる者が名前を自由に決められる。
 * 「Claude」と名乗るだけなら誰にでもできる。
 *
 * → **照合済みのホストを主に出し、名前は自称として添える。**
 */
const describeClient = (view: ConsentView): string => {
  const name = escapeHtml(view.clientName);
  if (view.clientNameSource === "registered") return name;

  let host = view.clientId;
  try {
    host = new URL(view.clientId).host;
  } catch {
    // URL として読めないものはここに来ない（許可リストの照合を通らない）が、
    // 表示のために落ちないようにする
  }
  return `${escapeHtml(host)}<br><span class="self-asserted">「${name}」と名乗っています（このサーバーに登録された名前ではありません）</span>`;
};

export const renderConsentPage = (view: ConsentView): string => {
  const permissions = view.permissions
    .map((permission) => `<li>${escapeHtml(permission)}</li>`)
    .join("");

  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>kintone への接続を許可しますか</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; padding: 1.5rem; line-height: 1.7; }
  main { max-width: 32rem; margin: 0 auto; }
  dl { background: #f5f5f5; padding: 1rem; border-radius: .5rem; }
  dt { font-size: .85rem; color: #555; }
  dd { margin: 0 0 .75rem; font-weight: 600; word-break: break-all; }
  dd:last-child { margin-bottom: 0; }
  ul { padding-left: 1.2rem; }
  .note { font-size: .9rem; color: #444; border-left: 3px solid #999; padding-left: .75rem; }
  .self-asserted { font-size: .85rem; color: #a33; font-weight: 400; }
  button { font-size: 1rem; padding: .75rem 1.5rem; border-radius: .5rem; border: 0; cursor: pointer; }
  .allow { background: #0b5; color: #fff; }
  .deny { background: #eee; }
  form { display: inline; }
</style>
</head>
<body>
<main>
  <h1>kintone への接続を許可しますか</h1>
  <dl>
    <dt>接続元</dt><dd>${describeClient(view)}</dd>
    <dt>接続先の kintone</dt><dd>${escapeHtml(view.kintoneHost)}</dd>
    <dt>許可後の転送先</dt><dd>${escapeHtml(view.redirectHost)}</dd>
  </dl>
  <h2>許可する操作</h2>
  <ul>${permissions}</ul>
  <p class="note">
    許可すると、この接続を解除するまで、${escapeHtml(view.clientName)} はあなたに代わって
    上記の操作を継続して行えます。ブラウザを閉じた後も有効です。
  </p>
  <form method="post" action="${escapeHtml(view.formAction)}">
    <input type="hidden" name="csrf" value="${escapeHtml(view.csrfToken)}">
    <button type="submit" name="decision" value="allow" class="allow">許可する</button>
    <button type="submit" name="decision" value="deny" class="deny">許可しない</button>
  </form>
</main>
</body>
</html>`;
};

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
  /** 登録済みのクライアント名。ユーザー入力ではない */
  clientName: string;
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
    <dt>接続元</dt><dd>${escapeHtml(view.clientName)}</dd>
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

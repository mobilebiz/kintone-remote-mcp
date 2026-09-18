# 運用の指針

立てたあと、**どう設定して使うか**の話です。
手順は [deployment.md](deployment.md)、確かめ方は [space-test.md](space-test.md) にあります。

---

## まず: 段階を踏む

一度に全部を有効にしないでください。**広げるのは簡単で、狭めるのは難しい**からです。

| 段階 | 設定 | 何ができるか |
| --- | --- | --- |
| 1 | 既定のまま | レコードとアプリ設定の**参照だけ** |
| 2 | `ENABLE_RECORD_WRITE=true` + スコープに `k:app_record:write` | レコードの登録・更新 |
| 3 | `KINTONE_INTEGRATION_*` | スペース操作と横断検索 |
| 4 | `ALLOW_DESTRUCTIVE=true` | 削除 |

> [!IMPORTANT]
> **段階を上げたら、利用者につなぎ直してもらう必要があります。** 理由は2つあり、別物です。
>
> | 仕組み | いつ効くか |
> | --- | --- |
> | **cybozu のスコープ** | `CYBOZU_OAUTH_SCOPES` を広げたとき。トークンの発行時にスコープが決まるので、既存のトークンには及ばない |
> | **このサーバーの同意** | 公開ツールが増えたとき。同意した時点の集合を記録し、実行時に現在の設定との積を取る |
>
> 前者は kintone が `403 CB_OA01` を返します。後者は**ツールが一覧に出ません**。
> どちらも「つなぎ直してください」で直ります。

---

## ID 認証（連携ユーザー）をどう設定するか

いちばん判断が要るところです。

### そもそも要りますか

連携ユーザーが必要なのは、**次の5つを使うときだけ**です。

```
kintone-get-space / kintone-update-space
kintone-delete-space / kintone-add-space-from-template
kintone-search
```

**残り22個は OAuth だけで動きます。** レコードの検索・参照・登録・更新、
アプリ設定の参照、フォームの変更は、すべて本人の権限で動きます。

> [!TIP]
> **「横断検索が使いたい」だけなら、いったん諦めることを勧めます。**
>
> `kintone-search` は **API ラボ**（検討中の新機能）の API を使っており、
> サイボウズは「テスト環境だけでの利用を推奨します」と明記しています。
> そのために主体が入れ替わる仕組みを常用するのは、釣り合いません。

### 要るなら: 専用ユーザーを作る

| 設定 | 理由 |
| --- | --- |
| **専用ユーザーを新規に作る** | 既存の誰かを使うと、その人の権限が全部効く |
| **2要素認証を無効にする** | 有効だと REST API が実行できない（サイボウズも専用ユーザーを推奨） |
| **参加するスペースを絞る** | ここが実質の権限境界になる |
| **管理者権限を与えない** | パスワード認証にスコープは無い。できること全部ができる |

> [!CAUTION]
> **パスワード認証にはスコープがありません。**
> `CYBOZU_OAUTH_SCOPES` はこのユーザーには一切かかりません。
> **参加させるスペースとアプリ権限が、唯一の絞り込みです。**

### 実際にどう動くか

本番で実測した記録です。

**① 監査ログで主体が分かれる**

```
identity=user         kintone-get-records   ['163']   ok=True
identity=integration  kintone-get-space     ['space:24'] ok=True
```

`identity` が `integration` のものは、**接続した本人ではなく連携ユーザー**が実行しています。
`targets` には触った対象（アプリ ID / `space:N`）が入ります。

**② 本人に見えないものが見える**

第三者が管理する非公開スペース（連携ユーザーだけがメンバー、接続した本人は非メンバー）
の内容が、**本人に返りました**。

```
identity=integration  kintone-get-space  ['space:25']  ok=True
```

同じ本人が kintone の画面で開くと `権限がありません (CB_NO02)` です。

**③ 横断検索は、アプリの権限も通り抜ける**

同じ本人・同じ会話・同じアプリに対して:

```
identity=user         kintone-get-records  ['164']  403 CB_NO02   ← 拒否
identity=integration  kintone-search                ok=True       ← 中身が返る
```

kintone のアプリ権限は正しく効いています。**その上を検索が通り抜けます。**
検索結果には検索語の周辺テキストが含まれるので、
**レコードを取得するまでもなく漏れます。**

**④ 連携ユーザーの権限が無ければ、ちゃんと落ちる**

```
identity=integration  kintone-get-space  ['space:1']  403 CB_NO02
```

連携ユーザーが非公開スペースのメンバーでない場合です。
**権限を絞る意味がある**ことの裏返しでもあります。

**⑤ 同意画面に出る**

```
スペースの作成・変更・スペースの参照・横断検索
（⚠ あなたではなく連携用ユーザー「kintone-mcp-integration」として実行されます。
  そのため、あなたが参加していない非公開スペースの内容も読めます）
```

**⑥ 名前を変えると、既存の接続からは消える**

同意は**その名前のユーザーとして実行されること**に紐づいています。
`KINTONE_INTEGRATION_USERNAME` を変えると、既存の接続では
**公開ツールが 17個 → 13個**になり、5つが一覧から消えます。

### パスワードを変えるとき

```sh
# 1. 新しい版を足す（⚠ echo を使わない。末尾の改行が混ざる）
read -rs "P?新しいパスワード: " && printf '%s' "$P" | \
  gcloud secrets versions add kintone-mcp-integration-password --data-file=- --project=$PROJECT_ID; unset P

# 2. Cloud Run に「新しい版を使え」と伝える（⚠ これを忘れると古いまま動く）
gcloud run services update $SERVICE --region=$REGION --project=$PROJECT_ID \
  --update-secrets="KINTONE_INTEGRATION_PASSWORD=kintone-mcp-integration-password:2"
```

> [!WARNING]
> **パスワードが違っても、サーバーは正常に起動します。**
> 検証は「値があるか」しか見ません。間違いはツール実行時に出ます。
>
> | 応答 | 意味 |
> | --- | --- |
> | `401` | **認証に失敗**。パスワードが違う |
> | `403` | 認証は通り、**権限が無い**（正常な拒否） |
>
> 401 を繰り返すと kintone 側でロックされます。1回落ちたら先に確かめてください。

### やめるとき

```sh
gcloud run services update $SERVICE --region=$REGION --project=$PROJECT_ID \
  --remove-env-vars="KINTONE_INTEGRATION_USERNAME,ENABLE_SPACE_READ,ENABLE_SPACE_WRITE,ENABLE_SEARCH" \
  --remove-secrets="KINTONE_INTEGRATION_PASSWORD"
```

> [!WARNING]
> **シークレット由来の変数は `--remove-secrets` でしか消えません。**
> `--remove-env-vars` に書いても残ります。2度踏みました。

---

## アプリを絞るか（`ALLOWED_APP_IDS`）

絞ると次の2つが効きます。

- 許可外のアプリは、**kintone に問い合わせる前に拒否**されます
  （監査ログ: `failureKind=app_not_allowed`、kintone のステータスが付かない）
- `kintone-get-apps` の結果も絞られます

> [!IMPORTANT]
> **絞ると、スペース操作と横断検索は1つも公開されません。**
>
> これらは引数にアプリ ID を持たないので、境界の判定が**素通り**します。
> 拒否しているように見えて何も見ていない状態を避けるため、出しません。
>
> **つまり `ALLOWED_APP_IDS` と連携ユーザーは両立しません。** どちらを取るか決めてください。

---

## 削除をどう扱うか

> [!CAUTION]
> **cybozu のスコープでは、登録・更新・削除がすべて `k:app_record:write` に含まれます。**
> **削除だけを止める手段が kintone 側にありません。**
> `ALLOW_DESTRUCTIVE` が唯一の歯止めです。

有効にするなら、**`ALLOWED_APP_IDS` と併用**することを強く勧めます。
スペースの削除は**置かれているアプリごと**使えなくします。

なお、**スペースの公開範囲（`isPrivate`）の変更は、このサーバーが常に拒否します**。
削除ではないので `ALLOW_DESTRUCTIVE` では止まらず、
データは消えないのに**見えなかったものが全社に見えるようになる**ためです。

---

## 事前登録していないクライアントを受け入れるか（`CIMD_ALLOWED_HOSTS`）

既定では無効です。有効にするときは**ホスト名を挙げる**必要があります。

```sh
CIMD_ALLOWED_HOSTS=chatgpt.com
```

> [!WARNING]
> **CIMD で来たクライアントの名前は、相手の自称です。**
> 同意画面では照合済みのホストを主に出し、名前は「こう名乗っています」と添えます。
>
> ホスト名は**完全一致**です。`a.chatgpt.com` も `evil-chatgpt.com` も通りません。

---

## 監査ログの読み方

```sh
gcloud logging read 'jsonPayload.type="tool.call"' --project=$PROJECT_ID \
  --limit=30 --freshness=1h \
  --format='value(timestamp,jsonPayload.identity,jsonPayload.toolName,jsonPayload.ok,jsonPayload.targets,jsonPayload.failureKind)'
```

| 見るところ | 意味 |
| --- | --- |
| `identity` | **`user`（本人）か `integration`（連携ユーザー）か** |
| `targets` | 触った対象（アプリ ID / `space:N`） |
| `failureKind=app_not_allowed` | **こちらが拒否**。`ALLOWED_APP_IDS` に足せば通る |
| `failureKind=forbidden_argument` | **こちらが拒否**。設定では通らない（公開範囲の変更など） |
| `status` が付いている | **kintone が拒否**。権限の問題 |
| `status` が無い失敗 | **kintone を呼んでいない** |

最後の2行の区別が大事です。「拒否された」だけでは、**誰が拒否したのか分かりません**。

---

## よくある誤解

| 誤解 | 実際 |
| --- | --- |
| 非公開スペースに入れたから安全 | **守っているのはアプリのアクセス権**。スペースの公開設定ではない |
| 一覧に出ないから安全 | 取得件数の上限に入らなかっただけかもしれない。**ID を直接指定して確かめる** |
| ツールを5個しか出していないから、5通りしかできない | **組み合わせは制御できない**。一覧のツールが無くても「一覧を見せて」は通る |
| 接続を消したから、資格情報も消えた | **クライアントの切断はサーバーに届きません**。400日の期限か、kintone 側で切るか |
| 設定を変えたから、すぐ反映された | **クライアントは古いツール一覧を持ち続けます**。新しいチャットを始めてもらう |

---

## 困ったときに最初に見るもの

| 症状 | 見るところ |
| --- | --- |
| ツールが見つからない | **設定を変えた直後では?** 新しいチャットで「使えるツールを一覧して」 |
| `403 CB_OA01` | **スコープを広げた?** つなぎ直してもらう |
| `401` | 連携ユーザーのパスワード |
| `400 GAIA_OF02` | `kintone-search` の API ラボが未有効 |
| 検索が0件 | 索引の反映待ち（**作成直後は出ません**）。別の語で検索が動くか先に確かめる |

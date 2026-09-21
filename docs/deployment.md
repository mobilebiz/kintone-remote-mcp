# デプロイ手順 (Google Cloud Run)

> [!WARNING]
> **この手順を最後まで実行しても、公開してよい状態にはなりません。**
> 外部レビューの判定は「公開デプロイの合格判定はまだ出せない」です。
> 未完了の項目は末尾の「公開前に残っていること」を参照してください。

## 前提

```sh
export PROJECT_ID="..."          # vonage-mcp-server と同じプロジェクト
export REGION="asia-northeast1"
export SERVICE="kintone-remote-mcp"
export KINTONE_HOST="example.cybozu.com"

gcloud services enable run.googleapis.com firestore.googleapis.com \
  secretmanager.googleapis.com cloudbuild.googleapis.com --project=$PROJECT_ID
```

## 1. Firestore を用意する

> [!IMPORTANT]
> **専用のデータベースを作る。** コレクション名では分離できません。
> サーバー SDK は Security Rules を迂回するので、あれは権限境界になりません。

```sh
gcloud firestore databases create --database=kintone-mcp \
  --location=$REGION --type=firestore-native --project=$PROJECT_ID
```

TTL ポリシーは **`ttlAt`** に設定します（`expiresAt` ではありません。
TTL は日時型のフィールドしか見ないため、数値の `expiresAt` では働きません）。

```sh
gcloud firestore fields ttls update ttlAt --enable-ttl \
  --collection-group=oidc --database=kintone-mcp --project=$PROJECT_ID
```

> [!IMPORTANT]
> **`--enable-ttl` を忘れない。** 付けないとポリシーは有効になりません。

## 2. サービスアカウントを分ける

> [!IMPORTANT]
> **既定の Compute SA を使わない。** vonage と共用すると、
> 片方の権限がもう片方にそのまま乗ります。

```sh
gcloud iam service-accounts create kintone-remote-mcp --project=$PROJECT_ID

SA="kintone-remote-mcp@$PROJECT_ID.iam.gserviceaccount.com"
# ⚠ プロジェクト全体に付けると、他のデータベースにも触れてしまう。
# 対象のデータベースに限定する
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$SA" --role="roles/datastore.user" \
  --condition="expression=resource.name.endsWith('/databases/kintone-mcp'),title=kintone-mcp-only"
```

> [!WARNING]
> **条件を付けないと分離になりません。** vonage と同じプロジェクトなので、
> 無条件の `roles/datastore.user` は既定のデータベースにも及びます。

## 3. 秘密を登録する

> [!NOTE]
> シークレット名に接頭辞を付けます。vonage 側に `mcp-auth-token` が既にあります。

```sh
# kintone のトークンを暗号化する鍵（32バイト）
openssl rand -base64 32 | tr -d '\n' | \
  gcloud secrets create kintone-mcp-token-key --data-file=- --project=$PROJECT_ID

# Cookie 署名鍵。**全インスタンスで共有する**
openssl rand -base64 32 | tr -d '\n' | \
  gcloud secrets create kintone-mcp-cookie-keys --data-file=- --project=$PROJECT_ID

# id_token の署名鍵。**未設定だと oidc-provider 同梱の公開済み固定鍵で署名します**
node -e "const {generateKeyPairSync}=require('crypto');
const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
console.log(JSON.stringify({keys:[{...privateKey.export({format:'jwk'}),kid:'v1',alg:'RS256',use:'sig'}]}))" | \
  gcloud secrets create kintone-mcp-jwks --data-file=- --project=$PROJECT_ID

# cybozu.com の OAuth クライアントシークレット。
# ⚠ **手順5 でしか取得できない。** ここでは作らず、手順5 のあとに登録する
#
# ⚠ **末尾に改行を入れないこと。** ターミナルで貼り付けて Enter を押すと
# 1バイト入り、Basic 認証が `clientId:secret\n` になって
# cybozu が **401 invalid_client** を返す（本番で踏んだ）。
# サーバー側でも前後の空白は落とすが、起動時に WARNING が出る。
# 確認:
#   gcloud secrets versions access latest --secret=kintone-mcp-cybozu-secret \
#     --project=$PROJECT_ID | od -c | tail -2

for s in kintone-mcp-token-key kintone-mcp-cookie-keys kintone-mcp-jwks; do
  gcloud secrets add-iam-policy-binding $s --member="serviceAccount:$SA" \
    --role="roles/secretmanager.secretAccessor" --project=$PROJECT_ID
done
```

## 4. 非公開でデプロイして URL を確定させる

> [!IMPORTANT]
> **1段階目は非公開で上げます。**
> `ALLOWED_HOSTS` は URL が確定しないと設定できず、
> 未設定のまま公開すると DNS rebinding に無防備になります。
> （未設定なら起動時に落ちるようにしてありますが、公開の順序は守ってください）

```sh
gcloud run deploy $SERVICE --source . --region=$REGION --project=$PROJECT_ID \
  --no-allow-unauthenticated \
  --service-account=$SA \
  --max-instances=10 --concurrency=20 --timeout=60 \
  --set-env-vars="OAUTH_ISSUER=https://placeholder,ALLOWED_HOSTS=placeholder" \
  --set-env-vars="KINTONE_BASE_URL=https://$KINTONE_HOST" \
  --set-env-vars="FIRESTORE_DATABASE=kintone-mcp" \
  --set-secrets="TOKEN_ENCRYPTION_KEY=kintone-mcp-token-key:1" \
  --set-secrets="COOKIE_KEYS=kintone-mcp-cookie-keys:1" \
  --set-secrets="OIDC_JWKS=kintone-mcp-jwks:1"

# ⚠ この時点では起動しません（CYBOZU_OAUTH_CLIENT_ID/SECRET が未設定なため、
# 設定の検証で落ちます）。URL を確定させるのが目的です。

URL=$(gcloud run services describe $SERVICE --region=$REGION \
  --project=$PROJECT_ID --format='value(status.url)')
echo $URL
```

> [!NOTE]
> **`:latest` を使わない。** シークレットのローテーションが、
> 意図しないタイミングで稼働中のリビジョンに効きます。

## 5. cybozu.com に OAuth クライアントを登録する

**.com 共通管理者の権限が要ります**（1ドメイン20個まで）。

1. cybozu.com 共通管理 → OAuth → 「OAuthクライアントの追加」
2. リダイレクトエンドポイントに **`$URL/oauth/callback`** を登録
3. 「利用者の設定」で、使うユーザーを許可する
   （**後から追加したユーザーは都度設定が必要です**）
4. クライアント ID とシークレットを控える

要求するスコープはフェーズ1 では読み取りのみです。

```
k:app_record:read  k:app_settings:read
```

## 6. 設定を確定して公開する

```sh
HOST=$(echo $URL | sed 's|https://||')

# 手順5 で取得したシークレットをここで登録する
printf '%s' '<手順5のクライアントシークレット>' | \
  gcloud secrets create kintone-mcp-cybozu-secret --data-file=- --project=$PROJECT_ID
gcloud secrets add-iam-policy-binding kintone-mcp-cybozu-secret \
  --member="serviceAccount:$SA" --role="roles/secretmanager.secretAccessor" --project=$PROJECT_ID

gcloud run services update $SERVICE --region=$REGION --project=$PROJECT_ID \
  --update-env-vars="OAUTH_ISSUER=$URL,ALLOWED_HOSTS=$HOST" \
  --update-env-vars="CYBOZU_OAUTH_CLIENT_ID=<手順5のクライアントID>" \
  --update-secrets="CYBOZU_OAUTH_CLIENT_SECRET=kintone-mcp-cybozu-secret:1"

curl -s "$URL/health"
# => {"status":"ok","version":"0.1.0"}
```

> [!WARNING]
> **公開（`allUsers` の付与）はここではありません。**
> 末尾の「公開前に残っていること」をすべて済ませてから、最後に行います。
>
> ```sh
> # すべて済んでから
> gcloud run services add-iam-policy-binding $SERVICE --region=$REGION \
>   --project=$PROJECT_ID --member=allUsers --role=roles/run.invoker
> ```

**`version` を必ず確認してください。** 古いリビジョンが動いていることに
気づかないまま調査を続けるのは、よくある時間の浪費です。

## 7. Claude に接続する

スマホまたは claude.ai で:

1. 設定 → コネクタ → カスタムコネクタを追加
2. URL に **`$URL/mcp`** を入れる（**保護リソースメタデータの `resource` と完全一致**）
3. OAuth クライアントは「独自の OAuth クライアントを使う」を選び、
   クライアント ID に **`claude-hosted`** を入れる（シークレットは空欄）

## 環境変数

| 変数 | 既定 | 説明 |
| --- | --- | --- |
| `OAUTH_ISSUER` | （必須） | `https://HOST`。**パスを付けない** |
| `ALLOWED_HOSTS` | （必須） | Host ヘッダーの許可リスト |
| `KINTONE_BASE_URL` | （必須） | `https://example.cybozu.com` |
| `CYBOZU_OAUTH_CLIENT_ID` / `_SECRET` | （必須） | 手順5 |
| `TOKEN_ENCRYPTION_KEY` | （KMS を使わない場合は必須） | base64 で32バイト。**本番では使わない**（設定を読める者が鍵を得られます）。使うと起動時に WARNING が出ます |
| `COOKIE_KEYS` | （必須） | **全インスタンスで共有** |
| `SECURE_COOKIES` | `true` | **本番では変えない**。false にできるのはローカルの平文 HTTP のみ |
| `CIMD_ALLOWED_HOSTS` | （空） | 事前登録していないクライアントを受け入れるホスト。**空なら CIMD ごと無効**。ホスト名のみ・完全一致（例: `chatgpt.com`） |
| `OIDC_JWKS` | （https では必須） | id_token の署名鍵。**未設定だと同梱の公開済み固定鍵が使われる** |
| `FIRESTORE_DATABASE` | `(default)` | 専用データベースを使う場合に指定 |
| `ALLOWED_ORIGINS` | 空 | ブラウザから使う場合のみ |
| `TRUSTED_PROXY_HOPS` | `1` | 信頼する転送ヘッダーの段数。**Cloud Run の直 URL なら 1**。前段に外部 LB を置くと 2 |
| `ALLOWED_APP_IDS` | 空 | **空は「制限なし」**。本人がアクセスできる全アプリが対象になる |
| `ENABLE_RECORD_READ` / `ENABLE_APP_READ` | `true` | 読み取り |
| `ENABLE_RECORD_WRITE` / `ENABLE_APP_WRITE` | `false` | 書き込み |
| `ALLOW_DESTRUCTIVE` | `false` | 削除系。`ENABLE_*_WRITE` とは別に要求 |
| `RATE_LIMIT_PRE_AUTH_PER_MINUTE` | `60` | 認証前。送信元ごと |
| `RATE_LIMIT_PRE_AUTH_TOTAL_PER_MINUTE` | `600` | 認証前。**送信元を見ない総量**。送信元ごとの枠は分散されると効かない |
| `RATE_LIMIT_GRANT_PER_MINUTE` | `120` | 認証後。grant ごと |
| `MAX_CONCURRENT_PER_GRANT` | `4` | 同時実行。接続ごと |
| `MAX_CONCURRENT_TOTAL` | `8` | 同時実行。**インスタンス全体**。kintone のドメインを守る枠 |
| `REQUEST_DEADLINE_MS` | `55000` | **Cloud Run の `--timeout` より短くする** |
| `CYBOZU_TIMEOUT_MS` | `10000` | cybozu のトークンエンドポイントを諦めるまで。**`REQUEST_DEADLINE_MS` より短くする** |
| `KMS_KEY_NAME` | 空 | トークン暗号鍵を包んだ KMS の鍵。`TOKEN_ENCRYPTION_KEY_CIPHERTEXT` とセット |
| `TOKEN_ENCRYPTION_KEY_CIPHERTEXT` | 空 | KMS で暗号化した鍵（base64）。`TOKEN_ENCRYPTION_KEY` とは**同時に設定できません** |
| `STORAGE_TIMEOUT_MS` | `5000` | 保存層の**1操作**を諦めるまで |
| `AUTH_REQUEST_DEADLINE_MS` | `10000` | 認可まわりの**要求1つぶん**の予算。⚠ 操作ごとの期限だけでは、操作のたびにタイマーが始まり直すので全体が長引く |

> [!WARNING]
> **流量制限はインスタンス単位でしか効きません。**
> プロセス内メモリで数えているので、**再起動でも枠が戻ります**。
> 実効的な上限は「制限値 × 稼働インスタンス数」ですが、
> **その掛け算は最悪値になりません**（理由は次節）。

## 負荷の予算を決める

**公開前に、この表を埋めてください。** 埋めずに公開すると、
「何人が使うと業務に影響するか」を誰も知らないまま動き続けます。

> [!WARNING]
> **`8 × --max-instances` は最悪値ではありません。**
> 見積もりを出すときに、まずこれを踏みました。
>
> - `--max-instances` は**リビジョン単位**です。サービス全体の上限ではありません
> - **デプロイ中は新旧のリビジョンが重なります**
> - Cloud Run は設定した最大インスタンス数を**一時的に超えることがあります**
>
> つまり上限は「掛け算で出る数」より必ず大きくなります。
> [Cloud Run の仕様](https://docs.cloud.google.com/run/docs/configuring/max-instances)

| 項目 | 既定 | 見積もり | 根拠 |
| --- | --- | --- | --- |
| 同時実行（1インスタンス） | `MAX_CONCURRENT_TOTAL=8` | 8 | プロセス内メモリなので、ここだけは確実 |
| 稼働インスタンス数 | `--max-instances=10` | 10 **＋ デプロイ中の重なり ＋ 一時超過** | 上限として扱えない |
| 同時実行（合計） | — | **80 より大きい。上限は無い** | |
| kintone の同時実行上限 | — | **ドメインあたり100** | 超えると**同じドメインの他の利用にも影響** |
| 既存業務に残す余裕 | — | | |
| API の日次消費 | — | | 同時実行だけでなく、1日の総数も見る |

> [!IMPORTANT]
> **上限が要るなら、この作りでは足りません。**
> インスタンスをまたいで数えていないので、厳密な上限は原理的に置けません
> （共有ストアによる調停が要ります。フェーズ1では入れていません）。
>
> いま置けるのは「1インスタンスあたりの歯止め」だけです。
> **既存業務と同じドメインで動かすなら、`MAX_CONCURRENT_TOTAL` と
> `--max-instances` の両方を、重なりと一時超過を見込んだ値まで下げてください。**
> 既定値は「1人で試す」前提の値です。

[kintone の外部システム連携の指針](https://cybozu.dev/ja/kintone/tips/best-practices/external-system-integration/secure-operation-of-forms-and-viewers/)

## 必ず行う設定（コードからは適用できません）

### ログからクエリ文字列を落とす

`code` と `state` は URL のクエリに載り、Cloud Logging の
`httpRequest.requestUrl` は**クエリを含みます**。
アプリ側で伏せても**基盤側には残る**ので、sink で除外します。

> [!IMPORTANT]
> **最初の OAuth 試験より前に適用してください。**
> 試験で流れた `code` は後から消せません。

```sh
gcloud logging sinks update _Default --project=$PROJECT_ID \
  --add-exclusion='name=kintone-mcp-query-strings,description=クエリ付きのリクエストログを落とす（code と state が requestUrl に載るため）,filter=resource.type="cloud_run_revision" AND resource.labels.service_name="'$SERVICE'" AND logName:"run.googleapis.com%2Frequests" AND httpRequest.requestUrl=~"\?"'

# 適用後、クエリ付きのリクエストログが0件であることを確かめる
gcloud logging read 'resource.labels.service_name="'$SERVICE'" AND httpRequest.requestUrl:"?"' \
  --project=$PROJECT_ID --limit=3 --freshness=1h
```

> [!WARNING]
> **組織の集約 sink と転送先は、これでは止まりません。**
> プロジェクトの外へ流れる経路がある場合は、そちらにも同じ除外が要ります。

## 連携ユーザーを有効にする（スペース操作と検索）

> [!NOTE]
> **2026-09-18 に実環境で動かしました。** `kintone-get-space` が
> 連携ユーザーとして実行され、監査ログに `identity: integration` が出ます。
> **まだ確かめていないのは、更新・作成・削除と `kintone-search` です。**

### なぜ別扱いか

スペース操作4つと `kintone-search` は、**OAuth では実行できません**。
cybozu がスコープを用意していないためで、これらの API は
パスワード認証／セッション認証しか受け付けません。

そのため**専用のユーザーとして実行します**。
接続した本人ではありません。

> [!WARNING]
> **パスワード認証にはスコープがありません。**
> そのユーザーにできること全部ができます。
> `ALLOWED_APP_IDS` で絞っていると、これらのツールは**1つも公開されません**
> （引数にアプリ ID を持たないので、境界の判定が素通りするため）。

### kintone 側で用意するもの

1. **専用ユーザーを作る**（例: `kintone-mcp-integration`）
2. **2要素認証を無効にする** — 有効だと REST API が実行できません
   （サイボウズも連携用の専用ユーザーを勧めています）
3. **権限を絞る** — 触らせたいスペースとアプリだけに参加させます。
   **管理者権限は絶対に付けないでください**
4. **試すスペースを1つ用意する**

### サーバー側の設定

```sh
# パスワードを Secret Manager へ。⚠ 履歴に残さないよう対話で入力する
read -rs INTEGRATION_PASSWORD
printf '%s' "$INTEGRATION_PASSWORD" | \
  gcloud secrets create kintone-mcp-integration-password --data-file=- --project=$PROJECT_ID
unset INTEGRATION_PASSWORD

gcloud secrets add-iam-policy-binding kintone-mcp-integration-password \
  --member=serviceAccount:$SA --role=roles/secretmanager.secretAccessor --project=$PROJECT_ID

gcloud run services update $SERVICE --region=$REGION --project=$PROJECT_ID \
  --update-env-vars="KINTONE_INTEGRATION_USERNAME=kintone-mcp-integration" \
  --update-env-vars="ENABLE_SPACE_READ=true,ENABLE_SPACE_WRITE=true,ENABLE_SEARCH=true" \
  --update-secrets="KINTONE_INTEGRATION_PASSWORD=kintone-mcp-integration-password:1"
```

> [!IMPORTANT]
> **`printf` を使い、`echo` を使わないでください。** `echo` は末尾に改行を足します。
> cybozu のクライアントシークレットで実際に踏み、`401 invalid_client` の原因を
> 探すのに時間を使いました。

> [!NOTE]
> **`ENABLE_SPACE_WRITE` は、削除を含みません。**
> `kintone-delete-space` には `ALLOW_DESTRUCTIVE` も要ります。
> **スペースの削除は、置かれているアプリごと使えなくします。** 試すなら最後に、
> 捨ててよいスペースで。

### つなぎ直しが要ります

**既存の接続では使えません。** 連携ユーザーへの同意は接続ごとに記録され、
**同意していない接続は、設定を変えても届きません**（主体が入れ替わることへの
同意なので、これは意図した動作です）。

Claude のコネクタを削除して、繋ぎ直してください。

### 確かめること

| 確かめる場所 | 期待する結果 |
| --- | --- |
| 同意画面 | **連携ユーザーの名前**と「あなたではなく」の断りが出る |
| `kintone-get-space` の実行 | 成功する |
| 監査ログの `identity` | **`integration`**（本人の操作は `user`） |
| 監査ログの `targets` | `space:<ID>` が入る（何を触ったか分かる） |
| **繋ぎ直していない接続** | スペース操作が**ツール一覧に出ない** |

最後の行がいちばん大事です。**設定を変えるだけで既存の接続の権限が広がらない**
ことの確認になります。

手順は **[docs/space-test.md](space-test.md)** に、
シナリオ8本として書いてあります。

> [!WARNING]
> **設定を変えても、クライアントの見えている一覧はすぐには変わりません。**
>
> 実測（2026-09-18）で、次の2つが起きました。
>
> - 公開ツールを 17→13 に減らしたのに、Claude 側は**17件の一覧を保持**し、
>   消えたはずのツールを呼んで弾かれた
> - `ALLOWED_APP_IDS` を**外した後も**、Claude は制限が続いている前提で動き、
>   新しく公開されたツール（`kintone-search`）を**一度も呼ばなかった**
>
> **強制は効いています。** 古い一覧から呼んでも実行されません
> （公開の判断は一覧を作るときだけでなく実行時にも効きます）。
> 遅れるのは**表示のほう**です。
>
> ⚠ **利用者からは「サーバーの不調」に見えます。**
> 実際モデルは「MCPサーバー内部の状態の問題」「再起動したほうが早い」と
> 説明しました。設定を変えたら、**利用者に新しいチャットを始めてもらう**か、
> 繋ぎ直してもらってください。
>
> 検証のときは、**先に「使えるツールを一覧して」と言わせて**、
> 期待どおりの一覧になっていることを確かめてから本題に入ってください。
> そうしないと、古い一覧のまま総当たりした結果を
> 「機能が動かない」と読み違えます（実際に読み違えました）。

### 動かしてみて分かったこと（2026-09-18）

> [!WARNING]
> **「スペースの一覧」を頼むと、`kintone-get-space` が何度も走ります。**
> 一覧のツールは無いので、Claude はアプリ一覧から `spaceId` を拾って
> **1つずつ呼びます**。実測で**20秒に13回**でした。
> その13回はすべて**連携ユーザーの権限**で走ります。
>
> `MAX_CONCURRENT_TOTAL` と kintone 側の API 制限の両方に効きます。

> [!IMPORTANT]
> **確認すべきは、スペースの公開設定ではなく「アプリのアクセス権」です。**
>
> kintone では2つが別の軸です。`kintone-get-apps` に要るのは
> **アプリのレコード権限**だけで、スペースのメンバーであることは条件に入っていません
> （[kintone の仕様](https://cybozu.dev/ja/kintone/docs/rest-api/apps/get-apps/)）。
>
> **実測（2026-09-18）:** スペースの中に作ったアプリは、既定でそのスペースの
> メンバーに絞られており、非メンバーからは `403` でした。**守られています。**
>
> ただし守っているのは**アプリのアクセス権**です。アプリ側の権限を
> 「Everyone」に広げれば、**スペースが非公開でも読めます**。
>
> 公開する前に、**アプリ側のアクセス権を確認してください**。

なお、非公開スペースを連携ユーザーが読めない場合は `403` が返ります。
これは**連携ユーザーの権限がそのまま効いている証拠**でもあります。

> [!NOTE]
> **到達範囲を確認しました（2026-09-18）。** 第三者がスペース管理者で、
> 連携ユーザーがメンバー、**接続した本人は非メンバー**という非公開スペースの
> 内容が、本人に返りました。
> 同意画面には、この結果（参加していない非公開スペースも読めること）を
> 明記してあります。

### 戻すとき

```sh
gcloud run services update $SERVICE --region=$REGION --project=$PROJECT_ID \
  --remove-env-vars="KINTONE_INTEGRATION_USERNAME,ENABLE_SPACE_READ,ENABLE_SPACE_WRITE,ENABLE_SEARCH" \
  --remove-secrets="KINTONE_INTEGRATION_PASSWORD"
```

> [!WARNING]
> **シークレット由来の変数は `--remove-secrets` でしか消えません。**
> `--remove-env-vars` に書いても消えず、設定が残ります。2度踏みました。

## 公開前に残っていること

外部レビューで「公開デプロイの合格判定は出せない」とされている項目です。

> [!NOTE]
> **2026-09-17 に公開しました。** 実環境で確かめられた項目には実績を書いています。
> `[~]` は「一部は確認できたが、残りがある」の意味です。
>
> このときの構成: リージョン `asia-northeast1` /
> `MAX_CONCURRENT_TOTAL=2` / `--max-instances=1` / 読み取りのみ。
>
> **現在稼働しているのは `kintone-remote-mcp-00013-649`**（2026-09-17、レビュー16回目の修正まで）。
> 構成は `MAX_CONCURRENT_TOTAL=4` / `--max-instances=1` /
> レコードの読み書き / KMS で包んだ鍵 / `ALLOWED_APP_IDS` と連携ユーザーは未設定。

> [!WARNING]
> **`gcloud run deploy --source` は、Cloud Run の切り替えを手元で行います。**
> ビルドは Cloud Build ですが、**サービスの更新はクライアント側**です。
> 途中で手元のプロセスが止まると、**イメージだけが出来ていて、
> リビジョンは古いまま**になります（実際に起きました）。
>
> ビルド済みイメージから続けられます。
>
> ```sh
> gcloud builds list --project=$PROJECT_ID --region=$REGION --limit=1
> gcloud run deploy $SERVICE --image=<results.images[0].name>@<digest> \
>   --region=$REGION --project=$PROJECT_ID
> ```
>
> **切り替わったことは必ずリビジョン名で確かめてください。**
> 「デプロイした」と思い込んだまま調査を続けるのがいちばん時間を無駄にします。

- [x] **ログ sink の除外設定。**（この環境での実施記録）2026-09-17 適用
      （`_Default` の除外 `kintone-mcp-query-strings`）。
      **最初の OAuth 試験より前に入れました。**
      適用後、クエリ付きリクエストログが0件であることも確認済み。
      ⚠ 組織の集約 sink・転送先は未確認

      > [!WARNING]
      > **これは記録であって、引き継がれません。**
      > 新しく立てる人は、下の「必ず行う設定」を自分で適用してください。
      > コードからは適用できません
- [x] **レコードの更新（書き込み）の実地確認。** 2026-09-17、リビジョン
      `00013-649` で `kintone-update-records` が成功（アプリ103）。
      **同意の記録を持つ新しい接続**での実績です。

      ⚠ **その手前で、古い接続からの更新が `403` / `CB_OA01` で落ちました。**
      同じユーザー・同じアプリで、つなぎ直した直後は成功しています。
      アプリ権限なら繋ぎ直しても403のままなので、原因は
      **cybozu のトークンのスコープ**です。
      `CYBOZU_OAUTH_SCOPES` を広げても、**既に発行されたトークンには及びません**。
      既存の利用者にはつなぎ直してもらう必要があります
- [x] **認可を一周する経路の実地確認。** 2026-09-17、`00013-649` で
      `connection_created` → `token_issued` → ツール実行まで到達。
      **同意を表示時点で固定する経路が、本番で一度通りました**
- [x] **ChatGPT からの接続確認（CIMD）。** 2026-09-20 に成功。
      認可 → トークン発行 → ツール実行（`identity=user`）まで通った。
      **PKCE が `private_key_jwt` のクライアントにも効いていること**も、
      ここで初めて確認できた（自動試験では確かめられない箇所）。

      実際に繋いで初めて出た不具合が2つある。**どちらも Claude では見えなかった。**

      | 不具合 | なぜ見えなかったか |
      | --- | --- |
      | PKCE が認証方式によって外れる | Claude は公開クライアントなので常に必須だった |
      | メタデータが RFC 9728 の場所に無い | Claude はルートに後退して拾う |

      > 「Claude で動いている」は「仕様どおり」を意味しない。

      ⚠ **未解明**: `POST /mcp` が `415` で弾かれることがある
      （`User-Agent: Python/3.14 aiohttp`、本文あり）。繋がったあとの
      `openai-mcp/1.0.0` からの要求は 200 なので実害は見えていないが、
      415 は**認証の案内（401 + `WWW-Authenticate`）より前に返る**。
- [~] **スマホの実機確認。** 2026-09-17、スマホの Claude アプリから
      レコード検索まで到達。**ただし2接続目の経路は未確認**。
      claude.ai のアカウントに紐づく接続をデスクトップと共有しており、
      スマホからの認可が走っていません（`connection_created` が出ていない）。
      **アカウント切替の自動送信 (`form_post`) は、まだ一度も試されていません。**
      接続を削除してスマホから繋ぎ直すと通る経路です
- [x] **Cloud KMS によるエンベロープ暗号化。** 2026-09-17 適用。
      鍵は `KMS_KEY_NAME` + `TOKEN_ENCRYPTION_KEY_CIPHERTEXT` から
      **起動時に1回だけ**取り出します（要求ごとに KMS を呼ぶと、
      でたらめな Bearer で KMS の課金と流量を誘発できるため）。
      起動ログの `encryptionKey` が `kms` なら効いています。
      ⚠ **守るのは「保存されている設定やデータだけが漏れた場合」**で、
      復号権限を持つ SA の侵害は防ぎません
- [x] **Data Access audit logs の有効化。** 2026-09-17、`cloudkms.googleapis.com` の
      DATA_READ / DATA_WRITE を有効化（プロジェクトの IAM ポリシー）
- [~] **専用 Firestore データベースと条件付き IAM の実環境確認。**
      2026-09-17、書き込みが `kintone-mcp` に入ることを確認
      （プロジェクトに他のデータベースは存在しない）。IAM の条件も付いている。
      ⚠ **否定側（別のデータベースに触れないこと）は未確認。**
      試すには捨てるためのデータベースが要ります
- [x] **TTL ポリシーの実環境確認。** 2026-09-17、`oidc` コレクショングループの
      `ttlAt` に対して **ACTIVE**。保存された文書の `ttlAt` が
      **`timestampValue`** であることも確認（数値だと TTL は働きません）
- [x] **署名鍵の実環境確認。** 2026-09-17、`/jwks` の `kid` が `v1`。
      同梱の `keystore-CHANGE-ME` ではありません
- [x] **Firestore エミュレータでの全試験**（`pnpm test:firestore`）
      2026-09-17 時点で **241件すべて通過、スキップ 0**（手順は `docs/firestore.md`）
- [x] **起動確認と SIGTERM 試験。** 2026-09-17 実施。
      コンテナの起動は Cloud Run で確認済み（同じ `dist/index.js`）。
      SIGTERM はローカルで直接動かして測った:

      | 確かめたこと | 結果 |
      | --- | --- |
      | 処理中の要求を走り切らせるか | **走り切って応答**（3.1秒かかる要求が完走） |
      | 停止中に新規接続を受けるか | 受けない（接続拒否） |
      | 終了コード | 0 |
      | 停止まで（保存層が生きている） | **1ミリ秒** |
      | 停止まで（保存層が死んでいる） | 6.4秒。**8秒の強制終了と Cloud Run の猶予10秒の内側** |

      ⚠ 遅いのは接続の排出ではなく**後始末**（到達できない Firestore の終了処理に4.1秒）。
      どこで時間を使ったかは `shutdown.progress` のログに出ます
- [x] **実ブラウザでの同意フォーム送信。** 2026-09-17、認可を完走。
      Origin 検証で止まっていません
- [~] **Claude 実機での認可・更新・切断。** 2026-09-17、**認可と更新は完了**
      （デスクトップ・スマホの両方からレコード検索まで到達）。

      リビジョン `00013-649` で、更新経路が両方とも通りました。

      | 記録 | 何が動いたか |
      | --- | --- |
      | `token_refreshed` (`reason: refresh_token`) | Claude 側のトークンの更新 |
      | `token_refreshed` (`accountId` あり) | **cybozu のアクセストークンの更新** |

      2つめが意味を持ちます。**KMS から取り出した鍵で、
      それ以前に保存したリフレッシュトークンを復号できた**ということです。
      包む前と同じ鍵であることが、実環境で確かめられました。

      ⚠ **切断はサーバーに届きませんでした。** 2026-09-17、Claude 側で接続を
      切ったあと、**失効の要求が1件も来ていません**（ツール実行を最後に、
      以降のリクエストログが0件）。

      失効の口（RFC 7009 の `/token/revocation`）は動きますが、
      **Claude はそれを呼びません**。保管した kintone のリフレッシュトークンは
      残ります。いま消す手立ては次のとおりです。

      | 手段 | 効き方 |
      | --- | --- |
      | 待つ | 接続の絶対期限（400日）で失効し、保存層からも消える |
      | **cybozu 側で切る** | 共通管理の OAuth クライアントで利用者を外す。**トークンそのものが無効になるので、いちばん確実** |
      | 運用者が消す | 監査ログの `accountId` で Firestore のレコードを消す（`payload.accountId` は暗号化していないので検索できる） |

      **利用者が自分で消す方法はありません。** kintone のユーザー名を保存しない
      設計なので、「この人の接続」を特定できないためです。
      この判断（主体を内部 ID に留める）の対価がここに出ています
- [ ] **回帰確認。** 以下は自動テストで固めてありますが、
      実環境でも一度確かめてください（手前のインフラが挙動を変えることがあります）
  - `Content-Type: application/json-patch+json` でのバッチと過大な本文が
    **上流に届かない**こと
  - `X-Forwarded-For` を足しても、認証前の枠が作り直せないこと
    （**`TRUSTED_PROXY_HOPS` が実際の構成と合っているか**をここで確かめる）
  - 送信元の枠で拒否された相手が、**他の利用者を締め出さない**こと
- [ ] **`TRUSTED_PROXY_HOPS` を増やす場合、より短い経路が無いことを確かめる。**
      ホップ数を2にしたまま1ホップの経路から到達できると、
      **左側の偽装値がそのまま送信元として使われ**、枠を作り直せます
      （実測で再現済み）。[Express の注意事項](https://expressjs.com/en/guide/behind-proxies/)
- [ ] **詰まりと切断の試験。** 認証・更新・ツール実行のそれぞれで、
      期限を過ぎても**処理中の枠を保ったまま**応答が返り、
      通信が終われば枠が戻ること。
      **詰まりを解いたあとまで追って**、締め切り後に kintone を呼んでいないことを確かめる
- [ ] **負荷の予算を決める**（上の表）。接続数・インスタンス数・既存業務を含めて、
      同時実行と日次消費の両方で判断する
- [ ] **異なる2ユーザーでの並行実行**（§9）。資格情報が混ざらないこと、
      実際の `/token` での競合、保存の途中で中断した場合の挙動
- [ ] **最新のコミットに対して、実ソケットと Firestore で流し直す。**
      過去の全件通過を、そのまま今の HEAD の証跡にしないこと

### 本番で分かったこと

- **同時実行の枠に実際に当たります。** `MAX_CONCURRENT_TOTAL=2` では、
  Claude が並列に投げたツール実行の1件が 429 になりました
  (`rate_limit.blocked` / `scope=concurrency-total`)。
  kintone のドメイン上限は100同時なので、4程度までは十分に小さい値です
- **`kintone-get-apps` は通るのに、個別のアプリで `GAIA_IL23` が返ることがあります。**
  一覧には出るがアクセスできないアプリ（ゲストスペースなど）が考えられます。
  監査ログに `kintoneCode` と `kintoneId` が残るので、問い合わせに使えます
- [ ] **上限を保証しない運用の取り決め。** インスタンスをまたいだ上限は置けないので、
      **監視の閾値・止める判断・止める手順**を先に決めておく。
      気づいて止められることが唯一の担保になります
- [ ] **保存層が止まったときの応答時間。** `/token` は10秒、更新は30秒という
      設計上の期限を、**保存層の障害時にも満たすこと**を確かめる
- [ ] **監査ログで操作を区別できること。** 正常な認可・発行・更新・切断と、
      **再使用検知**を、保存されたログだけで見分けられるか
- [ ] **ログ除外の範囲確認。** `_Default` だけでなく、
      組織の集約 sink と転送先まで見て、試験で流した値が残っていないことを確かめる

## トークン暗号鍵を KMS で包む

> [!IMPORTANT]
> **既存の鍵をそのまま包んでください。** 別の鍵にすると、
> **保存済みの kintone トークンを1つも復号できなくなります**
> （利用者は全員つなぎ直しになります）。

```sh
# 1. 鍵を作る。**このサービス専用にする**（鍵の使用を監査で切り分けるため）
gcloud kms keyrings create kintone-mcp --location=$REGION --project=$PROJECT_ID
gcloud kms keys create token-key --location=$REGION --keyring=kintone-mcp \
  --purpose=encryption --project=$PROJECT_ID

# 2. 実行 SA には**復号だけ**。暗号化は人が行うので要らない
gcloud kms keys add-iam-policy-binding token-key --location=$REGION \
  --keyring=kintone-mcp --project=$PROJECT_ID \
  --member="serviceAccount:$SA" --role="roles/cloudkms.cryptoKeyDecrypter"

# 3. いまの鍵を包む。⚠ **往復できることを確かめてから保存する**
TMP=$(mktemp); TMPC=$(mktemp)
gcloud secrets versions access 1 --secret=kintone-mcp-token-key --project=$PROJECT_ID > "$TMP"
gcloud kms encrypt --location=$REGION --keyring=kintone-mcp --key=token-key \
  --plaintext-file="$TMP" --ciphertext-file="$TMPC" --project=$PROJECT_ID
gcloud kms decrypt --location=$REGION --keyring=kintone-mcp --key=token-key \
  --ciphertext-file="$TMPC" --plaintext-file=- --project=$PROJECT_ID | cmp - "$TMP" \
  && echo "往復 OK"
base64 < "$TMPC" | tr -d '\n' | \
  gcloud secrets create kintone-mcp-token-key-wrapped --data-file=- --project=$PROJECT_ID
rm -f "$TMP" "$TMPC"

# ⚠ **新しいシークレットにも読み取り権限を付ける。**
# 手順3で付けたのは別のシークレットに対してです。忘れると
# KMS 版のリビジョンが**起動できません**（Cloud Run がシークレットを読めない）
gcloud secrets add-iam-policy-binding kintone-mcp-token-key-wrapped \
  --member="serviceAccount:$SA" --role="roles/secretmanager.secretAccessor" \
  --project=$PROJECT_ID

# 4. 差し替える。⚠ **生の鍵はシークレット参照なので --remove-secrets で消す**
#    （--remove-env-vars では消えず、「両方設定されている」で起動が止まります）
gcloud run services update $SERVICE --region=$REGION --project=$PROJECT_ID \
  --remove-secrets="TOKEN_ENCRYPTION_KEY" \
  --update-env-vars="KMS_KEY_NAME=projects/$PROJECT_ID/locations/$REGION/keyRings/kintone-mcp/cryptoKeys/token-key" \
  --update-secrets="TOKEN_ENCRYPTION_KEY_CIPHERTEXT=kintone-mcp-token-key-wrapped:1"
```

**起動ログの `encryptionKey` が `kms` になっていることを確認してください。**
`plain` のままなら包めていません（`config.plain_key` の WARNING も出ます）。

### 鍵の使用を監査に残す

```sh
# Data Access ログは既定で無効。有効にしないと、鍵が使われた記録は残りません
gcloud projects get-iam-policy $PROJECT_ID --format=json > policy.json
# auditConfigs に cloudkms.googleapis.com の DATA_READ / DATA_WRITE を足して
gcloud projects set-iam-policy $PROJECT_ID policy.json
```

> [!WARNING]
> **プロジェクト全体の IAM ポリシーを書き換えます。**
> `etag` を保ったまま書くこと（競合を検知させるため）。
> 書く前に、`auditConfigs` 以外が変わっていないことを確かめてください。

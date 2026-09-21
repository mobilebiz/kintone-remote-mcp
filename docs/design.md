# kintone Remote MCP Server 設計書

対象: `https://github.com/kintone/mcp-server` (`@kintone/mcp-server` v1.9.3) を
Streamable HTTP のリモート MCP サーバーとして運用できるようにする。
参考実装: `vonage-mcp-server` v3.2.0 (Cloud Run / Streamable HTTP / OAuth 2.1 RS)。

## 決定事項 (2026-09-16)

> **改訂あり。** 当初は「リクエストヘッダーで資格情報を渡す (案B)」で確定していたが、
> **目的がスマホの Claude アプリからの利用であることが判明し、案B を破棄した** (§4.1)。
> スマホではローカルプロセスを起動できず、カスタムヘッダーも渡せないため。

| 項目 | 決定 |
| --- | --- |
| **目的** | **スマホの Claude アプリから自分の kintone を呼ぶこと** |
| kintone の認証 | **kintone OAuth に委譲 (案C)** (§4)。~~案B: ヘッダー必須~~ は破棄 |
| 入口の認証 | **OAuth 2.1。MCP サーバーが Claude から見た認可サーバーを兼ねる** (§4.5) |
| DCR | **不要**（カスタムコネクタは事前登録クライアント ID を受け付ける）(§4.2)。ただし**クライアント登録は必要** (§4.6) |
| 認可サーバーの実装 | **`oidc-provider` に委ねる。自作しない** (§4.4)。自前はブリッジと保管のみ |
| フェーズ1 の範囲 | **スマホ / クライアント1つ / OAuth のみ / 読み取りのみ**で接続ライフサイクルを完成させる (§9) |
| テナント | **1デプロイ＝1 kintone ドメイン**。`KINTONE_BASE_URL` はサーバー設定 (§4.8) |
| 想定する接続元 | **Claude モバイル（本命）** / Claude.ai / Desktop / Claude Code |
| スペース系4ツール + search | **フェーズ1では諦める**。API がパスワード認証しか受け付けないため (§4.10) |
| パスワードログイン | **フェーズ2**。同時に作らない (§4.10) |
| ツール公開範囲 | **書き込みまで開ける**。ただし既定値は読み取り専用で、書き込みは環境変数で明示的に有効化する (§5) |
| 削除系ツール | `ALLOW_DESTRUCTIVE=true` を別途要求する (§5) |
| kintone 側の IP アドレス制限 | **未使用**。したがって Cloud NAT / VPC コネクタは不要 (§6) |
| 2要素認証 | **無効**（フェーズ2 のパスワードログインの前提）|
| GCP プロジェクト | **vonage-mcp-server と同一プロジェクト**。サービス名とシークレット名で分離する (§6) |
| 配布形態 | Docker イメージ + Cloud Run。npm / mcpb 配布はしない（それは上流の仕事） |
| レビュー | Codex による外部レビューを反映済み（→ 付録） |
| ヘッダー到達性 | 実測済み (§9.1)。ただし**案B の破棄により、この結果は前提としては不要になった** |

---

## 1. 上流の現状分析 — リモート化を阻む4点

上流を読んだ結果、「そのまま HTTP で包めば動く」構造にはなっていない。
阻害要因は次の4つで、**どれを踏むかは後述の認証モデルの選択で変わる**。

### (a) 設定がモジュール読み込み時に確定する

`src/config/index.ts` の先頭で `parseKintoneMcpServerConfig()` を実行し、
`process.env` と `process.argv` からプロセス単位の設定を1回だけ作る。
不正ならそこで `throw` する。

一方 `createServer(options)` は設定をすべて引数で受け取る設計になっている。

```ts
// src/server/index.ts
export const createServer = (options: KintoneMcpServerOptions): McpServer
```

→ **`src/config/index.ts` を経由しなければ、設定はリクエスト単位で差し替えられる。**
これは上流の設計が素直で、こちらに有利な点。

### (b) kintone クライアントがプロセス単位のシングルトン ★最重要

```ts
// src/client/index.ts
let client: KintoneRestAPIClient | null = null;
export const getKintoneClient = (config) => {
  if (client) { return client; }   // ← 2回目以降は config を完全に無視する
  ...
};
```

`createServer()` はこれを呼ぶ。つまり**リクエストごとに `createServer()` を呼んでも、
2人目以降のユーザーは1人目の kintone 資格情報で API を叩く**。
マルチテナント構成でこれを踏むと、他人のドメインのデータが返る事故になる。

→ マルチテナントにするなら `createServer()` は使えない。後述のアダプタで回避する。

### (c) エントリポイントが stdio 専用

`src/index.ts` は `StdioServerTransport` 固定。HTTP のエントリは存在しない。
→ こちらで `http-server.ts` を新規に書く（vonage の実装をほぼ流用可）。

### (d) `kintone-download-file` がローカルファイルシステム前提

`attachmentsDir` にファイルを書き、**サーバー上の絶対パス**を返す。
リモートではクライアントから触れないパスを返すだけで、コンテナの寿命とともに消える。
→ リモートでは既定で無効化する（§5）。

### 補足: 認証方式がツール一覧に影響する

`src/server/tool-filters.ts` は `isApiTokenAuth` のとき次を除外する。

```
kintone-get-apps / kintone-add-app / kintone-add-space-from-template /
kintone-search / kintone-update-space / kintone-get-space / kintone-delete-space
```

API トークン認証では上記が使えない。**リモート化でどの認証を選ぶかが、
公開できるツールの数に直結する。**

---

## 2. 基本方針

### 2.1 上流をフォークしない — npm 依存 + アダプタ

`@kintone/mcp-server` の `package.json` には `exports` フィールドが無く、
`files: ["dist"]` なので **`dist/` 配下への deep import が可能**。
必要なのは次の4つだけで、いずれも export されている。

| import 元 | シンボル | 用途 |
| --- | --- | --- |
| `dist/tools/index.js` | `tools` | 27個のツール定義 |
| `dist/tools/index.js` | `createToolCallback` | `(args) => callback(args, {client, attachmentsDir})` |
| `dist/server/tool-filters.js` | `shouldEnableTool` | API トークン時の除外 |
| `dist/server/tool-definitions.js` | `buildToolDefinition` | JSON Schema 2020-12 での tools/list |

つまり **`createServer()`(=(b)のシングルトンを踏む) を使わず、その中身20行を自前で再実装する**。
`KintoneRestAPIClient` はこちらで生成するので、リクエストごと・テナントごとに差し替えられる。

```ts
// 自前の createRemoteServer のイメージ
const client = new KintoneRestAPIClient({ baseUrl, auth, userAgent, httpsAgent: sharedAgent });
const enabled = tools.filter(t => shouldEnableTool(t.name, cond) && policy.allows(t.name));
enabled.forEach(t => server.registerTool(t.name, t.config, wrapCallback(t, client)));
server.server.setRequestHandler(ListToolsRequestSchema, () => ({
  // ★ buildToolDefinition は annotations を返さないので、ここで合成する（下記）
  tools: enabled.map(t => ({ ...buildToolDefinition(t), annotations: annotationsFor(t.name) })),
}));
```

**⚠ `buildToolDefinition` は annotations を落とす。** 実物は次の5つしか返さない。

```ts
// src/server/tool-definitions.ts
export const buildToolDefinition = (tool: Tool): McpTool => ({
  name, title, description, inputSchema, outputSchema   // ← annotations が無い
});
```

`registerTool` の config に annotations を足しても、**上流と同じく `ListToolsRequestSchema` を
上書きする以上、一覧に載るのは `buildToolDefinition` の戻り値だけ**で、annotations は消える。
アダプタ側で明示的にマージし、**実際の `tools/list` 応答を検証するテストを置く**。

**⚠ 上流は `.d.ts` を出していない。** `tsconfig.json` の `"declaration": true` は
コメントアウトされたままなので、`dist/` に型宣言が無い。strict な TypeScript から
deep import すると型解決に失敗する。
→ アダプタ境界に**最小限の ambient 宣言を自前で置く**。
宣言を書く＝上流の形に依存を固定することなので、置く場所を1ファイルに閉じ込め、
契約テストで実体とのズレを検出する。

**フォークしない理由**: 上流は release-please で活発に更新されている (v1.9.3)。
フォークするとツール追加・スキーマ修正を毎回マージすることになる。
ツールのロジックには一切手を入れないので、依存として持つほうが追随コストが低い。

**リスクと対策**: deep import は上流のリファクタで壊れる。
- `package.json` でパッチまで完全固定する（上流も依存を完全固定する流儀）
- `@kintone/rest-api-client` / `@modelcontextprotocol/sdk` / `zod` は
  **上流の推移的依存に頼らず、こちらの直接依存として上流と同じバージョンに固定する**。
  アダプタは3つとも型レベルで直接触るため、上流が上げたときに黙ってズレると
  「型は通るが実行時に別インスタンス」という壊れ方をする
- CI に **アダプタの契約テスト**を置く。件数だけでなく次を検証する:
  4シンボルが import でき、**ツール名の集合が期待どおり**で、
  `tools/list` の応答に **annotations が載っており**、入力スキーマが JSON Schema 2020-12 である。
  Renovate の更新 PR がここで落ちれば気づける
- **検証は npm から取得した公開パッケージに対して行う。** 上流リポジトリのソースを読んで
  「export されている」ことを確認しただけでは、配布物 (`dist/`) に同じ形で入っている保証にならない
- 壊れた場合の退避路は**上流のピン留めを上げないこと**。
  上流の `createServer()` に逃がす案は成立しない — それはプロセス単位で資格情報を固定する構造で、
  ヘッダー必須のマルチテナント (§4) とは両立しない

### 2.2 トランスポート — ステートレス Streamable HTTP

vonage と同じ。`sessionIdGenerator: undefined` + `enableJsonResponse: true`。
リクエストごとに `McpServer` と `StreamableHTTPServerTransport` を作り、`res.on('close')` で捨てる。

- ツール呼び出しは全部 1リクエスト完結で、サーバー起点の通知が無い → セッション不要
- セッションを持つとインスタンス間で状態が割れる。**kintone 版は vonage と違い
  レートリミットや Webhook ストアを持たないので、`--max-instances=1` の制約が無い**（§6）
- SSE はプロキシにバッファされることがあるので JSON で返す

**ただし「1リクエスト完結」は MCP のリクエスト単位の話で、kintone 側の処理単位ではない。**
`kintone-deploy-app` は**反映処理の開始を要求するだけ**で、完了は
`kintone-get-app-deploy-status` のポーリングで確認する。これは非同期だが、
**進行状態は kintone 側にあってこちらのプロセスには乗らない**ので、ステートレス構成と矛盾しない。

**セッションを持たないことで提供できないもの**（ドキュメントに明記する）:

| MCP の機能 | この構成での扱い |
| --- | --- |
| サーバー起点の通知 (`notifications/*`) | 提供しない。`listChanged: true` を**広告しない** |
| 別リクエストからのキャンセル | 提供しない |
| 再開 (resumability / `Last-Event-ID`) | 提供しない |
| セッション終了 (`DELETE /mcp`) | 提供しない → **405 を返す** |
| GET による SSE ストリーム | 提供しない → **405 を返す** |

**`enableJsonResponse: true` は POST の応答形式の設定であって、GET の SSE を塞がない。**
vonage の `app.all('/mcp')` をそのまま移植すると、使わない GET ストリームが開けてしまう。
メソッドごとに明示的に許可・拒否する。`MCP-Protocol-Version` ヘッダーの扱いと、
未対応バージョンに 400 を返すことも契約テストに含める。

### 2.3 vonage から流用するもの / しないもの

| 流用する | 備考 |
| --- | --- |
| `http-server.ts` の骨格 | Express 5 + body size 上限。**CORS はそのまま移植しない**（下記） |
| `requireMcpAuth` | パス単位 (`app.use('/mcp', ...)`) で GET/DELETE の漏れを防ぐ |
| `requireAllowedHost` | DNS rebinding 対策。`ALLOWED_HOSTS` |
| `/health` | 認証不要 + version を返す（デプロイ確認用） |
| `oauthResourceServer.ts` | **移植する。** RFC 9728 メタデータと `WWW-Authenticate` の組み立ては再利用できる。ただし**トークン検証は作り直す** — vonage は外部 IdP の JWT を JWKS で検証するが、こちらは**自分が発行した不透明トークンを Firestore で引く** |
| 起動時 fail-fast 設定検証 | 不正な設定でツールを1つも登録する前に落とす |
| `BIND_HOST` の既定ループバック | 認証未設定なら外部公開させない |
| Cloud Run + Secret Manager 手順 | `docs/deployment.md` 相当 |
| **流用しない / 作り直す** | |
| Webhook 系 (`webhookAuth` / `*Store`) | kintone 側に対応する非同期通知が無い |
| `--min-instances=1` の縛り | プロセス内状態が無いため不要 |
| ~~CORS 設定~~ | **Origin 検証として作り直す**（下記） |
| ~~「レートリミット不要」~~ | **撤回。上限は要る**（§7） |

**vonage の CORS をそのまま持ってきてはいけない。**
vonage は `ALLOWED_ORIGINS` 未設定のとき CORS ミドルウェア自体を素通しする。
これは「ブラウザに応答を読ませない」制御であって、**リクエストの実行を止めてはいない**。
MCP 仕様が求めるのは「不正な `Origin` があれば拒否する」ことなので、
**CORS とは独立に Origin 検証を置き、許可外の Origin が付いていれば 403 を返す**。
Origin が無いリクエスト（非ブラウザの MCP クライアント）は通してよい。

**Host 検証を「デプロイ後に設定する」運用にしない。** vonage の `requireAllowedHost` は
`ALLOWED_HOSTS` 未設定なら素通しする。§6 の2段階デプロイと組み合わせると、
**1段階目は Host 検証が効いていない状態で公開される**。
初回は `--no-allow-unauthenticated` で上げて URL を確定させ、
`ALLOWED_HOSTS` を入れてから公開に切り替える。

**`express.json()` は認証より前に動く。** vonage もその順序で、
未認証のリクエストでも上限までボディをパースする。上限値を小さく保つこと自体が防御になる。

---

## 3. 全体構成

```
スマホ / PC の Claude アプリ（カスタムコネクタ）
        │  Streamable HTTP  POST /mcp
        │  Authorization: Bearer <このサーバーが発行したトークン>
        ▼
  Cloud Run: kintone-remote-mcp
   ├ /.well-known/oauth-protected-resource   RFC 9728（認証不要）
   ├ /.well-known/oauth-authorization-server RFC 8414（認証不要）
   ├ /auth → /interaction → /oauth/callback → /token   認可サーバー (§4.6)
   │      └──────────────> cybozu.com/oauth2/*  へ委譲
   ├ requireAllowedHost / requireAllowedOrigin
   ├ requireMcpAuth           自分が発行したトークンを検証（401 + WWW-Authenticate）
   ├ resolveKintoneToken      ★ Firestore の対応表から kintone トークンを引く (§4.9)
   ├ buildServer(token)       アダプタ (§2.1) — auth: { oAuthToken } で client を生成
   └ StreamableHTTPServerTransport (stateless)
        │  @kintone/rest-api-client
        ▼
  https://<固定サブドメイン>.cybozu.com/k/v1/...
```

**ステートレスなのは MCP のリクエスト処理まで。** トークンの対応表だけが共有状態で、
Firestore に置く (§4.9)。

---

## 4. 認証設計

**目的がスマホの Claude アプリからの利用に確定したため、案B（ヘッダー必須）は破棄した。**
理由と、採用した OAuth ブリッジの設計を以下に記す。

### 4.1 なぜ案B が死んだか

スマホには**ローカルプロセスが無い**ので `mcp-remote` ブリッジを動かせない。
Claude のカスタムコネクタでカスタムヘッダーを渡す `static_headers` は存在するが、

- **beta で、提供されるのは限られた組織のみ**（ダイアログに項目自体が出ない可能性がある）
- `authorization` / `x-api-key` / `x-auth-token` 以外の名前は **Anthropic の個別承認が必要**。
  `X-Kintone-Base-Url` は承認対象

→ **スマホを前提にするなら OAuth 一択。**

### 4.2 当初の見積もりの訂正 — DCR は必須ではない

§4-案C で「MCP 側の DCR をこちらで受ける必要がある」と書いたが、**これは不正確だった。**
カスタムコネクタの追加画面には OAuth クライアントの選択肢が3つある。

| 選択肢 | 内容 |
| --- | --- |
| Use Claude's published identity (CIMD) | Anthropic がホストするクライアント情報を読ませる |
| Register automatically (DCR) | 接続のたびにクライアントを動的登録する |
| **Use your own OAuth client** | **事前登録したクライアント ID（必要ならシークレット）を入力する** |

→ **DCR を実装せずに始められる。** 自分用のコネクタなら3つ目が最も単純で、
クライアントが際限なく増える問題も起きない。DCR は後から足せる。

### 4.3 副次的な利得 — 監査の問題が解ける

§4-案B の問題として挙げた「API トークンでの操作は Administrator 名義で記録される」は、
OAuth では起きない。**操作は実際のユーザーとして記録される。**
アクセス権も本来どおり効く。

### 4.4 認可サーバーを自作しない — `oidc-provider` に委ねる

**外部レビューの判定: 「この設計のまま認可サーバーの実装を進めることは勧めない」。**
DCR を省いても、認可サーバーとしての責務（state の束縛、クライアント登録、
認可コードの束縛と使い捨て、リフレッシュのローテーションと再使用検知、失効）は残る。
これらを手書きすると、**仕様を1つ読み落とすたびに穴が空く**。

→ **OAuth の中核は [`oidc-provider`](https://www.npmjs.com/package/oidc-provider) に任せ、
自前で書くのは「cybozu への橋渡し」と「kintone トークンの保管」だけにする。**

| | 担当 |
| --- | --- |
| discovery メタデータ / `/auth` / `/token` / `/register` | **oidc-provider** |
| PKCE (S256) の検証 | **oidc-provider**（`/token` で `code_verifier` を受けた時点） |
| クライアント登録と `redirect_uri` の厳密一致 | **oidc-provider**（静的クライアント定義） |
| 認可コードの束縛・使い捨て | **oidc-provider** |
| リフレッシュトークンのローテーションと再使用検知 | **oidc-provider** |
| 失効・TTL | **oidc-provider**（Adapter 経由） |
| ログイン＝cybozu.com へのリダイレクトと code 交換 | **自前**（interaction） |
| kintone トークンの暗号化保管 | **自前**（Adapter + KMS） |
| Firestore Adapter | **自前**（薄い） |

`oidc-provider` 9.12.2 / MIT / 実依存3つ。RFC 8414 と OIDC Discovery のどちらも配れる。
**Claude は「RFC 8414 または OpenID Connect Discovery 1.0」のどちらでも受け付ける**ので、
`/.well-known/openid-configuration` のままでよい。

> **注意**: これは「ライブラリを入れれば安全」という話ではない。
> クライアント定義、scope、リソース指標、Adapter の実装は依然としてこちらの責任で、
> 以下 §4.6〜§4.9 はその設計である。

### 4.5 全体のフロー

**MCP サーバーが、Claude から見た認可サーバー (AS) を兼ねる。**
実際の認可は cybozu.com へ委譲する。二段構えになる。

```
[スマホ Claude] --(1) MCP 接続--> [kintone-remote-mcp]
                                        |
     <--(2) 401 + WWW-Authenticate: Bearer resource_metadata="..."
                                        |
     --(3) discovery: /.well-known/oauth-protected-resource
                      /.well-known/oauth-authorization-server
                                        |
     --(4) GET /auth (PKCE S256) --> [同意画面]
                                        |
                          (5) cybozu.com/oauth2/authorization へリダイレクト
                                        |
[ユーザーが kintone でログインして許可]
                                        |
                          (6) こちらの /oauth/callback に code
                                        |
                          (7) cybozu.com/oauth2/token で
                              kintone のアクセストークン/リフレッシュトークンを取得
                                        |
                          (8) こちらのトークンを発行し、対応表に保存
                                        |
     <--(9) https://claude.ai/api/mcp/auth_callback へリダイレクト
                                        |
     --(10) POST /token --> こちらのアクセストークン
                                        |
     --(11) MCP リクエスト (Authorization: Bearer <こちらのトークン>)
                                        |
                          (12) 対応表から kintone のトークンを引き、
                               auth: { oAuthToken } でクライアントを生成
                                        v
                                   kintone REST API
```

**受け取ったトークンをそのまま下流に流さない**（token passthrough の禁止）。
Claude に渡すのはこちらが発行したトークンで、kintone に渡すのは kintone のトークン。別物。

#### 二段の認可を結ぶ state — PKCE だけでは足りない

PKCE が守るのは **Claude ↔ こちら**の区間だけで、**こちら ↔ cybozu** の区間は守らない。
(6) の callback が「**このブラウザで、この接続に同意した結果**」であることは、
別の仕組みで保証する必要がある。

| 値 | 扱い |
| --- | --- |
| Claude から来た `state` | **保存してそのまま返す**。こちらは解釈しない |
| cybozu へ送る `state` | **別に生成した乱数**。短命なブラウザセッション Cookie と、承認済みの認可トランザクションに束縛する |

callback では **一致・期限内・未使用** の3つを検証する。
**「DB にその state が存在する」だけでは不足**で、それでは別ブラウザからの持ち込みを通す。

同意は **CSRF トークン付きの POST** で受ける。表示する内容は、
登録済みクライアント名 / 接続先の kintone ドメイン / 要求する権限 / 転送先ホスト。
すべて HTML エスケープし、iframe 埋め込みを禁止する。

#### ⚠ callback では `interactionFinished()` を呼べない

**provider の interaction Cookie は interaction のパスに限定して発行される**ので、
provider の管理外である `/oauth/callback` には届かない。
実装して初めて分かった制約で、経路を4つに分ける必要がある。

```
GET  /interaction/:uid          同意画面（副作用なし）
POST /interaction/:uid          同意 → cybozu へリダイレクト
GET  /oauth/callback            state 検証 → token 交換 → 保存 → finish へ戻す
GET  /interaction/:uid/finish   provider の Cookie が届く。ここで interactionFinished()
```

callback から finish へ結果を渡すときは、**URL に載せない**
（`code` / `state` と同じくログに残るため）。短命なレコードに置いて1回で使い捨てる。

### 4.6 エンドポイントとクライアント登録

**フェーズ1 は `issuer = https://HOST`（パス無し）、`resource = https://HOST/mcp` に固定する。**

`oidc-provider` の既定ルートをそのまま使う。**独自に `/authorize` を生やさない。**
パスが2つあると、流量制限とログ除外を片方にしか掛けていない、という事故になる。

| パス | 既定値（v9.12.2 で確認） |
| --- | --- |
| 認可 | **`/auth`**（`/authorize` ではない） |
| トークン | `/token` |
| 失効 | `/token/revocation` |
| discovery | `/.well-known/openid-configuration` |

Claude は **RFC 8414 と OIDC Discovery のどちらでも受け付ける**ので、
`openid-configuration` のままでよい。
将来 issuer にパスを付ける場合は、**OIDC と RFC 8414 で well-known の配置規則が違う**点に注意。

**自前で書くのは2つだけ:**

| エンドポイント | 役割 |
| --- | --- |
| `GET /interaction/:uid` | 同意画面。**POST で受ける**（CSRF トークン付き）。クライアント名・接続先 kintone ドメイン・要求権限・転送先ホストを表示する |
| `GET /oauth/callback` | cybozu.com からの戻り。**cybozu 側の OAuth クライアントにはこの URL を登録する** |

`GET /.well-known/oauth-protected-resource` (RFC 9728) も自前。
`resource` は**ユーザーが Claude に入力する MCP URL と完全一致**させる（パス込み）。
`authorization_servers` は**先頭しか見られない**。

#### クライアント登録 — 「DCR 不要」は「登録不要」ではない

**`client_id` ごとに、許可する `redirect_uri` を固定する。**
全体で1つの許可リストにすると、**Claude hosted 用の ID に localhost の転送先を
組み合わせる**といった越境ができてしまう。

| client_id | 許可する redirect_uri | 種別 | フェーズ |
| --- | --- | --- | --- |
| `claude-hosted` | `https://claude.ai/api/mcp/auth_callback` のみ | public (PKCE 必須) | **1** |
| `claude-code` | `http://localhost/callback` / `http://127.0.0.1/callback`<br>**ポートは無視して一致**(RFC 8252 §7.3) | public (PKCE 必須) | **後続** |

**フェーズ1 で登録するのは `claude-hosted` だけ。** 目的はスマホなので、
Claude Code 対応は後続に回す。ループバック転送先を最初から許すと、
検証対象が増えるわりに目的に近づかない。

- **cybozu.com の `client_id` / `client_secret` とは完全に別物。** 混同しない
- シークレット無しの事前登録も **public client** なので、
  リフレッシュトークンのローテーション義務はかかる (RFC 9700 §4.14)
- `resource` は固定の MCP URL と照合する。`/auth` と `/token` の両方で

#### 応答ヘッダー

| 対象 | ヘッダー |
| --- | --- |
| `/token` の応答 | `Cache-Control: no-store` |
| 同意画面・`/oauth/callback` | `Referrer-Policy: no-referrer`、`X-Frame-Options: DENY` |
| 同意画面の Cookie | `Secure` / `HttpOnly` / `SameSite=Lax` |

#### 401 は必ず返す

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://.../.well-known/oauth-protected-resource"
```

**`200` に `WWW-Authenticate` を付けても Claude は見ない。**
ここを間違えると「MCP サーバーには届いているのに認可サーバーには一切アクセスが来ない」
という切り分けにくい失敗になる。

#### 守るべき制限

#### エラーの返し分け

**「リフレッシュ失敗はすべて `invalid_grant`」にしない。**
一時的な障害まで「認可が切れた」と見せると、ユーザーに不要な再接続を強いる。

| 状況 | 返すもの |
| --- | --- |
| リフレッシュトークンが無効・失効済み | `invalid_grant` |
| クライアント認証の失敗 | `invalid_client` |
| パラメーター不正 | `invalid_request` |
| Firestore / KMS / cybozu の障害 | **5xx**（`invalid_grant` にしない） |
| `/mcp` で無効なトークン | 401 |
| `/mcp` で scope 不足 | 403 |
| `/mcp` で保存基盤の障害 | 503 |

**kintone のアクセストークンの期限切れを、そのまま Claude の認可切れとして扱わない。**
こちらがリフレッシュすればよいだけの状態で 401 を返すと、
ユーザーに再ログインを求めることになる。

| 項目 | 制限 |
| --- | --- |
| discovery / register / token の応答 | **10秒以内** |
| refresh の応答 | **30秒以内** |
| Anthropic からの送信元 IP | `160.79.104.0/21`。**ただしこの制限を同意画面に掛けない** — そこを通るのはユーザーのブラウザ |

### 4.7 cybozu.com 側の準備

- **.com 共通管理者が OAuth クライアントを登録する**（1ドメイン20個まで）
- リダイレクトエンドポイントに**こちらの `/oauth/callback`** を登録
- 「利用者の設定」で、使うユーザーを明示的に許可する（**後から追加したユーザーは都度設定が要る**）
- **要求するスコープは、その時点で有効な機能から導出する。**
  既定ポリシーが読み取り専用 (§5) なのに書き込みスコープまで最初に取ると、
  **同意画面の表示と実際の上限が食い違う**。フェーズ1 は読み取りだけを要求する。

  | フェーズ | 要求するスコープ |
  | --- | --- |
  | 1（読み取り） | `k:app_record:read` `k:app_settings:read` |
  | 書き込みを開くとき | 上記 + `k:app_record:write` `k:app_settings:write` → **再同意させる** |
  | ファイル取得を開くとき | + `k:file:read` |

  実行可否は **「サーバーポリシー ∩ 接続時に同意した scope ∩ kintone のアクセス権」**の積で決める
- アクセストークンの有効期間は1時間。リフレッシュトークンに期限は無いが、
  **1クライアントあたり1ユーザー10個まで**。使い捨てにすると枯れる

### 4.8 単一テナント（1デプロイ＝1 kintone ドメイン）

**cybozu.com の認可エンドポイントはサブドメイン固有**
(`https://<sub>.cybozu.com/oauth2/authorization`) で、OAuth クライアントもドメインごとに登録する。

マルチテナントにすると、認可を始める前にサブドメインを確定させる画面が要り、
ドメインごとの `client_id` / `client_secret` を保管することになる。
**目的が自分のドメインをスマホから使うことなので、1デプロイ1ドメインにする。**
`KINTONE_BASE_URL` はサーバーの設定に戻る。

→ **これに伴い、案B で必要だった SSRF 対策（ヘッダーで任意の baseUrl を受ける）は不要になる。**
`baseUrl` は起動時に固定され、リクエストからは変えられない。

### 4.9 保存モデル

ステートレスを崩す唯一の箇所。**Firestore に置く。**
`oidc-provider` の Adapter として実装するが、**3種類を分けて持つ**。
1つのレコードに混ぜると、失効の単位と期限の単位が合わなくなる。

| レコード | 内容 | 寿命 |
| --- | --- | --- |
| **認可トランザクション** | cybozu 向け `state`、ブラウザセッション、Claude の `state`、承認済み scope、`client_id`、`resource` | 数分 |
| **接続 grant** | kintone のアクセストークン / リフレッシュトークン（暗号化）、kintone の有効期限、同意した scope | ユーザーが切断するまで |
| **こちらの access / refresh トークン** | **ハッシュのみ**。grant への参照、期限、世代 | access は短命、refresh は世代管理 |

原則:

- **トークンとコードは平文で保存しない。** ハッシュを保存して照合する
- **コードの消費は「未使用を条件にした更新」で行う。**
  ただし**「消費と発行の全体が1つの transaction」にはならない** —
  provider はコード取得・消費・トークン保存を別々の Adapter 呼び出しで行う。
  保証するのは次の3つで、実現方法は §4.10 に書く。
  **(a) 二重に成功しない (b) 失効後に使えない (c) 中断時は安全側に閉じる**
- **transaction の再実行対象の中で外部 API（cybozu の token エンドポイント）を呼ばない。**
  再実行のたびに上流を叩くことになる
- **TTL は掃除であって認可判定ではない。** Firestore の TTL 削除は最大24時間程度遅れうるので、
  **使用のたびに期限と失効状態を検証する**
- アクセストークンの期限切れで**接続 grant まで消さない**。
  使用済みリフレッシュの履歴も、再使用検知のために早すぎる削除をしない

**cybozu のリフレッシュ応答には新しいリフレッシュトークンが含まれない**
（公開仕様の応答は `access_token` / `token_type` / `expires_in` / `scope` のみ）。
**既存のリフレッシュトークンを保持し続ける。** 上流のリフレッシュとこちらの
リフレッシュトークンのローテーションは**別の処理**で、混同すると接続が切れる。

上流の token 交換が成功した後に保存が失敗した場合・応答を取りこぼした場合の扱いも決める
（リフレッシュトークンは発行済みなのに手元に無い、という状態になる）。

#### 暗号化の範囲と、防げないもの

kintone のトークンは **Cloud KMS でエンベロープ暗号化**する。
認証付き暗号を使い、**AAD に grant の識別子を入れて暗号文を grant に束縛する**
（別レコードへの差し替えを検出するため）。DEK と nonce の管理、鍵の版、
ローテーション手順を決める。

**ただし KMS は、復号権限を持つ実行サービスアカウントの侵害を防がない。**
Firestore への書き込みを奪われた場合の、トークンハッシュと grant の対応の差し替えも防がない。
**暗号化が守るのは「保存データだけが漏れた場合」である**と明記し、
それ以上を期待しない。

KMS の利用監査を残すには **Data Access audit logs の有効化**がデプロイ手順に要る（既定では無効）。

### 4.10 `oidc-provider` の設定と Adapter の契約

**「ライブラリを採用した」だけでは、本番の認証にも MCP 用アクセストークンにもならない。**
v9.12.2 のソースで確認した既定値を踏まえ、決めるべきことを固定する。

#### 設定表

| 設定 | 値 | 理由 |
| --- | --- | --- |
| `features.devInteractions` | **`{ enabled: false }`** | **既定は `true`。** 開発用のログイン画面が有効なまま公開されうる |
| `features.revocation` | **`{ enabled: true }`** | **既定は `false`。** 切断を実装するのに要る |
| `features.resourceIndicators` | `enabled: true` + **`getResourceServerInfo` を実装** | 既定の実装は「必ず差し替えろ」と例外を投げる。ここで audience と scope を固定 MCP resource に束縛する |
| `clients[].token_endpoint_auth_method` | `none` | public client。シークレットを持たない |
| `pkce.required` | 常に必須 | Claude は常に S256 を送る |
| `grant_types` | `authorization_code` / `refresh_token` | それ以外は許可しない |
| `formats.customizers` | 使わない（不透明トークン） | JWT にすると失効できない |
| `cookies.keys` | **Secret Manager から。全インスタンスで共有** | 署名鍵がインスタンスごとに違うと interaction が壊れる |
| `proxy` | `true` | Cloud Run は TLS を手前で終端する。設定しないと `https` の issuer を組めない |

#### `/mcp` での受信トークン検証

**「provider が発行したから正しい」で済ませない。** MCP 仕様は受信側での検証を要求する。

| 検証 | 落とす条件 |
| --- | --- |
| トークンの種別 | **`AccessToken` 以外を Bearer として受け付けない**（リフレッシュトークンを投げ込まれても通さない） |
| 有効期限 | 期限切れ |
| audience | 固定の `resource`（`https://HOST/mcp`）と不一致 |
| scope | ツールに必要な scope を含まない → **403** |
| grant の生存 | 接続 grant が失効済み → 401 |

#### Adapter の契約 — ここが自作の中心

**`oidc-provider` に任せても原子性は自動では得られない。**
実装は「検索 → 使用済み判定 → `consume()` → 新トークン保存」という別々の操作で、
**同時リクエストが両方「未使用」を読めば両方進む。**

| 要件 | 実現方法 |
| --- | --- |
| **二重成功しない** | `consume` を**未使用を条件にした更新**にする（Firestore の transaction で「読んだ時点の状態」を前提条件にする） |
| **競合したら系列ごと失効させる** | ⚠ **エラーを投げるだけでは足りない。** provider の失効処理は「取得したオブジェクトの `consumed` が真」のときにだけ走る。2要求が未使用状態を読んだ後で片方の `consume()` が例外を投げても、その経路には入らず**先行要求のトークンが生き残る**。→ **競合を検知した transaction の中で接続 grant の失効を確定し、コミットしてから `invalid_grant` を返す。** transaction 内で例外を投げると失効の更新まで巻き戻る |
| **失効後に発行しない** | 新トークンの保存時にも失効状態を確認し、**その確認と保存を同一 transaction に入れる** |
| **失効後に使えない** | 接続 grant に**永続的な失効フラグ**を持ち、**保存時にも利用時にも照合する**。「失効処理の後にトークン文書が作られる」経路を塞ぐ |
| **中断時は安全側に閉じる** | 上流の交換に成功した後で保存に失敗したら、**無理に再交換せず再認可に戻す**（リフレッシュトークンは発行済みなのに手元に無い、という状態になりうる） |

#### ⚠ 不透明トークンは、そのまま保存すると平文で残る

v9.12.2 のソースで確認した事実:

```js
// lib/models/base_model.js
const IN_PAYLOAD = ['iat', 'exp', 'jti', 'kind'];
await this.adapter.upsert(this.jti, payload, ttl);

// lib/models/formats/opaque.js
return { value: token.jti, payload };   // クライアントに渡す値 = jti
```

→ **クライアントが持つ Bearer トークンの値そのものが `jti`** で、それが
**Firestore の文書 ID にも payload にも入る。**
**文書 ID だけをハッシュ化しても、本文に平文が残る。**

Adapter で次を行う:

| 操作 | 実装 |
| --- | --- |
| `upsert(id, payload, ttl)` | 文書 ID は `hash(id)`。**payload から生の `jti` を除いて保存する** |
| `find(id)` | `hash(id)` で引き、**戻す payload に `jti` を復元して詰め直す**（provider は `jti` がある前提で動く） |
| `findByUid` / `findByUserCode` | ⚠ **`find(id)` と同じ手は使えない。** 引数は `uid` であって `jti` ではないので、**戻す payload に `jti` を復元できない**。provider の `Session` は `uid` と `jti` が別値で、`jti` を欠いたまま返すとコンストラクタが別の値を作ってしまう |

**モデルごとに保存・復元の契約を分ける。**

| モデル | 検索の入口 | 保存 |
| --- | --- | --- |
| `AccessToken` / `RefreshToken` / `AuthorizationCode` | `find(id)` のみ。`id` が秘密 | 文書 ID は `hash(id)`、payload から生 `jti` を除去。`find` で引数から復元 |
| `Session` | `find(jti)` と **`findByUid(uid)`** | `uid` で引けるようにしつつ、**`jti` は暗号化して保存**（除去すると `findByUid` で復元できない） |
| `Interaction` | `find(jti)` | ⚠ **`interaction.session.cookie` に Session の生 `jti` が入る。** トップレベルだけ見ても取りこぼす。**ネストした秘密も暗号化する** |
| `Grant` / `ClientCredentials` 等 | `find(id)` | 秘密を含まないなら素通し。含むなら上に準じる |

**`findByUid` → 更新 → 削除**の往復と、
**既存セッション付きの interaction** の往復をテストで固定する。

**§9 の「秘密が出てこない」テストは、ログだけでなく
Firestore の文書 ID・本文・索引まで対象にする。**

#### リフレッシュトークンの発行方針

⚠ **`grant_types` に `refresh_token` を入れるだけでは、リフレッシュトークンは一度も発行されない。**
v9.12.2 のソースで確認した2つの既定が噛み合っている。

```js
// lib/helpers/defaults.js — 既定の発行条件
async function issueRefreshToken(_ctx, client, source) {
  return client.grantTypeAllowed('refresh_token') && source.scopes.has('offline_access');
}

// lib/actions/authorization/scopes.js — offline_access はこの条件で捨てられる
if (scopes.includes('offline_access')) {
  if (... || (PARAM_LIST.has('prompt') && !prompts.has('consent')) || ...) {
    scopes.splice(scopes.indexOf('offline_access'), 1);
  }
}
```

**`prompt=consent` を含まない認可要求では `offline_access` が除去され、
その結果 `issueRefreshToken` が false を返す。**
Claude がこのパラメータを送る保証は無い。
`scopes_supported` にメタデータとして載せるだけでは足りない。

**決定（フェーズ1）:**

| 項目 | 決定 |
| --- | --- |
| `issueRefreshToken` | **差し替える。`offline_access` に依存せず、承認済みブリッジを完了した `claude-hosted` には常に発行する** |
| 同意画面 | **継続アクセス（オフラインでの利用）への同意を明示的に含める。** scope に現れない以上、画面で伝える責任がこちらにある |
| `expiresWithSession` | **`false`**。ブラウザのセッションが切れても接続を維持する（スマホから使うので、ブラウザは認可のときだけ） |
| ローテーション | public client なので**ローテーションする**。再使用検知で系列を失効 |

> **ローテーションの注意**: v9.12.2 の既定 `rotateRefreshToken` には、
> **系列の総寿命が約1年を超えると `false` を返す分岐**がある。
> 方針を明示的に書き、既定任せにしない。

#### 新規接続は必ずブリッジを通す

⚠ **既定の `loadExistingGrant` と interaction policy は、既存のセッションと同意を再利用する。**
同じブラウザから2つ目の接続を作ると、**同意画面も cybozu のログインも飛ばして
新しいトークンが出る** — つまり新しい接続 grant（= kintone のトークン）が作られない。

→ **新規の認可要求では必ず承認済みブリッジを通し、新しい Grant を作る policy を定義する。**
テスト対象に **「同じブラウザでの2接続」「再接続」「片方だけの失効」** を入れる。

#### 主体（accountId）と Grant の対応

cybozu の token 応答にユーザー識別子が無い (§7.5) ので、**provider に返す主体はこちらで作る。**

```
interaction UID
  → 認可トランザクション（cybozu 向け state / ブラウザ Cookie / Claude の state）
  → 内部主体 accountId（接続ごとのランダム値。kintone のユーザー名ではない）
  → provider の Grant（scope / resource を登録）
  → 接続 grant（kintone のトークンを暗号化して保持）
```

- **接続ごとに新しい内部主体を作る。** 再接続で既存の資格情報を上書きしない
- **切断・再使用検知・上流の失効は、provider の Grant と接続 grant の両方、
  およびそこから出た全トークンに伝播させる**
- `findAccount` は内部主体を返すだけ。kintone を叩かない

#### ブリッジ Cookie

**provider の interaction Cookie は interaction のパスに限定される。**
`/oauth/callback` は provider の管理外なので、そのままでは検証できない。

- **独立したブリッジ Cookie を発行する。** Path は `/oauth/callback` を含む範囲に限定し、
  `Secure` / `HttpOnly` / `SameSite=Lax`
- callback の処理後、**provider の interaction を再開する**経路を明示する
  （`interactionFinished` に戻す）

---

### 4.11 ログイン方法を2つ用意する（フェーズ2）

**スペース系4ツールと `kintone-search` は、OAuth では実行できない。**
スコープが無いからではなく、**API 自体がパスワード認証／セッション認証しか受け付けない**
（`GET /k/v1/space.json` のドキュメントに明記）。

そこで、こちらの同意画面でログイン方法を選べるようにする。
**Claude から見ればどちらも同じ OAuth 接続**で、違うのは同意画面で何を渡すかだけ。

| ログイン方法 | kintone への認証 | ツール数 | 資格情報 |
| --- | --- | --- | --- |
| **kintone OAuth に委譲**（フェーズ1） | OAuth アクセストークン | **22** | トークンのみ。パスワードは知らない |
| パスワードを入力（フェーズ2） | `X-Cybozu-Authorization` | **27** | **パスワードを暗号化して保管する** |

**フェーズ1では OAuth だけを作る。** 理由は、認可サーバーの実装とパスワード保管の設計を
同時に走らせると、どちらも検証しきれないため。スペース操作は「最悪諦める」前提で合意済み。

パスワード方式を足すときの前提:

- **このサーバーが kintone のパスワードの預かり先になる。** KMS で緩和はできるが事実は消えない
- **2要素認証を有効にしたユーザーはパスワード認証で REST API を実行できない**（確認済み: 現在は無効）
- SAML 認証だけに制限した環境では、共通管理者しか使えない

---

## 5. ツール公開ポリシー（ガードレール）

**まず、OAuth では実行できないツールがある。**
kintone の OAuth スコープは6つしかなく、次の5ツールに対応するものが存在しない。

| 使えないツール | 理由 |
| --- | --- |
| `kintone-get-space` / `update-space` / `delete-space` / `add-space-from-template` | スペース API は**パスワード認証／セッション認証のみ**（スコープの問題ではない） |
| `kintone-search` | 同上 |

→ **OAuth で技術的に実行可能なのは 22 ツール**。ただし**公開される数とは別物**なので混同しない。

| 数え方 | 数 |
| --- | --- |
| 上流の全ツール | 27 |
| OAuth で実行可能 | **22**（スペース4 + search を除く） |
| `ENABLE_FILE_DOWNLOAD=false`（既定）を踏まえた上限 | **21** |
| **既定ポリシーで実際に公開される数** (§5 の表) | **9**（レコード読み取り2 + アプリ読み取り7） |

フェーズ2 でパスワードログインを足しても 27 に戻るとは限らない。
**`kintone-search` は API Lab（検討中機能）扱いで、ドメイン側で機能を有効化する必要がある。**

**⚠ 上流の `shouldEnableTool` はこれを知らない。** あれが見るのは `isApiTokenAuth` だけで、
OAuth のときは `false` になるため**27個すべてを登録してしまう**。
アダプタ側に「OAuth のときに落とす5つ」のフィルタを自前で持つ。

なお **API トークン認証とは落ちるツールが違う**。
`kintone-get-apps` / `kintone-add-app` は API トークンでは使えないが、
**OAuth（`k:app_settings:read/write`）では使える**。

#### アプリ単位の境界が失われたことへの対処

初版の付録で「アプリ単位で発行される API トークンが被害範囲を絞るので、独自 ACL は不要」
と書いたが、**OAuth に変更したことでこの前提は消滅した。**
OAuth のスコープは**操作種別の区分であって、対象アプリの区分ではない**。
本人が広い権限を持っていれば、**その全範囲が Claude に開く**。

フェーズ1 の対処は軽いもので足りる。

- **`ALLOWED_APP_IDS`（固定リスト）を持つ。** 指定があればそのアプリ以外は拒否する
- **`app` 引数だけを見ても足りない。** フェーズ1 の9ツールを上流のソースで調べたところ、
  **アプリ ID を運ぶパラメータ名は3種類あり、列挙系は引数が無くても結果にアプリが出る。**

| ツール | アプリ ID の在り処 | 扱い |
| --- | --- | --- |
| `kintone-get-app` | **`appId`**（単数） | 許可外なら拒否 |
| `kintone-get-form-fields` | `app` | 同上 |
| `kintone-get-form-layout` | `app` | 同上 |
| `kintone-get-general-settings` | `app` | 同上 |
| `kintone-get-process-management` | `app` | 同上 |
| `kintone-get-records` | `app` | 同上 |
| `kintone-get-record-comments` | `app` | 同上 |
| `kintone-get-app-deploy-status` | **`apps[]`**（文字列／数値の配列、最大300） | **全要素を検査する。** 1つでも許可外なら拒否 |
| `kintone-deploy-app` | **`apps[].app`**（⚠ **オブジェクトの配列**） | 同上 |
| `kintone-get-apps` | **`ids[]`**（省略可） | 指定があれば**問い合わせ前に**検査。省略時は結果を絞る |

⚠ **同じ `apps` という名前で形が違う。**
`get-app-deploy-status` は `["10","99"]`、`deploy-app` は `[{app:"10"},{app:"99"}]`。
一方の形だけを見る実装にすると**もう一方が素通りする**（実際にそうなっていた）。

⚠ **`get-apps` は「引数が無い」わけではない。** `ids[]` で明示できる。
結果の絞り込みだけに頼ると「許可外は問い合わせる前に拒否する」が成立しない。

- **`kintone-get-apps` は同じデータを `structuredContent` と `content[].text` の
  両方に載せて返す**（上流のソースで確認）。
  **片方だけ絞ると、もう片方から漏れる。** 絞った後の同一データから両方を組み立てる
- 書き込みを開ける段では `kintone-deploy-app` の複数アプリ指定も同様に扱う
- 公開ゲート (§9) に「許可外 ID の直接指定」「許可内と許可外の混在指定」
  「引数なしの列挙」を入れる
- リストを設定しない運用にするなら、**「本人がアクセスできる全アプリが対象になる」と
  ドキュメントに明記する。** 消えた防御が残っているかのように書かない
- **空文字は「制限なし」として扱う。** 「1つも許可しない」と読むと、
  設定ミスで全ツールが黙って動かなくなり、原因が分かりにくい
- 拒否は **kintone に問い合わせる前**に行う。
  エラー分類は `app_not_allowed`（kintone の権限不足 `forbidden` とは別物）

**書き込みは開ける方針**だが、既定値は読み取り専用にして、有効化は明示的な操作にする。
リモート公開はプロンプトインジェクションの射程が広がるので、
「デプロイしたら全27ツールが生えていた」という状態を作らない。vonage の capability フラグと同じ考え方。

なお、**実際に何ができるかを最終的に決めるのは kintone 側の権限**
（ヘッダーで渡された API トークン／ユーザーのアクセス権）である。
ここの環境変数は、その手前に置くサーバー全体の上限にすぎない。

| 環境変数 | 既定 | 対象 |
| --- | --- | --- |
| `ENABLE_RECORD_READ` | `true` | get-records / get-record-comments |
| `ENABLE_RECORD_WRITE` | `false` | add-records / update-records / update-statuses / add-record-comment |
| `ENABLE_APP_READ` | `true` | get-app(s) / get-form-* / get-general-settings / get-process-management / get-app-deploy-status |
| `ENABLE_APP_WRITE` | `false` | add-app / add-form-fields / update-form-fields / update-form-layout / update-general-settings / deploy-app |
| `ENABLE_SPACE_READ` | `false` | get-space（**フェーズ2 まで使用不可**） |
| `ENABLE_SPACE_WRITE` | `false` | update-space / add-space-from-template（**同上**） |
| `ENABLE_SEARCH` | `false` | search（**フェーズ2 まで使用不可**。全文横断検索は情報漏えいの射程も広い） |
| `ENABLE_FILE_DOWNLOAD` | `false` | download-file — **リモートでは原則 OFF**（§1-d） |
| `ALLOW_DESTRUCTIVE` | `false` | **delete-records / delete-form-fields / delete-space** |

- **スペースは読み取りと書き込みを別フラグにする。** 当初 `ENABLE_SPACE` ひとつにしていたが、
  これは**閲覧を許すと同時に変更も許す**設計だった。
  `kintone-update-space` は `isPrivate` や参加メンバーを変更でき、
  **スペースを公開範囲ごと書き換えられる**
- **削除系は上の `ENABLE_*` を満たしたうえで `ALLOW_DESTRUCTIVE=true` も要求する。**
  `kintone-delete-records` はレコードを、`kintone-delete-form-fields` はフィールドとその中身を、
  `kintone-delete-space` はスペースごと消す。いずれも**復旧不能**で、
  「書き込みを許可した」ことと「消してよい」ことは別の判断である
- **ただし「削除フラグを閉じれば壊れない」ではない。**
  - `kintone-update-records` は**値を空にできる**。削除ツールを封じてもデータは消せる
  - `kintone-update-form-fields` / `update-form-layout` はフォームの構造を変える
  - `kintone-deploy-app` は**動作テスト環境の変更を本番へ反映する**。
    自分が加えた変更だけでなく、**他の管理者が作業中の未反映の変更も一緒に本番へ出す**
  → `ENABLE_APP_WRITE` を開けることは、`ALLOW_DESTRUCTIVE` を閉じていても
  「アプリを壊せる」状態を作る。開ける判断は `ALLOWED_APP_IDS` と組で考える
- 更新系では **`revision` を指定して楽観ロックを効かせる**運用を手順書に書く。
  上流の `update-records` は `revision` を受け付ける。指定しないと、
  他の人の更新を黙って上書きする
- 上流のツールには `annotations` (readOnlyHint / destructiveHint) が付いていない。
  アダプタ側で名前ベースに付与する。付けないとクライアントは全ツールを
  「破壊的かどうか不明」として扱い、確認 UI の出方が基盤の既定任せになる。
  **§2.1 のとおり `buildToolDefinition` が annotations を落とすので、一覧生成側でマージする**
- **annotations は「ヒント」であって強制力はない。**
  readOnlyHint を付けたから安全になるわけでも、destructiveHint を付けたから
  クライアントが必ず確認を出すわけでもない。実際の制御は `ENABLE_*` と
  kintone 側の権限でやる

### プロンプトインジェクションの扱い

**ツールの実行結果は非信頼データである。** レコードの本文、コメント、
`kintone-search` の検索結果には、**第三者が書き込んだテキストが入る**。
エージェントがそれを指示として読めば、**すでに許可されているツールだけを使って**
データを壊したり、別アプリの内容を読み出して外部に持ち出したりできる。

- これは `ENABLE_*` では防げない。許可の範囲内で起きるため
- 防御は「射程を狭くすること」に尽きる。**`ALLOWED_APP_IDS` によるアプリの限定**が効く。次点が `ENABLE_*` の最小化。
  （初版では「アプリ単位の API トークン」を挙げていたが、**OAuth では成立しない**。
  OAuth のスコープは操作種別の区分で、対象アプリの区分ではない）
- **`ENABLE_SEARCH` の既定 `false` はこの理由でも正しい。**
  全文横断検索は、攻撃者が仕込んだ文字列を拾う経路であると同時に、
  仕込みに成功した後の情報収集の経路でもある
- `kintone-download-file` を有効化する場合は、ローカル保存ではなく
  **base64 で content に載せて返す**か、**署名付き URL を返す**設計に差し替える
  （= 上流のツールをそのまま使えない。アダプタで差し替える）

---

## 6. インフラ設計 (Google Cloud Run)

vonage と同じ構成。**違いは「複数インスタンスを許容できる」こと。**

| 項目 | vonage | kintone |
| --- | --- | --- |
| `--max-instances` | **1 必須**（レートリミットがプロセス内メモリ） | 制約なし（10 など） |
| `--min-instances` | 1 推奨（DLR ストア保持） | 0 で可（コールドスタート許容） |
| Secret Manager | private.key / MCP_AUTH_TOKEN | **cybozu OAuth の client_id / client_secret** |
| データストア | なし | **Firestore**（トークン対応表 §4.9） |
| 鍵管理 | なし | **Cloud KMS**（kintone トークンのエンベロープ暗号化） |
| Webhook | あり | **なし**（ただし `/auth` `/interaction` `/oauth/callback` `/token` は認証不要で公開する） |
| 送信 IP 固定 | 不要 | **不要**（kintone 側の IP アドレス制限は未使用と確認済み） |

**GCP プロジェクトは vonage-mcp-server と同一。** リージョンも `asia-northeast1` を揃える。
同居にあたって注意する点:

- **シークレット名を衝突させない。** vonage 側に `mcp-auth-token` が既にある。
  こちらは `kintone-mcp-auth-token` のように接頭辞を付ける
- **サービスアカウントを分ける。** 既定の Compute SA を共用すると、
  片方の権限がもう片方にもそのまま乗る。`kintone-remote-mcp@` を作り、
  **自分の Secret だけ**を読ませる
- **サービス名・イメージ名は権限境界ではない。** 分離は SA と IAM でしか実現しない
- **デプロイ側の権限も分ける。** Cloud Build / デプロイ実行者が
  vonage のサービスや Secret を更新できる状態なら、kintone 側の侵害が vonage に届く
**構成（実装済み。詳細は `docs/firestore.md`）:**

- **単一コレクション**（既定 `oidc`）。文書 ID は `<model>__<key>`。
  モデルごとにコレクションを分けると `revokeByGrantId()` が全モデル横断の検索になり、
  **失効の取りこぼしが即セキュリティの穴になる**
- 索引は**単一フィールドの等価検索のみ**（`model` / `uidHash` / `userCodeHash` / `grantId`）。
  複合索引は不要
- `consume()` と `update()` は **transaction 内で読んで書く**。
  Firestore は競合時にコールバックを再実行するので、
  **その中で外部 API を呼ばない**（`Storage` の契約で mutator を同期関数に限っている）

- **Firestore はコレクション名では分離できない。**
  サーバー SDK は Security Rules を迂回するので、あれは権限境界にならない。
  **専用の Firestore データベースを作り、データベース条件付きの IAM で縛る**
  （それが難しければ専用プロジェクトにする）。
  **別の SA がトークン文書を読めないことを、実際の IAM で検証する**
- **KMS の鍵はこのサービス専用にする。** 鍵の使用を監査に残すには
  **Data Access audit logs の有効化が要る**（既定では無効）
- **同居を選んだ以上、共有されるものを受け入れる**: プロジェクト単位のクォータ、
  プロジェクト IAM 管理者、課金。片方の暴走がもう片方の可用性に影響する
- Artifact Registry は共用でよい

```bash
# 1段階目: 非公開で上げて URL を確定させる（Host 検証を入れる前に公開しない）
gcloud run deploy kintone-remote-mcp \
  --source . --region asia-northeast1 \
  --no-allow-unauthenticated \
  --service-account="kintone-remote-mcp@$PROJECT_ID.iam.gserviceaccount.com" \
  --max-instances=10 --concurrency=20 --timeout=120 \
  --set-env-vars="KINTONE_BASE_URL=https://YOUR.cybozu.com" \
  --set-env-vars="ENABLE_RECORD_READ=true,ENABLE_APP_READ=true" \
  --set-secrets="CYBOZU_OAUTH_CLIENT_SECRET=kintone-oauth-client-secret:1"   # ← latest ではなく固定版

# 2段階目: ALLOWED_HOSTS / ALLOWED_ORIGINS を入れてから公開に切り替える
HOST=$(gcloud run services describe kintone-remote-mcp --region=asia-northeast1 \
  --format='value(status.url)' | sed 's|https://||')
gcloud run services update kintone-remote-mcp --region=asia-northeast1 \
  --update-env-vars="ALLOWED_HOSTS=$HOST,OAUTH_ISSUER=https://$HOST"
# ここで初めて cybozu.com 側の OAuth クライアントに
# https://$HOST/oauth/callback を登録できる（URL が確定するまで登録できない）
gcloud run services add-iam-policy-binding kintone-remote-mcp --region=asia-northeast1 \
  --member=allUsers --role=roles/run.invoker
```

**`:latest` を使わない。** Secret のローテーションが、こちらの意図しない
タイミングで稼働中のリビジョンに効く。版を固定し、更新はデプロイで行う。

Dockerfile は上流の `docker/Dockerfile` (distroless + pnpm) を踏襲するが、
ENTRYPOINT を `dist/http-server.js` に変え、`EXPOSE 8080` / `PORT` を Cloud Run に合わせる。

**その他の考慮**
- PFX クライアント証明書（セキュアアクセス）は**サポート外** (§4)。
  将来セキュアアクセス環境に繋ぐ必要が出たら、そのドメイン専用の単一テナント
  インスタンスを別に立てるほうが素直
- 流量・タイムアウト・エラー・監査は §7 にまとめる

---

## 7. 流量制御・タイムアウト・エラー・可観測性

初版では「課金が発生しないのでレートリミットは不要」と書いていたが、**これは撤回する。**

### 7.1 上限を置く理由

- **Cloud Run のコストは発生する**（CPU・メモリ・下り通信・ログ）
- **kintone 側の API 制限を使い切ると、そのドメインの通常業務が止まる。**
  こちらの都合で相手の環境を壊すことになる
- `--max-instances=10` は**同時 API 呼び出し数の上限ではない**。
  1インスタンスが同時に何本 kintone を叩くかは別の話
- 資格情報を大量に変えたリクエストを投げれば、クライアント生成のコストを突ける

### 7.2 置く上限

| 上限 | 置き方 |
| --- | --- |
| Cloud Run の同時実行 | `--concurrency` を明示（既定80は多すぎる） |
| インスタンス数 | `--max-instances` に上限 |
| **テナント別の同時実行** | `baseUrl` のホスト名ごとに in-flight 数を制限 |
| 認証後の流量 | **grant（接続）単位**で秒間・時間あたりの上限。トークン単位にしない（更新で枠が戻る） |
| リクエストボディ | `express.json({ limit })` を小さく保つ（認証より前に走るため） |
| 応答サイズ・取得件数 | ツール引数の上限（上流のスキーマにも `max(100)` などがある） |
| **`/auth` の乱打** | **未認証者が認可トランザクション文書を量産できる。** 保存する前に制限する |
| **でたらめな Bearer / code** | **Firestore 照会と KMS 復号を誘発する。** 無効トークンで KMS を呼ぶ経路を作らない（ハッシュ照合で先に落とす） |
| 認可トランザクション | 同時数と寿命に上限 |
| `x-www-form-urlencoded` | サイズとパラメーター数の上限 |

**制限の単位を、認証前と認証後で分ける。** 未認証のリクエストには grant が存在しない。

| 区間 | 単位 | 適用する位置 |
| --- | --- | --- |
| **認証前**（`/auth` / `/token` / 無効な Bearer） | 送信元 + **サービス全体の総量** | **Firestore を引く前・KMS を呼ぶ前** |
| **認証後**（`/mcp`） | **grant（接続）単位 + インスタンス全体** | ツール実行前 |

**送信元ごとの枠は、総量の上限にならない。**
送信元は詐称でも分散でも増やせる。特に `X-Forwarded-For` を全面的に信頼すると、
**ヘッダーを1行足すだけで枠を作り直せる**（第10回レビューで実測）。
Cloud Run は既存の値を検証も削除もせず**実 IP を末尾に追記するだけ**なので、
左端ではなく**右から数えたホップ**を見る。
そのうえで、**送信元を見ない総量の枠**を必ず1つ置く。

**grant 単位の同時実行は、上流の上限にならない。**
接続が増えるほど枠の合計が増えるため、kintone への同時実行は接続数に比例して伸びる。
kintone は**ドメインあたり100同時要求**が上限で、超過は同じドメインの他の利用にも響く。
→ **インスタンス全体の枠**を別に置く。

ただし **`枠 × --max-instances` は最悪値にならない**。
`--max-instances` は**リビジョン単位**で、デプロイ中は新旧が重なり、
Cloud Run は設定値を**一時的に超えることもある**。
掛け算で出るのは下限に近い目安であって、上限ではない。

**トークンを単位にしない。** こちらのアクセストークンは更新されるので、
更新のたびに枠がリセットされる。grant は接続が続く限り同一。

**これらはインスタンス単位でしか効かない**（プロセス内メモリ）。
複数インスタンスでは実効的に「インスタンス数倍」に緩む。
**厳密にやるなら共有ストアが要るが、フェーズ1では入れない。**
ただし**許容する理由を「課金が直撃しないから」にしない** —
Firestore と KMS を導入した時点でその説明は成り立たない。

フェーズ1 で緩い制限を許容する条件を、次のように明示する。

- **上限は置けない**ことを前提にする。インスタンスをまたいで数えていないので、
  「これ以上は出ない」と言える数は存在しない。
  `--max-instances` を掛けた数も**上限ではない**
  （リビジョン単位 + デプロイ中の重なり + 一時超過）
- **再起動で枠が戻る**（プロセス内メモリなので）
- 置けるのは「1インスタンスあたりの歯止め」だけ。
  既存業務と同じドメインで動かすなら、**歯止めとインスタンス数の両方を、
  重なりと一時超過を見込んだ値まで下げる**
- **監視の閾値と、止める判断・手順を先に決めておく**。
  上限を保証できない以上、気づいて止められることが唯一の担保になる
- 不足が実測で分かった時点で共有ストアに移す

### 7.3 タイムアウトと「結果不明」

**HTTP 接続が切れても kintone の処理は止まらない。**
上流の `createToolCallback` は MCP SDK から渡されるキャンセルシグナルを
ツールへ渡していないので、**こちらからは止めようがない**。

```
クライアント → (タイムアウト) → 接続断
                                    └→ kintone への PUT は完了している
クライアントが再試行 → レコードが二重に作られる
```

- **書き込みの失敗は「失敗」ではなく「結果不明」**として扱い、
  レスポンスでもそう伝える。`kintone-add-records` / `add-record-comment` は
  再試行で**重複を作る**
- **読み取りの再試行と書き込みの再試行を分ける。**
  サーバー側で自動リトライするのは読み取りだけ
- Cloud Run の `--timeout` より**手前**で自分のデッドラインを切り、
  「どこで切れたか分からない」状態を減らす
- **デッドラインはリクエストの先頭から数える。**
  ツール実行の直前から数えると、その手前にある
  トークン照会（Firestore）と kintone トークン更新（cybozu への通信）が
  **期限の外**に落ちる。そこで詰まると応答は永遠に始まらない
- **外部への通信そのものにも期限を与える。**
  `fetch` に既定の期限は無く、デッドラインで HTTP を切っても
  **その通信は走り続ける**。更新は単一飛行なので、
  詰まるとその接続の後続リクエストがまとめて止まる。
  kintone クライアントにも `socketTimeout` を渡す
- **通信の期限切れは「一時障害」**として扱う。`invalid_grant` と同じ扱いにすると、
  **繋がらなかっただけで接続を失効させ**、利用者に不要な再認可を強いる
- **HTTP 応答を返しても、裏の kintone 呼び出しが続いている間は同時実行枠を解放しない。**
  解放すると、タイムアウトの連鎖で上流への同時接続が上限を超える
- 書き込みの自動リトライを禁じるなら、**`@kintone/rest-api-client` 内部のリトライ有無も確認する**
- `SIGTERM` で新規受付を止め、処理中のリクエストを終わらせてから落とす

### 7.4 エラーの詰め替え

**⚠ 秘密を扱うのはツールの外側にもある。**
`/oauth/callback`、cybozu との token 交換、リフレッシュ、KMS、Firestore は
ツール callback の外なので、そこにも同じ境界を置く。

**とくに `code` と `state` は URL のクエリに載る。**
Cloud Logging の `httpRequest.requestUrl` はクエリを含むため、
**アプリ側でログを伏せても基盤側に残る。**
ログから外すもの: `code` / `state` / `code_verifier` / `client_secret` /
リフレッシュトークン / Cookie / `Location`。

**「設定を確認する」では対策になっていない。** Cloud Logging の sink は
**それぞれ独立に評価される**ので、`_Default` から除外しても
別の sink・集約 sink・転送先には残りうる。決めること:

| 決めること | 内容 |
| --- | --- |
| 除外の位置 | このサービスの request log を**どの sink で除外するか**（`_Default` だけでは足りない） |
| 網羅 | 組織の集約 sink、別プロジェクトへの転送を含めて確認する |
| 順序 | **最初の OAuth 試験より前に適用する。** 試験で流れた `code` は後から消せない |

「基盤がログを**生成しない**」と「**保存・転送しない**」は別物。
ここは**公開前の未完了項目**として扱う。

**ツールの callback 境界で例外を安全なエラーに変換する。**
MCP SDK はツールが投げた例外の `message` を結果に載せてクライアントへ返すため、
ここを通さないと kintone クライアントの例外（**リクエスト設定＝資格情報を含みうる**）が
そのまま外に出る。

- 例外オブジェクトを丸ごとログに出さない。**出す項目を列挙して構造化ログにする**
- ログに出さないもの: 受信・送信の資格情報、URL 内の秘密、**レコードの本文**
- kintone の HTTP ステータスとエラーコードは残す（切り分けに要る）

### 7.5 監査ログ

**「kintone 側で監査できる」には頼れない。** §4 のとおり、
API トークンでの操作は kintone 上で Administrator の操作として記録される。
入口も共有 Bearer 1本なら、利用者を区別できない。

記録する項目:

| 項目 | 備考 |
| --- | --- |
| 相関 ID | リクエストを貫通させる |
| 入口の主体 | **`client_id` と grant ID。** これは確実に取れる |
| kintone のユーザー | **取得手段が確認できた場合だけ記録する。** cybozu の token 応答にユーザー識別子は含まれないので、**「保存する」と書くだけでは実現しない** |
| テナント | 固定の `KINTONE_BASE_URL` のホスト名。資格情報そのものは絶対に記録しない |
| 認証方式 | `oauth`（フェーズ2 で `password` が加わる） |
| 認可イベント | **認可・更新・リフレッシュ再使用の検知・失効も監査対象にする** |
| ツール名・対象 ID（app / record / space） | 本文は残さない |
| 成否・kintone のステータス・所要時間 | HTTP 200 で返る `isError: true` も**失敗として集計する** |

- **自己申告の username を「認証済みの主体」として扱わない。** あれは
  kintone に渡す資格情報の一部であって、こちらが検証した身元ではない
- 監視: 失敗率、429 の発生、レイテンシ、インスタンス数

---

## 8. リポジトリ構成案

```
kintone-remote-mcp/
├ src/
│  ├ http-server.ts        Express + ルーティング + 起動（vonage から移植）
│  ├ config.ts             環境変数の検証（起動時 fail-fast）
│  ├ auth/
│  │  ├ provider.ts            oidc-provider の設定（クライアント定義 / scope / resource）
│  │  ├ firestoreAdapter.ts    ★ oidc-provider の Adapter (§4.9)
│  │  ├ interaction.ts         同意画面 + cybozu へのリダイレクト（state 束縛）
│  │  ├ callback.ts            /oauth/callback — cybozu の code 交換
│  │  ├ grantStore.ts          ★ 接続 grant / KMS エンベロープ暗号化 (§4.9)
│  │  ├ mcpAuth.ts             /mcp の認証（不透明トークン検証 + 401 + WWW-Authenticate）
│  │  ├ protectedResource.ts   RFC 9728 メタデータ (§4.6)
│  │  └ originHost.ts          Origin 検証 + Host 検証 (§2.3)
│  ├ adapter/
│  │  ├ createRemoteServer.ts    ★ 上流 dist からの組み立て (§2.1)
│  │  ├ upstream.d.ts            ★ 上流に .d.ts が無いための型宣言 (§2.1)
│  │  ├ toolPolicy.ts            ENABLE_* + OAuth 非対応5ツールの除外 + annotations のマージ
│  │  ├ errorBoundary.ts         ツール例外の詰め替え (§7.4)
│  │  └ kintoneClient.ts         auth: { oAuthToken } で生成 / HTTPS Agent は共有
│  │  └ appScope.ts              ALLOWED_APP_IDS の適用 (§5)
│  ├ limits.ts             テナント別同時実行・デッドライン (§7.2 / §7.3)
│  ├ audit.ts              構造化ログ (§7.5)
│  └ version.ts
├ tools/
│  └ header-probe/         ★ クライアントのヘッダー到達性を実測するプローブ (§9.1)
├ tests/
│  └ adapter/upstream-contract.test.ts  ★ deep import の契約テスト
├ docs/
│  ├ design.md (これ)
│  ├ deployment.md
│  └ setup-guide.md
├ Dockerfile
└ package.json             @kintone/mcp-server をパッチまで固定
```

---

## 9. 実装フェーズ

| # | 内容 | 完了条件 |
| --- | --- | --- |
| 1 | リポジトリ初期化 (git init / TS / vitest / lint) | `pnpm test` が通る |
| 2 | アダプタ + 型宣言 + 契約テスト | 上流27ツールを `tools/list` に出せ、**annotations が載っている** |
| 3 | `http-server.ts` + 入口認証 (Bearer) + `/health` | ローカルで MCP Inspector から接続できる |
| 4a | **`oidc-provider` の組み込み** + クライアント定義 + Firestore Adapter | curl で認可コードフローを一周できる |
| 4b | cybozu への橋渡し（interaction + `/oauth/callback` + state 束縛） | 同意画面から kintone ログインまで通る |
| 4c | 接続 grant の暗号化保管 + リフレッシュ + 失効 | 期限切れ後も継続して使え、切断が全インスタンスに効く |
| 5 | ツールポリシー + `ALLOWED_APP_IDS` + annotations のマージ | 既定が読み取り専用で、`tools/call` 側でも拒否される |
| 6 | エラー詰め替え + 上限 + 監査ログ (§7) | 秘密がログにも応答にも出ない |
| 7 | Dockerfile + Cloud Run デプロイ（2段階） | 公開 URL に Claude Code から接続できる |
| 8 | ドキュメント (deployment / setup-guide) | 第三者が再現できる |
| 9 | (将来) パスワードログイン | スペース系4ツールと search が使える (§4.10) |

**フェーズ1 の範囲を絞る。** 外部レビューの助言どおり、次に限定する。

| 含む | 含まない（後続フェーズ） |
| --- | --- |
| 登録クライアントは **`claude-hosted` のみ** | `claude-code`（ループバック転送先） |
| **OAuth のみ** | パスワードログイン (§4.11) |
| **読み取りツールのみ**（既定9ツール） | `ENABLE_*_WRITE` / `ALLOW_DESTRUCTIVE` |
| **接続のライフサイクルを完成させる**（認可・更新・失効・再接続） | — |

認可の設計と書き込みの設計を同時に検証しようとしない。

### 公開の条件とするテスト

「27ツールが import できる」だけでは足りない。**次が通るまで公開しない。**

| # | 検証すること |
| --- | --- |
| 1 | **同一ドメインの異なる2ユーザー・2接続を並行処理し、資格情報と権限が混ざらない**（上流のシングルトン問題の再発検知を兼ねる） |
| 2 | 無効化したツールが**一覧から消えるだけでなく、名前を直接指定しても実行できない** |
| 3 | **OAuth 異常系**: 同意拒否 / `state` の欠落・再使用・別ブラウザ / callback 直打ち / PKCE ダウングレード / 不正な `client_id`・`resource` を**すべて拒否する** |
| 3b | **競合**: 同一コードの同時交換、同一リフレッシュの同時使用、旧リフレッシュの再使用を**検知して系列ごと失効させる** |
| 3c | **中断**: 保存の前後で強制終了、上流応答の取りこぼしからの復帰 |
| 3d | **TTL 未削除でも期限切れを拒否する。** 接続の失効が全インスタンスに効く |
| 3e | Firestore / KMS の障害、IAM 拒否、scope 拡大を正しく扱う |
| 3f | **`AccessToken` 以外（リフレッシュトークン等）を Bearer として受け付けない**。audience・scope・grant 生存の検証 (§4.10) |
| 3g | **`ALLOWED_APP_IDS`**: 許可外 ID の直接指定 / 許可内と許可外の混在指定 / 引数なしの列挙（`get-apps` は `structuredContent` と `content[].text` の**両方**が絞られていること） |
| 4 | Origin / Host / 認証ヘッダーの異常系を拒否する。GET / DELETE が 405 になる |
| 5 | **投入した秘密文字列が、どこにも出てこない**: アプリのログ / 例外 / MCP 応答 / Cloud Logging の `httpRequest.requestUrl` / **Firestore の文書 ID・本文・索引**(§4.10) |
| 6 | 429・遅延・接続断・インスタンス終了を扱える |
| 7 | **npm の公開パッケージと本番コンテナ**で、対象クライアントの initialize から実行まで通る |
| 8 | **スマホの Claude アプリで実際にコネクタを追加し、認可してツールを呼べる**（これが目的そのもの） |
| 9 | discovery / token が **10秒以内**、refresh が **30秒以内**に応答する |

7 について、「カスタムヘッダーを設定できる」ことの確認では足りない。
**`tools/list` を含む全リクエストにヘッダーが付くか**を実機で確認する必要がある。
→ **実施済み。結果は §9.1。**

### 9.1 ヘッダー到達性の実測 (2026-09-16)

**案B を検討していた時点での検証記録。**
案B は破棄したため前提としては不要になったが、
**GET に 405 を返してよいこと**の確認は現在の設計にも効いているので残す。
受信ヘッダーを JSON-RPC メソッドごとに記録する最小の MCP サーバー
(`tools/header-probe/server.mjs`) を 127.0.0.1 に立て、実クライアントから接続した。
生ログは `tools/header-probe/result-2026-09-16.jsonl`。

| クライアント | 経路 | initialize | notifications/<br>initialized | tools/list | tools/call | 判定 |
| --- | --- | :-: | :-: | :-: | :-: | --- |
| **Claude Code** 2.1.226 | ネイティブ HTTP (`claude mcp add --transport http -H`) | ✅ | ✅ | ✅ | ✅ | **実測で成立** |
| **Claude Desktop 相当** | `mcp-remote` ブリッジ (`--header`) | ✅ | ✅ | ✅ | 未実行 | **実測で成立** |
| n8n | MCP Client Tool ノード | — | — | — | — | ドキュメント上は可（未実測） |
| Dify | MCP 設定の `headers` | — | — | — | — | ドキュメント上は可（未実測） |

**当時の結論: 案B は成立する。** Claude Code は4種すべてのメッセージにヘッダーを付与した。
**ただしスマホでは成立しない**ことが後に判明し、案B 自体を破棄した (§4.1)。

**副次的に確認できたこと:**

- **GET `/mcp` に 405 を返してよい。** `mcp-remote` は既定の transport だと
  まず `GET /mcp`（SSE）を試すが、405 を受けても**フォールバックして正常に接続を続けた**。
  §2.2 の「GET / DELETE は 405」方針が実クライアントを壊さないことを確認した
- **Claude Desktop はネイティブのコネクタ設定でカスタムヘッダーを渡せない。**
  `mcp-remote` を stdio ブリッジとして噛ませる必要がある。
  **セットアップ手順はクライアントごとに分けて書く**
- `mcp-remote` は接続確認のために `initialize` を2回投げる。
  **初期化のコストを前提にした実装にしない**

**未実測の n8n / Dify は、接続時にこのプローブで確認する。**
プローブはそのために残してある。

---

## 10. 残る未決事項

1. **どの `ENABLE_*` を本番で立てるか** — 書き込みを開ける方針は決まったが、
   レコード更新まで開けるか、アプリ設定変更まで開けるかは運用の判断
2. **cybozu.com の OAuth クライアント登録** — .com 共通管理者権限が要る。
   誰がいつ登録するか。リダイレクト URI は Cloud Run の URL が確定してからでないと入れられないので、
   **§6 の2段階デプロイと順序を合わせる**
3. **DCR を実装するか** — フェーズ1 は「事前登録クライアント ID を入力」で足りる。
   他人に配る段になったら DCR か CIMD を足す（`oidc-provider` はどちらも持っている）
5. **`ALLOWED_APP_IDS` を使うか** — 使わないなら「本人がアクセスできる全アプリが対象」と
   明記する必要がある (§5)
6. **Firestore を専用データベースにするか専用プロジェクトにするか** (§6)
7. **ログ sink の除外をどこで行うか** (§7.4)。組織の集約 sink がある場合は
   その管理者との調整が要る。**最初の OAuth 試験より前に決める必要がある**
4. **フェーズ2（パスワードログイン）に進むか** — スペース系4ツールと `search` が
   実際に必要になってから判断する

---

## 付録: 設計の転回 (2026-09-16)

**「スマホの Claude アプリから使いたい」という目的が後から判明し、認証設計を作り直した。**
経緯を残す。

| 時点 | 決定 | 破棄の理由 |
| --- | --- | --- |
| 初版 | 案A+B ハイブリッド | — |
| 改訂1 | **案B 単独**（ヘッダー必須） | — |
| **改訂2** | **案C（OAuth ブリッジ）** | **スマホでは `mcp-remote` を動かせず、カスタムヘッダーも渡せない** |

**この転回で分かったこと:**

- **案C の見積もりが過大だった。** 「DCR の実装が要る」と書いたが、
  カスタムコネクタは事前登録クライアント ID を受け付けるので不要だった (§4.2)
- **案B で積み上げた対策のうち、SSRF 対策は不要になった。**
  単一テナントで `baseUrl` が固定されるため (§4.8)
- **案B で問題だった「監査が Administrator 名義」は、OAuth で解決した** (§4.3)
- **スペース API はスコープの問題ではなかった。**
  API 自体がパスワード認証しか受け付けない (§4.10)

**教訓: 目的（誰がどこから使うか）を先に確認していれば、案A/B の検討は不要だった。**

---

## 付録: 実装して判明したこと (フェーズ4a / 4b)

設計はソースを読んで書いたので、**実際に動かして初めて分かった**ことがある。
いずれも設計書側を直した。

| 設計書の記述 | 実際 | 対応 |
| --- | --- | --- |
| 「`proxy: true` を設定する」 | ⚠ **一度「v9 に proxy 設定は無い」と結論したが、これは誤りだった。** 設定オブジェクトの項目ではないが、`Provider` は Koa を継承していて **`provider.proxy`（既定 `false`）** を持つ。false のままだと TLS 終端後に `ctx.secure` が false になり、Cookie の発行が `Cannot send secure cookie over unencrypted connection` で失敗する | §4.10 — **`provider.proxy = true` を設定**し、`Secure` の明示も併用する |
| クライアントの `scope` にリソース側の scope を書く | **`invalid_client_metadata: scope must only contain Authorization Server supported scope values` でクライアントの読み込み自体が失敗**（再現済み） | §4.10 — **AS の scope とリソースの scope は別系統**と明記。後者は `getResourceServerInfo` と `addResourceScope` が持つ |
| 「callback 後に interaction を再開する」 | **`/oauth/callback` には provider の interaction Cookie が届かない**（provider は interaction のパスに限定して発行する） | §4.5 — 経路を**4つに分割**。callback は確認と保存だけを行い、`/interaction/:uid/finish` へ戻してから `interactionFinished()` を呼ぶ |

### テストの弱点をミューテーション検査で見つけた

「同じ callback を2回使っても2回目は通らない」というテストが**通っていたが、
理由が違った**。callback が応答でブリッジ Cookie を消すため、
2回目は「Cookie が無い」で弾かれており、**再使用防止そのものは試されていなかった**。

再使用防止の実装をわざと無効化しても、このテストは落ちなかった。
→ Cookie を控えて付け直し、`already-used` で弾かれることを確かめる形に修正した。

**ブラウザ束縛**についても同じ検査を行い、無効化するとテストが落ちることを確認済み。

---

## 付録: Firestore の実装と、複数インスタンスの実証

レビューが完了条件に挙げていた「**切断が全インスタンスに効くことの実証**」を済ませた。
メモリ実装だけでは原理的に確かめられない性質だった。

### 同じ契約テストを両実装に流す

`tests/auth/storage-contract.test.ts` を `MemoryStorage` と `FirestoreStorage`
の**両方**に流す。`FIRESTORE_EMULATOR_HOST` が無ければ Firestore 側は飛ばすが、
**飛ばしたことがテスト名に出る**ようにした
（「通った」と読み違えないため）。

### 実際の Firestore で確かめたこと

| 確認 | 結果 |
| --- | --- |
| 両実装が同じ契約を満たす | ✅ 35件 |
| **片方で切断 → もう片方でもアクセストークンが使えない** | ✅ |
| **片方で再使用検知 → もう片方でも接続が失効** | ✅ |
| **同じ認可コードを2インスタンスで同時消費 → 成功は1回** | ✅ |
| トークン更新の単一飛行がインスタンスをまたぐか | ❌ **またがない**（既知の制約としてテストで固定） |

競合テストが本当に競合を試しているかは、ミューテーション検査で確認した。
`consume` を非トランザクション化すると、**実際の Firestore に対してだけ落ちる**
（メモリ実装は単一スレッドなので落ちない）。

### 環境上の注意

Firestore エミュレータは **Java 21 以上**を要求する。
`gcloud` が拾う既定の Java が 17 だと
`The java executable on your PATH is not a Java 21+ JRE` で起動しない。

---

## 付録: スペース操作をどう足したか (2026-09-17)

**方針: 連携用ユーザー。既定は無効。5ツールだけ。**

`kintone-search` とスペース操作3種＋テンプレートは、cybozu がスコープを
用意していないため OAuth では実行できない。パスワード認証が要る。

### なぜ「接続した本人のパスワード」にしないか

| | 本人のパスワードを預かる | 連携用ユーザー |
| --- | --- | --- |
| 同意画面 | **パスワード入力欄を出す**ことになる | 出さない |
| 利用者への影響 | 非 kintone の画面に打つ習慣がつく（詐欺に弱くなる） | 無い |
| 2要素認証 | **有効な利用者は使えない** | 連携用は無効にできる |
| 権限 | 本人のまま（望ましい） | **広がる**（望ましくない） |

サイボウズ自身が「2要素認証を無効にした**連携用ユーザー**を用意してください」と
案内している。本人のパスワードを集める形は、2要素認証を使う組織では
そもそも成立しない。

権限が広がる欠点は残るが、**それを見えるようにする**ことで引き受ける。

### 引き受けた欠点と、その扱い

| 欠点 | 扱い |
| --- | --- |
| 主体が入れ替わる | **同意画面に明記**する。「あなたではなく連携用ユーザーとして実行されます」 |
| 後から切り分けられない | 監査ログに `identity` を残す。kintone 側の監査と突き合わせられる |
| 権限が広い | **5ツールだけ**に限る。残りは本人の OAuth トークンのまま |
| スコープが無い | capability フラグが唯一の歯止め。既定は無効 |

### アプリ境界と検索は両立しない

`kintone-search` は**引数にアプリ ID を持たない**ので、アプリ境界の判定
(`assertAppAllowed`) が素通りする。結果を絞る手立ても無い。

そのうえ連携ユーザーの権限で動くので、緩みが2つ重なる。
→ **`ALLOWED_APP_IDS` があるときは `kintone-search` を公開しない。**

### 認証ヘッダーは絶対に混ぜない

kintone の認証には優先順位があり、**パスワード認証が OAuth より上**。

> 1. パスワード認証 2. APIトークン認証 3. OAuth 4. セッション認証

1つのクライアントに両方の資格情報を載せると、**すべての操作が連携ユーザーとして
実行される**。クライアントを2つ作り、ツールごとにどちらを使うかを決める。
`kintoneClientOptions` は `auth` をそのまま受け取る形にして、
**混ざりようが無い**ようにした。

---

## 付録: 同意を「操作の集合」にするまで (2026-09-17)

第13回・第14回のレビューで、同意の扱いを2度作り直した。

### 名前だけでは足りなかった

最初は「同意した連携ユーザーの名前」だけを接続に記録した。
これでは **「参照に同意した」と「削除に同意した」を区別できない**。

`ALLOW_DESTRUCTIVE` を後から有効にすると、削除に同意していない既存の接続に
**削除権限が付いた**（第14回で再現された）。
kintone の書き込みスコープは削除も許すので、**上流のスコープ検証でも止まらない**。

→ **同意した時点で公開されていたツールの名前**をそのまま記録する。
実行時は**現在の設定との積**で公開する。

| 記録 | 現在の設定 | 公開されるもの |
| --- | --- | --- |
| 参照＋登録 | 参照＋登録＋削除 | 参照＋登録（削除は付かない） |
| 参照＋登録＋削除 | 参照のみ | 参照のみ（同意が設定を上書きしない） |
| 記録なし（機能導入前） | 現在の設定 | **移行時点で確定した範囲との積** |

最後の行は、当初「現在の設定のまま」にしていた。
それは**将来追加する権限への白紙同意**で、第15回で再現された。
かといって「何も許さない」にすると**既存の利用者が全員その場で使えなくなる**。
→ 移行時点で確定した名前を**固定で持つ**（`LEGACY_CONSENTED_TOOLS`）。

### 同意した瞬間の内容を、認可の途中で固定する

`callback` を受けた時点の設定から作り直していた。
同意した瞬間と cybozu から戻る瞬間の間に設定が変わりうるし、
複数インスタンスなら**別の設定のインスタンスが callback を受ける**。

→ ブリッジのトランザクションに**同意の内容を載せて持ち回る**。

### 本番のラッパーが引数を捨てていた

同意を保存する仕組みを入れたのに、**一度も保存されていなかった**。
`httpServer` の `grants.create` ラッパーが引数を2つしか受けていなかった。

**テストのハーネスで同じ間違いを直しながら、本番側を見落としていた。**
ブリッジ単体のテストは別のラッパーを使うので、そちらは通ってしまう。
→ **本番の `buildServer` で認可を一周する**テストを足した。

### 接続の寿命とトークンの寿命は別物

`Grant` の寿命をリフレッシュトークンと同じ30日にしていた。
リフレッシュのたびにトークンは更新されるが、**親の Grant は延びない**。

使い続けていても**初回の認可から30日で更新できなくなる**
（29日目は成功、31日目は `invalid_grant`。第14回で実測された）。

→ 接続は「切断するまで生きる」設計なので、Grant は別に持つ（既定400日）。
無期限にはしない。使われなくなった接続が永遠に残ると、
失効の手立てが切断だけになる。

### 空の許可リストで判断が割れていた

同意画面は `!== undefined`、実行側は解析後の集合で判断していた。
`ALLOWED_APP_IDS=""` では**同意画面は「絞っている」・実行側は「制限なし」**。
→ 設定の読み込み時に一度だけ正規化する。

---

## 付録: ChatGPT に繋いで分かったこと (2026-09-20)

「ChatGPT からは使えない」と説明していたが、**理由を取り違えていた**。
OAuth が問題なのではなく、**クライアントの入口が静的登録しか無かった**だけだった。

OpenAI の現行文書では、推奨は **CIMD**（Client ID Metadata Document）で、
DCR は「設定すれば使える」扱い。そして `oidc-provider` 9.12.2 は
CIMD (draft-02) を既に持っていた。**有効にするだけで届いた。**

### 実際に繋いで初めて出た不具合が2つ

**どちらも Claude では見えなかった。**

| 不具合 | なぜ見えなかったか |
| --- | --- |
| **PKCE が認証方式によって外れる** | Claude は公開クライアントなので常に必須だった |
| **メタデータが RFC 9728 の場所に無い** | Claude はルートに後退して拾う |

1つめが重い。既定の `pkceRequired` は `clientAuthMethod === 'none'` のときだけ
true を返す。コードにも「この指定だけで必須になる」と書いていたが、
それは**公開クライアントしか居ない間の話**だった。
ChatGPT の CIMD 文書は `private_key_jwt` を使うので、そのままなら
**PKCE が外れたまま繋がっていた**。

2つめは、RFC 9728 が「リソース識別子のパスを
`/.well-known/oauth-protected-resource` の**後ろに差し込む**」と定めているのに、
ルートにしか置いていなかった。ChatGPT は仕様どおりの場所を先に見て 404 を受け、
**認可に進まず探索を繰り返していた**。

> **「Claude で動いている」は「仕様どおり」を意味しない。**

### 自動試験では確かめられない領域がある

PKCE の修正は、**手元では検証できなかった**。
`private_key_jwt` のクライアントは CIMD でしか作れず、CIMD は
**HTTPS かつ private IP でないホスト**を要求する
（ライブラリが接続後のソケットの実アドレスで弾く）。

最初に書いた試験は `claude-hosted`（公開クライアント）を使っており、
**修正前から通った**。証明になっていない。試験の説明をそう書き直し、
実接続での確認を未了項目に置いた。**そして実接続で確認できた。**

### 挙動の違い

| | Claude | ChatGPT |
| --- | --- | --- |
| クライアント登録 | 静的（`claude-hosted`） | **CIMD** |
| クライアント認証 | public (`none`) | **`private_key_jwt`** |
| メタデータの探索 | ルートに後退 | **仕様どおりの場所を先に** |
| ツールの呼び方 | 1つずつ | **複数を同時に** |

最後の行は上限に効く。`MAX_CONCURRENT_TOTAL=4` では
`rate_limit.blocked (concurrency)` が出た（再試行で最終的には成功する）。

## 付録: スペース操作を実環境で動かして分かったこと (2026-09-18)

連携ユーザーを設定し、スペース操作を**初めて実環境で動かした**。
設計で想定していなかったことが2つ出た。どちらも kintone の仕様どおりで、
こちらの欠陥ではない。**それでも、知らずに公開すると驚く。**

### 「一覧」は、ID の総当たりで作られる

公開しているスペース関連のツールに**一覧は無い**
（`get-space` は ID 指定、あとは更新・作成・削除・検索）。
それでも「スペースの一覧を見せて」は成立した。

Claude は次のようにした。

| 段階 | 主体 | 得たもの |
| --- | --- | --- |
| `kintone-get-apps` | **本人** (`identity=user`) | 各アプリの `spaceId` |
| `kintone-get-space` ×13 | **連携ユーザー** (`identity=integration`) | 各スペースの中身 |

**20秒で13回**。ID が `1,2,3,5,6,14,…` と飛んでいたので、
総当たりではなくアプリ一覧から拾った候補である。

つまり「連携ユーザーの権限で見えるもの」は理論上の話ではなく、
**モデルが能動的に探る**。監査ログの `identity` と `targets` を入れておいたことで、
どちらの資格情報で何を触ったかが1行ずつ追えた。**入れていなければ、
この区別は永久に付かなかった。**

### 前提を確かめずに README を書き、翌日に訂正した

「非公開スペースのアプリ名が取れてしまう」と報告された。
ログを見ると `identity=user` の `kintone-get-apps` で、連携ユーザー経由ではなかった。

kintone ではスペースの公開/非公開とアプリのアクセス権が**別の軸**で、
`get-apps` の必要な権限は「アプリのレコード閲覧権限または追加権限」。
スペースのメンバーであることは条件に入っていない。**ここまでは仕様どおり。**

そこから「**非公開スペースは中のアプリを隠さない**」と結論して README に節を書いた。
**これが誤りだった。**

報告の対象はスペース1と6で、そこで `403` を受けたのは**連携ユーザー**である。
**本人がそれらのスペースのメンバーかどうかを、調べていなかった。**

**後で本人に訊いたら、メンバーだった。** アプリ名が見えるのは当たり前で、
異常は何も起きていない。

**前提を確かめないまま、仕様の一般論と観測を結び付けてしまった。**
訊けば30秒で済むことだった。

### 統制された実験で、逆の結果が出た

翌日、条件を揃えて試した。

- 非公開スペースに**連携ユーザーが**アプリを作り、レコードを1件入れる
- **そのスペースの非メンバーである接続者**が、自分のトークンで読む

| 操作 | 結果 |
| --- | --- |
| `kintone-get-apps`（ID 指定） | 0件 |
| `kintone-get-records` | `403 CB_NO02` |

**守られていた。** スペースの中に作ったアプリは、既定でそのスペースのメンバーに絞られる。

モデルは「存在しないアプリでも同じエラーになる」と説明したが、これは推測である。
状態の違うアプリには `400 GAIA_IL23` という**別のコード**が返っており、
kintone はエラーを区別している。またレコードを入れてあるので未デプロイでもない。

→ README の節を**書き直した**。正しい言い方はこうなる。
**守っているのはスペースの公開設定ではなく、アプリのアクセス権。**
アプリ側の権限を広げれば、スペースが非公開でも読める。
**確認すべきはアプリのアクセス権であって、スペースの公開設定ではない。**

### 教訓

このプロジェクトは「**通る理由が間違っているテスト**」を何度も潰してきた。
同じ間違いを、**ドキュメントでやった**。

観測を説明できる仮説が複数あるとき、**確かめずにいちばん怖いものを採用する**のは
安全側に倒しているようで、そうではない。**嘘を書くことになる。**
利用者は、当たっている警告と外れている警告を区別できない。

### 403 は、設計が効いている証拠でもある

スペース1と6は `403` で名前すら返らなかった。
**連携ユーザーが非公開スペースのメンバーでない**ためで、
「連携ユーザーの権限がそのまま効く」ことの裏返しでもある。
権限を絞った専用ユーザーを勧めているのは、これが効くからである。

## 付録: 外部レビュー 第15回・第16回 (2026-09-17) — 同意はいつ決まるか

### 第15回: 同意の内容が、表示ではなく承認の時点で作られていた

GET は権限を**表示するだけ**で、POST が承認を受けたインスタンスの設定から
作り直していた。画面を出したインスタンスと承認を受けるインスタンスは別でありうる。

連携無効の画面を出したあと、連携有効のサーバーで承認すると、
**表示していない連携ユーザーと削除が同意済みとして保存され**、削除 API まで到達した。

→ GET で内容を確定して保存し、**CSRF トークンに束縛する**。
POST は保存済みの内容だけを承認する。無ければ承認しない。

前回入れたテストは「生成関数が1回だけ呼ばれる」ことを見ていたが、
**その1回は GET ではなく POST だった**。表示内容の固定を何も保証していなかった。

あわせて、対象アプリ（`ALLOWED_APP_IDS`）も同意に含めた。
ツール名だけでは境界の変更を止められない。許可リストを変えても名前は同じなので、
積では止まらない。

### 第16回: 「固定した」つもりの範囲が、まだ動いていた

第16回で P1 は無くなったが、**前回の修正のどれもが、あと一歩足りていなかった**。
6件のうち4件が「入れた仕組みが、思っていた範囲に届いていない」という形をしている。

| 指摘 | 届いていなかった先 | 修正 |
| --- | --- | --- |
| 旧接続の許可集合が**分類表から導出**されていた | 上流がツールを追加すると、旧接続の同意にも自動で入る | 名前を**直に並べる**。ここは現在の分類の写しではなく、過去の記録 |
| 絶対期限が**新しい接続にしか付かない** | 記録の無いレコードは401日後も復号でき、失効もしない | 記録が無いものは**移行時点で作られたとみなす**（`LEGACY_CONNECTION_EXPIRES_AT`） |
| 接続と `Grant` の期限を**別々に数えていた** | callback と finish の間が延びたぶんずれる（90秒遅らせると90秒） | callback で1度決め、finish へ運んで**同じ絶対期限**にする |
| `/mcp` の除外が**完全一致**だった | `/mcp/` と `/MCP` にも認可用の短い予算が掛かる（同じ無効トークンで401と503に割れた） | ルーターと**同じ規則**で判定する（`isMcpPath`） |

残る2件は、アプリ境界とテストの穴。

**アプリ境界を課せないツールを、主体で選んでいた。**
`assertAppAllowed` は**引数からアプリ ID を取り出せないツールを素通りさせる**。
連携ユーザーのものだけを止めていたので、次の2つが漏れていた。

| ツール | 起きること |
| --- | --- |
| `kintone-add-app` | 許可リストが `{"1"}` でも、**積が空でも**アプリを作れた |
| `kintone-download-file` | `fileKey` だけで**どのアプリの添付でも**落とせた |

→ **主体ではなく、境界を課せるかで決める**（`enforcesAppBoundary`）。
判断の材料は `appScope` が持っているので、そちらに訊く。
ツール名を別に並べると、取り出し方を足したときに片方だけ古くなる。

### また「通る理由が間違っている」テストが2件

どちらも、これまでと同じ形をしている。

**累積の予算を確かめる試験が、1回しか読まない要求で書かれていた。**
存在しない認可コードを `/token` へ投げるもので、保存層の読み取りは1回。
それでは「操作ごとの期限」と「要求全体の予算」の区別が付かず、
**残り時間を毎回戻す変異が通った**。
→ 順番に2回読む経路（`/token/revocation` に `token_type_hint=refresh_token`）に変え、
**読み取り回数そのものを数える**。1回しか読んでいないなら試験が空振りしていると分かる。

**KMS の差し替えの口が高すぎて、本番の既定経路が1行も実行されなかった。**
復号関数まるごとを注入していたので、
**既定を「KMS を呼ばず固定の鍵を返す」に変えても15件すべて通った**。
→ 口を**クライアントまで下げる**。応答の読み取りも例外の包み方も base64 の読み方も
本番と同じものが動き、試験が通らないのは `new KeyManagementServiceClient()` の1行だけになる。
その1行も、既定値そのものを見る試験で押さえた。

### 直さなかったもの

同意の記録は**使い捨てにしていない**。同じ POST を並行して送ると
認可トランザクションが2件できる、という指摘は事実。

増えるのは**同じ内容の**トランザクションで、最後まで進めるのは1つだけ
（完了レコードの consume が不可分）。残りは使われないまま期限で消える。権限は広がらない。

一方、1回限りにすると**スマホでの二度押しが必ず失敗する**。
1回目のリダイレクトが飛んでいる最中に2回目が届くと「最初からやり直してください」になる。
実害の無い重複を防ぐために、実際に起きる操作を壊すことはしない。

## 付録: 外部レビュー 第12回 (2026-09-17) — 期限の及ぶ範囲と、記録

**判定: 公開不可。ただし新しい P1 の実装欠陥は無し。P2 5件。**

前回までの修正はすべて確認された。残ったのは
「**入れた仕組みが、思っていたほど広く効いていない**」という指摘。

| 指摘 | 実物で確認した内容 | 修正 |
| --- | --- | --- |
| 更新処理の**内側**に打ち切りが無い | `getAccessToken()` に入る前は見るが、中の保存層読み込みの後は見ない。そこで止めると 504 後に cybozu 呼び出しが1回増えた | 更新を始める直前にも見る。**待ち手を持たせ**、開始側が諦めても他が待っていれば続ける |
| `/token` に期限が無い | 締め切りは `/mcp` にしか掛かっていない。保存層を止めると**11秒後も未応答**だった | **保存層そのものに期限**を掛ける（`STORAGE_TIMEOUT_MS`）。認可エンドポイントに効く唯一の仕組み |
| 本文ガードの `undefined` 経路は到達可能 | `Content-Length` も `Transfer-Encoding` も無い POST は body-parser が解析を省略する | 生のソケットで試験を追加。「到達不能」という記述を撤回 |
| 認可の監査ログが実フローに繋がっていない | 認可を完走しても**出力が空**。さらに正常な切断が `token-reuse` として記録されていた | 接続作成・発行・更新を記録。失効理由は**経路から**判断する |
| 負荷上限の訂正が文書全体に反映されていない | 予算表の直前と設計本文に旧記述が残っていた | 削除 |

### 「到達できない」と書く前に、確かめる

第11回で「本文ガードの `undefined` 経路は手前の層があるので到達不能」と結論したが、
**誤りだった**。`fetch` と `http.request` が必ず `Content-Length` を付けることを
「本文の無い POST は作れない」と読み違えていた。生のソケットなら作れる。

**試せない理由を書くときは、その理由自体を確かめること。**

### 失効の理由は、呼ばれた側では分からない

provider は、**再使用を検知したときも利用者が切断したときも同じ口**を呼ぶ。
アダプタ側で `token-reuse` と決め打ちしていたため、
**正常な操作と盗用の疑いがログで区別できなかった**。

理由が分かるのは、経路 (`ctx.oidc.route`) を持つ provider のイベント側だけ。
アダプタ側は `provider-revoked`（言われたから失効させた）に改め、
理由の記録はイベント側へ移した。

### 記録は、出力先を差し替えられないと検証できない

「ログに出ているはず」を確かめる手段が無かったので、
配線が無いことに気づけなかった。出力先を差し替える口を作り、
**HTTP から叩いて、実際に出た内容**を見るようにした。

なお、失効理由を決め打ちに戻す変異を当てても**テストは1つも落ちなかった**。
記録の内容を誰も見ていなかったということ。

### 観測できない判定は、置かない

打ち切りの判定を4か所に置いていたが、外から違いが見えるのは
**外部呼び出しの直前2か所**だけだった。残り2つは、壊してもテストが落ちない。

節約になるのは保存層の読み取りだけなので、消した。
**壊れていることに気づけないコードを残さない。**

---

## 付録: 外部レビュー 第11回 (2026-09-17) — 上限の順序と、締め切り後の実行

**判定: 公開不可。P1 2件。**

前回の7件はいずれも実装としては直っていた。残ったのは
「**上限の掛け方が、守りたいものを守れていない**」という問題。

| 指摘 | 実物で確認した内容 | 修正 |
| --- | --- | --- |
| **拒否した要求が総量枠を食う** | 総量を先に数えていたため、**送信元制限で既に拒否されている相手**が送り続けるだけで総量枠を使い切れた。総量枠は全利用者で共有なので、1つの送信元が全員を締め出せる | **送信元の判定を先に**。総量は「拒否しなかった要求」だけで数える |
| **負荷予算の 8×10=80 が成立しない** | `--max-instances` は**リビジョン単位**。デプロイ中は新旧が重なり、Cloud Run は一時的に超えることもある | 掛け算を最悪値として書くのをやめ、**上限を置けないことを明記** |
| 締め切り後に新しい仕事を始める | タイマーは応答を返すが処理を終了状態にしない。待機から戻った地点は「まだ何も始めていない」ので、**結果を届けられない相手のために kintone を呼んでいた** | 打ち切りの印を持ち、各待機から戻ったところで未着手の処理を止める |
| 実装を壊しても通るテストが6種類 | 下表 | 5件はテストで捕まえられるようにし、1件は到達不能である事実を明記 |
| ポート競合の修正が2ファイルに残る | `bridge-flow` / `provider-flow` に仮サーバー方式が残っていた | 先に listen する形に統一 |

### 自分の修正が、被害の範囲を広げていた

レビューを待つ間に自分で見つけた分。**枠を取ったあとに例外が出る経路で、
枠が返っていなかった。**

接続ごとの枠だけだった頃は、この漏れはその接続に閉じていた。
**インスタンス全体の枠を入れたことで、1つの接続の不具合が全員に波及するようになった。**
全体の枠は既定8本なので、8回踏むとそのインスタンスは以後 429 しか返さない。

枠を取った直後から `finally` で包み、**解放する場所を1か所だけ**にした。

### すり抜けた変異と、その理由

| 壊した実装 | 通ってしまった理由 | どう直したか |
| --- | --- | --- |
| 全体枠のキーを grant 単位に | 同じ接続しか使っていなかった | **別々の接続**で試す |
| 全体枠が取れないときの巻き戻し | 拒否を繰り返したあとの回復を見ていなかった | 接続の枠を超える回数だけ断らせ、**そのあと使えること**を見る |
| 相関 ID の受け渡し | テスト側がアダプタへ直接 ID を渡していた | **HTTP から叩いて、実際にログへ出た内容**と突き合わせる |
| `lastFailure` の代入 | アダプタのフックまでしか見ていなかった | 同上 |
| 本番クライアントの `socketTimeout` | HTTP テストがクライアント生成をスタブに差し替えている | **設定を作る関数に切り出して**直接試す |
| 本文ガードの `undefined` 経路 | 手前の Content-Type 限定が先に 415 を返すと考えた | **この判断が誤りだった**（第12回で指摘）。下記 |

最後の1件を「到達不能」と結論したのは**誤りだった**（第12回レビューで判明）。
`Content-Length` も `Transfer-Encoding` も無い POST は、
Content-Type が `application/json` でも body-parser が解析を省略し、
`req.body` は `undefined` のままになる。**手前の層を緩めなくても外から叩ける。**

「試せないから仕方がない」と書く前に、**試せない理由が本当かを確かめること。**
このときは、`fetch` と `http.request` が必ず `Content-Length` を付けることを
「本文の無い POST は作れない」と読み違えていた。生のソケットなら作れる。

### 監査ログに出る内容は、外から見えないと検証できない

相関 ID の受け渡しも kintone のエラーコードも、
**ログに出て初めて意味がある**。出力先を差し替える口を作っていなかったので、
配線を外しても気づけない状態だった。

---

## 付録: 外部レビュー 第10回 (2026-09-16) — 上限と締め切り

**判定: 公開不可。P1 4件。**

第9回の P1 7件は直ったが、**2件は塞ぎ方が足りず、迂回路が残っていた**。
残る指摘はすべて「**上限を上限として機能させる**」話に収束した。

| 指摘 | 実物で確認した内容 | 修正 |
| --- | --- | --- |
| **Content-Type を変えるとバッチ拒否と本文上限を迂回できる** | `express.json` は `application/json` に**厳密一致**、MCP SDK は `ct.includes("application/json")` の**部分一致**。`application/json-patch+json` はこの隙間に落ち、`req.body` が未定義のまま SDK が本文を読み直す | 型名を `/mcp` で限定し、**解析済みの単一オブジェクト以外は SDK に渡さない** |
| **認証前の枠を自己申告ヘッダーで作り直せる** | `trust proxy = true` は `X-Forwarded-For` の**左端**を採る。Cloud Run は既存の値を検証も削除もせず実 IP を**末尾に追記**するだけ | 信頼するホップ数を指定（既定1）。加えて**送信元を見ない総量の枠**を Firestore の手前に置く |
| **認証・更新に締め切りが無い** | 締め切りの開始が Firestore 照会と kintone トークン更新の**後**。cybozu への `fetch` にも kintone クライアントにも期限が無い | 締め切りを**ハンドラの先頭**から数える。cybozu に `AbortSignal`、kintone に `socketTimeout` |
| **同時実行が grant 単位だけ** | 接続が増えるほど枠が増え、上流への同時実行は青天井。kintone はドメインあたり100同時要求が上限 | **インスタンス全体の枠**を追加し、手順書に負荷の予算表を置く |
| 大文字の `HTTPS://` で署名鍵の必須化と Secure Cookie の強制が外れる | `startsWith("https://")` で判定していた。スキームは大文字小文字を区別しない | 解釈した `protocol` で判定し、issuer を正規化 |
| 応答の相関 ID でログを検索できない | 境界が独自に ID を生成し、監査ログはリクエストの ID を書いていた | リクエストの ID を境界に渡す。`onToolFailure` を繋いで kintone のコード・ID も残す |

### 「防御が2枚あるとテストが通ってしまう」が、また起きた

今回も3度踏んだ。**いずれも、テストは通るのに欠陥は残っていた。**

| 場面 | 通ってしまった理由 | どう直したか |
| --- | --- | --- |
| 未解析の本文を SDK に渡さない判定 | 手前の Content-Type 限定が先に止める。HTTP 越しでは単独で試せない | **判定そのものを直接呼ぶ**テストに分けた |
| 締め切りが認証段階を覆っているか | cybozu 側の期限が先に応答を作るので、**締め切りを丸ごと止めても通った** | **保存層を止める**（締め切り以外に解く手段が無い状況を作る） |
| 期限切れ state を消費しないこと | 「2回目も expired」は、消費してから弾く実装でも成り立つ | **保存層への呼び出しを数える** |

### 時間で測るテストは、直っていても落ちる

締め切りの検証を「○秒以内に返ること」で書いたところ、
並行実行の負荷で**3割ほど落ちた**。実装は正しい。

止まった処理が**テストの後片付けでしか解けない**形にすれば、
「返るかどうか」だけで判定でき、実時間に依存しなくなる。

### 空きポートを探してから listen し直すと、まれに固まる

調べてから掴むまでの間に、並行して走る別のテストファイルが同じポートを取れる。
`listen` の失敗を受ける相手がいないため、テストは**失敗ではなく固まる**。
**先に listen して、決まったポートで組み立てる**形に変えた。

---

## 付録: 外部レビュー 第7回 (2026-09-16) — 失効経路

**判定: フェーズ5 は続行可。ただし 4a/4b/4c の完了判定は保留。**

P1 3件・P2 2件。**すべて再現スクリプト付き**で、こちらでも裏を取って修正した。

| 指摘 | 実物で確認した内容 | 修正 |
| --- | --- | --- |
| **切断しても発行済みアクセストークンが残る** | `Grant extends BaseToken` で、`destroy()` は Grant 文書を消すだけ。`revokeByGrantId()` は呼ばない | 系列のトークンを明示的に消す |
| **Grant 削除との競合で失効が飛ぶ** | `helpers/revoke.js` が `revokeByGrantId()` と Grant 削除を `Promise.all` で並行実行する。Grant が先に消えると主体を引けない | Grant とは独立した `GrantOwner` 対応レコードを持つ |
| 失効確認と保存が非原子的 | 単一文書の `update()` では複数文書をまたげない | **利用時にも照合する**（`adapter.find` が失効済みなら `undefined`） |
| 切断の再試行ができない | `revoke()` が `providerGrantId` を消していた | 失効済みレコードにも対応 ID を残す |
| 上流失効が provider 側に届かない | `grants.revoke()` しか呼んでいなかった | 失効を `revocation.ts` に一点集約 |

### ミューテーション検査で「二重防御がテストを隠す」ことが分かった

修正後に検査したところ、**3つとも壊してもテストが落ちなかった**。

`provider.AccessToken.find()` は利用時の照合でも `undefined` を返すため、
「トークンが本当に消えたか」を区別できていなかった。
**保存層を直接見る**形に変え、3つの防御を独立に検証するようにした。

---

## 付録: 外部レビュー 第6回 (2026-09-16) — 実装 (4a/4b)

**判定: 4c・5・6 の開発は続行可。ただし 4a/4b を完了扱いにするには修正が必要。**

P1 4件 + P2 2件。**すべて実物の provider で再現されたうえでの指摘**で、
自分でも再現を確認して修正した。

| 指摘 | 再現した内容 | 修正 |
| --- | --- | --- |
| **失効した接続が競合で復活する** | `create()` と `revoke()` の並行実行で最終状態が `revoked:false` | `storage.update()`（読み取りと書き込みを不可分に行う）を追加し、`create` / `updateAccessToken` を条件付き更新に |
| **再使用検知が接続の失効につながっていない** | 逐次の再使用は `consume()` を通らず、provider が `revokeByGrantId()` を呼ぶ。そこを拾っていなかった | 両経路を `revokeConnection` に集約。`upsert` でも失効を確認。`TokenReuseError` を `errors.InvalidGrant` 継承に |
| **2回目の接続が同意も cybozu 認可も飛ばす** | 既定の `loadExistingGrant` が `session.grantIdFor(clientId)` にフォールバックする | `loadExistingGrant` を差し替え、interaction policy に「ブリッジ必須」チェックを追加 |
| **`provider.proxy`** | TLS 終端後に Cookie 発行が失敗する | 上記のとおり訂正 |
| finish の「一度きり」が非原子的 | 並行実行で Grant が2個できる | （4c で対応。`storage.consume` を使う） |
| 不正な `resource` が 500 になる | 通常の `Error` を投げていた | `errors.InvalidTarget` に |

### 実装して分かったこと: 接続ごとに accountId を変えると、アカウント切替が挟まる

2接続目で `accountId` が変わるため、provider が `resume.js` の次の分岐に入る。

```js
if (result?.login && session.accountId && session.accountId !== result.login.accountId) {
  // → end_session_confirm への form_post（アカウント切替の確認）
}
```

**接続ごとの主体という設計の必然的な帰結**で、実ブラウザは JS でこのフォームを
自動送信する。フローは完結するが、**スマホの内蔵ブラウザで JS 自動送信が
動くかは実機で確認する必要がある**（フェーズ6 の確認項目）。

### テストの指摘も反映した

- **PKCE のテストが別の理由で通っていた。** 存在しないコードを送っていたため
  verifier の検証に到達していなかった。有効な未使用コードと別 verifier に変更し、
  さらに「正しい verifier なら通る」対のテストを足して、
  別の理由で落ちていないことを示した
- 失効のテストに意味のないアサーションが残っていたので、
  失効した `accountId` を実際に捕まえて確認する形にした

---

## 付録: 外部レビュー 第5回 (2026-09-16) — 着手判定

**残る設計ブロッカーは1件だけになった。**

> 設計で決めるべきこと：refresh 発行条件を一つに確定すること。
> **これが済めば、今回の指摘を理由に認証・保管の本実装を止める必要はありません。**

### 設計 — 確定させた1件

⚠ **`grant_types` に `refresh_token` を書くだけでは、リフレッシュトークンが一度も発行されない。**
v9.12.2 のソースで裏を取った。

- 既定の `issueRefreshToken` は `source.scopes.has('offline_access')` を要求する
- `offline_access` は **`prompt=consent` を含まない認可要求で除去される**
- Claude がそれを送る保証は無い

→ §4.10 で **「`issueRefreshToken` を差し替え、`offline_access` に依存せず
承認済みブリッジを完了した `claude-hosted` には常に発行する」**と確定した。
scope に現れない以上、**継続アクセスへの同意は画面で伝える**。

### 実装 — 例外境界を3度目の作り直し

**境界自身の例外が境界を素通りしていた。** 再現を確認した。

```
[フックが投げる]   漏えい: true | {"content":[{"text":"HOOK_SENTINEL_secret_7c1e"}],"isError":true}
[getter が投げる] 漏えい: true | {"content":[{"text":"HOOK_SENTINEL_secret_7c1e"}],"isError":true}
```

分類処理もログ用フックも `catch` の内側で動くのに、それ自体の例外を捕まえていなかった。

**あわせて「形の検証」方式も捨てた。** `code` / `id` を正規表現で縛っても、
**形に合う秘密は通る**（`code: "REVIEW_SECRET_SENTINEL"` が通過することを指摘された）。

→ **方針を「未知の文字列を一切外に出さない」に変えた。**
クライアントに返すのは **HTTP ステータス・そこから決まる固定の分類・相関 ID** だけ。
kintone のエラーコードと ID は**サーバー側のログにだけ**残し、相関 ID で突き合わせる。

| 回 | 方式 | 破れ方 |
| --- | --- | --- |
| 1 | 例外の `message` をそのまま返す | 資格情報がそのまま出た |
| 2 | `status` / `code` / `id` だけ通す | `code` の中身が未検証 |
| 3 | `code` / `id` の形を正規表現で縛る | 形に合う秘密は通る。境界自身の例外も素通り |
| **4** | **未知の文字列を出さない（固定分類 + 相関 ID）** | — |

---

## 付録: 外部レビュー 第4回 (2026-09-16) — 実装済みコードを含む

**判定は「着手不可。ただし設計全体の作り直しは不要」。** 残るのは設計3件。

> 改善は実質的ですが、認証・保管部分の本実装への着手は、下記3件の設計補完後とします。
> アダプタ修正・契約テスト・非公開の技術検証は継続できます。

### 実装済みコードに実在のバグが2件見つかった

**どちらも再現を確認して修正した。** 契約テストが `tools/call` を実行していなかったため、
16件が通っていても検出できなかった。

| バグ | 再現した内容 | 修正 |
| --- | --- | --- |
| **ツール例外の秘密が MCP 応答に出る** | `{"content":[{"text":"kintone API failed: X-Cybozu-API-Token=REVIEW_SECRET_SENTINEL..."}],"isError":true}` | `src/adapter/errorBoundary.ts` を追加。出すのは status / code / id だけ |
| **`listChanged: true` を広告していた** | initialize 応答が `{"tools":{"listChanged":true}}` | `registerTool()` が立てる値を明示的に打ち消す |

2件目は**設計 §2.2 に「広告しない」と書いておきながら、実装が逆になっていた**。
`registerCapabilities({ tools: {} })` ではマージされるだけで消えない。

あわせて、上流の `shouldEnableTool` を `selectTools` に通していなかった点も修正した
（API トークン認証で `kintone-get-apps` を公開してしまう）。
テストは16件 → **22件**に増やし、例外経路と capability 広告を固定した。

### 設計に反映した3件

| 指摘 | 反映 |
| --- | --- |
| **`consume()` の競合失敗が系列失効につながらない。** provider の失効処理は「取得済みオブジェクトの `consumed` が真」のときしか走らないので、例外を投げても先行要求のトークンが生き残る | §4.10 — **競合を検知した transaction 内で失効を確定し、コミットしてから `invalid_grant` を返す**（transaction 内で投げると失効まで巻き戻る） |
| **全モデル共通の `jti` 除去では `findByUid()` が成立しない。** `Session` は `uid` と `jti` が別値で、`Interaction.session.cookie` にも生 `jti` が入る | §4.10 — **モデル別の保存・復元契約**に分離 |
| **`grant_types` に `refresh_token` を書くだけでは発行されない。** 既定の `issueRefreshToken` は `offline_access` を要求。既定の `loadExistingGrant` は既存セッションを再利用し、2つ目の接続でブリッジを飛ばす | §4.10 — 発行方針・`expiresWithSession`・**新規接続は必ずブリッジを通す policy** |

`/authorize` と `/auth` の混在、流量制限の単位の食い違いも解消した。

---

## 付録: 外部レビュー 第3回 (2026-09-16) — oidc-provider 採用後

**判定はまた「不合格」。** ただし範囲は狭まった。

> 改善は実質的ですが、まだ合格にはできません。フェーズ1でも、認証・保管部分の本実装は
> P1 を具体化してから着手すべきです。**アダプタ・契約テスト・非公開の技術検証は着手可、公開は不可です。**

P1 が5件、P2 が3件。**`oidc-provider` 9.12.2 のソースで裏を取り、すべて反映した。**

**実物で確認した事実:**

| 主張 | 検証結果 |
| --- | --- |
| 不透明トークンの値は `jti` そのもので、文書 ID にも payload にも入る | **事実。** `IN_PAYLOAD = ['iat','exp','jti','kind']`、`adapter.upsert(this.jti, payload, ttl)`、`return { value: token.jti, payload }` |
| `devInteractions` の既定は有効 | **事実。** `devInteractions: { enabled: true }` |
| `revocation` の既定は無効 | **事実。** `revocation: { enabled: false }` |
| `getResourceServerInfo` は実装必須 | **事実。** 既定は「必ず差し替えろ」と例外を投げる |
| 認可パスの既定は `/auth` | **事実。** 設計書に `/authorize` と `/auth` が混在していた |
| `get-app` は `appId`、`get-app-deploy-status` は `apps[]` | **事実。** 上流ソースで確認。設計書は `app` しか想定していなかった |
| `get-apps` は同じデータを `structuredContent` と `content[].text` に返す | **事実。** 片方だけ絞ると漏れる |

**反映:**

| 指摘 | 反映 |
| --- | --- |
| Adapter の原子性が「原則の追記」で閉じていない（前回 P1 が未解消） | §4.10 — `consume` を未使用条件付き更新に、失効フラグを保存時・利用時の両方で照合 |
| 「ハッシュのみ保存」は payload の `jti` で破れる | §4.10 — 保存時に生 `jti` を除去、`find` で復元。テスト対象に Firestore の本文・索引を追加 |
| 主体 / Grant / 接続 grant の対応が未設計 | §4.10 — `interaction UID → 認可トランザクション → 内部主体 → provider Grant → 接続 grant` |
| provider 設定と `/mcp` の検証契約が不足 | §4.10 — 設定表と検証表を追加 |
| `ALLOWED_APP_IDS` の適用対象が実物と合っていない | §5 — 9ツール分の抽出表 |
| 撤回が文書全体に反映されていない | 「アプリ単位の API トークン」を防御として引用する記述を全削除 |
| ログ sink は独立評価される | §7.4 — 除外位置・網羅・順序を決める項目に |
| 流量制御の単位が表と本文で矛盾 | §7.2 — 認証前／認証後で分離 |
| issuer とパスの不整合 | §4.6 — provider 既定に統一、フェーズ1 は `claude-hosted` のみ |

---

## 付録: 外部レビュー 第2回 (2026-09-16) — OAuth 設計

**判定は「不合格」だった。**

> この設計のまま認可サーバーの実装を進めることは勧めません。
> アダプタ・契約テストなどの基盤作業は開始できますが、
> 認証部分は P1 を設計に反映してから着手すべきです。公開は不可です。

P1 が9件、P2 が1件。**すべて妥当と判断し、反映した。**

| 指摘 | 反映 |
| --- | --- |
| **認可サーバーを自作するな**（保守された実装を使い、自作をブリッジと保管に限定せよ） | §4.4 — `oidc-provider` を採用 |
| 二段の認可を結ぶ state とブラウザ束縛が無い | §4.5 — cybozu 向けに別 state を生成し、Cookie とトランザクションに束縛 |
| 「DCR 不要」と「クライアント登録不要」は別 | §4.6 — `client_id` ごとに `redirect_uri` を固定 |
| 認可コードの束縛項目が足りない / 原子性が無い | §4.9 — 3種のレコードに分離、transaction で消費 |
| リフレッシュ・失効・TTL の保存モデルが無い | §4.9 — TTL は掃除であって認可判定ではない、と明記 |
| **アプリ単位の境界が OAuth で消えたのに、旧防御を引用している** | §5 — `ALLOWED_APP_IDS` を追加、付録の判断を撤回 |
| ログ対策が OAuth 経路と基盤ログを覆っていない | §7.4 — `code`/`state` が Cloud Logging に残る点を明記 |
| Firestore はコレクション名では分離できない | §6 — 専用データベース + 条件付き IAM |
| 流量制御が新しい攻撃面に未対応 | §7.2 — `/authorize` 乱打、無効 Bearer での KMS 呼び出しを遮断 |
| 公開テストが正常系中心 | §9 — 競合・中断・失効・秘密混入を公開ゲートに |

**事実の訂正3件:**

| 誤り | 正 |
| --- | --- |
| 「OAuth では22ツール」 | 22 は**技術的に実行可能な数**。既定ポリシーで公開されるのは **9** |
| 「ユーザー識別子を保存する」 | **cybozu の token 応答にユーザー識別子は含まれない。** 取得手段が未定のまま書いていた |
| 「API トークンがアプリ単位の制御を担うので ACL 不要」 | OAuth への変更で**前提が消滅していた** |

**cybozu のリフレッシュ応答に新しいリフレッシュトークンが含まれない**点も指摘で気づき、
§4.9 に明記した（既存の値を保持し続ける必要がある）。

---

## 付録: 外部レビュー 第1回 (2026-09-16) — 案B 時点

Codex によるレビューを受け、**15件の指摘のうち14件を反映した**。
特に次の2件は、実物のソースを読み直して**設計の誤りを確認**したもの。

| 指摘 | 検証結果 | 反映 |
| --- | --- | --- |
| `buildToolDefinition` は annotations を落とす | **事実。** 返すのは name/title/description/inputSchema/outputSchema の5つだけ | §2.1 / §5 — 一覧生成側でマージし、テストで検証 |
| 上流は `.d.ts` を出していない | **事実。** `tsconfig.json` の `"declaration": true` はコメントアウト | §2.1 — 自前の ambient 宣言を置く |
| API トークン操作の監査 | **事実。** 公式ドキュメントに「APIトークンを使用した操作は、Administratorによる操作として扱われます」 | §4 — 「監査が効く」の記述を訂正、§7.5 で入口側の監査を設計 |
| LRU キャッシュと「資格情報を保持しない」の矛盾 | **妥当。** プールを持つのは Agent でありクライアントではない | §4 — リクエストごとに生成、Agent を共有する方式へ変更 |
| 「課金が発生しないのでレートリミット不要」 | **妥当。** kintone 側の制限を使い切ると相手の業務が止まる | §2.3 で撤回、§7.2 で上限を定義 |

**当初「反映しない」とした1件を、後に撤回した**: 「利用主体ごとに操作範囲を制限する」。
「アプリ単位の API トークンがその制御を担っている」という理由で見送ったが、
**OAuth へ変更したことでその前提が消えた**（OAuth のスコープは操作種別の区分であって、
対象アプリの区分ではない）。§5 に `ALLOWED_APP_IDS` を追加した。

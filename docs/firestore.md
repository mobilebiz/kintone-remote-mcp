# Firestore の検証手順

保存層は **MemoryStorage と FirestoreStorage の2実装**があり、
`tests/auth/storage-contract.test.ts` が**同じ契約テストを両方に流す**。

メモリ実装だけで確かめても意味が無い。本番は Firestore で動く。

## エミュレータで動かす

Firestore エミュレータは **Java 21 以上**を要求する。
このリポジトリを動かした環境では、`gcloud` が拾う既定の Java が 17 だったため
明示的に新しい JDK を渡す必要があった。

```sh
# 1. エミュレータを入れる（初回のみ）
gcloud components install cloud-firestore-emulator

# 2. 起動する。Java 21+ を PATH の先頭に置く
PATH="/opt/homebrew/opt/openjdk/bin:$PATH" \
  gcloud emulators firestore start --host-port=127.0.0.1:8411

# 3. 別のシェルでテストを流す
pnpm test:firestore
```

`FIRESTORE_EMULATOR_HOST` が無い場合、Firestore 側のテストは**飛ばされる**。
飛ばしたことはテスト名に出るので、「通った」と読み違えないこと。

```
✓ スキップ: FIRESTORE_EMULATOR_HOST が未設定のため Firestore の検証は行っていない
```

## 何を確かめているか

| テスト | 確かめていること |
| --- | --- |
| `storage-contract.test.ts` | 両実装が**同じ契約**を満たす。特に `consume` / `update` の原子性 |
| `multi-instance.test.ts` | **切断・再使用検知が別インスタンスにも効く**（共有 Firestore 経由） |

後者は Cloud Run で複数インスタンスが動く前提の確認で、
**メモリ実装では原理的に確かめられない**。

## 本番の構成

- **専用のデータベース**を作り、**データベース条件付きの IAM** で縛る (§6)。
  コレクション名では分離できない（サーバー SDK は Security Rules を迂回する）
- 単一コレクション（既定 `oidc`）。文書 ID は `<model>|<key>`

  ⚠ **区切り文字は `|`。`__` にしてはいけない。**
  key は base64url なので `_` を含みうる。`__` にすると
  `("Access", "Token__k1")` と `("Access__Token", "k1")` が
  **同じ文書 ID になる**（エミュレータで再現した）

- **`undefined` は入れ子まで落とす。** Firestore は `undefined` を保存できず、
  `payload` の中に1つあるだけで書き込みが落ちる。
  浅く落とすだけだと**メモリ実装とだけ挙動が割れる**
- 索引は**単一フィールドの等価検索のみ**（`model` / `uidHash` / `userCodeHash` / `grantId`）。
  複合索引は不要
- `expiresAt` に TTL ポリシーを設定してよいが、
  **TTL は掃除であって認可判定ではない**。期限は使うたびにコード側で見る (§4.9)

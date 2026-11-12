# syntax=docker/dockerfile:1

# ---- ビルド ----
# 実行用と同じ版に固定する（パッチ版まで書かないと、古い版のキャッシュが使われることがある）
FROM node:22.23.5-slim AS build

WORKDIR /app
RUN corepack enable

# 依存だけ先に入れてレイヤーを効かせる
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY tsconfig.json ./
COPY src ./src
RUN pnpm run build

# 本番用の依存だけに絞る
RUN pnpm prune --prod

# ---- 実行 ----
# ⚠ 本来は distroless（シェルもパッケージマネージャも入っていない）を使う。
# 2026-11 の Node.js セキュリティ修正（v22.23.5）が distroless にまだ入っていない
# （nodejs22-debian12:nonroot は v22.22.0 のまま）ため、一時的に node:slim で動かしている。
# distroless が 22.23.5 以上になったら、次の行に戻す:
#   FROM gcr.io/distroless/nodejs22-debian12:nonroot  （CMD は ["dist/index.js"]）
FROM node:22.23.5-slim

# root で動かさない（node イメージに入っている uid 1000 のユーザー）
USER node

LABEL org.opencontainers.image.description="Remote MCP server for kintone"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json

# Cloud Run は PORT を渡してくる
ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "dist/index.js"]

# syntax=docker/dockerfile:1

# ---- ビルド ----
FROM node:22-slim AS build

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
# distroless。シェルもパッケージマネージャも入っていない
FROM gcr.io/distroless/nodejs22-debian12:nonroot

LABEL org.opencontainers.image.description="Remote MCP server for kintone"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json

# Cloud Run は PORT を渡してくる
ENV NODE_ENV=production
EXPOSE 8080

CMD ["dist/index.js"]

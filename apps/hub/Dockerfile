# syntax=docker/dockerfile:1.7

FROM node:24-slim AS prepare

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME/bin:$PNPM_HOME:$PATH

WORKDIR /repo
RUN corepack enable

COPY . .

RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
  pnpm config set store-dir /pnpm/store && \
  pnpm dlx turbo@2.9.18 prune @enoki/hub @enoki/web --docker

FROM node:24-slim AS installer

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME/bin:$PNPM_HOME:$PATH

WORKDIR /app
RUN corepack enable

COPY --from=prepare /repo/out/json/ ./
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
  pnpm config set store-dir /pnpm/store && \
  pnpm install --frozen-lockfile --dangerously-allow-all-builds

FROM installer AS builder

COPY --from=prepare /repo/out/full/ ./
COPY --from=prepare /repo/tsconfig.base.json ./tsconfig.base.json

RUN pnpm exec turbo run build --filter=@enoki/hub --filter=@enoki/web
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
  PNPM_CONFIG_DANGEROUSLY_ALLOW_ALL_BUILDS=true \
  pnpm --filter @enoki/hub --prod deploy --legacy --offline /app/deploy

FROM node:24-slim AS runtime

ENV ENOKI_WEB_DIST=/app/web-dist
ENV ENOKI_DATA_ROOT=/data
ENV ENOKI_DEPLOYMENT=docker
ENV ENOKI_SQLITE_PATH=/data/enoki.db
ENV HOST=0.0.0.0
ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

COPY --from=builder --chown=node:node /app/deploy ./
COPY --from=builder --chown=node:node /app/apps/hub/drizzle drizzle
COPY --from=builder --chown=node:node /app/apps/web/dist web-dist

RUN mkdir -p /data && chown -R node:node /app /data

VOLUME ["/data"]
EXPOSE 3000 3001
CMD ["node", "dist/src/server.js"]

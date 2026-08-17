# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM node:26-slim@sha256:4ebb5ace66f15a24c14c492e01a8beeed4fddf970a856109f5126e703e5fe503 AS prepare

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME/bin:$PNPM_HOME:$PATH

WORKDIR /repo
RUN corepack enable

COPY . .
RUN mkdir -p probe-assets

RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
  pnpm config set store-dir /pnpm/store && \
  pnpm dlx turbo@2.10.2 prune @enoki/hub @enoki/web --docker

FROM node:26-slim@sha256:4ebb5ace66f15a24c14c492e01a8beeed4fddf970a856109f5126e703e5fe503 AS installer

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME/bin:$PNPM_HOME:$PATH

WORKDIR /app
RUN corepack enable

COPY --from=prepare /repo/out/json/ ./
COPY --from=prepare /repo/out/full/ ./
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
  pnpm config set store-dir /pnpm/store && \
  pnpm install --frozen-lockfile --dangerously-allow-all-builds

FROM installer AS builder

COPY --from=prepare /repo/out/full/ ./
COPY --from=prepare /repo/tsconfig.base.json ./tsconfig.base.json
COPY --from=prepare /repo/probe-assets/ /app/probe-assets/
RUN mkdir -p /app/probe-assets

RUN pnpm exec turbo run build --filter=@enoki/hub --filter=@enoki/web
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
  PNPM_CONFIG_DANGEROUSLY_ALLOW_ALL_BUILDS=true \
  pnpm --filter @enoki/hub --prod --no-optional deploy --legacy /app/deploy && \
  rm -f /app/deploy/node_modules/.modules.yaml

FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS runtime

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
COPY --from=builder --chown=node:node /app/apps/hub/drizzle-official-metrics drizzle-official-metrics
COPY --from=builder --chown=node:node /app/apps/web/dist web-dist
COPY --from=builder --chown=node:node /app/probe-assets probe-assets
COPY apps/hub/docker-entrypoint.sh /usr/local/bin/enoki-hub-entrypoint

ADD --checksum=sha256:4003163f58cd4a75df79973171d25e4912df4284d8bac9850ac267b58b969be5 \
  https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/su-exec-0.3-r0.apk \
  /tmp/su-exec.apk

RUN apk add --allow-untrusted --no-network /tmp/su-exec.apk && \
  rm /tmp/su-exec.apk && \
  rm -f /var/log/apk.log && \
  chmod +x /app/dist/src/hub-state-snapshot/cli.js && \
  ln -s /app/dist/src/hub-state-snapshot/cli.js /usr/local/bin/enoki-hub-state && \
  chmod +x /usr/local/bin/enoki-hub-entrypoint && \
  install -d -o node -g node /data

VOLUME ["/data"]
EXPOSE 3000 3001
ENTRYPOINT ["enoki-hub-entrypoint"]
CMD ["node", "dist/src/server.js"]

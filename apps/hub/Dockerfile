# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG ENOKI_HUB_IMAGE_INPUTS="release"

FROM node:26-slim@sha256:c0753125a3789977aefe869cbebccf70e3cfd7ea84ca48547458f02e4f1d7146 AS prepare

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME/bin:$PNPM_HOME:$PATH

WORKDIR /repo
RUN corepack enable

COPY . .
RUN mkdir -p probe-assets
RUN mkdir -p probe-bootstrap-publication

RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
  pnpm config set store-dir /pnpm/store && \
  pnpm dlx turbo@2.10.2 prune @enoki/hub @enoki/web --docker

FROM node:26-slim@sha256:c0753125a3789977aefe869cbebccf70e3cfd7ea84ca48547458f02e4f1d7146 AS installer

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

ARG ENOKI_HUB_IMAGE_INPUTS

COPY --from=prepare /repo/out/full/ ./
COPY --from=prepare /repo/tsconfig.base.json ./tsconfig.base.json
COPY --from=prepare /repo/probe-assets/ /app/probe-assets/
COPY --from=prepare /repo/probe-bootstrap-publication/ /app/probe-bootstrap-publication/
RUN mkdir -p /app/probe-assets /app/probe-bootstrap-publication /app/probe-distribution-root && \
  case "$ENOKI_HUB_IMAGE_INPUTS" in \
    standard-ci-non-production) \
      printf '%s\n' 'ENOKI standard CI non-production fixture; not a release trust root.' > /app/probe-assets/root-key.pem; \
      cp /app/probe-assets/root-key.pem /app/probe-distribution-root/root-key.pem; \
      printf '%s\n' 'standard CI non-production Bootstrap fixture' > /app/probe-bootstrap-publication/enoki-probe-bootstrap.py; \
      recipe_sha256="$(sha256sum /app/probe-bootstrap-publication/enoki-probe-bootstrap.py | cut -d ' ' -f1)"; \
      recipe_size="$(wc -c < /app/probe-bootstrap-publication/enoki-probe-bootstrap.py)"; \
      printf '{"bundleVersion":"0.0.0","distribution":"enoki","kind":"enoki-probe-bootstrap-recipe-record","recipe":{"file":"enoki-probe-bootstrap.py","sha256":"%s","size":%s,"version":"v1"},"rootFingerprint":"0000000000000000000000000000000000000000000000000000000000000000","schemaVersion":1,"targets":["aarch64-unknown-linux-gnu","aarch64-unknown-linux-musl","x86_64-unknown-linux-gnu","x86_64-unknown-linux-musl"]}\n' "$recipe_sha256" "$recipe_size" > /app/probe-bootstrap-publication/enoki-probe-bootstrap-recipe.json ;; \
    release) \
      cp /app/probe-assets/root-key.pem /app/probe-distribution-root/root-key.pem ;; \
    *) \
      echo "unsupported ENOKI_HUB_IMAGE_INPUTS: $ENOKI_HUB_IMAGE_INPUTS" >&2; exit 2 ;; \
  esac

RUN pnpm exec turbo run build --filter=@enoki/hub --filter=@enoki/web
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
  PNPM_CONFIG_DANGEROUSLY_ALLOW_ALL_BUILDS=true \
  pnpm --filter @enoki/hub --prod --no-optional deploy --legacy /app/deploy && \
  rm -f /app/deploy/node_modules/.modules.yaml

FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS runtime

ARG ENOKI_HUB_IMAGE_INPUTS

ENV ENOKI_WEB_DIST=/app/web-dist
ENV ENOKI_DATA_ROOT=/data
ENV ENOKI_DEPLOYMENT=docker
ENV ENOKI_SQLITE_PATH=/data/enoki.db
ENV HOST=0.0.0.0
ENV NODE_ENV=production
ENV ENOKI_HUB_IMAGE_INPUTS=$ENOKI_HUB_IMAGE_INPUTS
ENV PORT=3000

WORKDIR /app

COPY --from=builder --chown=node:node /app/deploy ./
COPY --from=builder --chown=node:node /app/apps/hub/drizzle drizzle
COPY --from=builder --chown=node:node /app/apps/hub/drizzle-official-metrics drizzle-official-metrics
COPY --from=builder --chown=node:node /app/apps/web/dist web-dist
COPY --from=builder --chown=node:node /app/probe-assets probe-assets
COPY --from=builder /app/probe-bootstrap-publication probe-bootstrap-publication
COPY --from=builder /app/probe-distribution-root probe-distribution-root
COPY apps/hub/docker-entrypoint.sh /usr/local/bin/enoki-hub-entrypoint

ADD --checksum=sha256:4003163f58cd4a75df79973171d25e4912df4284d8bac9850ac267b58b969be5 \
  https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/su-exec-0.3-r0.apk \
  /tmp/su-exec.apk

RUN apk add --allow-untrusted --no-network /tmp/su-exec.apk && \
  rm /tmp/su-exec.apk && \
  rm -f /var/log/apk.log && \
  chmod 0555 /app/probe-distribution-root && \
  chmod 0444 /app/probe-distribution-root/root-key.pem && \
  chmod 0555 /app/probe-bootstrap-publication && \
  chmod 0444 /app/probe-bootstrap-publication/enoki-probe-bootstrap-recipe.json && \
  chmod +x /app/dist/src/hub-state-snapshot/cli.js && \
  ln -s /app/dist/src/hub-state-snapshot/cli.js /usr/local/bin/enoki-hub-state && \
  chmod +x /usr/local/bin/enoki-hub-entrypoint && \
  install -d -o node -g node /data

VOLUME ["/data"]
EXPOSE 3000 3001
ENTRYPOINT ["enoki-hub-entrypoint"]
CMD ["node", "dist/src/server.js"]

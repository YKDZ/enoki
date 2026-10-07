ARG NODE_VERSION=24.21.0
FROM node:${NODE_VERSION}-bookworm-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG PLAYWRIGHT_CLI_PACKAGE=@playwright/test@1.61.1
ARG RUST_TOOLCHAIN=1.97.1

ENV COREPACK_HOME="/corepack"
ENV PNPM_HOME="/pnpm"
ENV RUSTUP_HOME="/usr/local/rustup"
ENV CARGO_HOME="/usr/local/cargo"
ENV PATH="/usr/local/cargo/bin:${PNPM_HOME}:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      git \
      git-lfs \
      jq \
      less \
      libc6-dev \
      openssh-client \
      pkg-config \
      procps \
      python3 \
      ripgrep \
      shellcheck \
      unzip \
      xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0755 "${COREPACK_HOME}" "${PNPM_HOME}" \
    && corepack enable --install-directory "${PNPM_HOME}" \
    && chmod -R a+rX "${COREPACK_HOME}" "${PNPM_HOME}" \
    && install -d -m 0755 /root/.config/pnpm \
    && printf '%s\n' 'store-dir: /pnpm/store' > /root/.config/pnpm/config.yaml \
    && printf '%s\n' 'export PATH="/usr/local/cargo/bin:/pnpm:${PATH}"' > /etc/profile.d/enoki-toolchain.sh

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain none \
    && rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal --component rustfmt --component clippy \
    && rustup default "${RUST_TOOLCHAIN}" \
    && chmod -R a+w "${RUSTUP_HOME}" "${CARGO_HOME}"

RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

RUN npx --yes --package "${PLAYWRIGHT_CLI_PACKAGE}" playwright install-deps chromium

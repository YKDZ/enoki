ARG NODE_VERSION=24
FROM node:${NODE_VERSION}-bookworm-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG PACKAGE_MANAGER_PIN=pnpm@11.11.0
ARG PLAYWRIGHT_CLI_PACKAGE=@playwright/test@1.61.1
ARG RUST_TOOLCHAIN=stable

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
      gh \
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
    && corepack prepare "${PACKAGE_MANAGER_PIN}" --activate \
    && chmod -R a+rX "${COREPACK_HOME}" "${PNPM_HOME}" \
    && printf '%s\n' 'export PATH="/usr/local/cargo/bin:/pnpm:${PATH}"' > /etc/profile.d/enoki-toolchain.sh

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain none \
    && rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal --component rustfmt --component clippy \
    && rustup default "${RUST_TOOLCHAIN}" \
    && chmod -R a+w "${RUSTUP_HOME}" "${CARGO_HOME}"

RUN npx --yes --package "${PLAYWRIGHT_CLI_PACKAGE}" playwright install-deps chromium

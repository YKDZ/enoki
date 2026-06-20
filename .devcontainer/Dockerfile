FROM node:24-bookworm

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
ENV SHELL=/bin/bash
ENV PNPM_HOME="/pnpm"
ENV CARGO_HOME="/usr/local/cargo"
ENV RUSTUP_HOME="/usr/local/rustup"
ENV RUST_BACKTRACE=1
ENV PATH="$PNPM_HOME/bin:$PNPM_HOME:$CARGO_HOME/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    bash-completion \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    fd-find \
    git \
    jq \
    less \
    libssl-dev \
    pkg-config \
    procps \
    python3 \
    ripgrep \
    screen \
    shellcheck \
    tmux \
    unzip \
    xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/fdfind /usr/local/bin/fd \
    && corepack enable \
    && corepack prepare pnpm --activate \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && rustup component add rustfmt clippy \
    && pnpm install -g --allow-build=@openai/codex @openai/codex turbo

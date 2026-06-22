#!/bin/sh
set -eu

data_root="${ENOKI_DATA_ROOT:-/data}"

if [ "$(id -u)" = "0" ]; then
  install -d -o node -g node "$data_root"
  chown -R node:node "$data_root"
  exec su-exec node "$@"
fi

exec "$@"

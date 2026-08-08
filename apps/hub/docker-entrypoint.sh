#!/bin/sh
set -eu

data_root_base="${ENOKI_DATA_ROOT_BASE:-/data}"
data_root="${ENOKI_DATA_ROOT:-$data_root_base}"

case "$data_root" in
  "$data_root_base" | "$data_root_base"/*) ;;
  *)
    echo "ENOKI_DATA_ROOT must be /data or a path below /data." >&2
    exit 1
    ;;
esac

case "$data_root" in
  *[[:space:]]* | */../* | */.. | */./* | */.)
    echo "ENOKI_DATA_ROOT must not contain whitespace, . or .. path components." >&2
    exit 1
    ;;
esac

reject_symlink_components() {
  current="$data_root_base"
  remainder="${data_root#$data_root_base}"
  remainder="${remainder#/}"

  if [ -L "$current" ]; then
    echo "ENOKI_DATA_ROOT must not contain symlink path components." >&2
    exit 1
  fi

  while [ -n "$remainder" ]; do
    component="${remainder%%/*}"
    if [ "$component" = "$remainder" ]; then
      remainder=""
    else
      remainder="${remainder#*/}"
    fi

    current="${current}/${component}"
    if [ -L "$current" ]; then
      echo "ENOKI_DATA_ROOT must not contain symlink path components." >&2
      exit 1
    fi
  done
}

reject_symlink_components

restore_journal="$data_root/.enoki-hub-state-restore-v1.json"
if [ -e "$restore_journal" ]; then
  echo "Hub Restore transaction is incomplete; keep the Hub stopped and run enoki-hub-state snapshot, verify, or restore to recover it." >&2
  exit 1
fi

if [ "$(id -u)" = "0" ]; then
  install -d -o node -g node "$data_root"
  chown -R node:node "$data_root"
  exec su-exec node "$@"
fi

exec "$@"

#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="enoki-probe"
SERVICE_USER="${ENOKI_SERVICE_USER:-enoki-probe}"
SERVICE_GROUP="${ENOKI_SERVICE_GROUP:-enoki-probe}"
PROBE_VERSION="${ENOKI_PROBE_VERSION:-}"
GITHUB_RELEASE_BASE_URL="${ENOKI_GITHUB_RELEASE_BASE_URL:-https://github.com/YKDZ/enoki/releases/download}"
GITHUB_LATEST_RELEASE_BASE_URL="${ENOKI_GITHUB_LATEST_RELEASE_BASE_URL:-https://github.com/YKDZ/enoki/releases/latest/download}"
INSTALL_PATH="${ENOKI_INSTALL_PATH:-/usr/local/bin/enoki-probe}"
CONFIG_PATH="${ENOKI_CONFIG_PATH:-/etc/enoki/probe-bootstrap.toml}"
STATE_DIR="${ENOKI_STATE_DIR:-/var/lib/enoki-probe}"
LOG_LEVEL="${ENOKI_LOG_LEVEL:-info}"
TEST_ROOT="${ENOKI_TEST_ROOT:-}"

fail() {
  echo "Enoki Probe install failed: $*" >&2
  exit 1
}

require_value() {
  local name="$1"
  local value="$2"

  if [ -z "$value" ]; then
    fail "$name is required."
  fi
}

rooted_path() {
  local path="$1"

  if [ -n "$TEST_ROOT" ] && [[ "$path" = /* ]]; then
    printf '%s%s\n' "$TEST_ROOT" "$path"
  else
    printf '%s\n' "$path"
  fi
}

host_path() {
  printf '%s\n' "$1"
}

detect_target() {
  if [ "$(uname -s)" != "Linux" ]; then
    fail "only Linux hosts are supported."
  fi

  case "$(uname -m)" in
    x86_64 | amd64)
      echo "x86_64-unknown-linux-gnu"
      ;;
    aarch64 | arm64)
      echo "aarch64-unknown-linux-gnu"
      ;;
    *)
      fail "unsupported CPU architecture: $(uname -m). Supported: x86_64, aarch64."
      ;;
  esac
}

ensure_systemd() {
  local runtime_dir="${ENOKI_SYSTEMD_RUNTIME_DIR:-/run/systemd/system}"

  command -v systemctl >/dev/null 2>&1 ||
    fail "systemd is required, but systemctl was not found."
  systemctl --version >/dev/null 2>&1 ||
    fail "systemd is required, but systemctl is not usable."

  if [ ! -d "$runtime_dir" ]; then
    fail "systemd is required, but $runtime_dir does not exist."
  fi
}

ensure_root() {
  if [ -n "$TEST_ROOT" ]; then
    return
  fi

  if [ "$(id -u)" != "0" ]; then
    fail "run this installer as root, for example through sudo."
  fi
}

download_file() {
  local url="$1"
  local output="$2"

  command -v curl >/dev/null 2>&1 ||
    fail "curl is required to download Probe release artifacts."
  curl -fsSL -o "$output" "$url"
}

download_urls() {
  local target="$1"
  local archive_url="${ENOKI_PROBE_DOWNLOAD_URL:-}"
  local checksum_url="${ENOKI_PROBE_SHA256_URL:-}"

  if [ -z "$archive_url" ]; then
    if [ -n "$PROBE_VERSION" ]; then
      archive_url="${GITHUB_RELEASE_BASE_URL}/${PROBE_VERSION}/enoki-probe-${target}.tar.gz"
    else
      archive_url="${GITHUB_LATEST_RELEASE_BASE_URL}/enoki-probe-${target}.tar.gz"
    fi
  fi

  if [ -z "$checksum_url" ]; then
    checksum_url="${archive_url}.sha256"
  fi

  printf '%s\n%s\n' "$archive_url" "$checksum_url"
}

verify_checksum() {
  local archive="$1"
  local checksum_file="$2"
  local expected="${ENOKI_PROBE_SHA256:-}"
  local actual

  if [ -z "$expected" ]; then
    expected="$(awk '{print $1; exit}' "$checksum_file")"
  fi

  if ! [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
    fail "downloaded Probe checksum is not a valid sha256 value."
  fi

  actual="$(sha256sum "$archive" | awk '{print $1}')"

  if [ "${actual,,}" != "${expected,,}" ]; then
    fail "Probe sha256 verification failed."
  fi
}

ensure_service_user() {
  ensure_service_group

  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    return
  fi

  useradd \
    --system \
    --gid "$SERVICE_GROUP" \
    --home-dir "$STATE_DIR" \
    --shell /usr/sbin/nologin \
    "$SERVICE_USER"
}

ensure_service_group() {
  if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    return
  fi

  groupadd --system "$SERVICE_GROUP"
}

install_binary() {
  local archive="$1"
  local work_dir="$2"
  local extract_dir="$work_dir/extract"
  local source_binary
  local install_path_rooted
  local install_dir_rooted

  mkdir -p "$extract_dir"
  tar -xzf "$archive" -C "$extract_dir"

  if [ -f "$extract_dir/enoki-probe" ]; then
    source_binary="$extract_dir/enoki-probe"
  else
    source_binary="$(find "$extract_dir" -type f -name enoki-probe | head -n 1)"
  fi

  if [ -z "$source_binary" ] || [ ! -f "$source_binary" ]; then
    fail "Probe release archive did not contain an enoki-probe binary."
  fi

  install_path_rooted="$(rooted_path "$INSTALL_PATH")"
  install_dir_rooted="$(dirname "$install_path_rooted")"
  mkdir -p "$install_dir_rooted"
  cp "$source_binary" "$install_path_rooted"
  chmod 0755 "$install_path_rooted"
}

write_bootstrap_config() {
  local config_path_rooted
  local state_dir_rooted

  config_path_rooted="$(rooted_path "$CONFIG_PATH")"
  state_dir_rooted="$(rooted_path "$STATE_DIR")"
  mkdir -p "$(dirname "$config_path_rooted")" "$state_dir_rooted"

  {
    printf 'hub_url = '
    toml_string "$ENOKI_HUB_URL"
    printf '\n'
    printf 'enrollment_token = '
    toml_string "$ENOKI_ENROLLMENT_TOKEN"
    printf '\n'
    printf 'state_dir = '
    toml_string "$STATE_DIR"
    printf '\n'
    printf 'log_level = '
    toml_string "$LOG_LEVEL"
    printf '\n'
  } >"$config_path_rooted"
  chmod 0600 "$config_path_rooted"

  if [ -z "$TEST_ROOT" ]; then
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$state_dir_rooted"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$config_path_rooted"
  fi
}

toml_string() {
  local value="$1"

  value="${value//\\/\\\\}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  value="${value//\"/\\\"}"

  printf '"%s"' "$value"
}

write_systemd_service() {
  local service_dir_rooted
  local service_path_rooted

  service_dir_rooted="$(rooted_path /etc/systemd/system)"
  service_path_rooted="$service_dir_rooted/${SERVICE_NAME}.service"
  mkdir -p "$service_dir_rooted"

  cat >"$service_path_rooted" <<EOF
[Unit]
Description=Enoki Probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
ExecStart=$(host_path "$INSTALL_PATH") run --config $(host_path "$CONFIG_PATH")
Restart=always
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=$(host_path "$STATE_DIR") $(dirname "$(host_path "$CONFIG_PATH")")

[Install]
WantedBy=multi-user.target
EOF
}

main() {
  local target
  local work_dir
  local archive
  local checksum_file
  local archive_url
  local checksum_url

  require_value "ENOKI_HUB_URL" "${ENOKI_HUB_URL:-}"
  require_value "ENOKI_ENROLLMENT_TOKEN" "${ENOKI_ENROLLMENT_TOKEN:-}"
  ensure_root
  ensure_systemd
  target="$(detect_target)"
  work_dir="$(mktemp -d)"
  archive="$work_dir/enoki-probe.tar.gz"
  checksum_file="$work_dir/enoki-probe.tar.gz.sha256"
  trap "rm -rf '$work_dir'" EXIT

  mapfile -t urls < <(download_urls "$target")
  archive_url="${urls[0]}"
  checksum_url="${urls[1]}"

  download_file "$archive_url" "$archive"
  download_file "$checksum_url" "$checksum_file"
  verify_checksum "$archive" "$checksum_file"
  ensure_service_user
  install_binary "$archive" "$work_dir"
  write_bootstrap_config
  write_systemd_service
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}.service"
  systemctl start "${SERVICE_NAME}.service"

  echo "Enoki Probe installed as ${SERVICE_NAME}.service."
}

main "$@"

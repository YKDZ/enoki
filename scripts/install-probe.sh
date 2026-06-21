#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="enoki-probe"
SERVICE_USER="${ENOKI_SERVICE_USER:-enoki-probe}"
SERVICE_GROUP="${ENOKI_SERVICE_GROUP:-enoki-probe}"
INSTALL_PATH="${ENOKI_INSTALL_PATH:-/usr/local/bin/enoki-probe}"
CONFIG_PATH="${ENOKI_CONFIG_PATH:-/etc/enoki/probe-bootstrap.toml}"
STATE_DIR="${ENOKI_STATE_DIR:-/var/lib/enoki-probe}"
LOG_LEVEL="${ENOKI_LOG_LEVEL:-info}"
TEST_ROOT="${ENOKI_TEST_ROOT:-}"
EMBEDDED_PUBLIC_KEY_SHA256="__ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256__"
DEFAULT_SERVICE_USER="enoki-probe"
DEFAULT_SERVICE_GROUP="enoki-probe"

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
    fail "curl is required to download Probe assets."
  curl -fsSL -o "$output" "$url"
}

hub_api_url() {
  local path="$1"
  printf '%s/%s\n' "${ENOKI_HUB_URL%/}" "${path#/}"
}

validate_hub_url() {
  case "$ENOKI_HUB_URL" in
    https://*) return ;;
    http://localhost* | http://127.0.0.1* | http://[::1]*) return ;;
  esac

  if [ -n "$TEST_ROOT" ] && [[ "$ENOKI_HUB_URL" = file://* ]]; then
    return
  fi

  fail "ENOKI_HUB_URL must use https, except localhost development URLs."
}

verify_manifest_signature() {
  local manifest="$1"
  local signature="$2"
  local public_key="$3"

  command -v openssl >/dev/null 2>&1 ||
    fail "openssl is required to verify Probe asset signatures."
  openssl dgst -sha256 -verify "$public_key" -signature "$signature" "$manifest" >/dev/null 2>&1 ||
    fail "Probe asset manifest signature verification failed."
}

verify_public_key_trust() {
  local public_key="$1"
  local expected="${ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256:-$EMBEDDED_PUBLIC_KEY_SHA256}"
  local placeholder="__ENOKI_PROBE_ASSET_PUBLIC_KEY""_SHA256__"
  local actual

  if [ -z "$expected" ] || [ "$expected" = "$placeholder" ]; then
    fail "Probe installer does not include a trusted asset signing key fingerprint."
  fi
  if ! [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
    fail "trusted Probe asset signing key fingerprint is not a valid sha256 value."
  fi

  actual="$(sha256sum "$public_key" | awk '{print $1}')"
  if [ "${actual,,}" != "${expected,,}" ]; then
    fail "Probe asset signing key fingerprint verification failed."
  fi
}

manifest_asset_field() {
  local manifest="$1"
  local target="$2"
  local field="$3"
  local line

  line="$(tr -d '\n' <"$manifest" | grep -o "{[^{}]*\"target\"[[:space:]]*:[[:space:]]*\"$target\"[^{}]*}" | head -n 1 || true)"
  if [ -z "$line" ]; then
    return 1
  fi

  printf '%s\n' "$line" |
    sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" |
    head -n 1
}

verify_checksum() {
  local archive="$1"
  local expected="$2"
  local actual

  if ! [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]]; then
    fail "Probe asset manifest does not contain a valid sha256 value."
  fi

  actual="$(sha256sum "$archive" | awk '{print $1}')"

  if [ "${actual,,}" != "${expected,,}" ]; then
    fail "Probe sha256 verification failed."
  fi
}

validate_upgrader_sudoers_paths() {
  local value

  for value in "$INSTALL_PATH" "$CONFIG_PATH"; do
    if [[ "$value" =~ [[:space:][:cntrl:]] ]]; then
      fail "Probe Upgrader sudoers paths must not contain whitespace or control characters."
    fi
  done
}

sudoers_regex_literal() {
  local value="$1"

  printf '%s\n' "$value" | sed 's/[][(){}.^$*+?|\\]/\\&/g'
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

remove_path() {
  local path="$1"
  local rooted

  rooted="$(rooted_path "$path")"
  rm -rf "$rooted"
}

remove_empty_dir() {
  local path="$1"
  local rooted

  rooted="$(rooted_path "$path")"
  rmdir "$rooted" >/dev/null 2>&1 || true
}

remove_service_account() {
  if [ "$SERVICE_USER" = "$DEFAULT_SERVICE_USER" ] &&
    id -u "$SERVICE_USER" >/dev/null 2>&1; then
    userdel "$SERVICE_USER" >/dev/null 2>&1 || true
  fi

  if [ "$SERVICE_GROUP" = "$DEFAULT_SERVICE_GROUP" ] &&
    getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    groupdel "$SERVICE_GROUP" >/dev/null 2>&1 || true
  fi
}

uninstall_probe() {
  local service_path_rooted
  local config_dir

  ensure_root
  ensure_systemd

  systemctl stop "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
  systemctl disable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true

  service_path_rooted="$(rooted_path "/etc/systemd/system/${SERVICE_NAME}.service")"
  rm -f "$service_path_rooted"

  systemctl daemon-reload
  systemctl reset-failed "${SERVICE_NAME}.service" >/dev/null 2>&1 || true

  remove_path "$INSTALL_PATH"
  remove_path /etc/sudoers.d/enoki-probe-upgrader
  remove_path "$CONFIG_PATH"
  config_dir="$(dirname "$CONFIG_PATH")"
  remove_empty_dir "$config_dir"
  remove_path "$STATE_DIR"
  remove_service_account

  echo "Enoki Probe uninstalled."
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
    printf 'install_path = '
    toml_string "$INSTALL_PATH"
    printf '\n'
    printf 'upgrader_launch = "systemd"\n'
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

write_upgrader_sudoers() {
  local sudoers_dir_rooted
  local sudoers_path_rooted
  local install_path_host
  local config_path_host
  local args_regex

  validate_upgrader_sudoers_paths
  sudoers_dir_rooted="$(rooted_path /etc/sudoers.d)"
  sudoers_path_rooted="$sudoers_dir_rooted/enoki-probe-upgrader"
  install_path_host="$(host_path "$INSTALL_PATH")"
  config_path_host="$(host_path "$CONFIG_PATH")"
  args_regex="^--collect --pipe --wait --unit=$(sudoers_regex_literal "$SERVICE_NAME")-upgrader --property=Type=exec -- $(sudoers_regex_literal "$install_path_host") internal-upgrader --config $(sudoers_regex_literal "$config_path_host")$"
  mkdir -p "$sudoers_dir_rooted"

  cat >"$sudoers_path_rooted" <<EOF
# Managed by Enoki Probe installer.
${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/systemd-run ${args_regex}
EOF
  chmod 0440 "$sudoers_path_rooted"
}

main() {
  local target
  local work_dir
  local archive
  local manifest_file
  local manifest_signature_file
  local public_key_file
  local asset_file
  local asset_sha256
  local archive_url

  if [ "${ENOKI_UNINSTALL:-}" = "1" ]; then
    uninstall_probe
    return
  fi

  require_value "ENOKI_HUB_URL" "${ENOKI_HUB_URL:-}"
  require_value "ENOKI_ENROLLMENT_TOKEN" "${ENOKI_ENROLLMENT_TOKEN:-}"
  validate_hub_url
  ensure_root
  ensure_systemd
  target="$(detect_target)"
  work_dir="$(mktemp -d)"
  archive="$work_dir/enoki-probe.tar.gz"
  manifest_file="$work_dir/manifest.json"
  manifest_signature_file="$work_dir/manifest.json.sig"
  public_key_file="$work_dir/signing-key.pem"
  trap "rm -rf '$work_dir'" EXIT

  download_file "$(hub_api_url /api/probe/assets/manifest.json)" "$manifest_file"
  download_file "$(hub_api_url /api/probe/assets/manifest.json.sig)" "$manifest_signature_file"
  download_file "$(hub_api_url /api/probe/assets/signing-key.pem)" "$public_key_file"
  verify_public_key_trust "$public_key_file"
  verify_manifest_signature "$manifest_file" "$manifest_signature_file" "$public_key_file"

  asset_file="$(manifest_asset_field "$manifest_file" "$target" file || true)"
  asset_sha256="$(manifest_asset_field "$manifest_file" "$target" sha256 || true)"
  if [ -z "$asset_file" ] || [ -z "$asset_sha256" ]; then
    fail "no Probe asset found for $target in signed manifest."
  fi
  case "$asset_file" in
    */* | *..* | -*)
      fail "Probe asset manifest contains an invalid asset filename."
      ;;
  esac

  archive_url="$(hub_api_url "/api/probe/assets/$asset_file")"
  download_file "$archive_url" "$archive"
  verify_checksum "$archive" "$asset_sha256"
  ensure_service_user
  install_binary "$archive" "$work_dir"
  write_bootstrap_config
  write_systemd_service
  write_upgrader_sudoers
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}.service"
  systemctl start "${SERVICE_NAME}.service"

  echo "Enoki Probe installed as ${SERVICE_NAME}.service."
}

main "$@"

#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="enoki-probe"
SERVICE_USER="${ENOKI_SERVICE_USER:-enoki-probe}"
SERVICE_GROUP="${ENOKI_SERVICE_GROUP:-enoki-probe}"
INSTALL_PATH="${ENOKI_INSTALL_PATH:-/usr/local/bin/enoki-probe}"
CONFIG_PATH="${ENOKI_CONFIG_PATH:-/etc/enoki/probe-bootstrap.toml}"
INSTALL_METADATA_PATH="/etc/enoki/probe-install.toml"
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

detect_linux_abi() {
  if command -v getconf >/dev/null 2>&1 &&
    getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
    echo "gnu"
    return
  fi

  if command -v ldd >/dev/null 2>&1 &&
    ldd --version 2>&1 | grep -qi "musl"; then
    echo "musl"
    return
  fi

  if ls /lib/ld-musl-*.so.1 /usr/lib/ld-musl-*.so.1 >/dev/null 2>&1; then
    echo "musl"
    return
  fi

  echo "gnu"
}

detect_target() {
  local arch
  local abi

  if [ "$(uname -s)" != "Linux" ]; then
    fail "only Linux hosts are supported."
  fi

  abi="$(detect_linux_abi)"
  case "$(uname -m)" in
    x86_64 | amd64)
      arch="x86_64"
      ;;
    aarch64 | arm64)
      arch="aarch64"
      ;;
    *)
      fail "unsupported CPU architecture: $(uname -m). Supported: x86_64, aarch64."
      ;;
  esac

  echo "${arch}-unknown-linux-${abi}"
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
  remove_path "$INSTALL_METADATA_PATH"
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
  local install_path_rooted
  local install_dir_rooted
  local entry_names
  local entry_count
  local entry_name
  local entry_type

  entry_names="$(tar -tzf "$archive")" ||
    fail "Probe release archive could not be listed."
  entry_count="$(printf '%s\n' "$entry_names" | sed '/^$/d' | wc -l | tr -d ' ')"
  entry_name="$(printf '%s\n' "$entry_names" | sed '/^$/d' | head -n 1)"
  if [ "$entry_count" != "1" ]; then
    fail "Probe release archive must contain exactly one enoki-probe binary."
  fi
  case "$entry_name" in
    enoki-probe | ./enoki-probe) ;;
    *)
      fail "Probe release archive did not contain an enoki-probe binary."
      ;;
  esac
  entry_type="$(tar -tvzf "$archive" "$entry_name" | head -n 1 | cut -c1)"
  if [ "$entry_type" != "-" ]; then
    fail "Probe release archive did not contain an enoki-probe binary."
  fi

  install_path_rooted="$(rooted_path "$INSTALL_PATH")"
  install_dir_rooted="$(dirname "$install_path_rooted")"
  mkdir -p "$install_dir_rooted"
  tar -xOf "$archive" "$entry_name" >"$install_path_rooted"
  chmod 0755 "$install_path_rooted"
}

write_bootstrap_config() {
  local config_path_rooted
  local state_dir_rooted
  local existing_config_path
  local existing_probe_id
  local existing_probe_private_key_pem
  local existing_probe_secret

  config_path_rooted="$(rooted_path "$CONFIG_PATH")"
  state_dir_rooted="$(rooted_path "$STATE_DIR")"
  existing_config_path="$(mktemp)"
  if [ -f "$config_path_rooted" ]; then
    cp "$config_path_rooted" "$existing_config_path"
  fi
  mkdir -p "$(dirname "$config_path_rooted")" "$state_dir_rooted"

  {
    printf 'hub_url = '
    toml_string "$ENOKI_HUB_URL"
    printf '\n'

    if can_reuse_existing_identity "$existing_config_path"; then
      existing_probe_id="$(toml_string_value "$existing_config_path" probe_id)"
      existing_probe_private_key_pem="$(toml_string_value "$existing_config_path" probe_private_key_pem)"
      existing_probe_secret="$(toml_string_value "$existing_config_path" probe_secret)"
      printf 'probe_id = "%s"\n' "$existing_probe_id"
      printf 'probe_secret = "%s"\n' "$existing_probe_secret"
      printf 'probe_private_key_pem = "%s"\n' "$existing_probe_private_key_pem"
    else
      rm -f "$(rooted_path "${STATE_DIR}/probe-operation-status.toml")"
      printf 'enrollment_token = '
      toml_string "$ENOKI_ENROLLMENT_TOKEN"
      printf '\n'
    fi

    printf 'state_dir = '
    toml_string "$STATE_DIR"
    printf '\n'
    printf 'operation_status_path = '
    toml_string "${STATE_DIR}/probe-operation-status.toml"
    printf '\n'
    printf 'install_path = '
    toml_string "$INSTALL_PATH"
    printf '\n'
    printf 'service_name = '
    toml_string "$SERVICE_NAME"
    printf '\n'
    printf 'service_user = '
    toml_string "$SERVICE_USER"
    printf '\n'
    printf 'sudoers_path = '
    toml_string "/etc/sudoers.d/enoki-probe-upgrader"
    printf '\n'
    printf 'probe_asset_public_key_sha256 = '
    toml_string "${ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256:-$EMBEDDED_PUBLIC_KEY_SHA256}"
    printf '\n'
    printf 'upgrader_launch = "systemd"\n'
    printf 'log_level = '
    toml_string "$LOG_LEVEL"
    printf '\n'

    if can_reuse_existing_identity "$existing_config_path"; then
      write_preserved_optional_string "$existing_config_path" probe_configuration_version
      write_preserved_optional_raw "$existing_config_path" reporting_batch_interval_seconds
      write_preserved_optional_raw "$existing_config_path" metrics_collection_interval_seconds
      write_preserved_optional_raw "$existing_config_path" collect_cpu
      write_preserved_optional_raw "$existing_config_path" collect_memory
      write_preserved_optional_raw "$existing_config_path" collect_disk
      write_preserved_optional_raw "$existing_config_path" collect_network
      write_preserved_optional_raw "$existing_config_path" collect_load
      write_preserved_optional_raw "$existing_config_path" collect_uptime
    fi
  } >"$config_path_rooted"
  rm -f "$existing_config_path"
  chmod 0600 "$config_path_rooted"

  if [ -z "$TEST_ROOT" ]; then
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$state_dir_rooted"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$config_path_rooted"
  fi
}

write_install_metadata() {
  local metadata_path_rooted

  metadata_path_rooted="$(rooted_path "$INSTALL_METADATA_PATH")"
  mkdir -p "$(dirname "$metadata_path_rooted")"

  {
    printf 'install_path = '
    toml_string "$INSTALL_PATH"
    printf '\n'
    printf 'state_dir = '
    toml_string "$STATE_DIR"
    printf '\n'
    printf 'operation_status_path = '
    toml_string "${STATE_DIR}/probe-operation-status.toml"
    printf '\n'
    printf 'service_name = '
    toml_string "$SERVICE_NAME"
    printf '\n'
    printf 'service_user = '
    toml_string "$SERVICE_USER"
    printf '\n'
    printf 'sudoers_path = '
    toml_string "/etc/sudoers.d/enoki-probe-upgrader"
    printf '\n'
    printf 'probe_asset_public_key_sha256 = '
    toml_string "${ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256:-$EMBEDDED_PUBLIC_KEY_SHA256}"
    printf '\n'
  } >"$metadata_path_rooted"
  chmod 0644 "$metadata_path_rooted"
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

toml_string_value() {
  local file="$1"
  local key="$2"

  if [ ! -f "$file" ]; then
    return 1
  fi

  sed -n "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*\"\\(.*\\)\"[[:space:]]*$/\\1/p" "$file" |
    head -n 1
}

toml_raw_value() {
  local file="$1"
  local key="$2"

  if [ ! -f "$file" ]; then
    return 1
  fi

  sed -n "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*\\([^[:space:]].*\\)$/\\1/p" "$file" |
    head -n 1
}

normalized_url() {
  local value="$1"

  printf '%s\n' "${value%/}"
}

can_reuse_existing_identity() {
  local existing_config="$1"
  local existing_hub_url
  local existing_probe_id
  local existing_probe_private_key_pem
  local existing_probe_secret

  existing_hub_url="$(toml_string_value "$existing_config" hub_url || true)"
  existing_probe_id="$(toml_string_value "$existing_config" probe_id || true)"
  existing_probe_private_key_pem="$(toml_string_value "$existing_config" probe_private_key_pem || true)"
  existing_probe_secret="$(toml_string_value "$existing_config" probe_secret || true)"

  if [ -z "$existing_hub_url" ] ||
    [ -z "$existing_probe_id" ] ||
    [ -z "$existing_probe_private_key_pem" ] ||
    [ -z "$existing_probe_secret" ]; then
    return 1
  fi

  [ "$(normalized_url "$existing_hub_url")" = "$(normalized_url "$ENOKI_HUB_URL")" ]
}

write_preserved_optional_string() {
  local existing_config="$1"
  local key="$2"
  local value

  value="$(toml_string_value "$existing_config" "$key" || true)"
  if [ -n "$value" ]; then
    printf '%s = "%s"\n' "$key" "$value"
  fi
}

write_preserved_optional_raw() {
  local existing_config="$1"
  local key="$2"
  local value

  value="$(toml_raw_value "$existing_config" "$key" || true)"
  if [ -n "$value" ]; then
    printf '%s = %s\n' "$key" "$value"
  fi
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

  validate_upgrader_sudoers_paths
  sudoers_dir_rooted="$(rooted_path /etc/sudoers.d)"
  sudoers_path_rooted="$sudoers_dir_rooted/enoki-probe-upgrader"
  install_path_host="$(host_path "$INSTALL_PATH")"
  config_path_host="$(host_path "$CONFIG_PATH")"
  mkdir -p "$sudoers_dir_rooted"

  cat >"$sudoers_path_rooted" <<EOF
# Managed by Enoki Probe installer.
${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit=${SERVICE_NAME}-upgrader --property=Type=exec -- ${install_path_host} internal-upgrader --config ${config_path_host}
${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/systemd-run --collect --pipe --wait --unit=${SERVICE_NAME}-uninstaller --property=Type=exec -- ${install_path_host} internal-uninstaller --config ${config_path_host}
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
  systemctl stop "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
  install_binary "$archive" "$work_dir"
  write_bootstrap_config
  write_install_metadata
  write_systemd_service
  write_upgrader_sudoers
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}.service"
  systemctl restart "${SERVICE_NAME}.service"

  echo "Enoki Probe installed as ${SERVICE_NAME}.service."
}

main "$@"

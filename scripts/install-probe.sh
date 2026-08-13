#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="enoki-probe"
TEST_ROOT="${ENOKI_TEST_ROOT:-}"
EMBEDDED_PUBLIC_KEY_SHA256="__ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256__"

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
  local rest
  local authority

  case "$ENOKI_HUB_URL" in
    https://*) rest="${ENOKI_HUB_URL#https://}" ;;
    http://*) rest="${ENOKI_HUB_URL#http://}" ;;
    file://*)
      if [ -n "$TEST_ROOT" ]; then
        return
      fi
      fail "ENOKI_HUB_URL must be an HTTP or HTTPS Origin."
      ;;
    *) fail "ENOKI_HUB_URL must be an HTTP or HTTPS Origin." ;;
  esac

  authority="${rest%%/*}"
  if [ -z "$authority" ] || [[ "$rest" == *"/"* || "$rest" == *"?"* || "$rest" == *"#"* || "$authority" == *"@"* ]]; then
    fail "ENOKI_HUB_URL must be an HTTP or HTTPS Origin with only scheme, host, and optional port."
  fi
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

stage_candidate_binary() {
  local archive="$1"
  local staged_path="$2"
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
    *) fail "Probe release archive did not contain an enoki-probe binary." ;;
  esac
  entry_type="$(tar -tvzf "$archive" "$entry_name" | head -n 1 | cut -c1)"
  if [ "$entry_type" != "-" ]; then
    fail "Probe release archive did not contain an enoki-probe binary."
  fi

  tar -xOf "$archive" "$entry_name" >"$staged_path"
  chmod 0755 "$staged_path"
}

delegate_to_probe_local_lifecycle() {
  local candidate="$1"
  local lifecycle_output
  local trusted_key

  trusted_key="${ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256:-$EMBEDDED_PUBLIC_KEY_SHA256}"
  export ENOKI_PROBE_ASSET_PUBLIC_KEY_SHA256="$trusted_key"
  if lifecycle_output="$("$candidate" local-install --candidate "$candidate" 2>&1)"; then
    if printf '%s\n' "$lifecycle_output" | grep -qx 'ENOKI_PROBE_LOCAL_LIFECYCLE_COMPLETE'; then
      printf '%s\n' "$lifecycle_output"
      return 0
    fi
  fi

  if [ -n "$lifecycle_output" ]; then
    printf '%s\n' "$lifecycle_output" >&2
  fi
  fail "staged Probe candidate did not complete the typed Probe Local Lifecycle."
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
  local staged_candidate

  require_value "ENOKI_HUB_URL" "${ENOKI_HUB_URL:-}"
  require_value "ENOKI_ENROLLMENT_TOKEN" "${ENOKI_ENROLLMENT_TOKEN:-}"
  validate_hub_url
  target="$(detect_target)"
  work_dir="$(mktemp -d)"
  archive="$work_dir/enoki-probe.tar.gz"
  staged_candidate="$work_dir/enoki-probe-candidate"
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
  stage_candidate_binary "$archive" "$staged_candidate"
  delegate_to_probe_local_lifecycle "$staged_candidate"

  echo "Enoki Probe installed as ${SERVICE_NAME}.service."
}

main "$@"

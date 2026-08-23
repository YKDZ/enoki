#!/usr/bin/env python3
"""由不可变发行记录生成的 Probe 首装配方。"""

import argparse
import fcntl
import hashlib
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

RECIPE_VERSION = "v1"
DISTRIBUTION = "__ENOKI_DISTRIBUTION__"
ROOT_FINGERPRINT = "__ENOKI_ROOT_FINGERPRINT__"
BUNDLE_VERSION = "__ENOKI_BUNDLE_VERSION__"
DELEGATION_DOMAIN = b"enoki/probe-trust-delegation/v1\0"
MANIFEST_DOMAIN = b"enoki/probe-asset-manifest/v1\0"
METADATA_LIMIT = 256 * 1024
ARCHIVE_LIMIT = 512 * 1024 * 1024
DEADLINE_SECONDS = 75
METADATA = (
    "root-key.pem", "trust-delegation.json", "trust-delegation.json.sig",
    "signing-key.pem", "manifest.json", "manifest.json.sig",
)
TARGETS = (
    "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl",
)
EXPECTED_ROLES = {
    "probe": ("enoki-probe", "probe-v4"),
    "bootstrap-acquirer": ("bootstrap/enoki-probe-bootstrap-acquire", "bootstrap-acquirer-v1"),
    "bootstrap-activator": ("bootstrap/enoki-probe-bootstrap-activate", "bootstrap-activator-v1"),
}


def fail(message):
    raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def canonical_key(data, label):
    try:
        canonical = run(["openssl", "pkey", "-pubin", "-pubout"], input=data).stdout
        details = run(["openssl", "pkey", "-pubin", "-text", "-noout"], input=canonical).stdout
    except subprocess.CalledProcessError:
        fail(f"{label} is not a valid public key")
    if b"Public-Key: (4096 bit)" not in details:
        fail(f"{label} is not RSA-4096")
    return canonical


def verify_signature(key, signature, message, label):
    directory = Path(tempfile.mkdtemp(prefix="enoki-recipe-signature-"))
    try:
        (directory / "key").write_bytes(key)
        (directory / "signature").write_bytes(signature)
        (directory / "message").write_bytes(message)
        run(["openssl", "dgst", "-sha256", "-verify", str(directory / "key"),
             "-signature", str(directory / "signature"), str(directory / "message")])
    except subprocess.CalledProcessError:
        fail(f"{label} signature is invalid")
    finally:
        shutil.rmtree(directory)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(origin, name, destination, limit, deadline, expected_size=None):
    for attempt in range(4):
        temporary = destination.with_name(f".{destination.name}.{attempt}")
        temporary.unlink(missing_ok=True)
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail("download deadline expired")
            response = build_opener(ProxyHandler({}), NoRedirect()).open(
                Request(f"{origin}/api/probe/assets/{name}", headers={"Accept-Encoding": "identity"}),
                timeout=min(remaining, 10),
            )
            with response:
                values = response.headers.get_all("Content-Length") or []
                if len(values) != 1 or not values[0].isdecimal():
                    fail(f"{name} has no exact Content-Length")
                declared = int(values[0])
                if declared <= 0 or declared > limit or (expected_size is not None and declared != expected_size):
                    fail(f"{name} violates its download bound")
                count = 0
                sha = hashlib.sha256()
                with temporary.open("xb", buffering=0) as output:
                    while count < declared:
                        chunk = response.read(min(65536, declared - count))
                        if not chunk:
                            raise URLError("truncated response")
                        count += len(chunk)
                        sha.update(chunk)
                        output.write(chunk)
                    if response.read(1):
                        fail(f"{name} exceeds Content-Length")
                os.replace(temporary, destination)
                return sha.hexdigest(), count
        except HTTPError as error:
            temporary.unlink(missing_ok=True)
            if error.code not in {408, 425, 429} and not 500 <= error.code <= 599:
                fail(f"{name} returned HTTP {error.code}")
        except (OSError, URLError, TimeoutError):
            temporary.unlink(missing_ok=True)
        if attempt == 3:
            fail(f"{name} retry budget exhausted")
        maximum = min(8, 2 ** attempt)
        delay = random.uniform(0, maximum)
        if time.monotonic() + delay >= deadline:
            fail(f"{name} retry deadline expired")
        time.sleep(delay)


def exact_json(raw, keys, label):
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        fail(f"{label} is not JSON")
    if not isinstance(value, dict) or set(value) != set(keys):
        fail(f"{label} fields are invalid")
    return value


def target_triple():
    architecture = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(platform.machine())
    if architecture is None:
        fail("unsupported CPU architecture")
    output = subprocess.run(["ldd", "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False).stdout.lower()
    return f"{architecture}-unknown-linux-{'musl' if b'musl' in output else 'gnu'}"


def authenticate_metadata(stage, target):
    root = canonical_key((stage / "root-key.pem").read_bytes(), "Probe Distribution Trust Root")
    if digest(root) != ROOT_FINGERPRINT:
        fail("Probe Distribution Trust Root fingerprint mismatch")
    delegation_raw = (stage / "trust-delegation.json").read_bytes()
    delegation = exact_json(delegation_raw, ("distribution", "generation", "kind", "purpose", "rootKeyId", "schemaVersion", "signingIdentity"), "Probe Trust Delegation")
    identity = delegation.get("signingIdentity")
    if (delegation.get("distribution") != DISTRIBUTION or delegation.get("kind") != "enoki-probe-trust-delegation"
            or delegation.get("purpose") != "probe-asset-signing" or delegation.get("schemaVersion") != 1
            or delegation.get("rootKeyId") != ROOT_FINGERPRINT or not isinstance(delegation.get("generation"), int)
            or isinstance(delegation.get("generation"), bool) or delegation["generation"] < 1
            or not isinstance(identity, dict) or set(identity) != {"algorithm", "keyId", "publicKeyPem"}):
        fail("Probe Trust Delegation is invalid")
    delegated = canonical_key(identity["publicKeyPem"].encode(), "delegated signing key")
    if identity.get("algorithm") != "rsa-sha256" or identity.get("keyId") != digest(delegated):
        fail("Probe Trust Delegation signing identity is invalid")
    verify_signature(root, (stage / "trust-delegation.json.sig").read_bytes(), DELEGATION_DOMAIN + delegation_raw, "Probe Trust Delegation")
    signing = canonical_key((stage / "signing-key.pem").read_bytes(), "Probe Asset Signing Identity")
    if signing != delegated:
        fail("Probe Asset Signing Identity does not match its delegation")
    manifest_raw = (stage / "manifest.json").read_bytes()
    manifest = exact_json(manifest_raw, ("assets", "kind", "signature", "version"), "Probe Asset Set manifest")
    verify_signature(signing, (stage / "manifest.json.sig").read_bytes(), MANIFEST_DOMAIN + manifest_raw, "Probe Asset Set manifest")
    if manifest.get("kind") != "enoki-probe-assets" or manifest.get("version") != BUNDLE_VERSION or not isinstance(manifest.get("assets"), list):
        fail("Probe Asset Set manifest is invalid")
    matches = [asset for asset in manifest["assets"] if isinstance(asset, dict) and asset.get("target") == target]
    if len(matches) != 1:
        fail("Probe Asset Set target is absent or duplicated")
    asset = matches[0]
    expected = {"bundleManifestSha256", "file", "sha256", "size", "target"}
    if (set(asset) != expected or asset.get("file") != f"enoki-probe-{target}.tar.gz"
            or not isinstance(asset.get("size"), int) or isinstance(asset.get("size"), bool)
            or not 0 < asset["size"] <= ARCHIVE_LIMIT
            or any(not re.fullmatch(r"[0-9a-f]{64}", asset.get(field, "")) for field in ("sha256", "bundleManifestSha256"))):
        fail("Probe Asset Set target descriptor is invalid")
    return asset


def verify_bundle_and_extract_acquirer(archive_path, asset):
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            if any(not member.isfile() or member.name.startswith("/") or "\\" in member.name or any(part in {"", ".", ".."} for part in member.name.split("/")) for member in members):
                fail("Probe Asset Bundle contains an unsafe member")
            by_name = {member.name: member for member in members}
            if len(by_name) != len(members) or "bundle-manifest.json" not in by_name:
                fail("Probe Asset Bundle closure is invalid")
            manifest_file = archive.extractfile(by_name["bundle-manifest.json"])
            manifest_raw = manifest_file.read(METADATA_LIMIT + 1) if manifest_file else b""
            if digest(manifest_raw) != asset["bundleManifestSha256"]:
                fail("Probe Asset Bundle manifest digest mismatch")
            manifest = exact_json(manifest_raw, ("bootstrapAssets", "components", "kind", "target", "version"), "Probe Asset Bundle manifest")
            entries = manifest.get("components", []) + manifest.get("bootstrapAssets", [])
            if manifest.get("kind") != "enoki-probe-bundle" or manifest.get("target") != asset["target"] or manifest.get("version") != BUNDLE_VERSION or len(entries) != 3:
                fail("Probe Asset Bundle manifest is incoherent")
            expected_paths = {"bundle-manifest.json"}
            acquirer = None
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {"path", "permissionProfile", "role", "sha256", "size", "version"}:
                    fail("Probe Asset Bundle role is invalid")
                expected = EXPECTED_ROLES.get(entry.get("role"))
                if expected != (entry.get("path"), entry.get("permissionProfile")) or entry.get("version") != BUNDLE_VERSION or entry.get("path") not in by_name:
                    fail("Probe Asset Bundle role is incoherent")
                member = by_name[entry["path"]]
                stream = archive.extractfile(member)
                data = stream.read(entry["size"] + 1) if stream else b""
                if len(data) != entry.get("size") or member.size != entry.get("size") or digest(data) != entry.get("sha256"):
                    fail("Probe Asset Bundle role receipt mismatch")
                expected_paths.add(entry["path"])
                if entry["role"] == "bootstrap-acquirer":
                    acquirer = data
            if set(by_name) != expected_paths or acquirer is None:
                fail("Probe Asset Bundle has an unexpected or missing role")
            return acquirer
    except (tarfile.TarError, EOFError) as error:
        fail(f"Probe Asset Bundle is invalid: {error}")


def execute_verified_acquirer(acquirer, environment, input_stream):
    descriptor = os.memfd_create(
        "enoki-probe-bootstrap-acquire",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        with os.fdopen(os.dup(descriptor), "wb", closefd=True) as output:
            output.write(acquirer)
            output.flush()
            os.fsync(output.fileno())
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != seals:
            fail("verified Probe acquirer descriptor could not be sealed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        receipt = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            receipt.update(chunk)
            total += len(chunk)
        if total != len(acquirer) or receipt.hexdigest() != digest(acquirer):
            fail("verified Probe acquirer descriptor changed before execution")
        result = subprocess.run(
            [f"/proc/self/fd/{descriptor}"],
            env=environment,
            stdin=input_stream,
            check=False,
            close_fds=True,
            pass_fds=(descriptor,),
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        after = hashlib.sha256()
        after_size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            after.update(chunk)
            after_size += len(chunk)
        if after_size != total or after.hexdigest() != receipt.hexdigest():
            fail("verified Probe acquirer descriptor changed during execution")
        return result.returncode
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description="Enoki Probe immutable bootstrap recipe")
    parser.add_argument("--hub-origin", required=True)
    arguments = parser.parse_args()
    parsed = urlparse(arguments.hub_origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
        fail("Hub origin is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", ROOT_FINGERPRINT) or not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", BUNDLE_VERSION):
        fail("immutable recipe record is incomplete")
    stage = Path(tempfile.mkdtemp(prefix="enoki-probe-bootstrap-"))
    os.chmod(stage, 0o700)
    try:
        origin = arguments.hub_origin.rstrip("/")
        deadline = time.monotonic() + DEADLINE_SECONDS
        for name in METADATA:
            fetch(origin, name, stage / name, METADATA_LIMIT, deadline)
        target = target_triple()
        if target not in TARGETS:
            fail("unsupported target")
        asset = authenticate_metadata(stage, target)
        archive_path = stage / asset["file"]
        archive_digest, archive_size = fetch(origin, asset["file"], archive_path, asset["size"], deadline, asset["size"])
        if archive_digest != asset["sha256"] or archive_size != asset["size"]:
            fail("Probe Asset Bundle receipt mismatch")
        acquirer = verify_bundle_and_extract_acquirer(archive_path, asset)
        environment = {"ENOKI_HUB_URL": origin, "ENOKI_PROBE_LOCAL_ASSET_DIR": str(stage), "ENOKI_PROBE_LOCAL_BUNDLE_ARCHIVE": str(archive_path)}
        if execute_verified_acquirer(acquirer, environment, sys.stdin) != 0:
            fail("verified Probe acquirer failed")
    finally:
        shutil.rmtree(stage)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        sys.stderr.write(f"enoki-probe-bootstrap: {error}\n")
        sys.exit(1)

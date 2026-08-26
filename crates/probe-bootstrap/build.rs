use std::{env, fs, path::PathBuf};

use rsa::{
    RsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding},
};
use sha2::{Digest, Sha256};

const SUPPORTED_TARGETS: &[&str] = &[
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
];

fn main() {
    let output =
        PathBuf::from(env::var("OUT_DIR").expect("Cargo supplies OUT_DIR")).join("build_trust.rs");
    if env::var_os("CARGO_FEATURE_COMPILED_TRUST").is_none() {
        fs::write(
            output,
            "const GENERATED_PRODUCTION_TRUST: Option<BuildTrust> = None;\n\
             const GENERATED_BUILD_IDENTITY_BYTES: [u8; 0] = [];\n",
        )
        .expect("write non-production build trust");
        return;
    }
    // `#[used]` retains the Rust static through compilation, but a release
    // linker may still garbage-collect an otherwise unreferenced custom
    // section. Keep this deliberately named public build attestation in the
    // executable so release inspection sees the exact bytes build.rs created.
    for role in [
        "enoki-probe-bootstrap-acquire",
        "enoki-probe-bootstrap-activate",
    ] {
        println!("cargo:rustc-link-arg-bin={role}=-Wl,--undefined=enoki_bootstrap_build_identity");
    }

    for variable in [
        "ENOKI_BOOTSTRAP_BUILD_DISTRIBUTION",
        "ENOKI_BOOTSTRAP_BUILD_ROOT_PEM",
        "ENOKI_BOOTSTRAP_BUILD_ROLE",
        "ENOKI_BOOTSTRAP_BUILD_TARGET",
        "ENOKI_BOOTSTRAP_BUILD_VERSION",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    let distribution = required("ENOKI_BOOTSTRAP_BUILD_DISTRIBUTION");
    if !is_distribution(&distribution) {
        panic!("ENOKI_BOOTSTRAP_BUILD_DISTRIBUTION must be a safe distribution identifier");
    }
    let target = required("ENOKI_BOOTSTRAP_BUILD_TARGET");
    let cargo_target = required("TARGET");
    if target != cargo_target || !SUPPORTED_TARGETS.contains(&target.as_str()) {
        panic!("ENOKI_BOOTSTRAP_BUILD_TARGET must exactly match one supported Cargo TARGET");
    }
    let version = required("ENOKI_BOOTSTRAP_BUILD_VERSION");
    if !is_stable_semver(&version) {
        panic!("ENOKI_BOOTSTRAP_BUILD_VERSION must be a stable SemVer tag");
    }
    let role = required("ENOKI_BOOTSTRAP_BUILD_ROLE");
    let role_variant = match role.as_str() {
        "acquirer"
            if feature_enabled("CARGO_FEATURE_ACQUIRER")
                && !feature_enabled("CARGO_FEATURE_ACTIVATOR") =>
        {
            "BootstrapRole::Acquirer"
        }
        "activator"
            if feature_enabled("CARGO_FEATURE_ACTIVATOR")
                && !feature_enabled("CARGO_FEATURE_ACQUIRER") =>
        {
            "BootstrapRole::Activator"
        }
        _ => panic!(
            "ENOKI_BOOTSTRAP_BUILD_ROLE must exactly match one compiled Bootstrap role feature"
        ),
    };

    let root = RsaPublicKey::from_public_key_pem(&required("ENOKI_BOOTSTRAP_BUILD_ROOT_PEM"))
        .unwrap_or_else(|_| panic!("ENOKI_BOOTSTRAP_BUILD_ROOT_PEM must be an RSA SPKI PEM"));
    let canonical_root = root
        .to_public_key_pem(LineEnding::LF)
        .expect("RSA SPKI PEM encoding");
    let root_key_id = sha256_hex(canonical_root.as_bytes());
    let identity = format!(
        "{{\"distribution\":\"{distribution}\",\"rootFingerprint\":\"{root_key_id}\",\"rootKeyId\":\"{root_key_id}\",\"target\":\"{target}\",\"version\":\"{version}\",\"role\":\"{role}\"}}"
    );
    let mut embedded = b"ENOKI_BOOTSTRAP_BUILD_IDENTITY_V1\0".to_vec();
    embedded.extend_from_slice(
        &u32::try_from(identity.len())
            .expect("bounded bootstrap build identity")
            .to_be_bytes(),
    );
    embedded.extend_from_slice(identity.as_bytes());

    fs::write(
        output,
        format!(
            "const GENERATED_PRODUCTION_TRUST: Option<BuildTrust> = Some(BuildTrust {{ distribution: {distribution:?}, role: {role_variant}, root_pem: {canonical_root:?}, root_fingerprint: {root_key_id:?}, root_key_id: {root_key_id:?}, target: {target:?}, version: {version:?} }});\nconst GENERATED_BUILD_IDENTITY_BYTES: [u8; {}] = {embedded:?};\n",
            embedded.len(),
        ),
    )
    .expect("write production build trust");
}

fn required(variable: &str) -> String {
    env::var(variable).unwrap_or_else(|_| panic!("{variable} is required for compiled-trust"))
}

fn feature_enabled(variable: &str) -> bool {
    env::var_os(variable).is_some()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_distribution(value: &str) -> bool {
    let mut characters = value.bytes();
    matches!(characters.next(), Some(b'a'..=b'z'))
        && value.len() <= 64
        && characters.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_stable_semver(value: &str) -> bool {
    let Some(numbers) = value.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<_> = numbers.split('.').collect();
    parts.len() == 3
        && parts.into_iter().all(|part| {
            !part.is_empty()
                && (part == "0"
                    || (!part.starts_with('0') && part.bytes().all(|byte| byte.is_ascii_digit())))
        })
}

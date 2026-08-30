use prost::Message;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey},
    signature::Verifier,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ReplacementRegistrationBinding;

const MAX_CAPSULE_BYTES: usize = 96 * 1024;

#[allow(dead_code)]
mod protocol {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packages/proto/src/generated/rust/enoki.v1.rs"
    ));
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplacementRegistrationAttemptCapsule {
    candidate_private_key_pem: String,
    enrollment_token_sha256: String,
    hub_origin: String,
    local_clock_reference_ms: u64,
    request_hex: String,
    schema_version: u8,
    signed_attempt_sha256: String,
}

/// A cryptographically self-contained projection of one root-private
/// replacement registration capsule. It is evidence about the signed attempt,
/// not authority for the Probe identity later assigned by the Hub.
pub(crate) struct ReplacementRegistrationAttemptProof {
    binding: ReplacementRegistrationBinding,
    candidate_private_key_pem: String,
    signed_attempt_sha256: String,
}

/// Opaque fail-closed result for malformed or internally inconsistent
/// registration attempt custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplacementRegistrationAttemptError;

impl ReplacementRegistrationAttemptProof {
    #[must_use]
    pub(crate) fn binding(&self) -> &ReplacementRegistrationBinding {
        &self.binding
    }

    #[must_use]
    pub(crate) fn candidate_private_key_pem(&self) -> &str {
        &self.candidate_private_key_pem
    }

    #[must_use]
    pub(crate) fn signed_attempt_sha256(&self) -> &str {
        &self.signed_attempt_sha256
    }
}

/// Fully proves a capsule from its own stored bytes. Any malformed envelope,
/// token binding, protobuf binding, candidate key or signature fails closed.
pub fn validate_replacement_registration_attempt_capsule(
    bytes: &[u8],
) -> Result<ReplacementRegistrationBinding, ReplacementRegistrationAttemptError> {
    prove_replacement_registration_attempt_capsule(bytes).map(|proof| proof.binding)
}

pub(crate) fn prove_replacement_registration_attempt_capsule(
    bytes: &[u8],
) -> Result<ReplacementRegistrationAttemptProof, ReplacementRegistrationAttemptError> {
    validate_capsule(bytes).map_err(|()| ReplacementRegistrationAttemptError)
}

fn validate_capsule(bytes: &[u8]) -> Result<ReplacementRegistrationAttemptProof, ()> {
    if bytes.len() > MAX_CAPSULE_BYTES {
        return Err(());
    }
    let capsule: ReplacementRegistrationAttemptCapsule =
        serde_json::from_slice(bytes).map_err(|_| ())?;
    if capsule.schema_version != 1
        || capsule.local_clock_reference_ms == 0
        || !valid_sha256(&capsule.enrollment_token_sha256)
        || !valid_sha256(&capsule.signed_attempt_sha256)
    {
        return Err(());
    }
    let request_body = decode_lower_hex(&capsule.request_hex).ok_or(())?;
    let request =
        protocol::ProbeRegistrationRequest::decode(request_body.as_slice()).map_err(|_| ())?;
    let attempt = protocol::ProbeRegistrationAttempt::decode(request.canonical_attempt.as_slice())
        .map_err(|_| ())?;
    if attempt.encode_to_vec() != request.canonical_attempt
        || capsule.enrollment_token_sha256 != sha256_hex(request.enrollment_token.as_bytes())
        || capsule.hub_origin != attempt.hub_origin
        || request.installation_inspection.is_some()
        || request.installation_rejection.is_some()
        || !request.snapshots.is_empty()
    {
        return Err(());
    }
    let binding = binding_from_valid_attempt(&attempt)?;

    let private_key =
        RsaPrivateKey::from_pkcs8_pem(&capsule.candidate_private_key_pem).map_err(|_| ())?;
    let public_key = RsaPublicKey::from(&private_key)
        .to_public_key_pem(Default::default())
        .map_err(|_| ())?;
    if public_key != request.probe_public_key_pem
        || public_key != attempt.candidate_public_key_pem
        || capsule.signed_attempt_sha256
            != signed_attempt_sha256(&request.canonical_attempt, &request.candidate_signature)
    {
        return Err(());
    }
    let signature =
        RsaPkcs1v15Signature::try_from(request.candidate_signature.as_slice()).map_err(|_| ())?;
    VerifyingKey::<Sha256>::new(RsaPublicKey::from_public_key_pem(&public_key).map_err(|_| ())?)
        .verify(
            registration_attempt_signature_payload(&request.canonical_attempt).as_bytes(),
            &signature,
        )
        .map_err(|_| ())?;

    Ok(ReplacementRegistrationAttemptProof {
        binding,
        candidate_private_key_pem: capsule.candidate_private_key_pem,
        signed_attempt_sha256: capsule.signed_attempt_sha256,
    })
}

#[cfg(test)]
pub(crate) fn signed_replacement_registration_attempt_capsule_for_test(
    binding: &ReplacementRegistrationBinding,
    enrollment_token: &str,
) -> Vec<u8> {
    use rsa::{
        pkcs1v15::SigningKey,
        pkcs8::EncodePrivateKey,
        rand_core::OsRng,
        signature::{RandomizedSigner, SignatureEncoding},
    };

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("test replacement key");
    let private_pem = private_key
        .to_pkcs8_pem(Default::default())
        .expect("test private pem")
        .to_string();
    let public_pem = RsaPublicKey::from(&private_key)
        .to_public_key_pem(Default::default())
        .expect("test public pem");
    let attempt = protocol::ProbeRegistrationAttempt {
        candidate_public_key_pem: public_pem.clone(),
        committed_source_probe_sha256: binding.committed_source_probe_sha256.clone(),
        enrollment_id: binding.enrollment_id.clone(),
        host_id: binding.host_id.clone(),
        hub_origin: binding.hub_origin.clone(),
        nonce: "a".repeat(64),
        old_probe_id: binding.old_probe_id.clone(),
        replacement_commit_sha256: binding.replacement_commit_sha256.clone(),
        schema_version: 1,
        source_probe_version: binding.source_probe_version.clone(),
        target_asset_set_digest: binding.target_asset_set_digest.clone(),
        target_bundle_target: binding.target_bundle_target.clone(),
        target_manifest_sha256: binding.target_manifest_sha256.clone(),
        target_probe_version: binding.target_probe_version.clone(),
    };
    let canonical_attempt = attempt.encode_to_vec();
    let signature = SigningKey::<Sha256>::new(private_key)
        .sign_with_rng(
            &mut OsRng,
            registration_attempt_signature_payload(&canonical_attempt).as_bytes(),
        )
        .to_bytes()
        .to_vec();
    let request = protocol::ProbeRegistrationRequest {
        candidate_signature: signature.clone(),
        canonical_attempt: canonical_attempt.clone(),
        enrollment_token: enrollment_token.to_owned(),
        installation_inspection: None,
        installation_rejection: None,
        probe_public_key_pem: public_pem,
        snapshots: Vec::new(),
    };
    serde_json::to_vec(&ReplacementRegistrationAttemptCapsule {
        candidate_private_key_pem: private_pem,
        enrollment_token_sha256: sha256_hex(enrollment_token.as_bytes()),
        hub_origin: binding.hub_origin.clone(),
        local_clock_reference_ms: 1_725_000_000_000,
        request_hex: encode_lower_hex(&request.encode_to_vec()),
        schema_version: 1,
        signed_attempt_sha256: signed_attempt_sha256(&canonical_attempt, &signature),
    })
    .expect("serialize test replacement capsule")
}

#[cfg(test)]
pub(crate) fn mutate_signed_replacement_capsule_for_test(bytes: &[u8], mutation: &str) -> Vec<u8> {
    use rsa::{
        pkcs1v15::SigningKey,
        rand_core::OsRng,
        signature::{RandomizedSigner, SignatureEncoding},
    };

    let mut capsule: ReplacementRegistrationAttemptCapsule =
        serde_json::from_slice(bytes).expect("test capsule");
    match mutation {
        "token-hash" => flip_first_hex(&mut capsule.enrollment_token_sha256),
        "key" => capsule.candidate_private_key_pem = "not a private key".to_owned(),
        "signed-digest" => flip_first_hex(&mut capsule.signed_attempt_sha256),
        "raw-token" | "signature" | "binding" => {
            let mut request = protocol::ProbeRegistrationRequest::decode(
                decode_lower_hex(&capsule.request_hex)
                    .expect("test request hex")
                    .as_slice(),
            )
            .expect("test request");
            match mutation {
                "raw-token" => request.enrollment_token.push_str("_tampered"),
                "signature" => request.candidate_signature[0] ^= 1,
                "binding" => {
                    let mut attempt = protocol::ProbeRegistrationAttempt::decode(
                        request.canonical_attempt.as_slice(),
                    )
                    .expect("test attempt");
                    attempt.target_manifest_sha256 = "e".repeat(64);
                    request.canonical_attempt = attempt.encode_to_vec();
                    let private_key =
                        RsaPrivateKey::from_pkcs8_pem(&capsule.candidate_private_key_pem)
                            .expect("test private key");
                    request.candidate_signature = SigningKey::<Sha256>::new(private_key)
                        .sign_with_rng(
                            &mut OsRng,
                            registration_attempt_signature_payload(&request.canonical_attempt)
                                .as_bytes(),
                        )
                        .to_bytes()
                        .to_vec();
                    capsule.signed_attempt_sha256 = signed_attempt_sha256(
                        &request.canonical_attempt,
                        &request.candidate_signature,
                    );
                }
                _ => unreachable!(),
            }
            capsule.request_hex = encode_lower_hex(&request.encode_to_vec());
        }
        _ => panic!("unknown test mutation {mutation}"),
    }
    serde_json::to_vec(&capsule).expect("serialize mutated test capsule")
}

#[cfg(test)]
fn flip_first_hex(value: &mut String) {
    let replacement = if value.starts_with('f') { "e" } else { "f" };
    value.replace_range(..1, replacement);
}

fn binding_from_valid_attempt(
    attempt: &protocol::ProbeRegistrationAttempt,
) -> Result<ReplacementRegistrationBinding, ()> {
    let binding = ReplacementRegistrationBinding {
        committed_source_probe_sha256: attempt.committed_source_probe_sha256.clone(),
        enrollment_id: attempt.enrollment_id.clone(),
        host_id: attempt.host_id.clone(),
        hub_origin: attempt.hub_origin.clone(),
        old_probe_id: attempt.old_probe_id.clone(),
        replacement_commit_sha256: attempt.replacement_commit_sha256.clone(),
        source_probe_version: attempt.source_probe_version.clone(),
        target_asset_set_digest: attempt.target_asset_set_digest.clone(),
        target_bundle_target: attempt.target_bundle_target.clone(),
        target_manifest_sha256: attempt.target_manifest_sha256.clone(),
        target_probe_version: attempt.target_probe_version.clone(),
    };
    if attempt.schema_version != 1
        || !valid_enrollment_id(&binding.enrollment_id)
        || binding.host_id.parse::<u64>().ok().is_none_or(|id| id == 0)
        || !bounded_identifier(&binding.old_probe_id)
        || !valid_semver(&binding.source_probe_version)
        || !valid_semver(&binding.target_probe_version)
        || !valid_sha256(&binding.committed_source_probe_sha256)
        || !valid_sha256(&binding.replacement_commit_sha256)
        || !valid_sha256(&binding.target_manifest_sha256)
        || !binding
            .target_asset_set_digest
            .strip_prefix("sha256:")
            .is_some_and(valid_sha256)
        || !matches!(
            binding.target_bundle_target.as_str(),
            "aarch64-unknown-linux-gnu"
                | "aarch64-unknown-linux-musl"
                | "x86_64-unknown-linux-gnu"
                | "x86_64-unknown-linux-musl"
        )
        || attempt.enrollment_id != binding.enrollment_id
        || attempt.host_id != binding.host_id
        || attempt.hub_origin != binding.hub_origin
        || attempt.old_probe_id != binding.old_probe_id
        || attempt.source_probe_version != binding.source_probe_version
        || attempt.committed_source_probe_sha256 != binding.committed_source_probe_sha256
        || attempt.target_probe_version != binding.target_probe_version
        || attempt.target_bundle_target != binding.target_bundle_target
        || attempt.target_asset_set_digest != binding.target_asset_set_digest
        || attempt.target_manifest_sha256 != binding.target_manifest_sha256
        || attempt.replacement_commit_sha256 != binding.replacement_commit_sha256
        || attempt.nonce.len() != 64
        || !attempt
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(());
    }
    Ok(binding)
}

fn valid_enrollment_id(value: &str) -> bool {
    value.strip_prefix("enr_").is_some_and(|suffix| {
        suffix.len() >= 16
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

fn bounded_identifier(value: &str) -> bool {
    (1..=160).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_semver(value: &str) -> bool {
    let value = value.strip_prefix('v').unwrap_or(value);
    let mut parts = value.split('.');
    parts.clone().count() == 3
        && parts.all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'))
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn registration_attempt_signature_payload(canonical_attempt: &[u8]) -> String {
    format!(
        "enoki.probe-registration-attempt.v1\n{}",
        sha256_hex(canonical_attempt)
    )
}

fn signed_attempt_sha256(canonical_attempt: &[u8], signature: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"enoki.probe-registration-attempt.signed.v1\n");
    digest.update(canonical_attempt);
    digest.update(signature);
    format!("{:x}", digest.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn decode_lower_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

#[cfg(test)]
fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
}

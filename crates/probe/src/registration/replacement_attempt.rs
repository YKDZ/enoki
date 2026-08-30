use enoki_probe_bootstrap::replacement::ReplacementRegistrationBinding as BootstrapReplacementRegistrationBinding;
use prost::Message;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature as RsaPkcs1v15Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    rand_core::{OsRng, RngCore},
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::{
    hub_url,
    protocol::enoki::v1::{ProbeRegistrationAttempt, ProbeRegistrationRequest},
    secure_file::{
        atomic_write, ensure_directory, read_private_regular_file,
        read_registration_attempt_credential_bytes,
    },
};

use super::{
    ProbeRegistrationInput, RegistrationError, bounded_identifier, push_optional_string,
    string_value, valid_enrollment_id, valid_semver, valid_sha256,
};

const MAX_REGISTRATION_ATTEMPT_CAPSULE_BYTES: usize = 96 * 1024;
const ROOT_CAPSULE_OWNER: (u32, u32) = (0, 0);

pub(super) struct PreparedProbeRegistration {
    pub(super) private_key_pem: String,
    pub(super) request_body: Vec<u8>,
    pub(super) server_time_reference_ms: Option<i128>,
    pub(super) signed_attempt_sha256: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RootReplacementRegistrationAttemptInput {
    pub enrollment_token: String,
    pub binding: BootstrapReplacementRegistrationBinding,
}

#[derive(Default)]
pub(super) struct InstalledRegistrationAttempt {
    committed_source_probe_sha256: Option<String>,
    enrollment_id: Option<String>,
    host_id: Option<String>,
    hub_origin: Option<String>,
    old_probe_id: Option<String>,
    credential_path: Option<String>,
    replacement_commit_sha256: Option<String>,
    signed_attempt_sha256: Option<String>,
    source_probe_version: Option<String>,
    target_asset_set_digest: Option<String>,
    target_bundle_target: Option<String>,
    target_manifest_sha256: Option<String>,
    target_probe_version: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeRegistrationAttemptCapsule {
    schema_version: u8,
    enrollment_token_sha256: String,
    hub_origin: String,
    candidate_private_key_pem: String,
    local_clock_reference_ms: u64,
    request_hex: String,
    signed_attempt_sha256: String,
}

#[derive(Clone, Debug)]
struct ReplacementRegistrationBinding {
    committed_source_probe_sha256: String,
    enrollment_id: String,
    host_id: String,
    hub_origin: String,
    old_probe_id: String,
    replacement_commit_sha256: String,
    source_probe_version: String,
    target_asset_set_digest: String,
    target_bundle_target: String,
    target_manifest_sha256: String,
    target_probe_version: String,
}

struct GeneratedProbeSigningKey {
    private_key_pem: String,
    public_key_pem: String,
}

impl InstalledRegistrationAttempt {
    pub(super) fn read(value: &toml::Value) -> Result<Self, RegistrationError> {
        Ok(Self {
            committed_source_probe_sha256: string_value(
                value,
                "registration_committed_source_probe_sha256",
            )?,
            enrollment_id: string_value(value, "registration_enrollment_id")?,
            host_id: string_value(value, "registration_host_id")?,
            hub_origin: string_value(value, "registration_hub_origin")?,
            old_probe_id: string_value(value, "registration_old_probe_id")?,
            credential_path: string_value(value, "registration_attempt_credential_path")?,
            replacement_commit_sha256: string_value(
                value,
                "registration_replacement_commit_sha256",
            )?,
            signed_attempt_sha256: string_value(value, "registration_signed_attempt_sha256")?,
            source_probe_version: string_value(value, "registration_source_probe_version")?,
            target_asset_set_digest: string_value(value, "registration_target_asset_set_digest")?,
            target_bundle_target: string_value(value, "registration_target_bundle_target")?,
            target_manifest_sha256: string_value(value, "registration_target_manifest_sha256")?,
            target_probe_version: string_value(value, "registration_target_probe_version")?,
        })
    }

    pub(super) fn prepare(
        &self,
        input: &ProbeRegistrationInput,
    ) -> Result<PreparedProbeRegistration, RegistrationError> {
        let Some(binding) = self.binding()? else {
            let signing_key = generate_probe_signing_key()?;
            return Ok(PreparedProbeRegistration {
                private_key_pem: signing_key.private_key_pem,
                request_body: registration_request(
                    input.enrollment_token.clone(),
                    signing_key.public_key_pem,
                )
                .encode_to_vec(),
                server_time_reference_ms: None,
                signed_attempt_sha256: None,
            });
        };
        if hub_url::normalized_base(&binding.hub_origin).ok()
            != hub_url::normalized_base(&input.hub_url).ok()
        {
            return Err(RegistrationError::InvalidResponse(
                "replacement registration Hub mismatch",
            ));
        }
        let capsule_path =
            self.credential_path
                .as_deref()
                .ok_or(RegistrationError::InvalidResponse(
                    "missing replacement registration credential path",
                ))?;
        match read_registration_attempt_credential(Path::new(capsule_path)) {
            Ok(Some(capsule)) => {
                validate_registration_attempt_capsule(&capsule, input, &binding)?;
                Ok(PreparedProbeRegistration {
                    private_key_pem: capsule.candidate_private_key_pem,
                    request_body: decode_lower_hex(&capsule.request_hex).ok_or(
                        RegistrationError::InvalidResponse("invalid registration attempt capsule"),
                    )?,
                    server_time_reference_ms: Some(i128::from(capsule.local_clock_reference_ms)),
                    signed_attempt_sha256: Some(capsule.signed_attempt_sha256),
                })
            }
            Ok(None) => Err(RegistrationError::InvalidResponse(
                "missing replacement registration credential",
            )),
            Err(error) => Err(RegistrationError::Io(error)),
        }
    }

    pub(super) fn remember_signed_digest(&mut self, digest: Option<String>) {
        self.signed_attempt_sha256 = digest;
    }

    pub(super) fn render(&self, output: &mut String) {
        push_optional_string(
            output,
            "registration_attempt_credential_path",
            self.credential_path.as_deref(),
        );
        for (key, value) in [
            (
                "registration_committed_source_probe_sha256",
                self.committed_source_probe_sha256.as_deref(),
            ),
            ("registration_enrollment_id", self.enrollment_id.as_deref()),
            ("registration_host_id", self.host_id.as_deref()),
            ("registration_hub_origin", self.hub_origin.as_deref()),
            ("registration_old_probe_id", self.old_probe_id.as_deref()),
            (
                "registration_replacement_commit_sha256",
                self.replacement_commit_sha256.as_deref(),
            ),
            (
                "registration_source_probe_version",
                self.source_probe_version.as_deref(),
            ),
            (
                "registration_signed_attempt_sha256",
                self.signed_attempt_sha256.as_deref(),
            ),
            (
                "registration_target_asset_set_digest",
                self.target_asset_set_digest.as_deref(),
            ),
            (
                "registration_target_bundle_target",
                self.target_bundle_target.as_deref(),
            ),
            (
                "registration_target_manifest_sha256",
                self.target_manifest_sha256.as_deref(),
            ),
            (
                "registration_target_probe_version",
                self.target_probe_version.as_deref(),
            ),
        ] {
            push_optional_string(output, key, value);
        }
    }

    fn binding(&self) -> Result<Option<ReplacementRegistrationBinding>, RegistrationError> {
        let fields = [
            self.committed_source_probe_sha256.as_ref(),
            self.enrollment_id.as_ref(),
            self.host_id.as_ref(),
            self.hub_origin.as_ref(),
            self.old_probe_id.as_ref(),
            self.replacement_commit_sha256.as_ref(),
            self.source_probe_version.as_ref(),
            self.target_asset_set_digest.as_ref(),
            self.target_bundle_target.as_ref(),
            self.target_manifest_sha256.as_ref(),
            self.target_probe_version.as_ref(),
        ];
        if fields.iter().all(|field| field.is_none()) {
            return Ok(None);
        }
        if fields.iter().any(|field| field.is_none()) {
            return Err(RegistrationError::InvalidResponse(
                "incomplete replacement registration binding",
            ));
        }
        let binding = ReplacementRegistrationBinding {
            committed_source_probe_sha256: self
                .committed_source_probe_sha256
                .clone()
                .unwrap_or_default(),
            enrollment_id: self.enrollment_id.clone().unwrap_or_default(),
            host_id: self.host_id.clone().unwrap_or_default(),
            hub_origin: self.hub_origin.clone().unwrap_or_default(),
            old_probe_id: self.old_probe_id.clone().unwrap_or_default(),
            replacement_commit_sha256: self.replacement_commit_sha256.clone().unwrap_or_default(),
            source_probe_version: self.source_probe_version.clone().unwrap_or_default(),
            target_asset_set_digest: self.target_asset_set_digest.clone().unwrap_or_default(),
            target_bundle_target: self.target_bundle_target.clone().unwrap_or_default(),
            target_manifest_sha256: self.target_manifest_sha256.clone().unwrap_or_default(),
            target_probe_version: self.target_probe_version.clone().unwrap_or_default(),
        };
        if !valid_enrollment_id(&binding.enrollment_id)
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
        {
            return Err(RegistrationError::InvalidResponse(
                "invalid replacement registration binding",
            ));
        }
        Ok(Some(binding))
    }
}

impl From<BootstrapReplacementRegistrationBinding> for ReplacementRegistrationBinding {
    fn from(binding: BootstrapReplacementRegistrationBinding) -> Self {
        Self {
            committed_source_probe_sha256: binding.committed_source_probe_sha256,
            enrollment_id: binding.enrollment_id,
            host_id: binding.host_id,
            hub_origin: binding.hub_origin,
            old_probe_id: binding.old_probe_id,
            replacement_commit_sha256: binding.replacement_commit_sha256,
            source_probe_version: binding.source_probe_version,
            target_asset_set_digest: binding.target_asset_set_digest,
            target_bundle_target: binding.target_bundle_target,
            target_manifest_sha256: binding.target_manifest_sha256,
            target_probe_version: binding.target_probe_version,
        }
    }
}

impl ReplacementRegistrationBinding {
    fn to_proto(
        &self,
        nonce: String,
        candidate_public_key_pem: String,
    ) -> ProbeRegistrationAttempt {
        ProbeRegistrationAttempt {
            candidate_public_key_pem,
            committed_source_probe_sha256: self.committed_source_probe_sha256.clone(),
            enrollment_id: self.enrollment_id.clone(),
            host_id: self.host_id.clone(),
            hub_origin: self.hub_origin.clone(),
            nonce,
            old_probe_id: self.old_probe_id.clone(),
            replacement_commit_sha256: self.replacement_commit_sha256.clone(),
            schema_version: 1,
            source_probe_version: self.source_probe_version.clone(),
            target_asset_set_digest: self.target_asset_set_digest.clone(),
            target_bundle_target: self.target_bundle_target.clone(),
            target_manifest_sha256: self.target_manifest_sha256.clone(),
            target_probe_version: self.target_probe_version.clone(),
        }
    }

    fn matches_proto(&self, attempt: &ProbeRegistrationAttempt) -> bool {
        attempt.schema_version == 1
            && attempt.enrollment_id == self.enrollment_id
            && attempt.host_id == self.host_id
            && attempt.hub_origin == self.hub_origin
            && attempt.old_probe_id == self.old_probe_id
            && attempt.source_probe_version == self.source_probe_version
            && attempt.committed_source_probe_sha256 == self.committed_source_probe_sha256
            && attempt.target_probe_version == self.target_probe_version
            && attempt.target_bundle_target == self.target_bundle_target
            && attempt.target_asset_set_digest == self.target_asset_set_digest
            && attempt.target_manifest_sha256 == self.target_manifest_sha256
            && attempt.replacement_commit_sha256 == self.replacement_commit_sha256
            && attempt.nonce.len() == 64
            && attempt
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
}

/// 具备 root 生命周期权限的主体会在允许 Replacement Probe 发出首次网络请求前，
/// 持久发布精确的已签名注册尝试。
pub fn prepare_root_replacement_registration_attempt(
    path: &Path,
    input: RootReplacementRegistrationAttemptInput,
) -> Result<(), RegistrationError> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(RegistrationError::InvalidResponse(
            "replacement registration capsule requires root authority",
        ));
    }
    let parent = path.parent().ok_or(RegistrationError::InvalidResponse(
        "invalid replacement registration capsule path",
    ))?;
    ensure_directory(parent, 0o700, Some(ROOT_CAPSULE_OWNER))?;
    let binding = ReplacementRegistrationBinding::from(input.binding);
    let registration_input = ProbeRegistrationInput {
        bootstrap_config_path: Default::default(),
        enrollment_token: input.enrollment_token,
        hub_url: binding.hub_origin.clone(),
    };
    match read_registration_attempt_capsule(path) {
        Ok(Some(capsule)) => {
            validate_registration_attempt_capsule(&capsule, &registration_input, &binding)
        }
        Ok(None) => {
            let capsule = create_registration_attempt(&registration_input, &binding)?;
            persist_registration_attempt_capsule(path, &capsule)
        }
        Err(error) => Err(RegistrationError::Io(error)),
    }
}

/// Validates the durable root capsule against one already-retained Replacement
/// commit before the coordinator may resume any destructive effect.
pub(crate) fn validate_root_replacement_registration_attempt(
    path: &Path,
    input: RootReplacementRegistrationAttemptInput,
) -> Result<(), RegistrationError> {
    let binding = ReplacementRegistrationBinding::from(input.binding);
    let capsule = read_registration_attempt_capsule(path)?.ok_or(
        RegistrationError::InvalidResponse("missing replacement registration capsule"),
    )?;
    validate_registration_attempt_capsule(
        &capsule,
        &ProbeRegistrationInput {
            bootstrap_config_path: Default::default(),
            enrollment_token: input.enrollment_token,
            hub_url: binding.hub_origin.clone(),
        },
        &binding,
    )
}

/// 仅替换仍精确绑定当前 Probe、Hub、Host 与 source 的 precommit capsule。
/// coordinator 只能在新 inspection 成功且 Replacement commit 缺失后调用。
pub fn replace_stale_root_replacement_registration_attempt(
    path: &Path,
    input: RootReplacementRegistrationAttemptInput,
) -> Result<(), RegistrationError> {
    let binding = ReplacementRegistrationBinding::from(input.binding.clone());
    let capsule = read_registration_attempt_capsule(path)?.ok_or(
        RegistrationError::InvalidResponse("missing replacement registration capsule"),
    )?;
    let request_body = decode_lower_hex(&capsule.request_hex).ok_or(
        RegistrationError::InvalidResponse("invalid registration attempt capsule"),
    )?;
    let request = ProbeRegistrationRequest::decode(request_body.as_slice())
        .map_err(|_| RegistrationError::InvalidResponse("invalid registration attempt capsule"))?;
    let attempt = ProbeRegistrationAttempt::decode(request.canonical_attempt.as_slice())
        .map_err(|_| RegistrationError::InvalidResponse("invalid registration attempt capsule"))?;
    if attempt.encode_to_vec() != request.canonical_attempt
        || capsule.hub_origin != binding.hub_origin
        || attempt.hub_origin != binding.hub_origin
        || attempt.host_id != binding.host_id
        || attempt.old_probe_id != binding.old_probe_id
        || attempt.source_probe_version != binding.source_probe_version
        || attempt.committed_source_probe_sha256 != binding.committed_source_probe_sha256
    {
        return Err(RegistrationError::InvalidResponse(
            "stale registration attempt does not match installed source",
        ));
    }
    let registration_input = ProbeRegistrationInput {
        bootstrap_config_path: Default::default(),
        enrollment_token: input.enrollment_token,
        hub_url: binding.hub_origin.clone(),
    };
    let replacement = create_registration_attempt(&registration_input, &binding)?;
    persist_registration_attempt_capsule(path, &replacement)
}

fn create_registration_attempt(
    input: &ProbeRegistrationInput,
    binding: &ReplacementRegistrationBinding,
) -> Result<ProbeRegistrationAttemptCapsule, RegistrationError> {
    let signing_key = generate_probe_signing_key()?;
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let attempt = binding.to_proto(encode_lower_hex(&nonce), signing_key.public_key_pem.clone());
    let canonical_attempt = attempt.encode_to_vec();
    let private_key = RsaPrivateKey::from_pkcs8_pem(&signing_key.private_key_pem)
        .map_err(|error| RegistrationError::KeyGeneration(error.to_string()))?;
    let signature = SigningKey::<Sha256>::new(private_key)
        .sign_with_rng(
            &mut OsRng,
            registration_attempt_signature_payload(&canonical_attempt).as_bytes(),
        )
        .to_bytes()
        .to_vec();
    let request_body = ProbeRegistrationRequest {
        candidate_signature: signature.clone(),
        canonical_attempt: canonical_attempt.clone(),
        enrollment_token: input.enrollment_token.clone(),
        installation_inspection: None,
        installation_rejection: None,
        probe_public_key_pem: signing_key.public_key_pem,
        snapshots: Vec::new(),
    }
    .encode_to_vec();
    let local_clock_reference_ms =
        u64::try_from(super::current_unix_time_ms_i128()).map_err(|_| {
            RegistrationError::InvalidResponse("invalid replacement registration clock reference")
        })?;
    Ok(ProbeRegistrationAttemptCapsule {
        schema_version: 1,
        enrollment_token_sha256: sha256_hex(input.enrollment_token.as_bytes()),
        hub_origin: input.hub_url.clone(),
        candidate_private_key_pem: signing_key.private_key_pem,
        local_clock_reference_ms,
        request_hex: encode_lower_hex(&request_body),
        signed_attempt_sha256: signed_attempt_sha256(&canonical_attempt, &signature),
    })
}

fn persist_registration_attempt_capsule(
    path: &Path,
    capsule: &ProbeRegistrationAttemptCapsule,
) -> Result<(), RegistrationError> {
    let bytes = serde_json::to_vec(capsule)
        .map_err(|_| RegistrationError::InvalidResponse("invalid registration attempt capsule"))?;
    if bytes.len() > MAX_REGISTRATION_ATTEMPT_CAPSULE_BYTES {
        return Err(RegistrationError::InvalidResponse(
            "registration attempt capsule is too large",
        ));
    }
    atomic_write(path, &bytes, 0o600, Some(ROOT_CAPSULE_OWNER))?;
    Ok(())
}

fn read_registration_attempt_capsule(
    path: &Path,
) -> Result<Option<ProbeRegistrationAttemptCapsule>, std::io::Error> {
    let bytes = match read_private_regular_file(
        path,
        0o600,
        ROOT_CAPSULE_OWNER,
        MAX_REGISTRATION_ATTEMPT_CAPSULE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid registration attempt capsule",
        )
    })
}

fn read_registration_attempt_credential(
    path: &Path,
) -> Result<Option<ProbeRegistrationAttemptCapsule>, std::io::Error> {
    let bytes = match read_registration_attempt_credential_bytes(
        path,
        MAX_REGISTRATION_ATTEMPT_CAPSULE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid registration attempt credential",
        )
    })
}

fn validate_registration_attempt_capsule(
    capsule: &ProbeRegistrationAttemptCapsule,
    input: &ProbeRegistrationInput,
    binding: &ReplacementRegistrationBinding,
) -> Result<(), RegistrationError> {
    if capsule.schema_version != 1
        || capsule.local_clock_reference_ms == 0
        || capsule.enrollment_token_sha256 != sha256_hex(input.enrollment_token.as_bytes())
        || capsule.hub_origin != input.hub_url
    {
        return Err(RegistrationError::InvalidResponse(
            "registration attempt capsule binding mismatch",
        ));
    }
    let request_body = decode_lower_hex(&capsule.request_hex).ok_or(
        RegistrationError::InvalidResponse("invalid registration attempt capsule"),
    )?;
    let request = ProbeRegistrationRequest::decode(request_body.as_slice())
        .map_err(|_| RegistrationError::InvalidResponse("invalid registration attempt capsule"))?;
    let attempt = ProbeRegistrationAttempt::decode(request.canonical_attempt.as_slice())
        .map_err(|_| RegistrationError::InvalidResponse("invalid registration attempt capsule"))?;
    if attempt.encode_to_vec() != request.canonical_attempt
        || request.enrollment_token != input.enrollment_token
        || request.installation_inspection.is_some()
        || request.installation_rejection.is_some()
        || !request.snapshots.is_empty()
        || !binding.matches_proto(&attempt)
    {
        return Err(RegistrationError::InvalidResponse(
            "registration attempt capsule binding mismatch",
        ));
    }
    let private_key = RsaPrivateKey::from_pkcs8_pem(&capsule.candidate_private_key_pem)
        .map_err(|_| RegistrationError::InvalidResponse("invalid registration attempt capsule"))?;
    let public_key = RsaPublicKey::from(&private_key)
        .to_public_key_pem(Default::default())
        .map_err(|_| RegistrationError::InvalidResponse("invalid registration attempt capsule"))?;
    if public_key != request.probe_public_key_pem
        || public_key != attempt.candidate_public_key_pem
        || capsule.signed_attempt_sha256
            != signed_attempt_sha256(&request.canonical_attempt, &request.candidate_signature)
    {
        return Err(RegistrationError::InvalidResponse(
            "registration attempt capsule key mismatch",
        ));
    }
    let signature = RsaPkcs1v15Signature::try_from(request.candidate_signature.as_slice())
        .map_err(|_| RegistrationError::InvalidResponse("invalid registration attempt capsule"))?;
    VerifyingKey::<Sha256>::new(
        RsaPublicKey::from_public_key_pem(&public_key).map_err(|_| {
            RegistrationError::InvalidResponse("invalid registration attempt capsule")
        })?,
    )
    .verify(
        registration_attempt_signature_payload(&request.canonical_attempt).as_bytes(),
        &signature,
    )
    .map_err(|_| RegistrationError::InvalidResponse("invalid registration attempt capsule"))?;
    Ok(())
}

fn registration_request(
    enrollment_token: String,
    probe_public_key_pem: String,
) -> ProbeRegistrationRequest {
    ProbeRegistrationRequest {
        candidate_signature: Vec::new(),
        canonical_attempt: Vec::new(),
        enrollment_token,
        installation_inspection: None,
        installation_rejection: None,
        probe_public_key_pem,
        snapshots: Vec::new(),
    }
}

fn generate_probe_signing_key() -> Result<GeneratedProbeSigningKey, RegistrationError> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|error| RegistrationError::KeyGeneration(error.to_string()))?;
    let public_key = private_key.to_public_key();
    let private_key_pem = private_key
        .to_pkcs8_pem(Default::default())
        .map_err(|error| RegistrationError::KeyGeneration(error.to_string()))?
        .to_string();
    let public_key_pem = public_key
        .to_public_key_pem(Default::default())
        .map_err(|error| RegistrationError::KeyGeneration(error.to_string()))?;

    Ok(GeneratedProbeSigningKey {
        private_key_pem,
        public_key_pem,
    })
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

fn encode_lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
mod tests {
    use super::*;

    fn binding() -> BootstrapReplacementRegistrationBinding {
        BootstrapReplacementRegistrationBinding {
            committed_source_probe_sha256: "a".repeat(64),
            enrollment_id: "enr_0123456789abcdef".into(),
            host_id: "7".into(),
            hub_origin: "https://hub.example".into(),
            old_probe_id: "probe_old_01".into(),
            replacement_commit_sha256: "b".repeat(64),
            source_probe_version: "1.2.3".into(),
            target_asset_set_digest: format!("sha256:{}", "c".repeat(64)),
            target_bundle_target: "x86_64-unknown-linux-gnu".into(),
            target_manifest_sha256: "d".repeat(64),
            target_probe_version: "1.2.4".into(),
        }
    }

    #[test]
    fn stale_capsule_replacement_requires_the_exact_installed_source_binding() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("attempt.json");
        let old = binding();
        let old_input = RootReplacementRegistrationAttemptInput {
            enrollment_token: "enk_old".into(),
            binding: old.clone(),
        };
        prepare_root_replacement_registration_attempt(&path, old_input).unwrap();
        let original = std::fs::read(&path).unwrap();
        let mut next = old.clone();
        next.enrollment_id = "enr_abcdef0123456789".into();
        next.replacement_commit_sha256 = "e".repeat(64);
        replace_stale_root_replacement_registration_attempt(
            &path,
            RootReplacementRegistrationAttemptInput {
                enrollment_token: "enk_new".into(),
                binding: next,
            },
        )
        .unwrap();
        assert_ne!(std::fs::read(&path).unwrap(), original);
        let mut wrong = old;
        wrong.old_probe_id = "probe_other".into();
        assert!(
            replace_stale_root_replacement_registration_attempt(
                &path,
                RootReplacementRegistrationAttemptInput {
                    enrollment_token: "enk_third".into(),
                    binding: wrong
                }
            )
            .is_err()
        );
    }

    #[test]
    fn retained_commit_validation_covers_the_complete_durable_capsule_binding() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("attempt.json");
        let exact = RootReplacementRegistrationAttemptInput {
            enrollment_token: "enk_exact".into(),
            binding: binding(),
        };
        prepare_root_replacement_registration_attempt(&path, exact.clone()).unwrap();
        let original = std::fs::read(&path).unwrap();
        validate_root_replacement_registration_attempt(&path, exact.clone()).unwrap();

        let mutations: [fn(&mut RootReplacementRegistrationAttemptInput); 12] = [
            |input| input.enrollment_token.push_str("_other"),
            |input| input.binding.enrollment_id.push_str("_other"),
            |input| input.binding.host_id.push('8'),
            |input| input.binding.hub_origin.push_str("/other"),
            |input| input.binding.old_probe_id.push_str("_other"),
            |input| input.binding.source_probe_version.push_str("+other"),
            |input| {
                input
                    .binding
                    .committed_source_probe_sha256
                    .replace_range(..1, "f")
            },
            |input| {
                input
                    .binding
                    .replacement_commit_sha256
                    .replace_range(..1, "f")
            },
            |input| input.binding.target_probe_version.push_str("+other"),
            |input| {
                input
                    .binding
                    .target_asset_set_digest
                    .replace_range(7..8, "f")
            },
            |input| input.binding.target_bundle_target.push_str("-other"),
            |input| input.binding.target_manifest_sha256.replace_range(..1, "f"),
        ];
        for mutate in mutations {
            let mut changed = exact.clone();
            mutate(&mut changed);
            assert!(validate_root_replacement_registration_attempt(&path, changed).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }

        let corrupt = b"corrupt durable capsule";
        std::fs::write(&path, corrupt).unwrap();
        assert!(validate_root_replacement_registration_attempt(&path, exact).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    }
}

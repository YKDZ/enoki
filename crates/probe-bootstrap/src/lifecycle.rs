//! 探针本机生命周期的封闭领域合同。

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LIFECYCLE_INSTALL_KEY_SALT: &[u8] = b"enoki/lifecycle-authority/install-key/hkdf-sha256/v1\0";
const LIFECYCLE_INSTALL_KEY_INFO_DOMAIN: &[u8] =
    b"enoki/lifecycle-authority/hub-origin/hkdf-sha256/v1\0";
const LIFECYCLE_AUTHORITY_SIGNING_DOMAIN: &[u8] =
    b"enoki/lifecycle-upgrade-authority/hmac-sha256/v1\0";
const LIFECYCLE_REPAIR_EVIDENCE_SIGNING_DOMAIN: &[u8] =
    b"enoki/lifecycle-repair-evidence/hmac-sha256/v1\0";
const LIFECYCLE_REPAIR_ELIGIBILITY_SIGNING_DOMAIN: &[u8] =
    b"enoki/lifecycle-repair-eligibility/hmac-sha256/v1\0";
const LIFECYCLE_REPAIR_AUTHORITY_SIGNING_DOMAIN: &[u8] =
    b"enoki/lifecycle-repair-authority/hmac-sha256/v1\0";
const INSTALLED_BUNDLE_FAILURE_EVIDENCE_SIGNING_DOMAIN: &[u8] =
    b"enoki/installed-bundle-failure-evidence/hmac-sha256/v1\0";
const INSTALLED_BUNDLE_REPAIR_AUTHORITY_SIGNING_DOMAIN: &[u8] =
    b"enoki/installed-bundle-repair-authority/hmac-sha256/v1\0";

type HmacSha256 = Hmac<Sha256>;

pub fn derive_lifecycle_authority_install_key(
    enrollment_token: &str,
    normalized_hub_origin: &str,
) -> [u8; 32] {
    let ikm = Sha256::digest(enrollment_token.as_bytes());
    let mut extract = HmacSha256::new_from_slice(LIFECYCLE_INSTALL_KEY_SALT)
        .expect("HMAC accepts the fixed lifecycle salt");
    extract.update(&ikm);
    let prk = extract.finalize().into_bytes();
    let mut expand =
        HmacSha256::new_from_slice(&prk).expect("HMAC accepts the HKDF pseudorandom key");
    expand.update(LIFECYCLE_INSTALL_KEY_INFO_DOMAIN);
    expand.update(normalized_hub_origin.as_bytes());
    expand.update(&[1]);
    expand.finalize().into_bytes().into()
}

pub fn verify_lifecycle_upgrade_authority_signature(
    install_key: &[u8; 32],
    canonical_authority: &[u8],
    signature_hex: &str,
) -> bool {
    let Some(signature) = decode_lower_hex_32(signature_hex) else {
        return false;
    };
    let mut verifier = HmacSha256::new_from_slice(install_key)
        .expect("HMAC accepts the fixed-size lifecycle install key");
    verifier.update(LIFECYCLE_AUTHORITY_SIGNING_DOMAIN);
    verifier.update(canonical_authority);
    verifier.verify_slice(&signature).is_ok()
}

fn decode_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        output[index] = ((high << 4) | low) as u8;
    }
    Some(output)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairEvidenceV1 {
    pub schema_version: u16,
    pub hub_origin: String,
    pub host_id: String,
    pub probe_id: String,
    pub failed_operation_id: String,
    pub failed_authority_sha256: String,
    pub journal_sha256: String,
    pub journal_phase: String,
    pub activated_targets: usize,
    pub finalized_targets: usize,
    pub target_bundle_version: String,
    pub target_asset_set_digest: String,
    pub target_manifest_sha256: String,
    pub verified_stage_sha256: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub request_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairEligibilityV1 {
    pub schema_version: u16,
    pub hub_origin: String,
    pub host_id: String,
    pub probe_id: String,
    pub failed_operation_id: String,
    pub failed_authority_sha256: String,
    pub journal_sha256: String,
    pub journal_phase: String,
    pub activated_targets: usize,
    pub finalized_targets: usize,
    pub target_bundle_version: String,
    pub target_asset_set_digest: String,
    pub target_manifest_sha256: String,
    pub verified_stage_sha256: String,
}

impl RepairEligibilityV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("fixed Repair Eligibility serializes")
    }

    pub fn sha256(&self) -> String {
        format!("{:x}", Sha256::digest(self.canonical_bytes()))
    }

    pub fn sign(&self, install_key: &[u8; 32]) -> String {
        sign_lifecycle_repair_facts(
            install_key,
            LIFECYCLE_REPAIR_ELIGIBILITY_SIGNING_DOMAIN,
            &self.canonical_bytes(),
        )
    }

    pub fn verify(&self, install_key: &[u8; 32], signature_hex: &str) -> bool {
        verify_lifecycle_repair_facts(
            install_key,
            LIFECYCLE_REPAIR_ELIGIBILITY_SIGNING_DOMAIN,
            &self.canonical_bytes(),
            signature_hex,
        )
    }
}

impl RepairEvidenceV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("fixed Repair Evidence serializes")
    }

    pub fn sha256(&self) -> String {
        format!("{:x}", Sha256::digest(self.canonical_bytes()))
    }

    pub fn sign(&self, install_key: &[u8; 32]) -> String {
        sign_lifecycle_repair_facts(
            install_key,
            LIFECYCLE_REPAIR_EVIDENCE_SIGNING_DOMAIN,
            &self.canonical_bytes(),
        )
    }

    pub fn verify(&self, install_key: &[u8; 32], signature_hex: &str) -> bool {
        verify_lifecycle_repair_facts(
            install_key,
            LIFECYCLE_REPAIR_EVIDENCE_SIGNING_DOMAIN,
            &self.canonical_bytes(),
            signature_hex,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairAuthorityV1 {
    pub schema_version: u16,
    pub hub_origin: String,
    pub host_id: String,
    pub probe_id: String,
    pub failed_operation_id: String,
    pub repair_operation_id: String,
    pub repair_nonce: String,
    pub repair_evidence_sha256: String,
    pub target_bundle_version: String,
    pub target_asset_set_digest: String,
    pub target_manifest_sha256: String,
    pub verified_stage_sha256: String,
    pub expires_at_ms: u64,
}

impl RepairAuthorityV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("fixed Repair Authority serializes")
    }

    pub fn verify(&self, install_key: &[u8; 32], signature_hex: &str) -> bool {
        verify_lifecycle_repair_facts(
            install_key,
            LIFECYCLE_REPAIR_AUTHORITY_SIGNING_DOMAIN,
            &self.canonical_bytes(),
            signature_hex,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstalledBundleFailureEvidenceV1 {
    pub kind: String,
    pub schema_version: u16,
    pub hub_origin: String,
    pub host_id: String,
    pub probe_id: String,
    pub generation: String,
    pub boot_id: String,
    pub unit: String,
    pub unit_sha256: String,
    pub identity_receipt_sha256: String,
    pub install_state_sha256: String,
    pub manifest_sha256: String,
    pub bundle_version: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub request_nonce: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledBundleBindingsV1 {
    pub hub_origin: String,
    pub host_id: String,
    pub probe_id: String,
    pub generation: String,
    pub boot_id: String,
    pub unit: String,
    pub unit_sha256: String,
    pub identity_receipt_sha256: String,
    pub install_state_sha256: String,
    pub manifest_sha256: String,
    pub bundle_version: String,
}

impl InstalledBundleFailureEvidenceV1 {
    #[must_use]
    pub fn bindings(&self) -> InstalledBundleBindingsV1 {
        InstalledBundleBindingsV1 {
            hub_origin: self.hub_origin.clone(),
            host_id: self.host_id.clone(),
            probe_id: self.probe_id.clone(),
            generation: self.generation.clone(),
            boot_id: self.boot_id.clone(),
            unit: self.unit.clone(),
            unit_sha256: self.unit_sha256.clone(),
            identity_receipt_sha256: self.identity_receipt_sha256.clone(),
            install_state_sha256: self.install_state_sha256.clone(),
            manifest_sha256: self.manifest_sha256.clone(),
            bundle_version: self.bundle_version.clone(),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("fixed Installed Bundle Failure Evidence serializes")
    }

    pub fn sha256(&self) -> String {
        format!("{:x}", Sha256::digest(self.canonical_bytes()))
    }

    pub fn sign(&self, install_key: &[u8; 32]) -> String {
        sign_lifecycle_repair_facts(
            install_key,
            INSTALLED_BUNDLE_FAILURE_EVIDENCE_SIGNING_DOMAIN,
            &self.canonical_bytes(),
        )
    }

    pub fn verify(&self, install_key: &[u8; 32], signature_hex: &str) -> bool {
        verify_lifecycle_repair_facts(
            install_key,
            INSTALLED_BUNDLE_FAILURE_EVIDENCE_SIGNING_DOMAIN,
            &self.canonical_bytes(),
            signature_hex,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstalledBundleRepairAuthorityV1 {
    pub kind: String,
    pub schema_version: u16,
    pub hub_origin: String,
    pub host_id: String,
    pub probe_id: String,
    pub generation: String,
    pub boot_id: String,
    pub unit: String,
    pub unit_sha256: String,
    pub identity_receipt_sha256: String,
    pub install_state_sha256: String,
    pub manifest_sha256: String,
    pub bundle_version: String,
    pub target_asset_set_digest: String,
    pub repair_operation_id: String,
    pub repair_nonce: String,
    pub repair_evidence_sha256: String,
    pub expires_at_ms: u64,
}

impl InstalledBundleRepairAuthorityV1 {
    #[must_use]
    pub fn bindings(&self) -> InstalledBundleBindingsV1 {
        InstalledBundleBindingsV1 {
            hub_origin: self.hub_origin.clone(),
            host_id: self.host_id.clone(),
            probe_id: self.probe_id.clone(),
            generation: self.generation.clone(),
            boot_id: self.boot_id.clone(),
            unit: self.unit.clone(),
            unit_sha256: self.unit_sha256.clone(),
            identity_receipt_sha256: self.identity_receipt_sha256.clone(),
            install_state_sha256: self.install_state_sha256.clone(),
            manifest_sha256: self.manifest_sha256.clone(),
            bundle_version: self.bundle_version.clone(),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("fixed Installed Bundle Repair Authority serializes")
    }

    pub fn verify(&self, install_key: &[u8; 32], signature_hex: &str) -> bool {
        verify_lifecycle_repair_facts(
            install_key,
            INSTALLED_BUNDLE_REPAIR_AUTHORITY_SIGNING_DOMAIN,
            &self.canonical_bytes(),
            signature_hex,
        )
    }

    #[must_use]
    pub fn matches_evidence(&self, evidence: &InstalledBundleFailureEvidenceV1) -> bool {
        self.kind == evidence.kind
            && self.bindings() == evidence.bindings()
            && self.repair_evidence_sha256 == evidence.sha256()
    }
}

fn sign_lifecycle_repair_facts(install_key: &[u8; 32], domain: &[u8], canonical: &[u8]) -> String {
    let mut signer = HmacSha256::new_from_slice(install_key)
        .expect("HMAC accepts the fixed-size lifecycle install key");
    signer.update(domain);
    signer.update(canonical);
    signer
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn verify_lifecycle_repair_facts(
    install_key: &[u8; 32],
    domain: &[u8],
    canonical: &[u8],
    signature_hex: &str,
) -> bool {
    let Some(signature) = decode_lower_hex_32(signature_hex) else {
        return false;
    };
    let mut verifier = HmacSha256::new_from_slice(install_key)
        .expect("HMAC accepts the fixed-size lifecycle install key");
    verifier.update(domain);
    verifier.update(canonical);
    verifier.verify_slice(&signature).is_ok()
}

pub const MAX_LIFECYCLE_REQUEST_BYTES: usize = 8 * 1024;
pub const MAX_OPERATION_TOKEN_BYTES: usize = 2 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleTransition {
    FreshInstall,
    Upgrade,
    Repair,
    ReplacementMigration,
    Uninstall,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleRequest {
    schema_version: u16,
    transition: LifecycleTransition,
    authority: LifecycleRequestAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LifecycleRequestAuthority {
    HubUpgrade {
        hub_origin: String,
        host_id: String,
        probe_id: String,
        operation_id: String,
        source_bundle_version: String,
        source_install_state_sha256: String,
        source_manifest_sha256: String,
        target_bundle_version: String,
        target_asset_set_digest: String,
        target_manifest_sha256: String,
        verified_stage_sha256: String,
        expires_at_ms: u64,
        authority_signature: String,
    },
    HubOperation {
        probe_id: String,
        operation_id: String,
        operation_token: String,
        install_state_sha256: String,
        target_manifest_sha256: String,
        bundle_version: String,
    },
    LocalRoot {
        probe_id: String,
        install_state_sha256: String,
        target_manifest_sha256: String,
        bundle_version: String,
    },
    LocalRepair {
        probe_id: String,
        install_state_sha256: String,
        target_manifest_sha256: String,
        bundle_version: String,
        invoking_uid: u32,
        invoking_gid: u32,
    },
    ReplacementEnrollment {
        enrollment_token: String,
        enrollment_id: String,
        hub_origin: String,
        host_id: String,
        expected_probe_id: String,
        source_probe_version: String,
        source_probe_sha256: Vec<String>,
        target_asset_set_digest: String,
        target_bundle_target: String,
        target_manifest_sha256: String,
        bundle_version: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleResultStatus {
    Succeeded,
    Failed,
    NotEnabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleResponse {
    schema_version: u16,
    status: LifecycleResultStatus,
    code: String,
}

impl LifecycleResponse {
    #[must_use]
    pub fn succeeded() -> Self {
        Self {
            schema_version: 1,
            status: LifecycleResultStatus::Succeeded,
            code: "lifecycle.succeeded".to_owned(),
        }
    }

    #[must_use]
    pub fn recovery_pending() -> Self {
        Self {
            schema_version: 1,
            status: LifecycleResultStatus::Succeeded,
            code: "lifecycle.recovery_pending".to_owned(),
        }
    }

    #[must_use]
    pub fn failed(code: &str) -> Self {
        Self {
            schema_version: 1,
            status: LifecycleResultStatus::Failed,
            code: bounded_result_code(code),
        }
    }

    #[must_use]
    pub fn not_enabled() -> Self {
        Self {
            schema_version: 1,
            status: LifecycleResultStatus::NotEnabled,
            code: "lifecycle.transition_not_enabled".to_owned(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("固定 Lifecycle Response 可序列化")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleRejection> {
        if bytes.is_empty() || bytes.len() > MAX_LIFECYCLE_REQUEST_BYTES {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        let response: Self =
            serde_json::from_slice(bytes).map_err(|_| LifecycleRejection::InvalidAuthority)?;
        if response.schema_version != 1
            || response.encode().as_slice() != bytes
            || bounded_result_code(&response.code) != response.code
        {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        Ok(response)
    }

    #[must_use]
    pub const fn status(&self) -> LifecycleResultStatus {
        self.status
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
}

fn bounded_result_code(code: &str) -> String {
    if (1..=96).contains(&code.len())
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        code.to_owned()
    } else {
        "lifecycle.failed".to_owned()
    }
}

impl LifecycleRequest {
    pub fn canonical_upgrade_authority_bytes(&self) -> Result<Vec<u8>, LifecycleRejection> {
        let LifecycleRequestAuthority::HubUpgrade {
            hub_origin,
            host_id,
            probe_id,
            operation_id,
            source_bundle_version,
            source_install_state_sha256,
            source_manifest_sha256,
            target_bundle_version,
            target_asset_set_digest,
            target_manifest_sha256,
            verified_stage_sha256,
            expires_at_ms,
            ..
        } = &self.authority
        else {
            return Err(LifecycleRejection::InvalidAuthority);
        };
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct CanonicalAuthority<'a> {
            schema_version: u16,
            hub_origin: &'a str,
            host_id: &'a str,
            probe_id: &'a str,
            operation_id: &'a str,
            source_bundle_version: &'a str,
            source_install_state_sha256: &'a str,
            source_manifest_sha256: &'a str,
            target_bundle_version: &'a str,
            target_asset_set_digest: &'a str,
            target_manifest_sha256: &'a str,
            verified_stage_sha256: &'a str,
            expires_at_ms: u64,
        }
        serde_json::to_vec(&CanonicalAuthority {
            schema_version: 1,
            hub_origin,
            host_id,
            probe_id,
            operation_id,
            source_bundle_version,
            source_install_state_sha256,
            source_manifest_sha256,
            target_bundle_version,
            target_asset_set_digest,
            target_manifest_sha256,
            verified_stage_sha256,
            expires_at_ms: *expires_at_ms,
        })
        .map_err(|_| LifecycleRejection::InvalidAuthority)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn hub_upgrade(
        hub_origin: &str,
        host_id: &str,
        probe_id: &str,
        operation_id: &str,
        source_bundle_version: &str,
        source_install_state_sha256: &str,
        source_manifest_sha256: &str,
        target_bundle_version: &str,
        target_asset_set_digest: &str,
        target_manifest_sha256: &str,
        verified_stage_sha256: &str,
        expires_at_ms: u64,
        authority_signature: &str,
    ) -> Result<Self, LifecycleRejection> {
        let request = Self {
            schema_version: 1,
            transition: LifecycleTransition::Upgrade,
            authority: LifecycleRequestAuthority::HubUpgrade {
                hub_origin: hub_origin.to_owned(),
                host_id: host_id.to_owned(),
                probe_id: probe_id.to_owned(),
                operation_id: operation_id.to_owned(),
                source_bundle_version: source_bundle_version.to_owned(),
                source_install_state_sha256: source_install_state_sha256.to_owned(),
                source_manifest_sha256: source_manifest_sha256.to_owned(),
                target_bundle_version: target_bundle_version.to_owned(),
                target_asset_set_digest: target_asset_set_digest.to_owned(),
                target_manifest_sha256: target_manifest_sha256.to_owned(),
                verified_stage_sha256: verified_stage_sha256.to_owned(),
                expires_at_ms,
                authority_signature: authority_signature.to_owned(),
            },
        };
        request.validate()?;
        Ok(request)
    }

    pub fn hub_uninstall(
        probe_id: &str,
        operation_id: &str,
        operation_token: &str,
        install_state_sha256: &str,
        target_manifest_sha256: &str,
        bundle_version: &str,
    ) -> Result<Self, LifecycleRejection> {
        let request = Self {
            schema_version: 1,
            transition: LifecycleTransition::Uninstall,
            authority: LifecycleRequestAuthority::HubOperation {
                probe_id: probe_id.to_owned(),
                operation_id: operation_id.to_owned(),
                operation_token: operation_token.to_owned(),
                install_state_sha256: install_state_sha256.to_owned(),
                target_manifest_sha256: target_manifest_sha256.to_owned(),
                bundle_version: bundle_version.to_owned(),
            },
        };
        request.validate()?;
        Ok(request)
    }

    pub fn local_uninstall(
        probe_id: &str,
        install_state_sha256: &str,
        target_manifest_sha256: &str,
        bundle_version: &str,
    ) -> Result<Self, LifecycleRejection> {
        let request = Self {
            schema_version: 1,
            transition: LifecycleTransition::Uninstall,
            authority: LifecycleRequestAuthority::LocalRoot {
                probe_id: probe_id.to_owned(),
                install_state_sha256: install_state_sha256.to_owned(),
                target_manifest_sha256: target_manifest_sha256.to_owned(),
                bundle_version: bundle_version.to_owned(),
            },
        };
        request.validate()?;
        Ok(request)
    }

    pub fn local_repair(
        probe_id: &str,
        install_state_sha256: &str,
        target_manifest_sha256: &str,
        bundle_version: &str,
        invoking_uid: u32,
        invoking_gid: u32,
    ) -> Result<Self, LifecycleRejection> {
        let request = Self {
            schema_version: 1,
            transition: LifecycleTransition::Repair,
            authority: LifecycleRequestAuthority::LocalRepair {
                probe_id: probe_id.to_owned(),
                install_state_sha256: install_state_sha256.to_owned(),
                target_manifest_sha256: target_manifest_sha256.to_owned(),
                bundle_version: bundle_version.to_owned(),
                invoking_uid,
                invoking_gid,
            },
        };
        request.validate()?;
        Ok(request)
    }

    pub fn replacement_migration(
        enrollment: &crate::handoff::Enrollment,
        target_asset_set_digest: &str,
        target_bundle_target: &str,
        target_manifest_sha256: &str,
        bundle_version: &str,
    ) -> Result<Self, LifecycleRejection> {
        let facts = enrollment
            .replacement_migration()
            .ok_or(LifecycleRejection::InvalidAuthority)?;
        if facts.target_asset_set_digest() != target_asset_set_digest
            || facts.target_probe_version() != bundle_version
        {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        let request = Self {
            schema_version: 1,
            transition: LifecycleTransition::ReplacementMigration,
            authority: LifecycleRequestAuthority::ReplacementEnrollment {
                enrollment_token: enrollment.enrollment_token().to_owned(),
                enrollment_id: facts.enrollment_id().to_owned(),
                hub_origin: enrollment.hub_origin().to_owned(),
                host_id: facts.target_host_id().to_owned(),
                expected_probe_id: facts.expected_probe_id().to_owned(),
                source_probe_version: facts.source_probe_version().to_owned(),
                source_probe_sha256: facts.source_probe_sha256().to_vec(),
                target_asset_set_digest: target_asset_set_digest.to_owned(),
                target_bundle_target: target_bundle_target.to_owned(),
                target_manifest_sha256: target_manifest_sha256.to_owned(),
                bundle_version: bundle_version.to_owned(),
            },
        };
        request.validate()?;
        Ok(request)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleRejection> {
        if bytes.is_empty() || bytes.len() > MAX_LIFECYCLE_REQUEST_BYTES {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| LifecycleRejection::InvalidAuthority)?;
        request.validate()?;
        if request.encode()?.as_slice() != bytes {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        Ok(request)
    }

    pub fn encode(&self) -> Result<Vec<u8>, LifecycleRejection> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| LifecycleRejection::InvalidAuthority)?;
        if bytes.len() > MAX_LIFECYCLE_REQUEST_BYTES {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), LifecycleRejection> {
        if self.schema_version != 1 {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        let (probe_id, install_state, manifest, version) = match &self.authority {
            LifecycleRequestAuthority::HubUpgrade {
                hub_origin,
                host_id,
                probe_id,
                operation_id,
                source_bundle_version,
                source_install_state_sha256,
                source_manifest_sha256,
                target_bundle_version,
                target_asset_set_digest,
                target_manifest_sha256,
                verified_stage_sha256,
                expires_at_ms,
                authority_signature,
            } => {
                if self.transition != LifecycleTransition::Upgrade
                    || !valid_hub_origin(hub_origin)
                    || !valid_identifier(host_id)
                    || !valid_identifier(probe_id)
                    || !valid_identifier(operation_id)
                    || !valid_bundle_version(source_bundle_version)
                    || !is_sha256_hex(source_install_state_sha256)
                    || !is_sha256_hex(source_manifest_sha256)
                    || !valid_bundle_version(target_bundle_version)
                    || source_bundle_version == target_bundle_version
                    || !is_prefixed_sha256(target_asset_set_digest)
                    || !is_sha256_hex(target_manifest_sha256)
                    || !is_sha256_hex(verified_stage_sha256)
                    || *expires_at_ms == 0
                    || authority_signature.is_empty()
                    || authority_signature.len() > 1024
                    || !authority_signature
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Err(LifecycleRejection::InvalidAuthority);
                }
                return Ok(());
            }
            LifecycleRequestAuthority::HubOperation {
                probe_id,
                operation_id,
                operation_token,
                install_state_sha256,
                target_manifest_sha256,
                bundle_version,
            } => {
                if !valid_identifier(operation_id)
                    || operation_token.is_empty()
                    || operation_token.len() > MAX_OPERATION_TOKEN_BYTES
                    || operation_token.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err(LifecycleRejection::InvalidAuthority);
                }
                (
                    probe_id,
                    install_state_sha256,
                    target_manifest_sha256,
                    bundle_version,
                )
            }
            LifecycleRequestAuthority::LocalRoot {
                probe_id,
                install_state_sha256,
                target_manifest_sha256,
                bundle_version,
            } => (
                probe_id,
                install_state_sha256,
                target_manifest_sha256,
                bundle_version,
            ),
            LifecycleRequestAuthority::LocalRepair {
                probe_id,
                install_state_sha256,
                target_manifest_sha256,
                bundle_version,
                invoking_uid,
                invoking_gid,
            } => {
                if self.transition != LifecycleTransition::Repair
                    || *invoking_uid == 0
                    || *invoking_gid == 0
                {
                    return Err(LifecycleRejection::InvalidAuthority);
                }
                (
                    probe_id,
                    install_state_sha256,
                    target_manifest_sha256,
                    bundle_version,
                )
            }
            LifecycleRequestAuthority::ReplacementEnrollment {
                enrollment_token,
                enrollment_id,
                hub_origin,
                host_id,
                expected_probe_id,
                source_probe_version,
                source_probe_sha256,
                target_asset_set_digest,
                target_bundle_target,
                target_manifest_sha256,
                bundle_version,
            } => {
                if self.transition != LifecycleTransition::ReplacementMigration
                    || enrollment_token.is_empty()
                    || enrollment_token.len() > MAX_OPERATION_TOKEN_BYTES
                    || enrollment_token.bytes().any(|byte| byte.is_ascii_control())
                    || !valid_identifier(enrollment_id)
                    || !valid_hub_origin(hub_origin)
                    || !valid_identifier(host_id)
                    || !valid_identifier(expected_probe_id)
                    || !valid_bundle_version(source_probe_version)
                    || source_probe_sha256.is_empty()
                    || source_probe_sha256.len() > 16
                    || !source_probe_sha256
                        .iter()
                        .all(|digest| is_sha256_hex(digest))
                    || !is_prefixed_sha256(target_asset_set_digest)
                    || !matches!(
                        target_bundle_target.as_str(),
                        "aarch64-unknown-linux-gnu"
                            | "aarch64-unknown-linux-musl"
                            | "x86_64-unknown-linux-gnu"
                            | "x86_64-unknown-linux-musl"
                    )
                    || !is_sha256_hex(target_manifest_sha256)
                    || !valid_bundle_version(bundle_version)
                {
                    return Err(LifecycleRejection::InvalidAuthority);
                }
                return Ok(());
            }
        };
        if !valid_identifier(probe_id)
            || !is_sha256_hex(install_state)
            || !is_sha256_hex(manifest)
            || !valid_bundle_version(version)
        {
            return Err(LifecycleRejection::InvalidAuthority);
        }
        Ok(())
    }

    #[must_use]
    pub const fn transition(&self) -> LifecycleTransition {
        self.transition
    }

    #[must_use]
    pub const fn authority(&self) -> &LifecycleRequestAuthority {
        &self.authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRejection {
    InvalidAuthority,
    InvalidState,
}

impl LifecycleRejection {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidAuthority => "lifecycle.invalid_authority",
            Self::InvalidState => "lifecycle.invalid_state",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(all(feature = "acquirer", feature = "activator")),
    allow(dead_code)
)]
pub(crate) enum UpgradeCompletion {
    Activated,
    RepairRequired,
}

#[cfg_attr(
    not(all(feature = "acquirer", feature = "activator")),
    allow(dead_code)
)]
pub(crate) enum UpgradeActivationFailure<E> {
    Preactivation(E),
    Postactivation(E),
    RecoveryPersistence(E),
}

#[cfg_attr(
    not(all(feature = "acquirer", feature = "activator")),
    allow(dead_code)
)]
pub(crate) trait UpgradeLifecycleEffects {
    type Error;

    /// 校验 Hub authority、当前 root-owned 安装收据与固定 stage；不得产生安装变更。
    fn verify_and_prepare(&mut self) -> Result<(), Self::Error>;

    /// 只有 durable activation boundary 之后的执行错误才能进入 Repair；
    /// boundary 前或恢复状态持久化错误必须向调用方传播。
    fn activate_complete_bundle(&mut self) -> Result<(), UpgradeActivationFailure<Self::Error>>;
}

#[cfg_attr(
    not(all(feature = "acquirer", feature = "activator")),
    allow(dead_code)
)]
pub(crate) fn execute_upgrade_lifecycle<E: UpgradeLifecycleEffects>(
    effects: &mut E,
) -> Result<UpgradeCompletion, E::Error> {
    effects.verify_and_prepare()?;
    match effects.activate_complete_bundle() {
        Ok(()) => Ok(UpgradeCompletion::Activated),
        Err(UpgradeActivationFailure::Postactivation(_)) => Ok(UpgradeCompletion::RepairRequired),
        Err(
            UpgradeActivationFailure::Preactivation(error)
            | UpgradeActivationFailure::RecoveryPersistence(error),
        ) => Err(error),
    }
}

fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_prefixed_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_sha256_hex)
}

fn valid_hub_origin(value: &str) -> bool {
    crate::handoff::normalize_hub_origin(value).as_deref() == Some(value)
}

fn valid_bundle_version(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatible_upgrade_authority_roundtrips_with_source_target_and_stage_bindings() {
        let request = LifecycleRequest::hub_upgrade(
            "https://hub.example",
            "host_01",
            "probe_01",
            "operation_01",
            "1.2.2",
            &"a".repeat(64),
            &"b".repeat(64),
            "1.2.3",
            &format!("sha256:{}", "c".repeat(64)),
            &"d".repeat(64),
            &"e".repeat(64),
            1_800_000_000_000,
            "signed-authority",
        )
        .expect("升级授权有效");

        assert_eq!(request.transition(), LifecycleTransition::Upgrade);
        assert_eq!(
            LifecycleRequest::decode(&request.encode().unwrap()),
            Ok(request)
        );
    }

    #[test]
    fn replacement_migration_authority_roundtrips_as_one_bounded_request() {
        let request = LifecycleRequest::replacement_migration(
            &crate::handoff::Enrollment::from_install_input(
                "https://hub.example",
                br#"{"hubOrigin":"https://hub.example","enrollmentToken":"enk_enroll_test","replacementMigration":{"enrollmentId":"enr_0123456789abcdef","expectedProbeId":"probe_old_01","sourceProbeSha256":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"sourceProbeVersion":"1.2.2","targetAssetSetDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","targetHostId":"7","targetProbeVersion":"1.2.3"},"schemaVersion":1}"#,
            )
            .unwrap(),
            &format!("sha256:{}", "a".repeat(64)),
            "x86_64-unknown-linux-gnu",
            &"b".repeat(64),
            "1.2.3",
        )
        .unwrap();
        let encoded = request.encode().unwrap();

        assert!(encoded.len() <= MAX_LIFECYCLE_REQUEST_BYTES);
        assert_eq!(LifecycleRequest::decode(&encoded), Ok(request));
    }

    #[test]
    fn local_repair_authority_binds_installed_receipt_and_nonroot_invoking_admin() {
        let request = LifecycleRequest::local_repair(
            "probe_01",
            &"a".repeat(64),
            &"b".repeat(64),
            "1.2.3",
            1000,
            1000,
        )
        .unwrap();
        assert_eq!(request.transition(), LifecycleTransition::Repair);
        assert_eq!(
            LifecycleRequest::decode(&request.encode().unwrap()),
            Ok(request)
        );
        assert_eq!(
            LifecycleRequest::local_repair(
                "probe_01",
                &"a".repeat(64),
                &"b".repeat(64),
                "1.2.3",
                0,
                1000,
            ),
            Err(LifecycleRejection::InvalidAuthority)
        );
    }

    #[test]
    fn repair_evidence_matches_the_hub_known_vector() {
        let evidence = RepairEvidenceV1 {
            schema_version: 1,
            hub_origin: "https://hub.example".to_owned(),
            host_id: "7".to_owned(),
            probe_id: "probe_01".to_owned(),
            failed_operation_id: "41".to_owned(),
            failed_authority_sha256: "b".repeat(64),
            journal_sha256: "c".repeat(64),
            journal_phase: "repair-required".to_owned(),
            activated_targets: 3,
            finalized_targets: 0,
            target_bundle_version: "1.2.4".to_owned(),
            target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
            target_manifest_sha256: "d".repeat(64),
            verified_stage_sha256: "e".repeat(64),
            issued_at_ms: 1_725_000_001_000,
            expires_at_ms: 1_725_000_061_000,
            request_nonce: "request_nonce_01".to_owned(),
        };
        assert_eq!(
            evidence.sign(&[0x11; 32]),
            "2010c4ef8f227628ce5c3ba568e3ddbe33d9e582bed425d46f7095d2d0147d82"
        );
    }

    #[test]
    fn installed_bundle_bindings_are_typed_without_changing_canonical_wire_order() {
        let evidence = InstalledBundleFailureEvidenceV1 {
            kind: "installed_bundle_failure".into(),
            schema_version: 1,
            hub_origin: "https://hub.example".into(),
            host_id: "7".into(),
            probe_id: "probe_01".into(),
            generation: "a".repeat(64),
            boot_id: "boot-01".into(),
            unit: "enoki-observation-runtime.service".into(),
            unit_sha256: "b".repeat(64),
            identity_receipt_sha256: "c".repeat(64),
            install_state_sha256: "d".repeat(64),
            manifest_sha256: "e".repeat(64),
            bundle_version: "1.2.3".into(),
            issued_at_ms: 10,
            expires_at_ms: 20,
            request_nonce: "request-01".into(),
        };
        let expected = format!(
            "{{\"kind\":\"installed_bundle_failure\",\"schemaVersion\":1,\"hubOrigin\":\"https://hub.example\",\"hostId\":\"7\",\"probeId\":\"probe_01\",\"generation\":\"{}\",\"bootId\":\"boot-01\",\"unit\":\"enoki-observation-runtime.service\",\"unitSha256\":\"{}\",\"identityReceiptSha256\":\"{}\",\"installStateSha256\":\"{}\",\"manifestSha256\":\"{}\",\"bundleVersion\":\"1.2.3\",\"issuedAtMs\":10,\"expiresAtMs\":20,\"requestNonce\":\"request-01\"}}",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
        );
        assert_eq!(evidence.canonical_bytes(), expected.as_bytes());

        let bindings = evidence.bindings();
        assert_eq!(bindings, evidence.bindings());
        let mut changed = evidence.clone();
        changed.boot_id = "boot-02".into();
        assert_ne!(bindings, changed.bindings());
    }

    #[test]
    fn lifecycle_request_round_trip_is_canonical_and_bound_to_fixed_authority_facts() {
        let request = LifecycleRequest::hub_uninstall(
            "probe_01",
            "operation_01",
            "opaque-operation-token",
            &"a".repeat(64),
            &"b".repeat(64),
            "1.2.3",
        )
        .expect("授权事实有效");
        let encoded = request.encode().expect("编码");

        assert_eq!(LifecycleRequest::decode(&encoded), Ok(request));
    }

    #[test]
    fn lifecycle_request_rejects_unbound_or_noncanonical_authority() {
        let invalid = format!(
            "{{\"schemaVersion\":1,\"transition\":\"uninstall\",\"authority\":{{\"kind\":\"hub-operation\",\"probe_id\":\"probe_01\",\"operationId\":\"operation_01\",\"operationToken\":\"token\",\"installStateSha256\":\"{}\",\"targetManifestSha256\":\"{}\",\"bundleVersion\":\"1.2.3\"}}}}",
            "a".repeat(64),
            "b".repeat(64),
        );
        assert_eq!(
            LifecycleRequest::decode(invalid.as_bytes()),
            Err(LifecycleRejection::InvalidAuthority),
        );
    }

    #[test]
    fn upgrade_runner_distinguishes_preactivation_failure_from_repair_required() {
        struct Effects {
            calls: Vec<&'static str>,
            fail: Option<&'static str>,
        }
        impl UpgradeLifecycleEffects for Effects {
            type Error = &'static str;
            fn verify_and_prepare(&mut self) -> Result<(), Self::Error> {
                self.calls.push("verify-and-prepare");
                (self.fail != Some("verify-and-prepare"))
                    .then_some(())
                    .ok_or("upgrade-failed")
            }
            fn activate_complete_bundle(
                &mut self,
            ) -> Result<(), UpgradeActivationFailure<Self::Error>> {
                self.calls.push("activate-complete-bundle");
                (self.fail != Some("activate-complete-bundle"))
                    .then_some(())
                    .ok_or(UpgradeActivationFailure::Postactivation("upgrade-failed"))
            }
        }

        let mut before = Effects {
            calls: Vec::new(),
            fail: Some("verify-and-prepare"),
        };
        assert_eq!(
            execute_upgrade_lifecycle(&mut before),
            Err("upgrade-failed")
        );
        assert_eq!(before.calls, ["verify-and-prepare"]);

        let mut after = Effects {
            calls: Vec::new(),
            fail: Some("activate-complete-bundle"),
        };
        assert_eq!(
            execute_upgrade_lifecycle(&mut after),
            Ok(UpgradeCompletion::RepairRequired)
        );
        assert_eq!(
            after.calls,
            ["verify-and-prepare", "activate-complete-bundle"]
        );
    }
}

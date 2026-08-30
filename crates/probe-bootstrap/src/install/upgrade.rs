use super::*;
use crate::lifecycle::{
    RepairAuthorityV1, RepairEligibilityV1, RepairEvidenceV1, UpgradeActivationFailure,
    UpgradeCompletion, UpgradeLifecycleEffects, execute_upgrade_lifecycle,
    verify_lifecycle_upgrade_authority_signature,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::os::fd::AsRawFd;

const UPGRADE_ATTEMPT_FILE: &str = "probe-upgrade-attempt.toml";
const OPERATION_STATUS_FILE: &str = "probe-operation-status.toml";
const REPAIR_ATTEMPT_FILE: &str = "probe-repair-attempt.toml";
const REPAIR_CAPSULE_SIGNING_DOMAIN: &[u8] = b"enoki/lifecycle-repair-capsule/hmac-sha256/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRepairEvidence {
    pub evidence: RepairEvidenceV1,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRepairEligibility {
    pub evidence: RepairEligibilityV1,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedRepairAuthority {
    pub repair_operation_id: String,
    pub failed_operation_id: String,
    pub probe_id: String,
    pub target_bundle_version: String,
    pub state: RepairIntentState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairIntentState {
    Consumed,
    CompletionPending,
}

const MAX_REPAIR_CANONICAL_BYTES: usize = 8 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepairCapsuleMacV1<'a> {
    schema_version: u16,
    repair_operation_id: &'a str,
    failed_operation_id: &'a str,
    repair_nonce: &'a str,
    repair_evidence_sha256: &'a str,
    repair_authority_sha256: &'a str,
    evidence_canonical_hex: &'a str,
    evidence_signature: &'a str,
    authority_canonical_hex: &'a str,
    authority_signature: &'a str,
    state: &'a str,
}

pub fn resume_probe_repair_intent(
    paths: &FixedInstallPaths,
) -> Result<Option<ConsumedRepairAuthority>, InstallError> {
    let repair_journal = paths.bootstrap_state().join(REPAIR_ATTEMPT_FILE);
    if !repair_journal.exists() {
        return Ok(None);
    }
    let (capsule, install_key) = read_verified_repair_capsule(paths)?;
    let state = journal_string(&capsule, "state")?;
    if matches!(state, "completed" | "unresolved") {
        return Ok(None);
    }
    let state = match state {
        "consumed" => RepairIntentState::Consumed,
        "completion-pending" => RepairIntentState::CompletionPending,
        _ => return Err(InstallError::ExistingResidue),
    };
    let evidence_bytes = decode_bounded_hex(
        journal_string(&capsule, "evidence_canonical_hex")?,
        MAX_REPAIR_CANONICAL_BYTES,
    )?;
    let authority_bytes = decode_bounded_hex(
        journal_string(&capsule, "authority_canonical_hex")?,
        MAX_REPAIR_CANONICAL_BYTES,
    )?;
    let evidence: RepairEvidenceV1 =
        serde_json::from_slice(&evidence_bytes).map_err(|_| InstallError::ExistingResidue)?;
    let authority: RepairAuthorityV1 =
        serde_json::from_slice(&authority_bytes).map_err(|_| InstallError::ExistingResidue)?;
    if evidence.canonical_bytes() != evidence_bytes
        || authority.canonical_bytes() != authority_bytes
        || evidence.sha256() != journal_string(&capsule, "repair_evidence_sha256")?
        || format!("{:x}", Sha256::digest(&authority_bytes))
            != journal_string(&capsule, "repair_authority_sha256")?
        || authority.repair_operation_id != journal_string(&capsule, "repair_operation_id")?
        || authority.failed_operation_id != journal_string(&capsule, "failed_operation_id")?
        || authority.repair_nonce != journal_string(&capsule, "repair_nonce")?
        || authority.repair_evidence_sha256 != evidence.sha256()
        || authority.hub_origin != evidence.hub_origin
        || authority.host_id != evidence.host_id
        || authority.probe_id != evidence.probe_id
        || authority.failed_operation_id != evidence.failed_operation_id
        || authority.target_bundle_version != evidence.target_bundle_version
        || authority.target_asset_set_digest != evidence.target_asset_set_digest
        || authority.target_manifest_sha256 != evidence.target_manifest_sha256
        || authority.verified_stage_sha256 != evidence.verified_stage_sha256
    {
        return Err(InstallError::ExistingResidue);
    }
    if !evidence.verify(
        &install_key,
        journal_string(&capsule, "evidence_signature")?,
    ) || !authority.verify(
        &install_key,
        journal_string(&capsule, "authority_signature")?,
    ) {
        return Err(InstallError::ExistingResidue);
    }
    Ok(Some(ConsumedRepairAuthority {
        repair_operation_id: authority.repair_operation_id,
        failed_operation_id: authority.failed_operation_id,
        probe_id: authority.probe_id,
        target_bundle_version: authority.target_bundle_version,
        state,
    }))
}

pub fn consume_probe_repair_authority(
    paths: &FixedInstallPaths,
    evidence: &RepairEvidenceV1,
    evidence_signature: &str,
    authority: &RepairAuthorityV1,
    authority_signature: &str,
    now_ms: u64,
) -> Result<ConsumedRepairAuthority, InstallError> {
    if authority.schema_version != 1
        || authority.expires_at_ms <= now_ms
        || !valid_upgrade_identifier(&authority.repair_operation_id)
        || !valid_upgrade_identifier(&authority.repair_nonce)
    {
        return Err(InstallError::ExistingResidue);
    }
    let metadata = trusted_text(&paths.metadata(), paths.expected_root_uid(), 0o600)?;
    let install_key = metadata_string(&metadata, "lifecycle_authority_install_key")
        .as_deref()
        .and_then(decode_lower_sha256)
        .ok_or(InstallError::ExistingResidue)?;
    let current = issue_probe_repair_evidence(
        paths,
        evidence.issued_at_ms,
        evidence.expires_at_ms,
        &evidence.request_nonce,
    )?;
    if current.evidence != *evidence
        || current.signature != evidence_signature
        || !evidence.verify(&install_key, evidence_signature)
        || !authority.verify(&install_key, authority_signature)
        || authority.hub_origin != evidence.hub_origin
        || authority.host_id != evidence.host_id
        || authority.probe_id != evidence.probe_id
        || authority.failed_operation_id != evidence.failed_operation_id
        || authority.repair_evidence_sha256 != evidence.sha256()
        || authority.target_bundle_version != evidence.target_bundle_version
        || authority.target_asset_set_digest != evidence.target_asset_set_digest
        || authority.target_manifest_sha256 != evidence.target_manifest_sha256
        || authority.verified_stage_sha256 != evidence.verified_stage_sha256
    {
        return Err(InstallError::ExistingResidue);
    }
    let repair_journal = paths.bootstrap_state().join(REPAIR_ATTEMPT_FILE);
    if repair_journal.exists() {
        let (prior, _) = read_verified_repair_capsule(paths)?;
        let same = journal_string(&prior, "repair_operation_id")? == authority.repair_operation_id
            && journal_string(&prior, "repair_nonce")? == authority.repair_nonce
            && journal_string(&prior, "repair_evidence_sha256")?
                == authority.repair_evidence_sha256;
        if same && journal_string(&prior, "state")? == "consumed" {
            let consumed = ConsumedRepairAuthority {
                repair_operation_id: authority.repair_operation_id.clone(),
                failed_operation_id: authority.failed_operation_id.clone(),
                probe_id: authority.probe_id.clone(),
                target_bundle_version: authority.target_bundle_version.clone(),
                state: RepairIntentState::Consumed,
            };
            write_repair_running_status(paths, &consumed)?;
            return Ok(consumed);
        }
        if same || !matches!(journal_string(&prior, "state")?, "completed" | "unresolved") {
            return Err(InstallError::ExistingResidue);
        }
    }
    let authority_sha256 = format!("{:x}", Sha256::digest(authority.canonical_bytes()));
    let capsule = format!(
        "schema_version = 2\nrepair_operation_id = {:?}\nfailed_operation_id = {:?}\nrepair_nonce = {:?}\nrepair_evidence_sha256 = {:?}\nrepair_authority_sha256 = {:?}\nevidence_canonical_hex = {:?}\nevidence_signature = {:?}\nauthority_canonical_hex = {:?}\nauthority_signature = {:?}\nstate = \"consumed\"\n",
        authority.repair_operation_id,
        authority.failed_operation_id,
        authority.repair_nonce,
        authority.repair_evidence_sha256,
        authority_sha256,
        encode_lower_hex(&evidence.canonical_bytes()),
        evidence_signature,
        encode_lower_hex(&authority.canonical_bytes()),
        authority_signature,
    );
    atomic_durable_write(
        &repair_journal,
        &signed_repair_capsule(&capsule, &install_key)?,
        0o600,
    )?;
    let consumed = ConsumedRepairAuthority {
        repair_operation_id: authority.repair_operation_id.clone(),
        failed_operation_id: authority.failed_operation_id.clone(),
        probe_id: authority.probe_id.clone(),
        target_bundle_version: authority.target_bundle_version.clone(),
        state: RepairIntentState::Consumed,
    };
    if write_repair_running_status(paths, &consumed).is_err() {
        transition_repair_state(paths, &consumed, &["consumed"], "unresolved")?;
        return Err(InstallError::Io);
    }
    Ok(consumed)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_bounded_hex(value: &str, max_bytes: usize) -> Result<Vec<u8>, InstallError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > max_bytes.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(InstallError::ExistingResidue);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char)
                .to_digit(16)
                .ok_or(InstallError::ExistingResidue)?;
            let low = (pair[1] as char)
                .to_digit(16)
                .ok_or(InstallError::ExistingResidue)?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

fn read_verified_repair_capsule(
    paths: &FixedInstallPaths,
) -> Result<(String, [u8; 32]), InstallError> {
    let metadata = trusted_text(&paths.metadata(), paths.expected_root_uid(), 0o600)?;
    let install_key = metadata_string(&metadata, "lifecycle_authority_install_key")
        .as_deref()
        .and_then(decode_lower_sha256)
        .ok_or(InstallError::ExistingResidue)?;
    let capsule = trusted_text(
        &paths.bootstrap_state().join(REPAIR_ATTEMPT_FILE),
        paths.expected_root_uid(),
        0o600,
    )?;
    let expected = decode_lower_sha256(journal_string(&capsule, "capsule_mac")?)
        .ok_or(InstallError::ExistingResidue)?;
    let mut verifier = Hmac::<Sha256>::new_from_slice(&install_key)
        .expect("HMAC accepts the fixed lifecycle install key");
    verifier.update(REPAIR_CAPSULE_SIGNING_DOMAIN);
    verifier.update(&repair_capsule_mac_canonical(&capsule)?);
    verifier
        .verify_slice(&expected)
        .map_err(|_| InstallError::ExistingResidue)?;
    Ok((capsule, install_key))
}

fn repair_capsule_mac_canonical(capsule: &str) -> Result<Vec<u8>, InstallError> {
    const REQUIRED_KEYS: [&str; 11] = [
        "schema_version",
        "repair_operation_id",
        "failed_operation_id",
        "repair_nonce",
        "repair_evidence_sha256",
        "repair_authority_sha256",
        "evidence_canonical_hex",
        "evidence_signature",
        "authority_canonical_hex",
        "authority_signature",
        "state",
    ];
    let mut seen = std::collections::BTreeSet::new();
    for line in capsule.lines() {
        let (key, _) = line
            .split_once(" = ")
            .ok_or(InstallError::ExistingResidue)?;
        if (!REQUIRED_KEYS.contains(&key) && key != "capsule_mac") || !seen.insert(key) {
            return Err(InstallError::ExistingResidue);
        }
    }
    if !REQUIRED_KEYS.iter().all(|key| seen.contains(key)) || !matches!(seen.len(), 11 | 12) {
        return Err(InstallError::ExistingResidue);
    }
    if metadata_scalar(capsule, "schema_version").as_deref() != Some("2") {
        return Err(InstallError::ExistingResidue);
    }
    serde_json::to_vec(&RepairCapsuleMacV1 {
        schema_version: 2,
        repair_operation_id: journal_string(capsule, "repair_operation_id")?,
        failed_operation_id: journal_string(capsule, "failed_operation_id")?,
        repair_nonce: journal_string(capsule, "repair_nonce")?,
        repair_evidence_sha256: journal_string(capsule, "repair_evidence_sha256")?,
        repair_authority_sha256: journal_string(capsule, "repair_authority_sha256")?,
        evidence_canonical_hex: journal_string(capsule, "evidence_canonical_hex")?,
        evidence_signature: journal_string(capsule, "evidence_signature")?,
        authority_canonical_hex: journal_string(capsule, "authority_canonical_hex")?,
        authority_signature: journal_string(capsule, "authority_signature")?,
        state: journal_string(capsule, "state")?,
    })
    .map_err(|_| InstallError::ExistingResidue)
}

fn signed_repair_capsule(
    capsule_without_mac: &str,
    key: &[u8; 32],
) -> Result<Vec<u8>, InstallError> {
    if capsule_without_mac
        .lines()
        .any(|line| line.starts_with("capsule_mac = "))
    {
        return Err(InstallError::ExistingResidue);
    }
    let mut signer =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts the fixed lifecycle install key");
    signer.update(REPAIR_CAPSULE_SIGNING_DOMAIN);
    signer.update(&repair_capsule_mac_canonical(capsule_without_mac)?);
    let mac = encode_lower_hex(&signer.finalize().into_bytes());
    Ok(format!("{capsule_without_mac}capsule_mac = {mac:?}\n").into_bytes())
}

fn write_repair_running_status(
    paths: &FixedInstallPaths,
    consumed: &ConsumedRepairAuthority,
) -> Result<(), InstallError> {
    write_operation_status(
        paths,
        &UpgradeAttempt {
            operation_id: consumed.repair_operation_id.clone(),
            stage_owner_uid: 0,
            authority_sha256: None,
        },
        &consumed.target_bundle_version,
        "running",
        None,
    )
}

pub fn mark_probe_repair_unresolved(
    paths: &FixedInstallPaths,
    consumed: &ConsumedRepairAuthority,
) -> Result<(), InstallError> {
    let (current, _) = read_verified_repair_capsule(paths)?;
    if journal_string(&current, "repair_operation_id")? != consumed.repair_operation_id {
        return Err(InstallError::ExistingResidue);
    }
    let state = journal_string(&current, "state")?;
    if state == "consumed" {
        transition_repair_state(paths, consumed, &["consumed"], "unresolved")?;
    } else if state != "unresolved" {
        return Err(InstallError::ExistingResidue);
    }
    write_operation_status(
        paths,
        &UpgradeAttempt {
            operation_id: consumed.repair_operation_id.clone(),
            stage_owner_uid: 0,
            authority_sha256: None,
        },
        &consumed.target_bundle_version,
        "failed",
        Some("lifecycle.repair_unresolved"),
    )
}

pub fn persist_probe_repair_execution_failure(
    paths: &FixedInstallPaths,
    consumed: &ConsumedRepairAuthority,
) -> Result<(), InstallError> {
    let persisted = resume_probe_repair_intent(paths)?.ok_or(InstallError::ExistingResidue)?;
    if persisted.repair_operation_id != consumed.repair_operation_id {
        return Err(InstallError::ExistingResidue);
    }
    if persisted.state == RepairIntentState::CompletionPending {
        return Ok(());
    }
    if repair_upgrade_is_exactly_activated(paths, &persisted)? {
        return Ok(());
    }
    mark_probe_repair_unresolved(paths, &persisted)
}

pub fn execute_authorized_probe_repair(
    paths: &FixedInstallPaths,
    consumed: &ConsumedRepairAuthority,
    systemd: &mut impl SystemdPort,
    mut cleanup_verified_stage: impl FnMut(&str, u32) -> Result<(), InstallError>,
) -> Result<(), InstallError> {
    let persisted = resume_probe_repair_intent(paths)?.ok_or(InstallError::ExistingResidue)?;
    if persisted != *consumed || persisted.state != RepairIntentState::Consumed {
        return Err(InstallError::ExistingResidue);
    }
    let recovered = recover_incomplete_probe_upgrade_for_repair(paths, systemd)?;
    match recovered {
        Some(receipt) => {
            if receipt.operation_id != consumed.failed_operation_id
                || receipt.probe_id != consumed.probe_id
                || receipt.target_bundle_version != consumed.target_bundle_version
                || !receipt.activated
            {
                return Err(InstallError::ExistingResidue);
            }
            cleanup_verified_stage(&receipt.operation_id, receipt.stage_owner_uid)?;
            finalize_probe_repair_stage_cleanup(paths, &receipt)?;
        }
        None if !repair_upgrade_is_exactly_activated(paths, consumed)? => {
            return Err(InstallError::ExistingResidue);
        }
        None => {}
    }
    transition_repair_state(paths, consumed, &["consumed"], "completion-pending")?;
    let pending = ConsumedRepairAuthority {
        state: RepairIntentState::CompletionPending,
        ..consumed.clone()
    };
    complete_authorized_probe_repair(paths, &pending)
}

pub fn complete_authorized_probe_repair(
    paths: &FixedInstallPaths,
    pending: &ConsumedRepairAuthority,
) -> Result<(), InstallError> {
    let persisted = resume_probe_repair_intent(paths)?.ok_or(InstallError::ExistingResidue)?;
    if persisted != *pending || persisted.state != RepairIntentState::CompletionPending {
        return Err(InstallError::ExistingResidue);
    }
    let repair_attempt = UpgradeAttempt {
        operation_id: pending.repair_operation_id.clone(),
        stage_owner_uid: 0,
        authority_sha256: None,
    };
    write_operation_status(
        paths,
        &repair_attempt,
        &pending.target_bundle_version,
        "running",
        None,
    )?;
    transition_repair_state(paths, pending, &["completion-pending"], "completed")
}

fn repair_upgrade_is_exactly_activated(
    paths: &FixedInstallPaths,
    repair: &ConsumedRepairAuthority,
) -> Result<bool, InstallError> {
    let journal_path = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    if !journal_path.exists() {
        return Ok(false);
    }
    let contents = trusted_text(&journal_path, paths.expected_root_uid(), 0o600)?;
    if journal_string(&contents, "operation_id")? != repair.failed_operation_id
        || journal_string(&contents, "source_probe_id")? != repair.probe_id
        || journal_string(&contents, "target_bundle_version")? != repair.target_bundle_version
        || journal_string(&contents, "phase")? != "activated"
    {
        return Ok(false);
    }
    let target_count = upgrade_destinations(paths).len();
    Ok(
        journal_usize(&contents, "activated_targets")? == target_count
            && journal_usize(&contents, "finalized_targets")? == target_count,
    )
}

fn transition_repair_state(
    paths: &FixedInstallPaths,
    consumed: &ConsumedRepairAuthority,
    expected: &[&str],
    next: &str,
) -> Result<(), InstallError> {
    let repair_journal = paths.bootstrap_state().join(REPAIR_ATTEMPT_FILE);
    let (current, install_key) = read_verified_repair_capsule(paths)?;
    if journal_string(&current, "repair_operation_id")? != consumed.repair_operation_id {
        return Err(InstallError::ExistingResidue);
    }
    let state = journal_string(&current, "state")?;
    if !expected.contains(&state) {
        return Err(InstallError::ExistingResidue);
    }
    if !matches!(
        (state, next),
        ("consumed", "unresolved" | "completion-pending") | ("completion-pending", "completed")
    ) {
        return Err(InstallError::ExistingResidue);
    }
    let mut replacement_count = 0;
    let mut unsigned = String::new();
    for line in current.lines() {
        if line.starts_with("capsule_mac = ") {
            replacement_count += 1;
        } else if line == format!("state = {state:?}") {
            replacement_count += 1;
            unsigned.push_str(&format!("state = {next:?}\n"));
        } else {
            unsigned.push_str(line);
            unsigned.push('\n');
        }
    }
    if replacement_count != 2 {
        return Err(InstallError::ExistingResidue);
    }
    atomic_durable_write(
        &repair_journal,
        &signed_repair_capsule(&unsigned, &install_key)?,
        0o600,
    )
}

pub fn issue_probe_repair_evidence(
    paths: &FixedInstallPaths,
    issued_at_ms: u64,
    expires_at_ms: u64,
    request_nonce: &str,
) -> Result<SignedRepairEvidence, InstallError> {
    if expires_at_ms <= issued_at_ms
        || expires_at_ms - issued_at_ms > 120_000
        || !valid_upgrade_identifier(request_nonce)
    {
        return Err(InstallError::ExistingResidue);
    }
    let eligibility = repair_eligibility_from_postactivation_journal(paths)?;
    let metadata = trusted_text(&paths.metadata(), paths.expected_root_uid(), 0o600)?;
    let install_key = metadata_string(&metadata, "lifecycle_authority_install_key")
        .as_deref()
        .and_then(decode_lower_sha256)
        .ok_or(InstallError::ExistingResidue)?;
    let evidence = RepairEvidenceV1 {
        schema_version: 1,
        hub_origin: eligibility.hub_origin,
        host_id: eligibility.host_id,
        probe_id: eligibility.probe_id,
        failed_operation_id: eligibility.failed_operation_id,
        failed_authority_sha256: eligibility.failed_authority_sha256,
        journal_sha256: eligibility.journal_sha256,
        journal_phase: eligibility.journal_phase,
        activated_targets: eligibility.activated_targets,
        finalized_targets: eligibility.finalized_targets,
        target_bundle_version: eligibility.target_bundle_version,
        target_asset_set_digest: eligibility.target_asset_set_digest,
        target_manifest_sha256: eligibility.target_manifest_sha256,
        verified_stage_sha256: eligibility.verified_stage_sha256,
        issued_at_ms,
        expires_at_ms,
        request_nonce: request_nonce.to_owned(),
    };
    Ok(SignedRepairEvidence {
        signature: evidence.sign(&install_key),
        evidence,
    })
}

pub fn issue_probe_repair_eligibility(
    paths: &FixedInstallPaths,
) -> Result<SignedRepairEligibility, InstallError> {
    let evidence = repair_eligibility_from_postactivation_journal(paths)?;
    let metadata = trusted_text(&paths.metadata(), paths.expected_root_uid(), 0o600)?;
    let install_key = metadata_string(&metadata, "lifecycle_authority_install_key")
        .as_deref()
        .and_then(decode_lower_sha256)
        .ok_or(InstallError::ExistingResidue)?;
    Ok(SignedRepairEligibility {
        signature: evidence.sign(&install_key),
        evidence,
    })
}

fn repair_eligibility_from_postactivation_journal(
    paths: &FixedInstallPaths,
) -> Result<RepairEligibilityV1, InstallError> {
    let state = load_validated_upgrade_attempt(paths)?;
    if !matches!(state.schema_version, 3 | 4) || !state.activation_started {
        return Err(InstallError::ExistingResidue);
    }
    let journal = state.contents;
    let phase = state.phase.as_str();
    if !matches!(
        phase,
        "activation-started" | "repair-required" | "finalizing" | "stage-cleanup-required"
    ) {
        return Err(InstallError::ExistingResidue);
    }
    let activated_targets = state.activated_targets;
    let finalized_targets = state.finalized_targets;
    let authority_scope = state
        .binding
        .authority_scope
        .as_ref()
        .ok_or(InstallError::ExistingResidue)?;
    Ok(RepairEligibilityV1 {
        schema_version: 1,
        hub_origin: authority_scope.hub_origin.clone(),
        host_id: authority_scope.host_id.clone(),
        probe_id: state.binding.source_probe_id.clone(),
        failed_operation_id: state.binding.operation_id.clone(),
        failed_authority_sha256: state.binding.authority_sha256.clone(),
        journal_sha256: format!("{:x}", Sha256::digest(journal.as_bytes())),
        journal_phase: phase.to_owned(),
        activated_targets,
        finalized_targets,
        target_bundle_version: state.binding.target_bundle_version.clone(),
        target_asset_set_digest: authority_scope.target_asset_set_digest.clone(),
        target_manifest_sha256: state.binding.target_manifest_sha256.clone(),
        verified_stage_sha256: authority_scope.verified_stage_sha256.clone(),
    })
}

struct ValidatedUpgradeAttemptJournal {
    contents: String,
    schema_version: u16,
    binding: ValidatedUpgradeAttemptBinding,
    phase: String,
    activation_started: bool,
    activated_targets: usize,
    finalized_targets: usize,
    runtime_failure_consumption: Option<RuntimeFailureConsumption>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RuntimeFailureConsumption {
    None,
    NoneConsumed,
    Bound {
        generation: String,
        epoch_sha256: String,
    },
    EpochRemoved {
        generation: String,
        epoch_sha256: String,
    },
    LatchRemoved {
        generation: String,
        epoch_sha256: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalRetryReceipt {
    schema_version: u16,
    generation: String,
    epoch_sha256: String,
    progress: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedUpgradeAttemptBinding {
    operation_id: String,
    stage_owner_uid: u32,
    authority_sha256: String,
    source_probe_id: String,
    source_bundle_version: String,
    source_install_state_sha256: String,
    source_manifest_sha256: String,
    target_bundle_version: String,
    target_manifest_sha256: String,
    authority_scope: Option<ValidatedUpgradeAuthorityScope>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedUpgradeAuthorityScope {
    hub_origin: String,
    host_id: String,
    target_asset_set_digest: String,
    verified_stage_sha256: String,
}

fn load_validated_upgrade_attempt(
    paths: &FixedInstallPaths,
) -> Result<ValidatedUpgradeAttemptJournal, InstallError> {
    let journal_path = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    let mut contents = trusted_text(&journal_path, paths.expected_root_uid(), 0o600)?;
    let schema_version = metadata_scalar(&contents, "schema_version")
        .as_deref()
        .ok_or(InstallError::ExistingResidue)?
        .parse::<u16>()
        .map_err(|_| InstallError::ExistingResidue)?;
    if !matches!(schema_version, 1..=4) {
        return Err(InstallError::ExistingResidue);
    }
    let operation_id = journal_string(&contents, "operation_id")?.to_owned();
    let stage_owner_uid = journal_usize(&contents, "stage_owner_uid")?
        .try_into()
        .map_err(|_| InstallError::ExistingResidue)?;
    let authority_sha256 = journal_string(&contents, "authority_sha256")?.to_owned();
    let source_probe_id = journal_string(&contents, "source_probe_id")?.to_owned();
    let source_bundle_version = journal_string(&contents, "source_bundle_version")?.to_owned();
    let source_install_state_sha256 =
        journal_string(&contents, "source_install_state_sha256")?.to_owned();
    let source_manifest_sha256 = journal_string(&contents, "source_manifest_sha256")?.to_owned();
    let target_bundle_version = journal_string(&contents, "target_bundle_version")?.to_owned();
    let target_manifest_sha256 = journal_string(&contents, "target_manifest_sha256")?.to_owned();
    if !valid_upgrade_identifier(&operation_id)
        || !valid_upgrade_identifier(&source_probe_id)
        || !valid_sha256(&authority_sha256)
        || !valid_upgrade_version(&source_bundle_version)
        || !valid_upgrade_version(&target_bundle_version)
        || !valid_sha256(&source_install_state_sha256)
        || !valid_sha256(&source_manifest_sha256)
        || !valid_sha256(&target_manifest_sha256)
    {
        return Err(InstallError::ExistingResidue);
    }
    let has_authority_scope = metadata_scalar(&contents, "hub_origin").is_some()
        || metadata_scalar(&contents, "host_id").is_some()
        || metadata_scalar(&contents, "target_asset_set_digest").is_some()
        || metadata_scalar(&contents, "verified_stage_sha256").is_some();
    let authority_scope = if has_authority_scope {
        let hub_origin = journal_string(&contents, "hub_origin")?.to_owned();
        let host_id = journal_string(&contents, "host_id")?.to_owned();
        let target_asset_set_digest =
            journal_string(&contents, "target_asset_set_digest")?.to_owned();
        let verified_stage_sha256 = journal_string(&contents, "verified_stage_sha256")?.to_owned();
        if hub_origin.is_empty()
            || !valid_upgrade_identifier(&host_id)
            || target_asset_set_digest
                .strip_prefix("sha256:")
                .is_none_or(|digest| !valid_sha256(digest))
            || !valid_sha256(&verified_stage_sha256)
        {
            return Err(InstallError::ExistingResidue);
        }
        Some(ValidatedUpgradeAuthorityScope {
            hub_origin,
            host_id,
            target_asset_set_digest,
            verified_stage_sha256,
        })
    } else if schema_version == 2 {
        return Err(InstallError::ExistingResidue);
    } else {
        None
    };
    let binding = ValidatedUpgradeAttemptBinding {
        operation_id,
        stage_owner_uid,
        authority_sha256,
        source_probe_id,
        source_bundle_version,
        source_install_state_sha256,
        source_manifest_sha256,
        target_bundle_version,
        target_manifest_sha256,
        authority_scope,
    };
    let phase = journal_string(&contents, "phase")?.to_owned();
    let activated_targets = journal_usize(&contents, "activated_targets")?;
    let finalized_targets = journal_usize(&contents, "finalized_targets")?;
    let runtime_failure_consumption = if schema_version == 4 {
        let progress = journal_string(&contents, "runtime_failure_consumption")?;
        let generation = metadata_string(&contents, "runtime_failure_generation");
        let epoch_sha256 = metadata_string(&contents, "runtime_failure_epoch_sha256");
        match (progress, generation, epoch_sha256) {
            ("none", None, None) => Some(RuntimeFailureConsumption::None),
            ("none-consumed", None, None) => Some(RuntimeFailureConsumption::NoneConsumed),
            ("bound", Some(generation), Some(epoch_sha256))
                if valid_sha256(&generation) && valid_sha256(&epoch_sha256) =>
            {
                Some(RuntimeFailureConsumption::Bound {
                    generation,
                    epoch_sha256,
                })
            }
            ("epoch-removed", Some(generation), Some(epoch_sha256))
                if valid_sha256(&generation) && valid_sha256(&epoch_sha256) =>
            {
                Some(RuntimeFailureConsumption::EpochRemoved {
                    generation,
                    epoch_sha256,
                })
            }
            ("latch-removed", Some(generation), Some(epoch_sha256))
                if valid_sha256(&generation) && valid_sha256(&epoch_sha256) =>
            {
                Some(RuntimeFailureConsumption::LatchRemoved {
                    generation,
                    epoch_sha256,
                })
            }
            _ => return Err(InstallError::ExistingResidue),
        }
    } else {
        None
    };
    let target_count = upgrade_destinations(paths).len();
    let activation_started = match schema_version {
        3 | 4 => match metadata_scalar(&contents, "activation_started").as_deref() {
            Some("true") => true,
            Some("false") => false,
            _ => return Err(InstallError::ExistingResidue),
        },
        2 => match metadata_scalar(&contents, "activation_started").as_deref() {
            Some("true") => true,
            Some("false") => false,
            None => infer_legacy_activation_started(
                &phase,
                activated_targets,
                finalized_targets,
                target_count,
            )?,
            _ => return Err(InstallError::ExistingResidue),
        },
        1 => infer_legacy_activation_started(
            &phase,
            activated_targets,
            finalized_targets,
            target_count,
        )?,
        _ => unreachable!(),
    };
    validate_upgrade_attempt_tuple(
        &phase,
        activation_started,
        activated_targets,
        finalized_targets,
        target_count,
    )?;
    if runtime_failure_consumption
        .as_ref()
        .is_some_and(|consumption| !runtime_failure_consumption_matches_phase(consumption, &phase))
    {
        return Err(InstallError::ExistingResidue);
    }
    if schema_version == 2 {
        let mut migrated = contents.replacen("schema_version = 2", "schema_version = 3", 1);
        if metadata_scalar(&contents, "activation_started").is_none() {
            migrated = migrated.replacen(
                &format!("phase = {phase:?}\n"),
                &format!("phase = {phase:?}\nactivation_started = {activation_started}\n"),
                1,
            );
        }
        if migrated == contents {
            return Err(InstallError::ExistingResidue);
        }
        atomic_durable_write(&journal_path, migrated.as_bytes(), 0o600)?;
        contents = migrated;
    }
    Ok(ValidatedUpgradeAttemptJournal {
        contents,
        schema_version: if schema_version == 2 {
            3
        } else {
            schema_version
        },
        binding,
        phase,
        activation_started,
        activated_targets,
        finalized_targets,
        runtime_failure_consumption,
    })
}

fn runtime_failure_consumption_matches_phase(
    consumption: &RuntimeFailureConsumption,
    phase: &str,
) -> bool {
    match consumption {
        RuntimeFailureConsumption::None | RuntimeFailureConsumption::Bound { .. } => matches!(
            phase,
            "consumed"
                | "admitted"
                | "prepared"
                | "aborted"
                | "activation-started"
                | "repair-required"
        ),
        RuntimeFailureConsumption::EpochRemoved { .. } => {
            matches!(phase, "activation-started" | "repair-required")
        }
        RuntimeFailureConsumption::NoneConsumed
        | RuntimeFailureConsumption::LatchRemoved { .. } => matches!(
            phase,
            "activation-started"
                | "repair-required"
                | "finalizing"
                | "stage-cleanup-required"
                | "activated"
        ),
    }
}

fn infer_legacy_activation_started(
    phase: &str,
    activated: usize,
    finalized: usize,
    target_count: usize,
) -> Result<bool, InstallError> {
    match phase {
        "consumed" | "admitted" | "prepared" | "aborted" => Ok(false),
        "activation-started" => Ok(true),
        "finalizing" | "stage-cleanup-required" | "activated" => Ok(true),
        "repair-required" if activated > 0 || finalized > 0 => Ok(true),
        "repair-required" => Err(InstallError::ExistingResidue),
        _ => {
            let _ = target_count;
            Err(InstallError::ExistingResidue)
        }
    }
}

fn validate_upgrade_attempt_tuple(
    phase: &str,
    activation_started: bool,
    activated: usize,
    finalized: usize,
    target_count: usize,
) -> Result<(), InstallError> {
    if finalized > activated || activated > target_count {
        return Err(InstallError::ExistingResidue);
    }
    let valid = match phase {
        "consumed" | "admitted" | "prepared" | "aborted" => {
            !activation_started && activated == 0 && finalized == 0
        }
        "activation-started" => activation_started && finalized == 0,
        "repair-required" => activation_started,
        "finalizing" => activation_started && activated == target_count,
        "stage-cleanup-required" | "activated" => {
            activation_started && activated == target_count && finalized == target_count
        }
        _ => false,
    };
    valid.then_some(()).ok_or(InstallError::ExistingResidue)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeAttempt {
    pub operation_id: String,
    pub stage_owner_uid: u32,
    pub authority_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeAuthorityConsumption {
    pub operation_id: String,
    pub stage_owner_uid: u32,
    pub hub_origin: String,
    pub host_id: String,
    pub probe_id: String,
    pub source_bundle_version: String,
    pub source_install_state_sha256: String,
    pub source_manifest_sha256: String,
    pub target_bundle_version: String,
    pub target_asset_set_digest: String,
    pub target_manifest_sha256: String,
    pub verified_stage_sha256: String,
}

#[derive(Debug)]
pub enum ConsumeBeforeOuterError<E> {
    Consume,
    Outer { consumed: UpgradeAttempt, error: E },
}

#[cfg(test)]
pub fn consume_before_upgrade_outer_checks<T, E>(
    paths: &FixedInstallPaths,
    authority: &UpgradeAuthorityConsumption,
    outer_checks: impl FnOnce(&UpgradeAttempt) -> Result<T, E>,
) -> Result<(UpgradeAttempt, T), ConsumeBeforeOuterError<E>> {
    let consumed = consume_probe_upgrade_authority(paths, authority)
        .map_err(|_| ConsumeBeforeOuterError::Consume)?;
    match outer_checks(&consumed) {
        Ok(output) => Ok((consumed, output)),
        Err(error) => Err(ConsumeBeforeOuterError::Outer { consumed, error }),
    }
}

pub fn consume_signed_before_upgrade_outer_checks<T, E>(
    paths: &FixedInstallPaths,
    authority: &UpgradeAuthorityConsumption,
    canonical_authority: &[u8],
    signature_hex: &str,
    outer_checks: impl FnOnce(&UpgradeAttempt) -> Result<T, E>,
) -> Result<(UpgradeAttempt, T), ConsumeBeforeOuterError<E>> {
    let consumed = consume_signed_probe_upgrade_authority(
        paths,
        authority,
        canonical_authority,
        signature_hex,
    )
    .map_err(|_| ConsumeBeforeOuterError::Consume)?;
    match outer_checks(&consumed) {
        Ok(output) => Ok((consumed, output)),
        Err(error) => Err(ConsumeBeforeOuterError::Outer { consumed, error }),
    }
}

fn consume_signed_probe_upgrade_authority(
    paths: &FixedInstallPaths,
    authority: &UpgradeAuthorityConsumption,
    canonical_authority: &[u8],
    signature_hex: &str,
) -> Result<UpgradeAttempt, InstallError> {
    let metadata = trusted_text(&paths.metadata(), paths.expected_root_uid(), 0o600)?;
    let key_hex = metadata_string(&metadata, "lifecycle_authority_install_key")
        .ok_or(InstallError::ExistingResidue)?;
    let install_key = decode_lower_sha256(&key_hex).ok_or(InstallError::ExistingResidue)?;
    if !verify_lifecycle_upgrade_authority_signature(
        &install_key,
        canonical_authority,
        signature_hex,
    ) {
        return Err(InstallError::ExistingResidue);
    }
    consume_probe_upgrade_authority_with_sha256(
        paths,
        authority,
        format!("{:x}", Sha256::digest(canonical_authority)),
    )
}

fn decode_lower_sha256(value: &str) -> Option<[u8; 32]> {
    if !valid_sha256(value) {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        bytes[index] = ((high << 4) | low) as u8;
    }
    Some(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeRecoveryReceipt {
    pub operation_id: String,
    pub probe_id: String,
    pub stage_owner_uid: u32,
    pub source_bundle_version: String,
    pub target_bundle_version: String,
    pub activated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InstalledUpgradeBinding {
    pub hub_origin: String,
    pub probe_id: String,
    pub source_bundle_version: String,
    pub source_install_state_sha256: String,
    pub source_manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledBundleRepairBinding {
    authority: crate::lifecycle::InstalledBundleRepairAuthorityV1,
    stage_operation_id: String,
    stage_target_asset_set_digest: String,
    stage_target_manifest_sha256: String,
    stage_target_version: String,
    verified_stage_sha256: String,
    stage_owner_uid: u32,
}

impl InstalledBundleRepairBinding {
    #[cfg(test)]
    pub(super) fn for_test(
        authority: crate::lifecycle::InstalledBundleRepairAuthorityV1,
        stage_owner_uid: u32,
    ) -> Self {
        Self {
            stage_operation_id: authority.repair_operation_id.clone(),
            stage_target_asset_set_digest: authority.target_asset_set_digest.clone(),
            stage_target_manifest_sha256: authority.manifest_sha256.clone(),
            stage_target_version: authority.bundle_version.clone(),
            verified_stage_sha256: "4".repeat(64),
            authority,
            stage_owner_uid,
        }
    }

    #[cfg(feature = "acquirer")]
    pub fn from_verified_stage(
        authority: &crate::lifecycle::InstalledBundleRepairAuthorityV1,
        stage: &crate::acquisition::VerifiedUpgradeStageReceipt,
        stage_owner_uid: u32,
    ) -> Result<Self, InstallError> {
        if authority.repair_operation_id != stage.operation_id
            || authority.bundle_version != stage.target_version
            || authority.manifest_sha256 != stage.target_manifest_sha256
            || authority.target_asset_set_digest != stage.target_asset_set_digest
            || stage.verified_stage_sha256.len() != 64
            || !stage
                .verified_stage_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(InstallError::ExistingResidue);
        }
        Ok(Self {
            authority: authority.clone(),
            stage_operation_id: stage.operation_id.clone(),
            stage_target_asset_set_digest: stage.target_asset_set_digest.clone(),
            stage_target_manifest_sha256: stage.target_manifest_sha256.clone(),
            stage_target_version: stage.target_version.clone(),
            verified_stage_sha256: stage.verified_stage_sha256.clone(),
            stage_owner_uid,
        })
    }

    pub(super) fn binding_sha256(
        &self,
        installed: &InstalledUpgradeBinding,
        bundle: &VerifiedBundle,
        paths: &FixedInstallPaths,
    ) -> Result<String, InstallError> {
        let identity_metadata =
            fs::symlink_metadata(paths.identity()).map_err(|_| InstallError::ExistingResidue)?;
        let identity = trusted_text(&paths.identity(), identity_metadata.uid(), 0o600)?;
        let identity_host_id = metadata_string(&identity, "host_id")
            .filter(|value| !value.is_empty())
            .ok_or(InstallError::ExistingResidue)?;
        let identity_receipt_sha256 = format!("{:x}", Sha256::digest(identity.as_bytes()));
        if self.authority.repair_operation_id != self.stage_operation_id
            || self.authority.hub_origin != installed.hub_origin
            || self.authority.host_id != identity_host_id
            || self.authority.identity_receipt_sha256 != identity_receipt_sha256
            || self.authority.probe_id != installed.probe_id
            || self.authority.bundle_version != installed.source_bundle_version
            || self.authority.install_state_sha256 != installed.source_install_state_sha256
            || self.authority.manifest_sha256 != installed.source_manifest_sha256
            || self.authority.bundle_version != bundle.version
            || self.authority.manifest_sha256 != bundle.manifest_sha256
            || self.stage_target_version != bundle.version
            || self.stage_target_manifest_sha256 != bundle.manifest_sha256
            || self.stage_target_asset_set_digest
                != format!("sha256:{}", bundle.asset_set_manifest_sha256)
            || self.authority.target_asset_set_digest != self.stage_target_asset_set_digest
        {
            return Err(InstallError::ExistingResidue);
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Binding<'a> {
            authority: &'a crate::lifecycle::InstalledBundleRepairAuthorityV1,
            stage_operation_id: &'a str,
            stage_target_asset_set_digest: &'a str,
            stage_target_manifest_sha256: &'a str,
            stage_target_version: &'a str,
            verified_stage_sha256: &'a str,
            stage_owner_uid: u32,
            installed: &'a InstalledUpgradeBinding,
            bundle_version: &'a str,
            bundle_manifest_sha256: &'a str,
            bundle_asset_set_sha256: &'a str,
            bundle_install_state_sha256: String,
            identity_host_id: &'a str,
            identity_receipt_sha256: &'a str,
        }
        serde_json::to_vec(&Binding {
            authority: &self.authority,
            stage_operation_id: &self.stage_operation_id,
            stage_target_asset_set_digest: &self.stage_target_asset_set_digest,
            stage_target_manifest_sha256: &self.stage_target_manifest_sha256,
            stage_target_version: &self.stage_target_version,
            verified_stage_sha256: &self.verified_stage_sha256,
            stage_owner_uid: self.stage_owner_uid,
            installed,
            bundle_version: &bundle.version,
            bundle_manifest_sha256: &bundle.manifest_sha256,
            bundle_asset_set_sha256: &bundle.asset_set_manifest_sha256,
            bundle_install_state_sha256: bundle.install_state_sha256(),
            identity_host_id: &identity_host_id,
            identity_receipt_sha256: &identity_receipt_sha256,
        })
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|_| InstallError::Io)
    }

    pub(super) fn retirement_binding_sha256(&self) -> Result<String, InstallError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct RetirementBinding<'a> {
            authority: &'a crate::lifecycle::InstalledBundleRepairAuthorityV1,
            stage_operation_id: &'a str,
            stage_target_asset_set_digest: &'a str,
            stage_target_manifest_sha256: &'a str,
            stage_target_version: &'a str,
            verified_stage_sha256: &'a str,
            stage_owner_uid: u32,
        }
        serde_json::to_vec(&RetirementBinding {
            authority: &self.authority,
            stage_operation_id: &self.stage_operation_id,
            stage_target_asset_set_digest: &self.stage_target_asset_set_digest,
            stage_target_manifest_sha256: &self.stage_target_manifest_sha256,
            stage_target_version: &self.stage_target_version,
            verified_stage_sha256: &self.verified_stage_sha256,
            stage_owner_uid: self.stage_owner_uid,
        })
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|_| InstallError::Io)
    }

    #[cfg(test)]
    pub(super) fn with_test_repair_nonce(mut self, nonce: &str) -> Self {
        self.authority.repair_nonce = nonce.to_owned();
        self
    }
}

pub struct VerifiedUpgradeComponents<'a> {
    pub probe: &'a mut File,
    pub observation_runtime: &'a mut File,
    pub system_state_provider: &'a mut File,
    pub disk_health_provider: &'a mut File,
    pub lifecycle_companion: &'a mut File,
    pub bootstrap_acquirer: &'a mut File,
    pub bootstrap_activator: &'a mut File,
}

pub fn inspect_installed_probe_for_upgrade(
    paths: &FixedInstallPaths,
) -> Result<InstalledUpgradeBinding, InstallError> {
    let (metadata, identity) = trusted_complete_installed_layout(paths)?;
    let field = |name: &str| {
        metadata_string(&metadata, name)
            .filter(|value| !value.is_empty())
            .ok_or(InstallError::ExistingResidue)
    };
    let hub_origin = field("hub_url")?;
    if metadata_string(&identity, "hub_url")
        .as_deref()
        .map(|value| value.trim_end_matches('/'))
        != Some(hub_origin.trim_end_matches('/'))
    {
        return Err(InstallError::ExistingResidue);
    }
    let probe_id = metadata_string(&identity, "probe_id")
        .filter(|value| !value.is_empty())
        .ok_or(InstallError::ExistingResidue)?
        .to_owned();
    Ok(InstalledUpgradeBinding {
        hub_origin,
        probe_id,
        source_bundle_version: field("bundle_version")?,
        source_install_state_sha256: sha256_field(&metadata, "install_state_sha256")?,
        source_manifest_sha256: sha256_field(&metadata, "target_manifest_sha256")?,
    })
}

fn trusted_complete_installed_layout(
    paths: &FixedInstallPaths,
) -> Result<(String, String), InstallError> {
    let metadata = trusted_text(&paths.metadata(), paths.expected_root_uid(), 0o600)?;
    if metadata_scalar(&metadata, "schema_version").as_deref() != Some("5") {
        return Err(InstallError::ExistingResidue);
    }
    for (path, mode) in [
        (paths.binary(), 0o755),
        (paths.observation_runtime_binary(), 0o755),
        (paths.cpu_provider_binary(), 0o755),
        (paths.disk_health_provider_binary(), 0o755),
        (paths.lifecycle_companion_binary(), 0o755),
        (paths.bootstrap_acquirer(), 0o755),
        (paths.bootstrap_activator(), 0o755),
        (paths.unit(), 0o644),
        (paths.observation_runtime_unit(), 0o644),
        (paths.observation_runtime_socket_unit(), 0o644),
        (paths.cpu_provider_unit(), 0o644),
        (paths.cpu_provider_socket_unit(), 0o644),
        (paths.disk_health_provider_unit(), 0o644),
        (paths.disk_health_provider_socket_unit(), 0o644),
        (paths.lifecycle_companion_unit(), 0o644),
        (paths.lifecycle_companion_socket_unit(), 0o644),
        (paths.lifecycle_upgrade_unit(), 0o644),
        (paths.lifecycle_upgrade_socket_unit(), 0o644),
    ] {
        trusted_file(&path, paths.expected_root_uid(), mode)?;
    }
    let identity_uid = fs::symlink_metadata(paths.identity())
        .map_err(|_| InstallError::ExistingResidue)?
        .uid();
    let identity = trusted_text(&paths.identity(), identity_uid, 0o600)?;
    Ok((metadata, identity))
}

pub(super) fn metadata_scalar(contents: &str, key: &str) -> Option<String> {
    let mut values = contents.lines().filter_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate.trim() == key).then(|| value.trim().to_owned())
    });
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

pub(super) fn metadata_string(contents: &str, key: &str) -> Option<String> {
    serde_json::from_str(&metadata_scalar(contents, key)?).ok()
}

fn sha256_field(contents: &str, name: &str) -> Result<String, InstallError> {
    let value = metadata_string(contents, name).ok_or(InstallError::ExistingResidue)?;
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(value)
        .ok_or(InstallError::ExistingResidue)
}

fn trusted_text(path: &Path, uid: u32, mode: u32) -> Result<String, InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::ExistingResidue)?;
    super::installed_layout::trusted_text(path, uid, metadata.gid(), mode)
}

fn trusted_file(path: &Path, uid: u32, mode: u32) -> Result<File, InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::ExistingResidue)?;
    super::installed_layout::trusted_file(path, uid, metadata.gid(), mode, metadata.len())
}

pub fn upgrade_current_probe_for_operation(
    components: VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
    expected_source: &InstalledUpgradeBinding,
    attempt: &UpgradeAttempt,
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
) -> Result<UpgradeCompletion, InstallError> {
    if attempt.operation_id.is_empty()
        || attempt.operation_id.len() > 96
        || !attempt
            .operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(InstallError::ExistingResidue);
    }
    upgrade_current_probe_inner(
        components,
        bundle,
        expected_source,
        Some(attempt),
        paths,
        systemd,
    )
}

pub fn restore_installed_bundle_for_repair(
    components: VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
    expected_installation: &InstalledUpgradeBinding,
    repair: &InstalledBundleRepairBinding,
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
) -> Result<(), InstallError> {
    if bundle.version != expected_installation.source_bundle_version
        || bundle.manifest_sha256 != expected_installation.source_manifest_sha256
    {
        return Err(InstallError::ExistingResidue);
    }
    super::bundle_restore::restore(
        components,
        bundle,
        expected_installation,
        repair,
        paths,
        systemd,
    )
    .map(|_| ())
}

#[cfg(test)]
pub(super) fn set_repair_rename_crash(index: usize) {
    super::bundle_restore::set_crash(&format!("publish:{index}"));
}

pub fn verify_installed_bundle_repair_complete(
    bundle: &VerifiedBundle,
    expected_installation: &InstalledUpgradeBinding,
    repair: &InstalledBundleRepairBinding,
    paths: &FixedInstallPaths,
) -> Result<(), InstallError> {
    super::bundle_restore::verify_complete(expected_installation, bundle, repair, paths)
}

pub fn cleanup_installed_bundle_repair(
    repair: &InstalledBundleRepairBinding,
    paths: &FixedInstallPaths,
) -> Result<(), InstallError> {
    super::bundle_restore::retire_complete(repair, paths)
}

fn upgrade_current_probe_inner(
    components: VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
    expected_source: &InstalledUpgradeBinding,
    attempt: Option<&UpgradeAttempt>,
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
) -> Result<UpgradeCompletion, InstallError> {
    let mut effects = UpgradeEffects {
        components: Some(components),
        bundle,
        expected_source,
        attempt,
        paths,
        systemd,
        prepared: None,
    };
    execute_upgrade_lifecycle(&mut effects)
}

struct UpgradeEffects<'a, S> {
    components: Option<VerifiedUpgradeComponents<'a>>,
    bundle: &'a VerifiedBundle,
    expected_source: &'a InstalledUpgradeBinding,
    attempt: Option<&'a UpgradeAttempt>,
    paths: &'a FixedInstallPaths,
    systemd: &'a mut S,
    prepared: Option<PreparedUpgrade>,
}

impl<S: SystemdPort> UpgradeLifecycleEffects for UpgradeEffects<'_, S> {
    type Error = InstallError;

    fn verify_and_prepare(&mut self) -> Result<(), Self::Error> {
        if let Some(attempt) = self.attempt {
            begin_upgrade_attempt(self.paths, attempt, self.expected_source, self.bundle)?;
        }
        let actual = inspect_installed_probe_for_upgrade(self.paths)?;
        if &actual != self.expected_source
            || self.bundle.version == actual.source_bundle_version
            || !version_is_newer(&self.bundle.version, &actual.source_bundle_version)
        {
            return Err(InstallError::ExistingResidue);
        }
        let components = self
            .components
            .as_mut()
            .ok_or(InstallError::InvalidVerifiedComponent)?;
        verify_component_lengths(components, self.bundle)?;
        if self.attempt.is_some() {
            bind_runtime_failure_pair_to_upgrade(self.paths)?;
        }
        let prepared = prepare_upgrade(components, self.bundle, self.paths, &actual)?;
        if let Some(attempt) = self.attempt
            && write_upgrade_attempt(
                self.paths,
                attempt,
                self.expected_source,
                self.bundle,
                "prepared",
                0,
                0,
            )
            .is_err()
        {
            return Err(InstallError::Io);
        }
        self.prepared = Some(prepared);
        Ok(())
    }

    fn activate_complete_bundle(&mut self) -> Result<(), UpgradeActivationFailure<Self::Error>> {
        let mut prepared = self
            .prepared
            .take()
            .ok_or(UpgradeActivationFailure::Preactivation(InstallError::Io))?;
        prepared.retain_for_repair = true;
        let activated: Result<(), InstallError> = (|| {
            if let Some(attempt) = self.attempt {
                write_upgrade_attempt(
                    self.paths,
                    attempt,
                    self.expected_source,
                    self.bundle,
                    "activation-started",
                    0,
                    0,
                )?;
                write_operation_status(self.paths, attempt, &self.bundle.version, "running", None)?;
            }
            self.systemd
                .set_command_deadline(Instant::now() + INSTALL_COMMAND_BUDGET);
            self.systemd.stop()?;
            for (index, (temporary, destination)) in prepared
                .staged
                .iter()
                .zip(&prepared.destinations)
                .enumerate()
            {
                fs::rename(temporary, destination).map_err(|_| InstallError::Io)?;
                sync_directory(destination.parent().ok_or(InstallError::Io)?)?;
                if let Some(attempt) = self.attempt {
                    write_upgrade_attempt(
                        self.paths,
                        attempt,
                        self.expected_source,
                        self.bundle,
                        "activation-started",
                        index + 1,
                        0,
                    )?;
                }
            }
            self.systemd.daemon_reload()?;
            if self.attempt.is_some() {
                consume_runtime_failure_pair_for_upgrade(self.paths)?;
            }
            self.systemd.start()?;
            self.systemd.wait_local_activated()?;
            if let Some(attempt) = self.attempt {
                write_upgrade_attempt(
                    self.paths,
                    attempt,
                    self.expected_source,
                    self.bundle,
                    "finalizing",
                    prepared.destinations.len(),
                    0,
                )?;
            }
            for (index, backup) in prepared.backups.iter().enumerate() {
                fs::remove_file(backup).map_err(|_| InstallError::Io)?;
                sync_directory(backup.parent().ok_or(InstallError::Io)?)?;
                if let Some(attempt) = self.attempt {
                    write_upgrade_attempt(
                        self.paths,
                        attempt,
                        self.expected_source,
                        self.bundle,
                        "finalizing",
                        prepared.destinations.len(),
                        index + 1,
                    )?;
                }
            }
            if let Some(attempt) = self.attempt {
                write_upgrade_attempt(
                    self.paths,
                    attempt,
                    self.expected_source,
                    self.bundle,
                    "stage-cleanup-required",
                    prepared.destinations.len(),
                    prepared.backups.len(),
                )?;
                write_operation_status(
                    self.paths,
                    attempt,
                    &self.bundle.version,
                    "failed",
                    Some("lifecycle.upgrade_repair_required"),
                )?;
            }
            prepared.retain_for_repair = false;
            Ok(())
        })();
        let error = match activated {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        let Some(attempt) = self.attempt else {
            return Err(UpgradeActivationFailure::Postactivation(error));
        };
        let journal = trusted_text(
            &self.paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE),
            self.paths.expected_root_uid(),
            0o600,
        )
        .map_err(UpgradeActivationFailure::RecoveryPersistence)?;
        let phase = journal_string(&journal, "phase")
            .map_err(UpgradeActivationFailure::RecoveryPersistence)?;
        if matches!(phase, "consumed" | "admitted" | "prepared") {
            prepared.retain_for_repair = false;
            cleanup_pre_activation_residue(self.paths)
                .map_err(UpgradeActivationFailure::RecoveryPersistence)?;
            transition_upgrade_attempt_phase(
                self.paths,
                UpgradeAttemptTerminalTransition::AbortPreactivation,
            )
            .map_err(UpgradeActivationFailure::RecoveryPersistence)?;
            write_operation_status(
                self.paths,
                attempt,
                &self.bundle.version,
                "failed",
                Some("lifecycle.upgrade_failed_before_activation"),
            )
            .map_err(UpgradeActivationFailure::RecoveryPersistence)?;
            return Err(UpgradeActivationFailure::Preactivation(error));
        }
        transition_upgrade_attempt_phase(
            self.paths,
            UpgradeAttemptTerminalTransition::RequireRepair,
        )
        .map_err(UpgradeActivationFailure::RecoveryPersistence)?;
        write_operation_status(
            self.paths,
            attempt,
            &self.bundle.version,
            "failed",
            Some("lifecycle.upgrade_repair_required"),
        )
        .map_err(UpgradeActivationFailure::RecoveryPersistence)?;
        Err(UpgradeActivationFailure::Postactivation(error))
    }
}

struct RuntimeFailurePairLock {
    _file: File,
}

fn acquire_runtime_failure_pair_lock(
    paths: &FixedInstallPaths,
) -> Result<RuntimeFailurePairLock, InstallError> {
    let lock_path = paths.runtime_failure_lock();
    let lock_parent = lock_path.parent().ok_or(InstallError::Io)?;
    let runtime_parent = lock_parent.parent().ok_or(InstallError::Io)?;
    match fs::symlink_metadata(runtime_parent) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == paths.expected_root_uid()
                && metadata.mode() & 0o022 == 0 => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(runtime_parent).map_err(|_| InstallError::Io)?;
            fs::set_permissions(runtime_parent, fs::Permissions::from_mode(0o755))
                .map_err(|_| InstallError::Io)?;
            sync_directory(runtime_parent.parent().ok_or(InstallError::Io)?)?;
        }
        _ => return Err(InstallError::ExistingResidue),
    }
    match fs::symlink_metadata(lock_parent) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(lock_parent).map_err(|_| InstallError::Io)?;
            fs::set_permissions(lock_parent, fs::Permissions::from_mode(0o700))
                .map_err(|_| InstallError::Io)?;
            sync_directory(lock_parent.parent().ok_or(InstallError::Io)?)?;
        }
        _ => return Err(InstallError::ExistingResidue),
    }
    let lock_parent_metadata =
        fs::symlink_metadata(lock_parent).map_err(|_| InstallError::ExistingResidue)?;
    if lock_parent_metadata.uid() != paths.expected_root_uid()
        || lock_parent_metadata.mode() & 0o7777 != 0o700
    {
        return Err(InstallError::ExistingResidue);
    }
    let state = fs::symlink_metadata(paths.state()).map_err(|_| InstallError::ExistingResidue)?;
    if !state.is_dir() || state.file_type().is_symlink() || state.nlink() < 2 {
        return Err(InstallError::ExistingResidue);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lock_path)
        .map_err(|_| InstallError::Io)?;
    let metadata = file.metadata().map_err(|_| InstallError::Io)?;
    if !metadata.is_file()
        || metadata.uid() != paths.expected_root_uid()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(InstallError::ExistingResidue);
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(InstallError::Io);
    }
    Ok(RuntimeFailurePairLock { _file: file })
}

pub(super) fn bind_runtime_failure_pair_to_upgrade(
    paths: &FixedInstallPaths,
) -> Result<(), InstallError> {
    let lock = acquire_runtime_failure_pair_lock(paths)?;
    let state = load_validated_upgrade_attempt(paths)?;
    if state.runtime_failure_consumption.is_some() {
        return Ok(());
    }
    let local_retry_receipt = paths.runtime_failure_dir().join("local-retry-receipt.json");
    let local_retry_receipt = trusted_optional_runtime_failure_bytes(
        &local_retry_receipt,
        paths.expected_root_uid(),
        0o600,
    )?;
    if managed_runtime_failure_path_exists(&paths.runtime_failure_dir().join("repair-intent.json"))?
    {
        return Err(InstallError::ExistingResidue);
    }
    let epoch_exists = fs::symlink_metadata(paths.runtime_failure_epoch())
        .map(|_| true)
        .or_else(|error| {
            (error.kind() == std::io::ErrorKind::NotFound)
                .then_some(false)
                .ok_or(InstallError::Io)
        })?;
    let latch_exists = fs::symlink_metadata(paths.runtime_failure_latch())
        .map(|_| true)
        .or_else(|error| {
            (error.kind() == std::io::ErrorKind::NotFound)
                .then_some(false)
                .ok_or(InstallError::Io)
        })?;
    let binding = match (epoch_exists, latch_exists) {
        (false, false) => {
            if let Some(receipt) = local_retry_receipt {
                let receipt: LocalRetryReceipt =
                    serde_json::from_slice(&receipt).map_err(|_| InstallError::ExistingResidue)?;
                if receipt.schema_version != 1
                    || !valid_sha256(&receipt.generation)
                    || !valid_sha256(&receipt.epoch_sha256)
                    || receipt.progress != "retry-invoked"
                {
                    return Err(InstallError::ExistingResidue);
                }
                fs::remove_file(paths.runtime_failure_dir().join("local-retry-receipt.json"))
                    .map_err(|_| InstallError::Io)?;
                sync_directory(&paths.runtime_failure_dir())?;
            }
            RuntimeFailureConsumption::None
        }
        (false, true) => return Err(InstallError::ExistingResidue),
        (true, latch_exists) => {
            if local_retry_receipt.is_some() {
                return Err(InstallError::ExistingResidue);
            }
            let (generation, epoch_sha256) =
                if state.schema_version == 3 && state.activation_started {
                    legacy_upgrade_runtime_failure_epoch_binding(paths, &state)?
                } else {
                    current_runtime_failure_epoch_binding(paths)?
                };
            if latch_exists {
                let latch = trusted_runtime_failure_bytes(
                    &paths.runtime_failure_latch(),
                    paths.expected_root_uid(),
                    0o600,
                )?;
                if latch != generation.as_bytes() {
                    return Err(InstallError::ExistingResidue);
                }
            }
            RuntimeFailureConsumption::Bound {
                generation,
                epoch_sha256,
            }
        }
    };
    write_runtime_failure_consumption(paths, None, &binding)?;
    drop(lock);
    Ok(())
}

pub(super) fn consume_runtime_failure_pair_for_upgrade(
    paths: &FixedInstallPaths,
) -> Result<(), InstallError> {
    let lock = acquire_runtime_failure_pair_lock(paths)?;
    let mut consumption = load_validated_upgrade_attempt(paths)?
        .runtime_failure_consumption
        .ok_or(InstallError::ExistingResidue)?;
    if consumption == RuntimeFailureConsumption::None {
        if managed_runtime_failure_path_exists(&paths.runtime_failure_epoch())?
            || managed_runtime_failure_path_exists(&paths.runtime_failure_latch())?
        {
            return Err(InstallError::ExistingResidue);
        }
        let next = RuntimeFailureConsumption::NoneConsumed;
        write_runtime_failure_consumption(paths, Some(&consumption), &next)?;
        consumption = next;
    }
    if consumption == RuntimeFailureConsumption::NoneConsumed {
        drop(lock);
        return Ok(());
    }
    if let RuntimeFailureConsumption::Bound {
        generation,
        epoch_sha256,
    } = &consumption
    {
        match trusted_optional_runtime_failure_bytes(
            &paths.runtime_failure_epoch(),
            paths.expected_root_uid(),
            0o600,
        )? {
            Some(epoch) => {
                let epoch_text =
                    std::str::from_utf8(&epoch).map_err(|_| InstallError::ExistingResidue)?;
                if metadata_string(epoch_text, "generation").as_deref() != Some(generation)
                    || format!("{:x}", Sha256::digest(&epoch)) != *epoch_sha256
                {
                    return Err(InstallError::ExistingResidue);
                }
                fs::remove_file(paths.runtime_failure_epoch()).map_err(|_| InstallError::Io)?;
                sync_directory(&paths.runtime_failure_dir())?;
            }
            None => {
                let latch = trusted_optional_runtime_failure_bytes(
                    &paths.runtime_failure_latch(),
                    paths.expected_root_uid(),
                    0o600,
                )?
                .ok_or(InstallError::ExistingResidue)?;
                if latch != generation.as_bytes() {
                    return Err(InstallError::ExistingResidue);
                }
            }
        }
        let next = RuntimeFailureConsumption::EpochRemoved {
            generation: generation.clone(),
            epoch_sha256: epoch_sha256.clone(),
        };
        write_runtime_failure_consumption(paths, Some(&consumption), &next)?;
        consumption = next;
    }
    if let RuntimeFailureConsumption::EpochRemoved {
        generation,
        epoch_sha256,
    } = &consumption
    {
        if managed_runtime_failure_path_exists(&paths.runtime_failure_epoch())? {
            return Err(InstallError::ExistingResidue);
        }
        match trusted_optional_runtime_failure_bytes(
            &paths.runtime_failure_latch(),
            paths.expected_root_uid(),
            0o600,
        )? {
            Some(latch) if latch == generation.as_bytes() => {
                fs::remove_file(paths.runtime_failure_latch()).map_err(|_| InstallError::Io)?;
                sync_directory(&paths.runtime_failure_dir())?;
            }
            None => {}
            _ => return Err(InstallError::ExistingResidue),
        }
        let next = RuntimeFailureConsumption::LatchRemoved {
            generation: generation.clone(),
            epoch_sha256: epoch_sha256.clone(),
        };
        write_runtime_failure_consumption(paths, Some(&consumption), &next)?;
        consumption = next;
    }
    if let RuntimeFailureConsumption::LatchRemoved { .. } = consumption {
        if managed_runtime_failure_path_exists(&paths.runtime_failure_epoch())?
            || managed_runtime_failure_path_exists(&paths.runtime_failure_latch())?
        {
            return Err(InstallError::ExistingResidue);
        }
        drop(lock);
        return Ok(());
    }
    Err(InstallError::ExistingResidue)
}

fn write_runtime_failure_consumption(
    paths: &FixedInstallPaths,
    expected: Option<&RuntimeFailureConsumption>,
    next: &RuntimeFailureConsumption,
) -> Result<(), InstallError> {
    let state = load_validated_upgrade_attempt(paths)?;
    if state.runtime_failure_consumption.as_ref() != expected {
        return Err(InstallError::ExistingResidue);
    }
    let mut output = if state.schema_version == 3 {
        state
            .contents
            .replacen("schema_version = 3", "schema_version = 4", 1)
    } else if state.schema_version == 4 {
        let current = expected.ok_or(InstallError::ExistingResidue)?;
        state.contents.replacen(
            &format!(
                "runtime_failure_consumption = {:?}",
                runtime_failure_progress(current)
            ),
            &format!(
                "runtime_failure_consumption = {:?}",
                runtime_failure_progress(next)
            ),
            1,
        )
    } else {
        return Err(InstallError::ExistingResidue);
    };
    if state.schema_version == 3 {
        output.push_str(&format!(
            "runtime_failure_consumption = {:?}\n",
            runtime_failure_progress(next)
        ));
        if let Some((generation, epoch_sha256)) = runtime_failure_binding(next) {
            output.push_str(&format!(
                "runtime_failure_generation = {generation:?}\nruntime_failure_epoch_sha256 = {epoch_sha256:?}\n"
            ));
        }
    }
    atomic_durable_write(
        &paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE),
        output.as_bytes(),
        0o600,
    )
}

fn runtime_failure_progress(consumption: &RuntimeFailureConsumption) -> &'static str {
    match consumption {
        RuntimeFailureConsumption::None => "none",
        RuntimeFailureConsumption::NoneConsumed => "none-consumed",
        RuntimeFailureConsumption::Bound { .. } => "bound",
        RuntimeFailureConsumption::EpochRemoved { .. } => "epoch-removed",
        RuntimeFailureConsumption::LatchRemoved { .. } => "latch-removed",
    }
}

fn runtime_failure_binding(consumption: &RuntimeFailureConsumption) -> Option<(&str, &str)> {
    match consumption {
        RuntimeFailureConsumption::None | RuntimeFailureConsumption::NoneConsumed => None,
        RuntimeFailureConsumption::Bound {
            generation,
            epoch_sha256,
        }
        | RuntimeFailureConsumption::EpochRemoved {
            generation,
            epoch_sha256,
        }
        | RuntimeFailureConsumption::LatchRemoved {
            generation,
            epoch_sha256,
        } => Some((generation, epoch_sha256)),
    }
}

pub(super) fn current_runtime_failure_epoch_binding(
    paths: &FixedInstallPaths,
) -> Result<(String, String), InstallError> {
    let epoch = trusted_runtime_failure_bytes(
        &paths.runtime_failure_epoch(),
        paths.expected_root_uid(),
        0o600,
    )?;
    let epoch_text = std::str::from_utf8(&epoch).map_err(|_| InstallError::ExistingResidue)?;
    let (metadata, identity) = trusted_complete_installed_layout(paths)?;
    let identity_bytes = identity.as_bytes();
    let unit = trusted_runtime_failure_bytes(
        &paths.observation_runtime_unit(),
        paths.expected_root_uid(),
        0o644,
    )?;
    let boot_id =
        trusted_runtime_failure_bytes(&paths.boot_id(), paths.expected_root_uid(), 0o444)?;
    let boot_id = std::str::from_utf8(&boot_id).map_err(|_| InstallError::ExistingResidue)?;
    let epoch_string =
        |key: &str| metadata_string(epoch_text, key).ok_or(InstallError::ExistingResidue);
    let identity_string =
        |key: &str| metadata_string(&identity, key).ok_or(InstallError::ExistingResidue);
    let generation = epoch_string("generation")?;
    if metadata_scalar(epoch_text, "schema_version").as_deref() != Some("1")
        || epoch_string("result")? != "start-limit-hit"
        || epoch_string("unit")? != "enoki-observation-runtime.service"
        || !valid_sha256(&generation)
        || epoch_string("boot_id")? != boot_id.trim()
        || epoch_string("unit_sha256")? != format!("{:x}", Sha256::digest(&unit))
        || epoch_string("identity_receipt_sha256")?
            != format!("{:x}", Sha256::digest(identity_bytes))
        || epoch_string("hub_origin")?
            != metadata_string(&metadata, "hub_url").ok_or(InstallError::ExistingResidue)?
        || epoch_string("hub_origin")? != identity_string("hub_url")?
        || epoch_string("host_id")? != identity_string("host_id")?
        || epoch_string("probe_id")? != identity_string("probe_id")?
        || epoch_string("install_state_sha256")?
            != metadata_string(&metadata, "install_state_sha256")
                .ok_or(InstallError::ExistingResidue)?
        || epoch_string("manifest_sha256")?
            != metadata_string(&metadata, "target_manifest_sha256")
                .ok_or(InstallError::ExistingResidue)?
        || epoch_string("bundle_version")?
            != metadata_string(&metadata, "bundle_version").ok_or(InstallError::ExistingResidue)?
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok((generation, format!("{:x}", Sha256::digest(&epoch))))
}

fn legacy_upgrade_runtime_failure_epoch_binding(
    paths: &FixedInstallPaths,
    state: &ValidatedUpgradeAttemptJournal,
) -> Result<(String, String), InstallError> {
    if state.schema_version != 3
        || !state.activation_started
        || !matches!(
            state.phase.as_str(),
            "activation-started" | "repair-required"
        )
    {
        return Err(InstallError::ExistingResidue);
    }
    let epoch = trusted_runtime_failure_bytes(
        &paths.runtime_failure_epoch(),
        paths.expected_root_uid(),
        0o600,
    )?;
    let epoch_text = std::str::from_utf8(&epoch).map_err(|_| InstallError::ExistingResidue)?;
    let unit = trusted_legacy_upgrade_source_target(paths, state, "runtime-unit")?;
    let identity = trusted_legacy_upgrade_source_target(paths, state, "identity")?;
    let metadata = trusted_legacy_upgrade_source_target(paths, state, "metadata")?;
    let identity_text =
        std::str::from_utf8(&identity).map_err(|_| InstallError::ExistingResidue)?;
    let metadata_text =
        std::str::from_utf8(&metadata).map_err(|_| InstallError::ExistingResidue)?;
    let boot_id =
        trusted_runtime_failure_bytes(&paths.boot_id(), paths.expected_root_uid(), 0o444)?;
    let boot_id = std::str::from_utf8(&boot_id).map_err(|_| InstallError::ExistingResidue)?;
    let epoch_string =
        |key: &str| metadata_string(epoch_text, key).ok_or(InstallError::ExistingResidue);
    let identity_string =
        |key: &str| metadata_string(identity_text, key).ok_or(InstallError::ExistingResidue);
    let metadata_value =
        |key: &str| metadata_string(metadata_text, key).ok_or(InstallError::ExistingResidue);
    let generation = epoch_string("generation")?;
    let source_matches_authority = match state.binding.authority_scope.as_ref() {
        Some(scope) => {
            metadata_value("hub_url")? == scope.hub_origin
                && identity_string("host_id")? == scope.host_id
        }
        None => true,
    };
    if metadata_scalar(epoch_text, "schema_version").as_deref() != Some("1")
        || epoch_string("result")? != "start-limit-hit"
        || epoch_string("unit")? != "enoki-observation-runtime.service"
        || !valid_sha256(&generation)
        || epoch_string("boot_id")? != boot_id.trim()
        || epoch_string("unit_sha256")? != format!("{:x}", Sha256::digest(&unit))
        || epoch_string("identity_receipt_sha256")? != format!("{:x}", Sha256::digest(&identity))
        || epoch_string("hub_origin")? != metadata_value("hub_url")?
        || epoch_string("hub_origin")? != identity_string("hub_url")?
        || epoch_string("host_id")? != identity_string("host_id")?
        || epoch_string("probe_id")? != identity_string("probe_id")?
        || epoch_string("probe_id")? != state.binding.source_probe_id
        || epoch_string("install_state_sha256")? != state.binding.source_install_state_sha256
        || metadata_value("install_state_sha256")? != state.binding.source_install_state_sha256
        || epoch_string("manifest_sha256")? != state.binding.source_manifest_sha256
        || metadata_value("target_manifest_sha256")? != state.binding.source_manifest_sha256
        || epoch_string("bundle_version")? != state.binding.source_bundle_version
        || metadata_value("bundle_version")? != state.binding.source_bundle_version
        || !source_matches_authority
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok((generation, format!("{:x}", Sha256::digest(&epoch))))
}

fn trusted_legacy_upgrade_source_target(
    paths: &FixedInstallPaths,
    state: &ValidatedUpgradeAttemptJournal,
    target_id: &str,
) -> Result<Vec<u8>, InstallError> {
    use std::io::Read as _;

    let registry = super::installed_layout::registry(paths);
    let (index, target) = registry
        .iter()
        .enumerate()
        .find(|(_, target)| target.id == target_id)
        .ok_or(InstallError::ExistingResidue)?;
    let name = target
        .destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(InstallError::ExistingResidue)?;
    let backup = target
        .destination
        .with_file_name(format!(".{name}.enoki-upgrade-old"));
    let (mut current, current_metadata) = open_legacy_upgrade_target(&target.destination)?;
    let (mut retained, retained_metadata) = open_legacy_upgrade_target(&backup)?;
    let same_inode = current_metadata.dev() == retained_metadata.dev()
        && current_metadata.ino() == retained_metadata.ino();
    let source_is_retained = if index < state.activated_targets {
        if same_inode || retained_metadata.nlink() != 1 {
            return Err(InstallError::ExistingResidue);
        }
        true
    } else if index == state.activated_targets {
        if same_inode {
            if current_metadata.nlink() != 2 || retained_metadata.nlink() != 2 {
                return Err(InstallError::ExistingResidue);
            }
            false
        } else {
            if retained_metadata.nlink() != 1 {
                return Err(InstallError::ExistingResidue);
            }
            true
        }
    } else {
        if !same_inode || current_metadata.nlink() != 2 || retained_metadata.nlink() != 2 {
            return Err(InstallError::ExistingResidue);
        }
        false
    };
    if current_metadata.mode() & 0o7777 != target.mode
        || retained_metadata.mode() & 0o7777 != target.mode
        || current_metadata.uid() != retained_metadata.uid()
        || current_metadata.gid() != retained_metadata.gid()
        || (target_id != "identity"
            && (retained_metadata.uid() != paths.expected_root_uid()
                || retained_metadata.gid() != paths.expected_root_uid()))
    {
        return Err(InstallError::ExistingResidue);
    }
    let source = if source_is_retained {
        &mut retained
    } else {
        &mut current
    };
    let mut bytes = Vec::new();
    source
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallError::Io)?;
    if bytes.is_empty() || bytes.len() > 256 * 1024 {
        return Err(InstallError::ExistingResidue);
    }
    Ok(bytes)
}

fn open_legacy_upgrade_target(path: &Path) -> Result<(File, fs::Metadata), InstallError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| InstallError::ExistingResidue)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| InstallError::ExistingResidue)?;
    let opened = file.metadata().map_err(|_| InstallError::ExistingResidue)?;
    if path_metadata.file_type().is_symlink()
        || !opened.is_file()
        || path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
        || opened.len() > 256 * 1024
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok((file, opened))
}

fn trusted_runtime_failure_bytes(
    path: &Path,
    uid: u32,
    mode: u32,
) -> Result<Vec<u8>, InstallError> {
    use std::io::Read as _;
    let mut file = trusted_file(path, uid, mode)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| InstallError::Io)?;
    if bytes.len() > 64 * 1024 {
        return Err(InstallError::ExistingResidue);
    }
    Ok(bytes)
}

fn trusted_optional_runtime_failure_bytes(
    path: &Path,
    uid: u32,
    mode: u32,
) -> Result<Option<Vec<u8>>, InstallError> {
    if !managed_runtime_failure_path_exists(path)? {
        return Ok(None);
    }
    trusted_runtime_failure_bytes(path, uid, mode).map(Some)
}

fn managed_runtime_failure_path_exists(path: &Path) -> Result<bool, InstallError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(InstallError::Io),
    }
}

#[derive(Clone, Copy)]
pub(super) enum UpgradeAttemptTerminalTransition {
    AbortPreactivation,
    RequireRepair,
    MarkActivated,
}

pub(super) fn transition_upgrade_attempt_phase(
    paths: &FixedInstallPaths,
    transition: UpgradeAttemptTerminalTransition,
) -> Result<(), InstallError> {
    let state = load_validated_upgrade_attempt(paths)?;
    let phase = match transition {
        UpgradeAttemptTerminalTransition::AbortPreactivation
            if matches!(state.phase.as_str(), "consumed" | "admitted" | "prepared") =>
        {
            "aborted"
        }
        UpgradeAttemptTerminalTransition::RequireRepair
            if state.activation_started
                && matches!(
                    state.phase.as_str(),
                    "activation-started"
                        | "repair-required"
                        | "finalizing"
                        | "stage-cleanup-required"
                ) =>
        {
            "repair-required"
        }
        UpgradeAttemptTerminalTransition::MarkActivated
            if state.activation_started && state.phase == "stage-cleanup-required" =>
        {
            "activated"
        }
        _ => return Err(InstallError::ExistingResidue),
    };
    write_upgrade_attempt_from_journal(
        paths,
        &state.contents,
        phase,
        state.activated_targets,
        state.finalized_targets,
    )
}

fn verify_component_lengths(
    components: &mut VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
) -> Result<(), InstallError> {
    validate_component(components.probe, bundle.component_len)?;
    for (file, role) in [
        (&mut *components.observation_runtime, "observation-runtime"),
        (
            &mut *components.system_state_provider,
            "system-state-provider",
        ),
        (
            &mut *components.disk_health_provider,
            "disk-health-provider",
        ),
        (&mut *components.lifecycle_companion, "lifecycle-companion"),
    ] {
        let (_, length) = bundle
            .component_receipt(role)
            .ok_or(InstallError::InvalidVerifiedComponent)?;
        validate_component(file, length)?;
    }
    validate_bootstrap_role_file(components.bootstrap_acquirer, bundle, true)?;
    validate_bootstrap_role_file(components.bootstrap_activator, bundle, false)
}

fn validate_bootstrap_role_file(
    file: &mut File,
    bundle: &VerifiedBundle,
    acquirer: bool,
) -> Result<(), InstallError> {
    let receipt = if acquirer {
        bundle.acquirer_receipt()
    } else {
        bundle.activator_receipt()
    }
    .ok_or(InstallError::InvalidVerifiedComponent)?;
    validate_component(file, receipt.1)
}

struct PreparedUpgrade {
    staged: Vec<PathBuf>,
    destinations: Vec<PathBuf>,
    backups: Vec<PathBuf>,
    retain_for_repair: bool,
}

impl Drop for PreparedUpgrade {
    fn drop(&mut self) {
        if self.retain_for_repair {
            return;
        }
        for path in self.staged.iter().chain(&self.backups) {
            let _ = fs::remove_file(path);
        }
    }
}

fn prepare_upgrade(
    components: &mut VerifiedUpgradeComponents<'_>,
    bundle: &VerifiedBundle,
    paths: &FixedInstallPaths,
    source: &InstalledUpgradeBinding,
) -> Result<PreparedUpgrade, InstallError> {
    let registry = super::installed_layout::registry(paths);
    let destinations = registry
        .iter()
        .map(|target| target.destination.clone())
        .collect();
    let mut prepared = PreparedUpgrade {
        staged: Vec::new(),
        destinations,
        backups: Vec::new(),
        retain_for_repair: false,
    };
    for target in registry {
        use super::installed_layout::TargetKind;
        let staged = match target.kind {
            TargetKind::Bundle(role) => {
                let component = match role {
                    "probe" => &mut *components.probe,
                    "observation-runtime" => &mut *components.observation_runtime,
                    "system-state-provider" => &mut *components.system_state_provider,
                    "disk-health-provider" => &mut *components.disk_health_provider,
                    "lifecycle-companion" => &mut *components.lifecycle_companion,
                    "bootstrap-acquirer" => &mut *components.bootstrap_acquirer,
                    "bootstrap-activator" => &mut *components.bootstrap_activator,
                    _ => return Err(InstallError::InvalidVerifiedComponent),
                };
                stage_reader(component, &target.destination, target.mode)?
            }
            TargetKind::Unit(generate) => {
                stage_bytes(generate().as_bytes(), &target.destination, target.mode)?
            }
            TargetKind::Identity => {
                let metadata = fs::symlink_metadata(&target.destination)
                    .map_err(|_| InstallError::ExistingResidue)?;
                let current = super::installed_layout::trusted_text(
                    &target.destination,
                    metadata.uid(),
                    metadata.gid(),
                    target.mode,
                )?;
                let updated = updated_receipt_projection(&current, bundle, source)?;
                stage_bytes_owned(
                    updated.as_bytes(),
                    &target.destination,
                    target.mode,
                    metadata.uid(),
                    metadata.gid(),
                )?
            }
            TargetKind::Metadata => {
                let root = paths.expected_root_uid();
                let current = super::installed_layout::trusted_text(
                    &target.destination,
                    root,
                    root,
                    target.mode,
                )?;
                let updated = updated_metadata(&current, bundle, source)?;
                stage_bytes(updated.as_bytes(), &target.destination, target.mode)?
            }
        };
        prepared.staged.push(staged);
    }
    for destination in &prepared.destinations {
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(InstallError::Io)?;
        let backup = destination.with_file_name(format!(".{name}.enoki-upgrade-old"));
        if fs::symlink_metadata(&backup).is_ok() {
            return Err(InstallError::ExistingResidue);
        }
        if destination == &paths.observation_runtime_failure_recorder_unit()
            && !destination.exists()
        {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&backup)
                .map_err(|_| InstallError::Io)?
                .sync_all()
                .map_err(|_| InstallError::Io)?;
        } else {
            fs::hard_link(destination, &backup).map_err(|_| InstallError::Io)?;
        }
        prepared.backups.push(backup);
    }
    Ok(prepared)
}

fn stage_reader(source: &mut File, destination: &Path, mode: u32) -> Result<PathBuf, InstallError> {
    source.rewind().map_err(|_| InstallError::Io)?;
    let parent = destination.parent().ok_or(InstallError::Io)?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(InstallError::Io)?;
    let path = parent.join(format!(".{name}.enoki-upgrade-new"));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&path)
        .map_err(|_| InstallError::ExistingResidue)?;
    std::io::copy(source, &mut output).map_err(|_| InstallError::Io)?;
    output
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| InstallError::Io)?;
    output.sync_all().map_err(|_| InstallError::Io)?;
    Ok(path)
}

fn stage_bytes(bytes: &[u8], destination: &Path, mode: u32) -> Result<PathBuf, InstallError> {
    let temporary = destination.with_file_name(format!(
        ".{}.enoki-upgrade-new",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(InstallError::Io)?
    ));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)
        .map_err(|_| InstallError::ExistingResidue)?;
    output.write_all(bytes).map_err(|_| InstallError::Io)?;
    output
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| InstallError::Io)?;
    output.sync_all().map_err(|_| InstallError::Io)?;
    Ok(temporary)
}

fn stage_bytes_owned(
    bytes: &[u8],
    destination: &Path,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<PathBuf, InstallError> {
    let path = stage_bytes(bytes, destination, mode)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| InstallError::Io)?;
    // SAFETY：descriptor 指向刚创建的普通暂存文件；uid/gid 来自已信任的
    // 当前 Probe Identity inode。
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        let _ = fs::remove_file(&path);
        return Err(InstallError::Io);
    }
    file.sync_all().map_err(|_| InstallError::Io)?;
    Ok(path)
}

pub(super) fn updated_metadata(
    current: &str,
    bundle: &VerifiedBundle,
    source: &InstalledUpgradeBinding,
) -> Result<String, InstallError> {
    let replacements = [
        ("install_state_sha256", bundle.install_state_sha256()),
        ("target_manifest_sha256", bundle.manifest_sha256.clone()),
        ("bundle_version", bundle.version.clone()),
    ];
    let mut counts = [0_u8; 3];
    let mut output = String::new();
    for line in current.lines() {
        if let Some((index, (key, value))) = replacements
            .iter()
            .enumerate()
            .find(|(_, (key, _))| line.starts_with(&format!("{key} = ")))
        {
            counts[index] += 1;
            output.push_str(&format!("{key} = {value:?}\n"));
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if counts != [1, 1, 1]
        || !current.contains(&format!(
            "bundle_version = {:?}",
            source.source_bundle_version
        ))
    {
        return Err(InstallError::ExistingResidue);
    }
    Ok(output)
}

pub(super) fn updated_receipt_projection(
    current: &str,
    bundle: &VerifiedBundle,
    source: &InstalledUpgradeBinding,
) -> Result<String, InstallError> {
    updated_metadata(current, bundle, source)
}

fn begin_upgrade_attempt(
    paths: &FixedInstallPaths,
    attempt: &UpgradeAttempt,
    source: &InstalledUpgradeBinding,
    bundle: &VerifiedBundle,
) -> Result<(), InstallError> {
    if let Some(authority_sha256) = attempt.authority_sha256.as_deref() {
        return confirm_consumed_upgrade_authority(
            paths,
            attempt,
            authority_sha256,
            source,
            bundle,
        );
    }
    let journal = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    if journal.exists() {
        let prior = load_validated_upgrade_attempt(paths)?;
        if prior.binding.operation_id == attempt.operation_id
            || matches!(
                prior.phase.as_str(),
                "activation-started" | "repair-required" | "finalizing" | "stage-cleanup-required"
            )
        {
            return Err(InstallError::ExistingResidue);
        }
        if !matches!(prior.phase.as_str(), "activated" | "aborted") {
            return Err(InstallError::ExistingResidue);
        }
        cleanup_pre_activation_residue(paths)?;
    }
    write_upgrade_attempt(paths, attempt, source, bundle, "admitted", 0, 0)
}

#[cfg(test)]
pub fn consume_probe_upgrade_authority(
    paths: &FixedInstallPaths,
    authority: &UpgradeAuthorityConsumption,
) -> Result<UpgradeAttempt, InstallError> {
    consume_probe_upgrade_authority_with_sha256(
        paths,
        authority,
        consumed_authority_sha256(authority),
    )
}

fn consume_probe_upgrade_authority_with_sha256(
    paths: &FixedInstallPaths,
    authority: &UpgradeAuthorityConsumption,
    authority_sha256: String,
) -> Result<UpgradeAttempt, InstallError> {
    if !valid_upgrade_identifier(&authority.operation_id)
        || !valid_upgrade_identifier(&authority.probe_id)
        || !valid_upgrade_identifier(&authority.host_id)
        || authority.hub_origin.is_empty()
        || !valid_upgrade_version(&authority.source_bundle_version)
        || !valid_upgrade_version(&authority.target_bundle_version)
        || !valid_sha256(&authority.source_install_state_sha256)
        || !valid_sha256(&authority.source_manifest_sha256)
        || !valid_sha256(&authority.target_manifest_sha256)
        || authority
            .target_asset_set_digest
            .strip_prefix("sha256:")
            .is_none_or(|digest| !valid_sha256(digest))
        || !valid_sha256(&authority.verified_stage_sha256)
    {
        return Err(InstallError::ExistingResidue);
    }
    let journal = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    if journal.exists() {
        let prior = load_validated_upgrade_attempt(paths)?;
        if prior.binding.operation_id == authority.operation_id
            || !matches!(prior.phase.as_str(), "aborted" | "activated")
        {
            return Err(InstallError::ExistingResidue);
        }
        cleanup_pre_activation_residue(paths)?;
    }
    let contents = format!(
        "schema_version = 3\noperation_id = {:?}\nstage_owner_uid = {}\nauthority_sha256 = {:?}\nhub_origin = {:?}\nhost_id = {:?}\nsource_probe_id = {:?}\nsource_bundle_version = {:?}\nsource_install_state_sha256 = {:?}\nsource_manifest_sha256 = {:?}\ntarget_bundle_version = {:?}\ntarget_asset_set_digest = {:?}\ntarget_manifest_sha256 = {:?}\nverified_stage_sha256 = {:?}\nphase = \"consumed\"\nactivation_started = false\nactivated_targets = 0\nfinalized_targets = 0\n",
        authority.operation_id,
        authority.stage_owner_uid,
        authority_sha256,
        authority.hub_origin,
        authority.host_id,
        authority.probe_id,
        authority.source_bundle_version,
        authority.source_install_state_sha256,
        authority.source_manifest_sha256,
        authority.target_bundle_version,
        authority.target_asset_set_digest,
        authority.target_manifest_sha256,
        authority.verified_stage_sha256,
    );
    atomic_durable_write(&journal, contents.as_bytes(), 0o600)?;
    Ok(UpgradeAttempt {
        operation_id: authority.operation_id.clone(),
        stage_owner_uid: authority.stage_owner_uid,
        authority_sha256: Some(authority_sha256),
    })
}

pub fn abort_consumed_probe_upgrade_authority(
    paths: &FixedInstallPaths,
    consumed: &UpgradeAttempt,
) -> Result<(), InstallError> {
    let contents = trusted_text(
        &paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE),
        paths.expected_root_uid(),
        0o600,
    )?;
    if journal_string(&contents, "operation_id")? != consumed.operation_id
        || journal_string(&contents, "phase")? != "consumed"
        || Some(journal_string(&contents, "authority_sha256")?)
            != consumed.authority_sha256.as_deref()
    {
        return Err(InstallError::ExistingResidue);
    }
    transition_upgrade_attempt_phase(paths, UpgradeAttemptTerminalTransition::AbortPreactivation)
}

fn confirm_consumed_upgrade_authority(
    paths: &FixedInstallPaths,
    attempt: &UpgradeAttempt,
    authority_sha256: &str,
    source: &InstalledUpgradeBinding,
    bundle: &VerifiedBundle,
) -> Result<(), InstallError> {
    let state = load_validated_upgrade_attempt(paths)?;
    let authority_scope = state
        .binding
        .authority_scope
        .as_ref()
        .ok_or(InstallError::ExistingResidue)?;
    if state.binding.operation_id != attempt.operation_id
        || state.binding.stage_owner_uid != attempt.stage_owner_uid
        || state.binding.authority_sha256 != authority_sha256
        || state.phase != "consumed"
        || authority_scope.hub_origin != source.hub_origin
        || state.binding.source_probe_id != source.probe_id
        || state.binding.source_bundle_version != source.source_bundle_version
        || state.binding.source_install_state_sha256 != source.source_install_state_sha256
        || state.binding.source_manifest_sha256 != source.source_manifest_sha256
        || state.binding.target_bundle_version != bundle.version
        || authority_scope.target_asset_set_digest
            != format!("sha256:{}", bundle.asset_set_manifest_sha256)
        || state.binding.target_manifest_sha256 != bundle.manifest_sha256
    {
        return Err(InstallError::ExistingResidue);
    }
    write_upgrade_attempt_from_journal(paths, &state.contents, "admitted", 0, 0)
}

fn valid_upgrade_identifier(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_upgrade_version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_whitespace)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
fn consumed_authority_sha256(authority: &UpgradeAuthorityConsumption) -> String {
    let canonical = format!(
        "enoki/lifecycle-upgrade-consumption/v2\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        authority.operation_id,
        authority.hub_origin,
        authority.host_id,
        authority.probe_id,
        authority.source_bundle_version,
        authority.source_install_state_sha256,
        authority.source_manifest_sha256,
        authority.target_bundle_version,
        authority.target_asset_set_digest,
        authority.target_manifest_sha256,
        authority.verified_stage_sha256,
    );
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

fn journal_string<'a>(contents: &'a str, key: &str) -> Result<&'a str, InstallError> {
    let prefix = format!("{key} = \"");
    let mut values = contents.lines().filter_map(|line| {
        line.strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix('"'))
    });
    let value = values.next().ok_or(InstallError::ExistingResidue)?;
    if value.is_empty() || values.next().is_some() {
        return Err(InstallError::ExistingResidue);
    }
    Ok(value)
}

fn cleanup_pre_activation_residue(paths: &FixedInstallPaths) -> Result<(), InstallError> {
    let destinations = upgrade_destinations(paths);
    let mut changed = Vec::new();
    for destination in &destinations {
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(InstallError::Io)?;
        for residue in [
            destination.with_file_name(format!(".{name}.enoki-upgrade-new")),
            destination.with_file_name(format!(".{name}.enoki-upgrade-old")),
        ] {
            match fs::remove_file(&residue) {
                Ok(()) => changed.push(destination.clone()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(InstallError::Io),
            }
        }
    }
    sync_destination_directories(&changed)
}

fn journal_usize(contents: &str, key: &str) -> Result<usize, InstallError> {
    let prefix = format!("{key} = ");
    let mut values = contents
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .map(str::parse::<usize>);
    let value = values
        .next()
        .ok_or(InstallError::ExistingResidue)?
        .map_err(|_| InstallError::ExistingResidue)?;
    if values.next().is_some() {
        return Err(InstallError::ExistingResidue);
    }
    Ok(value)
}

pub fn recover_incomplete_probe_upgrade(
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
) -> Result<Option<UpgradeRecoveryReceipt>, InstallError> {
    recover_incomplete_probe_upgrade_with_status(paths, systemd, true)
}

fn recover_incomplete_probe_upgrade_for_repair(
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
) -> Result<Option<UpgradeRecoveryReceipt>, InstallError> {
    recover_incomplete_probe_upgrade_with_status(paths, systemd, false)
}

fn recover_incomplete_probe_upgrade_with_status(
    paths: &FixedInstallPaths,
    systemd: &mut impl SystemdPort,
    publish_upgrade_status: bool,
) -> Result<Option<UpgradeRecoveryReceipt>, InstallError> {
    let journal_path = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    if !journal_path.exists() {
        return Ok(None);
    }
    let state = load_validated_upgrade_attempt(paths)?;
    let operation_id = state.binding.operation_id.clone();
    let probe_id = state.binding.source_probe_id.clone();
    let target_bundle_version = state.binding.target_bundle_version.clone();
    let source_bundle_version = state.binding.source_bundle_version.clone();
    let stage_owner_uid = state.binding.stage_owner_uid;
    let phase = state.phase.as_str();
    let destinations = upgrade_destinations(paths);
    let activated_targets = state.activated_targets;
    let finalized_targets = state.finalized_targets;
    let receipt = UpgradeRecoveryReceipt {
        operation_id: operation_id.clone(),
        probe_id,
        stage_owner_uid,
        source_bundle_version,
        target_bundle_version: target_bundle_version.clone(),
        activated: !matches!(phase, "consumed" | "admitted" | "prepared" | "aborted"),
    };
    let attempt = UpgradeAttempt {
        operation_id,
        stage_owner_uid,
        authority_sha256: Some(state.binding.authority_sha256.clone()),
    };

    let recovered = (|| {
        match phase {
            "consumed" | "admitted" | "prepared" => {
                cleanup_pre_activation_residue(paths)?;
                transition_upgrade_attempt_phase(
                    paths,
                    UpgradeAttemptTerminalTransition::AbortPreactivation,
                )?;
                if publish_upgrade_status {
                    write_operation_status(
                        paths,
                        &attempt,
                        &target_bundle_version,
                        "failed",
                        Some("lifecycle.upgrade_failed_before_activation"),
                    )?;
                }
            }
            "aborted" => {}
            "activation-started" | "repair-required" => {
                // A candidate companion can inherit a schema-3 journal from an
                // older binary. Establish custody from its retained source
                // closure before any further stop or target rename.
                if finalized_targets == 0 {
                    bind_runtime_failure_pair_to_upgrade(paths)?;
                }
                if activated_targets < destinations.len() || finalized_targets == 0 {
                    systemd.set_command_deadline(Instant::now() + INSTALL_COMMAND_BUDGET);
                    systemd.stop()?;
                    for (index, destination) in
                        destinations.iter().enumerate().skip(activated_targets)
                    {
                        let name = destination
                            .file_name()
                            .and_then(|name| name.to_str())
                            .ok_or(InstallError::Io)?;
                        let staged =
                            destination.with_file_name(format!(".{name}.enoki-upgrade-new"));
                        if staged.exists() {
                            fs::rename(&staged, destination).map_err(|_| InstallError::Io)?;
                            sync_directory(destination.parent().ok_or(InstallError::Io)?)?;
                        } else if !destination.exists() {
                            return Err(InstallError::ExistingResidue);
                        }
                        advance_upgrade_attempt(paths, phase, index + 1, finalized_targets)?;
                    }
                    systemd.daemon_reload()?;
                    consume_runtime_failure_pair_for_upgrade(paths)?;
                    systemd.start()?;
                    systemd.wait_local_activated()?;
                }
                advance_upgrade_attempt(
                    paths,
                    "finalizing",
                    destinations.len(),
                    finalized_targets,
                )?;
                for (index, destination) in destinations.iter().enumerate().skip(finalized_targets)
                {
                    let name = destination
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or(InstallError::Io)?;
                    let backup = destination.with_file_name(format!(".{name}.enoki-upgrade-old"));
                    match fs::remove_file(&backup) {
                        Ok(()) => sync_directory(backup.parent().ok_or(InstallError::Io)?)?,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => return Err(InstallError::Io),
                    }
                    advance_upgrade_attempt(paths, "finalizing", destinations.len(), index + 1)?;
                }
                advance_upgrade_attempt(
                    paths,
                    "stage-cleanup-required",
                    destinations.len(),
                    destinations.len(),
                )?;
                if publish_upgrade_status {
                    write_operation_status(
                        paths,
                        &attempt,
                        &target_bundle_version,
                        "failed",
                        Some("lifecycle.upgrade_repair_required"),
                    )?;
                }
            }
            "finalizing" => {
                for (index, destination) in destinations.iter().enumerate().skip(finalized_targets)
                {
                    let name = destination
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or(InstallError::Io)?;
                    let backup = destination.with_file_name(format!(".{name}.enoki-upgrade-old"));
                    match fs::remove_file(&backup) {
                        Ok(()) => sync_directory(backup.parent().ok_or(InstallError::Io)?)?,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => return Err(InstallError::Io),
                    }
                    advance_upgrade_attempt(paths, "finalizing", destinations.len(), index + 1)?;
                }
                advance_upgrade_attempt(
                    paths,
                    "stage-cleanup-required",
                    destinations.len(),
                    destinations.len(),
                )?;
            }
            "stage-cleanup-required" => {}
            "activated" => return Ok(None),
            _ => return Err(InstallError::ExistingResidue),
        }
        Ok(Some(receipt))
    })();
    match recovered {
        Ok(receipt) => Ok(receipt),
        Err(error) => {
            if matches!(phase, "consumed" | "admitted" | "prepared" | "aborted") {
                return Err(error);
            }
            transition_upgrade_attempt_phase(
                paths,
                UpgradeAttemptTerminalTransition::RequireRepair,
            )?;
            if publish_upgrade_status {
                write_operation_status(
                    paths,
                    &attempt,
                    &target_bundle_version,
                    "failed",
                    Some("lifecycle.upgrade_repair_required"),
                )?;
            }
            Err(error)
        }
    }
}

pub fn finalize_probe_upgrade_stage_cleanup(
    paths: &FixedInstallPaths,
    receipt: &UpgradeRecoveryReceipt,
) -> Result<(), InstallError> {
    finalize_probe_upgrade_stage_cleanup_with_status(paths, receipt, true)
}

fn finalize_probe_repair_stage_cleanup(
    paths: &FixedInstallPaths,
    receipt: &UpgradeRecoveryReceipt,
) -> Result<(), InstallError> {
    finalize_probe_upgrade_stage_cleanup_with_status(paths, receipt, false)
}

fn finalize_probe_upgrade_stage_cleanup_with_status(
    paths: &FixedInstallPaths,
    receipt: &UpgradeRecoveryReceipt,
    publish_upgrade_status: bool,
) -> Result<(), InstallError> {
    let journal_path = paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE);
    let contents = trusted_text(&journal_path, paths.expected_root_uid(), 0o600)?;
    if journal_string(&contents, "operation_id")? != receipt.operation_id
        || journal_usize(&contents, "stage_owner_uid")? != receipt.stage_owner_uid as usize
        || journal_string(&contents, "target_bundle_version")? != receipt.target_bundle_version
    {
        return Err(InstallError::ExistingResidue);
    }
    let phase = journal_string(&contents, "phase")?;
    if receipt.activated {
        if phase != "stage-cleanup-required" {
            return Err(InstallError::ExistingResidue);
        }
        transition_upgrade_attempt_phase(paths, UpgradeAttemptTerminalTransition::MarkActivated)?;
        if publish_upgrade_status {
            write_operation_status(
                paths,
                &UpgradeAttempt {
                    operation_id: receipt.operation_id.clone(),
                    stage_owner_uid: receipt.stage_owner_uid,
                    authority_sha256: None,
                },
                &receipt.target_bundle_version,
                "running",
                None,
            )
        } else {
            Ok(())
        }
    } else {
        if phase != "aborted" {
            return Err(InstallError::ExistingResidue);
        }
        write_operation_status(
            paths,
            &UpgradeAttempt {
                operation_id: receipt.operation_id.clone(),
                stage_owner_uid: receipt.stage_owner_uid,
                authority_sha256: None,
            },
            &receipt.target_bundle_version,
            "failed",
            Some("lifecycle.upgrade_failed_before_activation"),
        )
    }
}

pub(super) fn write_upgrade_attempt_from_journal(
    paths: &FixedInstallPaths,
    expected: &str,
    phase: &str,
    activated_targets: usize,
    finalized_targets: usize,
) -> Result<(), InstallError> {
    let state = load_validated_upgrade_attempt(paths)?;
    let current = state.contents;
    if current != expected {
        return Err(InstallError::ExistingResidue);
    }
    if !valid_upgrade_attempt_transition(
        &state.phase,
        phase,
        state.activated_targets,
        state.finalized_targets,
        activated_targets,
        finalized_targets,
        upgrade_destinations(paths).len(),
    ) {
        return Err(InstallError::ExistingResidue);
    }
    let prior = current.as_str();
    let schema_version = metadata_scalar(prior, "schema_version");
    let marker_required = matches!(schema_version.as_deref(), Some("3" | "4"));
    let mut counts = [0_u8; 4];
    let mut output = String::new();
    for line in prior.lines() {
        if line.starts_with("phase = ") {
            counts[0] += 1;
            output.push_str(&format!("phase = {phase:?}\n"));
        } else if line.starts_with("activated_targets = ") {
            counts[1] += 1;
            output.push_str(&format!("activated_targets = {activated_targets}\n"));
        } else if line.starts_with("finalized_targets = ") {
            counts[2] += 1;
            output.push_str(&format!("finalized_targets = {finalized_targets}\n"));
        } else if line.starts_with("activation_started = ") {
            counts[3] += 1;
            let started = phase == "activation-started"
                || metadata_scalar(prior, "activation_started").as_deref() == Some("true");
            output.push_str(&format!("activation_started = {started}\n"));
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if counts[..3] != [1, 1, 1]
        || (marker_required && counts[3] != 1)
        || (!marker_required && counts[3] != 0)
    {
        return Err(InstallError::ExistingResidue);
    }
    atomic_durable_write(
        &paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE),
        output.as_bytes(),
        0o600,
    )
}

fn advance_upgrade_attempt(
    paths: &FixedInstallPaths,
    phase: &str,
    activated_targets: usize,
    finalized_targets: usize,
) -> Result<(), InstallError> {
    let current = load_validated_upgrade_attempt(paths)?;
    write_upgrade_attempt_from_journal(
        paths,
        &current.contents,
        phase,
        activated_targets,
        finalized_targets,
    )
}

fn valid_upgrade_attempt_transition(
    current: &str,
    next: &str,
    current_activated: usize,
    current_finalized: usize,
    next_activated: usize,
    next_finalized: usize,
    target_count: usize,
) -> bool {
    if next_activated < current_activated || next_finalized < current_finalized {
        return false;
    }
    let phase_allowed = matches!(
        (current, next),
        ("consumed", "admitted")
            | ("admitted", "prepared")
            | ("consumed" | "admitted" | "prepared", "aborted")
            | ("prepared", "activation-started")
            | (
                "activation-started",
                "activation-started" | "repair-required" | "finalizing"
            )
            | ("repair-required", "repair-required" | "finalizing")
            | (
                "finalizing",
                "finalizing" | "repair-required" | "stage-cleanup-required"
            )
            | ("stage-cleanup-required", "repair-required" | "activated")
    );
    let marker = !matches!(next, "consumed" | "admitted" | "prepared" | "aborted");
    phase_allowed
        && validate_upgrade_attempt_tuple(
            next,
            marker,
            next_activated,
            next_finalized,
            target_count,
        )
        .is_ok()
}

fn write_upgrade_attempt(
    paths: &FixedInstallPaths,
    attempt: &UpgradeAttempt,
    source: &InstalledUpgradeBinding,
    bundle: &VerifiedBundle,
    phase: &str,
    activated_targets: usize,
    finalized_targets: usize,
) -> Result<(), InstallError> {
    if attempt.authority_sha256.is_some() {
        let prior = trusted_text(
            &paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE),
            paths.expected_root_uid(),
            0o600,
        )?;
        return write_upgrade_attempt_from_journal(
            paths,
            &prior,
            phase,
            activated_targets,
            finalized_targets,
        );
    }
    let authority_sha256 = attempt
        .authority_sha256
        .clone()
        .unwrap_or_else(|| upgrade_authority_sha256(attempt, source, bundle));
    if phase != "admitted" {
        let state = load_validated_upgrade_attempt(paths)?;
        if state.binding.operation_id != attempt.operation_id
            || state.binding.stage_owner_uid != attempt.stage_owner_uid
            || state.binding.authority_sha256 != authority_sha256
            || state.binding.source_probe_id != source.probe_id
            || state.binding.source_bundle_version != source.source_bundle_version
            || state.binding.source_install_state_sha256 != source.source_install_state_sha256
            || state.binding.source_manifest_sha256 != source.source_manifest_sha256
            || state.binding.target_bundle_version != bundle.version
            || state.binding.target_manifest_sha256 != bundle.manifest_sha256
            || state.binding.authority_scope.is_some()
        {
            return Err(InstallError::ExistingResidue);
        }
        return write_upgrade_attempt_from_journal(
            paths,
            &state.contents,
            phase,
            activated_targets,
            finalized_targets,
        );
    }
    let contents = format!(
        "schema_version = 3\noperation_id = {:?}\nstage_owner_uid = {}\nauthority_sha256 = {:?}\nsource_probe_id = {:?}\nsource_bundle_version = {:?}\nsource_install_state_sha256 = {:?}\nsource_manifest_sha256 = {:?}\ntarget_bundle_version = {:?}\ntarget_install_state_sha256 = {:?}\ntarget_manifest_sha256 = {:?}\nphase = {:?}\nactivation_started = false\nactivated_targets = {activated_targets}\nfinalized_targets = {finalized_targets}\n",
        attempt.operation_id,
        attempt.stage_owner_uid,
        authority_sha256,
        source.probe_id,
        source.source_bundle_version,
        source.source_install_state_sha256,
        source.source_manifest_sha256,
        bundle.version,
        bundle.install_state_sha256(),
        bundle.manifest_sha256,
        phase,
    );
    atomic_durable_write(
        &paths.bootstrap_state().join(UPGRADE_ATTEMPT_FILE),
        contents.as_bytes(),
        0o600,
    )
}

fn upgrade_authority_sha256(
    attempt: &UpgradeAttempt,
    source: &InstalledUpgradeBinding,
    bundle: &VerifiedBundle,
) -> String {
    let canonical = format!(
        "enoki/lifecycle-upgrade-consumption/v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        attempt.operation_id,
        source.hub_origin,
        source.probe_id,
        source.source_bundle_version,
        source.source_install_state_sha256,
        bundle.version,
        bundle.manifest_sha256,
    );
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

pub(crate) fn write_operation_status(
    paths: &FixedInstallPaths,
    attempt: &UpgradeAttempt,
    target_version: &str,
    status: &str,
    error_code: Option<&str>,
) -> Result<(), InstallError> {
    let eligibility = error_code
        .filter(|code| *code == "lifecycle.upgrade_repair_required")
        .and_then(|_| issue_probe_repair_eligibility(paths).ok())
        .and_then(|eligibility| {
            String::from_utf8(eligibility.evidence.canonical_bytes())
                .ok()
                .map(|canonical| (canonical, eligibility.signature))
        });
    let contents = crate::operation_status::OperationStatusDocument {
        operation_id: &attempt.operation_id,
        target_probe_version: target_version,
        status: match (status, error_code) {
            ("failed", Some(error_code)) => {
                crate::operation_status::OperationStatus::Failed { error_code }
            }
            ("running", None) => crate::operation_status::OperationStatus::Running,
            ("succeeded", None) => crate::operation_status::OperationStatus::Succeeded,
            _ => return Err(InstallError::ExistingResidue),
        },
        repair_eligibility: eligibility.as_ref().map(|(canonical, signature)| {
            crate::operation_status::RepairEligibilityDocument {
                canonical_evidence: canonical,
                signature,
            }
        }),
    }
    .encode();
    atomic_durable_write(
        &paths.state().join(OPERATION_STATUS_FILE),
        contents.as_bytes(),
        0o644,
    )
}

fn atomic_durable_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), InstallError> {
    #[cfg(test)]
    if fail_atomic_write_for_test(bytes) {
        return Err(InstallError::Io);
    }
    let parent = path.parent().ok_or(InstallError::Io)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| InstallError::Io)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        return Err(InstallError::ExistingResidue);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(InstallError::Io)?;
    let temporary = parent.join(format!(".{name}.enoki-write"));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| InstallError::Io)?;
    file.write_all(bytes).map_err(|_| InstallError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| InstallError::Io)?;
    file.sync_all().map_err(|_| InstallError::Io)?;
    fs::rename(&temporary, path).map_err(|_| InstallError::Io)?;
    sync_directory(parent)
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_ATOMIC_WRITE_CONTAINING: std::cell::RefCell<Option<String>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_atomic_write_containing(needle: &str) {
    FAIL_NEXT_ATOMIC_WRITE_CONTAINING.with(|configured| {
        *configured.borrow_mut() = Some(needle.to_owned());
    });
}

#[cfg(test)]
fn fail_atomic_write_for_test(bytes: &[u8]) -> bool {
    FAIL_NEXT_ATOMIC_WRITE_CONTAINING.with(|configured| {
        let mut configured = configured.borrow_mut();
        if configured.as_deref().is_some_and(|needle| {
            bytes
                .windows(needle.len())
                .any(|part| part == needle.as_bytes())
        }) {
            configured.take();
            true
        } else {
            false
        }
    })
}

fn sync_destination_directories(paths: &[PathBuf]) -> Result<(), InstallError> {
    let mut parents = std::collections::BTreeSet::new();
    for path in paths {
        parents.insert(path.parent().ok_or(InstallError::Io)?.to_path_buf());
    }
    for parent in parents {
        sync_directory(&parent)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), InstallError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InstallError::Io)
}

pub(super) fn upgrade_destinations(paths: &FixedInstallPaths) -> Vec<PathBuf> {
    super::installed_layout::registry(paths)
        .into_iter()
        .map(|target| target.destination)
        .collect()
}

fn version_is_newer(target: &str, source: &str) -> bool {
    fn parse(value: &str) -> Option<[u64; 3]> {
        let values = value.strip_prefix('v').unwrap_or(value);
        let mut parts = values.split('.');
        let parsed = [
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        ];
        parts.next().is_none().then_some(parsed)
    }
    parse(target)
        .zip(parse(source))
        .is_some_and(|(target, source)| target > source)
}

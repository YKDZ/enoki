use super::*;

pub(super) const OPERATION_STATUS_PATH: &str = "/var/lib/enoki-probe/probe-operation-status.toml";
pub(super) const REPAIR_INTENT_PATH: &str =
    "/var/lib/enoki-probe/runtime-failure/repair-intent.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstalledBundleRepairError {
    InvalidBoundary,
    RecoveryPending,
}

#[derive(Clone, Debug)]
pub struct InstalledBundleRepairGrant {
    pub(super) authority: InstalledBundleRepairAuthorityV1,
    pub(super) authority_signature: String,
    pub(super) signed_evidence: SignedInstalledBundleFailureEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstalledBundleRepairProgress {
    Admitted,
    ValidationPending,
    RuntimeHealthy,
    ProbeActive,
    InvalidationCommitted,
    EpochRemoved,
    LatchRemoved,
    StatusPublished,
    Unresolved,
}

impl InstalledBundleRepairProgress {
    #[must_use]
    pub fn is_forward_only(self) -> bool {
        matches!(
            self,
            Self::InvalidationCommitted
                | Self::EpochRemoved
                | Self::LatchRemoved
                | Self::StatusPublished
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct InstalledBundleRepairIntent {
    pub(super) schema_version: u16,
    pub(super) state: InstalledBundleRepairProgress,
    pub(super) stage_owner_uid: u32,
    pub(super) stage_receipt: enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
    pub(super) signed_evidence: SignedInstalledBundleFailureEvidence,
    pub(super) authority: InstalledBundleRepairAuthorityV1,
    pub(super) authority_signature: String,
}

impl InstalledBundleRepairGrant {
    #[must_use]
    pub fn authority(&self) -> &InstalledBundleRepairAuthorityV1 {
        &self.authority
    }

    pub fn persist_unresolved(&self) -> Result<(), InstalledBundleRepairError> {
        self.transition_intent(InstalledBundleRepairProgress::Unresolved)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
        write_installed_bundle_repair_status(
            Path::new("/"),
            &self.authority,
            "failed",
            Some("lifecycle.repair_unresolved"),
        )
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)
    }

    pub fn persist_intent(
        &self,
        stage_receipt: &enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
        stage_owner_uid: u32,
    ) -> Result<(), InstalledBundleRepairError> {
        write_installed_bundle_repair_intent(
            Path::new("/"),
            &InstalledBundleRepairIntent {
                schema_version: 1,
                state: InstalledBundleRepairProgress::Admitted,
                stage_owner_uid,
                stage_receipt: stage_receipt.clone(),
                signed_evidence: self.signed_evidence.clone(),
                authority: self.authority.clone(),
                authority_signature: self.authority_signature.clone(),
            },
        )
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)
    }

    pub fn mark_validation_pending(&self) -> Result<(), InstalledBundleRepairError> {
        self.transition_intent(InstalledBundleRepairProgress::ValidationPending)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)
    }

    pub fn mark_runtime_healthy(&self) -> Result<(), InstalledBundleRepairError> {
        self.transition_intent(InstalledBundleRepairProgress::RuntimeHealthy)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)
    }

    pub fn mark_probe_active(&self) -> Result<(), InstalledBundleRepairError> {
        self.transition_intent(InstalledBundleRepairProgress::ProbeActive)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)
    }

    fn transition_intent(&self, state: InstalledBundleRepairProgress) -> std::io::Result<()> {
        let bytes = trusted_file(Path::new(REPAIR_INTENT_PATH), 0, 0o600)?;
        let mut intent: InstalledBundleRepairIntent = serde_json::from_slice(&bytes)
            .map_err(|_| std::io::Error::other("repair intent invalid"))?;
        if intent.schema_version != 1
            || intent.authority != self.authority
            || intent.authority_signature != self.authority_signature
            || intent.signed_evidence != self.signed_evidence
            || !valid_transition(intent.state, state)
        {
            return Err(std::io::Error::other("repair intent binding invalid"));
        }
        intent.state = state;
        write_installed_bundle_repair_intent(Path::new("/"), &intent)
    }

    pub fn complete(&self) -> Result<(String, String), InstalledBundleRepairError> {
        complete_installed_bundle_repair_at(Path::new("/"), 0, &self.authority)
    }
}

pub struct ResumableInstalledBundleRepair {
    pub grant: InstalledBundleRepairGrant,
    pub progress: InstalledBundleRepairProgress,
    pub stage_owner_uid: u32,
    pub stage_receipt: enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
}

pub fn resume_installed_bundle_repair()
-> Result<Option<ResumableInstalledBundleRepair>, InstalledBundleRepairError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(InstalledBundleRepairError::InvalidBoundary);
    }
    resume_installed_bundle_repair_at(Path::new("/"), 0)
}

pub fn installed_bundle_failure_is_current() -> bool {
    if unsafe { libc::geteuid() } != 0 {
        return false;
    }
    if matches!(resume_installed_bundle_repair(), Ok(Some(_))) {
        return true;
    }
    let mut systemd = SystemRuntimeFailureSystemd;
    matches!(
        systemd.fixed_runtime_state(),
        Ok(RuntimeUnitState { active_state, result })
            if active_state == "failed" && result == "start-limit-hit"
    ) && current_epoch_at(Path::new("/"), 0).is_ok()
}

pub(super) fn resume_installed_bundle_repair_at(
    root: &Path,
    expected_uid: u32,
) -> Result<Option<ResumableInstalledBundleRepair>, InstalledBundleRepairError> {
    let path = rooted(root, REPAIR_INTENT_PATH);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = trusted_file(&path, expected_uid, 0o600)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    let intent: InstalledBundleRepairIntent =
        serde_json::from_slice(&bytes).map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    let metadata_bytes = trusted_file(&rooted(root, METADATA_PATH), expected_uid, 0o600)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    let metadata: toml::Value = toml::from_str(
        std::str::from_utf8(&metadata_bytes)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)?,
    )
    .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    let install_key = metadata_string(&metadata, "lifecycle_authority_install_key")
        .and_then(|value| decode_lower_hex_32(&value))
        .ok_or(InstalledBundleRepairError::RecoveryPending)?;
    if intent.schema_version != 1
        || !intent
            .signed_evidence
            .evidence
            .verify(&install_key, &intent.signed_evidence.signature)
        || !intent
            .authority
            .verify(&install_key, &intent.authority_signature)
        || !intent
            .authority
            .matches_evidence(&intent.signed_evidence.evidence)
        || !repair_generation_is_still_terminal(root, expected_uid, &intent)?
        || intent.stage_receipt.operation_id != intent.authority.repair_operation_id
        || intent.stage_receipt.target_version != intent.authority.bundle_version
        || intent.stage_receipt.target_manifest_sha256 != intent.authority.manifest_sha256
        || intent.stage_receipt.target_asset_set_digest != intent.authority.target_asset_set_digest
    {
        return Err(InstalledBundleRepairError::RecoveryPending);
    }
    Ok(Some(ResumableInstalledBundleRepair {
        grant: InstalledBundleRepairGrant {
            authority: intent.authority,
            authority_signature: intent.authority_signature,
            signed_evidence: intent.signed_evidence,
        },
        progress: intent.state,
        stage_owner_uid: intent.stage_owner_uid,
        stage_receipt: intent.stage_receipt,
    }))
}

fn repair_generation_is_still_terminal(
    root: &Path,
    expected_uid: u32,
    intent: &InstalledBundleRepairIntent,
) -> Result<bool, InstalledBundleRepairError> {
    if intent.state.is_forward_only() {
        return Ok(intent.authority.generation == intent.signed_evidence.evidence.generation);
    }
    if let Ok((epoch, _)) = current_epoch_at(root, expected_uid) {
        return Ok(intent.authority.generation == epoch.generation);
    }
    if intent.state != InstalledBundleRepairProgress::RuntimeHealthy {
        return Ok(false);
    }
    let latch = trusted_file(&rooted(root, LATCH_PATH), expected_uid, 0o600)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    Ok(latch == intent.authority.generation.as_bytes())
}

pub(super) fn write_installed_bundle_repair_intent(
    root: &Path,
    intent: &InstalledBundleRepairIntent,
) -> std::io::Result<()> {
    let bytes =
        serde_json::to_vec(intent).map_err(|_| std::io::Error::other("repair intent invalid"))?;
    atomic_write(
        &rooted(root, REPAIR_INTENT_PATH),
        &bytes,
        0o600,
        Some((0, 0)),
    )
}

pub(super) fn complete_installed_bundle_repair_at(
    root: &Path,
    expected_uid: u32,
    authority: &InstalledBundleRepairAuthorityV1,
) -> Result<(String, String), InstalledBundleRepairError> {
    let intent_path = rooted(root, REPAIR_INTENT_PATH);
    let intent_bytes = trusted_file(&intent_path, expected_uid, 0o600)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    let mut intent: InstalledBundleRepairIntent = serde_json::from_slice(&intent_bytes)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    if intent.schema_version != 1 || intent.authority != *authority {
        return Err(InstalledBundleRepairError::RecoveryPending);
    }
    if intent.state == InstalledBundleRepairProgress::ProbeActive {
        intent.state = InstalledBundleRepairProgress::InvalidationCommitted;
        write_installed_bundle_repair_intent(root, &intent)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    } else if !intent.state.is_forward_only() {
        return Err(InstalledBundleRepairError::RecoveryPending);
    }
    let epoch_path = rooted(root, EPOCH_PATH);
    let generation_matches = if epoch_path.exists() {
        current_epoch_at(root, expected_uid)
            .map(|(epoch, _)| epoch.generation == authority.generation)
            .unwrap_or(false)
    } else {
        intent.state.is_forward_only()
    };
    if !generation_matches {
        return Err(InstalledBundleRepairError::RecoveryPending);
    }
    if intent.state == InstalledBundleRepairProgress::InvalidationCommitted {
        remove_regular_file_if_present(&epoch_path, 0o600, expected_uid)?;
        intent.state = InstalledBundleRepairProgress::EpochRemoved;
        write_installed_bundle_repair_intent(root, &intent)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    }
    if intent.state == InstalledBundleRepairProgress::EpochRemoved {
        remove_regular_file_if_present(&rooted(root, LATCH_PATH), 0o600, expected_uid)?;
        intent.state = InstalledBundleRepairProgress::LatchRemoved;
        write_installed_bundle_repair_intent(root, &intent)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    }
    if intent.state == InstalledBundleRepairProgress::LatchRemoved {
        write_installed_bundle_repair_status(root, authority, "succeeded", None)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
        intent.state = InstalledBundleRepairProgress::StatusPublished;
        write_installed_bundle_repair_intent(root, &intent)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    }
    remove_regular_file_if_present(&intent_path, 0o600, expected_uid)?;
    Ok((authority.probe_id.clone(), authority.bundle_version.clone()))
}

fn remove_regular_file_if_present(
    path: &Path,
    mode: u32,
    expected_uid: u32,
) -> Result<(), InstalledBundleRepairError> {
    match remove_regular_file(path, mode, Some((expected_uid, expected_uid))) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstalledBundleRepairError::RecoveryPending),
    }
}

fn valid_transition(
    current: InstalledBundleRepairProgress,
    next: InstalledBundleRepairProgress,
) -> bool {
    matches!(
        (current, next),
        (
            InstalledBundleRepairProgress::Admitted,
            InstalledBundleRepairProgress::ValidationPending
        ) | (
            InstalledBundleRepairProgress::ValidationPending,
            InstalledBundleRepairProgress::RuntimeHealthy
        ) | (
            InstalledBundleRepairProgress::RuntimeHealthy,
            InstalledBundleRepairProgress::ProbeActive
        ) | (
            InstalledBundleRepairProgress::Admitted
                | InstalledBundleRepairProgress::ValidationPending
                | InstalledBundleRepairProgress::RuntimeHealthy
                | InstalledBundleRepairProgress::ProbeActive,
            InstalledBundleRepairProgress::Unresolved
        )
    )
}

pub(super) fn write_installed_bundle_repair_status(
    root: &Path,
    authority: &InstalledBundleRepairAuthorityV1,
    status: &str,
    error_code: Option<&str>,
) -> std::io::Result<()> {
    let status = match (status, error_code) {
        ("running", None) => enoki_probe_bootstrap::operation_status::OperationStatus::Running,
        ("succeeded", None) => enoki_probe_bootstrap::operation_status::OperationStatus::Succeeded,
        ("failed", Some(error_code)) => {
            enoki_probe_bootstrap::operation_status::OperationStatus::Failed { error_code }
        }
        _ => return Err(std::io::Error::other("repair status invalid")),
    };
    let contents = enoki_probe_bootstrap::operation_status::OperationStatusDocument {
        operation_id: &authority.repair_operation_id,
        target_probe_version: &authority.bundle_version,
        status,
        repair_eligibility: None,
    }
    .encode();
    atomic_write(
        &rooted(root, OPERATION_STATUS_PATH),
        contents.as_bytes(),
        0o644,
        Some((unsafe { libc::geteuid() }, unsafe { libc::getegid() })),
    )
}

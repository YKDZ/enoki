use super::*;

mod live;
pub(crate) use live::{LiveInstalledBundleRepairError, drive_live_installed_bundle_repair};

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
    pub(super) root: PathBuf,
    pub(super) expected_uid: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstalledBundleRepairProgress {
    Admitted,
    ValidationPending,
    TemporaryRuntimeHealthy,
    ProbeActive,
    InvalidationCommitted,
    EpochRemoved,
    LatchRemoved,
    CanonicalRuntimeHealthy,
    StatusPublished,
}

impl InstalledBundleRepairProgress {
    #[must_use]
    pub fn is_forward_only(self) -> bool {
        matches!(
            self,
            Self::ProbeActive
                | Self::InvalidationCommitted
                | Self::EpochRemoved
                | Self::LatchRemoved
                | Self::CanonicalRuntimeHealthy
                | Self::StatusPublished
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct InstalledBundleRepairIntent {
    pub(super) schema_version: u16,
    pub(super) state: InstalledBundleRepairProgress,
    #[serde(default)]
    pub(super) last_error_code: Option<String>,
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

    pub fn persist_failure(&self, error_code: &str) -> Result<(), InstalledBundleRepairError> {
        let bytes = trusted_file(
            &rooted(&self.root, REPAIR_INTENT_PATH),
            self.expected_uid,
            0o600,
        )
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
        let mut intent: InstalledBundleRepairIntent = serde_json::from_slice(&bytes)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
        if intent.schema_version != 2
            || intent.authority != self.authority
            || intent.authority_signature != self.authority_signature
            || intent.signed_evidence != self.signed_evidence
        {
            return Err(InstalledBundleRepairError::RecoveryPending);
        }
        intent.last_error_code = Some(error_code.to_owned());
        write_installed_bundle_repair_intent(&self.root, &intent)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
        if intent.state.is_forward_only() {
            return Ok(());
        }
        write_installed_bundle_repair_status(
            &self.root,
            &self.authority,
            "failed",
            Some(error_code),
        )
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)
    }

    pub fn persist_intent(
        &self,
        stage_receipt: &enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
        stage_owner_uid: u32,
    ) -> Result<(), InstalledBundleRepairError> {
        write_installed_bundle_repair_intent(
            &self.root,
            &InstalledBundleRepairIntent {
                schema_version: 2,
                state: InstalledBundleRepairProgress::Admitted,
                last_error_code: None,
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

    pub fn mark_temporary_runtime_healthy(&self) -> Result<(), InstalledBundleRepairError> {
        self.transition_intent(InstalledBundleRepairProgress::TemporaryRuntimeHealthy)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)
    }

    pub fn mark_probe_active(&self) -> Result<(), InstalledBundleRepairError> {
        self.transition_intent(InstalledBundleRepairProgress::ProbeActive)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)
    }

    pub fn mark_canonical_runtime_healthy(&self) -> Result<(), InstalledBundleRepairError> {
        self.transition_intent(InstalledBundleRepairProgress::CanonicalRuntimeHealthy)
            .map_err(|_| InstalledBundleRepairError::RecoveryPending)
    }

    fn transition_intent(&self, state: InstalledBundleRepairProgress) -> std::io::Result<()> {
        let bytes = trusted_file(
            &rooted(&self.root, REPAIR_INTENT_PATH),
            self.expected_uid,
            0o600,
        )?;
        let mut intent: InstalledBundleRepairIntent = serde_json::from_slice(&bytes)
            .map_err(|_| std::io::Error::other("repair intent invalid"))?;
        if intent.schema_version != 2
            || intent.authority != self.authority
            || intent.authority_signature != self.authority_signature
            || intent.signed_evidence != self.signed_evidence
            || !valid_transition(intent.state, state)
        {
            return Err(std::io::Error::other("repair intent binding invalid"));
        }
        intent.state = state;
        write_installed_bundle_repair_intent(&self.root, &intent)
    }

    pub fn invalidate_failure_evidence(&self) -> Result<(), InstalledBundleRepairError> {
        invalidate_installed_bundle_failure_at(&self.root, self.expected_uid, &self.authority)
    }

    pub fn publish_success(&self) -> Result<(String, String), InstalledBundleRepairError> {
        publish_installed_bundle_repair_success_at(&self.root, self.expected_uid, &self.authority)
    }

    pub fn finish_success(&self) -> Result<(), InstalledBundleRepairError> {
        finish_installed_bundle_repair_success_at(&self.root, self.expected_uid, &self.authority)
    }
}

pub(crate) struct ResumableInstalledBundleRepair {
    pub(super) grant: InstalledBundleRepairGrant,
    pub(super) progress: InstalledBundleRepairProgress,
    pub(super) stage_owner_uid: u32,
    pub(super) stage_receipt: enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
}

pub(crate) trait InstalledBundleRepairEffects {
    type Error;

    fn restore_bundle(
        &mut self,
        receipt: &enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
        owner_uid: u32,
        authority: &InstalledBundleRepairAuthorityV1,
    ) -> Result<(), Self::Error>;
    fn validate_temporary_runtime(&mut self) -> Result<(), Self::Error>;
    fn activate_probe_on_canonical_gate(&mut self) -> Result<(), Self::Error>;
    fn validate_canonical_runtime(&mut self) -> Result<(), Self::Error>;
    fn recover_preboundary_reporting(&mut self) -> Result<(), Self::Error>;
    fn verify_bundle_restore_complete(
        &mut self,
        receipt: &enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
        owner_uid: u32,
        authority: &InstalledBundleRepairAuthorityV1,
    ) -> Result<(), Self::Error>;
    fn retire_bundle_restore(
        &mut self,
        receipt: &enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
        owner_uid: u32,
        authority: &InstalledBundleRepairAuthorityV1,
    ) -> Result<(), Self::Error>;
    fn remove_stage(&mut self, operation_id: &str, owner_uid: u32) -> Result<(), Self::Error>;
    fn error_code<'a>(&self, error: &'a Self::Error) -> &'a str;
}

#[derive(Debug)]
pub(crate) enum InstalledBundleRepairDriveError<E> {
    Effect(E),
    RecoveryPending(&'static str),
}

pub(crate) struct InstalledBundleRepairOutcome {
    pub(crate) probe_id: String,
    pub(crate) repaired_version: String,
}

pub(crate) fn begin_installed_bundle_repair(
    grant: InstalledBundleRepairGrant,
    stage_receipt: enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
    stage_owner_uid: u32,
) -> Result<ResumableInstalledBundleRepair, InstalledBundleRepairError> {
    grant.persist_intent(&stage_receipt, stage_owner_uid)?;
    Ok(ResumableInstalledBundleRepair {
        grant,
        progress: InstalledBundleRepairProgress::Admitted,
        stage_owner_uid,
        stage_receipt,
    })
}

pub(crate) fn drive_installed_bundle_repair<E: InstalledBundleRepairEffects>(
    session: ResumableInstalledBundleRepair,
    effects: &mut E,
) -> Result<InstalledBundleRepairOutcome, InstalledBundleRepairDriveError<E::Error>> {
    let ResumableInstalledBundleRepair {
        grant,
        mut progress,
        stage_owner_uid,
        stage_receipt,
    } = session;

    let preboundary = (|| {
        if progress == InstalledBundleRepairProgress::Admitted {
            effects
                .restore_bundle(&stage_receipt, stage_owner_uid, grant.authority())
                .map_err(InstalledBundleRepairDriveError::Effect)?;
            grant.mark_validation_pending().map_err(|_| {
                InstalledBundleRepairDriveError::RecoveryPending(
                    "probe_repair_intent_persist_failed",
                )
            })?;
            progress = InstalledBundleRepairProgress::ValidationPending;
        }
        if progress == InstalledBundleRepairProgress::ValidationPending {
            effects
                .validate_temporary_runtime()
                .map_err(InstalledBundleRepairDriveError::Effect)?;
            grant.mark_temporary_runtime_healthy().map_err(|_| {
                InstalledBundleRepairDriveError::RecoveryPending(
                    "probe_repair_intent_persist_failed",
                )
            })?;
            progress = InstalledBundleRepairProgress::TemporaryRuntimeHealthy;
        }
        if progress == InstalledBundleRepairProgress::TemporaryRuntimeHealthy {
            effects
                .activate_probe_on_canonical_gate()
                .map_err(InstalledBundleRepairDriveError::Effect)?;
            grant.mark_probe_active().map_err(|_| {
                InstalledBundleRepairDriveError::RecoveryPending(
                    "probe_repair_intent_persist_failed",
                )
            })?;
            progress = InstalledBundleRepairProgress::ProbeActive;
        }
        Ok::<(), InstalledBundleRepairDriveError<E::Error>>(())
    })();
    if let Err(error) = preboundary {
        if let InstalledBundleRepairDriveError::Effect(ref effect_error) = error {
            let code = effects.error_code(effect_error).to_owned();
            let _ = effects.recover_preboundary_reporting();
            grant.persist_failure(&code).map_err(|_| {
                InstalledBundleRepairDriveError::RecoveryPending(
                    "probe_repair_intent_persist_failed",
                )
            })?;
        }
        return Err(error);
    }

    if matches!(
        progress,
        InstalledBundleRepairProgress::ProbeActive
            | InstalledBundleRepairProgress::InvalidationCommitted
            | InstalledBundleRepairProgress::EpochRemoved
            | InstalledBundleRepairProgress::LatchRemoved
    ) {
        if grant.invalidate_failure_evidence().is_err() {
            let code = "probe_repair_completion_persist_failed";
            let _ = grant.persist_failure(code);
            return Err(InstalledBundleRepairDriveError::RecoveryPending(code));
        }
        progress = InstalledBundleRepairProgress::LatchRemoved;
    }
    if progress == InstalledBundleRepairProgress::LatchRemoved {
        if let Err(error) = effects.validate_canonical_runtime() {
            let code = effects.error_code(&error).to_owned();
            grant.persist_failure(&code).map_err(|_| {
                InstalledBundleRepairDriveError::RecoveryPending(
                    "probe_repair_intent_persist_failed",
                )
            })?;
            return Err(InstalledBundleRepairDriveError::Effect(error));
        }
        grant.mark_canonical_runtime_healthy().map_err(|_| {
            InstalledBundleRepairDriveError::RecoveryPending("probe_repair_intent_persist_failed")
        })?;
    }
    let (probe_id, repaired_version) = if progress == InstalledBundleRepairProgress::StatusPublished
    {
        (
            grant.authority().probe_id.clone(),
            grant.authority().bundle_version.clone(),
        )
    } else {
        effects
            .verify_bundle_restore_complete(&stage_receipt, stage_owner_uid, grant.authority())
            .map_err(InstalledBundleRepairDriveError::Effect)?;
        grant.publish_success().map_err(|_| {
            InstalledBundleRepairDriveError::RecoveryPending(
                "probe_repair_completion_persist_failed",
            )
        })?
    };
    effects
        .retire_bundle_restore(&stage_receipt, stage_owner_uid, grant.authority())
        .map_err(InstalledBundleRepairDriveError::Effect)?;
    effects
        .remove_stage(&stage_receipt.operation_id, stage_owner_uid)
        .map_err(InstalledBundleRepairDriveError::Effect)?;
    grant.finish_success().map_err(|_| {
        InstalledBundleRepairDriveError::RecoveryPending("probe_repair_completion_persist_failed")
    })?;
    Ok(InstalledBundleRepairOutcome {
        probe_id,
        repaired_version,
    })
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
    if intent.schema_version != 2
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
            root: root.to_path_buf(),
            expected_uid,
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
    if intent.state != InstalledBundleRepairProgress::TemporaryRuntimeHealthy {
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

pub(super) fn invalidate_installed_bundle_failure_at(
    root: &Path,
    expected_uid: u32,
    authority: &InstalledBundleRepairAuthorityV1,
) -> Result<(), InstalledBundleRepairError> {
    let intent_path = rooted(root, REPAIR_INTENT_PATH);
    let intent_bytes = trusted_file(&intent_path, expected_uid, 0o600)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    let mut intent: InstalledBundleRepairIntent = serde_json::from_slice(&intent_bytes)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    if intent.schema_version != 2 || intent.authority != *authority {
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
    Ok(())
}

pub(super) fn publish_installed_bundle_repair_success_at(
    root: &Path,
    expected_uid: u32,
    authority: &InstalledBundleRepairAuthorityV1,
) -> Result<(String, String), InstalledBundleRepairError> {
    let intent_path = rooted(root, REPAIR_INTENT_PATH);
    let intent_bytes = trusted_file(&intent_path, expected_uid, 0o600)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    let mut intent: InstalledBundleRepairIntent = serde_json::from_slice(&intent_bytes)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    if intent.schema_version != 2 || intent.authority != *authority {
        return Err(InstalledBundleRepairError::RecoveryPending);
    }
    if intent.state == InstalledBundleRepairProgress::StatusPublished {
        return Ok((authority.probe_id.clone(), authority.bundle_version.clone()));
    }
    if intent.state != InstalledBundleRepairProgress::CanonicalRuntimeHealthy {
        return Err(InstalledBundleRepairError::RecoveryPending);
    }
    write_installed_bundle_repair_status(root, authority, "succeeded", None)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    intent.state = InstalledBundleRepairProgress::StatusPublished;
    write_installed_bundle_repair_intent(root, &intent)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    Ok((authority.probe_id.clone(), authority.bundle_version.clone()))
}

pub(super) fn finish_installed_bundle_repair_success_at(
    root: &Path,
    expected_uid: u32,
    authority: &InstalledBundleRepairAuthorityV1,
) -> Result<(), InstalledBundleRepairError> {
    let intent_path = rooted(root, REPAIR_INTENT_PATH);
    let intent_bytes = trusted_file(&intent_path, expected_uid, 0o600)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    let intent: InstalledBundleRepairIntent = serde_json::from_slice(&intent_bytes)
        .map_err(|_| InstalledBundleRepairError::RecoveryPending)?;
    if intent.schema_version != 2
        || intent.authority != *authority
        || intent.state != InstalledBundleRepairProgress::StatusPublished
    {
        return Err(InstalledBundleRepairError::RecoveryPending);
    }
    remove_regular_file_if_present(&intent_path, 0o600, expected_uid)
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
            InstalledBundleRepairProgress::TemporaryRuntimeHealthy
        ) | (
            InstalledBundleRepairProgress::TemporaryRuntimeHealthy,
            InstalledBundleRepairProgress::ProbeActive
        ) | (
            InstalledBundleRepairProgress::LatchRemoved,
            InstalledBundleRepairProgress::CanonicalRuntimeHealthy
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

//! Probe Uninstall 的 crate-private 深模块。
//!
//! Hub/Local authority、durable recovery 与固定 cleanup mechanics 都封闭在这里；
//! 父模块只保留 lifecycle/replacement 的窄生产 adapter。

use super::*;

pub(in crate::upgrader) mod cleanup;
use cleanup::*;
#[cfg(test)]
mod tests;

pub(super) const UNINSTALL_CAPSULE_FILE_NAME: &str = "probe-uninstall.capsule";
pub(super) const MAX_UNINSTALL_CAPSULE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum UninstallCapsulePhase {
    Verified,
    Prepared,
    TerminalAcknowledged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResumeDecision {
    Completed,
    RecoveryPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CompanionBinaryFacts {
    pub(super) regular_file: bool,
    pub(super) link_count: u64,
    pub(super) owner_uid: u32,
    pub(super) mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PostCommitSelfFinalizeFacts {
    pub(super) install_metadata_absent: bool,
    pub(super) install_state_absent: bool,
    pub(super) companion_binary: CompanionBinaryFacts,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UninstallRecoveryCapsule {
    pub(super) schema_version: u16,
    pub(super) authority_sha256: String,
    pub(super) phase: UninstallCapsulePhase,
    pub(super) request_json: String,
    pub(super) install_metadata: TrustedProbeInstallMetadata,
}

pub(super) fn run_uninstall_lifecycle_adapter(
    request: &LifecycleRequest,
    metadata: &TrustedProbeInstallMetadata,
    identity: &TrustedProbeInstallPreflight,
    install_metadata_path: &Path,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> LifecycleResponse {
    if !matches!(metadata.schema_version, 4 | 5) {
        return LifecycleResponse::failed("lifecycle.replacement_required");
    }
    let (probe_id, install_state, manifest, version) = match request.authority() {
        LifecycleRequestAuthority::HubOperation {
            probe_id,
            install_state_sha256,
            target_manifest_sha256,
            bundle_version,
            ..
        }
        | LifecycleRequestAuthority::LocalRoot {
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
        LifecycleRequestAuthority::HubUpgrade { .. }
        | LifecycleRequestAuthority::LocalRepair { .. }
        | LifecycleRequestAuthority::ReplacementEnrollment { .. } => {
            return LifecycleResponse::not_enabled();
        }
    };
    if identity.probe_id != *probe_id
        || metadata.install_state_sha256.as_deref() != Some(install_state)
        || metadata.target_manifest_sha256.as_deref() != Some(manifest)
        || metadata.bundle_version.as_deref() != Some(version)
    {
        return LifecycleResponse::failed("lifecycle.authority_mismatch");
    }
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: metadata.identity_path.clone(),
    };
    lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        request,
        &input,
        metadata,
        install_metadata_path,
        transport,
        systemd,
    ))
}

pub(super) struct HubUninstallIntent<'a> {
    operation_id: &'a str,
    operation_token: &'a str,
    mechanics: UninstallMechanics<'a>,
}

impl<'a> HubUninstallIntent<'a> {
    pub(super) fn classify(
        request: &'a LifecycleRequest,
        input: &'a ProbeUninstallerRunInput,
        install_metadata: &'a TrustedProbeInstallMetadata,
        install_metadata_path: &'a Path,
    ) -> Result<Self, ProbeUpgraderRunError> {
        let LifecycleRequestAuthority::HubOperation {
            operation_id,
            operation_token,
            ..
        } = request.authority()
        else {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "uninstall authority is not a Hub operation",
            ));
        };
        Ok(Self {
            operation_id,
            operation_token,
            mechanics: prepare_uninstall_mechanics(
                request,
                input,
                install_metadata,
                install_metadata_path,
            )?,
        })
    }
}

pub(super) struct LocalUninstallIntent<'a> {
    mechanics: UninstallMechanics<'a>,
}

impl<'a> LocalUninstallIntent<'a> {
    pub(super) fn classify(
        request: &'a LifecycleRequest,
        input: &'a ProbeUninstallerRunInput,
        install_metadata: &'a TrustedProbeInstallMetadata,
        install_metadata_path: &'a Path,
    ) -> Result<Self, ProbeUpgraderRunError> {
        if !matches!(
            request.authority(),
            LifecycleRequestAuthority::LocalRoot { .. }
        ) {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "uninstall authority is not local root",
            ));
        }
        Ok(Self {
            mechanics: prepare_uninstall_mechanics(
                request,
                input,
                install_metadata,
                install_metadata_path,
            )?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HubUninstallResult {
    Complete,
    RecoveryPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LocalUninstallComplete;

pub(super) fn prepare_uninstall_mechanics<'a>(
    request: &'a LifecycleRequest,
    input: &'a ProbeUninstallerRunInput,
    install_metadata: &'a TrustedProbeInstallMetadata,
    install_metadata_path: &'a Path,
) -> Result<UninstallMechanics<'a>, ProbeUpgraderRunError> {
    let capsule_path = uninstall_capsule_path(install_metadata_path)?;
    let authority_sha256 = lifecycle_authority_sha256(request)?;
    let capsule = read_uninstall_capsule(&capsule_path)?;
    if let Some(existing) = &capsule
        && (existing.authority_sha256 != authority_sha256
            || existing.install_metadata != *install_metadata)
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule belongs to another authority",
        ));
    }
    let plan = if capsule.is_some() {
        plan_probe_uninstall_recovery(input, install_metadata, install_metadata_path)?
    } else {
        plan_probe_uninstall_cleanup(input, install_metadata, install_metadata_path)?
    };
    let terminal_was_acknowledged = matches!(
        capsule.as_ref().map(|capsule| capsule.phase),
        Some(UninstallCapsulePhase::TerminalAcknowledged)
    );
    let bootstrap_config = if terminal_was_acknowledged {
        None
    } else {
        validate_identity_path(&input.bootstrap_config_path, install_metadata)?;
        let config = read_upgrader_bootstrap_config(&input.bootstrap_config_path)?;
        validate_bootstrap_config_matches_trusted_install_metadata(&config, install_metadata)?;
        Some(config)
    };
    Ok(UninstallMechanics {
        request,
        plan,
        capsule_path,
        capsule,
        bootstrap_config,
        terminal_is_acknowledged: terminal_was_acknowledged,
    })
}

pub(super) struct UninstallMechanics<'a> {
    request: &'a LifecycleRequest,
    plan: ProbeUninstallCleanupPlan<'a>,
    capsule_path: PathBuf,
    capsule: Option<UninstallRecoveryCapsule>,
    bootstrap_config: Option<ProbeUpgraderBootstrapConfig>,
    terminal_is_acknowledged: bool,
}

impl UninstallMechanics<'_> {
    fn request_auth_material(&self) -> Result<(String, String, i64), ProbeUpgraderRunError> {
        let auth =
            probe_request_auth_from_bootstrap_config(self.bootstrap_config.as_ref().ok_or(
                ProbeUpgraderRunError::InvalidInstallMetadata(
                    "uninstall capsule lost report identity",
                ),
            )?)?;
        Ok((
            auth.probe_id.to_owned(),
            auth.probe_private_key_pem.to_owned(),
            auth.server_time_offset_ms,
        ))
    }

    fn verify_hub_authority(
        &mut self,
        operation_id: &str,
        operation_token: &str,
        transport: &mut impl ProbeUpgraderValidationTransport,
    ) -> Result<(), ProbeUpgraderRunError> {
        if self.capsule.is_none() {
            let token_body = format!(
                "{{\"token\":\"{}\"}}",
                json_string_fragment(operation_token)
            );
            let (probe_id, probe_private_key_pem, server_time_offset_ms) =
                self.request_auth_material()?;
            let auth = ProbeRequestAuth {
                probe_id: &probe_id,
                probe_private_key_pem: &probe_private_key_pem,
                server_time_offset_ms,
            };
            transport.post_token_validation(
                &operation_token_validation_url(&self.plan.install_metadata.hub_url, operation_id)?,
                &auth,
                &token_body,
            )?;
        }
        self.persist_verified()
    }

    pub(super) fn persist_verified(&mut self) -> Result<(), ProbeUpgraderRunError> {
        if self.capsule.is_none() {
            persist_uninstall_capsule(
                &self.capsule_path,
                self.request,
                self.plan.install_metadata,
                UninstallCapsulePhase::Verified,
            )?;
            self.capsule = read_uninstall_capsule(&self.capsule_path)?;
        }
        Ok(())
    }

    pub(super) fn prepare(
        &mut self,
        systemd: &mut impl ProbeUpgraderSystemdRunner,
    ) -> Result<(), ProbeUpgraderRunError> {
        if !self.terminal_is_acknowledged {
            prepare_probe_uninstall_cleanup(&self.plan, systemd)?;
            persist_uninstall_capsule(
                &self.capsule_path,
                self.request,
                self.plan.install_metadata,
                UninstallCapsulePhase::Prepared,
            )?;
            self.capsule = read_uninstall_capsule(&self.capsule_path)?;
        }
        Ok(())
    }

    fn report_hub_terminal(
        &mut self,
        operation_id: &str,
        operation_token: &str,
        transport: &mut impl ProbeUpgraderValidationTransport,
    ) -> Result<(), ProbeUpgraderRunError> {
        if !self.terminal_is_acknowledged {
            let body = render_operation_status_body(operation_token, "succeeded", None, None);
            let (probe_id, probe_private_key_pem, server_time_offset_ms) =
                self.request_auth_material()?;
            let auth = ProbeRequestAuth {
                probe_id: &probe_id,
                probe_private_key_pem: &probe_private_key_pem,
                server_time_offset_ms,
            };
            transport.post_operation_status(
                &operation_status_url(&self.plan.install_metadata.hub_url, operation_id)?,
                &auth,
                &body,
            )?;
        }
        Ok(())
    }

    pub(super) fn acknowledge_terminal(&mut self) -> Result<(), ProbeUpgraderRunError> {
        persist_uninstall_capsule(
            &self.capsule_path,
            self.request,
            self.plan.install_metadata,
            UninstallCapsulePhase::TerminalAcknowledged,
        )?;
        self.terminal_is_acknowledged = true;
        Ok(())
    }

    pub(super) fn finalize(
        &mut self,
        systemd: &mut impl ProbeUpgraderSystemdRunner,
    ) -> Result<(), ProbeUpgraderRunError> {
        let companion_binary = self
            .plan
            .install_metadata
            .lifecycle_companion_path
            .as_deref()
            .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
                "schema v4 metadata is missing lifecycle companion",
            ))?;
        finalize_recoverable_uninstall_cleanup(&self.plan, systemd)?;
        let _ = companion_binary;
        commit_lifecycle_capsule_with(&self.capsule_path, remove_path_if_exists)
    }
}

pub(super) fn coordinate_hub_uninstall(
    intent: HubUninstallIntent<'_>,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<HubUninstallResult, ProbeUpgraderRunError> {
    let HubUninstallIntent {
        operation_id,
        operation_token,
        mut mechanics,
    } = intent;
    mechanics.verify_hub_authority(operation_id, operation_token, transport)?;
    mechanics.prepare(systemd)?;
    mechanics.report_hub_terminal(operation_id, operation_token, transport)?;
    if mechanics.acknowledge_terminal().is_err() || mechanics.finalize(systemd).is_err() {
        return Ok(HubUninstallResult::RecoveryPending);
    }
    Ok(HubUninstallResult::Complete)
}

pub(super) fn coordinate_local_uninstall(
    intent: LocalUninstallIntent<'_>,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<LocalUninstallComplete, ProbeUpgraderRunError> {
    let mut mechanics = intent.mechanics;
    mechanics.persist_verified()?;
    mechanics.prepare(systemd)?;
    mechanics.acknowledge_terminal()?;
    mechanics.finalize(systemd)?;
    Ok(LocalUninstallComplete)
}

pub(super) fn adapt_uninstall_wire_request(
    request: &LifecycleRequest,
    input: &ProbeUninstallerRunInput,
    install_metadata: &TrustedProbeInstallMetadata,
    install_metadata_path: &Path,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<ResumeDecision, ProbeUpgraderRunError> {
    match request.authority() {
        LifecycleRequestAuthority::HubOperation { .. } => {
            let intent = HubUninstallIntent::classify(
                request,
                input,
                install_metadata,
                install_metadata_path,
            )?;
            coordinate_hub_uninstall(intent, transport, systemd).map(|result| match result {
                HubUninstallResult::Complete => ResumeDecision::Completed,
                HubUninstallResult::RecoveryPending => ResumeDecision::RecoveryPending,
            })
        }
        LifecycleRequestAuthority::LocalRoot { .. } => {
            let intent = LocalUninstallIntent::classify(
                request,
                input,
                install_metadata,
                install_metadata_path,
            )?;
            coordinate_local_uninstall(intent, systemd)
                .map(|LocalUninstallComplete| ResumeDecision::Completed)
        }
        LifecycleRequestAuthority::HubUpgrade { .. }
        | LifecycleRequestAuthority::LocalRepair { .. }
        | LifecycleRequestAuthority::ReplacementEnrollment { .. } => Err(
            ProbeUpgraderRunError::InvalidInstallMetadata("invalid uninstall authority"),
        ),
    }
}

pub(super) fn commit_lifecycle_capsule_with(
    capsule_path: &Path,
    mut remove: impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
) -> Result<(), ProbeUpgraderRunError> {
    remove(capsule_path)
}

pub(super) fn lifecycle_response_from_resume_decision(
    decision: Result<ResumeDecision, ProbeUpgraderRunError>,
) -> LifecycleResponse {
    match decision {
        Ok(ResumeDecision::Completed) => LifecycleResponse::succeeded(),
        Ok(ResumeDecision::RecoveryPending) => LifecycleResponse::recovery_pending(),
        Err(error) => LifecycleResponse::failed(error.code()),
    }
}

pub(super) fn resume_lifecycle_companion_at(
    install_metadata_path: &Path,
    install_state_dir: &Path,
    companion_binary_path: &Path,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> Result<ResumeDecision, ProbeUpgraderRunError> {
    let capsule_path = uninstall_capsule_path(install_metadata_path)?;
    let Some(capsule) = read_uninstall_capsule(&capsule_path)? else {
        let facts = read_post_commit_self_finalize_facts(
            install_metadata_path,
            install_state_dir,
            companion_binary_path,
        )?;
        return post_commit_self_finalize_policy(facts).map_err(|()| {
            ProbeUpgraderRunError::InvalidInstallMetadata(
                "lifecycle resume is not a committed uninstall",
            )
        });
    };
    let request = LifecycleRequest::decode(capsule.request_json.as_bytes()).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("uninstall capsule request is invalid")
    })?;
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: capsule.install_metadata.identity_path.clone(),
    };
    adapt_uninstall_wire_request(
        &request,
        &input,
        &capsule.install_metadata,
        install_metadata_path,
        transport,
        systemd,
    )
}

pub(super) fn read_post_commit_self_finalize_facts(
    install_metadata_path: &Path,
    install_state_dir: &Path,
    companion_binary_path: &Path,
) -> Result<PostCommitSelfFinalizeFacts, ProbeUpgraderRunError> {
    let install_metadata_absent = path_absence_fact(install_metadata_path)?;
    let install_state_absent = path_absence_fact(install_state_dir)?;
    let binary = fs::symlink_metadata(companion_binary_path).map_err(ProbeUpgraderRunError::Io)?;
    Ok(PostCommitSelfFinalizeFacts {
        install_metadata_absent,
        install_state_absent,
        companion_binary: CompanionBinaryFacts {
            regular_file: binary.file_type().is_file(),
            link_count: binary.nlink(),
            owner_uid: binary.uid(),
            mode: binary.mode() & 0o777,
        },
    })
}

pub(super) fn path_absence_fact(path: &Path) -> Result<bool, ProbeUpgraderRunError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(ProbeUpgraderRunError::Io(error)),
    }
}

pub(super) fn post_commit_self_finalize_policy(
    facts: PostCommitSelfFinalizeFacts,
) -> Result<ResumeDecision, ()> {
    (facts.install_metadata_absent
        && facts.install_state_absent
        && facts.companion_binary.regular_file
        && facts.companion_binary.link_count == 1
        && facts.companion_binary.owner_uid == 0
        && facts.companion_binary.mode == 0o755)
        .then_some(ResumeDecision::Completed)
        .ok_or(())
}

pub(super) fn uninstall_capsule_path(
    install_metadata_path: &Path,
) -> Result<PathBuf, ProbeUpgraderRunError> {
    let Some(parent) = install_metadata_path.parent() else {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "install metadata path has no parent",
        ));
    };
    Ok(parent.join(UNINSTALL_CAPSULE_FILE_NAME))
}

pub(super) fn lifecycle_authority_sha256(
    request: &LifecycleRequest,
) -> Result<String, ProbeUpgraderRunError> {
    request
        .encode()
        .map(|bytes| hex_sha256(&bytes))
        .map_err(|_| ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority invalid"))
}

pub(super) fn read_uninstall_capsule(
    path: &Path,
) -> Result<Option<UninstallRecoveryCapsule>, ProbeUpgraderRunError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ProbeUpgraderRunError::Io(error)),
    };
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > MAX_UNINSTALL_CAPSULE_BYTES
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule is not a root-owned regular 0600 file",
        ));
    }
    let contents = fs::read_to_string(path).map_err(ProbeUpgraderRunError::Io)?;
    let capsule: UninstallRecoveryCapsule = toml::from_str(&contents).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("uninstall capsule is malformed")
    })?;
    let request = LifecycleRequest::decode(capsule.request_json.as_bytes()).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("uninstall capsule request is invalid")
    })?;
    let canonical = toml::to_string(&capsule).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("uninstall capsule is malformed")
    })?;
    if capsule.schema_version != 1
        || canonical != contents
        || lifecycle_authority_sha256(&request)? != capsule.authority_sha256
        || !capsule_receipt_matches_request(&capsule.install_metadata, &request)
    {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule is malformed",
        ));
    }
    Ok(Some(capsule))
}

pub(super) fn persist_uninstall_capsule(
    path: &Path,
    request: &LifecycleRequest,
    install_metadata: &TrustedProbeInstallMetadata,
    phase: UninstallCapsulePhase,
) -> Result<(), ProbeUpgraderRunError> {
    let authority_sha256 = lifecycle_authority_sha256(request)?;
    if !capsule_receipt_matches_request(install_metadata, request) {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule receipt does not match authority",
        ));
    }
    if let Some(existing) = read_uninstall_capsule(path)? {
        if existing.authority_sha256 != authority_sha256 {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "uninstall capsule belongs to another authority",
            ));
        }
        if uninstall_capsule_phase_rank(phase) < uninstall_capsule_phase_rank(existing.phase) {
            return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
                "uninstall capsule phase cannot move backward",
            ));
        }
    }
    let parent = path
        .parent()
        .ok_or(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule path has no parent",
        ))?;
    let temporary = parent.join(".probe-uninstall.capsule.tmp");
    let request_json = String::from_utf8(request.encode().map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority invalid")
    })?)
    .map_err(|_| ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority invalid"))?;
    let capsule = UninstallRecoveryCapsule {
        schema_version: 1,
        authority_sha256,
        phase,
        request_json,
        install_metadata: install_metadata.clone(),
    };
    let contents = toml::to_string(&capsule).map_err(|_| {
        ProbeUpgraderRunError::InvalidInstallMetadata("uninstall capsule is malformed")
    })?;
    if contents.len() as u64 > MAX_UNINSTALL_CAPSULE_BYTES {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule is too large",
        ));
    }
    let _ = fs::remove_file(&temporary);
    write_new_synced_file(&temporary, contents.as_bytes(), 0o600)?;
    fs::rename(&temporary, path).map_err(ProbeUpgraderRunError::Io)?;
    sync_directory(parent)
}

pub(super) fn uninstall_capsule_phase_rank(phase: UninstallCapsulePhase) -> u8 {
    match phase {
        UninstallCapsulePhase::Verified => 0,
        UninstallCapsulePhase::Prepared => 1,
        UninstallCapsulePhase::TerminalAcknowledged => 2,
    }
}

pub(super) fn capsule_receipt_matches_request(
    metadata: &TrustedProbeInstallMetadata,
    request: &LifecycleRequest,
) -> bool {
    let (install_state, manifest, version) = match request.authority() {
        LifecycleRequestAuthority::HubOperation {
            install_state_sha256,
            target_manifest_sha256,
            bundle_version,
            ..
        }
        | LifecycleRequestAuthority::LocalRoot {
            install_state_sha256,
            target_manifest_sha256,
            bundle_version,
            ..
        } => (install_state_sha256, target_manifest_sha256, bundle_version),
        LifecycleRequestAuthority::HubUpgrade { .. }
        | LifecycleRequestAuthority::LocalRepair { .. }
        | LifecycleRequestAuthority::ReplacementEnrollment { .. } => return false,
    };
    matches!(metadata.schema_version, 4 | 5)
        && metadata.install_state_sha256.as_deref() == Some(install_state)
        && metadata.target_manifest_sha256.as_deref() == Some(manifest)
        && metadata.bundle_version.as_deref() == Some(version)
}

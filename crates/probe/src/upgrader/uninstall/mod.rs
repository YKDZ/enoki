//! Probe Uninstall 的 crate-private 深模块。
//!
//! Hub/Local authority、durable recovery 与固定 cleanup mechanics 都封闭在这里；
//! 父模块只保留 lifecycle/replacement 的窄生产 adapter。

use super::{
    PRODUCTION_INSTALL_METADATA_PATH, ProbeUninstallerRunInput, ProbeUpgraderBootstrapConfig,
    ProbeUpgraderRunError, ProbeUpgraderSystemdRunner, ProbeUpgraderValidationTransport,
    SystemProbeUpgraderSystemdRunner, TrustedProbeInstallMetadata, TrustedProbeInstallPreflight,
    hex_sha256, json_string_fragment, operation_status_url, operation_token_validation_url,
    probe_request_auth_from_bootstrap_config, read_trusted_probe_install_metadata,
    read_trusted_probe_install_preflight, read_upgrader_bootstrap_config,
    rebase_trusted_install_metadata_paths, remove_path_if_exists, render_operation_status_body,
    sync_directory, validate_bootstrap_config_matches_trusted_install_metadata,
    validate_identity_path, write_new_synced_file,
};
use crate::probe_auth::ProbeRequestAuth;
use enoki_probe_bootstrap::lifecycle::{
    LifecycleRequest, LifecycleRequestAuthority, LifecycleResponse,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

mod cleanup;
use super::replacement::{ReplacementCoordinatorGuard, production_path};
pub(super) use cleanup::commit_replacement_and_cleanup_install_with_systemd;
use cleanup::{
    ProbeUninstallCleanupPlan, finalize_recoverable_uninstall_cleanup,
    plan_probe_uninstall_cleanup, plan_probe_uninstall_recovery, prepare_probe_uninstall_cleanup,
};
#[cfg(test)]
mod tests;

const UNINSTALL_CAPSULE_FILE_NAME: &str = "probe-uninstall.capsule";
const MAX_UNINSTALL_CAPSULE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum UninstallCapsulePhase {
    Verified,
    Prepared,
    TerminalAcknowledged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResumeDecision {
    Completed,
    RecoveryPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompanionBinaryFacts {
    regular_file: bool,
    link_count: u64,
    owner_uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PostCommitSelfFinalizeFacts {
    install_metadata_absent: bool,
    install_state_absent: bool,
    companion_binary: CompanionBinaryFacts,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UninstallRecoveryCapsule {
    schema_version: u16,
    authority_sha256: String,
    phase: UninstallCapsulePhase,
    request_json: String,
    install_metadata: TrustedProbeInstallMetadata,
}

pub(super) fn coordinate(
    request: Option<&LifecycleRequest>,
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> LifecycleResponse {
    let mut systemd = SystemProbeUpgraderSystemdRunner;
    coordinate_at(request, None, transport, &mut systemd)
}

fn coordinate_at(
    request: Option<&LifecycleRequest>,
    production_root: Option<&Path>,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> LifecycleResponse {
    let Ok(_guard) = ReplacementCoordinatorGuard::acquire_existing(production_root) else {
        return LifecycleResponse::failed("probe_uninstall_metadata_invalid");
    };
    let install_metadata_path = production_path(PRODUCTION_INSTALL_METADATA_PATH, production_root);
    let mut metadata = match read_trusted_probe_install_metadata(&install_metadata_path, None) {
        Ok(metadata) => metadata,
        Err(_) => return LifecycleResponse::failed("lifecycle.install_state_invalid"),
    };
    let identity =
        match read_trusted_probe_install_preflight(&install_metadata_path, production_root) {
            Ok(identity) => identity,
            Err(_) => return LifecycleResponse::failed("lifecycle.identity_invalid"),
        };
    rebase_trusted_install_metadata_paths(&mut metadata, production_root);
    let local_request;
    let request = if let Some(request) = request {
        request
    } else {
        let Some((install_state, manifest, version)) = metadata
            .install_state_sha256
            .as_deref()
            .zip(metadata.target_manifest_sha256.as_deref())
            .zip(metadata.bundle_version.as_deref())
            .map(|((install_state, manifest), version)| (install_state, manifest, version))
        else {
            return LifecycleResponse::failed("lifecycle.install_state_invalid");
        };
        local_request = match LifecycleRequest::local_uninstall(
            &identity.probe_id,
            install_state,
            manifest,
            version,
        ) {
            Ok(request) => request,
            Err(_) => return LifecycleResponse::failed("lifecycle.install_state_invalid"),
        };
        &local_request
    };
    run_uninstall_lifecycle_adapter(
        request,
        &metadata,
        &identity,
        &install_metadata_path,
        transport,
        systemd,
    )
}

fn run_uninstall_lifecycle_adapter(
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

struct HubUninstallIntent<'a> {
    operation_id: &'a str,
    operation_token: &'a str,
    mechanics: UninstallMechanics<'a>,
}

impl<'a> HubUninstallIntent<'a> {
    fn classify(
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

struct LocalUninstallIntent<'a> {
    mechanics: UninstallMechanics<'a>,
}

impl<'a> LocalUninstallIntent<'a> {
    fn classify(
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
enum HubUninstallResult {
    Complete,
    RecoveryPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalUninstallComplete;

fn prepare_uninstall_mechanics<'a>(
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

struct UninstallMechanics<'a> {
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

    fn persist_verified(&mut self) -> Result<(), ProbeUpgraderRunError> {
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

    fn prepare(
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
            let body = render_operation_status_body(operation_token, "succeeded");
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

    fn acknowledge_terminal(&mut self) -> Result<(), ProbeUpgraderRunError> {
        persist_uninstall_capsule(
            &self.capsule_path,
            self.request,
            self.plan.install_metadata,
            UninstallCapsulePhase::TerminalAcknowledged,
        )?;
        self.terminal_is_acknowledged = true;
        Ok(())
    }

    fn finalize(
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

fn coordinate_hub_uninstall(
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

fn coordinate_local_uninstall(
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

fn adapt_uninstall_wire_request(
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

fn commit_lifecycle_capsule_with(
    capsule_path: &Path,
    mut remove: impl FnMut(&Path) -> Result<(), ProbeUpgraderRunError>,
) -> Result<(), ProbeUpgraderRunError> {
    remove(capsule_path)
}

fn lifecycle_response_from_resume_decision(
    decision: Result<ResumeDecision, ProbeUpgraderRunError>,
) -> LifecycleResponse {
    match decision {
        Ok(ResumeDecision::Completed) => LifecycleResponse::succeeded(),
        Ok(ResumeDecision::RecoveryPending) => LifecycleResponse::recovery_pending(),
        Err(error) => LifecycleResponse::failed(error.code()),
    }
}

fn resume_lifecycle_companion_decision_at(
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

pub(super) fn resume_lifecycle_companion_at(
    install_metadata_path: &Path,
    install_state_dir: &Path,
    companion_binary_path: &Path,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> LifecycleResponse {
    lifecycle_response_from_resume_decision(resume_lifecycle_companion_decision_at(
        install_metadata_path,
        install_state_dir,
        companion_binary_path,
        transport,
        systemd,
    ))
}

#[cfg(test)]
fn coordinate_lifecycle_companion_recovery_at(
    production_root: Option<&Path>,
    transport: &mut impl ProbeUpgraderValidationTransport,
    systemd: &mut impl ProbeUpgraderSystemdRunner,
) -> LifecycleResponse {
    let Ok(_guard) = ReplacementCoordinatorGuard::acquire_existing(production_root) else {
        return LifecycleResponse::failed("probe_uninstall_metadata_invalid");
    };
    resume_lifecycle_companion_at(
        &production_path(PRODUCTION_INSTALL_METADATA_PATH, production_root),
        &production_path(super::PRODUCTION_INSTALL_STATE_DIR, production_root),
        &production_path(super::LIFECYCLE_COMPANION_BINARY_PATH, production_root),
        transport,
        systemd,
    )
}

fn read_post_commit_self_finalize_facts(
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

fn path_absence_fact(path: &Path) -> Result<bool, ProbeUpgraderRunError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(ProbeUpgraderRunError::Io(error)),
    }
}

fn post_commit_self_finalize_policy(
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

fn uninstall_capsule_path(install_metadata_path: &Path) -> Result<PathBuf, ProbeUpgraderRunError> {
    let Some(parent) = install_metadata_path.parent() else {
        return Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "install metadata path has no parent",
        ));
    };
    Ok(parent.join(UNINSTALL_CAPSULE_FILE_NAME))
}

fn lifecycle_authority_sha256(request: &LifecycleRequest) -> Result<String, ProbeUpgraderRunError> {
    request
        .encode()
        .map(|bytes| hex_sha256(&bytes))
        .map_err(|_| ProbeUpgraderRunError::InvalidInstallMetadata("lifecycle authority invalid"))
}

fn read_uninstall_capsule(
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

fn persist_uninstall_capsule(
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

fn uninstall_capsule_phase_rank(phase: UninstallCapsulePhase) -> u8 {
    match phase {
        UninstallCapsulePhase::Verified => 0,
        UninstallCapsulePhase::Prepared => 1,
        UninstallCapsulePhase::TerminalAcknowledged => 2,
    }
}

fn capsule_receipt_matches_request(
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

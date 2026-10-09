use super::cleanup::{
    StateRootRemovalFault, execute_committed_replacement_cleanup, inject_state_root_removal_fault,
    plan_committed_replacement_cleanup,
};
use super::{
    CompanionBinaryFacts, PostCommitSelfFinalizeFacts, ResumeDecision, UninstallCapsulePhase,
    adapt_uninstall_wire_request, commit_lifecycle_capsule_with,
    lifecycle_response_from_resume_decision, post_commit_self_finalize_policy,
    read_uninstall_capsule, resume_lifecycle_companion_at, run_uninstall_lifecycle_adapter,
    uninstall_capsule_path,
};
use crate::{
    probe_auth::ProbeRequestAuth,
    upgrader::{
        ProbeUninstallerRunInput, ProbeUpgraderRunError, ProbeUpgraderSystemdRunner,
        ProbeUpgraderValidationTransport, TrustedProbeInstallMetadata,
        TrustedProbeInstallPreflight,
    },
};
use enoki_probe_bootstrap::handoff::Enrollment;
use enoki_probe_bootstrap::lifecycle::{LifecycleRequest, LifecycleResponse};
use enoki_probe_bootstrap::replacement::{
    FileReplacementCommitStore, ReplacementCommitFact, ReplacementCommitStore, ReplacementIntent,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Default)]
struct RecordingValidationTransport {
    ack_persistence_blocker: Option<PathBuf>,
    assets: HashMap<String, Vec<u8>>,
    body: String,
    downloads: Vec<String>,
    probe_id: String,
    status_body: String,
    status_failure: bool,
    status_url: String,
    url: String,
}

impl ProbeUpgraderValidationTransport for RecordingValidationTransport {
    fn get_asset(&mut self, url: &str) -> Result<Vec<u8>, ProbeUpgraderRunError> {
        self.downloads.push(url.to_owned());
        self.assets
            .get(url)
            .cloned()
            .ok_or(ProbeUpgraderRunError::AssetMissing)
    }

    fn post_token_validation(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        self.url = url.to_owned();
        self.probe_id = auth.probe_id.to_owned();
        self.body = body.to_owned();
        Ok(())
    }

    fn post_operation_status(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        self.status_url = url.to_owned();
        self.probe_id = auth.probe_id.to_owned();
        self.status_body = body.to_owned();
        if self.status_failure {
            return Err(ProbeUpgraderRunError::UninstallStatusReportFailure(
                "temporary report failure".to_owned(),
            ));
        }
        if let Some(path) = self.ack_persistence_blocker.take() {
            fs::create_dir(path).map_err(ProbeUpgraderRunError::Io)?;
        }
        Ok(())
    }

    fn validate_probe_identity(
        &mut self,
        _url: &str,
        _auth: &ProbeRequestAuth<'_>,
    ) -> Result<(), ProbeUpgraderRunError> {
        Ok(())
    }
}

#[derive(Default)]
struct RecordingSystemdRunner {
    calls: Vec<String>,
    failure_step: Option<&'static str>,
    loaded_service_residue: bool,
}

impl RecordingSystemdRunner {
    fn fail(&self, step: &'static str) -> Result<(), ProbeUpgraderRunError> {
        if self.failure_step == Some(step) {
            return Err(ProbeUpgraderRunError::RestartFailure(format!(
                "{step} failed"
            )));
        }
        Ok(())
    }
}

impl ProbeUpgraderSystemdRunner for RecordingSystemdRunner {
    fn restart_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!("restart {service_name}"));
        self.fail("restart")
    }

    fn stop_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!("stop {service_name}"));
        self.fail("stop")
    }

    fn disable_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!("disable {service_name}"));
        if self.failure_step == Some("disable-probe") && service_name == "enoki-probe" {
            return Err(ProbeUpgraderRunError::RestartFailure(
                "disable-probe failed".to_owned(),
            ));
        }
        self.fail("disable")
    }

    fn daemon_reload(&mut self) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push("daemon-reload".to_owned());
        self.fail("daemon-reload")
    }

    fn reset_failed(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!("reset-failed {service_name}"));
        self.fail("reset-failed")
    }

    fn verify_service_absent(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls
            .push(format!("verify-service-absent {service_name}"));
        if self.loaded_service_residue {
            return Err(ProbeUpgraderRunError::UninstallCleanupFailure {
                action: "verifying the service is absent",
                code: "probe_uninstall_service_residue",
                message: "systemd LoadState is loaded".to_owned(),
            });
        }
        self.fail("verify-service")
    }

    fn remove_service_identity(
        &mut self,
        service_user: &str,
        service_group: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!(
            "remove-service-identity {service_user}:{service_group}"
        ));
        self.fail("remove-account")
    }

    fn remove_owned_ipc_group(
        &mut self,
        group: &str,
        ownership_marker: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        self.calls
            .push(format!("remove-owned-ipc-group {group}:{ownership_marker}"));
        self.fail("remove-ipc-group")
    }
}

struct UninstallCoordinatorFixture {
    metadata: TrustedProbeInstallMetadata,
    metadata_path: PathBuf,
    identity_path: PathBuf,
    companion_path: PathBuf,
}

fn uninstall_coordinator_fixture(root: &Path) -> UninstallCoordinatorFixture {
    let state_dir = root.join("var/lib/enoki-probe");
    let identity_path = state_dir.join("identity/probe-bootstrap.toml");
    let metadata_path = root.join("etc/enoki/probe-install.toml");
    let companion_path = root.join("usr/local/bin/enoki-probe-lifecycle-companion");
    let observation_units = [
        root.join("etc/systemd/system/enoki-observation-runtime.service"),
        root.join("etc/systemd/system/enoki-observation-runtime.socket"),
        root.join("etc/systemd/system/enoki-cpu-resource-provider@.service"),
        root.join("etc/systemd/system/enoki-cpu-resource-provider.socket"),
        root.join("etc/systemd/system/enoki-disk-health-resource-provider@.service"),
        root.join("etc/systemd/system/enoki-disk-health-resource-provider.socket"),
        root.join("etc/systemd/system/enoki-probe-lifecycle-companion@.service"),
        root.join("etc/systemd/system/enoki-probe-lifecycle-companion.socket"),
    ];
    let mut metadata = recovery_metadata(root);
    metadata.state_dir = state_dir;
    metadata.identity_path = identity_path.clone();
    metadata.install_path = root.join("usr/local/bin/enoki-probe");
    metadata.service_unit_path = root.join("etc/systemd/system/enoki-probe.service");
    metadata.operation_status_path = metadata.state_dir.join("probe-operation-status.toml");
    metadata.observation_runtime_path = Some(root.join("usr/local/bin/enoki-observation-runtime"));
    metadata.cpu_provider_path = Some(root.join("usr/local/bin/enoki-cpu-resource-provider"));
    metadata.disk_health_provider_path =
        Some(root.join("usr/local/bin/enoki-disk-health-resource-provider"));
    metadata.lifecycle_companion_path = Some(companion_path.clone());
    metadata.observation_unit_paths = observation_units.to_vec();
    metadata.bootstrap_acquirer_path =
        Some(root.join("usr/local/bin/enoki-probe-bootstrap-acquire"));
    metadata.bootstrap_activator_path =
        Some(root.join("usr/local/bin/enoki-probe-bootstrap-activate"));
    metadata.bootstrap_state_dir = Some(root.join("var/lib/enoki-probe-bootstrap"));
    metadata.probe_ipc_group = Some("enoki-probe-ipc".to_owned());
    metadata.probe_ipc_group_ownership = Some(format!("!enoki-bootstrap-{}", "d".repeat(32)));
    metadata.observation_ipc_group = Some("enoki-observation-ipc".to_owned());

    for path in [
        &metadata_path,
        &metadata.install_path,
        metadata.observation_runtime_path.as_ref().unwrap(),
        metadata.cpu_provider_path.as_ref().unwrap(),
        metadata.disk_health_provider_path.as_ref().unwrap(),
        &metadata.service_unit_path,
        &companion_path,
        metadata.bootstrap_acquirer_path.as_ref().unwrap(),
        metadata.bootstrap_activator_path.as_ref().unwrap(),
    ]
    .into_iter()
    .chain(observation_units.iter())
    {
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
        fs::write(path, "owned").expect("fixture file");
    }
    for path in [
        metadata.bootstrap_acquirer_path.as_ref().unwrap(),
        metadata.bootstrap_activator_path.as_ref().unwrap(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("bootstrap role mode");
    }
    let bootstrap_state = metadata.bootstrap_state_dir.as_ref().unwrap();
    fs::create_dir_all(bootstrap_state.join("trust")).expect("trust state");
    fs::create_dir(bootstrap_state.join("inbox")).expect("inbox state");
    for path in [
        bootstrap_state.as_path(),
        &bootstrap_state.join("trust"),
        &bootstrap_state.join("inbox"),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("bootstrap state mode");
    }
    for entry in ["delegation-generation", ".delegation-generation.lock"] {
        let path = bootstrap_state.join("trust").join(entry);
        fs::write(&path, "owned").expect("trust entry");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("trust entry mode");
    }
    fs::create_dir_all(identity_path.parent().unwrap()).expect("identity parent");
    fs::write(
        &identity_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_private_key_pem = \"test-private-key\"",
            "",
        ]
        .join("\n"),
    )
    .expect("identity config");

    UninstallCoordinatorFixture {
        metadata,
        metadata_path,
        identity_path,
        companion_path,
    }
}

fn remove_path_if_exists(path: &Path) -> Result<(), ProbeUpgraderRunError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn recovery_metadata(root: &Path) -> TrustedProbeInstallMetadata {
    TrustedProbeInstallMetadata {
        schema_version: 4,
        hub_url: "https://hub.example".to_owned(),
        identity_path: root.join("identity.toml"),
        install_path: root.join("enoki-probe"),
        operation_status_path: root.join("status.toml"),
        probe_asset_public_key_sha256: "a".repeat(64),
        probe_distribution_root_sha256: None,
        bootstrap_acquirer_path: Some(root.join("bootstrap-acquire")),
        bootstrap_activator_path: Some(root.join("bootstrap-activate")),
        bootstrap_state_dir: Some(root.join("bootstrap-state")),
        service_name: "enoki-probe".to_owned(),
        service_group: "enoki-probe".to_owned(),
        service_unit_path: root.join("enoki-probe.service"),
        service_user: "enoki-probe".to_owned(),
        state_dir: root.join("state"),
        operation_sudoers_path: None,
        collector_helper_sudoers_path: None,
        old_sudoers_paths: Vec::new(),
        observation_runtime_path: None,
        cpu_provider_path: None,
        disk_health_provider_path: None,
        lifecycle_companion_path: Some(root.join("lifecycle-companion")),
        observation_unit_paths: Vec::new(),
        probe_ipc_group: None,
        probe_ipc_group_ownership: None,
        observation_ipc_group: None,
        install_state_sha256: Some("b".repeat(64)),
        target_manifest_sha256: Some("c".repeat(64)),
        bundle_version: Some("1.2.3".to_owned()),
        lifecycle_authority_install_key: None,
    }
}

#[test]
fn lifecycle_commit_deletes_only_the_capsule_before_process_self_finalization() {
    let capsule = Path::new("/etc/enoki/probe-uninstall.capsule");
    let mut calls = Vec::new();
    let result = commit_lifecycle_capsule_with(capsule, |path| {
        calls.push(path.to_path_buf());
        Err(ProbeUpgraderRunError::Io(std::io::Error::other(
            "injected ordinary transaction failure",
        )))
    });
    assert!(result.is_err());
    assert_eq!(calls, [capsule]);
}

#[test]
fn post_commit_self_finalize_policy_uses_explicit_trusted_facts() {
    let trusted = PostCommitSelfFinalizeFacts {
        install_metadata_absent: true,
        install_state_retired: true,
        companion_binary: CompanionBinaryFacts {
            regular_file: true,
            link_count: 1,
            owner_uid: 0,
            mode: 0o755,
        },
    };
    assert_eq!(
        post_commit_self_finalize_policy(trusted),
        Ok(ResumeDecision::Completed)
    );

    for rejected in [
        PostCommitSelfFinalizeFacts {
            install_metadata_absent: false,
            ..trusted
        },
        PostCommitSelfFinalizeFacts {
            install_state_retired: false,
            ..trusted
        },
        PostCommitSelfFinalizeFacts {
            companion_binary: CompanionBinaryFacts {
                owner_uid: 1000,
                ..trusted.companion_binary
            },
            ..trusted
        },
        PostCommitSelfFinalizeFacts {
            companion_binary: CompanionBinaryFacts {
                mode: 0o775,
                ..trusted.companion_binary
            },
            ..trusted
        },
    ] {
        assert_eq!(post_commit_self_finalize_policy(rejected), Err(()));
    }
}

#[test]
fn resume_decision_maps_to_the_wire_response_at_one_boundary() {
    assert_eq!(
        lifecycle_response_from_resume_decision(Ok(ResumeDecision::Completed)),
        LifecycleResponse::succeeded()
    );
    assert_eq!(
        lifecycle_response_from_resume_decision(Ok(ResumeDecision::RecoveryPending)),
        LifecycleResponse::recovery_pending()
    );
}

#[test]
fn acknowledgement_persistence_interruption_keeps_the_exact_private_capsule_binding() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    let capsule_path = uninstall_capsule_path(&fixture.metadata_path).expect("capsule path");
    let request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_42",
        "operation-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("bound request");
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: fixture.identity_path.clone(),
    };
    let mut first_transport = RecordingValidationTransport {
        status_failure: true,
        ..RecordingValidationTransport::default()
    };
    let mut first_systemd = RecordingSystemdRunner::default();
    let first = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut first_transport,
        &mut first_systemd,
    ));
    assert_eq!(first, LifecycleResponse::failed("probe_uninstall_failed"));
    let prepared = fs::read(&capsule_path).expect("prepared bytes");
    let prepared_capsule = read_uninstall_capsule(&capsule_path)
        .expect("read prepared capsule")
        .expect("prepared capsule");
    assert_eq!(prepared_capsule.phase, UninstallCapsulePhase::Prepared);
    let mut recovery_asset_paths = vec![
        fixture.metadata_path.clone(),
        fixture.identity_path.clone(),
        fixture.companion_path.clone(),
    ];
    recovery_asset_paths.extend(
        fixture
            .metadata
            .observation_unit_paths
            .iter()
            .filter(|path| {
                path.file_name().is_some_and(|name| {
                    name == "enoki-probe-lifecycle-companion@.service"
                        || name == "enoki-probe-lifecycle-companion.socket"
                })
            })
            .cloned(),
    );
    let recovery_assets = recovery_asset_paths
        .into_iter()
        .map(|path| (path.clone(), fs::read(path).expect("recovery asset")))
        .collect::<Vec<_>>();

    let persistence_temporary = capsule_path
        .parent()
        .expect("capsule parent")
        .join(".probe-uninstall.capsule.tmp");
    let mut acknowledged_transport = RecordingValidationTransport {
        ack_persistence_blocker: Some(persistence_temporary.clone()),
        ..RecordingValidationTransport::default()
    };
    let mut acknowledged_systemd = RecordingSystemdRunner::default();
    let interrupted = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut acknowledged_transport,
        &mut acknowledged_systemd,
    ));
    assert!(acknowledged_transport.url.is_empty());
    assert!(
        acknowledged_transport
            .status_body
            .contains("\"status\":\"succeeded\"")
    );
    assert_eq!(interrupted, LifecycleResponse::recovery_pending());
    assert_eq!(
        fs::read(&capsule_path).expect("unchanged capsule"),
        prepared
    );
    let unchanged_capsule = read_uninstall_capsule(&capsule_path)
        .expect("read unchanged capsule")
        .expect("unchanged capsule");
    assert_eq!(unchanged_capsule.phase, prepared_capsule.phase);
    assert_eq!(
        unchanged_capsule.authority_sha256,
        prepared_capsule.authority_sha256
    );
    assert_eq!(
        unchanged_capsule.request_json,
        prepared_capsule.request_json
    );
    for (path, bytes) in &recovery_assets {
        assert_eq!(fs::read(path).expect("unchanged recovery asset"), *bytes);
    }

    fs::remove_dir(&persistence_temporary).expect("remove injected failure");
    let mut retry_transport = RecordingValidationTransport::default();
    let mut retry_systemd = RecordingSystemdRunner::default();
    let retry = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut retry_transport,
        &mut retry_systemd,
    ));
    assert_eq!(retry, LifecycleResponse::succeeded());
    assert!(
        retry_transport.url.is_empty(),
        "prepared retry skips token validation"
    );
    assert!(
        retry_transport
            .status_body
            .contains("\"status\":\"succeeded\"")
    );
    for path in [
        &capsule_path,
        &fixture.metadata_path,
        &fixture.identity_path,
        &fixture.metadata.state_dir,
    ] {
        assert!(!path.exists(), "retry residue: {}", path.display());
    }
}

#[test]
fn local_uninstall_never_uses_hub_transport_and_propagates_finalize_failure() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    let request =
        LifecycleRequest::local_uninstall("probe_01", &"b".repeat(64), &"c".repeat(64), "1.2.3")
            .expect("bound local uninstall request");
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: fixture.identity_path.clone(),
    };
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner {
        failure_step: Some("remove-account"),
        ..RecordingSystemdRunner::default()
    };

    let result = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut transport,
        &mut systemd,
    ));

    assert_eq!(
        result,
        LifecycleResponse::failed("probe_uninstall_service_account_remove_failed")
    );
    assert!(transport.url.is_empty());
    assert!(transport.status_url.is_empty());
    assert!(fixture.companion_path.exists());
}

fn schema_four_prepare_systemd_transcript() -> Vec<String> {
    [
        "stop enoki-disk-health-resource-provider@*.service",
        "disable enoki-disk-health-resource-provider@*.service",
        "stop enoki-cpu-resource-provider@*.service",
        "disable enoki-cpu-resource-provider@*.service",
        "stop enoki-disk-health-resource-provider.socket",
        "disable enoki-disk-health-resource-provider.socket",
        "stop enoki-cpu-resource-provider.socket",
        "disable enoki-cpu-resource-provider.socket",
        "stop enoki-observation-runtime.socket",
        "disable enoki-observation-runtime.socket",
        "stop enoki-observation-runtime.service",
        "disable enoki-observation-runtime.service",
        "stop enoki-probe",
        "disable enoki-probe",
        "daemon-reload",
        "reset-failed enoki-probe",
        "verify-service-absent enoki-probe",
        "reset-failed enoki-observation-runtime.service",
        "verify-service-absent enoki-observation-runtime.service",
        "reset-failed enoki-observation-runtime.socket",
        "verify-service-absent enoki-observation-runtime.socket",
        "reset-failed enoki-cpu-resource-provider.socket",
        "verify-service-absent enoki-cpu-resource-provider.socket",
        "reset-failed enoki-disk-health-resource-provider.socket",
        "verify-service-absent enoki-disk-health-resource-provider.socket",
        "reset-failed enoki-cpu-resource-provider@*.service",
        "verify-service-absent enoki-cpu-resource-provider@*.service",
        "reset-failed enoki-disk-health-resource-provider@*.service",
        "verify-service-absent enoki-disk-health-resource-provider@*.service",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn local_uninstall_request() -> LifecycleRequest {
    LifecycleRequest::local_uninstall("probe_01", &"b".repeat(64), &"c".repeat(64), "1.2.3")
        .expect("bound local uninstall request")
}

#[test]
fn complete_local_workflow_maps_disable_failure_at_the_exact_effect_boundary() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: fixture.identity_path.clone(),
    };
    let preserved = [
        fixture.metadata_path.clone(),
        fixture.identity_path.clone(),
        fixture.metadata.install_path.clone(),
        fixture.metadata.service_unit_path.clone(),
        fixture.companion_path.clone(),
    ]
    .into_iter()
    .chain(fixture.metadata.observation_unit_paths.iter().cloned())
    .chain(fixture.metadata.observation_runtime_path.iter().cloned())
    .chain(fixture.metadata.cpu_provider_path.iter().cloned())
    .chain(fixture.metadata.disk_health_provider_path.iter().cloned())
    .chain(fixture.metadata.bootstrap_acquirer_path.iter().cloned())
    .chain(fixture.metadata.bootstrap_activator_path.iter().cloned())
    .map(|path| (path.clone(), fs::read(path).expect("preserved asset")))
    .collect::<Vec<_>>();
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner {
        failure_step: Some("disable-probe"),
        ..RecordingSystemdRunner::default()
    };

    let response = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &local_uninstall_request(),
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut transport,
        &mut systemd,
    ));

    assert_eq!(
        response,
        LifecycleResponse::failed("probe_uninstall_service_disable_failed")
    );
    assert_eq!(
        systemd.calls,
        schema_four_prepare_systemd_transcript()[..14]
    );
    assert!(transport.url.is_empty() && transport.status_url.is_empty());
    for (path, bytes) in preserved {
        assert_eq!(fs::read(path).expect("asset unchanged"), bytes);
    }
}

#[test]
fn complete_local_workflow_maps_loaded_service_residue_at_the_exact_effect_boundary() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: fixture.identity_path.clone(),
    };
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner {
        loaded_service_residue: true,
        ..RecordingSystemdRunner::default()
    };

    let response = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &local_uninstall_request(),
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut transport,
        &mut systemd,
    ));

    assert_eq!(
        response,
        LifecycleResponse::failed("probe_uninstall_service_residue")
    );
    assert_eq!(
        systemd.calls,
        schema_four_prepare_systemd_transcript()[..17]
    );
    assert!(transport.url.is_empty() && transport.status_url.is_empty());
    for path in [
        &fixture.metadata.install_path,
        &fixture.identity_path,
        &fixture.metadata_path,
        &fixture.companion_path,
    ]
    .into_iter()
    .chain(fixture.metadata.observation_runtime_path.iter())
    .chain(fixture.metadata.cpu_provider_path.iter())
    .chain(fixture.metadata.disk_health_provider_path.iter())
    .chain(fixture.metadata.bootstrap_acquirer_path.iter())
    .chain(fixture.metadata.bootstrap_activator_path.iter())
    {
        assert!(path.exists(), "later asset changed: {}", path.display());
    }
    assert!(
        fixture
            .metadata
            .bootstrap_state_dir
            .as_ref()
            .unwrap()
            .exists()
    );
    assert!(!fixture.metadata.service_unit_path.exists());
    for path in &fixture.metadata.observation_unit_paths {
        let companion_activation = path.file_name().is_some_and(|name| {
            name == "enoki-probe-lifecycle-companion@.service"
                || name == "enoki-probe-lifecycle-companion.socket"
        });
        assert_eq!(path.exists(), companion_activation, "{}", path.display());
    }
}

#[test]
fn complete_local_workflow_maps_account_failure_at_the_exact_effect_boundary() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: fixture.identity_path.clone(),
    };
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner {
        failure_step: Some("remove-account"),
        ..RecordingSystemdRunner::default()
    };

    let response = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &local_uninstall_request(),
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut transport,
        &mut systemd,
    ));

    assert_eq!(
        response,
        LifecycleResponse::failed("probe_uninstall_service_account_remove_failed")
    );
    let mut expected = schema_four_prepare_systemd_transcript();
    expected.push("remove-service-identity enoki-probe:enoki-probe".to_owned());
    assert_eq!(systemd.calls, expected);
    assert!(transport.url.is_empty() && transport.status_url.is_empty());
    for path in [
        &fixture.metadata_path,
        &fixture.identity_path,
        &fixture.companion_path,
    ]
    .into_iter()
    .chain(
        fixture
            .metadata
            .observation_unit_paths
            .iter()
            .filter(|path| {
                path.file_name().is_some_and(|name| {
                    name == "enoki-probe-lifecycle-companion@.service"
                        || name == "enoki-probe-lifecycle-companion.socket"
                })
            }),
    ) {
        assert!(path.exists(), "reentry asset changed: {}", path.display());
    }
    for path in [
        fixture.metadata.bootstrap_acquirer_path.as_ref().unwrap(),
        fixture.metadata.bootstrap_activator_path.as_ref().unwrap(),
        fixture.metadata.bootstrap_state_dir.as_ref().unwrap(),
        &fixture.metadata.install_path,
        &fixture.metadata.service_unit_path,
    ]
    .into_iter()
    .chain(fixture.metadata.observation_runtime_path.iter())
    .chain(fixture.metadata.cpu_provider_path.iter())
    .chain(fixture.metadata.disk_health_provider_path.iter())
    .chain(
        fixture
            .metadata
            .observation_unit_paths
            .iter()
            .filter(|path| {
                path.file_name().is_none_or(|name| {
                    name != "enoki-probe-lifecycle-companion@.service"
                        && name != "enoki-probe-lifecycle-companion.socket"
                })
            }),
    ) {
        assert!(
            !path.exists(),
            "completed prior effect remains: {}",
            path.display()
        );
    }
}

#[test]
fn production_uninstall_adapter_fails_closed_for_schema_two_and_three_without_effects() {
    for schema_version in [2, 3] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut fixture = uninstall_coordinator_fixture(temporary.path());
        fixture.metadata.schema_version = schema_version;
        let request = LifecycleRequest::hub_uninstall(
            "probe_01",
            "operation_42",
            "operation-token",
            &"b".repeat(64),
            &"c".repeat(64),
            "1.2.3",
        )
        .expect("bound uninstall request");
        let identity = TrustedProbeInstallPreflight {
            hub_url: "https://hub.example".to_owned(),
            probe_id: "probe_01".to_owned(),
        };
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();

        let response = run_uninstall_lifecycle_adapter(
            &request,
            &fixture.metadata,
            &identity,
            &fixture.metadata_path,
            &mut transport,
            &mut systemd,
        );

        assert_eq!(
            response,
            LifecycleResponse::failed("lifecycle.replacement_required")
        );
        assert!(transport.url.is_empty());
        assert!(transport.status_url.is_empty());
        assert!(systemd.calls.is_empty());
        assert!(fixture.metadata_path.exists());
        assert!(fixture.identity_path.exists());
        assert!(fixture.companion_path.exists());
    }
}

#[test]
fn schema_five_uninstall_removes_upgrade_companion_roles_and_complete_layout() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let mut fixture = uninstall_coordinator_fixture(temporary.path());
    fixture.metadata.schema_version = 5;
    fixture.metadata.lifecycle_authority_install_key = Some("e".repeat(64));
    let upgrade_service = temporary
        .path()
        .join("etc/systemd/system/enoki-probe-lifecycle-upgrade@.service");
    let upgrade_socket = temporary
        .path()
        .join("etc/systemd/system/enoki-probe-lifecycle-upgrade.socket");
    for path in [&upgrade_service, &upgrade_socket] {
        fs::write(path, "owned").expect("schema five lifecycle unit");
    }
    fixture
        .metadata
        .observation_unit_paths
        .extend([upgrade_service.clone(), upgrade_socket.clone()]);
    let request =
        LifecycleRequest::local_uninstall("probe_01", &"b".repeat(64), &"c".repeat(64), "1.2.3")
            .expect("bound local uninstall request");
    let identity = TrustedProbeInstallPreflight {
        hub_url: "https://hub.example".to_owned(),
        probe_id: "probe_01".to_owned(),
    };
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();

    let response = run_uninstall_lifecycle_adapter(
        &request,
        &fixture.metadata,
        &identity,
        &fixture.metadata_path,
        &mut transport,
        &mut systemd,
    );

    assert_eq!(response, LifecycleResponse::succeeded());
    assert!(transport.url.is_empty());
    assert!(transport.status_url.is_empty());
    assert!(
        fixture.companion_path.exists(),
        "production coordinator leaves the executing binary to the response-flush self-unlink seam"
    );
    remove_path_if_exists(&fixture.companion_path)
        .expect("response-flush self-unlink completes the no-residue boundary");
    for path in fixture
        .metadata
        .observation_unit_paths
        .iter()
        .chain(fixture.metadata.observation_runtime_path.iter())
        .chain(fixture.metadata.cpu_provider_path.iter())
        .chain(fixture.metadata.disk_health_provider_path.iter())
        .chain(fixture.metadata.bootstrap_acquirer_path.iter())
        .chain(fixture.metadata.bootstrap_activator_path.iter())
        .chain([
            &fixture.metadata.install_path,
            &fixture.metadata.service_unit_path,
            &fixture.identity_path,
            &fixture.metadata_path,
            &fixture.metadata.state_dir,
            fixture
                .metadata
                .bootstrap_state_dir
                .as_ref()
                .expect("bootstrap state"),
            &fixture.companion_path,
        ])
    {
        assert!(!path.exists(), "{} remains", path.display());
    }
    assert!(
        systemd
            .calls
            .contains(&"stop enoki-probe-lifecycle-upgrade.socket".to_owned())
    );
    assert!(
        systemd
            .calls
            .contains(&"disable enoki-probe-lifecycle-upgrade.socket".to_owned())
    );
}

fn assert_single_authority_field_mismatch_is_rejected(
    conflicting_operation: &str,
    conflicting_token: &str,
    conflicting_install_state: &str,
    conflicting_target_manifest: &str,
    conflicting_version: &str,
) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    let request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_mechanics",
        "mechanics-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("mechanics request");
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: fixture.identity_path.clone(),
    };
    let mut transport = RecordingValidationTransport {
        status_failure: true,
        ..RecordingValidationTransport::default()
    };
    let mut systemd = RecordingSystemdRunner::default();

    let result = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut transport,
        &mut systemd,
    ));

    assert_eq!(result, LifecycleResponse::failed("probe_uninstall_failed"));
    assert!(transport.url.contains("operation_mechanics"));
    assert!(transport.status_url.contains("operation_mechanics"));
    let capsule_path = uninstall_capsule_path(&fixture.metadata_path).expect("capsule path");
    let prepared_capsule = fs::read(&capsule_path).expect("prepared capsule bytes");
    let recovery_assets = [
        fixture.metadata_path.clone(),
        fixture.identity_path.clone(),
        fixture.companion_path.clone(),
    ]
    .map(|path| {
        let bytes = fs::read(&path).expect("recovery asset bytes");
        (path, bytes)
    });

    let conflicting_request = LifecycleRequest::hub_uninstall(
        "probe_01",
        conflicting_operation,
        conflicting_token,
        conflicting_install_state,
        conflicting_target_manifest,
        conflicting_version,
    );
    let conflicting_request = conflicting_request.expect("conflicting bound request");
    let mut conflicting_transport = RecordingValidationTransport::default();
    let mut conflicting_systemd = RecordingSystemdRunner::default();
    let conflicting = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &conflicting_request,
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut conflicting_transport,
        &mut conflicting_systemd,
    ));
    assert_eq!(
        conflicting,
        LifecycleResponse::failed("probe_uninstall_metadata_invalid")
    );
    assert!(conflicting_transport.url.is_empty());
    assert!(conflicting_transport.status_url.is_empty());
    assert!(conflicting_transport.downloads.is_empty());
    assert!(conflicting_systemd.calls.is_empty());
    assert_eq!(
        fs::read(&capsule_path).expect("capsule survives conflict"),
        prepared_capsule
    );
    for (path, bytes) in &recovery_assets {
        assert_eq!(fs::read(path).expect("recovery asset survives"), *bytes);
    }

    let mut retry_transport = RecordingValidationTransport::default();
    let mut retry_systemd = RecordingSystemdRunner::default();
    let retry = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut retry_transport,
        &mut retry_systemd,
    ));
    assert_eq!(retry, LifecycleResponse::succeeded());
    assert!(retry_transport.url.is_empty());
    assert!(
        retry_transport
            .status_body
            .contains("\"status\":\"succeeded\"")
    );
    for path in [
        &fixture.metadata_path,
        &fixture.identity_path,
        &fixture.metadata.state_dir,
    ] {
        assert!(
            !path.exists(),
            "{} remains after convergence",
            path.display()
        );
    }
    assert!(
        fixture.companion_path.exists(),
        "response-flush self-unlink remains the only final effect"
    );
}

#[test]
fn hub_uninstall_rejects_operation_takeover_without_effects_then_converges() {
    assert_single_authority_field_mismatch_is_rejected(
        "operation_takeover",
        "mechanics-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    );
}

#[test]
fn hub_uninstall_rejects_token_takeover_without_effects_then_converges() {
    assert_single_authority_field_mismatch_is_rejected(
        "operation_mechanics",
        "takeover-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    );
}

#[test]
fn hub_uninstall_rejects_install_state_takeover_without_effects_then_converges() {
    assert_single_authority_field_mismatch_is_rejected(
        "operation_mechanics",
        "mechanics-token",
        &"d".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    );
}

#[test]
fn hub_uninstall_rejects_target_manifest_takeover_without_effects_then_converges() {
    assert_single_authority_field_mismatch_is_rejected(
        "operation_mechanics",
        "mechanics-token",
        &"b".repeat(64),
        &"d".repeat(64),
        "1.2.3",
    );
}

#[test]
fn hub_uninstall_rejects_version_takeover_without_effects_then_converges() {
    assert_single_authority_field_mismatch_is_rejected(
        "operation_mechanics",
        "mechanics-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "9.9.9",
    );
}

#[test]
fn hub_uninstall_restarts_from_verified_without_revalidating_the_token() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    let request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_42",
        "operation-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("bound uninstall request");
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: fixture.identity_path.clone(),
    };
    let mut first_transport = RecordingValidationTransport::default();
    let mut failed_systemd = RecordingSystemdRunner {
        failure_step: Some("stop"),
        ..RecordingSystemdRunner::default()
    };

    let first = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut first_transport,
        &mut failed_systemd,
    ));
    assert_eq!(
        first,
        LifecycleResponse::failed("probe_uninstall_service_stop_failed")
    );
    assert!(!first_transport.url.is_empty());
    assert!(first_transport.status_url.is_empty());

    let mut retry_transport = RecordingValidationTransport::default();
    let mut retry_systemd = RecordingSystemdRunner::default();
    let retry = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &input,
        &fixture.metadata,
        &fixture.metadata_path,
        &mut retry_transport,
        &mut retry_systemd,
    ));
    assert_eq!(retry, LifecycleResponse::succeeded());
    assert!(retry_transport.url.is_empty());
    assert!(
        retry_transport
            .status_body
            .contains("\"status\":\"succeeded\"")
    );
}

#[test]
fn hub_uninstall_report_failure_keeps_exact_reentry_until_acknowledged_cleanup() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    let metadata = fixture.metadata;
    let metadata_path = fixture.metadata_path;
    let identity_path = fixture.identity_path;
    let companion_path = fixture.companion_path;
    let state_dir = metadata.state_dir.clone();
    let companion_service = metadata
        .observation_unit_paths
        .iter()
        .find(|path| path.ends_with("enoki-probe-lifecycle-companion@.service"))
        .expect("companion service")
        .clone();
    let companion_socket = metadata
        .observation_unit_paths
        .iter()
        .find(|path| path.ends_with("enoki-probe-lifecycle-companion.socket"))
        .expect("companion socket")
        .clone();
    let request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_42",
        "operation-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("bound uninstall request");
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: identity_path.clone(),
    };
    let mut systemd = RecordingSystemdRunner::default();
    let mut failed_transport = RecordingValidationTransport {
        status_failure: true,
        ..RecordingValidationTransport::default()
    };

    let first = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &input,
        &metadata,
        &metadata_path,
        &mut failed_transport,
        &mut systemd,
    ));
    assert_eq!(first, LifecycleResponse::failed("probe_uninstall_failed"));
    for path in [
        identity_path.as_path(),
        metadata_path.as_path(),
        companion_path.as_path(),
        companion_service.as_path(),
        companion_socket.as_path(),
    ] {
        assert!(path.exists(), "reentry asset lost: {}", path.display());
    }

    let mut retry_transport = RecordingValidationTransport::default();
    systemd.failure_step = Some("remove-account");
    let completed = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &input,
        &metadata,
        &metadata_path,
        &mut retry_transport,
        &mut systemd,
    ));
    assert_eq!(completed, LifecycleResponse::recovery_pending());
    assert!(
        retry_transport.url.is_empty(),
        "trusted capsule skips revalidation"
    );
    assert!(
        retry_transport
            .status_body
            .contains("\"status\":\"succeeded\"")
    );
    assert!(metadata_path.exists());
    assert!(identity_path.exists());
    assert!(companion_path.exists());

    assert!(
        companion_path.exists(),
        "fixed resume entry remains recoverable"
    );

    drop(request);
    drop(input);
    drop(metadata);
    drop(retry_transport);
    drop(systemd);
    let child = Command::new(std::env::current_exe().expect("current test process"))
        .args([
            "--exact",
            "upgrader::uninstall::tests::lifecycle_resume_child_process",
            "--nocapture",
        ])
        .env("ENOKI_TEST_RESUME_METADATA", &metadata_path)
        .env("ENOKI_TEST_RESUME_STATE", &state_dir)
        .env("ENOKI_TEST_RESUME_BINARY", &companion_path)
        .status()
        .expect("start a fresh Companion recovery process");
    assert!(child.success(), "fresh recovery process failed");
    assert!(!metadata_path.exists());
    assert!(!identity_path.exists());
    assert!(!companion_path.exists());
}

#[test]
fn lifecycle_resume_child_process() {
    let Ok(metadata_path) = std::env::var("ENOKI_TEST_RESUME_METADATA") else {
        return;
    };
    let binary_path =
        std::env::var("ENOKI_TEST_RESUME_BINARY").expect("fixed test recovery binary");
    let state_path = std::env::var("ENOKI_TEST_RESUME_STATE").expect("fixed test install state");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();
    let completed = resume_lifecycle_companion_at(
        Path::new(&metadata_path),
        Path::new(&state_path),
        Path::new(&binary_path),
        &mut transport,
        &mut systemd,
    );
    assert_eq!(completed, LifecycleResponse::succeeded());
    assert!(transport.url.is_empty());
    assert!(transport.status_url.is_empty());
    remove_path_if_exists(Path::new(&binary_path))
        .expect("fresh Companion process performs its final self-unlink");
}

#[test]
fn empty_resume_rejects_a_healthy_install_without_self_finalizing() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let metadata = temporary.path().join("etc/enoki/probe-install.toml");
    let state = temporary.path().join("var/lib/enoki-probe");
    let binary = temporary
        .path()
        .join("usr/local/bin/enoki-probe-lifecycle-companion");
    for parent in [
        metadata.parent().unwrap(),
        state.as_path(),
        binary.parent().unwrap(),
    ] {
        fs::create_dir_all(parent).expect("fixture directory");
    }
    fs::write(&metadata, "healthy install metadata").expect("metadata");
    fs::write(&binary, "companion").expect("companion binary");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();

    let response =
        resume_lifecycle_companion_at(&metadata, &state, &binary, &mut transport, &mut systemd);
    assert_eq!(
        response,
        LifecycleResponse::failed("probe_uninstall_metadata_invalid")
    );
    assert!(binary.exists());
    assert!(transport.url.is_empty());
    assert!(systemd.calls.is_empty());
}

#[test]
fn hub_uninstall_adapter_rejects_bootstrap_hub_url_mismatch_before_token_validation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let mut install_metadata = recovery_metadata(temp.path());
    install_metadata.install_path = install_path;
    install_metadata.operation_status_path = status_path;
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://attacker.example\"".to_string(),
            "probe_id = \"probe_01\"".to_string(),
            "probe_private_key_pem = \"test-private-key\"".to_string(),
            String::new(),
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();
    let request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "42",
        "probe-operation-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("bound Hub uninstall request");
    let metadata_path = temp.path().join("etc/enoki/probe-install.toml");

    let response = lifecycle_response_from_resume_decision(adapt_uninstall_wire_request(
        &request,
        &ProbeUninstallerRunInput {
            bootstrap_config_path,
        },
        &install_metadata,
        &metadata_path,
        &mut transport,
        &mut systemd,
    ));

    assert_eq!(
        response,
        LifecycleResponse::failed("probe_uninstall_failed")
    );
    assert_eq!(transport.url, "");
    assert_eq!(transport.status_url, "");
    assert!(transport.downloads.is_empty());
}

fn assert_state_shell_retained(state_dir: &Path) {
    let shell = fs::symlink_metadata(state_dir).expect("harmless state shell");
    assert!(shell.is_dir() && !shell.file_type().is_symlink());
    assert_eq!(
        fs::read_dir(state_dir)
            .expect("enumerate state shell")
            .count(),
        0,
        "retained root must hold no child"
    );
}

#[test]
fn production_uninstall_entries_complete_around_a_harmless_empty_state_shell() {
    let identity = TrustedProbeInstallPreflight {
        hub_url: "https://hub.example".to_owned(),
        probe_id: "probe_01".to_owned(),
    };
    inject_state_root_removal_fault(Some(StateRootRemovalFault::ContentsCleared));

    let local_temporary = tempfile::tempdir().expect("local temporary directory");
    let local_fixture = uninstall_coordinator_fixture(local_temporary.path());
    let local_capsule =
        uninstall_capsule_path(&local_fixture.metadata_path).expect("local capsule");
    let local_request =
        LifecycleRequest::local_uninstall("probe_01", &"b".repeat(64), &"c".repeat(64), "1.2.3")
            .expect("bound local uninstall request");
    let mut local_transport = RecordingValidationTransport::default();
    let mut local_systemd = RecordingSystemdRunner::default();
    let local = run_uninstall_lifecycle_adapter(
        &local_request,
        &local_fixture.metadata,
        &identity,
        &local_fixture.metadata_path,
        &mut local_transport,
        &mut local_systemd,
    );

    assert_eq!(local, LifecycleResponse::succeeded());
    assert!(local_transport.url.is_empty());
    assert!(local_transport.status_url.is_empty());
    assert_state_shell_retained(&local_fixture.metadata.state_dir);
    for path in [
        &local_fixture.metadata_path,
        &local_fixture.identity_path,
        &local_capsule,
    ] {
        assert!(
            !path.exists(),
            "necessary resource residue: {}",
            path.display()
        );
    }

    let hub_temporary = tempfile::tempdir().expect("hub temporary directory");
    let hub_fixture = uninstall_coordinator_fixture(hub_temporary.path());
    let hub_capsule = uninstall_capsule_path(&hub_fixture.metadata_path).expect("hub capsule");
    let hub_request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_42",
        "operation-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("bound Hub uninstall request");
    let mut hub_transport = RecordingValidationTransport::default();
    let mut hub_systemd = RecordingSystemdRunner::default();
    let hub = run_uninstall_lifecycle_adapter(
        &hub_request,
        &hub_fixture.metadata,
        &identity,
        &hub_fixture.metadata_path,
        &mut hub_transport,
        &mut hub_systemd,
    );
    inject_state_root_removal_fault(None);

    assert_eq!(hub, LifecycleResponse::succeeded());
    assert!(
        hub_transport.url.contains("operation_42"),
        "Hub authority is still validated"
    );
    assert!(
        hub_transport
            .status_body
            .contains("\"status\":\"succeeded\"")
    );
    assert_state_shell_retained(&hub_fixture.metadata.state_dir);
    for path in [
        &hub_fixture.metadata_path,
        &hub_fixture.identity_path,
        &hub_capsule,
    ] {
        assert!(
            !path.exists(),
            "necessary resource residue: {}",
            path.display()
        );
    }
    assert_eq!(
        hub_systemd.calls, local_systemd.calls,
        "两个授权入口共享同一必要资源退休边界"
    );
}

#[test]
fn hub_uninstall_success_does_not_mask_a_state_root_that_still_holds_install_data() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    let capsule_path = uninstall_capsule_path(&fixture.metadata_path).expect("capsule path");
    let identity = TrustedProbeInstallPreflight {
        hub_url: "https://hub.example".to_owned(),
        probe_id: "probe_01".to_owned(),
    };
    let request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_42",
        "operation-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("bound Hub uninstall request");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();
    inject_state_root_removal_fault(Some(StateRootRemovalFault::ContentsRetained));
    let response = run_uninstall_lifecycle_adapter(
        &request,
        &fixture.metadata,
        &identity,
        &fixture.metadata_path,
        &mut transport,
        &mut systemd,
    );
    inject_state_root_removal_fault(None);

    assert_eq!(response, LifecycleResponse::recovery_pending());
    assert!(
        transport.status_body.contains("\"status\":\"succeeded\""),
        "Hub 已被上报成功，但本机退休未成立"
    );
    assert!(capsule_path.exists(), "未完成必须保留精确恢复事实");
    assert!(
        fs::read_dir(&fixture.metadata.state_dir)
            .expect("enumerate state root")
            .count()
            > 0,
        "无法证明无害的根内容不被吞掉"
    );
}

#[test]
fn a_proven_harmless_state_shell_does_not_keep_recovery_pending_forever() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    let capsule_path = uninstall_capsule_path(&fixture.metadata_path).expect("capsule path");
    let identity = TrustedProbeInstallPreflight {
        hub_url: "https://hub.example".to_owned(),
        probe_id: "probe_01".to_owned(),
    };
    let request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_42",
        "operation-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("bound Hub uninstall request");
    let mut systemd = RecordingSystemdRunner::default();
    let mut interrupted_transport = RecordingValidationTransport {
        status_failure: true,
        ..RecordingValidationTransport::default()
    };
    inject_state_root_removal_fault(Some(StateRootRemovalFault::ContentsCleared));
    let interrupted = run_uninstall_lifecycle_adapter(
        &request,
        &fixture.metadata,
        &identity,
        &fixture.metadata_path,
        &mut interrupted_transport,
        &mut systemd,
    );

    assert_eq!(
        interrupted,
        LifecycleResponse::failed("probe_uninstall_failed")
    );
    assert!(capsule_path.exists(), "中断保留既有恢复事实");

    let mut retry_transport = RecordingValidationTransport::default();
    let retry = run_uninstall_lifecycle_adapter(
        &request,
        &fixture.metadata,
        &identity,
        &fixture.metadata_path,
        &mut retry_transport,
        &mut systemd,
    );
    inject_state_root_removal_fault(None);

    assert_eq!(retry, LifecycleResponse::succeeded());
    assert!(!capsule_path.exists());
    assert_state_shell_retained(&fixture.metadata.state_dir);
}

#[test]
fn committed_resume_accepts_a_retained_shell_and_refuses_unproven_state_roots() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let metadata_path = root.join("etc/enoki/probe-install.toml");
    let state_dir = root.join("var/lib/enoki-probe");
    let binary = root.join("usr/local/bin/enoki-probe-lifecycle-companion");
    fs::create_dir_all(&state_dir).expect("state shell");
    fs::create_dir_all(binary.parent().expect("binary parent")).expect("binary parent directory");
    fs::write(&binary, "companion").expect("companion binary");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("companion mode");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();

    assert_eq!(
        resume_lifecycle_companion_at(
            &metadata_path,
            &state_dir,
            &binary,
            &mut transport,
            &mut systemd
        ),
        LifecycleResponse::succeeded()
    );
    assert!(transport.url.is_empty());
    assert!(systemd.calls.is_empty());

    let data_child = state_dir.join("audit");
    fs::create_dir_all(&data_child).expect("retained install data");
    assert_eq!(
        resume_lifecycle_companion_at(
            &metadata_path,
            &state_dir,
            &binary,
            &mut transport,
            &mut systemd
        ),
        LifecycleResponse::failed("probe_uninstall_metadata_invalid")
    );
    assert!(data_child.exists(), "只读入口不删除未确认对象");
    fs::remove_dir(&data_child).expect("remove data child");

    fs::remove_dir(&state_dir).expect("remove empty shell");
    let external_root = root.join("var/lib/private/enoki-probe");
    fs::create_dir_all(&external_root).expect("external root");
    fs::write(external_root.join("payload"), "install data").expect("external payload");
    symlink(Path::new("../../private/enoki-probe"), &state_dir).expect("state root symlink");
    assert_eq!(
        resume_lifecycle_companion_at(
            &metadata_path,
            &state_dir,
            &binary,
            &mut transport,
            &mut systemd
        ),
        LifecycleResponse::failed("probe_uninstall_metadata_invalid")
    );
    assert!(state_dir.is_symlink());
    assert!(
        external_root.join("payload").exists(),
        "归属不可确认的 symlink 不被跟随删除"
    );
    assert!(systemd.calls.is_empty());
}

/// 把 fixture 的 ordinary state 根换成生产 DynamicUser 形态：public 为 exact 单链，
/// 实际本机 state 位于固定 private 投影。
fn project_state_root_to_canonical(root: &Path, state_dir: &Path) -> PathBuf {
    let private_root = root.join("var/lib/private/enoki-probe");
    fs::create_dir_all(private_root.parent().expect("private parent"))
        .expect("private parent directory");
    fs::rename(state_dir, &private_root).expect("project state root");
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o750)).expect("private mode");
    symlink(Path::new("private/enoki-probe"), state_dir).expect("canonical public link");
    private_root
}

fn canonical_local_uninstall_fixture(root: &Path) -> (UninstallCoordinatorFixture, PathBuf) {
    let fixture = uninstall_coordinator_fixture(root);
    let private_root = project_state_root_to_canonical(root, &fixture.metadata.state_dir);
    fs::create_dir_all(private_root.join("upgrade-stages/stage")).expect("upgrade stage");
    fs::write(
        private_root.join("upgrade-stages/stage/payload"),
        "install stage",
    )
    .expect("stage payload");
    (fixture, private_root)
}

#[test]
fn authorized_uninstall_clears_a_canonical_state_root_without_following_internal_links() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let (fixture, private_root) = canonical_local_uninstall_fixture(root);
    let outside = root.join("var/lib/outside/payload");
    fs::create_dir_all(outside.parent().expect("outside parent")).expect("outside parent");
    fs::write(&outside, "external").expect("external payload");
    symlink(
        Path::new("../../outside/payload"),
        private_root.join("evidence-link"),
    )
    .expect("internal link");
    let identity = TrustedProbeInstallPreflight {
        hub_url: "https://hub.example".to_owned(),
        probe_id: "probe_01".to_owned(),
    };
    let request =
        LifecycleRequest::local_uninstall("probe_01", &"b".repeat(64), &"c".repeat(64), "1.2.3")
            .expect("bound local uninstall request");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();

    assert_eq!(
        run_uninstall_lifecycle_adapter(
            &request,
            &fixture.metadata,
            &identity,
            &fixture.metadata_path,
            &mut transport,
            &mut systemd
        ),
        LifecycleResponse::succeeded()
    );
    assert!(
        fs::symlink_metadata(&fixture.metadata.state_dir).is_err(),
        "canonical public 链随空壳一起退休"
    );
    assert!(!private_root.exists(), "canonical 实际数据必须清空");
    assert!(
        outside.exists(),
        "根内 symlink 只 unlink 自身，不递归访问外部 target"
    );
    assert!(!fixture.metadata_path.exists());
}

#[test]
fn an_unremovable_canonical_shell_still_completes_once_its_data_is_cleared() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let (fixture, private_root) = canonical_local_uninstall_fixture(root);
    let identity = TrustedProbeInstallPreflight {
        hub_url: "https://hub.example".to_owned(),
        probe_id: "probe_01".to_owned(),
    };
    let request =
        LifecycleRequest::local_uninstall("probe_01", &"b".repeat(64), &"c".repeat(64), "1.2.3")
            .expect("bound local uninstall request");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();
    inject_state_root_removal_fault(Some(StateRootRemovalFault::ContentsCleared));

    let response = run_uninstall_lifecycle_adapter(
        &request,
        &fixture.metadata,
        &identity,
        &fixture.metadata_path,
        &mut transport,
        &mut systemd,
    );
    inject_state_root_removal_fault(None);

    assert_eq!(response, LifecycleResponse::succeeded());
    assert!(
        fixture.metadata.state_dir.is_symlink(),
        "无法删除的 exact public 链可保留"
    );
    assert!(private_root.is_dir());
    assert_eq!(
        fs::read_dir(&private_root)
            .expect("enumerate canonical shell")
            .count(),
        0,
        "保留的 canonical 根必须已证明没有任何 child"
    );
}

/// 替换迁移的 committed 清理走同一退休判据：实际数据确已清空后，无法删除的无害壳可保留；
/// 可信 metadata 不由清理路径退休，仍留给 exact commit custody。
#[test]
fn committed_replacement_cleanup_completes_around_a_retained_harmless_canonical_shell() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let (fixture, private_root) = canonical_local_uninstall_fixture(root);
    let input = ProbeUninstallerRunInput {
        bootstrap_config_path: fixture.metadata.identity_path.clone(),
    };
    let plan =
        plan_committed_replacement_cleanup(&input, &fixture.metadata, &fixture.metadata_path)
            .expect("committed Replacement cleanup plan");
    let mut systemd = RecordingSystemdRunner::default();
    inject_state_root_removal_fault(Some(StateRootRemovalFault::ContentsCleared));

    let outcome = execute_committed_replacement_cleanup(&plan, &mut systemd);
    inject_state_root_removal_fault(None);

    outcome.expect("已证明无害的保留壳不阻塞 committed Replacement 清理");
    assert!(
        fixture.metadata.state_dir.is_symlink(),
        "尽力删除失败后 exact public 链可保留"
    );
    assert_eq!(
        fs::read_dir(&private_root)
            .expect("enumerate canonical shell")
            .count(),
        0,
        "替换清理保留的壳必须已证明没有任何 child"
    );
    assert!(
        fixture.metadata_path.exists(),
        "替换清理不退休可信 metadata"
    );
    assert!(
        fixture
            .metadata
            .bootstrap_state_dir
            .as_ref()
            .unwrap()
            .exists(),
        "committed Replacement 保留候选 Bootstrap custody"
    );
}

#[test]
fn an_absent_public_root_does_not_mask_private_data_from_the_no_capsule_proof() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let metadata_path = root.join("etc/enoki/probe-install.toml");
    let state_dir = root.join("var/lib/enoki-probe");
    let binary = root.join("usr/local/bin/enoki-probe-lifecycle-companion");
    let private_root = root.join("var/lib/private/enoki-probe");
    fs::create_dir_all(&private_root).expect("private root");
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o750)).expect("private mode");
    fs::write(private_root.join("payload"), "install data").expect("private payload");
    fs::create_dir_all(binary.parent().expect("binary parent")).expect("binary parent directory");
    fs::write(&binary, "companion").expect("companion binary");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("companion mode");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();

    assert_eq!(
        resume_lifecycle_companion_at(
            &metadata_path,
            &state_dir,
            &binary,
            &mut transport,
            &mut systemd
        ),
        LifecycleResponse::failed("probe_uninstall_metadata_invalid")
    );
    assert!(
        private_root.join("payload").exists(),
        "public absent 不掩盖 private 数据，只读入口也不删除它"
    );
    assert!(systemd.calls.is_empty());
}

/// 归属未确认的 state 根不取得删除权：未知根本体与实际数据逐字节保留。两种入口都只如实
/// 拒绝，不接管、不清理未知对象。
#[test]
fn an_untrusted_state_root_form_does_not_take_on_removal_authority() {
    let identity = TrustedProbeInstallPreflight {
        hub_url: "https://hub.example".to_owned(),
        probe_id: "probe_01".to_owned(),
    };
    let request =
        LifecycleRequest::local_uninstall("probe_01", &"b".repeat(64), &"c".repeat(64), "1.2.3")
            .expect("bound local uninstall request");

    // 一、可信 metadata 与 identity 均可正常读取，只有根归属不属于本安装：拒绝发生在共同
    // state 根退休接缝，未知对象不被清理。
    let proven_metadata = tempfile::tempdir().expect("temporary directory");
    let root = proven_metadata.path();
    let fixture = uninstall_coordinator_fixture(root);
    std::os::unix::fs::chown(&fixture.metadata.state_dir, Some(1000), Some(1000))
        .expect("relinquish root");
    fs::write(
        fixture.metadata.state_dir.join("unknown-payload"),
        "unknown data",
    )
    .expect("unknown payload");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();
    assert_eq!(
        run_uninstall_lifecycle_adapter(
            &request,
            &fixture.metadata,
            &identity,
            &fixture.metadata_path,
            &mut transport,
            &mut systemd
        ),
        LifecycleResponse::failed("probe_uninstall_state_residue")
    );
    assert_eq!(
        fs::read(fixture.metadata.state_dir.join("unknown-payload")).expect("unknown payload"),
        b"unknown data",
        "归属未确认时不删除未知对象"
    );
    assert!(fixture.metadata.state_dir.is_dir(), "未知根本体不被退休");

    // 二、public 根是指向未知目标的近似链：可信 identity 读端先一步拒绝，因此没有任何退休
    // 动作发生，链与其外部数据完整保留。
    let unresolvable = tempfile::tempdir().expect("temporary directory");
    let root = unresolvable.path();
    let fixture = uninstall_coordinator_fixture(root);
    let private_root = root.join("var/lib/private/enoki-probe");
    fs::create_dir_all(&private_root).expect("private root");
    fs::write(private_root.join("payload"), "install data").expect("private payload");
    fs::remove_dir_all(&fixture.metadata.state_dir).expect("remove ordinary root");
    symlink(
        Path::new("../../private/enoki-probe"),
        &fixture.metadata.state_dir,
    )
    .expect("approximate target link");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();
    assert_eq!(
        run_uninstall_lifecycle_adapter(
            &request,
            &fixture.metadata,
            &identity,
            &fixture.metadata_path,
            &mut transport,
            &mut systemd
        ),
        LifecycleResponse::failed("probe_uninstall_failed")
    );
    assert!(
        fixture.metadata.state_dir.is_symlink(),
        "近似 target 的链不取得删除权"
    );
    assert!(
        private_root.join("payload").exists(),
        "形态未确认时不删除未知对象"
    );
    assert!(
        fixture.metadata_path.exists(),
        "更早的可信读端拒绝时尚未退休任何必要资源"
    );
}

/// 命令替身只替换环境供应：产品 Adapter 仍按 PATH 解析并执行同名程序，清理算法不被复制。
/// 每条调用按出现顺序留痕；删除命令额外记录当时的 state 根本体 owner，用来证明归属交接
/// 耐久先于账户删除，以及拒绝路径下账户删除从未开始。
const LEGACY_STATE_ROOT_COMMAND_SHIM: &str = r#"#!/bin/sh
name=${0##*/}
printf '%s <%s>\n' "$name" "$*" >> "$ENOKI_TEST_LEGACY_STATE_COMMANDS"
case "$name" in
  systemctl)
    if [ "$1" = show ]; then printf 'not-found\n'; fi
    exit 0
    ;;
  getent)
    record=$(/usr/bin/sed -n "s#^$1|$2|##p" "$ENOKI_TEST_LEGACY_STATE_ACCOUNTS")
    if [ -z "$record" ]; then exit 2; fi
    printf '%s\n' "$record"
    exit 0
    ;;
  userdel|groupdel)
    if [ -e "$ENOKI_TEST_LEGACY_STATE_DIR" ]; then
      printf 'state-owner %s\n' "$(/usr/bin/stat -c '%u:%g' "$ENOKI_TEST_LEGACY_STATE_DIR")" >> "$ENOKI_TEST_LEGACY_STATE_COMMANDS"
    else
      printf 'state-owner absent\n' >> "$ENOKI_TEST_LEGACY_STATE_COMMANDS"
    fi
    if [ "$name" = userdel ]; then database=passwd; else database=group; fi
    /usr/bin/sed -i "/^$database|$1|/d" "$ENOKI_TEST_LEGACY_STATE_ACCOUNTS"
    exit 0
    ;;
  *)
    printf '替身不接受的命令\n' >&2
    exit 99
    ;;
esac
"#;

/// 真实主机上可查询的旧服务账户记录。正向反馈只接受当场可读、且数值与 state 根本体
/// owner 对应的实际账户，不接受构造常量。
struct LegacyHostAccount {
    user: String,
    group: String,
    uid: u32,
    gid: u32,
    passwd_record: String,
    group_record: String,
}

fn host_legacy_service_account() -> Option<LegacyHostAccount> {
    let record = |database: &str, name: &str| -> Option<(String, u32)> {
        let output = Command::new("getent")
            .args([database, name])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let record = String::from_utf8(output.stdout).ok()?.trim().to_owned();
        if record.split(':').next() != Some(name) {
            return None;
        }
        let identifier = record.split(':').nth(2)?.parse().ok()?;
        Some((record, identifier))
    };
    let (passwd_record, uid) = record("passwd", "sys")?;
    let (group_record, gid) = record("group", "tty")?;
    Some(LegacyHostAccount {
        user: "sys".to_owned(),
        group: "tty".to_owned(),
        uid,
        gid,
        passwd_record,
        group_record,
    })
}

/// 旧产品（schema 1）的正式替换清理输入：可信 root-owned metadata 与其清单内的真实资产、
/// state 根本体的实际数值 owner 和实际数据、durable 的 cleanup_complete=false 提交事实。
struct LegacyStateRootScenario<'a> {
    root: &'a Path,
    service_user: &'a str,
    service_group: &'a str,
    accounts: &'a str,
    owner: (u32, u32),
}

struct LegacyStateRootFixture {
    metadata_path: PathBuf,
    identity_path: PathBuf,
    state_dir: PathBuf,
    candidate_bootstrap_state: PathBuf,
    commit_path: PathBuf,
    accounts_path: PathBuf,
    commands_log: PathBuf,
    shim_dir: PathBuf,
}

fn legacy_schema_one_metadata_contents(service_user: &str, service_group: &str) -> String {
    [
        "schema_version = 1".to_owned(),
        "hub_url = \"https://hub.example\"".to_owned(),
        "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"".to_owned(),
        "install_path = \"/usr/local/bin/enoki-probe\"".to_owned(),
        "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"".to_owned(),
        "operation_sudoers_path = \"/etc/sudoers.d/enoki-probe-operations\"".to_owned(),
        "collector_helper_sudoers_path = \"/etc/sudoers.d/enoki-probe-collector-helpers\""
            .to_owned(),
        format!("probe_asset_public_key_sha256 = \"{}\"", "a".repeat(64)),
        "service_name = \"enoki-probe\"".to_owned(),
        format!("service_user = \"{service_user}\""),
        format!("service_group = \"{service_group}\""),
        "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"".to_owned(),
        "state_dir = \"/var/lib/enoki-probe\"".to_owned(),
        String::new(),
    ]
    .join("\n")
}

/// durable intent 与 canonical request 在父子进程各自按同一固定输入重建，恢复证明因此携带
/// 同一 intent，而不是新造一次授权。
fn legacy_replacement_intent() -> ReplacementIntent {
    ReplacementIntent {
        enrollment_id: "enr_0123456789abcdef".to_owned(),
        enrollment_token_sha256: format!("{:x}", Sha256::digest(b"enk_enroll_test")),
        host_id: "7".to_owned(),
        hub_origin: "https://hub.example".to_owned(),
        old_probe_id: "probe_old_01".to_owned(),
        source_probe_version: "1.2.3".to_owned(),
        source_probe_sha256: format!("{:x}", Sha256::digest(b"owned")),
        target_bundle_target: "x86_64-unknown-linux-gnu".to_owned(),
        target_probe_version: "1.2.3".to_owned(),
        target_asset_set_digest: format!("sha256:{}", "c".repeat(64)),
        target_manifest_sha256: "d".repeat(64),
    }
}

fn legacy_replacement_request() -> LifecycleRequest {
    let intent = legacy_replacement_intent();
    let input = format!(
        "{{\"hubOrigin\":\"https://hub.example\",\"enrollmentToken\":\"enk_enroll_test\",\"replacementMigration\":{{\"enrollmentId\":\"{}\",\"expectedProbeId\":\"{}\",\"sourceProbeSha256\":[\"{}\"],\"sourceProbeVersion\":\"1.2.3\",\"targetAssetSetDigest\":\"{}\",\"targetHostId\":\"{}\",\"targetProbeVersion\":\"1.2.3\"}},\"schemaVersion\":1}}",
        intent.enrollment_id,
        intent.old_probe_id,
        intent.source_probe_sha256,
        intent.target_asset_set_digest,
        intent.host_id,
    );
    let enrollment = Enrollment::from_install_input("https://hub.example", input.as_bytes())
        .expect("exact replacement enrollment");
    LifecycleRequest::replacement_migration(
        &enrollment,
        &intent.target_asset_set_digest,
        &intent.target_bundle_target,
        &intent.target_manifest_sha256,
        &intent.target_probe_version,
    )
    .expect("exact replacement request")
}

fn build_legacy_state_root_fixture(
    scenario: &LegacyStateRootScenario<'_>,
) -> LegacyStateRootFixture {
    let rooted = |absolute: &str| scenario.root.join(absolute.trim_start_matches('/'));
    for path in [
        "/usr/local/bin/enoki-probe",
        "/etc/systemd/system/enoki-probe.service",
        "/etc/sudoers.d/enoki-probe-operations",
        "/etc/sudoers.d/enoki-probe-collector-helpers",
    ] {
        let path = rooted(path);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture parent");
        fs::write(&path, "owned").expect("fixture asset");
    }
    fs::set_permissions(
        rooted("/usr/local/bin/enoki-probe"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("installed Probe mode");

    let state_dir = rooted("/var/lib/enoki-probe");
    let identity_path = state_dir.join("identity/probe-bootstrap.toml");
    fs::create_dir_all(identity_path.parent().expect("identity parent")).expect("identity parent");
    fs::write(
        &identity_path,
        "hub_url = \"https://hub.example\"\nprobe_id = \"probe_old_01\"\nprobe_private_key_pem = \"test-private-key\"\n",
    )
    .expect("source Probe identity");
    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600)).expect("identity mode");
    fs::write(state_dir.join("installed-state"), "本安装实际数据夹具").expect("state data");
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o750)).expect("state mode");

    let candidate_bootstrap_state = rooted("/var/lib/enoki-probe-bootstrap");
    fs::create_dir_all(&candidate_bootstrap_state).expect("candidate Bootstrap state");
    fs::set_permissions(
        &candidate_bootstrap_state,
        fs::Permissions::from_mode(0o700),
    )
    .expect("candidate Bootstrap state mode");

    let metadata_path = rooted("/etc/enoki/probe-install.toml");
    fs::create_dir_all(metadata_path.parent().expect("metadata parent")).expect("metadata parent");
    fs::write(
        &metadata_path,
        legacy_schema_one_metadata_contents(scenario.service_user, scenario.service_group),
    )
    .expect("metadata");
    fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o600)).expect("metadata mode");

    let intent = legacy_replacement_intent();
    let commit_path = rooted("/var/lib/enoki-probe-bootstrap/replacement-migration.json");
    FileReplacementCommitStore::at(&commit_path, 0)
        .persist(&ReplacementCommitFact {
            schema_version: 1,
            canonical_intent_sha256: intent.canonical_sha256().expect("canonical intent"),
            intent,
            cleanup_complete: false,
            candidate_layout_complete: false,
        })
        .expect("durable pre-cleanup commit");

    let shim_dir = scenario.root.join("command-shim");
    fs::create_dir_all(&shim_dir).expect("shim directory");
    let shim = shim_dir.join("command-shim.sh");
    fs::write(&shim, LEGACY_STATE_ROOT_COMMAND_SHIM).expect("command shim");
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).expect("command shim mode");
    for program in ["systemctl", "getent", "userdel", "groupdel"] {
        symlink(&shim, shim_dir.join(program)).expect("command shim link");
    }
    let accounts_path = scenario.root.join("accounts");
    fs::write(&accounts_path, scenario.accounts).expect("account substitute");
    let commands_log = scenario.root.join("commands.log");
    fs::write(&commands_log, "").expect("command log");
    std::os::unix::fs::chown(&state_dir, Some(scenario.owner.0), Some(scenario.owner.1))
        .expect("state root owner");

    LegacyStateRootFixture {
        metadata_path,
        identity_path,
        state_dir,
        candidate_bootstrap_state,
        commit_path,
        accounts_path,
        commands_log,
        shim_dir,
    }
}

fn legacy_state_root_owner(path: &Path) -> Option<(u32, u32)> {
    let metadata = fs::symlink_metadata(path).ok()?;
    Some((metadata.uid(), metadata.gid()))
}

fn legacy_command_trace(fixture: &LegacyStateRootFixture) -> Vec<String> {
    fs::read_to_string(&fixture.commands_log)
        .expect("command trace")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// 全新进程真正结束首个执行后，父进程重新读取 durable commit 事实本身。
fn legacy_persisted_cleanup_completed(fixture: &LegacyStateRootFixture) -> bool {
    FileReplacementCommitStore::at(&fixture.commit_path, 0)
        .load()
        .expect("durable commit fact is readable")
        .expect("commit fact survives")
        .cleanup_complete
}

fn run_legacy_state_root_child(
    fixture: &LegacyStateRootFixture,
    root: &Path,
    expected: &str,
    retirement_fault: bool,
    sync_failure: bool,
) {
    let mut command = Command::new(std::env::current_exe().expect("current test process"));
    command
        .args([
            "--exact",
            "upgrader::uninstall::tests::legacy_state_root_formal_recovery_child_process",
            "--nocapture",
        ])
        .env(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                fixture.shim_dir.display()
            ),
        )
        .env("ENOKI_TEST_REPLACEMENT_PRODUCTION_ROOT", root)
        .env("ENOKI_TEST_LEGACY_STATE_EXPECTED", expected)
        .env("ENOKI_TEST_LEGACY_STATE_ACCOUNTS", &fixture.accounts_path)
        .env("ENOKI_TEST_LEGACY_STATE_COMMANDS", &fixture.commands_log)
        .env("ENOKI_TEST_LEGACY_STATE_DIR", &fixture.state_dir);
    if retirement_fault {
        command.env("ENOKI_TEST_LEGACY_STATE_RETIREMENT_FAULT", "1");
    } else {
        command.env_remove("ENOKI_TEST_LEGACY_STATE_RETIREMENT_FAULT");
    }
    if sync_failure {
        command.env(
            "ENOKI_TEST_STATE_ROOT_SYNC_FAILURE_PATH",
            &fixture.state_dir,
        );
    } else {
        command.env_remove("ENOKI_TEST_STATE_ROOT_SYNC_FAILURE_PATH");
    }
    let status = command
        .status()
        .expect("start a fresh production recovery process");
    assert!(
        status.success(),
        "fresh recovery process for expected {expected} did not converge"
    );
}

/// 正式 `run_lifecycle_companion` 的 exact-request 恢复入口：真实 committed cleanup、真实
/// 目录 owner 与真实 metadata/commit 编解码，账户与 systemd 只由 PATH 替身供应环境。
#[test]
fn legacy_service_owned_state_root_is_handed_over_before_the_formal_account_deletion() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Some(account) = host_legacy_service_account() else {
        return;
    };
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let fixture = build_legacy_state_root_fixture(&LegacyStateRootScenario {
        root,
        service_user: &account.user,
        service_group: &account.group,
        accounts: &format!(
            "passwd|{}|{}\ngroup|{}|{}\n",
            account.user, account.passwd_record, account.group, account.group_record
        ),
        owner: (account.uid, account.gid),
    });
    assert_eq!(
        legacy_state_root_owner(&fixture.state_dir),
        Some((account.uid, account.gid)),
        "旧产品把 state 根本体留给服务账户"
    );

    run_legacy_state_root_child(&fixture, root, "succeeded", false, false);

    let trace = legacy_command_trace(&fixture);
    let userdel = trace
        .iter()
        .position(|line| line.starts_with("userdel <"))
        .expect("旧服务账户由命令 Adapter 删除");
    assert_eq!(
        trace.get(userdel + 1).map(String::as_str),
        Some("state-owner 0:0"),
        "归属交接必须耐久先于账户删除"
    );
    let groupdel = trace
        .iter()
        .position(|line| line.starts_with("groupdel <"))
        .expect("旧服务组由命令 Adapter 删除");
    assert_eq!(
        trace.get(groupdel + 1).map(String::as_str),
        Some("state-owner 0:0"),
        "服务组删除时根仍归 root"
    );
    let accounts = fs::read_to_string(&fixture.accounts_path).expect("account substitute");
    assert!(
        !accounts.contains("passwd|") && !accounts.contains("group|"),
        "账户删除替身确实退休了本次记录：{accounts}"
    );
    assert!(
        !fixture.state_dir.exists(),
        "交接后的旧 ordinary 根本体随本安装 state 一起退休"
    );
    assert!(!fixture.identity_path.exists());
    assert!(
        !fixture.metadata_path.exists(),
        "metadata 由 exact commit custody 在最后退休"
    );
    assert!(
        fixture.candidate_bootstrap_state.exists(),
        "committed Replacement 保留候选 Bootstrap custody"
    );
    assert!(
        legacy_persisted_cleanup_completed(&fixture),
        "成功清理的 receipt 必须为真"
    );
}

/// 归属交接已耐久完成、账户也已删除后被打断：磁盘保留 false commit、留存 metadata 与
/// root:root 的实际数据。第二个全新进程的账户查询明确 absent，准备动作不再依赖 owner。
#[test]
fn legacy_service_owned_state_root_recovers_in_a_new_process_after_the_accounts_are_deleted() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Some(account) = host_legacy_service_account() else {
        return;
    };
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let fixture = build_legacy_state_root_fixture(&LegacyStateRootScenario {
        root,
        service_user: &account.user,
        service_group: &account.group,
        accounts: &format!(
            "passwd|{}|{}\ngroup|{}|{}\n",
            account.user, account.passwd_record, account.group, account.group_record
        ),
        owner: (account.uid, account.gid),
    });

    run_legacy_state_root_child(
        &fixture,
        root,
        "lifecycle.replacement_cleanup_failed",
        true,
        false,
    );

    assert!(
        !legacy_persisted_cleanup_completed(&fixture),
        "本机未退休不能记为清理完成"
    );
    assert_eq!(
        legacy_state_root_owner(&fixture.state_dir),
        Some((0, 0)),
        "中断后磁盘保留已交接的 root:root 根本体"
    );
    assert!(
        fixture.state_dir.join("installed-state").exists(),
        "内容保留故障下实际安装数据仍在"
    );
    assert!(
        fixture.metadata_path.exists(),
        "可信 metadata 活过可失败清理，仍由 exact commit custody 最后退休"
    );
    let accounts = fs::read_to_string(&fixture.accounts_path).expect("account substitute");
    assert!(
        !accounts.contains("passwd|") && !accounts.contains("group|"),
        "首个进程已删除账户，重入不得再次依赖账户查询：{accounts}"
    );

    run_legacy_state_root_child(&fixture, root, "succeeded", false, false);

    assert!(legacy_persisted_cleanup_completed(&fixture));
    assert!(!fixture.state_dir.exists());
    assert!(!fixture.metadata_path.exists());
    assert!(fixture.candidate_bootstrap_state.exists());
}

/// chown 已完成而同步未完成的中断：任何 userdel/groupdel 都还没被调用，receipt 仍假，
/// 磁盘保留 root:root 的实际数据；全新进程重新完成同步后继续。
#[test]
fn legacy_service_owned_state_root_rewaits_an_interrupted_handover_sync_in_a_new_process() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Some(account) = host_legacy_service_account() else {
        return;
    };
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let fixture = build_legacy_state_root_fixture(&LegacyStateRootScenario {
        root,
        service_user: &account.user,
        service_group: &account.group,
        accounts: &format!(
            "passwd|{}|{}\ngroup|{}|{}\n",
            account.user, account.passwd_record, account.group, account.group_record
        ),
        owner: (account.uid, account.gid),
    });

    run_legacy_state_root_child(
        &fixture,
        root,
        "lifecycle.replacement_cleanup_failed",
        false,
        true,
    );

    let trace = legacy_command_trace(&fixture);
    assert!(
        trace
            .iter()
            .all(|line| !line.starts_with("userdel") && !line.starts_with("groupdel")),
        "交接耐久完成前绝不开始账户删除：{trace:?}"
    );
    assert!(
        !legacy_persisted_cleanup_completed(&fixture),
        "同步未完成不能把清理记为完成"
    );
    assert_eq!(
        legacy_state_root_owner(&fixture.state_dir),
        Some((0, 0)),
        "中断只可能落在 chown 之后，重入必须重新完成同步"
    );
    assert!(fixture.state_dir.join("installed-state").exists());
    assert!(fixture.metadata_path.exists());
    let accounts = fs::read_to_string(&fixture.accounts_path).expect("account substitute");
    assert!(
        accounts.contains("passwd|") && accounts.contains("group|"),
        "账户删除尚未开始：{accounts}"
    );

    run_legacy_state_root_child(&fixture, root, "succeeded", false, false);

    let trace = legacy_command_trace(&fixture);
    assert!(
        trace.iter().any(|line| line.starts_with("userdel <")),
        "重新同步后账户删除才继续：{trace:?}"
    );
    assert!(legacy_persisted_cleanup_completed(&fixture));
    assert!(!fixture.state_dir.exists());
    assert!(!fixture.metadata_path.exists());
}

/// 同一正式入口下的必要负项：owner 与本安装 metadata 名称的精确记录不符（含已接受调查的
/// getent 全 absent 孤根输入）时不取得任何删除权，账户删除不开始，实际数据与壳逐字节保留。
#[test]
fn an_unqueryable_legacy_state_root_owner_never_starts_the_formal_account_deletion() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let host_account = host_legacy_service_account();
    let mut cases = vec![(
        "原 getent 全 absent 的孤根输入".to_owned(),
        "enoki-probe".to_owned(),
        "enoki-probe".to_owned(),
        String::new(),
        (8_888_u32, 8_888_u32),
    )];
    if let Some(account) = host_account.as_ref() {
        cases.push((
            "账户可查但目录 gid 与 group 记录不符".to_owned(),
            account.user.clone(),
            account.group.clone(),
            format!(
                "passwd|{}|{}\ngroup|{}|{}\n",
                account.user, account.passwd_record, account.group, account.group_record
            ),
            (account.uid, account.gid + 1),
        ));
    }

    for (label, service_user, service_group, accounts, owner) in cases {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path();
        let fixture = build_legacy_state_root_fixture(&LegacyStateRootScenario {
            root,
            service_user: &service_user,
            service_group: &service_group,
            accounts: &accounts,
            owner,
        });
        fs::write(fixture.state_dir.join("unknown-payload"), "unknown data")
            .expect("unknown payload");

        run_legacy_state_root_child(
            &fixture,
            root,
            "lifecycle.replacement_cleanup_failed",
            false,
            false,
        );

        let trace = legacy_command_trace(&fixture);
        assert!(
            trace
                .iter()
                .all(|line| !line.starts_with("userdel") && !line.starts_with("groupdel")),
            "{label}：归属未确认时账户删除不开始"
        );
        assert_eq!(
            legacy_state_root_owner(&fixture.state_dir),
            Some(owner),
            "{label}：未确认归属的根本体 owner 不被改动"
        );
        assert_eq!(
            fs::read(fixture.state_dir.join("unknown-payload")).expect("unknown payload"),
            b"unknown data",
            "{label}：归属未确认时不删除未知对象"
        );
        assert!(
            !legacy_persisted_cleanup_completed(&fixture),
            "{label}：本机未退休不能记为清理完成"
        );
        assert!(
            fixture.metadata_path.exists(),
            "{label}：可信 metadata 仍由 exact commit custody 保管"
        );
        assert!(
            fixture.identity_path.exists(),
            "{label}：身份退休尚未开始，必要资源不被提前吞掉"
        );
        assert!(fixture.candidate_bootstrap_state.exists());
    }
}

/// canonical 投影不经过 ordinary 账户交接：准备动作既不改动固定 private 根的 owner，
/// 也不把实际数据交给交接路径；退休中断只可能落在原样保留的固定投影上。
#[test]
fn canonical_state_root_never_takes_the_ordinary_account_handover() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Some(account) = host_legacy_service_account() else {
        return;
    };
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let fixture = build_legacy_state_root_fixture(&LegacyStateRootScenario {
        root,
        service_user: &account.user,
        service_group: &account.group,
        accounts: &format!(
            "passwd|{}|{}\ngroup|{}|{}\n",
            account.user, account.passwd_record, account.group, account.group_record
        ),
        owner: (999, 999),
    });
    let private = root.join("var/lib/private/enoki-probe");
    fs::create_dir_all(private.parent().expect("private parent")).expect("private parent");
    fs::rename(&fixture.state_dir, &private).expect("canonical private root");
    symlink("private/enoki-probe", &fixture.state_dir).expect("canonical public link");

    run_legacy_state_root_child(
        &fixture,
        root,
        "lifecycle.replacement_cleanup_failed",
        true,
        false,
    );

    assert_eq!(
        legacy_state_root_owner(&private),
        Some((999, 999)),
        "准备动作不改 canonical owner"
    );
    assert!(
        private.join("installed-state").exists(),
        "canonical 实际数据不被交接路径改动"
    );
    assert!(fixture.state_dir.is_symlink(), "exact public 链保持原形态");
    assert!(
        !legacy_persisted_cleanup_completed(&fixture),
        "未退休不能记为清理完成"
    );
    assert!(fixture.metadata_path.exists());
}

#[test]
fn legacy_state_root_formal_recovery_child_process() {
    let Ok(expected) = std::env::var("ENOKI_TEST_LEGACY_STATE_EXPECTED") else {
        return;
    };
    if std::env::var("ENOKI_TEST_LEGACY_STATE_RETIREMENT_FAULT").is_ok_and(|fault| fault == "1") {
        inject_state_root_removal_fault(Some(StateRootRemovalFault::ContentsRetained));
    }
    let request = legacy_replacement_request();
    let mut transport = RecordingValidationTransport::default();

    let response = crate::upgrader::run_lifecycle_companion(&request, &mut transport);

    let expected = if expected == "succeeded" {
        LifecycleResponse::succeeded()
    } else {
        LifecycleResponse::failed(&expected)
    };
    assert_eq!(response, expected, "正式 exact-request 恢复入口的反馈");
    assert!(
        transport.downloads.is_empty(),
        "恢复路径不访问 Hub，反馈只来自本机清理"
    );
}

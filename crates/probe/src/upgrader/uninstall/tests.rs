use super::{
    CompanionBinaryFacts, PostCommitSelfFinalizeFacts, ResumeDecision, UninstallCapsulePhase,
    adapt_uninstall_wire_request, commit_lifecycle_capsule_with, coordinate_at,
    coordinate_lifecycle_companion_recovery_at, lifecycle_response_from_resume_decision,
    post_commit_self_finalize_policy, read_uninstall_capsule, resume_lifecycle_companion_at,
    run_uninstall_lifecycle_adapter, uninstall_capsule_path,
};
use crate::{
    probe_auth::ProbeRequestAuth,
    upgrader::{
        ProbeUninstallerRunInput, ProbeUpgraderRunError, ProbeUpgraderSystemdRunner,
        ProbeUpgraderValidationTransport, TrustedProbeInstallMetadata,
        TrustedProbeInstallPreflight,
    },
};
use enoki_probe_bootstrap::{
    install::commit_current_layout_for_test,
    lifecycle::{LifecycleRequest, LifecycleResponse},
};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{PermissionsExt, chown},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    thread,
    time::Duration,
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
    final_verification_barrier: Option<(usize, mpsc::Sender<()>, mpsc::Receiver<()>)>,
    final_verification_failure_after: Option<usize>,
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
        if service_name == "enoki-probe"
            && let Some((remaining, _, _)) = self.final_verification_barrier.as_mut()
        {
            if *remaining == 0 {
                let (_, entered, release) = self.final_verification_barrier.take().unwrap();
                entered.send(()).expect("publish final verification");
                release.recv().expect("release final verification");
            } else {
                *remaining -= 1;
            }
        }
        if service_name == "enoki-probe"
            && let Some(remaining) = self.final_verification_failure_after.as_mut()
        {
            if *remaining == 0 {
                return Err(ProbeUpgraderRunError::RestartFailure(
                    "injected final verification failure".to_owned(),
                ));
            }
            *remaining -= 1;
        }
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
        install_state_absent: true,
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
            install_state_absent: false,
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
        fixture.metadata.bootstrap_state_dir.as_ref().unwrap(),
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
fn production_uninstall_serializes_planning_and_retires_a_waiting_activation_generation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    fs::write(
        &fixture.metadata_path,
        crate::upgrader::install_metadata_tests::schema_five_metadata_contents(),
    )
    .expect("schema five install metadata");
    fs::set_permissions(&fixture.metadata_path, fs::Permissions::from_mode(0o600))
        .expect("install metadata mode");
    fs::set_permissions(&fixture.identity_path, fs::Permissions::from_mode(0o600))
        .expect("identity mode");
    commit_current_layout_for_test(temporary.path(), "1.2.3")
        .expect("canonical install producer commits current-layout receipt");
    let activation_lock = fixture
        .metadata
        .bootstrap_state_dir
        .as_ref()
        .expect("bootstrap state")
        .join("activation.lock");
    let held_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&activation_lock)
        .expect("open canonical activation lock");
    assert_eq!(
        unsafe { libc::flock(held_lock.as_raw_fd(), libc::LOCK_EX) },
        0
    );

    let request =
        LifecycleRequest::local_uninstall("probe_01", &"b".repeat(64), &"c".repeat(64), "1.2.3")
            .expect("bound local uninstall request");
    let (effect_entered_tx, effect_entered_rx) = mpsc::channel();
    let (effect_release_tx, effect_release_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let root = temporary.path().to_path_buf();
    let uninstall = thread::spawn(move || {
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner {
            final_verification_barrier: Some((1, effect_entered_tx, effect_release_rx)),
            ..RecordingSystemdRunner::default()
        };
        let response = coordinate_at(Some(&request), Some(&root), &mut transport, &mut systemd);
        finished_tx
            .send((response, transport, systemd.calls))
            .expect("publish uninstall result");
    });

    assert!(
        effect_entered_rx
            .recv_timeout(Duration::from_millis(40))
            .is_err(),
        "the lifecycle lock precedes every final verification"
    );
    assert!(finished_rx.try_recv().is_err());
    assert_eq!(
        unsafe { libc::flock(held_lock.as_raw_fd(), libc::LOCK_UN) },
        0
    );
    drop(held_lock);
    effect_entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("uninstall reaches its final pre-retirement verification");

    let (activation_tx, activation_rx) = mpsc::channel();
    let activation_root = temporary.path().to_path_buf();
    let activation = thread::spawn(move || {
        activation_tx
            .send(commit_current_layout_for_test(&activation_root, "1.2.3"))
            .expect("publish activation result");
    });
    assert!(
        activation_rx
            .recv_timeout(Duration::from_millis(40))
            .is_err(),
        "activation cannot enter while uninstall owns the lifecycle"
    );
    effect_release_tx
        .send(())
        .expect("release uninstall effect");

    let (response, transport, transcript) = finished_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("uninstall converges after the prior holder releases");
    assert_eq!(response, LifecycleResponse::succeeded());
    assert!(transport.url.is_empty());
    assert!(transport.status_url.is_empty());
    assert!(transcript.contains(&"stop enoki-probe".to_owned()));
    assert!(transcript.contains(&"disable enoki-probe".to_owned()));
    assert!(
        activation_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .is_err()
    );
    uninstall.join().unwrap();
    activation.join().unwrap();
}

#[test]
fn production_recovery_can_resume_after_the_final_pre_retirement_effect_fails() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let fixture = uninstall_coordinator_fixture(temporary.path());
    fs::write(
        &fixture.metadata_path,
        crate::upgrader::install_metadata_tests::schema_five_metadata_contents(),
    )
    .expect("schema five install metadata");
    fs::set_permissions(&fixture.metadata_path, fs::Permissions::from_mode(0o600))
        .expect("install metadata mode");
    fs::set_permissions(&fixture.identity_path, fs::Permissions::from_mode(0o600))
        .expect("identity mode");
    commit_current_layout_for_test(temporary.path(), "1.2.3")
        .expect("canonical install producer commits current-layout receipt");
    let request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_42",
        "operation-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("bound Hub uninstall request");
    let mut first_transport = RecordingValidationTransport::default();
    let mut first_systemd = RecordingSystemdRunner {
        final_verification_failure_after: Some(1),
        ..RecordingSystemdRunner::default()
    };

    let first = coordinate_at(
        Some(&request),
        Some(temporary.path()),
        &mut first_transport,
        &mut first_systemd,
    );
    assert_eq!(first, LifecycleResponse::recovery_pending());

    let mut retry_transport = RecordingValidationTransport::default();
    let mut retry_systemd = RecordingSystemdRunner::default();
    let retry = coordinate_lifecycle_companion_recovery_at(
        Some(temporary.path()),
        &mut retry_transport,
        &mut retry_systemd,
    );
    assert_eq!(retry, LifecycleResponse::succeeded());
    assert!(retry_transport.url.is_empty());
    assert!(retry_transport.status_url.is_empty());
}

#[test]
fn production_recovery_serializes_its_first_fact_read_and_then_converges() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bootstrap_state = temporary.path().join("var/lib/enoki-probe-bootstrap");
    fs::create_dir_all(&bootstrap_state).expect("bootstrap state");
    fs::set_permissions(&bootstrap_state, fs::Permissions::from_mode(0o700))
        .expect("bootstrap state mode");
    let activation_lock = bootstrap_state.join("activation.lock");
    fs::write(&activation_lock, []).expect("activation lock");
    fs::set_permissions(&activation_lock, fs::Permissions::from_mode(0o600))
        .expect("activation lock mode");
    let companion = temporary
        .path()
        .join("usr/local/bin/enoki-probe-lifecycle-companion");
    fs::create_dir_all(companion.parent().unwrap()).expect("companion parent");
    fs::write(&companion, "companion").expect("companion binary");
    fs::set_permissions(&companion, fs::Permissions::from_mode(0o755)).expect("companion mode");
    let held_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&activation_lock)
        .expect("open activation lock");
    assert_eq!(
        unsafe { libc::flock(held_lock.as_raw_fd(), libc::LOCK_EX) },
        0
    );

    let (finished_tx, finished_rx) = mpsc::channel();
    let root = temporary.path().to_path_buf();
    let recovery = thread::spawn(move || {
        let mut transport = RecordingValidationTransport::default();
        let mut systemd = RecordingSystemdRunner::default();
        let response =
            coordinate_lifecycle_companion_recovery_at(Some(&root), &mut transport, &mut systemd);
        finished_tx
            .send((response, transport, systemd.calls))
            .expect("publish recovery result");
    });
    assert!(finished_rx.recv_timeout(Duration::from_millis(40)).is_err());

    assert_eq!(
        unsafe { libc::flock(held_lock.as_raw_fd(), libc::LOCK_UN) },
        0
    );
    drop(held_lock);
    let (response, transport, transcript) = finished_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("recovery re-reads and converges after release");
    assert_eq!(response, LifecycleResponse::succeeded());
    assert!(transport.url.is_empty());
    assert!(transport.status_url.is_empty());
    assert!(transcript.is_empty());
    recovery.join().unwrap();
}

#[test]
fn schema_five_uninstall_accepts_the_production_current_layout_receipt() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let mut fixture = uninstall_coordinator_fixture(temporary.path());
    fixture.metadata.schema_version = 5;
    fixture.metadata.lifecycle_authority_install_key = Some("e".repeat(64));
    commit_current_layout_for_test(temporary.path(), "1.2.3")
        .expect("canonical install producer commits current-layout receipt");
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
}

#[test]
fn schema_five_uninstall_rejects_noncanonical_production_activation_lock_before_effects() {
    for corruption in ["mode", "type", "nlink", "owner"] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut fixture = uninstall_coordinator_fixture(temporary.path());
        fixture.metadata.schema_version = 5;
        fixture.metadata.lifecycle_authority_install_key = Some("e".repeat(64));
        commit_current_layout_for_test(temporary.path(), "1.2.3")
            .expect("canonical install producer commits current-layout receipt");
        let activation_lock = fixture
            .metadata
            .bootstrap_state_dir
            .as_ref()
            .expect("bootstrap state")
            .join("activation.lock");
        match corruption {
            "mode" => fs::set_permissions(&activation_lock, fs::Permissions::from_mode(0o4600))
                .expect("activation lock special mode"),
            "type" => {
                fs::remove_file(&activation_lock).expect("remove activation lock file");
                fs::create_dir(&activation_lock).expect("replace activation lock with directory");
            }
            "nlink" => fs::hard_link(
                &activation_lock,
                temporary.path().join("activation-lock-alias"),
            )
            .expect("hard-link activation lock"),
            "owner" => {
                chown(&activation_lock, Some(1), Some(1)).expect("change activation lock owner")
            }
            _ => unreachable!(),
        }
        let request = LifecycleRequest::local_uninstall(
            "probe_01",
            &"b".repeat(64),
            &"c".repeat(64),
            "1.2.3",
        )
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

        assert_eq!(
            response,
            LifecycleResponse::failed("probe_uninstall_metadata_invalid"),
            "corruption: {corruption}"
        );
        assert!(transport.url.is_empty());
        assert!(transport.status_url.is_empty());
        assert!(transport.downloads.is_empty());
        assert!(systemd.calls.is_empty());
    }
}

#[test]
fn schema_five_uninstall_rejects_mismatched_current_layout_receipt_before_effects() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let mut fixture = uninstall_coordinator_fixture(temporary.path());
    fixture.metadata.schema_version = 5;
    fixture.metadata.lifecycle_authority_install_key = Some("e".repeat(64));
    let current_layout = fixture
        .metadata
        .bootstrap_state_dir
        .as_ref()
        .expect("bootstrap state")
        .join("current-layout");
    fs::write(&current_layout, "schema_version=1\nversion=1.2.4\n")
        .expect("mismatched current-layout receipt");
    fs::set_permissions(&current_layout, fs::Permissions::from_mode(0o600))
        .expect("current-layout mode");
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

    assert_eq!(
        response,
        LifecycleResponse::failed("probe_uninstall_metadata_invalid")
    );
    assert!(transport.url.is_empty());
    assert!(transport.status_url.is_empty());
    assert!(transport.downloads.is_empty());
    assert!(systemd.calls.is_empty());
}

#[test]
fn schema_five_uninstall_rejects_special_mode_current_layout_receipt_before_effects() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let mut fixture = uninstall_coordinator_fixture(temporary.path());
    fixture.metadata.schema_version = 5;
    fixture.metadata.lifecycle_authority_install_key = Some("e".repeat(64));
    let current_layout = fixture
        .metadata
        .bootstrap_state_dir
        .as_ref()
        .expect("bootstrap state")
        .join("current-layout");
    fs::write(&current_layout, "schema_version=1\nversion=1.2.3\n")
        .expect("production current-layout receipt");
    fs::set_permissions(&current_layout, fs::Permissions::from_mode(0o4600))
        .expect("current-layout special mode");
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

    assert_eq!(
        response,
        LifecycleResponse::failed("probe_uninstall_metadata_invalid")
    );
    assert!(transport.url.is_empty());
    assert!(transport.status_url.is_empty());
    assert!(transport.downloads.is_empty());
    assert!(systemd.calls.is_empty());
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

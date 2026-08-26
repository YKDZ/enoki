use super::*;
use super::{
    replacement::{
        fixed_installed_probe_sha256, production_path as replacement_production_path,
        resume_committed_from_exact_request as resume_committed_replacement_from_exact_request,
    },
    uninstall::commit_replacement_and_cleanup_install_with_systemd,
};
use enoki_probe_bootstrap::replacement::{
    FileReplacementCommitStore, ReplacementCommitError, ReplacementCommitFact,
    ReplacementCommitStore, ReplacementIntent,
};
use flate2::{Compression, write::GzEncoder};
use rsa::{
    RsaPrivateKey,
    pkcs1v15::SigningKey,
    pkcs8::EncodePublicKey,
    rand_core::OsRng,
    signature::{RandomizedSigner, SignatureEncoding},
};
use std::{collections::HashMap, fs};

#[derive(Default)]
struct RecordingValidationTransport {
    assets: HashMap<String, Vec<u8>>,
    body: String,
    downloads: Vec<String>,
    probe_id: String,
    status_body: String,
    status_failure: bool,
    status_url: String,
    url: String,
    validated_identity_url: String,
    identity_failure: Option<String>,
}

#[derive(Default)]
struct RecordingSystemdRunner {
    calls: Vec<String>,
    failure: Option<String>,
    failure_step: Option<&'static str>,
    paths_required_during_identity_removal: Vec<PathBuf>,
    restarted: Vec<String>,
    verification_failure_after_paths_absent: Vec<PathBuf>,
}

impl RecordingSystemdRunner {
    fn record_step(&mut self, step: &'static str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(step.to_string());
        if self.failure_step == Some(step) {
            return Err(ProbeUpgraderRunError::RestartFailure(format!(
                "{step} failed"
            )));
        }
        Ok(())
    }
}

impl ProbeUpgraderValidationTransport for RecordingValidationTransport {
    fn get_asset(&mut self, url: &str) -> Result<Vec<u8>, ProbeUpgraderRunError> {
        self.downloads.push(url.to_string());
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
        self.url = url.to_string();
        self.probe_id = auth.probe_id.to_string();
        self.body = body.to_string();

        Ok(())
    }

    fn post_operation_status(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        self.status_url = url.to_string();
        self.probe_id = auth.probe_id.to_string();
        self.status_body = body.to_string();

        if self.status_failure {
            return Err(ProbeUpgraderRunError::UninstallStatusReportFailure(
                "temporary report failure".to_owned(),
            ));
        }

        Ok(())
    }

    fn validate_probe_identity(
        &mut self,
        url: &str,
        auth: &ProbeRequestAuth<'_>,
    ) -> Result<(), ProbeUpgraderRunError> {
        self.validated_identity_url = url.to_string();
        self.probe_id = auth.probe_id.to_string();
        if let Some(message) = self.identity_failure.take() {
            return Err(ProbeUpgraderRunError::IdentityValidation(message));
        }
        Ok(())
    }
}

impl ProbeUpgraderSystemdRunner for RecordingSystemdRunner {
    fn ensure_service_group(&mut self, _service_group: &str) -> Result<(), ProbeUpgraderRunError> {
        self.record_step("ensure-group")
    }

    fn ensure_service_account(
        &mut self,
        _service_user: &str,
        _service_group: &str,
        _state_dir: &Path,
        _identity_path: &Path,
    ) -> Result<(), ProbeUpgraderRunError> {
        self.record_step("ensure-account")
    }

    fn enable_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!("enable {service_name}"));
        if self.failure_step == Some("enable") {
            return Err(ProbeUpgraderRunError::RestartFailure(
                "enable failed".to_string(),
            ));
        }
        Ok(())
    }

    fn restart_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!("restart {service_name}"));
        if self.failure_step == Some("restart") {
            return Err(ProbeUpgraderRunError::RestartFailure(
                "restart failed".to_string(),
            ));
        }
        if let Some(failure) = self.failure.take() {
            return Err(ProbeUpgraderRunError::RestartFailure(failure));
        }
        self.restarted.push(service_name.to_string());
        Ok(())
    }

    fn stop_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!("stop {service_name}"));
        if self.failure_step == Some("stop") {
            return Err(ProbeUpgraderRunError::RestartFailure(
                "stop failed".to_string(),
            ));
        }
        Ok(())
    }

    fn disable_service(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!("disable {service_name}"));
        if self.failure_step == Some("disable") {
            return Err(ProbeUpgraderRunError::RestartFailure(
                "disable failed".to_string(),
            ));
        }
        Ok(())
    }

    fn daemon_reload(&mut self) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push("daemon-reload".to_string());
        if self.failure_step == Some("daemon-reload") {
            return Err(ProbeUpgraderRunError::RestartFailure(
                "daemon-reload failed".to_string(),
            ));
        }
        Ok(())
    }

    fn reset_failed(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!("reset-failed {service_name}"));
        if self.failure_step == Some("reset-failed") {
            return Err(ProbeUpgraderRunError::RestartFailure(
                "reset-failed failed".to_string(),
            ));
        }
        Ok(())
    }

    fn verify_service_active(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!("verify-active {service_name}"));
        if self.failure_step == Some("verify-active") {
            return Err(ProbeUpgraderRunError::RestartFailure(
                "service is not active".to_string(),
            ));
        }
        Ok(())
    }

    fn verify_service_absent(&mut self, service_name: &str) -> Result<(), ProbeUpgraderRunError> {
        self.calls
            .push(format!("verify-service-absent {service_name}"));
        if self.failure_step == Some("verify-service")
            || (!self.verification_failure_after_paths_absent.is_empty()
                && self
                    .verification_failure_after_paths_absent
                    .iter()
                    .all(|path| !path.exists()))
        {
            return Err(uninstall_cleanup_failure(
                "probe_uninstall_service_residue",
                "verifying the service is absent",
                "systemd LoadState is loaded".to_string(),
            ));
        }
        Ok(())
    }

    fn remove_service_identity(
        &mut self,
        service_user: &str,
        service_group: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        self.calls.push(format!(
            "remove-service-identity {service_user}:{service_group}"
        ));
        if self
            .paths_required_during_identity_removal
            .iter()
            .any(|path| !path.exists())
        {
            return Err(ProbeUpgraderRunError::RestartFailure(
                "lifecycle recovery assets disappeared too early".to_string(),
            ));
        }
        if self.failure_step == Some("remove-account") {
            return Err(ProbeUpgraderRunError::RestartFailure(
                "service account removal failed".to_string(),
            ));
        }
        Ok(())
    }
}

#[test]
fn internal_probe_upgrader_rejects_missing_stdin_token() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_private_key_pem = \"test-private-key\"",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingValidationTransport::default();

    let error = run_probe_upgrader(
        ProbeUpgraderRunInput {
            bootstrap_config_path,
        },
        "",
        &mut transport,
    )
    .expect_err("missing token fails");

    assert!(matches!(error, ProbeUpgraderRunError::MissingToken));
    assert_eq!(transport.url, "");
}

fn fixed_schema_four_metadata_contents() -> String {
    [
        "schema_version = 4".to_owned(),
        "hub_url = \"https://hub.example\"".to_owned(),
        "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"".to_owned(),
        "install_path = \"/usr/local/bin/enoki-probe\"".to_owned(),
        format!("observation_runtime_path = \"{OBSERVATION_RUNTIME_BINARY_PATH}\""),
        format!("cpu_provider_path = \"{CPU_PROVIDER_BINARY_PATH}\""),
        format!("disk_health_provider_path = \"{DISK_HEALTH_PROVIDER_BINARY_PATH}\""),
        format!("lifecycle_companion_path = \"{LIFECYCLE_COMPANION_BINARY_PATH}\""),
        format!("probe_ipc_group = \"{PROBE_IPC_GROUP}\""),
        format!(
            "probe_ipc_group_ownership = \"!enoki-bootstrap-{}\"",
            "d".repeat(32)
        ),
        format!("observation_ipc_group = \"{OBSERVATION_IPC_GROUP}\""),
        "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"".to_owned(),
        "state_dir = \"/var/lib/enoki-probe\"".to_owned(),
        format!("probe_distribution_root_sha256 = \"{}\"", "a".repeat(64)),
        format!("install_state_sha256 = \"{}\"", "b".repeat(64)),
        format!("target_manifest_sha256 = \"{}\"", "c".repeat(64)),
        "bundle_version = \"1.2.3\"".to_owned(),
        format!("bootstrap_acquirer_path = \"{PRODUCTION_BOOTSTRAP_ACQUIRER_PATH}\""),
        format!("bootstrap_activator_path = \"{PRODUCTION_BOOTSTRAP_ACTIVATOR_PATH}\""),
        format!("bootstrap_state_dir = \"{PRODUCTION_BOOTSTRAP_STATE_DIR}\""),
        "service_name = \"enoki-probe\"".to_owned(),
        "service_user = \"enoki-probe\"".to_owned(),
        "service_group = \"enoki-probe\"".to_owned(),
        "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"".to_owned(),
        format!(
            "observation_runtime_service_unit_path = \"{OBSERVATION_RUNTIME_SERVICE_UNIT_PATH}\""
        ),
        format!(
            "observation_runtime_socket_unit_path = \"{OBSERVATION_RUNTIME_SOCKET_UNIT_PATH}\""
        ),
        format!("cpu_provider_service_unit_path = \"{CPU_PROVIDER_SERVICE_UNIT_PATH}\""),
        format!("cpu_provider_socket_unit_path = \"{CPU_PROVIDER_SOCKET_UNIT_PATH}\""),
        format!(
            "disk_health_provider_service_unit_path = \"{DISK_HEALTH_PROVIDER_SERVICE_UNIT_PATH}\""
        ),
        format!(
            "disk_health_provider_socket_unit_path = \"{DISK_HEALTH_PROVIDER_SOCKET_UNIT_PATH}\""
        ),
        format!(
            "lifecycle_companion_service_unit_path = \"{LIFECYCLE_COMPANION_SERVICE_UNIT_PATH}\""
        ),
        format!(
            "lifecycle_companion_socket_unit_path = \"{LIFECYCLE_COMPANION_SOCKET_UNIT_PATH}\""
        ),
        format!("collector_helper_sudoers_path = \"{PRODUCTION_COLLECTOR_HELPER_SUDOERS_PATH}\""),
    ]
    .join("\n")
}

fn fixed_replacement_cleanup_fixture(root: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    fixed_replacement_cleanup_fixture_with_contents(root, fixed_schema_four_metadata_contents())
}

fn fixed_replacement_cleanup_fixture_with_contents(
    root: &Path,
    contents: String,
) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let metadata =
        parse_trusted_probe_install_metadata(&contents).expect("trusted install metadata");
    let rooted = |path: &Path| preflight_rooted_path(Some(root), path);
    let metadata_path = rooted(Path::new(PRODUCTION_INSTALL_METADATA_PATH));
    for path in [
        &metadata.identity_path,
        &metadata.install_path,
        &metadata.service_unit_path,
    ]
    .into_iter()
    .chain(metadata.observation_unit_paths.iter())
    .map(PathBuf::as_path)
    .chain(
        [
            metadata.observation_runtime_path.as_deref(),
            metadata.cpu_provider_path.as_deref(),
            metadata.disk_health_provider_path.as_deref(),
            metadata.lifecycle_companion_path.as_deref(),
            metadata.bootstrap_acquirer_path.as_deref(),
            metadata.bootstrap_activator_path.as_deref(),
            metadata.collector_helper_sudoers_path.as_deref(),
        ]
        .into_iter()
        .flatten(),
    )
    .chain(metadata.old_sudoers_paths.iter().map(PathBuf::as_path))
    {
        let path = rooted(path);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture parent");
        fs::write(&path, "owned").expect("fixture file");
    }
    for path in [
        metadata
            .bootstrap_acquirer_path
            .as_deref()
            .expect("acquirer"),
        metadata
            .bootstrap_activator_path
            .as_deref()
            .expect("activator"),
    ] {
        fs::set_permissions(rooted(path), fs::Permissions::from_mode(0o755))
            .expect("Bootstrap role mode");
    }
    fs::set_permissions(
        rooted(&metadata.install_path),
        fs::Permissions::from_mode(0o755),
    )
    .expect("installed Probe mode");
    fs::write(
            rooted(&metadata.identity_path),
            "hub_url = \"https://hub.example\"\nprobe_id = \"probe_old_01\"\nprobe_private_key_pem = \"test-private-key\"\n",
        )
        .expect("source Probe identity");
    fs::set_permissions(
        rooted(&metadata.identity_path),
        fs::Permissions::from_mode(0o600),
    )
    .expect("source Probe identity mode");
    let bootstrap_state = rooted(metadata.bootstrap_state_dir.as_deref().expect("state"));
    fs::create_dir_all(bootstrap_state.join("trust")).expect("trust state");
    fs::create_dir(bootstrap_state.join("inbox")).expect("inbox state");
    for path in [
        &bootstrap_state,
        &bootstrap_state.join("trust"),
        &bootstrap_state.join("inbox"),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("Bootstrap state mode");
    }
    fs::create_dir_all(metadata_path.parent().expect("metadata parent")).expect("metadata parent");
    fs::write(&metadata_path, contents).expect("metadata");
    fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o600)).expect("metadata mode");
    (
        metadata_path,
        bootstrap_state,
        rooted(&metadata.identity_path),
        rooted(&metadata.state_dir),
    )
}

fn fixed_schema_two_metadata_contents() -> String {
    [
        "schema_version = 2".to_owned(),
        "hub_url = \"https://hub.example\"".to_owned(),
        "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"".to_owned(),
        "install_path = \"/usr/local/bin/enoki-probe\"".to_owned(),
        "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"".to_owned(),
        "state_dir = \"/var/lib/enoki-probe\"".to_owned(),
        format!("probe_distribution_root_sha256 = \"{}\"", "a".repeat(64)),
        format!("bootstrap_acquirer_path = \"{PRODUCTION_BOOTSTRAP_ACQUIRER_PATH}\""),
        format!("bootstrap_activator_path = \"{PRODUCTION_BOOTSTRAP_ACTIVATOR_PATH}\""),
        format!("bootstrap_state_dir = \"{PRODUCTION_BOOTSTRAP_STATE_DIR}\""),
        "service_name = \"enoki-probe\"".to_owned(),
        "service_user = \"enoki-probe\"".to_owned(),
        "service_group = \"enoki-probe\"".to_owned(),
        "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"".to_owned(),
        String::new(),
    ]
    .join("\n")
}

#[test]
fn committed_replacement_closure_starts_after_commit_and_retries_metadata_last_cleanup() {
    #[derive(Default)]
    struct TestCommitStore {
        fact: Option<ReplacementCommitFact>,
        fail_next_persist: bool,
        persisted_cleanup: Vec<bool>,
    }

    impl ReplacementCommitStore for TestCommitStore {
        type Error = &'static str;

        fn load(&mut self) -> Result<Option<ReplacementCommitFact>, Self::Error> {
            Ok(self.fact.clone())
        }

        fn persist(&mut self, fact: &ReplacementCommitFact) -> Result<(), Self::Error> {
            if self.fail_next_persist {
                self.fail_next_persist = false;
                return Err("injected commit persistence failure");
            }
            self.persisted_cleanup.push(fact.cleanup_complete);
            self.fact = Some(fact.clone());
            Ok(())
        }
    }

    let temporary = tempfile::tempdir().expect("temporary directory");
    let (metadata_path, candidate_bootstrap_state, identity_path, state_dir) =
        fixed_replacement_cleanup_fixture(temporary.path());
    let installed_probe_sha256 = fixed_installed_probe_sha256(
        Path::new(PRODUCTION_PROBE_BINARY_PATH),
        Some(temporary.path()),
    )
    .expect("installed Probe digest");
    let token = "enk_enroll_test";
    let intent = ReplacementIntent {
        enrollment_id: "enr_0123456789abcdef".to_owned(),
        enrollment_token_sha256: format!("{:x}", Sha256::digest(token.as_bytes())),
        host_id: "7".to_owned(),
        hub_origin: "https://hub.example".to_owned(),
        old_probe_id: "probe_old_01".to_owned(),
        source_probe_version: "1.2.3".to_owned(),
        source_probe_sha256: installed_probe_sha256,
        target_bundle_target: "x86_64-unknown-linux-gnu".to_owned(),
        target_probe_version: "1.2.3".to_owned(),
        target_asset_set_digest: format!("sha256:{}", "c".repeat(64)),
        target_manifest_sha256: "d".repeat(64),
    };
    let mut store = TestCommitStore {
        fail_next_persist: true,
        ..TestCommitStore::default()
    };
    let mut precommit_systemd = RecordingSystemdRunner::default();

    let precommit = commit_replacement_and_cleanup_install_with_systemd(
        intent.clone(),
        &mut store,
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        Some(temporary.path()),
        &mut precommit_systemd,
    );
    assert!(matches!(precommit, Err(ReplacementCommitError::Store(_))));
    assert!(
        precommit_systemd.calls.is_empty(),
        "commit precedes cleanup"
    );
    assert!(metadata_path.exists());
    assert!(identity_path.exists());
    assert!(candidate_bootstrap_state.exists());

    let mut late_failure_systemd = RecordingSystemdRunner {
        verification_failure_after_paths_absent: vec![identity_path.clone(), state_dir.clone()],
        ..RecordingSystemdRunner::default()
    };
    let postcommit = commit_replacement_and_cleanup_install_with_systemd(
        intent.clone(),
        &mut store,
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        Some(temporary.path()),
        &mut late_failure_systemd,
    );
    assert!(
        matches!(postcommit, Err(ReplacementCommitError::Effect(_))),
        "unexpected postcommit result: {postcommit:?}"
    );
    assert_eq!(store.persisted_cleanup, [false]);
    assert!(
        metadata_path.exists(),
        "metadata survives every earlier fallible step"
    );
    assert!(!identity_path.exists());
    assert!(!state_dir.exists());
    assert!(
        candidate_bootstrap_state.exists(),
        "committed Replacement preserves candidate Bootstrap custody"
    );

    let completed = commit_replacement_and_cleanup_install_with_systemd(
        intent.clone(),
        &mut store,
        Path::new(PRODUCTION_INSTALL_METADATA_PATH),
        Some(temporary.path()),
        &mut RecordingSystemdRunner::default(),
    )
    .expect("production Replacement seam converges the committed cleanup");
    assert!(completed.cleanup_complete);
    assert!(!metadata_path.exists());

    let commit_path =
        replacement_production_path(PRODUCTION_REPLACEMENT_COMMIT_PATH, Some(temporary.path()));
    let mut production_store =
        FileReplacementCommitStore::at(&commit_path, unsafe { libc::geteuid() });
    production_store
        .persist(store.fact.as_ref().expect("cleanup receipt"))
        .expect("persist production cleanup receipt");
    let enrollment_input = format!(
        "{{\"hubOrigin\":\"https://hub.example\",\"enrollmentToken\":\"{token}\",\"replacementMigration\":{{\"enrollmentId\":\"enr_0123456789abcdef\",\"expectedProbeId\":\"probe_old_01\",\"sourceProbeSha256\":[\"{}\"],\"sourceProbeVersion\":\"1.2.3\",\"targetAssetSetDigest\":\"sha256:{}\",\"targetHostId\":\"7\",\"targetProbeVersion\":\"1.2.3\"}},\"schemaVersion\":1}}",
        intent.source_probe_sha256,
        "c".repeat(64),
    );
    let enrollment = enoki_probe_bootstrap::handoff::Enrollment::from_install_input(
        "https://hub.example",
        enrollment_input.as_bytes(),
    )
    .expect("exact replacement enrollment");
    let request = LifecycleRequest::replacement_migration(
        &enrollment,
        &intent.target_asset_set_digest,
        &intent.target_bundle_target,
        &intent.target_manifest_sha256,
        &intent.target_probe_version,
    )
    .expect("exact replacement request");
    assert_eq!(
        resume_committed_replacement_from_exact_request(&request, Some(temporary.path())),
        Some(LifecycleResponse::succeeded()),
        "fresh production adapter retries metadata retirement monotonically"
    );
    assert!(production_store.load().unwrap().unwrap().cleanup_complete);
    assert_eq!(store.persisted_cleanup, [false, true]);
    assert!(
        !metadata_path.exists(),
        "metadata is the final local deletion"
    );
    assert!(candidate_bootstrap_state.exists());
}

#[test]
fn committed_replacement_cleans_schema_two_and_three_inventory_and_preserves_candidate_custody() {
    #[derive(Default)]
    struct Store(Option<ReplacementCommitFact>);
    impl ReplacementCommitStore for Store {
        type Error = ();
        fn load(&mut self) -> Result<Option<ReplacementCommitFact>, Self::Error> {
            Ok(self.0.clone())
        }
        fn persist(&mut self, fact: &ReplacementCommitFact) -> Result<(), Self::Error> {
            self.0 = Some(fact.clone());
            Ok(())
        }
    }

    for contents in [
        fixed_schema_two_metadata_contents(),
        schema_three_install_metadata_contents(),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let (metadata_path, candidate_bootstrap_state, identity_path, state_dir) =
            fixed_replacement_cleanup_fixture_with_contents(temporary.path(), contents);
        let installed_probe_sha256 = fixed_installed_probe_sha256(
            Path::new(PRODUCTION_PROBE_BINARY_PATH),
            Some(temporary.path()),
        )
        .expect("installed Probe digest");
        let intent = ReplacementIntent {
            enrollment_id: "enr_0123456789abcdef".to_owned(),
            enrollment_token_sha256: "a".repeat(64),
            host_id: "7".to_owned(),
            hub_origin: "https://hub.example".to_owned(),
            old_probe_id: "probe_old_01".to_owned(),
            source_probe_version: "1.2.3".to_owned(),
            source_probe_sha256: installed_probe_sha256,
            target_bundle_target: "x86_64-unknown-linux-gnu".to_owned(),
            target_probe_version: "1.2.3".to_owned(),
            target_asset_set_digest: format!("sha256:{}", "c".repeat(64)),
            target_manifest_sha256: "d".repeat(64),
        };
        let mut store = Store::default();

        let completed = commit_replacement_and_cleanup_install_with_systemd(
            intent.clone(),
            &mut store,
            Path::new(PRODUCTION_INSTALL_METADATA_PATH),
            Some(temporary.path()),
            &mut RecordingSystemdRunner::default(),
        )
        .expect("legacy committed inventory cleanup");

        assert!(completed.cleanup_complete);
        assert!(!metadata_path.exists());
        assert!(!identity_path.exists());
        assert!(!state_dir.exists());
        assert!(candidate_bootstrap_state.exists());
        commit_replacement_and_cleanup_install_with_systemd(
            intent,
            &mut store,
            Path::new(PRODUCTION_INSTALL_METADATA_PATH),
            Some(temporary.path()),
            &mut RecordingSystemdRunner::default(),
        )
        .expect("committed legacy cleanup retry is idempotent");
    }
}

#[test]
fn committed_replacement_metadata_mismatch_is_zero_effect_and_keeps_the_incomplete_fact() {
    struct Store {
        fact: ReplacementCommitFact,
        writes: usize,
    }
    impl ReplacementCommitStore for Store {
        type Error = ();
        fn load(&mut self) -> Result<Option<ReplacementCommitFact>, Self::Error> {
            Ok(Some(self.fact.clone()))
        }
        fn persist(&mut self, fact: &ReplacementCommitFact) -> Result<(), Self::Error> {
            self.writes += 1;
            self.fact = fact.clone();
            Ok(())
        }
    }

    for mismatch in [
        "metadata-hub",
        "receipt-metadata-hub",
        "source-version",
        "probe-digest",
        "identity-hub",
        "identity-probe",
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let (metadata_path, candidate_bootstrap_state, identity_path, _) =
            fixed_replacement_cleanup_fixture(temporary.path());
        let installed_probe_sha256 = fixed_installed_probe_sha256(
            Path::new(PRODUCTION_PROBE_BINARY_PATH),
            Some(temporary.path()),
        )
        .expect("installed Probe digest");
        let intent = ReplacementIntent {
            enrollment_id: "enr_0123456789abcdef".to_owned(),
            enrollment_token_sha256: "a".repeat(64),
            host_id: "7".to_owned(),
            hub_origin: "https://hub.example".to_owned(),
            old_probe_id: "probe_old_01".to_owned(),
            source_probe_version: "1.2.3".to_owned(),
            source_probe_sha256: installed_probe_sha256,
            target_bundle_target: "x86_64-unknown-linux-gnu".to_owned(),
            target_probe_version: "1.2.4".to_owned(),
            target_asset_set_digest: format!("sha256:{}", "c".repeat(64)),
            target_manifest_sha256: "d".repeat(64),
        };
        let fact = ReplacementCommitFact {
            schema_version: 1,
            canonical_intent_sha256: intent.canonical_sha256().expect("canonical intent"),
            intent: intent.clone(),
            cleanup_complete: mismatch == "receipt-metadata-hub",
            candidate_layout_complete: false,
        };
        match mismatch {
                "metadata-hub" | "receipt-metadata-hub" => fs::write(
                    &metadata_path,
                    fixed_schema_four_metadata_contents()
                        .replace("https://hub.example", "https://other.example"),
                )
                .expect("mismatched metadata Hub"),
                "source-version" => fs::write(
                    &metadata_path,
                    fixed_schema_four_metadata_contents().replace("1.2.3", "1.2.2"),
                )
                .expect("mismatched source version"),
                "probe-digest" => fs::write(
                    preflight_rooted_path(
                        Some(temporary.path()),
                        Path::new(PRODUCTION_PROBE_BINARY_PATH),
                    ),
                    "different Probe",
                )
                .expect("mismatched source Probe"),
                "identity-hub" => fs::write(
                    &identity_path,
                    "hub_url = \"https://other.example\"\nprobe_id = \"probe_old_01\"\nprobe_private_key_pem = \"test-private-key\"\n",
                )
                .expect("mismatched identity Hub"),
                "identity-probe" => fs::write(
                    &identity_path,
                    "hub_url = \"https://hub.example\"\nprobe_id = \"probe_other_01\"\nprobe_private_key_pem = \"test-private-key\"\n",
                )
                .expect("mismatched identity Probe"),
                _ => unreachable!(),
            }
        let mut store = Store { fact, writes: 0 };
        let mut systemd = RecordingSystemdRunner::default();

        let result = commit_replacement_and_cleanup_install_with_systemd(
            intent,
            &mut store,
            Path::new(PRODUCTION_INSTALL_METADATA_PATH),
            Some(temporary.path()),
            &mut systemd,
        );

        assert!(
            matches!(result, Err(ReplacementCommitError::Effect(_))),
            "{mismatch}"
        );
        assert_eq!(store.writes, 0, "{mismatch}");
        assert_eq!(
            store.fact.cleanup_complete,
            mismatch == "receipt-metadata-hub",
            "{mismatch}"
        );
        assert!(systemd.calls.is_empty(), "{mismatch}");
        assert!(metadata_path.exists(), "{mismatch}");
        assert!(identity_path.exists(), "{mismatch}");
        assert!(candidate_bootstrap_state.exists(), "{mismatch}");
    }
}

#[test]
fn exact_incomplete_commit_without_custodied_metadata_fails_closed_without_persisting() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let (metadata_path, candidate_bootstrap_state, identity_path, _) =
        fixed_replacement_cleanup_fixture(temporary.path());
    let token = "enk_enroll_test";
    let intent = ReplacementIntent {
        enrollment_id: "enr_0123456789abcdef".to_owned(),
        enrollment_token_sha256: format!("{:x}", Sha256::digest(token.as_bytes())),
        host_id: "7".to_owned(),
        hub_origin: "https://hub.example".to_owned(),
        old_probe_id: "probe_old_01".to_owned(),
        source_probe_version: "1.2.2".to_owned(),
        source_probe_sha256: "b".repeat(64),
        target_bundle_target: "x86_64-unknown-linux-gnu".to_owned(),
        target_probe_version: "1.2.3".to_owned(),
        target_asset_set_digest: format!("sha256:{}", "c".repeat(64)),
        target_manifest_sha256: "d".repeat(64),
    };
    let commit_path =
        replacement_production_path(PRODUCTION_REPLACEMENT_COMMIT_PATH, Some(temporary.path()));
    let mut store = FileReplacementCommitStore::at(&commit_path, unsafe { libc::geteuid() });
    store
        .persist(&ReplacementCommitFact {
            schema_version: 1,
            canonical_intent_sha256: intent.canonical_sha256().expect("canonical intent"),
            intent: intent.clone(),
            cleanup_complete: false,
            candidate_layout_complete: false,
        })
        .expect("incomplete durable commit");
    fs::remove_file(&metadata_path).expect("legacy metadata-last crash window");
    fs::remove_file(&identity_path).expect("old identity already removed");
    let enrollment_input = format!(
        "{{\"hubOrigin\":\"https://hub.example\",\"enrollmentToken\":\"{token}\",\"replacementMigration\":{{\"enrollmentId\":\"enr_0123456789abcdef\",\"expectedProbeId\":\"probe_old_01\",\"sourceProbeSha256\":[\"{}\"],\"sourceProbeVersion\":\"1.2.2\",\"targetAssetSetDigest\":\"sha256:{}\",\"targetHostId\":\"7\",\"targetProbeVersion\":\"1.2.3\"}},\"schemaVersion\":1}}",
        "b".repeat(64),
        "c".repeat(64),
    );
    let enrollment = enoki_probe_bootstrap::handoff::Enrollment::from_install_input(
        "https://hub.example",
        enrollment_input.as_bytes(),
    )
    .expect("replacement enrollment");
    let request = LifecycleRequest::replacement_migration(
        &enrollment,
        &format!("sha256:{}", "c".repeat(64)),
        "x86_64-unknown-linux-gnu",
        &"d".repeat(64),
        "1.2.3",
    )
    .expect("exact candidate request");

    assert_eq!(
        resume_committed_replacement_from_exact_request(&request, Some(temporary.path())),
        Some(LifecycleResponse::failed(
            "lifecycle.replacement_cleanup_failed"
        ))
    );
    assert!(
        !store.load().unwrap().unwrap().cleanup_complete,
        "exact authority must not fabricate cleanup evidence"
    );
    assert!(candidate_bootstrap_state.exists());

    let wrong = enoki_probe_bootstrap::handoff::Enrollment::from_install_input(
        "https://hub.example",
        enrollment_input
            .replace(token, "enk_enroll_wrong")
            .as_bytes(),
    )
    .expect("wrong replacement enrollment");
    let wrong_request = LifecycleRequest::replacement_migration(
        &wrong,
        &format!("sha256:{}", "c".repeat(64)),
        "x86_64-unknown-linux-gnu",
        &"d".repeat(64),
        "1.2.3",
    )
    .expect("well-formed wrong request");
    assert_eq!(
        resume_committed_replacement_from_exact_request(&wrong_request, Some(temporary.path())),
        Some(LifecycleResponse::failed(
            "lifecycle.replacement_commit_conflict"
        ))
    );

    let wrong_target_request = LifecycleRequest::replacement_migration(
        &enrollment,
        &format!("sha256:{}", "c".repeat(64)),
        "aarch64-unknown-linux-gnu",
        &"d".repeat(64),
        "1.2.3",
    )
    .expect("well-formed wrong-target request");
    assert_eq!(
        resume_committed_replacement_from_exact_request(
            &wrong_target_request,
            Some(temporary.path()),
        ),
        Some(LifecycleResponse::failed(
            "lifecycle.replacement_commit_conflict"
        ))
    );
    assert!(!store.load().unwrap().unwrap().cleanup_complete);
    assert!(candidate_bootstrap_state.exists());
}

#[test]
fn required_systemd_cleanup_rejects_failure_for_a_loaded_service() {
    let mut calls = Vec::new();
    let mut run = |program: &str, args: &[&str]| {
        calls.push(format!("{program} {}", args.join(" ")));
        Ok(match args.first().copied() {
            Some("disable") => {
                CleanupCommandOutput::failure(Some(1), "", "Failed to disable unit: access denied")
            }
            Some("show") => CleanupCommandOutput::success("loaded\n"),
            _ => panic!("unexpected command: {program} {args:?}"),
        })
    };

    let error = run_required_systemctl_cleanup_with(
        &["disable", "enoki-probe"],
        "enoki-probe",
        "probe_uninstall_service_disable_failed",
        "disabling the service",
        &mut run,
    )
    .expect_err("a loaded unit cannot turn disable failure into success");

    assert_eq!(
        probe_upgrader_error_code(&error),
        "probe_uninstall_service_disable_failed"
    );
    assert!(error.to_string().contains("access denied"));
    assert_eq!(
        calls,
        [
            "systemctl disable enoki-probe",
            "systemctl show --property=LoadState --value enoki-probe",
        ]
    );
}

#[test]
fn required_systemd_cleanup_allows_only_an_explicitly_missing_service() {
    let mut calls = Vec::new();
    let mut run = |program: &str, args: &[&str]| {
        calls.push(format!("{program} {}", args.join(" ")));
        Ok(match args.first().copied() {
            Some("disable") => CleanupCommandOutput::failure(Some(1), "", "unit does not exist"),
            Some("show") => CleanupCommandOutput::success("not-found\n"),
            _ => panic!("unexpected command: {program} {args:?}"),
        })
    };

    run_required_systemctl_cleanup_with(
        &["disable", "enoki-probe"],
        "enoki-probe",
        "probe_uninstall_service_disable_failed",
        "disabling the service",
        &mut run,
    )
    .expect("an explicit systemd not-found state is idempotent success");

    assert_eq!(
        calls,
        [
            "systemctl disable enoki-probe",
            "systemctl show --property=LoadState --value enoki-probe",
        ]
    );
}

#[test]
fn systemd_service_absence_check_rejects_loaded_state_and_accepts_not_found() {
    let mut loaded = |_program: &str, _args: &[&str]| Ok(CleanupCommandOutput::success("loaded\n"));
    let error = verify_systemd_service_absent_with("enoki-probe", &mut loaded)
        .expect_err("a loaded service is uninstall residue");
    assert_eq!(
        probe_upgrader_error_code(&error),
        "probe_uninstall_service_residue"
    );

    let mut missing =
        |_program: &str, _args: &[&str]| Ok(CleanupCommandOutput::success("not-found\n"));
    verify_systemd_service_absent_with("enoki-probe", &mut missing)
        .expect("an explicit not-found LoadState is absent");
}

#[test]
fn service_identity_cleanup_fails_closed_when_userdel_fails() {
    let mut calls = Vec::new();
    let mut run = |program: &str, args: &[&str]| {
        calls.push(format!("{program} {}", args.join(" ")));
        Ok(match program {
            "getent" => CleanupCommandOutput::success("enoki-probe:x:999:999"),
            "userdel" => CleanupCommandOutput::failure(Some(1), "", "account is in use"),
            _ => panic!("unexpected command: {program} {args:?}"),
        })
    };

    let error = remove_service_identity_with("enoki-probe", "enoki-probe", &mut run)
        .expect_err("an unexplained userdel failure is fatal");

    assert_eq!(
        probe_upgrader_error_code(&error),
        "probe_uninstall_service_account_remove_failed"
    );
    assert!(error.to_string().contains("account is in use"));
    assert_eq!(calls, ["getent passwd enoki-probe", "userdel enoki-probe"]);
}

#[test]
fn service_identity_cleanup_verifies_account_and_group_are_absent() {
    let mut calls = Vec::new();
    let mut passwd_queries = 0;
    let mut group_queries = 0;
    let mut run = |program: &str, args: &[&str]| {
        calls.push(format!("{program} {}", args.join(" ")));
        Ok(match (program, args.first().copied()) {
            ("getent", Some("passwd")) => {
                passwd_queries += 1;
                if passwd_queries == 1 {
                    CleanupCommandOutput::success("enoki-probe:x:999:999")
                } else {
                    CleanupCommandOutput::failure(Some(2), "", "")
                }
            }
            ("getent", Some("group")) => {
                group_queries += 1;
                if group_queries == 1 {
                    CleanupCommandOutput::success("enoki-probe:x:999:")
                } else {
                    CleanupCommandOutput::failure(Some(2), "", "")
                }
            }
            ("userdel" | "groupdel", _) => CleanupCommandOutput::success(""),
            _ => panic!("unexpected command: {program} {args:?}"),
        })
    };

    remove_service_identity_with("enoki-probe", "enoki-probe", &mut run)
        .expect("both identity entries are deleted and verified absent");

    assert_eq!(
        calls,
        [
            "getent passwd enoki-probe",
            "userdel enoki-probe",
            "getent passwd enoki-probe",
            "getent group enoki-probe",
            "groupdel enoki-probe",
            "getent group enoki-probe",
        ]
    );
}

#[test]
fn service_identity_cleanup_is_idempotent_only_for_explicitly_missing_entries() {
    let mut calls = Vec::new();
    let mut run = |program: &str, args: &[&str]| {
        calls.push(format!("{program} {}", args.join(" ")));
        Ok(CleanupCommandOutput::failure(Some(2), "", ""))
    };

    remove_service_identity_with("enoki-probe", "enoki-probe", &mut run)
        .expect("getent exit code 2 explicitly means the entries are absent");

    assert_eq!(
        calls,
        ["getent passwd enoki-probe", "getent group enoki-probe"]
    );
}

#[test]
fn service_identity_cleanup_rejects_account_residue_after_userdel() {
    let mut run = |program: &str, _args: &[&str]| {
        Ok(match program {
            "getent" => CleanupCommandOutput::success("enoki-probe:x:999:999"),
            "userdel" => CleanupCommandOutput::success(""),
            _ => panic!("unexpected command: {program}"),
        })
    };

    let error = remove_service_identity_with("enoki-probe", "enoki-probe", &mut run)
        .expect_err("an account that remains after userdel is fatal");

    assert_eq!(
        probe_upgrader_error_code(&error),
        "probe_uninstall_service_account_residue"
    );
}

#[test]
fn service_unit_absence_check_rejects_residue_and_accepts_not_found() {
    let temp = tempfile::tempdir().expect("temp dir");
    let service_unit_path = temp.path().join("enoki-probe.service");
    fs::write(&service_unit_path, "unit").expect("service unit");

    let error = verify_path_absent(
        &service_unit_path,
        "probe_uninstall_service_unit_residue",
        "verifying the service unit is absent",
    )
    .expect_err("a remaining unit file is fatal");
    assert_eq!(
        probe_upgrader_error_code(&error),
        "probe_uninstall_service_unit_residue"
    );

    fs::remove_file(&service_unit_path).expect("remove service unit");
    verify_path_absent(
        &service_unit_path,
        "probe_uninstall_service_unit_residue",
        "verifying the service unit is absent",
    )
    .expect("not-found is idempotent success");
}

#[test]
fn lifecycle_ipc_group_cleanup_requires_and_consumes_the_install_receipt() {
    let marker = format!("!enoki-bootstrap-{}", "d".repeat(32));
    let mut calls = Vec::new();
    remove_owned_ipc_group_with(PROBE_IPC_GROUP, &marker, &mut |program, arguments| {
        calls.push(format!("{program} {}", arguments.join(" ")));
        Ok(match (program, arguments) {
            ("getent", ["gshadow", PROBE_IPC_GROUP]) => {
                CleanupCommandOutput::success(&format!("{PROBE_IPC_GROUP}:{marker}::\n"))
            }
            ("getent", ["group", PROBE_IPC_GROUP]) if calls.len() == 2 => {
                CleanupCommandOutput::success("enoki-probe-ipc:x:998:\n")
            }
            ("groupdel", [PROBE_IPC_GROUP]) => CleanupCommandOutput::success(""),
            ("getent", ["group", PROBE_IPC_GROUP]) => {
                CleanupCommandOutput::failure(Some(2), "", "")
            }
            _ => panic!("unexpected cleanup command"),
        })
    })
    .expect("owned lifecycle IPC group is removed");

    assert_eq!(
        calls,
        [
            "getent gshadow enoki-probe-ipc",
            "getent group enoki-probe-ipc",
            "groupdel enoki-probe-ipc",
            "getent group enoki-probe-ipc",
        ]
    );
}

#[test]
fn lifecycle_ipc_group_cleanup_keeps_a_group_without_the_install_receipt() {
    let marker = format!("!enoki-bootstrap-{}", "d".repeat(32));
    let mut calls = Vec::new();
    let error = remove_owned_ipc_group_with(PROBE_IPC_GROUP, &marker, &mut |program, arguments| {
        calls.push(format!("{program} {}", arguments.join(" ")));
        Ok(CleanupCommandOutput::success(
            "enoki-probe-ipc:!enoki-bootstrap-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee::\n",
        ))
    })
    .expect_err("unowned lifecycle IPC group remains untouched");

    assert_eq!(
        probe_upgrader_error_code(&error),
        "probe_uninstall_service_group_residue"
    );
    assert_eq!(calls, ["getent gshadow enoki-probe-ipc"]);
}

#[test]
fn trusted_install_metadata_rejects_unsafe_service_user_for_sudoers() {
    let contents = [
            "hub_url = \"https://hub.example\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "operation_sudoers_path = \"/etc/sudoers.d/enoki-probe-operations\"",
            "collector_helper_sudoers_path = \"/etc/sudoers.d/enoki-probe-collector-helpers\"",
            "service_name = \"enoki-probe\"",
            "service_user = \"enoki-probe\\nALL=(root) NOPASSWD: ALL\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "",
        ]
        .join("\n");

    let error = parse_trusted_probe_install_metadata(&contents)
        .expect_err("unsafe service user is rejected");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidInstallMetadata("service user is not safe for sudoers")
    ));
}

#[test]
fn trusted_install_metadata_rejects_root_paths() {
    let contents = [
            "hub_url = \"https://hub.example\"",
            "install_path = \"/\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "service_name = \"enoki-probe\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "",
        ]
        .join("\n");

    let error = parse_trusted_probe_install_metadata(&contents).expect_err("root path is rejected");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidInstallMetadata("paths must not be filesystem root")
    ));
}

#[test]
fn trusted_install_metadata_rejects_parent_components_before_cleanup_can_start() {
    let value = "path = \"/var/lib/enoki-probe/../outside\""
        .parse::<toml::Value>()
        .expect("metadata value");

    let error = required_install_metadata_path(&value, "path")
        .expect_err("parent traversal cannot become a cleanup target");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidInstallMetadata("paths contain unsafe components")
    ));
}

#[test]
fn trusted_install_metadata_uses_fresh_split_sudoers_paths() {
    let temp = tempfile::tempdir().expect("temp dir");
    let (contents, operation_sudoers_path, collector_helper_sudoers_path, legacy_sudoers_path) =
        fresh_split_install_metadata_contents(temp.path());

    let install_metadata =
        parse_trusted_probe_install_metadata(&contents).expect("fresh metadata parses");

    assert_eq!(
        install_metadata.operation_sudoers_path,
        Some(operation_sudoers_path)
    );
    assert_eq!(
        install_metadata.collector_helper_sudoers_path,
        Some(collector_helper_sudoers_path)
    );
    assert_ne!(
        install_metadata.operation_sudoers_path,
        Some(legacy_sudoers_path)
    );
}

#[test]
fn supported_legacy_install_metadata_migrates_to_version_one_deterministically() {
    let temp = tempfile::tempdir().expect("temp dir");
    let (contents, _, _, _) = fresh_split_install_metadata_contents(temp.path());
    let metadata_path = temp.path().join("etc/enoki/probe-install.toml");
    let legacy_identity_path = temp.path().join("etc/enoki/custom-identity.toml");
    fs::create_dir_all(metadata_path.parent().expect("metadata dir")).expect("metadata dir");
    fs::write(&metadata_path, contents).expect("legacy metadata");
    fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o644))
        .expect("legacy permissions");

    let metadata = read_trusted_probe_install_metadata_with_file_metadata(
        &metadata_path,
        Some(&legacy_identity_path),
        TrustedFileMetadata {
            is_regular_file: true,
            is_symlink: false,
            mode: 0o644,
            owner_uid: 0,
        },
    )
    .expect("supported legacy metadata migrates");

    assert_eq!(metadata.schema_version, 1);
    assert_eq!(metadata.identity_path, legacy_identity_path);
    let migrated = fs::read_to_string(&metadata_path).expect("migrated metadata");
    assert!(migrated.starts_with("schema_version = 1\n"));
    assert!(migrated.contains(&format!(
        "identity_path = {}",
        toml_string(&legacy_identity_path.display().to_string()),
    )));
    assert!(migrated.contains("service_group = \"enoki-probe\""));
    assert!(migrated.contains("service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",));
    assert_eq!(
        fs::metadata(&metadata_path)
            .expect("metadata stat")
            .permissions()
            .mode()
            & 0o777,
        0o600,
    );
}

#[test]
fn legacy_install_metadata_preflight_keeps_bytes_mode_and_mtime_unchanged() {
    let temp = tempfile::tempdir().expect("temp dir");
    let (contents, _, _, _) = fresh_split_install_metadata_contents(temp.path());
    let metadata_path = temp.path().join("etc/enoki/probe-install.toml");
    let identity_path = temp.path().join("etc/enoki/probe-bootstrap.toml");
    fs::create_dir_all(metadata_path.parent().expect("metadata dir")).expect("metadata dir");
    fs::write(&metadata_path, &contents).expect("legacy metadata");
    fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o644))
        .expect("legacy permissions");

    let mut metadata = parse_trusted_probe_install_metadata(&contents).expect("legacy metadata");
    metadata.identity_path = identity_path.clone();
    write_test_bootstrap_config(&identity_path, &metadata).expect("identity");
    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
        .expect("identity permissions");

    let before_bytes = fs::read(&metadata_path).expect("metadata bytes");
    let before_metadata = fs::metadata(&metadata_path).expect("metadata stat");
    let before_mode = before_metadata.permissions().mode() & 0o777;
    let before_mtime = (before_metadata.mtime(), before_metadata.mtime_nsec());

    let preflight = read_trusted_probe_install_preflight(&metadata_path, Some(temp.path()))
        .expect("legacy preflight");

    assert_eq!(preflight.hub_url, "https://hub.example");
    assert_eq!(preflight.probe_id, "probe_01");
    let after_metadata = fs::metadata(&metadata_path).expect("metadata stat");
    assert_eq!(
        fs::read(&metadata_path).expect("metadata bytes"),
        before_bytes
    );
    assert_eq!(after_metadata.permissions().mode() & 0o777, before_mode);
    assert_eq!(
        (after_metadata.mtime(), after_metadata.mtime_nsec()),
        before_mtime
    );
}

#[test]
fn version_one_install_metadata_requires_exact_mode_0600() {
    let temp = tempfile::tempdir().expect("temp dir");
    let metadata_path = temp.path().join("probe-install.toml");
    fs::write(
        &metadata_path,
        version_one_install_metadata_contents(temp.path()),
    )
    .expect("metadata");

    for mode in [0o644, 0o640] {
        let error = read_trusted_probe_install_metadata_with_file_metadata(
            &metadata_path,
            None,
            TrustedFileMetadata {
                is_regular_file: true,
                is_symlink: false,
                mode,
                owner_uid: 0,
            },
        )
        .expect_err("non-0600 v1 metadata is rejected");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata("schema v1 metadata mode must be 0600")
        ));
    }
}

#[test]
fn install_metadata_rejects_symlink_non_regular_and_non_root_files() {
    let temp = tempfile::tempdir().expect("temp dir");
    let metadata_path = temp.path().join("probe-install.toml");
    fs::write(
        &metadata_path,
        version_one_install_metadata_contents(temp.path()),
    )
    .expect("metadata");

    for (file_metadata, expected_message) in [
        (
            TrustedFileMetadata {
                is_regular_file: true,
                is_symlink: true,
                mode: 0o600,
                owner_uid: 0,
            },
            "metadata path must be a regular non-symlink file",
        ),
        (
            TrustedFileMetadata {
                is_regular_file: false,
                is_symlink: false,
                mode: 0o600,
                owner_uid: 0,
            },
            "metadata path must be a regular non-symlink file",
        ),
        (
            TrustedFileMetadata {
                is_regular_file: true,
                is_symlink: false,
                mode: 0o600,
                owner_uid: 1000,
            },
            "metadata file is not owned by root",
        ),
    ] {
        let error = read_trusted_probe_install_metadata_with_file_metadata(
            &metadata_path,
            None,
            file_metadata,
        )
        .expect_err("untrusted metadata file is rejected");

        assert!(matches!(
            &error,
            ProbeUpgraderRunError::InvalidInstallMetadata(message)
                if *message == expected_message
        ));
        assert_eq!(
            ProbeRepairRunError::from(error).code(),
            "probe_repair_metadata_invalid",
        );
    }
}

#[test]
fn legacy_install_metadata_rejects_modes_outside_the_compatibility_allowlist() {
    let temp = tempfile::tempdir().expect("temp dir");
    let metadata_path = temp.path().join("probe-install.toml");
    let (contents, _, _, _) = fresh_split_install_metadata_contents(temp.path());
    fs::write(&metadata_path, contents).expect("legacy metadata");

    let error = read_trusted_probe_install_metadata_with_file_metadata(
        &metadata_path,
        Some(&temp.path().join("probe-bootstrap.toml")),
        TrustedFileMetadata {
            is_regular_file: true,
            is_symlink: false,
            mode: 0o640,
            owner_uid: 0,
        },
    )
    .expect_err("unrecognized legacy metadata mode is rejected");

    assert!(matches!(
        &error,
        ProbeUpgraderRunError::InvalidInstallMetadata("legacy metadata mode is not supported")
    ));
    assert_eq!(
        ProbeRepairRunError::from(error).code(),
        "probe_repair_metadata_invalid",
    );
}

#[cfg(unix)]
#[test]
fn trusted_install_metadata_uses_lstat_and_rejects_a_symlink_path() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("temp dir");
    let target = temp.path().join("target.toml");
    let link = temp.path().join("probe-install.toml");
    fs::write(&target, version_one_install_metadata_contents(temp.path()))
        .expect("metadata target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("metadata mode");
    symlink(&target, &link).expect("metadata symlink");

    let error =
        read_trusted_probe_install_metadata(&link, None).expect_err("metadata symlink is rejected");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidInstallMetadata(
            "metadata path must be a regular non-symlink file"
        )
    ));
}

#[test]
fn install_metadata_rejects_unsupported_schema_version_with_stable_repair_code() {
    let contents = [
        "schema_version = 6",
        "hub_url = \"https://hub.example\"",
        "",
    ]
    .join("\n");

    let error =
        parse_trusted_probe_install_metadata(&contents).expect_err("future metadata fails closed");
    let repair_error = ProbeRepairRunError::from(error);

    assert_eq!(repair_error.code(), "probe_repair_metadata_unsupported");
}

#[test]
fn schema_four_metadata_closes_over_lifecycle_receipts_and_fixed_role_inventory() {
    let contents = fixed_schema_four_metadata_contents();

    let metadata =
        parse_trusted_probe_install_metadata(&contents).expect("schema four metadata is accepted");

    assert_eq!(metadata.schema_version, 4);
    assert_eq!(
        metadata.lifecycle_companion_path.as_deref(),
        Some(Path::new(LIFECYCLE_COMPANION_BINARY_PATH))
    );
    assert_eq!(metadata.observation_unit_paths.len(), 8);
    assert_eq!(metadata.install_state_sha256, Some("b".repeat(64)));
    assert_eq!(metadata.probe_ipc_group.as_deref(), Some(PROBE_IPC_GROUP));

    let schema_five = contents
            .replace("schema_version = 4", "schema_version = 5")
            .replace(
                &format!(
                    "lifecycle_companion_socket_unit_path = \"{LIFECYCLE_COMPANION_SOCKET_UNIT_PATH}\""
                ),
                &format!(
                    "lifecycle_companion_socket_unit_path = \"{LIFECYCLE_COMPANION_SOCKET_UNIT_PATH}\"\nlifecycle_upgrade_service_unit_path = \"{LIFECYCLE_UPGRADE_SERVICE_UNIT_PATH}\"\nlifecycle_upgrade_socket_unit_path = \"{LIFECYCLE_UPGRADE_SOCKET_UNIT_PATH}\""
                ),
            );
    let schema_five = format!(
        "{schema_five}\nlifecycle_authority_install_key = {:?}\n",
        "a".repeat(64),
    );
    let metadata = parse_trusted_probe_install_metadata(&schema_five)
        .expect("schema five metadata closes over the Upgrade Companion units");
    assert_eq!(metadata.schema_version, 5);
    assert_eq!(metadata.observation_unit_paths.len(), 10);
}

#[test]
fn schema_three_and_four_metadata_fix_the_installed_probe_path() {
    for schema_version in [3, 4, 5] {
        let contents = schema_three_install_metadata_contents()
            .replace(
                "schema_version = 3",
                &format!("schema_version = {schema_version}"),
            )
            .replace(
                "install_path = \"/usr/local/bin/enoki-probe\"",
                "install_path = \"/opt/enoki-probe\"",
            );

        let error = parse_trusted_probe_install_metadata(&contents)
            .expect_err("signed install metadata cannot redirect the Probe binary");

        assert!(matches!(
            error,
            ProbeUpgraderRunError::InvalidInstallMetadata(
                "install_path does not match the fixed production path"
            )
        ));
    }
}

#[test]
fn signed_package_metadata_uses_root_trust_without_legacy_sudoers_or_daily_key() {
    let root = "a".repeat(64);
    let contents = [
        "schema_version = 2".to_string(),
        "hub_url = \"https://hub.example\"".to_string(),
        "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"".to_string(),
        "install_path = \"/usr/local/bin/enoki-probe\"".to_string(),
        "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"".to_string(),
        "state_dir = \"/var/lib/enoki-probe\"".to_string(),
        format!("probe_distribution_root_sha256 = \"{root}\""),
        "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"".to_string(),
        "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"".to_string(),
        "bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\"".to_string(),
        "service_name = \"enoki-probe\"".to_string(),
        "service_user = \"enoki-probe\"".to_string(),
        "service_group = \"enoki-probe\"".to_string(),
        "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"".to_string(),
        String::new(),
    ]
    .join("\n");
    let metadata = parse_trusted_probe_install_metadata(&contents).expect("schema v2 parses");
    assert_eq!(metadata.schema_version, 2);
    assert_eq!(
        metadata.probe_distribution_root_sha256.as_deref(),
        Some(root.as_str())
    );
    assert_eq!(metadata.operation_sudoers_path, None);
    assert_eq!(metadata.collector_helper_sudoers_path, None);
    assert_eq!(
        metadata.bootstrap_acquirer_path.as_deref(),
        Some(Path::new(PRODUCTION_BOOTSTRAP_ACQUIRER_PATH))
    );
    assert_eq!(
        metadata.bootstrap_activator_path.as_deref(),
        Some(Path::new(PRODUCTION_BOOTSTRAP_ACTIVATOR_PATH))
    );
    assert_eq!(
        metadata.bootstrap_state_dir.as_deref(),
        Some(Path::new(PRODUCTION_BOOTSTRAP_STATE_DIR))
    );
    assert!(metadata.old_sudoers_paths.is_empty());
    assert!(!contents.contains("sudoers_path"));
    assert!(!contents.contains("probe_asset_public_key_sha256"));
}

#[test]
fn schema_three_metadata_owns_the_complete_observation_role_inventory() {
    let contents = schema_three_install_metadata_contents();

    let metadata = parse_trusted_probe_install_metadata(&contents).unwrap();

    assert_eq!(metadata.schema_version, 3);
    assert_eq!(
        metadata.observation_ipc_group.as_deref(),
        Some(OBSERVATION_IPC_GROUP)
    );
    assert_eq!(
        metadata.observation_runtime_path.as_deref(),
        Some(Path::new(OBSERVATION_RUNTIME_BINARY_PATH))
    );
    assert_eq!(
        metadata.cpu_provider_path.as_deref(),
        Some(Path::new(CPU_PROVIDER_BINARY_PATH))
    );
    assert_eq!(metadata.observation_unit_paths.len(), 4);
    assert_eq!(
        metadata.operation_sudoers_path.as_deref(),
        Some(Path::new(PRODUCTION_OPERATION_SUDOERS_PATH))
    );
}

#[test]
fn signed_package_metadata_requires_all_fixed_bootstrap_owned_paths() {
    let contents = [
            "schema_version = 2",
            "hub_url = \"https://hub.example\"",
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"",
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"",
            "service_name = \"enoki-probe\"",
            "service_user = \"enoki-probe\"",
            "service_group = \"enoki-probe\"",
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
            "",
        ]
        .join("\n");
    assert!(matches!(
        parse_trusted_probe_install_metadata(&contents),
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "missing required field"
        ))
    ));
}

#[test]
fn signed_package_metadata_rejects_legacy_authority_fields() {
    let contents = [
            "schema_version = 2",
            "hub_url = \"https://hub.example\"",
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "service_name = \"enoki-probe\"",
            "service_group = \"enoki-probe\"",
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
            "",
        ].join("\n");
    assert!(matches!(
        parse_trusted_probe_install_metadata(&contents),
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "signed package metadata must not carry legacy sudoers or daily signing trust"
        ))
    ));
}

#[test]
fn signed_package_metadata_rejects_a_nonfixed_bootstrap_role_path() {
    let contents = [
            "schema_version = 2",
            "hub_url = \"https://hub.example\"",
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "bootstrap_acquirer_path = \"/tmp/attacker-bootstrap\"",
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"",
            "bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\"",
            "service_name = \"enoki-probe\"",
            "service_group = \"enoki-probe\"",
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
            "",
        ]
        .join("\n");
    assert!(matches!(
        parse_trusted_probe_install_metadata(&contents),
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap role path is not the fixed production path"
        ))
    ));
}

#[test]
fn legacy_schema_cannot_claim_bootstrap_role_ownership() {
    let mut contents = version_one_install_metadata_contents(Path::new("/"));
    contents
        .push_str("bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"\n");
    assert!(matches!(
        parse_trusted_probe_install_metadata(&contents),
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "legacy metadata must not carry Probe Bootstrap ownership"
        ))
    ));
}

#[test]
fn signed_package_metadata_rejects_a_nonfixed_bootstrap_state_path() {
    let contents = [
            "schema_version = 2",
            "hub_url = \"https://hub.example\"",
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"",
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"",
            "bootstrap_state_dir = \"/tmp/attacker-bootstrap-state\"",
            "service_name = \"enoki-probe\"",
            "service_group = \"enoki-probe\"",
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
            "",
        ]
        .join("\n");
    assert!(matches!(
        parse_trusted_probe_install_metadata(&contents),
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "Probe Bootstrap role path is not the fixed production path"
        ))
    ));
}

#[test]
fn trusted_install_metadata_rejects_old_single_sudoers_path_metadata() {
    let contents = [
            "hub_url = \"https://hub.example\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "sudoers_path = \"/etc/sudoers.d/enoki-probe-upgrader\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "service_name = \"enoki-probe\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "",
        ]
        .join("\n");

    let error =
        parse_trusted_probe_install_metadata(&contents).expect_err("old metadata is rejected");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidInstallMetadata("old sudoers_path metadata is not supported")
    ));
}

#[test]
fn trusted_install_metadata_requires_explicit_split_sudoers_paths() {
    let contents = [
            "hub_url = \"https://hub.example\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "service_name = \"enoki-probe\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "",
        ]
        .join("\n");

    let error = parse_trusted_probe_install_metadata(&contents)
        .expect_err("split sudoers paths are required");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidInstallMetadata("missing required field")
    ));
}

#[test]
fn probe_operation_sudoers_uses_fresh_operation_path_without_legacy_mixed_layout() {
    let temp = tempfile::tempdir().expect("temp dir");
    let (contents, operation_sudoers_path, collector_helper_sudoers_path, legacy_sudoers_path) =
        fresh_split_install_metadata_contents(temp.path());
    let install_metadata =
        parse_trusted_probe_install_metadata(&contents).expect("fresh metadata parses");
    let bootstrap_config_path = temp.path().join("etc/enoki/probe-bootstrap.toml");

    write_probe_operation_sudoers(&install_metadata, &bootstrap_config_path)
        .expect("operation sudoers are written");

    let sudoers = fs::read_to_string(&operation_sudoers_path).expect("operation sudoers");
    assert!(sudoers.contains("internal-upgrader --config"));
    assert!(sudoers.contains("internal-uninstaller --config"));
    assert!(!sudoers.contains("internal-privileged-collector-helper"));
    assert!(!sudoers.contains("disk-health.smartctl"));
    assert!(!legacy_sudoers_path.exists());
    assert!(!collector_helper_sudoers_path.exists());
}

#[test]
fn probe_operation_sudoers_rejects_paths_unsafe_for_sudoers() {
    let temp = tempfile::tempdir().expect("temp dir");
    let unsafe_install_path = temp.path().join("bin/enoki probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let install_metadata = trusted_install_metadata(
        &unsafe_install_path,
        &status_path,
        assets_public_key_sha256(),
    );
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");

    let error = write_probe_operation_sudoers(&install_metadata, &bootstrap_config_path)
        .expect_err("unsafe install path is rejected");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidInstallMetadata("sudoers command contains unsafe values")
    ));
}

#[test]
fn probe_operation_sudoers_rejects_bootstrap_path_unsafe_for_sudoers() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let install_metadata =
        trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
    let unsafe_bootstrap_config_path = temp.path().join("probe bootstrap.toml");

    let error = write_probe_operation_sudoers(&install_metadata, &unsafe_bootstrap_config_path)
        .expect_err("unsafe bootstrap path is rejected");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidInstallMetadata("sudoers command contains unsafe values")
    ));
}

#[test]
fn internal_probe_upgrader_validates_stdin_token_with_hub_before_noop_result() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_private_key_pem = \"test-private-key\"",
            "",
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingValidationTransport::default();

    let mut systemd = RecordingSystemdRunner::default();
    let install_metadata = trusted_install_metadata(
        &temp.path().join("bin/enoki-probe"),
        &temp.path().join("state/probe-operation-status.toml"),
        assets_public_key_sha256(),
    );
    let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
            ProbeUpgraderRunInput {
                bootstrap_config_path: bootstrap_config_path.clone(),
            },
            &[
                "operation_id = \"42\"",
                "target_asset_set_digest = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
                "target_probe_version = \"0.2.0\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
            &mut transport,
            &mut systemd,
            &install_metadata,
        )
        .expect("missing assets are reported as operation failure");

    assert_eq!(
        transport.url,
        "https://hub.example/api/probe/operations/42/token/validate",
    );
    assert_eq!(transport.probe_id, "probe_01");
    assert_eq!(
        transport.body,
        "{\"targetAssetSetDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"targetProbeVersion\":\"0.2.0\",\"token\":\"probe-operation-token\"}",
    );
    assert_eq!(
        result,
        ProbeUpgraderResult {
            error_code: Some("asset_missing".to_string()),
            message: Some("Probe Asset Set archive is missing".to_string()),
            operation_id: "42".to_string(),
            status: "failed".to_string(),
        },
    );
    assert_eq!(
        transport.downloads,
        vec!["https://hub.example/api/probe/assets/manifest.json"],
    );
}

#[test]
fn internal_probe_upgrader_rejects_unsafe_hub_url_before_token_validation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let install_metadata =
        trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example/base\"".to_string(),
            "probe_id = \"probe_01\"".to_string(),
            "probe_private_key_pem = \"test-private-key\"".to_string(),
            String::new(),
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();

    let error = run_probe_upgrader_with_systemd_runner_and_install_metadata(
        ProbeUpgraderRunInput {
            bootstrap_config_path,
        },
        &operation_stdin(),
        &mut transport,
        &mut systemd,
        &install_metadata,
    )
    .expect_err("unsafe Hub URL is rejected");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidConfig("invalid Hub URL")
    ));
    assert_eq!(transport.url, "");
    assert!(transport.downloads.is_empty());
}

#[test]
fn internal_probe_upgrader_rejects_bootstrap_hub_url_mismatch_before_token_validation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let install_metadata =
        trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());
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

    let error = run_probe_upgrader_with_systemd_runner_and_install_metadata(
        ProbeUpgraderRunInput {
            bootstrap_config_path,
        },
        &operation_stdin(),
        &mut transport,
        &mut systemd,
        &install_metadata,
    )
    .expect_err("Hub URL mismatch is rejected before network calls");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidConfig("Hub URL does not match trusted install metadata")
    ));
    assert_eq!(transport.url, "");
    assert_eq!(transport.status_url, "");
    assert!(transport.downloads.is_empty());
}

#[test]
fn internal_probe_upgrader_allows_explicit_non_loopback_http_hub() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let install_path = temp.path().join("bin/enoki-probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let install_metadata = trusted_install_metadata_for_hub(
        "http://192.0.2.20:8787",
        &install_path,
        &status_path,
        assets_public_key_sha256(),
    );
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"http://192.0.2.20:8787\"".to_string(),
            "probe_id = \"probe_01\"".to_string(),
            "probe_private_key_pem = \"test-private-key\"".to_string(),
            String::new(),
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();

    let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
        ProbeUpgraderRunInput {
            bootstrap_config_path,
        },
        &operation_stdin(),
        &mut transport,
        &mut systemd,
        &install_metadata,
    )
    .expect("missing assets are reported as operation failure");

    assert_eq!(
        transport.url,
        "http://192.0.2.20:8787/api/probe/operations/42/token/validate",
    );
    assert_eq!(
        transport.downloads,
        vec!["http://192.0.2.20:8787/api/probe/assets/manifest.json"],
    );
    assert_eq!(result.error_code.as_deref(), Some("asset_missing"));
}

#[test]
fn formats_probe_upgrader_running_result_for_probe_runtime() {
    let result = ProbeUpgraderResult {
        error_code: None,
        message: None,
        operation_id: "42".to_string(),
        status: "running".to_string(),
    };

    assert_eq!(
        parse_probe_upgrader_result(&format_probe_upgrader_result(&result)),
        Some(result),
    );
}

#[test]
fn internal_probe_upgrader_verifies_assets_replaces_binary_writes_status_and_restarts() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let state_dir = temp.path().join("state");
    let status_path = state_dir.join("probe-operation-status.toml");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let assets = signed_assets("0.2.0", &replacement_probe_binary("new probe"), None);
    let install_metadata = trusted_install_metadata_for_hub(
        "https://hub.example",
        &install_path,
        &status_path,
        assets.public_key_sha256.clone(),
    );
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"".to_string(),
            "probe_id = \"probe_01\"".to_string(),
            "probe_private_key_pem = \"test-private-key\"".to_string(),
            format!(
                "state_dir = {}",
                toml_string(state_dir.to_str().expect("state dir"))
            ),
            format!(
                "operation_status_path = {}",
                toml_string(status_path.to_str().expect("status path")),
            ),
            format!(
                "install_path = {}",
                toml_string(install_path.to_str().expect("install path")),
            ),
            "service_name = \"enoki-probe\"".to_string(),
            format!(
                "probe_asset_public_key_sha256 = \"{}\"",
                assets.public_key_sha256,
            ),
            String::new(),
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingValidationTransport {
        assets: assets.for_hub("https://hub.example"),
        ..RecordingValidationTransport::default()
    };
    let mut systemd = RecordingSystemdRunner::default();

    let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
        ProbeUpgraderRunInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
        },
        &operation_stdin_for_assets(&assets),
        &mut transport,
        &mut systemd,
        &install_metadata,
    )
    .expect("upgrade succeeds");

    assert_eq!(
        result,
        ProbeUpgraderResult {
            error_code: None,
            message: None,
            operation_id: "42".to_string(),
            status: "running".to_string(),
        },
    );
    assert!(
        fs::read_to_string(&install_path)
            .expect("binary")
            .contains("new probe")
    );
    assert_eq!(systemd.restarted, vec!["enoki-probe"]);
    assert_eq!(
        fs::read_to_string(&status_path).expect("status"),
        [
            "operation_id = \"42\"",
            "target_probe_version = \"0.2.0\"",
            "status = \"running\"",
            "",
        ]
        .join("\n"),
    );
    assert_eq!(
        transport.downloads,
        vec![
            "https://hub.example/api/probe/assets/manifest.json",
            "https://hub.example/api/probe/assets/manifest.json.sig",
            "https://hub.example/api/probe/assets/signing-key.pem",
            &format!(
                "https://hub.example/api/probe/assets/enoki-probe-{}.tar.gz",
                host_probe_asset_target().expect("supported test architecture"),
            ),
        ],
    );
    let bootstrap_config =
        fs::read_to_string(bootstrap_config_path).expect("bootstrap config remains");
    assert!(bootstrap_config.contains("probe_id = \"probe_01\""));
}

#[test]
fn internal_probe_upgrader_removes_the_retired_collector_helper_sudoers() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let planner_log_path = temp.path().join("planner.log");
    let replacement_probe = format!(
        r#"#!/bin/sh
if [ "${{1:-}}" = "internal-render-collector-helper-sudoers" ]; then
  printf '%s\n' "$*" > '{}'
  cat <<'EOF'
# Managed by replacement Probe.
enoki-probe ALL=(root) NOPASSWD: replacement-helper-from-new-binary
EOF
  exit 0
fi
echo replacement probe
"#,
        planner_log_path.display(),
    );
    let assets = signed_assets("0.2.0", &replacement_probe, None);
    let mut install_metadata = trusted_install_metadata(
        &install_path,
        &status_path,
        assets.public_key_sha256.clone(),
    );
    let old_sudoers_path = temp.path().join("etc/sudoers.d/enoki-probe-upgrader");
    fs::create_dir_all(old_sudoers_path.parent().expect("old sudoers parent"))
        .expect("old sudoers parent");
    fs::write(&old_sudoers_path, "old mixed sudoers").expect("old sudoers");
    fs::create_dir_all(
        install_metadata
            .operation_sudoers_path
            .as_ref()
            .expect("legacy sudoers")
            .parent()
            .expect("operation sudoers parent"),
    )
    .expect("operation sudoers parent");
    fs::write(
        install_metadata
            .operation_sudoers_path
            .as_ref()
            .expect("legacy sudoers"),
        "stale operation sudoers",
    )
    .expect("stale operation sudoers");
    install_metadata.old_sudoers_paths = vec![old_sudoers_path.clone()];
    write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
        .expect("write bootstrap config");
    let bootstrap_config =
        read_upgrader_bootstrap_config(&bootstrap_config_path).expect("bootstrap config");
    let operation = ProbeUpgraderOperationMetadata {
        operation_id: "42".to_string(),
        target_asset_set_digest: format!("sha256:{}", hex_sha256(&assets.manifest)),
        target_probe_version: "0.2.0".to_string(),
        token: "probe-operation-token".to_string(),
    };
    let mut transport = RecordingValidationTransport {
        assets: assets.for_hub("https://hub.example"),
        ..RecordingValidationTransport::default()
    };
    let mut systemd = RecordingSystemdRunner::default();

    execute_probe_upgrade_with_current_version(
        &operation,
        &bootstrap_config,
        &bootstrap_config_path,
        &install_metadata,
        &mut transport,
        &mut systemd,
        "0.1.9",
    )
    .expect("upgrade succeeds");

    let operation_sudoers = fs::read_to_string(
        install_metadata
            .operation_sudoers_path
            .as_ref()
            .expect("legacy sudoers"),
    )
    .expect("operation sudoers");
    assert!(operation_sudoers.contains("internal-upgrader --config"));
    assert!(operation_sudoers.contains("internal-uninstaller --config"));
    assert!(!operation_sudoers.contains("internal-privileged-collector-helper"));
    assert!(
        !install_metadata
            .collector_helper_sudoers_path
            .as_ref()
            .expect("legacy sudoers")
            .exists()
    );
    assert!(!planner_log_path.exists());
    assert!(!old_sudoers_path.exists());
    assert_eq!(systemd.restarted, vec!["enoki-probe".to_string()]);
}

#[test]
fn internal_probe_upgrader_deletes_collector_helper_sudoers_when_no_helper_is_exposed() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let assets = signed_assets(
        "0.2.0",
        r#"#!/bin/sh
if [ "${1:-}" = "internal-render-collector-helper-sudoers" ]; then
  exit 0
fi
echo replacement probe
"#,
        None,
    );
    let install_metadata = trusted_install_metadata(
        &install_path,
        &status_path,
        assets.public_key_sha256.clone(),
    );
    fs::create_dir_all(
        install_metadata
            .collector_helper_sudoers_path
            .as_ref()
            .expect("legacy sudoers")
            .parent()
            .expect("collector-helper sudoers parent"),
    )
    .expect("collector-helper sudoers parent");
    fs::write(
        install_metadata
            .collector_helper_sudoers_path
            .as_ref()
            .expect("legacy sudoers"),
        "stale collector helper sudoers",
    )
    .expect("stale collector-helper sudoers");
    write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
        .expect("write bootstrap config");
    let bootstrap_config =
        read_upgrader_bootstrap_config(&bootstrap_config_path).expect("bootstrap config");
    let operation = ProbeUpgraderOperationMetadata {
        operation_id: "42".to_string(),
        target_asset_set_digest: format!("sha256:{}", hex_sha256(&assets.manifest)),
        target_probe_version: "0.2.0".to_string(),
        token: "probe-operation-token".to_string(),
    };
    let mut transport = RecordingValidationTransport {
        assets: assets.for_hub("https://hub.example"),
        ..RecordingValidationTransport::default()
    };
    let mut systemd = RecordingSystemdRunner::default();

    execute_probe_upgrade_with_current_version(
        &operation,
        &bootstrap_config,
        &bootstrap_config_path,
        &install_metadata,
        &mut transport,
        &mut systemd,
        "0.1.9",
    )
    .expect("upgrade succeeds");

    let operation_sudoers = fs::read_to_string(
        install_metadata
            .operation_sudoers_path
            .as_ref()
            .expect("legacy sudoers"),
    )
    .expect("operation sudoers");
    assert!(operation_sudoers.contains("internal-upgrader --config"));
    assert!(operation_sudoers.contains("internal-uninstaller --config"));
    assert!(!operation_sudoers.contains("internal-privileged-collector-helper"));
    assert!(
        !install_metadata
            .collector_helper_sudoers_path
            .as_ref()
            .expect("legacy sudoers")
            .exists()
    );
    assert_eq!(systemd.restarted, vec!["enoki-probe".to_string()]);
}

#[test]
fn internal_probe_upgrader_rejects_checksum_mismatch_before_replacement() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let assets = signed_assets("0.2.0", "new probe", Some("0".repeat(64)));
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let install_metadata = trusted_install_metadata(
        &install_path,
        &status_path,
        assets.public_key_sha256.clone(),
    );
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"".to_string(),
            "probe_id = \"probe_01\"".to_string(),
            "probe_private_key_pem = \"test-private-key\"".to_string(),
            format!(
                "state_dir = {}",
                toml_string(temp.path().join("state").to_str().expect("state dir")),
            ),
            format!(
                "install_path = {}",
                toml_string(install_path.to_str().expect("install path")),
            ),
            format!(
                "probe_asset_public_key_sha256 = \"{}\"",
                assets.public_key_sha256,
            ),
            String::new(),
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingValidationTransport {
        assets: assets.for_hub("https://hub.example"),
        ..RecordingValidationTransport::default()
    };
    let mut systemd = RecordingSystemdRunner::default();

    let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
        ProbeUpgraderRunInput {
            bootstrap_config_path,
        },
        &operation_stdin_for_assets(&assets),
        &mut transport,
        &mut systemd,
        &install_metadata,
    )
    .expect("checksum mismatch is reported as operation failure");

    assert_eq!(
        result,
        ProbeUpgraderResult {
            error_code: Some("checksum_failure".to_string()),
            message: Some("Probe archive sha256 verification failed".to_string()),
            operation_id: "42".to_string(),
            status: "failed".to_string(),
        },
    );
    assert_eq!(
        fs::read_to_string(&install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn internal_probe_upgrader_rejects_untrusted_signing_key() {
    let (result, install_path, systemd) =
        run_upgrade_with_assets(signed_assets("0.2.0", "new probe", None), "0".repeat(64));

    assert_eq!(result.error_code.as_deref(), Some("signing_key_untrusted"));
    assert_eq!(
        result.message.as_deref(),
        Some("Probe asset signing key fingerprint verification failed"),
    );
    assert_eq!(
        fs::read_to_string(install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn internal_probe_upgrader_rejects_manifest_signature_failure() {
    let mut assets = signed_assets("0.2.0", "new probe", None);
    assets.signature[0] ^= 0xff;
    let public_key_sha256 = assets.public_key_sha256.clone();
    let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

    assert_eq!(result.error_code.as_deref(), Some("signature_failure"));
    assert_eq!(
        fs::read_to_string(install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn internal_probe_upgrader_rejects_target_version_mismatch() {
    let assets = signed_assets("0.3.0", "new probe", None);
    let public_key_sha256 = assets.public_key_sha256.clone();
    let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

    assert_eq!(result.error_code.as_deref(), Some("target_mismatch"));
    assert_eq!(
        fs::read_to_string(install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn internal_probe_upgrader_rejects_signed_downgrade_asset_before_replacement() {
    let assets = signed_assets("0.1.9", "downgraded probe", None);
    let public_key_sha256 = assets.public_key_sha256.clone();
    let (result, install_path, systemd) = run_upgrade_with_assets_and_current_version(
        assets,
        public_key_sha256,
        "0.2.0",
        "0.1.9",
        None,
    );

    assert!(matches!(
        result,
        Err(ProbeUpgraderRunError::DowngradeRejected)
    ));
    assert_eq!(
        fs::read_to_string(install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn internal_probe_upgrader_rejects_signed_same_version_replay_before_replacement() {
    let assets = signed_assets("0.2.0", "replayed probe", None);
    let public_key_sha256 = assets.public_key_sha256.clone();
    let (result, install_path, systemd) = run_upgrade_with_assets_and_current_version(
        assets,
        public_key_sha256,
        "0.2.0",
        "0.2.0",
        None,
    );

    assert!(matches!(
        result,
        Err(ProbeUpgraderRunError::DowngradeRejected)
    ));
    assert_eq!(
        fs::read_to_string(install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn internal_probe_upgrader_accepts_signed_newer_asset_with_local_version_guard() {
    let assets = signed_assets("0.2.0", &replacement_probe_binary("new probe"), None);
    let public_key_sha256 = assets.public_key_sha256.clone();
    let (result, install_path, systemd) = run_upgrade_with_assets_and_current_version(
        assets,
        public_key_sha256,
        "0.1.9",
        "0.2.0",
        None,
    );

    assert!(result.is_ok());
    assert!(
        fs::read_to_string(install_path)
            .expect("binary")
            .contains("new probe")
    );
    assert_eq!(systemd.restarted, vec!["enoki-probe".to_string()]);
}

#[test]
fn internal_probe_upgrader_rejects_a_different_asset_set_at_the_same_version() {
    let assets = signed_assets("0.2.0", &replacement_probe_binary("new probe"), None);
    let public_key_sha256 = assets.public_key_sha256.clone();
    let (result, install_path, systemd) = run_upgrade_with_assets_and_current_version(
        assets,
        public_key_sha256,
        "0.1.9",
        "0.2.0",
        Some(&format!("sha256:{}", "b".repeat(64))),
    );

    assert!(matches!(result, Err(ProbeUpgraderRunError::TargetMismatch)));
    assert_eq!(
        fs::read_to_string(install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn internal_probe_upgrader_accepts_tag_prefixed_manifest_version() {
    let assets = signed_assets("v0.2.0", &replacement_probe_binary("new probe"), None);
    let public_key_sha256 = assets.public_key_sha256.clone();
    let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

    assert_eq!(result.error_code, None);
    assert!(
        fs::read_to_string(install_path)
            .expect("binary")
            .contains("new probe")
    );
    assert_eq!(systemd.restarted, vec!["enoki-probe".to_string()]);
}

#[test]
fn internal_probe_upgrader_rejects_missing_architecture_asset() {
    let assets = signed_assets_for_target(
        "0.2.0",
        "new probe",
        None,
        "i686-unknown-linux-gnu",
        "enoki-probe-i686-unknown-linux-gnu.tar.gz",
    );
    let public_key_sha256 = assets.public_key_sha256.clone();
    let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

    assert_eq!(result.error_code.as_deref(), Some("architecture_missing"));
    assert_eq!(
        fs::read_to_string(install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn internal_probe_upgrader_rejects_missing_asset_download() {
    let assets = signed_assets("0.2.0", &replacement_probe_binary("new probe"), None);
    let public_key_sha256 = assets.public_key_sha256.clone();
    let archive_file = assets.archive_file.clone();
    let (result, install_path, systemd) =
        run_upgrade_with_assets_filtering(assets, public_key_sha256, |url| {
            !url.ends_with(&archive_file)
        });

    assert_eq!(result.error_code.as_deref(), Some("asset_missing"));
    assert_eq!(
        fs::read_to_string(install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn internal_probe_upgrader_rejects_unsafe_asset_filename() {
    let assets = signed_assets_for_target(
        "0.2.0",
        "new probe",
        None,
        host_probe_asset_target().expect("supported test architecture"),
        "../enoki-probe.tar.gz",
    );
    let public_key_sha256 = assets.public_key_sha256.clone();
    let (result, install_path, systemd) = run_upgrade_with_assets(assets, public_key_sha256);

    assert_eq!(result.error_code.as_deref(), Some("asset_missing"));
    assert_eq!(
        fs::read_to_string(install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn internal_probe_upgrader_reports_post_replacement_restart_failure() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let assets = signed_assets("0.2.0", &replacement_probe_binary("new probe"), None);
    let install_metadata = trusted_install_metadata(
        &install_path,
        &status_path,
        assets.public_key_sha256.clone(),
    );
    write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
        .expect("write bootstrap config");
    let mut transport = RecordingValidationTransport {
        assets: assets.for_hub("https://hub.example"),
        ..RecordingValidationTransport::default()
    };
    let mut systemd = RecordingSystemdRunner {
        failure: Some("systemd refused restart".to_string()),
        ..RecordingSystemdRunner::default()
    };

    let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
        ProbeUpgraderRunInput {
            bootstrap_config_path,
        },
        &operation_stdin_for_assets(&assets),
        &mut transport,
        &mut systemd,
        &install_metadata,
    )
    .expect("restart failure is reported as operation failure");

    assert!(
        fs::read_to_string(&install_path)
            .expect("binary")
            .contains("new probe")
    );
    assert_eq!(
        result.error_code.as_deref(),
        Some("post_replacement_restart_failure"),
    );
    assert!(
        result
            .message
            .as_deref()
            .expect("message")
            .contains("Probe binary was replaced")
    );
    assert_eq!(
        transport.status_url,
        "https://hub.example/api/probe/operations/42/status",
    );
    assert!(
        transport
            .status_body
            .contains("\"errorCode\":\"post_replacement_restart_failure\"")
    );
    assert!(transport.status_body.contains("\"status\":\"failed\""));
    assert_eq!(
            fs::read_to_string(status_path).expect("status"),
            [
                "operation_id = \"42\"",
                "target_probe_version = \"0.2.0\"",
                "status = \"failed\"",
                "error_code = \"post_replacement_restart_failure\"",
                "message = \"Probe binary was replaced, but restarting the Probe service failed: failed to restart Probe service: systemd refused restart\"",
                "",
            ]
            .join("\n"),
        );
}

#[cfg(unix)]
#[test]
fn local_operation_status_preflight_rejects_existing_status_symlink() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    fs::create_dir_all(status_path.parent().expect("status dir")).expect("status dir");
    let target_path = temp.path().join("attacker-target.toml");
    fs::write(&target_path, "target").expect("target");
    symlink(&target_path, &status_path).expect("status symlink");
    let install_metadata =
        trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());

    let error = preflight_local_operation_status_writable(&install_metadata)
        .expect_err("status symlink is rejected");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidInstallMetadata(
            "operation status path must not be a symlink"
        )
    ));
    assert_eq!(fs::read_to_string(target_path).expect("target"), "target");
}

#[cfg(unix)]
#[test]
fn local_operation_status_preflight_rejects_group_writable_status_parent() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    let status_dir = temp.path().join("state");
    let status_path = status_dir.join("probe-operation-status.toml");
    fs::create_dir_all(&status_dir).expect("status dir");
    fs::set_permissions(&status_dir, fs::Permissions::from_mode(0o775)).expect("status dir perms");
    let install_metadata =
        trusted_install_metadata(&install_path, &status_path, assets_public_key_sha256());

    let error = preflight_local_operation_status_writable(&install_metadata)
        .expect_err("writable status parent is rejected");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidInstallMetadata(
            "operation status parent must not be writable by group or other"
        )
    ));
    assert!(!status_path.exists());
}

#[test]
fn internal_probe_upgrader_rejects_bootstrap_privileged_field_mismatch() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let assets = signed_assets("0.2.0", "new probe", None);
    let install_metadata = trusted_install_metadata(
        &install_path,
        &status_path,
        assets.public_key_sha256.clone(),
    );
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"".to_string(),
            "probe_id = \"probe_01\"".to_string(),
            "probe_private_key_pem = \"test-private-key\"".to_string(),
            "install_path = \"/tmp/attacker-controlled-probe\"".to_string(),
            format!(
                "probe_asset_public_key_sha256 = \"{}\"",
                assets.public_key_sha256,
            ),
            String::new(),
        ]
        .join("\n"),
    )
    .expect("write bootstrap config");
    let mut transport = RecordingValidationTransport {
        assets: assets.for_hub("https://hub.example"),
        ..RecordingValidationTransport::default()
    };
    let mut systemd = RecordingSystemdRunner::default();

    let error = run_probe_upgrader_with_systemd_runner_and_install_metadata(
        ProbeUpgraderRunInput {
            bootstrap_config_path,
        },
        &operation_stdin_for_assets(&assets),
        &mut transport,
        &mut systemd,
        &install_metadata,
    )
    .expect_err("mismatch is rejected before network calls");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::InvalidConfig(
            "install path does not match trusted install metadata"
        )
    ));
    assert_eq!(transport.url, "");
    assert!(transport.downloads.is_empty());
    assert_eq!(
        fs::read_to_string(&install_path).expect("binary"),
        "old probe"
    );
    assert!(systemd.restarted.is_empty());
}

#[test]
fn probe_asset_target_supports_only_x86_64_and_aarch64() {
    assert_eq!(
        probe_asset_target_for_arch_and_abi("x86_64", LinuxAbi::Musl).expect("x86 target"),
        "x86_64-unknown-linux-musl",
    );
    assert_eq!(
        probe_asset_target_for_arch_and_abi("aarch64", LinuxAbi::Musl).expect("aarch64 target"),
        "aarch64-unknown-linux-musl",
    );
    assert_eq!(
        probe_asset_target_for_arch_and_abi("x86_64", LinuxAbi::Gnu).expect("x86 target"),
        "x86_64-unknown-linux-gnu",
    );
    assert_eq!(
        probe_asset_target_for_arch_and_abi("aarch64", LinuxAbi::Gnu).expect("aarch64 target"),
        "aarch64-unknown-linux-gnu",
    );
    assert!(matches!(
        probe_asset_target_for_arch_and_abi("riscv64", LinuxAbi::Gnu),
        Err(ProbeUpgraderRunError::UnsupportedArchitecture(architecture))
            if architecture == "riscv64"
    ));
}

#[test]
fn probe_archive_rejects_path_traversal_entry() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let archive = archive_with_entry("../enoki-probe", tar::EntryType::Regular);

    let error = replace_installed_probe_binary(&archive, &install_path)
        .expect_err("path traversal is rejected");

    assert!(matches!(error, ProbeUpgraderRunError::UnsafeArchive(_)));
    assert_eq!(
        fs::read_to_string(&install_path).expect("binary"),
        "old probe"
    );
}

#[test]
fn probe_archive_rejects_symlink_entry() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let archive = archive_with_entry("enoki-probe", tar::EntryType::Symlink);

    let error =
        replace_installed_probe_binary(&archive, &install_path).expect_err("symlink is rejected");

    assert!(matches!(error, ProbeUpgraderRunError::UnsafeArchive(_)));
    assert_eq!(
        fs::read_to_string(&install_path).expect("binary"),
        "old probe"
    );
}

#[test]
fn probe_archive_rejects_hardlink_entry() {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let archive = archive_with_entry("enoki-probe", tar::EntryType::Link);

    let error =
        replace_installed_probe_binary(&archive, &install_path).expect_err("hardlink is rejected");

    assert!(matches!(error, ProbeUpgraderRunError::UnsafeArchive(_)));
    assert_eq!(
        fs::read_to_string(&install_path).expect("binary"),
        "old probe"
    );
}

struct SignedAssets {
    archive_file: String,
    archive: Vec<u8>,
    manifest: Vec<u8>,
    public_key: Vec<u8>,
    public_key_sha256: String,
    signature: Vec<u8>,
}

impl SignedAssets {
    fn for_hub(&self, hub_url: &str) -> HashMap<String, Vec<u8>> {
        HashMap::from([
            (
                format!("{hub_url}/api/probe/assets/manifest.json"),
                self.manifest.clone(),
            ),
            (
                format!("{hub_url}/api/probe/assets/manifest.json.sig"),
                self.signature.clone(),
            ),
            (
                format!("{hub_url}/api/probe/assets/signing-key.pem"),
                self.public_key.clone(),
            ),
            (
                format!("{hub_url}/api/probe/assets/{}", self.archive_file),
                self.archive.clone(),
            ),
        ])
    }
}

fn signed_assets(
    version: &str,
    binary_contents: &str,
    sha256_override: Option<String>,
) -> SignedAssets {
    let target = host_probe_asset_target().expect("supported test architecture");
    signed_assets_for_target(
        version,
        binary_contents,
        sha256_override,
        target,
        &format!("enoki-probe-{target}.tar.gz"),
    )
}

fn replacement_probe_binary(label: &str) -> String {
    format!(
        r#"#!/bin/sh
if [ "${{1:-}}" = "internal-render-collector-helper-sudoers" ]; then
  exit 0
fi
printf '%s\n' '{}'
"#,
        label,
    )
}

fn signed_assets_for_target(
    version: &str,
    binary_contents: &str,
    sha256_override: Option<String>,
    target: &str,
    archive_file: &str,
) -> SignedAssets {
    let archive = archive_with_probe_binary(binary_contents);
    let sha256 = sha256_override.unwrap_or_else(|| hex_sha256(&archive));
    let manifest = format!(
            "{{\"assets\":[{{\"file\":\"{}\",\"sha256\":\"{}\",\"size\":{},\"target\":\"{}\"}}],\"kind\":\"enoki-probe-assets\",\"signature\":{{\"algorithm\":\"rsa-sha256\",\"file\":\"manifest.json.sig\",\"publicKey\":\"signing-key.pem\"}},\"version\":\"{}\"}}\n",
            archive_file,
            sha256,
            archive.len(),
            target,
            version,
        )
        .into_bytes();
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("private key");
    let public_key = private_key
        .to_public_key()
        .to_public_key_pem(Default::default())
        .expect("public key")
        .into_bytes();
    let signature = SigningKey::<Sha256>::new(private_key)
        .sign_with_rng(&mut rng, &manifest)
        .to_vec();
    let public_key_sha256 = hex_sha256(&public_key);

    SignedAssets {
        archive_file: archive_file.to_string(),
        archive,
        manifest,
        public_key,
        public_key_sha256,
        signature,
    }
}

struct CompleteBundleAssets {
    archive_file: String,
    files: HashMap<String, Vec<u8>>,
    manifest: Vec<u8>,
    root_fingerprint: String,
    target_units: Vec<Vec<u8>>,
}

fn complete_bundle_assets(version: &str) -> CompleteBundleAssets {
    let target = host_probe_asset_target().expect("supported test target");
    let mut rng = OsRng;
    let root = RsaPrivateKey::new(&mut rng, 2048).expect("root key");
    let daily = RsaPrivateKey::new(&mut rng, 2048).expect("daily key");
    let root_pem = root
        .to_public_key()
        .to_public_key_pem(Default::default())
        .expect("root PEM")
        .into_bytes();
    let daily_pem = daily
        .to_public_key()
        .to_public_key_pem(Default::default())
        .expect("daily PEM")
        .into_bytes();
    let probe = b"new probe".to_vec();
    let runtime = b"new runtime".to_vec();
    let provider = b"new provider".to_vec();
    let disk_health_provider = b"new disk health provider".to_vec();
    let lifecycle_companion = b"new lifecycle companion".to_vec();
    let acquirer = b"acquirer".to_vec();
    let target_units = enoki_probe_bootstrap::install::fixed_observation_unit_contents()
        .into_iter()
        .take(6)
        .map(|mut unit| {
            unit.extend_from_slice(b"# target-version-integration\n");
            unit
        })
        .collect::<Vec<_>>();
    let mut integration = b"enoki.observation-integration.v1\n".to_vec();
    for unit in &target_units {
        integration.extend_from_slice(unit.len().to_string().as_bytes());
        integration.push(b'\n');
        integration.extend_from_slice(unit);
    }
    let quoted = String::from_utf8(integration)
        .expect("integration UTF-8")
        .replace('\'', "'\\''");
    let activator = format!(
            "#!/bin/sh\n[ \"${{1:-}}\" = \"--render-observation-integration-v1\" ] || exit 64\nprintf '%s' '{quoted}'\n"
        )
        .into_bytes();
    let bundle_manifest = format!(
            "{{\"bootstrapAssets\":[{{\"path\":\"bootstrap/enoki-probe-bootstrap-acquire\",\"permissionProfile\":\"bootstrap-acquirer-v1\",\"role\":\"bootstrap-acquirer\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}},{{\"path\":\"bootstrap/enoki-probe-bootstrap-activate\",\"permissionProfile\":\"bootstrap-activator-v1\",\"role\":\"bootstrap-activator\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}}],\"components\":[{{\"path\":\"enoki-probe\",\"permissionProfile\":\"probe-v5\",\"resourceContract\":\"hub-reporting-v1\",\"role\":\"probe\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}},{{\"path\":\"enoki-observation-runtime\",\"permissionProfile\":\"observation-runtime-v4\",\"resourceContract\":\"official-observation-v2\",\"role\":\"observation-runtime\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}},{{\"path\":\"enoki-cpu-resource-provider\",\"permissionProfile\":\"system-state-provider-v5\",\"resourceContract\":\"system-state-v3\",\"role\":\"system-state-provider\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}},{{\"path\":\"enoki-disk-health-resource-provider\",\"permissionProfile\":\"disk-health-provider-v3\",\"resourceContract\":\"disk-health-v1\",\"role\":\"disk-health-provider\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}},{{\"path\":\"enoki-probe-lifecycle-companion\",\"permissionProfile\":\"lifecycle-companion-v3\",\"resourceContract\":\"local-lifecycle-v1\",\"role\":\"lifecycle-companion\",\"sha256\":\"{}\",\"size\":{},\"version\":\"{version}\"}}],\"kind\":\"enoki-probe-bundle\",\"target\":\"{target}\",\"version\":\"{version}\"}}\n",
            hex_sha256(&acquirer),
            acquirer.len(),
            hex_sha256(&activator),
            activator.len(),
            hex_sha256(&probe),
            probe.len(),
            hex_sha256(&runtime),
            runtime.len(),
            hex_sha256(&provider),
            provider.len(),
            hex_sha256(&disk_health_provider),
            disk_health_provider.len(),
            hex_sha256(&lifecycle_companion),
            lifecycle_companion.len(),
        )
        .into_bytes();
    let gzip = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive_builder = tar::Builder::new(gzip);
    for (name, bytes) in [
        ("bundle-manifest.json", bundle_manifest.clone()),
        ("enoki-probe", probe),
        ("enoki-observation-runtime", runtime),
        ("enoki-cpu-resource-provider", provider),
        ("enoki-disk-health-resource-provider", disk_health_provider),
        ("enoki-probe-lifecycle-companion", lifecycle_companion),
        ("bootstrap/enoki-probe-bootstrap-acquire", acquirer),
        ("bootstrap/enoki-probe-bootstrap-activate", activator),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        archive_builder
            .append_data(&mut header, name, bytes.as_slice())
            .expect("archive entry");
    }
    let archive = archive_builder
        .into_inner()
        .expect("gzip")
        .finish()
        .expect("archive");
    let root_id = hex_sha256(&root_pem);
    let daily_id = hex_sha256(&daily_pem);
    let daily_pem_json =
        serde_json::to_string(std::str::from_utf8(&daily_pem).expect("daily PEM UTF-8"))
            .expect("daily PEM JSON");
    let delegation = format!(
            "{{\"distribution\":\"enoki\",\"generation\":1,\"kind\":\"enoki-probe-trust-delegation\",\"purpose\":\"probe-asset-signing\",\"rootKeyId\":\"{root_id}\",\"schemaVersion\":1,\"signingIdentity\":{{\"algorithm\":\"rsa-sha256\",\"keyId\":\"{daily_id}\",\"publicKeyPem\":{daily_pem_json}}}}}\n"
        )
        .into_bytes();
    let mut delegation_input = b"enoki/probe-trust-delegation/v1\0".to_vec();
    delegation_input.extend_from_slice(&delegation);
    let delegation_signature = SigningKey::<Sha256>::new(root)
        .sign_with_rng(&mut rng, &delegation_input)
        .to_vec();
    let archive_file = format!("enoki-probe-{target}.tar.gz");
    let manifest = format!(
            "{{\"assets\":[{{\"bundleManifestSha256\":\"{}\",\"file\":\"{archive_file}\",\"sha256\":\"{}\",\"size\":{},\"target\":\"{target}\"}}],\"kind\":\"enoki-probe-assets\",\"signature\":{{\"algorithm\":\"rsa-sha256\",\"delegationGeneration\":1,\"delegationKeyId\":\"{daily_id}\",\"file\":\"manifest.json.sig\",\"publicKey\":\"signing-key.pem\"}},\"version\":\"{version}\"}}\n",
            hex_sha256(&bundle_manifest),
            hex_sha256(&archive),
            archive.len(),
        )
        .into_bytes();
    let manifest_signature = SigningKey::<Sha256>::new(daily)
        .sign_with_rng(&mut rng, &manifest)
        .to_vec();
    let files = [
        ("root-key.pem".to_string(), root_pem),
        ("trust-delegation.json".to_string(), delegation),
        (
            "trust-delegation.json.sig".to_string(),
            delegation_signature,
        ),
        ("manifest.json".to_string(), manifest.clone()),
        ("manifest.json.sig".to_string(), manifest_signature),
        ("signing-key.pem".to_string(), daily_pem),
        (archive_file.clone(), archive),
    ]
    .into_iter()
    .collect();
    CompleteBundleAssets {
        archive_file,
        files,
        manifest,
        root_fingerprint: root_id,
        target_units: target_units.to_vec(),
    }
}

#[test]
fn schema_three_upgrade_verifies_and_switches_the_complete_package_bundle() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let binary_dir = temporary.path().join("bin");
    let state_dir = temporary.path().join("state");
    let bootstrap_state = temporary.path().join("bootstrap-state");
    fs::create_dir_all(&binary_dir).expect("binary directory");
    fs::create_dir_all(&state_dir).expect("state directory");
    fs::create_dir_all(&bootstrap_state).expect("Bootstrap state");
    fs::set_permissions(&bootstrap_state, fs::Permissions::from_mode(0o700))
        .expect("Bootstrap state mode");
    let probe_path = binary_dir.join("enoki-probe");
    let runtime_path = binary_dir.join("enoki-observation-runtime");
    let provider_path = binary_dir.join("enoki-cpu-resource-provider");
    let disk_health_provider_path = binary_dir.join("enoki-disk-health-resource-provider");
    let bootstrap_acquirer_path = binary_dir.join("enoki-probe-bootstrap-acquire");
    let bootstrap_activator_path = binary_dir.join("enoki-probe-bootstrap-activate");
    let unit_dir = temporary.path().join("systemd");
    fs::create_dir_all(&unit_dir).expect("unit directory");
    let unit_paths = [
        "enoki-observation-runtime.service",
        "enoki-observation-runtime.socket",
        "enoki-cpu-resource-provider@.service",
        "enoki-cpu-resource-provider.socket",
        "enoki-disk-health-resource-provider@.service",
        "enoki-disk-health-resource-provider.socket",
    ]
    .map(|name| unit_dir.join(name));
    for path in [
        &probe_path,
        &runtime_path,
        &provider_path,
        &disk_health_provider_path,
        &bootstrap_acquirer_path,
        &bootstrap_activator_path,
    ] {
        fs::write(path, b"old").expect("old role");
    }
    for path in &unit_paths {
        fs::write(path, b"old unit").expect("old unit");
    }
    let status_path = state_dir.join("probe-operation-status.toml");
    let assets = complete_bundle_assets("0.2.0");
    let archive_file = assets.archive_file.clone();
    let expected_target_units = assets.target_units.clone();
    let mut install_metadata = trusted_install_metadata(&probe_path, &status_path, String::new());
    install_metadata.schema_version = 3;
    install_metadata.probe_distribution_root_sha256 = Some(assets.root_fingerprint.clone());
    install_metadata.bootstrap_state_dir = Some(bootstrap_state.clone());
    install_metadata.bootstrap_acquirer_path = Some(bootstrap_acquirer_path.clone());
    install_metadata.bootstrap_activator_path = Some(bootstrap_activator_path.clone());
    install_metadata.observation_runtime_path = Some(runtime_path.clone());
    install_metadata.cpu_provider_path = Some(provider_path.clone());
    install_metadata.disk_health_provider_path = Some(disk_health_provider_path.clone());
    install_metadata.observation_ipc_group = Some(OBSERVATION_IPC_GROUP.to_string());
    install_metadata.observation_unit_paths = unit_paths.to_vec();
    install_metadata.operation_sudoers_path = None;
    install_metadata.collector_helper_sudoers_path = None;
    let operation = ProbeUpgraderOperationMetadata {
        operation_id: "42".to_string(),
        target_asset_set_digest: format!("sha256:{}", hex_sha256(&assets.manifest)),
        target_probe_version: "0.2.0".to_string(),
        token: "probe-operation-token".to_string(),
    };
    let mut transport = RecordingValidationTransport {
        assets: assets
            .files
            .into_iter()
            .map(|(name, bytes)| {
                (
                    format!("https://hub.example/api/probe/assets/{name}"),
                    bytes,
                )
            })
            .collect(),
        ..RecordingValidationTransport::default()
    };
    let mut systemd = RecordingSystemdRunner::default();

    execute_schema_three_probe_upgrade(
        &operation,
        &temporary.path().join("identity.toml"),
        &install_metadata,
        &mut transport,
        &mut systemd,
        "0.1.0",
        true,
    )
    .expect("schema 3 upgrade");

    assert_eq!(fs::read(&probe_path).expect("probe"), b"new probe");
    assert_eq!(fs::read(&runtime_path).expect("runtime"), b"new runtime");
    assert_eq!(fs::read(&provider_path).expect("provider"), b"new provider");
    assert_eq!(
        fs::read(&disk_health_provider_path).expect("Disk Health Provider"),
        b"new disk health provider"
    );
    assert_eq!(
        fs::read(&bootstrap_acquirer_path).expect("Bootstrap Acquirer"),
        b"acquirer"
    );
    assert!(
        fs::read(&bootstrap_activator_path)
            .expect("Bootstrap Activator")
            .starts_with(b"#!/bin/sh")
    );
    for (path, expected) in unit_paths.iter().zip(expected_target_units) {
        assert_eq!(fs::read(path).expect("target integration unit"), expected);
        assert_ne!(expected.as_slice(), b"old unit");
    }
    assert!(
        fs::read_to_string(&unit_paths[3])
            .expect("Provider socket unit")
            .contains("SocketGroup=enoki-observation-ipc")
    );
    let target_provider_unit =
        fs::read_to_string(&unit_paths[2]).expect("target Provider service unit");
    assert!(target_provider_unit.contains("ReadOnlyPaths=/proc/stat"));
    assert!(!target_provider_unit.contains("ProcSubset=pid"));
    assert_eq!(
        fs::read_to_string(bootstrap_state.join("trust/delegation-generation"))
            .expect("generation"),
        "1\n"
    );
    assert!(
        transport
            .downloads
            .iter()
            .any(|url| url.ends_with(&archive_file))
    );
    assert_eq!(
        &systemd.calls[..5],
        [
            "stop enoki-disk-health-resource-provider.socket",
            "stop enoki-cpu-resource-provider.socket",
            "stop enoki-observation-runtime.socket",
            "stop enoki-observation-runtime.service",
            "stop enoki-probe",
        ]
    );
}

#[test]
fn legacy_schema_three_inventory_requires_signed_replacement_before_upgrade() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let probe_path = temporary.path().join("enoki-probe");
    let status_path = temporary.path().join("status.toml");
    let mut metadata = trusted_install_metadata(&probe_path, &status_path, String::new());
    metadata.schema_version = 3;
    metadata.probe_distribution_root_sha256 = Some("a".repeat(64));
    metadata.bootstrap_state_dir = Some(temporary.path().join("bootstrap-state"));
    metadata.observation_runtime_path = Some(temporary.path().join("runtime"));
    metadata.cpu_provider_path = Some(temporary.path().join("system-state-provider"));
    metadata.disk_health_provider_path = None;
    metadata.observation_unit_paths = vec![
        temporary.path().join("runtime.service"),
        temporary.path().join("runtime.socket"),
        temporary.path().join("provider@.service"),
        temporary.path().join("provider.socket"),
    ];
    metadata.observation_ipc_group = Some(OBSERVATION_IPC_GROUP.to_string());
    let mut transport = RecordingValidationTransport::default();
    let mut systemd = RecordingSystemdRunner::default();

    let error = run_probe_upgrader_with_systemd_runner_and_install_metadata(
        ProbeUpgraderRunInput {
            bootstrap_config_path: temporary.path().join("identity.toml"),
        },
        &operation_stdin(),
        &mut transport,
        &mut systemd,
        &metadata,
    )
    .expect_err("旧闭包不能被当作同合同原地升级");

    assert!(matches!(
        error,
        ProbeUpgraderRunError::ManualProbeReinstallRequired
    ));
    assert!(transport.downloads.is_empty());
    assert!(systemd.calls.is_empty());
}

#[test]
fn schema_three_activation_rolls_back_every_partial_persist_and_is_retryable() {
    for failed_index in 0..9 {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let state = temporary.path().join("state");
        let targets = temporary.path().join("targets");
        fs::create_dir_all(&state).expect("state");
        fs::create_dir_all(&targets).expect("targets");
        let paths = (0..9)
            .map(|index| {
                let path = targets.join(format!("role-{index}"));
                fs::write(&path, format!("old-{index}")).expect("old role");
                path
            })
            .collect::<Vec<_>>();
        let candidates = (0..9)
            .map(|index| format!("new-{index}").into_bytes())
            .collect::<Vec<_>>();
        let replacements = paths
            .iter()
            .zip(&candidates)
            .map(|(path, bytes)| (path.as_path(), bytes.as_slice(), 0o755))
            .collect::<Vec<_>>();
        let transaction = prepare_schema_three_activation(&state, &replacements).expect("prepared");
        fs::remove_file(&transaction.entries[failed_index].staged).expect("inject persist failure");

        transaction.activate().expect_err("persist fails");
        transaction.rollback().expect("rollback succeeds");
        for (index, path) in paths.iter().enumerate() {
            assert_eq!(
                fs::read(path).expect("restored role"),
                format!("old-{index}").as_bytes()
            );
        }
        assert!(!state.join("upgrade-transaction").exists());
    }
}

#[test]
fn schema_three_crash_recovery_restores_every_role_before_restarting_services() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let state = temporary.path().join("state");
    let targets = temporary.path().join("targets");
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&targets).unwrap();
    let paths = (0..9)
        .map(|index| {
            let path = targets.join(format!("role-{index}"));
            fs::write(&path, format!("old-{index}")).unwrap();
            path
        })
        .collect::<Vec<_>>();
    let candidates = (0..9)
        .map(|index| format!("new-{index}").into_bytes())
        .collect::<Vec<_>>();
    let replacements = paths
        .iter()
        .zip(&candidates)
        .map(|(path, bytes)| (path.as_path(), bytes.as_slice(), 0o755))
        .collect::<Vec<_>>();
    let transaction = prepare_schema_three_activation(&state, &replacements).unwrap();
    transaction.activate().unwrap();
    assert_eq!(fs::read(&paths[0]).unwrap(), b"new-0");

    let status_path = temporary.path().join("operation-status.toml");
    let mut metadata = trusted_install_metadata(&paths[0], &status_path, String::new());
    metadata.service_name = "enoki-probe".into();
    let mut systemd = RecordingSystemdRunner::default();
    recover_schema_three_activation(&state, &replacements, &mut systemd, &metadata)
        .expect("recovery");

    for (index, path) in paths.iter().enumerate() {
        assert_eq!(fs::read(path).unwrap(), format!("old-{index}").as_bytes());
    }
    let first_restart = systemd
        .calls
        .iter()
        .position(|call| call.starts_with("restart "))
        .unwrap();
    assert!(
        systemd.calls[..first_restart]
            .iter()
            .any(|call| call == "stop enoki-probe")
    );
    assert!(!state.join("upgrade-transaction").exists());
}

fn trusted_install_metadata(
    install_path: &Path,
    operation_status_path: &Path,
    probe_asset_public_key_sha256: String,
) -> TrustedProbeInstallMetadata {
    trusted_install_metadata_for_hub(
        "https://hub.example",
        install_path,
        operation_status_path,
        probe_asset_public_key_sha256,
    )
}

fn trusted_install_metadata_for_hub(
    hub_url: &str,
    install_path: &Path,
    operation_status_path: &Path,
    probe_asset_public_key_sha256: String,
) -> TrustedProbeInstallMetadata {
    TrustedProbeInstallMetadata {
        schema_version: 0,
        hub_url: hub_url::normalized_base(hub_url).expect("valid test Hub URL"),
        identity_path: operation_status_path
            .parent()
            .expect("status parent")
            .join("probe-bootstrap.toml"),
        install_path: install_path.to_path_buf(),
        operation_status_path: operation_status_path.to_path_buf(),
        probe_asset_public_key_sha256,
        probe_distribution_root_sha256: None,
        bootstrap_acquirer_path: None,
        bootstrap_activator_path: None,
        bootstrap_state_dir: None,
        service_name: "enoki-probe".to_string(),
        service_group: "enoki-probe".to_string(),
        service_unit_path: operation_status_path
            .parent()
            .expect("status parent")
            .join("enoki-probe.service"),
        service_user: "enoki-probe".to_string(),
        state_dir: operation_status_path
            .parent()
            .expect("status parent")
            .to_path_buf(),
        operation_sudoers_path: Some(
            operation_status_path
                .parent()
                .expect("status parent")
                .join("enoki-probe-operations.sudoers"),
        ),
        collector_helper_sudoers_path: Some(
            operation_status_path
                .parent()
                .expect("status parent")
                .join("enoki-probe-collector-helpers.sudoers"),
        ),
        old_sudoers_paths: Vec::new(),
        observation_runtime_path: None,
        cpu_provider_path: None,
        disk_health_provider_path: None,
        lifecycle_companion_path: None,
        observation_unit_paths: Vec::new(),
        probe_ipc_group: None,
        probe_ipc_group_ownership: None,
        observation_ipc_group: None,
        install_state_sha256: None,
        target_manifest_sha256: None,
        bundle_version: None,
        lifecycle_authority_install_key: None,
    }
}

fn fresh_split_install_metadata_contents(root: &Path) -> (String, PathBuf, PathBuf, PathBuf) {
    let operation_sudoers_path = root.join("etc/sudoers.d/enoki-probe-operations");
    let collector_helper_sudoers_path = root.join("etc/sudoers.d/enoki-probe-collector-helpers");
    let legacy_sudoers_path = root.join("etc/sudoers.d/enoki-probe-upgrader");
    let contents = [
        "hub_url = \"https://hub.example\"".to_string(),
        format!(
            "install_path = \"{}\"",
            root.join("usr/local/bin/enoki-probe").display()
        ),
        format!(
            "operation_status_path = \"{}\"",
            root.join("var/lib/enoki-probe/probe-operation-status.toml")
                .display()
        ),
        format!(
            "operation_sudoers_path = \"{}\"",
            operation_sudoers_path.display()
        ),
        format!(
            "collector_helper_sudoers_path = \"{}\"",
            collector_helper_sudoers_path.display()
        ),
        format!(
            "probe_asset_public_key_sha256 = \"{}\"",
            assets_public_key_sha256()
        ),
        "service_name = \"enoki-probe\"".to_string(),
        "service_user = \"enoki-probe\"".to_string(),
        format!(
            "state_dir = \"{}\"",
            root.join("var/lib/enoki-probe").display()
        ),
        "".to_string(),
    ]
    .join("\n");

    (
        contents,
        operation_sudoers_path,
        collector_helper_sudoers_path,
        legacy_sudoers_path,
    )
}

fn version_one_install_metadata_contents(root: &Path) -> String {
    let (legacy, _, _, _) = fresh_split_install_metadata_contents(root);
    [
        "schema_version = 1".to_string(),
        format!(
            "identity_path = \"{}\"",
            root.join("etc/enoki/probe-bootstrap.toml").display()
        ),
        "service_group = \"enoki-probe\"".to_string(),
        format!(
            "service_unit_path = \"{}\"",
            root.join("etc/systemd/system/enoki-probe.service")
                .display()
        ),
        legacy,
    ]
    .join("\n")
}

fn schema_three_install_metadata_contents() -> String {
    [
            "schema_version = 3",
            "hub_url = \"https://hub.example\"",
            "identity_path = \"/var/lib/enoki-probe/identity/probe-bootstrap.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "observation_runtime_path = \"/usr/local/bin/enoki-observation-runtime\"",
            "cpu_provider_path = \"/usr/local/bin/enoki-cpu-resource-provider\"",
            "observation_ipc_group = \"enoki-observation-ipc\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "probe_distribution_root_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"",
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"",
            "bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\"",
            "service_name = \"enoki-probe\"",
            "service_user = \"enoki-probe\"",
            "service_group = \"enoki-probe\"",
            "service_unit_path = \"/etc/systemd/system/enoki-probe.service\"",
            "observation_runtime_service_unit_path = \"/etc/systemd/system/enoki-observation-runtime.service\"",
            "observation_runtime_socket_unit_path = \"/etc/systemd/system/enoki-observation-runtime.socket\"",
            "cpu_provider_service_unit_path = \"/etc/systemd/system/enoki-cpu-resource-provider@.service\"",
            "cpu_provider_socket_unit_path = \"/etc/systemd/system/enoki-cpu-resource-provider.socket\"",
            "operation_sudoers_path = \"/etc/sudoers.d/enoki-probe-operations\"",
            "collector_helper_sudoers_path = \"/etc/sudoers.d/enoki-probe-collector-helpers\"",
            "",
        ]
        .join("\n")
}

fn assets_public_key_sha256() -> String {
    "a".repeat(64)
}

fn run_upgrade_with_assets(
    assets: SignedAssets,
    public_key_sha256: String,
) -> (ProbeUpgraderResult, PathBuf, RecordingSystemdRunner) {
    run_upgrade_with_assets_filtering(assets, public_key_sha256, |_| true)
}

fn run_upgrade_with_assets_filtering(
    assets: SignedAssets,
    public_key_sha256: String,
    keep_asset: impl Fn(&str) -> bool,
) -> (ProbeUpgraderResult, PathBuf, RecordingSystemdRunner) {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let install_metadata = trusted_install_metadata(&install_path, &status_path, public_key_sha256);
    write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
        .expect("write bootstrap config");
    let mut hub_assets = assets.for_hub("https://hub.example");
    hub_assets.retain(|url, _| keep_asset(url));
    let mut transport = RecordingValidationTransport {
        assets: hub_assets,
        ..RecordingValidationTransport::default()
    };
    let mut systemd = RecordingSystemdRunner::default();

    let result = run_probe_upgrader_with_systemd_runner_and_install_metadata(
        ProbeUpgraderRunInput {
            bootstrap_config_path,
        },
        &operation_stdin_for_assets(&assets),
        &mut transport,
        &mut systemd,
        &install_metadata,
    )
    .expect("operation failure is returned");
    let persisted_install_path = temp.keep().join("bin/enoki-probe");

    (result, persisted_install_path, systemd)
}

fn run_upgrade_with_assets_and_current_version(
    assets: SignedAssets,
    public_key_sha256: String,
    current_probe_version: &str,
    target_probe_version: &str,
    target_asset_set_digest: Option<&str>,
) -> (
    Result<(), ProbeUpgraderRunError>,
    PathBuf,
    RecordingSystemdRunner,
) {
    let temp = tempfile::tempdir().expect("temp dir");
    let install_path = temp.path().join("bin/enoki-probe");
    fs::create_dir_all(install_path.parent().expect("install dir")).expect("install dir");
    fs::write(&install_path, "old probe").expect("old probe");
    let status_path = temp.path().join("state/probe-operation-status.toml");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let install_metadata = trusted_install_metadata(&install_path, &status_path, public_key_sha256);
    write_test_bootstrap_config(&bootstrap_config_path, &install_metadata)
        .expect("write bootstrap config");
    let bootstrap_config =
        read_upgrader_bootstrap_config(&bootstrap_config_path).expect("bootstrap config");
    let operation = ProbeUpgraderOperationMetadata {
        operation_id: "42".to_string(),
        target_asset_set_digest: target_asset_set_digest.map_or_else(
            || format!("sha256:{}", hex_sha256(&assets.manifest)),
            str::to_string,
        ),
        target_probe_version: target_probe_version.to_string(),
        token: "probe-operation-token".to_string(),
    };
    let mut transport = RecordingValidationTransport {
        assets: assets.for_hub("https://hub.example"),
        ..RecordingValidationTransport::default()
    };
    let mut systemd = RecordingSystemdRunner::default();

    let result = execute_probe_upgrade_with_current_version(
        &operation,
        &bootstrap_config,
        &bootstrap_config_path,
        &install_metadata,
        &mut transport,
        &mut systemd,
        current_probe_version,
    );
    let persisted_install_path = temp.keep().join("bin/enoki-probe");

    (result, persisted_install_path, systemd)
}

fn write_test_bootstrap_config(
    bootstrap_config_path: &Path,
    install_metadata: &TrustedProbeInstallMetadata,
) -> Result<(), std::io::Error> {
    fs::write(
        bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"".to_string(),
            "probe_id = \"probe_01\"".to_string(),
            "probe_private_key_pem = \"test-private-key\"".to_string(),
            format!(
                "state_dir = {}",
                toml_string(install_metadata.state_dir.to_str().expect("state dir")),
            ),
            format!(
                "operation_status_path = {}",
                toml_string(
                    install_metadata
                        .operation_status_path
                        .to_str()
                        .expect("status path"),
                ),
            ),
            format!(
                "install_path = {}",
                toml_string(
                    install_metadata
                        .install_path
                        .to_str()
                        .expect("install path")
                ),
            ),
            "service_name = \"enoki-probe\"".to_string(),
            format!(
                "probe_asset_public_key_sha256 = \"{}\"",
                install_metadata.probe_asset_public_key_sha256,
            ),
            String::new(),
        ]
        .join("\n"),
    )
}

fn operation_stdin() -> String {
    operation_stdin_with_digest(&format!("sha256:{}", "a".repeat(64)))
}

fn operation_stdin_for_assets(assets: &SignedAssets) -> String {
    operation_stdin_with_digest(&format!("sha256:{}", hex_sha256(&assets.manifest)))
}

fn operation_stdin_with_digest(target_asset_set_digest: &str) -> String {
    [
        "operation_id = \"42\"".to_string(),
        format!(
            "target_asset_set_digest = {}",
            toml_string(target_asset_set_digest)
        ),
        "target_probe_version = \"0.2.0\"".to_string(),
        "token = \"probe-operation-token\"".to_string(),
        String::new(),
    ]
    .join("\n")
}

fn archive_with_probe_binary(contents: &str) -> Vec<u8> {
    let mut archive_bytes = Vec::new();
    {
        let encoder = GzEncoder::new(&mut archive_bytes, Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        archive
            .append_data(&mut header, "enoki-probe", contents.as_bytes())
            .expect("append probe binary");
        archive.finish().expect("finish archive");
    }

    archive_bytes
}

fn archive_with_entry(path: &str, entry_type: tar::EntryType) -> Vec<u8> {
    let mut archive_bytes = Vec::new();
    {
        let encoder = GzEncoder::new(&mut archive_bytes, Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(if entry_type == tar::EntryType::Regular {
            "new probe".len() as u64
        } else {
            0
        });
        header.set_mode(0o755);
        if entry_type == tar::EntryType::Symlink || entry_type == tar::EntryType::Link {
            header.set_link_name("target").expect("link name");
        }
        if path.contains("..") {
            let bytes = header.as_mut_bytes();
            bytes[..path.len()].copy_from_slice(path.as_bytes());
            bytes[path.len()] = 0;
            header.set_cksum();
            archive
                .append(&header, "new probe".as_bytes())
                .expect("append entry");
        } else {
            header.set_cksum();
            archive
                .append_data(&mut header, path, "new probe".as_bytes())
                .expect("append entry");
        }
        archive.finish().expect("finish archive");
    }

    archive_bytes
}

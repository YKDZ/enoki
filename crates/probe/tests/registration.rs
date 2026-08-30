use std::fs;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use enoki_probe_bootstrap::replacement::ReplacementRegistrationBinding;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

use enoki_probe::{
    metrics::CollectorId,
    protocol::enoki::v1::{
        ProbeConfigurationResponse, ProbeRegistrationRequest, ProbeRegistrationResponse,
    },
    registration::{
        ProbeInstallationInspectionInput, ProbeInstallationRejectionInput, ProbeInstallationTarget,
        ProbeRegistrationInput, RegistrationError, RegistrationTransport,
        inspect_probe_installation, register_probe, reject_probe_installation,
    },
};
use prost::Message;

#[test]
fn probe_registration_posts_protobuf_and_stores_probe_identity() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let response = ProbeRegistrationResponse {
        enrollment_id: String::new(),
        host_id: "7".to_string(),
        installation_inspection: None,
        initial_configuration: Some(ProbeConfigurationResponse {
            enabled_collector_ids: all_collector_ids(),
            metrics_collection_interval_seconds: 5,
            version: "default-v1".to_string(),
        }),
        probe_id: "probe_01".to_string(),
        probe_secret: String::new(),
        server_time_ms: 1_725_000_000_000,
    }
    .encode_to_vec();
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response,
    };

    let outcome = register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    )
    .expect("Probe registration succeeds");

    assert_eq!(outcome.probe_id, "probe_01");
    assert_eq!(outcome.host_id, "7");
    assert_eq!(
        transport.observed_url,
        "https://hub.example/api/probe/register",
    );
    assert!(!transport.observed_url.contains("enk_enroll_secret"));
    let request = ProbeRegistrationRequest::decode(transport.observed_body.as_slice())
        .expect("registration request decodes");
    assert_eq!(request.enrollment_token, "enk_enroll_secret");
    assert!(
        request
            .probe_public_key_pem
            .starts_with("-----BEGIN PUBLIC KEY-----")
    );
    assert!(request.snapshots.is_empty());

    let bootstrap_config =
        fs::read_to_string(bootstrap_config_path).expect("bootstrap config exists");
    assert!(bootstrap_config.contains("hub_url = \"https://hub.example\""));
    assert!(bootstrap_config.contains("host_id = \"7\""));
    assert!(bootstrap_config.contains("probe_id = \"probe_01\""));
    assert!(bootstrap_config.contains("probe_private_key_pem = \"-----BEGIN PRIVATE KEY-----"));
    assert!(bootstrap_config.contains("server_time_offset_ms = "));
    assert!(!bootstrap_config.contains("enk_enroll_secret"));
    assert!(!bootstrap_config.contains("install_path"));
    assert!(!bootstrap_config.contains("operation_status_path"));
    assert!(!bootstrap_config.contains("service_name"));
    assert!(!bootstrap_config.contains("probe_asset_public_key_sha256"));
}

#[test]
fn probe_registration_rejects_a_legacy_response_without_host_identity() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let response = ProbeRegistrationResponse {
        host_id: String::new(),
        probe_id: "probe_01".to_string(),
        server_time_ms: 1_725_000_000_000,
        ..Default::default()
    };
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response: response.encode_to_vec(),
    };

    let error = register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    )
    .expect_err("旧 registration outcome 无法证明 Host binding");

    assert!(matches!(error, RegistrationError::InvalidResponse(_)));
    assert!(!bootstrap_config_path.exists());
}

#[test]
fn probe_registration_restart_reuses_the_candidate_key_and_exact_request_after_response_loss() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let capsule_path = temp.path().join("registration-attempt.json");
    let binding = enoki_probe_bootstrap::replacement::ReplacementRegistrationBinding {
        committed_source_probe_sha256: "a".repeat(64),
        enrollment_id: "enr_0123456789abcdef".to_string(),
        host_id: "7".to_string(),
        hub_origin: "https://hub.example".to_string(),
        old_probe_id: "probe_old_01".to_string(),
        replacement_commit_sha256: "d".repeat(64),
        source_probe_version: "0.1.0".to_string(),
        target_asset_set_digest: format!("sha256:{}", "b".repeat(64)),
        target_bundle_target: "x86_64-unknown-linux-gnu".to_string(),
        target_manifest_sha256: "c".repeat(64),
        target_probe_version: "0.2.0".to_string(),
    };
    enoki_probe::registration::prepare_root_replacement_registration_attempt(
        &capsule_path,
        enoki_probe::registration::RootReplacementRegistrationAttemptInput {
            enrollment_token: "enk_enroll_response_loss".to_string(),
            binding,
        },
    )
    .expect("root companion publishes attempt before activation");
    let one_shot_config = [
        "hub_url = \"https://hub.example\"",
        "enrollment_token = \"enk_enroll_response_loss\"",
        &format!(
            "registration_attempt_credential_path = {:?}",
            capsule_path.display().to_string()
        ),
        "registration_enrollment_id = \"enr_0123456789abcdef\"",
        "registration_host_id = \"7\"",
        "registration_hub_origin = \"https://hub.example\"",
        "registration_old_probe_id = \"probe_old_01\"",
        "registration_source_probe_version = \"0.1.0\"",
        &format!(
            "registration_committed_source_probe_sha256 = \"{}\"",
            "a".repeat(64)
        ),
        "registration_target_probe_version = \"0.2.0\"",
        "registration_target_bundle_target = \"x86_64-unknown-linux-gnu\"",
        &format!(
            "registration_target_asset_set_digest = \"sha256:{}\"",
            "b".repeat(64)
        ),
        &format!(
            "registration_target_manifest_sha256 = \"{}\"",
            "c".repeat(64)
        ),
        &format!(
            "registration_replacement_commit_sha256 = \"{}\"",
            "d".repeat(64)
        ),
        "",
    ]
    .join("\n");
    fs::write(&bootstrap_config_path, &one_shot_config).expect("replacement bootstrap config");
    let mut transport = ResponseLossThenSuccessTransport {
        attempts: 0,
        bodies: Vec::new(),
        response: registration_response(),
    };

    let first = register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
            enrollment_token: "enk_enroll_response_loss".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    );
    assert!(matches!(first, Err(RegistrationError::Attempt(_))));

    register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
            enrollment_token: "enk_enroll_response_loss".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    )
    .expect("fresh process replays the committed registration attempt");

    let first_success_config = fs::read(&bootstrap_config_path).expect("first identity config");
    fs::write(&bootstrap_config_path, one_shot_config).expect("restore one-shot config");
    std::thread::sleep(std::time::Duration::from_millis(25));
    register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
            enrollment_token: "enk_enroll_response_loss".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    )
    .expect("delayed exact-outcome replay converges");
    assert!(
        fs::read(&bootstrap_config_path).expect("replayed identity config") == first_success_config,
        "exact outcome replay must persist byte-identical identity config"
    );

    assert_eq!(transport.bodies.len(), 3);
    assert_eq!(transport.bodies[1], transport.bodies[0]);
    assert_eq!(transport.bodies[2], transport.bodies[0]);
    let first_request = ProbeRegistrationRequest::decode(transport.bodies[0].as_slice())
        .expect("first request decodes");
    let replay_request = ProbeRegistrationRequest::decode(transport.bodies[1].as_slice())
        .expect("replayed request decodes");
    assert_eq!(
        replay_request.probe_public_key_pem, first_request.probe_public_key_pem,
        "restart must not generate a second candidate keypair"
    );
}

#[test]
fn replacement_attempt_capsule_is_explicitly_root_owned_and_private() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("registration-attempt.json");
    enoki_probe::registration::prepare_root_replacement_registration_attempt(
        &path,
        enoki_probe::registration::RootReplacementRegistrationAttemptInput {
            enrollment_token: "enk_enroll_owner".to_string(),
            binding: enoki_probe_bootstrap::replacement::ReplacementRegistrationBinding {
                committed_source_probe_sha256: "a".repeat(64),
                enrollment_id: "enr_0123456789abcdef".to_string(),
                host_id: "7".to_string(),
                hub_origin: "https://hub.example".to_string(),
                old_probe_id: "probe_old_01".to_string(),
                replacement_commit_sha256: "d".repeat(64),
                source_probe_version: "0.1.0".to_string(),
                target_asset_set_digest: format!("sha256:{}", "b".repeat(64)),
                target_bundle_target: "x86_64-unknown-linux-gnu".to_string(),
                target_manifest_sha256: "c".repeat(64),
                target_probe_version: "0.2.0".to_string(),
            },
        },
    )
    .expect("root companion prepares capsule");

    let metadata = fs::symlink_metadata(&path).expect("capsule metadata");
    assert_eq!(
        metadata.uid(),
        0,
        "durable capsule custody is root, not service euid"
    );
    assert_eq!(metadata.gid(), 0, "durable capsule group is root");
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
}

#[test]
fn root_publisher_fails_closed_on_unresolved_capsule_publish_residue() {
    if let Some(path) = std::env::var_os("ENOKI_TEST_ROOT_CAPSULE_PATH") {
        let path = std::path::PathBuf::from(path);
        let mut binding = replacement_registration_binding();
        let replacement = std::env::var_os("ENOKI_TEST_ROOT_CAPSULE_REPLACE").is_some();
        if replacement {
            binding.enrollment_id = "enr_abcdef0123456789".to_string();
            binding.replacement_commit_sha256 = "e".repeat(64);
        }
        let input = enoki_probe::registration::RootReplacementRegistrationAttemptInput {
            enrollment_token: if replacement {
                "enk_enroll_replacement"
            } else {
                "enk_enroll_publish_recovery"
            }
            .to_string(),
            binding,
        };
        let result = if replacement {
            enoki_probe::registration::replace_stale_root_replacement_registration_attempt(
                &path, input,
            )
        } else {
            enoki_probe::registration::prepare_root_replacement_registration_attempt(&path, input)
        };
        result.expect("root production publisher converges");
        return;
    }

    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "test requires real root custody"
    );
    assert_eq!(
        unsafe { libc::getegid() },
        0,
        "test requires real root custody"
    );
    let temporary = tempfile::tempdir().expect("temporary root state");
    let before = temporary.path().join("before/attempt.json");
    let after = temporary.path().join("after/attempt.json");

    let crashed_before = run_root_capsule_publisher(&before, Some("before-rename"));
    assert!(!crashed_before.success());
    assert!(
        !before.exists(),
        "pre-publish crash cannot expose a capsule"
    );
    assert!(
        !run_root_capsule_publisher(&before, None).success(),
        "fresh process must not guess that pre-rename residue is discardable"
    );

    let crashed_after = run_root_capsule_publisher(&after, Some("after-rename"));
    assert!(!crashed_after.success());
    let published = fs::read(&after).expect("post-publish crash retains durable capsule");
    assert!(run_root_capsule_publisher(&after, None).success());
    assert_eq!(fs::read(&after).unwrap(), published);

    let stale = temporary.path().join("stale/attempt.json");
    assert!(run_root_capsule_publisher(&stale, None).success());
    let old = fs::read(&stale).unwrap();
    let crashed_stale = run_root_capsule_replacement(&stale, Some("before-rename"));
    assert!(!crashed_stale.success());
    assert_eq!(fs::read(&stale).unwrap(), old);
    assert!(
        !run_root_capsule_replacement(&stale, None).success(),
        "fresh stale replacement must retain old capsule when residue is unresolved"
    );
    assert_eq!(fs::read(&stale).unwrap(), old);

    for (name, symlink_residue) in [("wrong-mode", false), ("symlink", true)] {
        let path = temporary.path().join(name).join("attempt.json");
        assert!(run_root_capsule_publisher(&path, None).success());
        let old = fs::read(&path).unwrap();
        let residue = path.parent().unwrap().join(format!(
            ".{}-enoki-write-999-1",
            path.file_name().unwrap().to_string_lossy()
        ));
        if symlink_residue {
            symlink(&path, &residue).unwrap();
        } else {
            fs::write(&residue, b"unknown publisher bytes").unwrap();
            fs::set_permissions(&residue, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(!run_root_capsule_replacement(&path, None).success());
        assert_eq!(fs::read(&path).unwrap(), old, "{name} retains old capsule");
    }

    let swapped = temporary.path().join("swapped/attempt.json");
    let swap_signal = temporary.path().join("swap-scanned");
    let swap_resume = temporary.path().join("swap-resume");
    let mut swap_child = spawn_root_capsule_race(&swapped, false, &swap_signal, &swap_resume);
    wait_for_test_signal(&mut swap_child, &swap_signal);
    let swapped_original = temporary.path().join("swapped-original");
    fs::rename(swapped.parent().unwrap(), &swapped_original).unwrap();
    fs::create_dir(swapped.parent().unwrap()).unwrap();
    fs::set_permissions(swapped.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    let new_namespace_residue = swapped
        .parent()
        .unwrap()
        .join(".attempt.json-enoki-write-new-namespace");
    fs::write(&new_namespace_residue, b"new namespace custody").unwrap();
    fs::write(&swap_resume, b"resume").unwrap();
    assert!(
        !swap_child.wait().unwrap().success(),
        "publisher must not authorize an orphaned durable capsule"
    );
    assert!(
        !swapped_original.join("attempt.json").exists(),
        "first-scan namespace rejection precedes capsule publication"
    );
    assert!(
        !swapped.exists(),
        "held FD never publishes into replacement namespace"
    );
    assert_eq!(
        fs::read(&new_namespace_residue).unwrap(),
        b"new namespace custody"
    );

    let post_publish = temporary.path().join("post-publish-swap/attempt.json");
    let post_publish_signal = temporary.path().join("post-publish-signal");
    let post_publish_resume = temporary.path().join("post-publish-resume");
    let mut post_publish_child = spawn_root_capsule_post_publish_race(
        &post_publish,
        &post_publish_signal,
        &post_publish_resume,
    );
    wait_for_test_signal(&mut post_publish_child, &post_publish_signal);
    let post_publish_original = temporary.path().join("post-publish-original");
    fs::rename(post_publish.parent().unwrap(), &post_publish_original).unwrap();
    fs::create_dir(post_publish.parent().unwrap()).unwrap();
    fs::set_permissions(
        post_publish.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let post_publish_residue = post_publish
        .parent()
        .unwrap()
        .join(".attempt.json-enoki-write-new-namespace");
    fs::write(&post_publish_residue, b"post-publish new namespace").unwrap();
    fs::write(&post_publish_resume, b"resume").unwrap();
    assert!(!post_publish_child.wait().unwrap().success());
    assert!(
        post_publish_original.join("attempt.json").exists(),
        "post-publish detection must not compensate orphan custody"
    );
    assert!(!post_publish.exists());
    assert_eq!(
        fs::read(&post_publish_residue).unwrap(),
        b"post-publish new namespace"
    );

    let after_scan = temporary.path().join("after-scan/attempt.json");
    assert!(run_root_capsule_publisher(&after_scan, None).success());
    let after_scan_old = fs::read(&after_scan).unwrap();
    let after_scan_signal = temporary.path().join("after-scan-scanned");
    let after_scan_resume = temporary.path().join("after-scan-resume");
    let mut after_scan_child =
        spawn_root_capsule_race(&after_scan, true, &after_scan_signal, &after_scan_resume);
    wait_for_test_signal(&mut after_scan_child, &after_scan_signal);
    let after_scan_residue = after_scan
        .parent()
        .unwrap()
        .join(".attempt.json-enoki-write-777-1");
    fs::write(&after_scan_residue, b"arrived after first scan").unwrap();
    fs::set_permissions(&after_scan_residue, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&after_scan_resume, b"resume").unwrap();
    assert!(!after_scan_child.wait().unwrap().success());
    assert_eq!(fs::read(&after_scan).unwrap(), after_scan_old);
    assert_eq!(
        fs::read(&after_scan_residue).unwrap(),
        b"arrived after first scan"
    );

    for path in [&after, &stale] {
        let parent = fs::symlink_metadata(path.parent().unwrap()).unwrap();
        let source = fs::symlink_metadata(path).unwrap();
        assert_eq!(parent.uid(), 0);
        assert_eq!(parent.gid(), 0);
        assert_eq!(parent.mode() & 0o777, 0o700);
        assert_eq!(source.uid(), 0);
        assert_eq!(source.gid(), 0);
        assert_eq!(source.mode() & 0o777, 0o600);
        assert_eq!(source.nlink(), 1);
    }
}

fn spawn_root_capsule_race(
    path: &std::path::Path,
    replacement: bool,
    signal: &std::path::Path,
    resume: &std::path::Path,
) -> Child {
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .arg("--exact")
        .arg("root_publisher_fails_closed_on_unresolved_capsule_publish_residue")
        .arg("--nocapture")
        .env("ENOKI_TEST_ROOT_CAPSULE_PATH", path)
        .env("ENOKI_TEST_PRIVATE_ATOMIC_PATH", path)
        .env("ENOKI_TEST_PRIVATE_ATOMIC_SIGNAL", signal)
        .env("ENOKI_TEST_PRIVATE_ATOMIC_RESUME", resume);
    if replacement {
        command.env("ENOKI_TEST_ROOT_CAPSULE_REPLACE", "1");
    }
    command
        .spawn()
        .expect("spawn synchronized capsule operation")
}

fn spawn_root_capsule_post_publish_race(
    path: &std::path::Path,
    signal: &std::path::Path,
    resume: &std::path::Path,
) -> Child {
    Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("root_publisher_fails_closed_on_unresolved_capsule_publish_residue")
        .arg("--nocapture")
        .env("ENOKI_TEST_ROOT_CAPSULE_PATH", path)
        .env("ENOKI_TEST_PRIVATE_ATOMIC_AFTER_PUBLISH_PATH", path)
        .env("ENOKI_TEST_PRIVATE_ATOMIC_AFTER_PUBLISH_SIGNAL", signal)
        .env("ENOKI_TEST_PRIVATE_ATOMIC_AFTER_PUBLISH_RESUME", resume)
        .spawn()
        .expect("spawn synchronized post-publish capsule operation")
}

fn wait_for_test_signal(child: &mut Child, path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if path.exists() {
            return;
        }

        if let Some(status) = child
            .try_wait()
            .expect("observe synchronized capsule operation")
        {
            panic!("private atomic race child exited before signal: {status}");
        }

        if Instant::now() >= deadline {
            panic!("timed out waiting for private atomic race signal; child remained running");
        }

        std::thread::sleep(Duration::from_millis(5));
    }
}

fn run_root_capsule_publisher(
    path: &std::path::Path,
    crash: Option<&str>,
) -> std::process::ExitStatus {
    let mut child = Command::new(std::env::current_exe().expect("current test executable"));
    child
        .arg("--exact")
        .arg("root_publisher_fails_closed_on_unresolved_capsule_publish_residue")
        .arg("--nocapture")
        .env("ENOKI_TEST_ROOT_CAPSULE_PATH", path);
    if let Some(point) = crash {
        child
            .env("ENOKI_TEST_SECURE_FILE_PATH", path)
            .env("ENOKI_TEST_SECURE_FILE_CRASH_POINT", point);
    }
    child.status().expect("run fresh root publisher")
}

fn run_root_capsule_replacement(
    path: &std::path::Path,
    crash: Option<&str>,
) -> std::process::ExitStatus {
    let mut child = Command::new(std::env::current_exe().expect("current test executable"));
    child
        .arg("--exact")
        .arg("root_publisher_fails_closed_on_unresolved_capsule_publish_residue")
        .arg("--nocapture")
        .env("ENOKI_TEST_ROOT_CAPSULE_PATH", path)
        .env("ENOKI_TEST_ROOT_CAPSULE_REPLACE", "1");
    if let Some(point) = crash {
        child
            .env("ENOKI_TEST_SECURE_FILE_PATH", path)
            .env("ENOKI_TEST_SECURE_FILE_CRASH_POINT", point);
    }
    child.status().expect("run fresh root stale replacement")
}

fn replacement_registration_binding() -> ReplacementRegistrationBinding {
    ReplacementRegistrationBinding {
        committed_source_probe_sha256: "a".repeat(64),
        enrollment_id: "enr_0123456789abcdef".to_string(),
        host_id: "7".to_string(),
        hub_origin: "https://hub.example".to_string(),
        old_probe_id: "probe_old_01".to_string(),
        replacement_commit_sha256: "d".repeat(64),
        source_probe_version: "0.1.0".to_string(),
        target_asset_set_digest: format!("sha256:{}", "b".repeat(64)),
        target_bundle_target: "x86_64-unknown-linux-gnu".to_string(),
        target_manifest_sha256: "c".repeat(64),
        target_probe_version: "0.2.0".to_string(),
    }
}

#[test]
fn production_registration_identity_rename_crash_seam_aborts_before_publish() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let config = temporary.path().join("probe-bootstrap.toml");
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("production_registration_identity_rename_crash_child")
        .arg("--nocapture")
        .env("ENOKI_TEST_SECURE_FILE_PATH", &config)
        .env("ENOKI_TEST_SECURE_FILE_CRASH_POINT", "before-rename")
        .output()
        .expect("run abrupt registration child");
    assert!(
        !output.status.success(),
        "production seam must abruptly stop the child"
    );
    assert!(
        !config.exists(),
        "pre-rename crash cannot publish an identity"
    );
}

#[test]
fn production_registration_identity_rename_crash_child() {
    let Some(config) = std::env::var_os("ENOKI_TEST_SECURE_FILE_PATH") else {
        return;
    };
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response: registration_response(),
    };
    let _ = register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path: config.into(),
            enrollment_token: "enk_enroll_crash".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    );
}

#[test]
fn installation_inspection_uses_registration_without_generating_an_identity() {
    let response =
        ProbeRegistrationResponse {
            enrollment_id: String::new(),
            host_id: "7".to_string(),
            initial_configuration: None,
            installation_inspection: Some(
                enoki_probe::protocol::enoki::v1::ProbeInstallationInspectionResponse {
                    target_kind:
                        enoki_probe::protocol::enoki::v1::ProbeEnrollmentTargetKind::ExistingHost
                            as i32,
                    ..Default::default()
                },
            ),
            probe_id: String::new(),
            probe_secret: String::new(),
            server_time_ms: 0,
        }
        .encode_to_vec();
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response,
    };

    let target = inspect_probe_installation(
        ProbeInstallationInspectionInput {
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    )
    .expect("inspection succeeds");

    assert_eq!(target, ProbeInstallationTarget::ExistingHost);
    assert_eq!(
        transport.observed_url,
        "https://hub.example/api/probe/register",
    );
    let request = ProbeRegistrationRequest::decode(transport.observed_body.as_slice())
        .expect("inspection request decodes");
    assert_eq!(request.enrollment_token, "enk_enroll_secret");
    assert!(request.installation_inspection.is_some());
    assert!(request.installation_rejection.is_none());
    assert!(request.probe_public_key_pem.is_empty());
    assert!(request.snapshots.is_empty());
}

#[test]
fn manual_reinstall_inspection_returns_the_bounded_hub_authority() {
    let response = ProbeRegistrationResponse {
        installation_inspection: Some(
            enoki_probe::protocol::enoki::v1::ProbeInstallationInspectionResponse {
                target_kind:
                    enoki_probe::protocol::enoki::v1::ProbeEnrollmentTargetKind::ManualReinstall
                        as i32,
                expected_hub_origin: "https://hub.example".to_string(),
                enrollment_id: "enr_0123456789abcdef".to_string(),
                target_host_id: "7".to_string(),
                expected_probe_id: "probe_old_01".to_string(),
                source_probe_version: "1.2.2".to_string(),
                source_probe_sha256: vec!["b".repeat(64)],
                target_probe_version: "1.2.3".to_string(),
                target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
            },
        ),
        ..Default::default()
    }
    .encode_to_vec();
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response,
    };

    let target = inspect_probe_installation(
        ProbeInstallationInspectionInput {
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    )
    .expect("手动重装授权应通过类型化inspection返回");

    assert_eq!(
        target,
        ProbeInstallationTarget::ManualReinstall(
            enoki_probe::registration::ProbeReplacementAuthorization {
                expected_hub_origin: "https://hub.example".to_string(),
                enrollment_id: "enr_0123456789abcdef".to_string(),
                host_id: "7".to_string(),
                expected_probe_id: "probe_old_01".to_string(),
                source_probe_version: "1.2.2".to_string(),
                source_probe_sha256: vec!["b".repeat(64)],
                target_asset_set_digest: format!("sha256:{}", "a".repeat(64)),
                target_probe_version: "1.2.3".to_string(),
            }
        )
    );
}

#[test]
fn installation_rejection_uses_the_registration_endpoint_without_generating_or_storing_identity() {
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response: Vec::new(),
    };

    reject_probe_installation(
        ProbeInstallationRejectionInput {
            code: "probe_bound_to_different_hub".to_string(),
            existing_probe_id: "probe_existing_01".to_string(),
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "https://hub.example".to_string(),
            message: "local Probe installation is bound to a different Hub".to_string(),
        },
        &mut transport,
    )
    .expect("rejection posts");

    assert_eq!(
        transport.observed_url,
        "https://hub.example/api/probe/register",
    );
    let request = ProbeRegistrationRequest::decode(transport.observed_body.as_slice())
        .expect("rejection request decodes");
    assert_eq!(request.enrollment_token, "enk_enroll_secret");
    assert_eq!(request.probe_public_key_pem, "");
    assert!(request.snapshots.is_empty());
    let rejection = request.installation_rejection.expect("typed rejection");
    assert_eq!(rejection.code, "probe_bound_to_different_hub");
    assert_eq!(rejection.existing_probe_id, "probe_existing_01");
    assert_eq!(
        rejection.message,
        "local Probe installation is bound to a different Hub"
    );
}

#[test]
fn probe_registration_preserves_installer_owned_bootstrap_fields() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    fs::write(
        &bootstrap_config_path,
        [
            "hub_url = \"https://hub.example\"",
            "enrollment_token = \"enk_enroll_secret\"",
            "state_dir = \"/var/lib/enoki-probe\"",
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\"",
            "install_path = \"/usr/local/bin/enoki-probe\"",
            "service_name = \"enoki-probe\"",
            "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "probe_distribution_root_sha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"",
            "install_state_sha256 = \"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"",
            "target_manifest_sha256 = \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"",
            "bundle_version = \"1.2.3\"",
            "bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"",
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\"",
            "bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\"",
            "upgrader_launch = \"systemd\"",
            "log_level = \"debug\"",
            "",
        ]
        .join("\n"),
    )
    .expect("write installer bootstrap config");
    let response = ProbeRegistrationResponse {
        enrollment_id: String::new(),
        host_id: "7".to_string(),
        installation_inspection: None,
        initial_configuration: Some(ProbeConfigurationResponse {
            enabled_collector_ids: all_collector_ids(),
            metrics_collection_interval_seconds: 5,
            version: "default-v1".to_string(),
        }),
        probe_id: "probe_01".to_string(),
        probe_secret: String::new(),
        server_time_ms: 1_725_000_000_000,
    }
    .encode_to_vec();
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response,
    };

    register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    )
    .expect("Probe registration succeeds");

    let bootstrap_config =
        fs::read_to_string(bootstrap_config_path).expect("bootstrap config exists");
    assert!(bootstrap_config.contains("state_dir = \"/var/lib/enoki-probe\""));
    assert!(
        bootstrap_config.contains(
            "operation_status_path = \"/var/lib/enoki-probe/probe-operation-status.toml\""
        )
    );
    assert!(bootstrap_config.contains("install_path = \"/usr/local/bin/enoki-probe\""));
    assert!(bootstrap_config.contains("service_name = \"enoki-probe\""));
    assert!(bootstrap_config.contains(
        "probe_asset_public_key_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
    ));
    assert!(bootstrap_config.contains("upgrader_launch = \"systemd\""));
    assert!(bootstrap_config.contains(
        "probe_distribution_root_sha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\""
    ));
    assert!(bootstrap_config.contains(
        "install_state_sha256 = \"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\""
    ));
    assert!(bootstrap_config.contains(
        "target_manifest_sha256 = \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\""
    ));
    assert!(bootstrap_config.contains("bundle_version = \"1.2.3\""));
    assert!(
        bootstrap_config
            .contains("bootstrap_acquirer_path = \"/usr/local/bin/enoki-probe-bootstrap-acquire\"")
    );
    assert!(
        bootstrap_config.contains(
            "bootstrap_activator_path = \"/usr/local/bin/enoki-probe-bootstrap-activate\""
        )
    );
    assert!(bootstrap_config.contains("bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\""));
    assert!(bootstrap_config.contains("log_level = \"debug\""));
    assert!(!bootstrap_config.contains("enrollment_token"));
    assert!(!bootstrap_config.contains("enk_enroll_secret"));
}

#[test]
fn probe_registration_does_not_persist_required_host_profile_as_configurable_collector() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let response = ProbeRegistrationResponse {
        enrollment_id: String::new(),
        host_id: "7".to_string(),
        installation_inspection: None,
        initial_configuration: Some(ProbeConfigurationResponse {
            enabled_collector_ids: vec![
                "official.host-profile".to_string(),
                "official.memory".to_string(),
                "official.disk-health".to_string(),
            ],
            metrics_collection_interval_seconds: 5,
            version: "default-v1".to_string(),
        }),
        probe_id: "probe_01".to_string(),
        probe_secret: String::new(),
        server_time_ms: 1_725_000_000_000,
    }
    .encode_to_vec();
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response,
    };

    register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    )
    .expect("Probe registration succeeds");

    let bootstrap_config =
        fs::read_to_string(bootstrap_config_path).expect("bootstrap config exists");
    assert!(bootstrap_config.contains("enabled_collector_ids = ["));
    assert!(!bootstrap_config.contains("\"official.host-profile\""));
    assert!(bootstrap_config.contains("\"official.memory\""));
    assert!(bootstrap_config.contains("\"official.disk-health\""));
}

#[test]
fn probe_registration_drops_unknown_initial_collector_ids_from_bootstrap_config() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let response = ProbeRegistrationResponse {
        enrollment_id: String::new(),
        host_id: "7".to_string(),
        installation_inspection: None,
        initial_configuration: Some(ProbeConfigurationResponse {
            enabled_collector_ids: vec![
                "official.memory".to_string(),
                "official.not-real".to_string(),
            ],
            metrics_collection_interval_seconds: 5,
            version: "default-v1".to_string(),
        }),
        probe_id: "probe_01".to_string(),
        probe_secret: String::new(),
        server_time_ms: 1_725_000_000_000,
    }
    .encode_to_vec();
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response,
    };

    register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path: bootstrap_config_path.clone(),
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    )
    .expect("Probe registration succeeds");

    let bootstrap_config =
        fs::read_to_string(bootstrap_config_path).expect("bootstrap config exists");
    assert!(bootstrap_config.contains("\"official.memory\""));
    assert!(!bootstrap_config.contains("\"official.not-real\""));
}

#[test]
fn probe_registration_rejects_unsafe_hub_urls_before_posting() {
    for hub_url in [
        "ftp://hub.example",
        "https://user:pass@hub.example",
        "https://hub.example/base",
        "https://hub.example/",
        "https://hub.example/%2e",
        "https://hub.example?",
        "https://hub.example#",
        "https://hub.example/#fragment",
    ] {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        let mut transport = RecordingTransport {
            observed_body: Vec::new(),
            observed_url: String::new(),
            response: registration_response(),
        };

        let error = register_probe(
            ProbeRegistrationInput {
                bootstrap_config_path: bootstrap_config_path.clone(),
                enrollment_token: "enk_enroll_secret".to_string(),
                hub_url: hub_url.to_string(),
            },
            &mut transport,
        )
        .expect_err("unsafe Hub URL is rejected");

        assert!(
            matches!(error, RegistrationError::InvalidResponse("invalid Hub URL")),
            "unexpected error for {hub_url}: {error}"
        );
        assert_eq!(transport.observed_url, "");
        assert!(!bootstrap_config_path.exists());
    }
}

#[test]
fn probe_registration_allows_explicit_non_loopback_http_hub() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response: registration_response(),
    };

    register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path,
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "http://192.0.2.20:8787".to_string(),
        },
        &mut transport,
    )
    .expect("explicit HTTP Hub is accepted");

    assert_eq!(
        transport.observed_url,
        "http://192.0.2.20:8787/api/probe/register",
    );
}

#[test]
fn probe_registration_allows_localhost_http_hub_for_development() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response: registration_response(),
    };

    register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path,
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "http://127.0.0.1:8787".to_string(),
        },
        &mut transport,
    )
    .expect("localhost HTTP Hub is accepted for development");

    assert_eq!(
        transport.observed_url,
        "http://127.0.0.1:8787/api/probe/register",
    );
}

#[cfg(unix)]
#[test]
fn probe_registration_rejects_existing_bootstrap_symlink_without_overwriting_target() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let target_path = temp.path().join("target.toml");
    fs::write(&target_path, "log_level = \"debug\"\n").expect("target");
    symlink(&target_path, &bootstrap_config_path).expect("bootstrap symlink");
    let mut transport = RecordingTransport {
        observed_body: Vec::new(),
        observed_url: String::new(),
        response: registration_response(),
    };

    let error = register_probe(
        ProbeRegistrationInput {
            bootstrap_config_path,
            enrollment_token: "enk_enroll_secret".to_string(),
            hub_url: "https://hub.example".to_string(),
        },
        &mut transport,
    )
    .expect_err("bootstrap symlink is rejected");

    assert!(matches!(error, RegistrationError::Io(_)));
    assert_eq!(
        fs::read_to_string(target_path).expect("target unchanged"),
        "log_level = \"debug\"\n",
    );
}

fn all_collector_ids() -> Vec<String> {
    CollectorId::all_official()
        .iter()
        .map(|collector_id| collector_id.as_config_id().to_string())
        .collect()
}

fn registration_response() -> Vec<u8> {
    ProbeRegistrationResponse {
        enrollment_id: String::new(),
        host_id: "7".to_string(),
        installation_inspection: None,
        initial_configuration: Some(ProbeConfigurationResponse {
            enabled_collector_ids: all_collector_ids(),
            metrics_collection_interval_seconds: 5,
            version: "default-v1".to_string(),
        }),
        probe_id: "probe_01".to_string(),
        probe_secret: String::new(),
        server_time_ms: 1_725_000_000_000,
    }
    .encode_to_vec()
}

struct RecordingTransport {
    observed_body: Vec<u8>,
    observed_url: String,
    response: Vec<u8>,
}

struct ResponseLossThenSuccessTransport {
    attempts: usize,
    bodies: Vec<Vec<u8>>,
    response: Vec<u8>,
}

impl RegistrationTransport for ResponseLossThenSuccessTransport {
    fn post_protobuf(&mut self, _url: &str, body: Vec<u8>) -> Result<Vec<u8>, RegistrationError> {
        self.bodies.push(body);
        self.attempts += 1;
        if self.attempts == 1 {
            return Err(RegistrationError::Attempt(
                enoki_probe::transport::HttpAttemptError::Network(
                    "response lost after Hub commit".to_string(),
                ),
            ));
        }
        Ok(self.response.clone())
    }
}

impl RegistrationTransport for RecordingTransport {
    fn post_protobuf(&mut self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, RegistrationError> {
        self.observed_url = url.to_string();
        self.observed_body = body;

        Ok(self.response.clone())
    }
}

use std::fs;

#[cfg(unix)]
use std::os::unix::fs::symlink;

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
fn installation_inspection_uses_registration_without_generating_an_identity() {
    let response =
        ProbeRegistrationResponse {
            enrollment_id: String::new(),
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
                expected_probe_id: "probe_old_01".to_string(),
                source_probe_version: "1.2.2".to_string(),
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
                expected_probe_id: "probe_old_01".to_string(),
                source_probe_version: "1.2.2".to_string(),
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

impl RegistrationTransport for RecordingTransport {
    fn post_protobuf(&mut self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, RegistrationError> {
        self.observed_url = url.to_string();
        self.observed_body = body;

        Ok(self.response.clone())
    }
}

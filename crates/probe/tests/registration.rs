use std::fs;

use enoki_probe::{
    protocol::enoki::v1::{
        ProbeConfigurationResponse, ProbeRegistrationRequest, ProbeRegistrationResponse,
    },
    registration::{
        ProbeRegistrationInput, RegistrationError, RegistrationTransport, register_probe,
    },
};
use prost::Message;

#[test]
fn probe_registration_posts_protobuf_and_stores_probe_identity() {
    let temp = tempfile::tempdir().expect("temp dir");
    let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
    let response = ProbeRegistrationResponse {
        initial_configuration: Some(ProbeConfigurationResponse {
            collect_cpu: true,
            collect_disk: true,
            collect_load: true,
            collect_memory: true,
            collect_network: true,
            collect_uptime: true,
            metrics_collection_interval_seconds: 5,
            reporting_batch_interval_seconds: 15,
            version: "default-v1".to_string(),
        }),
        probe_id: "probe_01".to_string(),
        probe_secret: "enk_probe_secret".to_string(),
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
            hub_url: "https://hub.example/base/".to_string(),
        },
        &mut transport,
    )
    .expect("Probe registration succeeds");

    assert_eq!(outcome.probe_id, "probe_01");
    assert_eq!(
        transport.observed_url,
        "https://hub.example/base/api/probe/register",
    );
    assert!(!transport.observed_url.contains("enk_enroll_secret"));
    let request = ProbeRegistrationRequest::decode(transport.observed_body.as_slice())
        .expect("registration request decodes");
    assert_eq!(request.enrollment_token, "enk_enroll_secret");
    assert_eq!(request.inventory.expect("inventory").probe_version, "dev");

    let bootstrap_config =
        fs::read_to_string(bootstrap_config_path).expect("bootstrap config exists");
    assert!(bootstrap_config.contains("hub_url = \"https://hub.example/base/\""));
    assert!(bootstrap_config.contains("probe_id = \"probe_01\""));
    assert!(bootstrap_config.contains("probe_secret = \"enk_probe_secret\""));
    assert!(bootstrap_config.contains("reporting_batch_interval_seconds = 15"));
    assert!(!bootstrap_config.contains("enk_enroll_secret"));
    assert!(!bootstrap_config.contains("install_path"));
    assert!(!bootstrap_config.contains("operation_status_path"));
    assert!(!bootstrap_config.contains("service_name"));
    assert!(!bootstrap_config.contains("probe_asset_public_key_sha256"));
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
            "upgrader_launch = \"systemd\"",
            "log_level = \"debug\"",
            "",
        ]
        .join("\n"),
    )
    .expect("write installer bootstrap config");
    let response = ProbeRegistrationResponse {
        initial_configuration: Some(ProbeConfigurationResponse {
            collect_cpu: true,
            collect_disk: true,
            collect_load: true,
            collect_memory: true,
            collect_network: true,
            collect_uptime: true,
            metrics_collection_interval_seconds: 5,
            reporting_batch_interval_seconds: 15,
            version: "default-v1".to_string(),
        }),
        probe_id: "probe_01".to_string(),
        probe_secret: "enk_probe_secret".to_string(),
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
    assert!(bootstrap_config.contains("log_level = \"debug\""));
    assert!(!bootstrap_config.contains("enrollment_token"));
    assert!(!bootstrap_config.contains("enk_enroll_secret"));
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

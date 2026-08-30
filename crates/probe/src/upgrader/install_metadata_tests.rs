use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::Path,
};

use super::*;

fn legacy_metadata_contents(root: &Path) -> String {
    [
        "hub_url = \"https://hub.example\"".to_owned(),
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
            root.join("etc/sudoers.d/enoki-probe-operations").display()
        ),
        format!(
            "collector_helper_sudoers_path = \"{}\"",
            root.join("etc/sudoers.d/enoki-probe-collector-helpers")
                .display()
        ),
        format!("probe_asset_public_key_sha256 = \"{}\"", "a".repeat(64)),
        "service_name = \"enoki-probe\"".to_owned(),
        "service_user = \"enoki-probe\"".to_owned(),
        format!(
            "state_dir = \"{}\"",
            root.join("var/lib/enoki-probe").display()
        ),
    ]
    .join("\n")
}

fn schema_one_metadata_contents(root: &Path) -> String {
    [
        "schema_version = 1".to_owned(),
        format!(
            "identity_path = \"{}\"",
            root.join("etc/enoki/probe-bootstrap.toml").display()
        ),
        "service_group = \"enoki-probe\"".to_owned(),
        format!(
            "service_unit_path = \"{}\"",
            root.join("etc/systemd/system/enoki-probe.service")
                .display()
        ),
        legacy_metadata_contents(root),
    ]
    .join("\n")
}

fn schema_two_metadata_contents() -> String {
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
    ]
    .join("\n")
}

fn schema_three_metadata_contents() -> String {
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
    ]
    .join("\n")
}

fn schema_four_metadata_contents() -> String {
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

fn schema_five_metadata_contents() -> String {
    [
        schema_four_metadata_contents().replacen("schema_version = 4", "schema_version = 5", 1),
        format!("lifecycle_upgrade_service_unit_path = \"{LIFECYCLE_UPGRADE_SERVICE_UNIT_PATH}\""),
        format!("lifecycle_upgrade_socket_unit_path = \"{LIFECYCLE_UPGRADE_SOCKET_UNIT_PATH}\""),
        format!("lifecycle_authority_install_key = \"{}\"", "e".repeat(64)),
    ]
    .join("\n")
}

fn supported_schema_contents(root: &Path) -> [String; 5] {
    [
        schema_one_metadata_contents(root),
        schema_two_metadata_contents(),
        schema_three_metadata_contents(),
        schema_four_metadata_contents(),
        schema_five_metadata_contents(),
    ]
}

fn file_facts(mode: u32) -> TrustedFileMetadata {
    TrustedFileMetadata {
        is_regular_file: true,
        is_symlink: false,
        mode,
        owner_uid: 0,
    }
}

#[test]
fn supported_schema_metadata_requires_exact_private_mode() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("probe-install.toml");

    for (schema, contents) in supported_schema_contents(temp.path())
        .into_iter()
        .enumerate()
    {
        fs::write(&path, contents).expect("metadata");
        assert!(
            read_trusted_probe_install_metadata_read_only_with_file_metadata(
                &path,
                None,
                file_facts(0o600),
            )
            .is_ok(),
            "schema v{} accepts its exact private mode",
            schema + 1,
        );
        for mode in [0o644, 0o640] {
            assert!(
                matches!(
                    read_trusted_probe_install_metadata_read_only_with_file_metadata(
                        &path,
                        None,
                        file_facts(mode),
                    ),
                    Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
                ),
                "schema v{} rejects mode {mode:o}",
                schema + 1,
            );
        }
    }
}

#[test]
fn supported_schema_metadata_requires_a_root_owned_regular_non_symlink_file() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("probe-install.toml");

    for (schema, contents) in supported_schema_contents(temp.path())
        .into_iter()
        .enumerate()
    {
        fs::write(&path, contents).expect("metadata");
        for facts in [
            TrustedFileMetadata {
                is_symlink: true,
                ..file_facts(0o600)
            },
            TrustedFileMetadata {
                is_regular_file: false,
                ..file_facts(0o600)
            },
            TrustedFileMetadata {
                owner_uid: 1000,
                ..file_facts(0o600)
            },
        ] {
            assert!(
                matches!(
                    read_trusted_probe_install_metadata_read_only_with_file_metadata(
                        &path, None, facts,
                    ),
                    Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
                ),
                "schema v{} rejects untrusted file facts {facts:?}",
                schema + 1,
            );
        }
    }
}

#[test]
fn metadata_reader_uses_lstat_and_rejects_a_symlink_path() {
    let temp = tempfile::tempdir().expect("temp dir");
    let target = temp.path().join("target.toml");
    let link = temp.path().join("probe-install.toml");
    fs::write(&target, schema_five_metadata_contents()).expect("metadata target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("metadata mode");
    symlink(&target, &link).expect("metadata symlink");

    assert!(matches!(
        read_trusted_probe_install_metadata_read_only(&link, None),
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "metadata path must be a regular non-symlink file"
        ))
    ));
}

#[test]
fn only_legacy_metadata_accepts_the_documented_compatibility_modes() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("probe-install.toml");
    fs::write(&path, legacy_metadata_contents(temp.path())).expect("legacy metadata");

    for mode in [0o600, 0o644] {
        assert!(
            read_trusted_probe_install_metadata_read_only_with_file_metadata(
                &path,
                None,
                file_facts(mode),
            )
            .is_ok(),
            "legacy mode {mode:o} remains accepted",
        );
    }
    assert!(matches!(
        read_trusted_probe_install_metadata_read_only_with_file_metadata(
            &path,
            None,
            file_facts(0o640),
        ),
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "legacy metadata mode is not supported"
        ))
    ));
}

#[test]
fn legacy_preflight_is_read_only_for_metadata_bytes_mode_and_mtime() {
    let temp = tempfile::tempdir().expect("temp dir");
    let metadata_path = temp.path().join("probe-install.toml");
    let identity_path = temp.path().join("etc/enoki/probe-bootstrap.toml");
    fs::create_dir_all(identity_path.parent().expect("identity parent")).expect("identity parent");
    fs::write(&metadata_path, legacy_metadata_contents(temp.path())).expect("legacy metadata");
    fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o644)).expect("legacy mode");
    fs::write(
        &identity_path,
        [
            "hub_url = \"https://hub.example\"",
            "probe_id = \"probe_01\"",
            "probe_private_key_pem = \"test-private-key\"",
        ]
        .join("\n"),
    )
    .expect("identity");
    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600)).expect("identity mode");

    let before_bytes = fs::read(&metadata_path).expect("metadata bytes");
    let before = fs::metadata(&metadata_path).expect("metadata facts");
    let before_mode = before.permissions().mode() & 0o777;
    let before_mtime = (before.mtime(), before.mtime_nsec());

    assert_eq!(
        read_trusted_probe_install_preflight(&metadata_path, Some(temp.path()))
            .expect("legacy preflight"),
        TrustedProbeInstallPreflight {
            hub_url: "https://hub.example".to_owned(),
            probe_id: "probe_01".to_owned(),
        }
    );
    let after = fs::metadata(&metadata_path).expect("metadata facts");
    assert_eq!(
        fs::read(&metadata_path).expect("metadata bytes"),
        before_bytes
    );
    assert_eq!(after.permissions().mode() & 0o777, before_mode);
    assert_eq!((after.mtime(), after.mtime_nsec()), before_mtime);
}

#[test]
fn mutating_reader_migrates_only_authoritative_legacy_metadata() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join("probe-install.toml");
    let identity_path = temp.path().join("custom/probe-bootstrap.toml");
    fs::write(&path, legacy_metadata_contents(temp.path())).expect("legacy metadata");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("legacy mode");

    let migrated =
        read_trusted_probe_install_metadata(&path, Some(&identity_path)).expect("legacy migration");

    assert_eq!(migrated.schema_version, 1);
    assert_eq!(migrated.identity_path, identity_path);
    assert!(
        fs::read_to_string(&path)
            .expect("migrated metadata")
            .starts_with("schema_version = 1\n")
    );
    assert_eq!(
        fs::metadata(&path)
            .expect("migrated facts")
            .permissions()
            .mode()
            & 0o777,
        0o600,
    );
}

#[test]
fn metadata_parser_rejects_paths_and_names_that_cannot_authorize_cleanup() {
    let temp = tempfile::tempdir().expect("temp dir");
    let valid = schema_one_metadata_contents(temp.path());
    for invalid in [
        valid.replace(
            "service_user = \"enoki-probe\"",
            "service_user = \"../root\"",
        ),
        valid.replace(
            &format!(
                "install_path = \"{}\"",
                temp.path().join("usr/local/bin/enoki-probe").display()
            ),
            "install_path = \"/\"",
        ),
        valid.replace(
            &format!(
                "state_dir = \"{}\"",
                temp.path().join("var/lib/enoki-probe").display()
            ),
            "state_dir = \"/var/lib/../root\"",
        ),
    ] {
        assert!(matches!(
            parse_trusted_probe_install_metadata_with_legacy_identity(&invalid, None),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
        ));
    }
}

#[test]
fn signed_metadata_accepts_only_fixed_inventory_without_legacy_authority() {
    let schema_two = schema_two_metadata_contents();
    let schema_five = schema_five_metadata_contents();
    for invalid in [
        format!(
            "{schema_two}\nprobe_asset_public_key_sha256 = \"{}\"",
            "f".repeat(64)
        ),
        schema_five.replace(
            PRODUCTION_BOOTSTRAP_ACQUIRER_PATH,
            "/tmp/enoki-probe-bootstrap-acquire",
        ),
        schema_five.replace(PRODUCTION_BOOTSTRAP_STATE_DIR, "/tmp/enoki-probe-bootstrap"),
        format!(
            "{schema_five}\noperation_sudoers_path = \"{PRODUCTION_LEGACY_UPGRADER_SUDOERS_PATH}\""
        ),
    ] {
        assert!(matches!(
            parse_trusted_probe_install_metadata_with_legacy_identity(&invalid, None),
            Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
        ));
    }

    let legacy_claim = format!(
        "{}\nbootstrap_state_dir = \"{}\"",
        legacy_metadata_contents(Path::new("/fixture")),
        PRODUCTION_BOOTSTRAP_STATE_DIR,
    );
    assert!(matches!(
        parse_trusted_probe_install_metadata_with_legacy_identity(&legacy_claim, None),
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(_))
    ));
}

#[test]
fn unsupported_schema_keeps_the_repair_failure_classification_stable() {
    let error = parse_trusted_probe_install_metadata_with_legacy_identity(
        "schema_version = 6\nhub_url = \"https://hub.example\"",
        None,
    )
    .expect_err("future schema fails closed");

    assert_eq!(
        ProbeRepairRunError::from(error).code(),
        "probe_repair_metadata_unsupported",
    );
}

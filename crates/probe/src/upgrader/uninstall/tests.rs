use super::{
    CompanionBinaryFacts, PostCommitSelfFinalizeFacts, ResumeDecision, UninstallCapsulePhase,
    commit_lifecycle_capsule_with, lifecycle_response_from_resume_decision,
    persist_uninstall_capsule, post_commit_self_finalize_policy, read_uninstall_capsule,
    uninstall_capsule_path,
};
use crate::upgrader::{ProbeUpgraderRunError, TrustedProbeInstallMetadata};
use enoki_probe_bootstrap::lifecycle::{LifecycleRequest, LifecycleResponse};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

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
    let metadata_path = temporary.path().join("probe-install.toml");
    let capsule_path = uninstall_capsule_path(&metadata_path).expect("capsule path");
    let metadata = recovery_metadata(temporary.path());
    let request = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_42",
        "operation-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("bound request");

    persist_uninstall_capsule(
        &capsule_path,
        &request,
        &metadata,
        UninstallCapsulePhase::Verified,
    )
    .expect("verified capsule");
    persist_uninstall_capsule(
        &capsule_path,
        &request,
        &metadata,
        UninstallCapsulePhase::Prepared,
    )
    .expect("prepared capsule");
    let prepared = fs::read(&capsule_path).expect("prepared bytes");
    fs::remove_file(&capsule_path).expect("remove prepared capsule");
    fs::create_dir(&capsule_path).expect("inject persistence interruption");
    assert!(matches!(
        read_uninstall_capsule(&capsule_path),
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule is not a root-owned regular 0600 file"
        ))
    ));

    fs::remove_dir(&capsule_path).expect("remove interruption");
    fs::write(&capsule_path, prepared).expect("restore prepared capsule");
    fs::set_permissions(&capsule_path, fs::Permissions::from_mode(0o600)).expect("restore mode");
    let restored = read_uninstall_capsule(&capsule_path)
        .expect("read restored capsule")
        .expect("restored capsule");
    assert_eq!(restored.phase, UninstallCapsulePhase::Prepared);

    let conflicting = LifecycleRequest::hub_uninstall(
        "probe_01",
        "operation_takeover",
        "takeover-token",
        &"b".repeat(64),
        &"c".repeat(64),
        "1.2.3",
    )
    .expect("conflicting request");
    assert!(matches!(
        persist_uninstall_capsule(
            &capsule_path,
            &conflicting,
            &metadata,
            UninstallCapsulePhase::Prepared,
        ),
        Err(ProbeUpgraderRunError::InvalidInstallMetadata(
            "uninstall capsule belongs to another authority"
        ))
    ));
}

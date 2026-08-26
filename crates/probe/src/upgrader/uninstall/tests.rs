use super::{
    CompanionBinaryFacts, PostCommitSelfFinalizeFacts, ResumeDecision,
    commit_lifecycle_capsule_with, lifecycle_response_from_resume_decision,
    post_commit_self_finalize_policy,
};
use crate::upgrader::ProbeUpgraderRunError;
use enoki_probe_bootstrap::lifecycle::LifecycleResponse;
use std::path::Path;

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

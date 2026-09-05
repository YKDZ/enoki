use super::*;

struct UnusedTransport;

impl ProbeUpgraderValidationTransport for UnusedTransport {
    fn get_asset(&mut self, _: &str) -> Result<Vec<u8>, ProbeUpgraderRunError> {
        panic!("Compatible Upgrade 不得进入旧 Probe transport")
    }

    fn post_token_validation(
        &mut self,
        _: &str,
        _: &ProbeRequestAuth<'_>,
        _: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        panic!("Compatible Upgrade 不得进入旧 Probe transport")
    }

    fn post_operation_status(
        &mut self,
        _: &str,
        _: &ProbeRequestAuth<'_>,
        _: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        panic!("Compatible Upgrade 不得进入旧 Probe transport")
    }

    fn validate_probe_identity(
        &mut self,
        _: &str,
        _: &ProbeRequestAuth<'_>,
    ) -> Result<(), ProbeUpgraderRunError> {
        panic!("Compatible Upgrade 不得进入旧 Probe transport")
    }
}

fn expired_upgrade_request() -> LifecycleRequest {
    LifecycleRequest::hub_upgrade(
        "https://hub.example",
        "host_01",
        "probe_01",
        "operation_01",
        "1.2.2",
        &"a".repeat(64),
        &"b".repeat(64),
        "1.2.3",
        &format!("sha256:{}", "c".repeat(64)),
        &"d".repeat(64),
        &"e".repeat(64),
        1,
        "signed-authority",
    )
    .expect("升级 request")
}

#[test]
fn both_probe_upgrade_entries_observe_the_same_deep_owner_rejection() {
    let request = expired_upgrade_request();
    let expected = LifecycleResponse::failed("lifecycle.invalid_authority");
    let mut transport = UnusedTransport;

    assert_eq!(
        run_lifecycle_companion_from_peer_with_effective_uid(
            &request,
            &mut transport,
            Some(1000),
            EffectiveUid::test(0),
        ),
        expected,
    );
    assert_eq!(
        run_upgrade_lifecycle_companion_from_peer_with_effective_uid(
            &request,
            Some(1000),
            EffectiveUid::test(0),
        ),
        expected,
    );
}

#[test]
fn both_probe_upgrade_entries_preserve_peer_authority() {
    let request = expired_upgrade_request();
    let expected = LifecycleResponse::failed("lifecycle.invalid_authority");
    let mut transport = UnusedTransport;

    assert_eq!(
        run_lifecycle_companion_from_peer_with_effective_uid(
            &request,
            &mut transport,
            None,
            EffectiveUid::test(0),
        ),
        expected,
    );
    assert_eq!(
        run_upgrade_lifecycle_companion_from_peer_with_effective_uid(
            &request,
            None,
            EffectiveUid::test(0),
        ),
        expected,
    );
}

#[test]
fn fixed_upgrade_entry_rejects_every_other_transition() {
    let request =
        LifecycleRequest::local_uninstall("probe_01", &"a".repeat(64), &"b".repeat(64), "1.2.3")
            .expect("卸载 request");

    assert_eq!(
        run_upgrade_lifecycle_companion_from_peer_with_effective_uid(
            &request,
            Some(0),
            EffectiveUid::test(0),
        ),
        LifecycleResponse::not_enabled(),
    );
}

#[test]
fn effective_uid_gate_precedes_both_upgrade_entries() {
    let request = expired_upgrade_request();
    let expected = LifecycleResponse::failed("lifecycle.root_required");
    let mut transport = UnusedTransport;

    assert_eq!(
        run_lifecycle_companion_from_peer_with_effective_uid(
            &request,
            &mut transport,
            Some(1000),
            EffectiveUid::test(65534),
        ),
        expected,
    );
    assert_eq!(
        run_upgrade_lifecycle_companion_from_peer_with_effective_uid(
            &request,
            Some(1000),
            EffectiveUid::test(65534),
        ),
        expected,
    );
}

#[test]
fn public_entries_use_the_process_effective_uid() {
    let request = expired_upgrade_request();
    let owner = replacement::StandaloneLifecycleOwner::for_test();
    let expected = if unsafe { libc::geteuid() } == 0 {
        LifecycleResponse::failed("lifecycle.invalid_authority")
    } else {
        LifecycleResponse::failed("lifecycle.root_required")
    };
    let mut transport = UnusedTransport;

    assert_eq!(
        run_lifecycle_companion_from_peer(&owner, &request, &mut transport, Some(1000)),
        expected,
    );
    assert_eq!(
        run_upgrade_lifecycle_companion_from_peer(&owner, &request, Some(1000)),
        expected,
    );
}

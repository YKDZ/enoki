use enoki_probe_bootstrap::trust::{BootstrapRole, embedded_production_trust_for};

#[test]
fn boot_probe_build_binds_only_activator_trust() {
    assert!(embedded_production_trust_for(BootstrapRole::Activator).is_some());
    assert!(embedded_production_trust_for(BootstrapRole::Acquirer).is_none());
}

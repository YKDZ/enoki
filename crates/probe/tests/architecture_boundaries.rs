const PROBE_MAIN: &str = include_str!("../src/main.rs");
const PROBE_LIBRARY: &str = include_str!("../src/lib.rs");
const PROBE_RUNTIME: &str = include_str!("../src/runtime.rs");
const OBSERVATION_RUNTIME: &str = include_str!("../src/observation_runtime.rs");
const OBSERVATION_RUNTIME_BINARY: &str = include_str!("../src/bin/enoki-observation-runtime.rs");
const SYSTEM_STATE_PROVIDER_BINARY: &str =
    include_str!("../src/bin/enoki-cpu-resource-provider.rs");
const DISK_HEALTH_PROVIDER_BINARY: &str =
    include_str!("../src/bin/enoki-disk-health-resource-provider.rs");
const LOCAL_LIFECYCLE: &str = include_str!("../src/local_lifecycle.rs");
const UPGRADER: &str = include_str!("../src/upgrader.rs");

fn production_source(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

#[test]
fn probe_entry_and_runtime_only_coordinate_runtime_finalized_windows() {
    let probe_entry = production_source(PROBE_MAIN);
    assert!(probe_entry.contains("ProbeCommand::Run"));
    assert!(probe_entry.contains("run_probe_with_loop_control("));
    for forbidden in [
        "metrics::",
        "host_profile",
        "observation_runtime",
        "resource_sandbox",
        "privileged_collector",
        "smartctl",
    ] {
        assert!(
            !probe_entry.contains(forbidden),
            "Probe 入口不得导入或调用观测实现：{forbidden}",
        );
    }

    assert!(PROBE_RUNTIME.contains("request_finalized_window"));
    for forbidden in [
        "MetricCollector",
        "CollectorRegistry",
        "CollectorCadenceSchedule",
        "collect_disk_health_metrics_from_smartctl_json",
        "collect_temperature_celsius_from_sysfs",
        "collect_battery_metrics_from_sysfs",
        "fs::read_to_string(\"/proc",
        "Command::new(\"smartctl",
        "local_privilege_boundary",
        "privileged_collector_helpers",
    ] {
        assert!(
            !PROBE_RUNTIME.contains(forbidden),
            "Probe Runtime 不得包含观测实现：{forbidden}",
        );
    }
    assert!(!PROBE_LIBRARY.contains("pub mod local_privilege_boundary"));
    assert!(!PROBE_LIBRARY.contains("pub mod privileged_collector_helpers"));
}

#[test]
fn observation_roles_have_one_way_dependency_boundaries() {
    assert!(OBSERVATION_RUNTIME_BINARY.contains("ObservationRuntimeServer"));
    assert!(SYSTEM_STATE_PROVIDER_BINARY.contains("collect_temperature_inputs()"));
    assert!(SYSTEM_STATE_PROVIDER_BINARY.contains("collect_battery_supplies()"));
    assert!(DISK_HEALTH_PROVIDER_BINARY.contains("SMARTCTL_CANDIDATES"));

    let runtime = production_source(OBSERVATION_RUNTIME);
    for forbidden in [
        "probe_auth",
        "registration",
        "HttpRegistrationTransport",
        "post_protobuf",
        "local_lifecycle",
        "upgrader",
        "ProbeRunInput",
    ] {
        assert!(
            !runtime.contains(forbidden),
            "Observation Runtime 不得反向依赖 Probe 身份、Hub 传输或生命周期：{forbidden}",
        );
    }
}

#[test]
fn fresh_probe_installation_cannot_render_collector_helper_sudoers() {
    let lifecycle = production_source(LOCAL_LIFECYCLE);
    assert!(!lifecycle.contains("internal-render-collector-helper-sudoers"));
    assert!(!lifecycle.contains("write_collector_helper_sudoers("));
    assert!(lifecycle.contains("collector_helper_sudoers_path"));

    assert!(!UPGRADER.contains("fn write_collector_helper_sudoers"));
    assert!(UPGRADER.contains("fn remove_legacy_collector_helper_sudoers"));
}

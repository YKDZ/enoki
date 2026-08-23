const PROBE_MAIN: &str = include_str!("../src/main.rs");
const PROBE_LIBRARY: &str = include_str!("../src/lib.rs");
const PROBE_RUNTIME: &str = include_str!("../src/runtime.rs");
const OBSERVATION_RUNTIME: &str = include_str!("../src/observation_runtime.rs");
const OBSERVATION_RUNTIME_BINARY: &str = include_str!("../src/bin/enoki-observation-runtime.rs");
const SYSTEM_STATE_PROVIDER_BINARY: &str =
    include_str!("../src/bin/enoki-cpu-resource-provider.rs");
const DISK_HEALTH_PROVIDER_BINARY: &str =
    include_str!("../src/bin/enoki-disk-health-resource-provider.rs");
const DISK_HEALTH_CALCULATION: &str = include_str!("../src/metrics/disk_health.rs");
const LOCAL_LIFECYCLE: &str = include_str!("../src/local_lifecycle.rs");
const UPGRADER: &str = include_str!("../src/upgrader.rs");
const BOOTSTRAP_INSTALL: &str = include_str!("../../probe-bootstrap/src/install.rs");

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
    for forbidden in ["fs::canonicalize", "fs::read_dir"] {
        assert!(
            !DISK_HEALTH_CALCULATION.contains(forbidden),
            "Runtime 可达的磁盘健康计算不得打开主机资源：{forbidden}",
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

#[test]
fn fresh_install_and_probe_binary_have_no_legacy_operation_executor() {
    let bootstrap = production_source(BOOTSTRAP_INSTALL);
    for forbidden in [
        "operation_sudoers().as_bytes()",
        "fn operation_sudoers()",
        "upgrader_launch = \"systemd\"",
    ] {
        assert!(
            !bootstrap.contains(forbidden),
            "新安装不得创建旧 operation 权限入口：{forbidden}",
        );
    }

    let probe_entry = production_source(PROBE_MAIN);
    for forbidden in [
        "run_probe_local_install",
        "run_probe_upgrader",
        "run_probe_uninstaller",
        "run_local_probe_uninstall",
        "run_probe_repair",
    ] {
        assert!(
            !probe_entry.contains(forbidden),
            "Probe executable 入口不得执行旧 lifecycle 工具：{forbidden}",
        );
    }
    for forbidden in [
        "launch_systemd_probe_upgrader",
        "launch_systemd_probe_uninstaller",
        "SystemProbeUpgraderCommandRunner",
    ] {
        assert!(
            !production_source(PROBE_RUNTIME).contains(forbidden),
            "Probe Runtime 不得调用旧 systemd-run executor：{forbidden}",
        );
    }
}

#[test]
fn built_probe_does_not_link_legacy_lifecycle_execution_symbols() {
    let output = std::process::Command::new("nm")
        .arg("-C")
        .arg(env!("CARGO_BIN_EXE_enoki-probe"))
        .output()
        .expect("nm 可读取测试构建的 Probe binary");
    assert!(output.status.success(), "nm 必须成功");
    let symbols = String::from_utf8(output.stdout).expect("nm 输出为 UTF-8");
    for forbidden in [
        "run_probe_local_install",
        "run_probe_upgrader",
        "run_probe_uninstaller",
        "run_local_probe_uninstall",
        "run_probe_repair",
        "launch_systemd_probe_upgrader",
        "launch_systemd_probe_uninstaller",
        "SystemProbeUpgraderCommandRunner",
    ] {
        assert!(
            !symbols.contains(forbidden),
            "Probe binary 不得链接旧 lifecycle 执行符号：{forbidden}",
        );
    }
}

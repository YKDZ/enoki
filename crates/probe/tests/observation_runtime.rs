use enoki_probe::observation_runtime::{
    CPU_COUNTERS_RESOURCE, CpuCountersProvider, CpuCountersResourceResult, ObservationRuntime,
    ObservationWindowRequest, ResourceAccess, static_collector_registry,
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
        .resource(CPU_COUNTERS_RESOURCE)
        .expect("CPU counters Resource is build-fixed");
    assert_eq!(descriptor.access, ResourceAccess::CpuCounters);
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
fn every_due_attempt_has_its_own_immutable_success_or_typed_outcome() {
    struct MixedProvider {
        attempts: std::collections::VecDeque<
            Result<&'static str, enoki_probe::observation_runtime::CpuResourceAcquisitionFailure>,
        >,
    }
    impl CpuCountersProvider for MixedProvider {
        fn pull_cpu_counters(
            &mut self,
            _request: enoki_probe::observation_runtime::CpuCountersPullRequest,
        ) -> Result<
            CpuCountersResourceResult,
            enoki_probe::observation_runtime::CpuResourceAcquisitionFailure,
        > {
            let counters = self
                .attempts
                .pop_front()
                .expect("one result per due attempt")?;
            CpuCountersResourceResult::from_records(
                enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(counters).unwrap(),
            )
            .ok_or(enoki_probe::observation_runtime::CpuResourceAcquisitionFailure::Malformed)
        }
    }
    let mut runtime = ObservationRuntime::new(MixedProvider {
        attempts: [
            Ok("cpu 100 0 0 900 0 0 0 0\n"),
            Err(enoki_probe::observation_runtime::CpuResourceAcquisitionFailure::Unavailable),
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
    assert_eq!(
        result.attempts[1].cpu_resource_outcome,
        Some(enoki_probe::observation_runtime::CpuResourceAcquisitionFailure::Unavailable)
    );
    assert!(result.attempts[2].sample.is_some());
    assert_eq!(sleeper.sleeps, vec![Duration::from_secs(1); 3]);
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

impl CpuCountersProvider for RecordingCpuProvider {
    fn pull_cpu_counters(
        &mut self,
        _request: enoki_probe::observation_runtime::CpuCountersPullRequest,
    ) -> Result<
        CpuCountersResourceResult,
        enoki_probe::observation_runtime::CpuResourceAcquisitionFailure,
    > {
        self.calls += 1;
        CpuCountersResourceResult::from_records(
            enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(
                self.results.pop_front().expect("one result per request"),
            )
            .expect("typed CPU counters"),
        )
        .ok_or(enoki_probe::observation_runtime::CpuResourceAcquisitionFailure::Malformed)
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

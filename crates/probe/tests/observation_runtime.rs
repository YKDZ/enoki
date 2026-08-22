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

    let batch = runtime
        .collect_next_window(&mut sleeper)
        .expect("Runtime finalizes its own CPU window");

    assert_eq!(batch.len(), 3);
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
        .observe(ObservationWindowRequest::next())
        .expect("first bounded CPU observation succeeds");
    let second = runtime
        .observe(ObservationWindowRequest::next())
        .expect("second bounded CPU observation succeeds");

    let provider = runtime.into_provider();
    assert_eq!(provider.calls, 2);
    assert_eq!(first.cpu_percent, Some(0.0));
    assert_eq!(second.cpu_percent, Some(20.0));
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
    type Error = ();

    fn pull_cpu_counters(
        &mut self,
        _request: enoki_probe::observation_runtime::CpuCountersPullRequest,
    ) -> Result<CpuCountersResourceResult, Self::Error> {
        self.calls += 1;
        CpuCountersResourceResult::from_records(
            enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(
                self.results.pop_front().expect("one result per request"),
            )
            .expect("typed CPU counters"),
        )
        .ok_or(())
    }
}

#[derive(Default)]
struct RecordingSleeper {
    sleeps: Vec<Duration>,
}

impl enoki_probe::observation_runtime::ObservationRuntimeSleeper for RecordingSleeper {
    fn sleep(&mut self, duration: Duration) {
        self.sleeps.push(duration);
    }
}

use std::{os::unix::net::UnixListener, thread};

use enoki_probe::observation_runtime::{
    CpuCountersProvider, CpuCountersPullRequest, CpuCountersResourceResult,
    ObservationRuntimeServer, UnixObservationRuntimeClient,
};

#[test]
fn probe_side_client_gets_a_bounded_cpu_result_over_the_runtime_socket() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("runtime.sock");
    let listener = UnixListener::bind(&socket).expect("runtime socket binds");
    let server = thread::spawn(move || {
        let (connection, _) = listener.accept().expect("Probe connects");
        let mut sleeper = NoopSleeper;
        ObservationRuntimeServer::new(FixedCpuProvider)
            .serve_connection_with_sleeper(connection, &mut sleeper)
            .expect("Runtime returns one bounded result");
    });

    let samples = UnixObservationRuntimeClient::new(&socket, "dev")
        .request_finalized_window()
        .expect("Probe receives Runtime result");
    server.join().expect("Runtime exits cleanly");

    assert_eq!(samples.len(), 3);
    assert_eq!(samples[0].cpu_percent, Some(0.0));
    assert_eq!(samples[0].cpu_cores.len(), 1);
}

struct NoopSleeper;

impl enoki_probe::observation_runtime::ObservationRuntimeSleeper for NoopSleeper {
    fn sleep(&mut self, _duration: std::time::Duration) {}
}

struct FixedCpuProvider;

impl CpuCountersProvider for FixedCpuProvider {
    type Error = ();

    fn pull_cpu_counters(
        &mut self,
        _request: CpuCountersPullRequest,
    ) -> Result<CpuCountersResourceResult, Self::Error> {
        CpuCountersResourceResult::from_records(
            enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(
                "cpu  100 0 0 900 0 0 0 0 0 0\ncpu0 100 0 0 900 0 0 0 0 0 0\n",
            )
            .expect("typed CPU counters"),
        )
        .ok_or(())
    }
}

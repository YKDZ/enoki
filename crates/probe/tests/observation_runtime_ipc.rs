use std::{os::unix::net::UnixListener, thread};

use enoki_probe::observation_runtime::{
    ObservationRuntimeProgressNotifier, ObservationRuntimeServer, SystemStateProvider,
    SystemStatePullRequest, SystemStateResourceResult, UnixObservationRuntimeClient,
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

    let result = UnixObservationRuntimeClient::new(&socket, "dev")
        .request_finalized_window(std::time::Duration::from_secs(7), 1)
        .expect("Probe receives Runtime result");
    server.join().expect("Runtime exits cleanly");

    assert_eq!(result.attempts.len(), 3);
    assert_eq!(
        result.attempts[0].sample.as_ref().unwrap().cpu_percent,
        Some(0.0)
    );
    assert_eq!(
        result.attempts[0].sample.as_ref().unwrap().cpu_cores.len(),
        1
    );
    assert_eq!(
        result.attempts[0]
            .sample
            .as_ref()
            .unwrap()
            .memory_used_bytes,
        Some(4_096)
    );
    assert_eq!(
        result.attempts[0].sample.as_ref().unwrap().load_1,
        Some(1.0)
    );
    assert_eq!(
        result.attempts[0].sample.as_ref().unwrap().uptime_seconds,
        Some(123)
    );
}

#[test]
fn probe_gets_the_runtime_cached_host_profile_snapshot_over_the_same_closed_ipc() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("runtime.sock");
    let listener = UnixListener::bind(&socket).expect("runtime socket binds");
    let server = thread::spawn(move || {
        let (connection, _) = listener.accept().expect("Probe connects");
        let mut sleeper = NoopSleeper;
        ObservationRuntimeServer::new(FixedCpuProvider)
            .serve_connection_with_sleeper(connection, &mut sleeper)
            .expect("Runtime returns its cached Snapshot");
    });

    let result = UnixObservationRuntimeClient::new(&socket, "dev")
        .request_finalized_window(std::time::Duration::from_secs(5), 1)
        .expect("Probe receives the finalized Window");
    server.join().expect("Runtime exits cleanly");
    let snapshot = result.host_profile.expect("Runtime-produced Snapshot");
    assert_eq!(snapshot.hostname, "runtime-host");
}

#[test]
fn completed_window_reports_progress_during_each_bounded_cadence_and_attempt() {
    let directory = tempfile::tempdir().expect("temporary socket directory");
    let socket = directory.path().join("runtime.sock");
    let listener = UnixListener::bind(&socket).expect("runtime socket binds");
    let server = thread::spawn(move || {
        let (connection, _) = listener.accept().expect("Probe connects");
        let mut sleeper = NoopSleeper;
        let mut progress = RecordingProgress::default();
        ObservationRuntimeServer::new(FixedCpuProvider)
            .serve_connection_with_sleeper_and_progress(connection, &mut sleeper, &mut progress)
            .expect("Runtime returns one bounded result");
        progress.notifications
    });

    UnixObservationRuntimeClient::new(&socket, "dev")
        .request_finalized_window(std::time::Duration::from_secs(7), 1)
        .expect("Probe receives Runtime result");

    assert_eq!(server.join().expect("Runtime exits cleanly"), 6);
}

#[derive(Default)]
struct RecordingProgress {
    notifications: usize,
}

impl ObservationRuntimeProgressNotifier for RecordingProgress {
    fn notify_ready(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn notify_progress(&mut self) -> std::io::Result<()> {
        self.notifications += 1;
        Ok(())
    }
}

struct NoopSleeper;

impl enoki_probe::observation_runtime::ObservationRuntimeSleeper for NoopSleeper {
    fn sleep(&mut self, _duration: std::time::Duration) {}
}

struct FixedCpuProvider;

impl SystemStateProvider for FixedCpuProvider {
    fn pull_system_state(
        &mut self,
        _request: SystemStatePullRequest,
    ) -> Result<
        SystemStateResourceResult,
        enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
    > {
        SystemStateResourceResult::from_records(
            enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(
                "cpu  100 0 0 900 0 0 0 0 0 0\ncpu0 100 0 0 900 0 0 0 0 0 0\n",
            )
            .expect("typed CPU counters"),
        )
        .map(|result| {
            result
                .with_system_state(
                    Some(enoki_probe::metrics::LoadMetrics {
                        one: 1.0,
                        five: 0.5,
                        fifteen: 0.25,
                    }),
                    Some(enoki_probe::metrics::MemoryMetrics {
                        cache_bytes: 512,
                        swap_total_bytes: 1_024,
                        swap_used_bytes: 256,
                        total_bytes: 8_192,
                        used_bytes: 4_096,
                    }),
                    Some(123),
                )
                .with_host_profile_facts(
                    enoki_probe::protocol::enoki::v1::HostProfileResourceFacts {
                        architecture: "x86_64".to_owned(),
                        cpu_count: 1,
                        hostname: "runtime-host".to_owned(),
                        kernel: "6.8.0".to_owned(),
                        os: "linux".to_owned(),
                        ..Default::default()
                    },
                )
        })
        .ok_or(enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure::Malformed)
    }
}

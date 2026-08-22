use std::{
    collections::HashMap,
    fs,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use enoki_probe::{
    metrics::parse_linux_proc_stat_cpu_counters,
    observation_runtime::{
        CpuCountersProvider, CpuCountersPullRequest, CpuCountersResourceResult,
        CpuResourceAcquisitionFailure, ObservationRuntimeServer, ObservationRuntimeSleeper,
        UnixObservationRuntimeClient,
    },
    protocol::enoki::v1::{
        CpuResourceCollectionOutcome, CpuResourceCollectionOutcomeReason, MetricSample,
        ProbeReportRequest,
    },
};
use prost::Message;

const FIXTURE_ROLE: &str = "ENOKI_OBSERVATION_PROCESS_FIXTURE_ROLE";

#[test]
fn process_fixture_entrypoint() {
    match std::env::var(FIXTURE_ROLE).as_deref() {
        Ok("provider") => {
            let output = std::env::var("ENOKI_PROVIDER_FIXTURE_OUTPUT").unwrap();
            let attempt: usize = std::env::var("ENOKI_PROVIDER_FIXTURE_ATTEMPT")
                .unwrap()
                .parse()
                .unwrap();
            let value = match attempt {
                2 => "unavailable",
                1 => "cpu 100 0 0 900 0 0 0 0\ncpu0 100 0 0 900 0 0 0 0\n",
                _ => "cpu 130 0 0 970 0 0 0 0\ncpu0 130 0 0 970 0 0 0 0\n",
            };
            fs::write(output, value).unwrap();
        }
        Ok("runtime") => {
            let socket = std::env::var("ENOKI_RUNTIME_FIXTURE_SOCKET").unwrap();
            let trace = std::env::var("ENOKI_RUNTIME_FIXTURE_TRACE").unwrap();
            let executable = std::env::current_exe().unwrap();
            let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
            let (connection, _) = listener.accept().unwrap();
            let mut sleeper = TraceSleeper {
                trace: trace.into(),
            };
            ObservationRuntimeServer::new(ProcessProvider {
                attempt: 0,
                executable,
                output_directory: tempfile::tempdir().unwrap(),
            })
            .serve_connection_with_sleeper(connection, &mut sleeper)
            .unwrap();
        }
        _ => {}
    }
}

#[test]
fn probe_runtime_provider_process_chain_reports_sequence_outcomes_idempotently() {
    if std::env::var(FIXTURE_ROLE).is_ok() {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("runtime.sock");
    let trace = temporary.path().join("runtime.trace");
    let registration = FakeAuthenticatedHub::register();
    let mut runtime = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_fixture_entrypoint", "--nocapture"])
        .env(FIXTURE_ROLE, "runtime")
        .env("ENOKI_RUNTIME_FIXTURE_SOCKET", &socket)
        .env("ENOKI_RUNTIME_FIXTURE_TRACE", &trace)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }

    let window = UnixObservationRuntimeClient::new(&socket, "dev")
        .request_finalized_window(Duration::from_secs(200), 101)
        .unwrap();
    assert!(runtime.wait().unwrap().success());
    assert_eq!(fs::read_to_string(&trace).unwrap(), "200\n200\n200\n");
    assert_eq!(window.attempts.len(), 3);
    assert!(
        window.attempts[0]
            .sample
            .as_ref()
            .unwrap()
            .cpu_idle_percent
            .is_some()
    );
    assert_eq!(
        window.attempts[1].cpu_resource_outcome,
        Some(CpuResourceAcquisitionFailure::Unavailable)
    );
    assert!(window.attempts[2].sample.is_some());

    let metrics = window
        .attempts
        .iter()
        .map(|attempt| {
            let mut sample = MetricSample {
                sequence: attempt.sequence,
                collected_at_ms: attempt.sequence as i64,
                memory_used_bytes: Some(42),
                ..MetricSample::default()
            };
            if let Some(cpu) = &attempt.sample {
                sample.cpu_percent = cpu.cpu_percent;
                sample.cpu_idle_percent = cpu.cpu_idle_percent;
            }
            sample
        })
        .collect();
    let outcomes = window
        .attempts
        .iter()
        .filter_map(|attempt| {
            attempt
                .cpu_resource_outcome
                .map(|_| CpuResourceCollectionOutcome {
                    sequence: attempt.sequence,
                    reason: CpuResourceCollectionOutcomeReason::CpuResourceUnavailable as i32,
                })
        })
        .collect();
    let report = ProbeReportRequest {
        probe_id: registration.probe_id.clone(),
        boot_id: "boot-process-chain".into(),
        sequence_start: 101,
        sequence_end: 103,
        probe_configuration_version: "default-v1".into(),
        metrics,
        cpu_resource_collection_outcomes: outcomes,
        ..ProbeReportRequest::default()
    };
    let body = report.encode_to_vec();
    let mut hub = FakeAuthenticatedHub::default();
    assert!(hub.report(&registration.token, &body));
    assert!(hub.report(&registration.token, &body));
    assert_eq!(hub.receipts.len(), 1);
    let stored = hub.receipts.values().next().unwrap();
    assert_eq!(stored.cpu_resource_collection_outcomes[0].sequence, 102);
    assert!(
        stored
            .metrics
            .iter()
            .all(|sample| sample.memory_used_bytes == Some(42))
    );
}

struct TraceSleeper {
    trace: std::path::PathBuf,
}

impl ObservationRuntimeSleeper for TraceSleeper {
    fn sleep(&mut self, duration: Duration) {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.trace)
            .unwrap();
        writeln!(file, "{}", duration.as_secs()).unwrap();
    }

    fn now_ms(&self) -> i64 {
        1_000
    }
}

struct ProcessProvider {
    attempt: usize,
    executable: std::path::PathBuf,
    output_directory: tempfile::TempDir,
}

impl CpuCountersProvider for ProcessProvider {
    fn pull_cpu_counters(
        &mut self,
        _request: CpuCountersPullRequest,
    ) -> Result<CpuCountersResourceResult, CpuResourceAcquisitionFailure> {
        self.attempt += 1;
        let output = self
            .output_directory
            .path()
            .join(format!("{}.txt", self.attempt));
        let status = Command::new(&self.executable)
            .args(["--exact", "process_fixture_entrypoint", "--nocapture"])
            .env(FIXTURE_ROLE, "provider")
            .env("ENOKI_PROVIDER_FIXTURE_ATTEMPT", self.attempt.to_string())
            .env("ENOKI_PROVIDER_FIXTURE_OUTPUT", &output)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| CpuResourceAcquisitionFailure::Unavailable)?;
        if !status.success() {
            return Err(CpuResourceAcquisitionFailure::Unavailable);
        }
        let value =
            fs::read_to_string(output).map_err(|_| CpuResourceAcquisitionFailure::Unavailable)?;
        if value == "unavailable" {
            return Err(CpuResourceAcquisitionFailure::Unavailable);
        }
        CpuCountersResourceResult::from_records(
            parse_linux_proc_stat_cpu_counters(&value)
                .ok_or(CpuResourceAcquisitionFailure::Malformed)?,
        )
        .ok_or(CpuResourceAcquisitionFailure::Malformed)
    }
}

struct Registration {
    probe_id: String,
    token: String,
}

#[derive(Default)]
struct FakeAuthenticatedHub {
    receipts: HashMap<(String, String, u64, u64), ProbeReportRequest>,
}

impl FakeAuthenticatedHub {
    fn register() -> Registration {
        Registration {
            probe_id: "probe-process-chain".into(),
            token: "authenticated-report-token".into(),
        }
    }

    fn report(&mut self, token: &str, bytes: &[u8]) -> bool {
        if token != "authenticated-report-token" {
            return false;
        }
        let Ok(report) = ProbeReportRequest::decode(bytes) else {
            return false;
        };
        let key = (
            report.probe_id.clone(),
            report.boot_id.clone(),
            report.sequence_start,
            report.sequence_end,
        );
        match self.receipts.get(&key) {
            Some(existing) => existing == &report,
            None => {
                self.receipts.insert(key, report);
                true
            }
        }
    }
}

//! 构建期固定、单次有界的 CPU 观测 Runtime。

use std::{
    ffi::CStr,
    io::{self, Read, Write},
    os::fd::{AsRawFd, RawFd},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use prost::Message;

use crate::{
    metrics::{
        CpuCounterRecord, CpuCounterSnapshot, LoadMetrics, MemoryMetrics,
        collect_cpu_metrics_from_counter_records,
    },
    protocol::enoki::v1::{
        CollectorFailure, CollectorFailureCode, CollectorFailurePhase, CollectorOutcome,
        CollectorOutcomeState, HostProfileResourceFacts, HostProfileSnapshot, MetricSample,
    },
};

pub const SYSTEM_STATE_RESOURCE: &str = "official.system-state";
pub const MAX_SYSTEM_STATE_BYTES: usize = 64 * 1024;
pub const SYSTEM_STATE_PULL: &[u8] = b"enoki.system-state.v1\n";
pub const OBSERVATION_WINDOW_PULL: &[u8] = b"enoki.observation-window.v2\n";
pub const OBSERVATION_RUNTIME_SOCKET: &str = "/run/enoki-observation-runtime.sock";
pub const CPU_PROVIDER_SOCKET: &str = "/run/enoki-cpu-resource-provider.sock";
const MAX_RUNTIME_RESPONSE_BYTES: usize = 256 * 1024;
const PROVIDER_DEADLINE: Duration = Duration::from_secs(2);
const RUNTIME_REQUEST_DEADLINE: Duration = Duration::from_secs(3);
const RUNTIME_WINDOW_HEADROOM: Duration = Duration::from_secs(5);
const CPU_SAMPLES_PER_WINDOW: usize = 3;
const MIN_COLLECTION_CADENCE_SECONDS: u16 = 1;
const MAX_COLLECTION_CADENCE_SECONDS: u16 = 200;

pub trait ObservationRuntimeSleeper {
    fn sleep(&mut self, duration: Duration);
    fn now_ms(&self) -> i64 {
        unix_time_ms()
    }
}

pub struct ThreadObservationRuntimeSleeper;

impl ObservationRuntimeSleeper for ThreadObservationRuntimeSleeper {
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceAccess {
    SystemState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectorResourceDescriptor {
    pub id: &'static str,
    pub access: ResourceAccess,
    pub max_result_bytes: usize,
    pub max_results_per_attempt: u8,
    pub request_accepts_caller_input: bool,
}

const SYSTEM_STATE_DESCRIPTOR: CollectorResourceDescriptor = CollectorResourceDescriptor {
    id: SYSTEM_STATE_RESOURCE,
    access: ResourceAccess::SystemState,
    max_result_bytes: MAX_SYSTEM_STATE_BYTES,
    max_results_per_attempt: 1,
    request_accepts_caller_input: false,
};

/// 注册表是闭合的构建产物，不是运行时插件表。
pub struct StaticCollectorRegistry;

impl StaticCollectorRegistry {
    pub fn resource(&self, id: &str) -> Option<&'static CollectorResourceDescriptor> {
        match id {
            SYSTEM_STATE_RESOURCE => Some(&SYSTEM_STATE_DESCRIPTOR),
            _ => None,
        }
    }
}

pub fn static_collector_registry() -> StaticCollectorRegistry {
    StaticCollectorRegistry
}

/// CPU Provider 唯一接受的空请求，调用者无法注入路径、命令或次数。
pub struct SystemStatePullRequest(());

impl SystemStatePullRequest {
    fn fixed() -> Self {
        Self(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SystemStateResourceResult {
    counters: Option<Vec<CpuCounterRecord>>,
    load: Option<LoadMetrics>,
    memory: Option<MemoryMetrics>,
    uptime_seconds: Option<u64>,
    host_profile_facts: Option<HostProfileResourceFacts>,
}

impl SystemStateResourceResult {
    pub fn from_records(counters: Vec<CpuCounterRecord>) -> Option<Self> {
        (!counters.is_empty() && counters.len() <= 4096).then_some(Self {
            counters: Some(counters),
            load: None,
            memory: None,
            uptime_seconds: None,
            host_profile_facts: None,
        })
    }

    pub fn with_system_state(
        mut self,
        load: Option<LoadMetrics>,
        memory: Option<MemoryMetrics>,
        uptime_seconds: Option<u64>,
    ) -> Self {
        self.load = load;
        self.memory = memory;
        self.uptime_seconds = uptime_seconds;
        self
    }

    pub fn with_host_profile_facts(mut self, facts: HostProfileResourceFacts) -> Self {
        self.host_profile_facts = Some(facts);
        self
    }

    fn counters(&self) -> Option<&[CpuCounterRecord]> {
        self.counters.as_deref()
    }
}

pub trait SystemStateProvider {
    fn pull_system_state(
        &mut self,
        request: SystemStatePullRequest,
    ) -> Result<SystemStateResourceResult, SystemStateResourceAcquisitionFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemStateResourceAcquisitionFailure {
    ActivationBudgetExhausted,
    Malformed,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservationWindowRequest {
    cadence_seconds: u16,
    sequence_start: u64,
}

impl ObservationWindowRequest {
    pub fn new(cadence: Duration) -> Option<Self> {
        let seconds = cadence.as_secs();
        (cadence.subsec_nanos() == 0
            && seconds >= u64::from(MIN_COLLECTION_CADENCE_SECONDS)
            && seconds <= u64::from(MAX_COLLECTION_CADENCE_SECONDS))
        .then_some(Self {
            cadence_seconds: seconds as u16,
            sequence_start: 1,
        })
    }

    pub fn with_sequence_start(mut self, sequence_start: u64) -> Option<Self> {
        (sequence_start > 0 && sequence_start <= u64::MAX - 2).then(|| {
            self.sequence_start = sequence_start;
            self
        })
    }

    pub fn cadence(self) -> Duration {
        Duration::from_secs(u64::from(self.cadence_seconds))
    }
}

fn runtime_window_deadline(cadence: Duration) -> Option<Duration> {
    cadence
        .checked_mul(CPU_SAMPLES_PER_WINDOW as u32)?
        .checked_add(PROVIDER_DEADLINE.checked_mul(CPU_SAMPLES_PER_WINDOW as u32)?)?
        .checked_add(RUNTIME_WINDOW_HEADROOM)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationRuntimeFailure {
    CpuResourceUnavailable,
    CpuResourceMalformed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ObservationWindowResult {
    pub attempts: Vec<ObservationAttemptResult>,
    pub host_profile: Option<HostProfileSnapshot>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ObservationAttemptResult {
    pub sequence: u64,
    pub sample: Option<MetricSample>,
    pub cpu_resource_outcome: Option<SystemStateResourceAcquisitionFailure>,
}

/// Runtime 持有 Collector cadence、计算和跨窗口采样状态。
pub struct ObservationRuntime<P> {
    provider: P,
    previous_cpu_counters: Option<CpuCounterSnapshot>,
    host_profile: Option<HostProfileSnapshot>,
}

impl<P> ObservationRuntime<P>
where
    P: SystemStateProvider,
{
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            previous_cpu_counters: None,
            host_profile: None,
        }
    }

    pub fn observe(
        &mut self,
        request: ObservationWindowRequest,
    ) -> Result<MetricSample, ObservationRuntimeFailure> {
        self.observe_at(request, unix_time_ms())
            .map_err(|failure| match failure {
                SystemStateResourceAcquisitionFailure::Malformed => {
                    ObservationRuntimeFailure::CpuResourceMalformed
                }
                SystemStateResourceAcquisitionFailure::ActivationBudgetExhausted
                | SystemStateResourceAcquisitionFailure::Unavailable => {
                    ObservationRuntimeFailure::CpuResourceUnavailable
                }
            })
    }

    fn observe_at(
        &mut self,
        _request: ObservationWindowRequest,
        collected_at_ms: i64,
    ) -> Result<MetricSample, SystemStateResourceAcquisitionFailure> {
        // 一次尝试只激活一次 Provider；同一不可变结果同时派生 CPU 汇总、
        // 分项和每核心结果。
        let resource = self
            .provider
            .pull_system_state(SystemStatePullRequest::fixed())?;
        let mut sample = MetricSample {
            collected_at_ms,
            load_1: resource.load.as_ref().map(|value| value.one),
            load_5: resource.load.as_ref().map(|value| value.five),
            load_15: resource.load.as_ref().map(|value| value.fifteen),
            memory_total_bytes: resource.memory.as_ref().map(|value| value.total_bytes),
            memory_used_bytes: resource.memory.as_ref().map(|value| value.used_bytes),
            memory_cache_bytes: resource.memory.as_ref().map(|value| value.cache_bytes),
            swap_total_bytes: resource.memory.as_ref().map(|value| value.swap_total_bytes),
            swap_used_bytes: resource.memory.as_ref().map(|value| value.swap_used_bytes),
            uptime_seconds: resource.uptime_seconds,
            ..MetricSample::default()
        };
        if let Some(cpu) = resource.counters().and_then(|counters| {
            collect_cpu_metrics_from_counter_records(counters, self.previous_cpu_counters.as_ref())
        }) {
            self.previous_cpu_counters = Some(cpu.snapshot.clone());
            sample.cpu_cores = cpu.cores;
            sample.cpu_percent = Some(cpu.aggregate_percent);
            sample.cpu_idle_percent = Some(cpu.breakdown.idle_percent);
            sample.cpu_iowait_percent = Some(cpu.breakdown.iowait_percent);
            sample.cpu_steal_percent = Some(cpu.breakdown.steal_percent);
            sample.cpu_system_percent = Some(cpu.breakdown.system_percent);
            sample.cpu_user_percent = Some(cpu.breakdown.user_percent);
            sample.collector_outcomes.push(produced("official.cpu"));
        } else {
            sample.collector_outcomes.push(calculation_failed(
                "official.cpu",
                CollectorFailureCode::CpuCountersMalformed,
            ));
        }
        for (id, produced_value, code) in [
            (
                "official.load",
                resource.load.is_some(),
                CollectorFailureCode::LoadFactsMalformed,
            ),
            (
                "official.memory",
                resource.memory.is_some(),
                CollectorFailureCode::MemoryFactsMalformed,
            ),
            (
                "official.uptime",
                resource.uptime_seconds.is_some(),
                CollectorFailureCode::UptimeFactsMalformed,
            ),
        ] {
            sample.collector_outcomes.push(if produced_value {
                produced(id)
            } else {
                calculation_failed(id, code)
            });
        }
        if self.host_profile.is_none()
            && let Some(facts) = resource
                .host_profile_facts
                .filter(crate::host_profile::valid_host_profile_resource_facts)
        {
            self.host_profile = Some(crate::host_profile::host_profile_from_resource_facts(facts));
        }
        Ok(sample)
    }

    pub fn collect_next_window(
        &mut self,
        request: ObservationWindowRequest,
        sleeper: &mut impl ObservationRuntimeSleeper,
    ) -> ObservationWindowResult {
        let host_profile_due = self.host_profile.is_none();
        let mut attempts = Vec::with_capacity(CPU_SAMPLES_PER_WINDOW);
        for offset in 0..CPU_SAMPLES_PER_WINDOW {
            sleeper.sleep(request.cadence());
            match self.observe_at(request, sleeper.now_ms()) {
                Ok(mut sample) => {
                    if offset == 0 && host_profile_due {
                        sample
                            .collector_outcomes
                            .push(if self.host_profile.is_some() {
                                produced("official.host-profile")
                            } else {
                                calculation_failed(
                                    "official.host-profile",
                                    CollectorFailureCode::HostProfileFactsMalformed,
                                )
                            });
                    }
                    attempts.push(ObservationAttemptResult {
                        sequence: request.sequence_start + offset as u64,
                        sample: Some(sample),
                        cpu_resource_outcome: None,
                    })
                }
                Err(outcome) => {
                    let mut sample = resource_failure_sample(sleeper.now_ms(), outcome);
                    if offset == 0 && host_profile_due {
                        sample
                            .collector_outcomes
                            .push(host_profile_resource_failed(outcome));
                    }
                    attempts.push(ObservationAttemptResult {
                        sequence: request.sequence_start + offset as u64,
                        sample: Some(sample),
                        cpu_resource_outcome: None,
                    })
                }
            }
        }
        ObservationWindowResult {
            attempts,
            host_profile: self.host_profile.clone(),
        }
    }

    pub fn into_provider(self) -> P {
        self.provider
    }
}

pub struct UnixSystemStateProvider {
    socket_path: PathBuf,
}

impl UnixSystemStateProvider {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }
}

impl SystemStateProvider for UnixSystemStateProvider {
    fn pull_system_state(
        &mut self,
        _request: SystemStatePullRequest,
    ) -> Result<SystemStateResourceResult, SystemStateResourceAcquisitionFailure> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|error| {
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionRefused
            ) {
                SystemStateResourceAcquisitionFailure::ActivationBudgetExhausted
            } else {
                SystemStateResourceAcquisitionFailure::Unavailable
            }
        })?;
        configure_deadline(&stream, PROVIDER_DEADLINE)
            .map_err(|_| SystemStateResourceAcquisitionFailure::Unavailable)?;
        stream
            .write_all(SYSTEM_STATE_PULL)
            .map_err(|_| SystemStateResourceAcquisitionFailure::Unavailable)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| SystemStateResourceAcquisitionFailure::Unavailable)?;

        let len = read_u32(&mut stream)
            .map_err(|_| SystemStateResourceAcquisitionFailure::Unavailable)?
            as usize;
        if len == 0 || len > MAX_SYSTEM_STATE_BYTES {
            return Err(SystemStateResourceAcquisitionFailure::Malformed);
        }
        let mut encoded = vec![0; len];
        stream
            .read_exact(&mut encoded)
            .map_err(|_| SystemStateResourceAcquisitionFailure::Unavailable)?;
        if stream
            .read(&mut [0; 1])
            .map_err(|_| SystemStateResourceAcquisitionFailure::Unavailable)?
            != 0
        {
            return Err(SystemStateResourceAcquisitionFailure::Malformed);
        }
        decode_system_state_result(&encoded).ok_or(SystemStateResourceAcquisitionFailure::Malformed)
    }
}

fn decode_cpu_counter_records(bytes: &[u8]) -> Option<Vec<CpuCounterRecord>> {
    if bytes.len() < 2 || bytes.len() > MAX_SYSTEM_STATE_BYTES {
        return None;
    }
    let count = u16::from_be_bytes(bytes[..2].try_into().ok()?) as usize;
    if count == 0 || count > 4096 {
        return None;
    }
    let mut offset = 2;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len = *bytes.get(offset)? as usize;
        offset += 1;
        if name_len == 0 || name_len > 32 {
            return None;
        }
        let name = std::str::from_utf8(bytes.get(offset..offset + name_len)?)
            .ok()?
            .to_owned();
        offset += name_len;
        let mut fields = [0_u64; 8];
        for field in &mut fields {
            *field = u64::from_be_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?);
            offset += 8;
        }
        records.push(CpuCounterRecord {
            name,
            user: fields[0],
            nice: fields[1],
            system: fields[2],
            idle: fields[3],
            iowait: fields[4],
            irq: fields[5],
            softirq: fields[6],
            steal: fields[7],
        });
    }
    (offset == bytes.len()).then_some(records)
}

fn decode_system_state_result(bytes: &[u8]) -> Option<SystemStateResourceResult> {
    let cpu_len = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let cpu = bytes.get(4..4 + cpu_len)?;
    let state = bytes.get(4 + cpu_len..)?;
    let counters = decode_cpu_counter_records(cpu);
    if state.is_empty() {
        return Some(SystemStateResourceResult {
            counters,
            load: None,
            memory: None,
            uptime_seconds: None,
            host_profile_facts: None,
        });
    }
    let text = std::str::from_utf8(state).ok()?;
    let (load_text, rest) = text.split_once('\0')?;
    let (memory_text, rest) = rest.split_once('\0')?;
    let (uptime_text, profile_bytes) = rest.split_once('\0')?;
    let load = crate::metrics::collect_load_metrics_from_proc_loadavg(load_text);
    let memory = crate::metrics::collect_memory_metrics_from_proc_meminfo(memory_text);
    let uptime_seconds = crate::metrics::collect_uptime_seconds_from_proc_uptime(uptime_text);
    let profile_bytes = decode_hex(profile_bytes)?;
    let host_profile_facts = (!profile_bytes.is_empty())
        .then(|| HostProfileResourceFacts::decode(profile_bytes.as_slice()).ok())
        .flatten();
    Some(SystemStateResourceResult {
        counters,
        load,
        memory,
        uptime_seconds,
        host_profile_facts,
    })
}

fn produced(id: &str) -> CollectorOutcome {
    CollectorOutcome {
        collector_id: id.to_owned(),
        state: CollectorOutcomeState::Produced as i32,
        failure: None,
    }
}
fn calculation_failed(id: &str, code: CollectorFailureCode) -> CollectorOutcome {
    CollectorOutcome {
        collector_id: id.to_owned(),
        state: CollectorOutcomeState::Failed as i32,
        failure: Some(CollectorFailure {
            phase: CollectorFailurePhase::Calculation as i32,
            code: code as i32,
        }),
    }
}

fn resource_failure_sample(
    collected_at_ms: i64,
    failure: SystemStateResourceAcquisitionFailure,
) -> MetricSample {
    let code = match failure {
        SystemStateResourceAcquisitionFailure::Unavailable => {
            CollectorFailureCode::SystemStateUnavailable
        }
        SystemStateResourceAcquisitionFailure::Malformed => {
            CollectorFailureCode::SystemStateMalformed
        }
        SystemStateResourceAcquisitionFailure::ActivationBudgetExhausted => {
            CollectorFailureCode::SystemStateActivationBudgetExhausted
        }
    };
    MetricSample {
        collected_at_ms,
        collector_outcomes: [
            "official.cpu",
            "official.load",
            "official.memory",
            "official.uptime",
        ]
        .into_iter()
        .map(|id| CollectorOutcome {
            collector_id: id.to_owned(),
            state: CollectorOutcomeState::Failed as i32,
            failure: Some(CollectorFailure {
                phase: CollectorFailurePhase::Resource as i32,
                code: code as i32,
            }),
        })
        .collect(),
        ..MetricSample::default()
    }
}

fn host_profile_resource_failed(
    failure: SystemStateResourceAcquisitionFailure,
) -> CollectorOutcome {
    let code = match failure {
        SystemStateResourceAcquisitionFailure::Unavailable => {
            CollectorFailureCode::HostProfileResourceUnavailable
        }
        SystemStateResourceAcquisitionFailure::Malformed => {
            CollectorFailureCode::HostProfileFactsMalformed
        }
        SystemStateResourceAcquisitionFailure::ActivationBudgetExhausted => {
            CollectorFailureCode::HostProfileActivationBudgetExhausted
        }
    };
    CollectorOutcome {
        collector_id: "official.host-profile".to_owned(),
        state: CollectorOutcomeState::Failed as i32,
        failure: Some(CollectorFailure {
            phase: CollectorFailurePhase::Resource as i32,
            code: code as i32,
        }),
    }
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

pub struct ObservationRuntimeServer<P> {
    runtime: ObservationRuntime<P>,
}

impl<P> ObservationRuntimeServer<P>
where
    P: SystemStateProvider,
{
    pub fn new(provider: P) -> Self {
        Self {
            runtime: ObservationRuntime::new(provider),
        }
    }

    pub fn serve_connection(&mut self, stream: UnixStream) -> io::Result<()> {
        let mut sleeper = ThreadObservationRuntimeSleeper;
        self.serve_connection_with_sleeper(stream, &mut sleeper)
    }

    pub fn serve_connection_with_sleeper(
        &mut self,
        mut stream: UnixStream,
        sleeper: &mut impl ObservationRuntimeSleeper,
    ) -> io::Result<()> {
        configure_deadline(&stream, RUNTIME_REQUEST_DEADLINE)?;
        let Some(request) = read_runtime_request(&mut stream)? else {
            return write_window_failure(&mut stream);
        };
        let RuntimeRequest::Window(request) = request;
        configure_deadline(
            &stream,
            runtime_window_deadline(request.cadence()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "bounded Runtime deadline")
            })?,
        )?;
        let result = self.runtime.collect_next_window(request, sleeper);
        write_window_success(&mut stream, crate::version::probe_version(), &result)
    }

    pub fn serve_listener(&mut self, listener: &UnixListener) -> io::Result<()> {
        self.serve_listener_connections(listener, None)
    }

    fn serve_listener_connections(
        &mut self,
        listener: &UnixListener,
        maximum_connections: Option<usize>,
    ) -> io::Result<()> {
        self.serve_incoming(listener.incoming(), maximum_connections)
    }

    fn serve_incoming(
        &mut self,
        incoming: impl IntoIterator<Item = io::Result<UnixStream>>,
        maximum_connections: Option<usize>,
    ) -> io::Result<()> {
        let mut accepted = 0_usize;
        for connection in incoming {
            let connection = match connection {
                Ok(connection) => connection,
                Err(error) if recoverable_accept_error(&error) => continue,
                Err(error) => return Err(error),
            };
            let _ = self.serve_connection(connection);
            accepted += 1;
            if maximum_connections == Some(accepted) {
                break;
            }
        }
        Ok(())
    }

    pub fn serve_fixed_probe_listener(&mut self, listener: &UnixListener) -> io::Result<()> {
        for connection in listener.incoming() {
            let connection = match connection {
                Ok(connection) => connection,
                Err(error) if recoverable_accept_error(&error) => continue,
                Err(error) => return Err(error),
            };
            if require_peer_uid(connection.as_raw_fd(), c"enoki-probe").is_err() {
                continue;
            }
            let _ = self.serve_connection(connection);
        }
        Ok(())
    }
}

fn recoverable_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::WouldBlock
    )
}

/// 在接管 FD 所有权前闭合校验 systemd socket activation 合同。
pub fn validate_systemd_listener_fd(
    fd: RawFd,
    listen_pid: u32,
    listen_fds: usize,
) -> io::Result<()> {
    if listen_pid != std::process::id() || listen_fds != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "systemd activation identity or descriptor count is invalid",
        ));
    }
    let mut socket_type = 0_i32;
    let mut option_length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: getsockopt 只写入固定大小的整数缓冲区。
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut i32).cast(),
            &mut option_length,
        )
    } != 0
        || option_length as usize != std::mem::size_of::<i32>()
        || socket_type != libc::SOCK_STREAM
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "activation descriptor is not a stream socket",
        ));
    }
    let mut accepting = 0_i32;
    option_length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: getsockopt 只写入固定大小的整数缓冲区。
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut accepting as *mut i32).cast(),
            &mut option_length,
        )
    } != 0
        || accepting != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "activation descriptor is not listening",
        ));
    }
    // SAFETY: sockaddr_storage 足以容纳 getsockname 返回的任意 socket 地址。
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: 地址缓冲区及其长度均有效且可写。
    if unsafe {
        libc::getsockname(
            fd,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_length,
        )
    } != 0
        || address.ss_family != libc::AF_UNIX as libc::sa_family_t
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "activation descriptor is not a Unix socket",
        ));
    }
    Ok(())
}

pub fn require_peer_uid(socket_fd: RawFd, expected_user: &CStr) -> io::Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: 目标是有效的 Unix socket，凭据缓冲区及长度均可写。
    if unsafe {
        libc::getsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 用户名是固定的 NUL 结尾字符串，返回记录仅在本函数内读取。
    let expected = unsafe { libc::getpwnam(expected_user.as_ptr()) };
    if expected.is_null() || credentials.uid != unsafe { (*expected).pw_uid } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected Unix peer identity",
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub struct UnixObservationRuntimeClient {
    socket_path: PathBuf,
    expected_bundle_version: String,
}

pub trait ObservationWindowClient: Sync {
    fn request_finalized_window(
        &self,
        cadence: Duration,
        sequence_start: u64,
    ) -> Result<ObservationWindowResult, ObservationClientError>;
}

impl ObservationWindowClient for UnixObservationRuntimeClient {
    fn request_finalized_window(
        &self,
        cadence: Duration,
        sequence_start: u64,
    ) -> Result<ObservationWindowResult, ObservationClientError> {
        UnixObservationRuntimeClient::request_finalized_window(self, cadence, sequence_start)
    }
}

impl UnixObservationRuntimeClient {
    pub fn production() -> Self {
        Self::new(OBSERVATION_RUNTIME_SOCKET, crate::version::probe_version())
    }

    pub fn new(
        socket_path: impl Into<PathBuf>,
        expected_bundle_version: impl Into<String>,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            expected_bundle_version: expected_bundle_version.into(),
        }
    }

    pub fn request_finalized_window(
        &self,
        cadence: Duration,
        sequence_start: u64,
    ) -> Result<ObservationWindowResult, ObservationClientError> {
        let request = ObservationWindowRequest::new(cadence)
            .and_then(|request| request.with_sequence_start(sequence_start))
            .ok_or(ObservationClientError::InvalidRequest)?;
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|_| ObservationClientError::Unavailable)?;
        configure_deadline(
            &stream,
            runtime_window_deadline(cadence).ok_or(ObservationClientError::InvalidRequest)?,
        )
        .map_err(|_| ObservationClientError::Unavailable)?;
        stream
            .write_all(&encode_window_request(request))
            .map_err(|_| ObservationClientError::Unavailable)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| ObservationClientError::Unavailable)?;
        let mut status = [0; 1];
        stream
            .read_exact(&mut status)
            .map_err(|_| ObservationClientError::Unavailable)?;
        if status[0] != 0 {
            return Err(ObservationClientError::WindowFailed);
        }
        let version_len =
            read_u16(&mut stream).map_err(|_| ObservationClientError::InvalidResponse)? as usize;
        if version_len == 0 || version_len > 128 {
            return Err(ObservationClientError::InvalidResponse);
        }
        let mut version = vec![0; version_len];
        stream
            .read_exact(&mut version)
            .map_err(|_| ObservationClientError::InvalidResponse)?;
        if String::from_utf8(version).map_err(|_| ObservationClientError::InvalidResponse)?
            != self.expected_bundle_version
        {
            return Err(ObservationClientError::BundleIncoherent);
        }
        let host_profile_len =
            read_u32(&mut stream).map_err(|_| ObservationClientError::InvalidResponse)? as usize;
        let host_profile = if host_profile_len == 0 {
            None
        } else {
            if host_profile_len > MAX_RUNTIME_RESPONSE_BYTES {
                return Err(ObservationClientError::InvalidResponse);
            }
            let mut encoded = vec![0; host_profile_len];
            stream
                .read_exact(&mut encoded)
                .map_err(|_| ObservationClientError::InvalidResponse)?;
            Some(
                HostProfileSnapshot::decode(encoded.as_slice())
                    .map_err(|_| ObservationClientError::InvalidResponse)?,
            )
        };
        let attempt_count =
            read_u16(&mut stream).map_err(|_| ObservationClientError::InvalidResponse)?;
        if attempt_count as usize != CPU_SAMPLES_PER_WINDOW {
            return Err(ObservationClientError::InvalidResponse);
        }
        let mut attempts = Vec::with_capacity(attempt_count as usize);
        for offset in 0..attempt_count {
            let sequence =
                read_u64(&mut stream).map_err(|_| ObservationClientError::InvalidResponse)?;
            if sequence != sequence_start + u64::from(offset) {
                return Err(ObservationClientError::InvalidResponse);
            }
            let mut outcome = [0; 1];
            stream
                .read_exact(&mut outcome)
                .map_err(|_| ObservationClientError::InvalidResponse)?;
            let cpu_resource_outcome = match outcome[0] {
                0 => None,
                1 => Some(SystemStateResourceAcquisitionFailure::Unavailable),
                2 => Some(SystemStateResourceAcquisitionFailure::Malformed),
                3 => Some(SystemStateResourceAcquisitionFailure::ActivationBudgetExhausted),
                _ => return Err(ObservationClientError::InvalidResponse),
            };
            let sample = if cpu_resource_outcome.is_none() {
                let encoded_len = read_u32(&mut stream)
                    .map_err(|_| ObservationClientError::InvalidResponse)?
                    as usize;
                if encoded_len == 0 || encoded_len > MAX_RUNTIME_RESPONSE_BYTES {
                    return Err(ObservationClientError::InvalidResponse);
                }
                let mut encoded = vec![0; encoded_len];
                stream
                    .read_exact(&mut encoded)
                    .map_err(|_| ObservationClientError::InvalidResponse)?;
                Some(
                    MetricSample::decode(encoded.as_slice())
                        .map_err(|_| ObservationClientError::InvalidResponse)?,
                )
            } else {
                None
            };
            attempts.push(ObservationAttemptResult {
                sequence,
                sample,
                cpu_resource_outcome,
            });
        }
        if stream
            .read(&mut [0; 1])
            .map_err(|_| ObservationClientError::InvalidResponse)?
            != 0
        {
            return Err(ObservationClientError::InvalidResponse);
        }
        Ok(ObservationWindowResult {
            attempts,
            host_profile,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationClientError {
    BundleIncoherent,
    InvalidResponse,
    InvalidRequest,
    Unavailable,
    WindowFailed,
}

fn configure_deadline(stream: &UnixStream, deadline: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(deadline))?;
    stream.set_write_timeout(Some(deadline))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeRequest {
    Window(ObservationWindowRequest),
}

fn read_runtime_request(stream: &mut UnixStream) -> io::Result<Option<RuntimeRequest>> {
    let max_request = OBSERVATION_WINDOW_PULL.len() + 10;
    let mut request = Vec::with_capacity(max_request);
    stream
        .take((max_request + 1) as u64)
        .read_to_end(&mut request)?;
    if request.len() != OBSERVATION_WINDOW_PULL.len() + 10
        || !request.starts_with(OBSERVATION_WINDOW_PULL)
    {
        return Ok(None);
    }
    let cadence_offset = OBSERVATION_WINDOW_PULL.len();
    let seconds = u16::from_be_bytes(
        request[cadence_offset..cadence_offset + 2]
            .try_into()
            .unwrap(),
    );
    let sequence_start = u64::from_be_bytes(request[cadence_offset + 2..].try_into().unwrap());
    Ok(
        ObservationWindowRequest::new(Duration::from_secs(u64::from(seconds)))
            .and_then(|request| request.with_sequence_start(sequence_start))
            .map(RuntimeRequest::Window),
    )
}

fn encode_window_request(request: ObservationWindowRequest) -> Vec<u8> {
    let mut encoded = OBSERVATION_WINDOW_PULL.to_vec();
    encoded.extend_from_slice(&request.cadence_seconds.to_be_bytes());
    encoded.extend_from_slice(&request.sequence_start.to_be_bytes());
    encoded
}

fn write_window_success(
    stream: &mut UnixStream,
    version: &str,
    result: &ObservationWindowResult,
) -> io::Result<()> {
    let version = version.as_bytes();
    let encoded = result
        .attempts
        .iter()
        .map(|attempt| attempt.sample.as_ref().map(Message::encode_to_vec))
        .collect::<Vec<_>>();
    let host_profile = result.host_profile.as_ref().map(Message::encode_to_vec);
    if version.is_empty()
        || version.len() > u16::MAX as usize
        || encoded.len() != CPU_SAMPLES_PER_WINDOW
        || result
            .attempts
            .windows(2)
            .any(|pair| pair[1].sequence != pair[0].sequence + 1)
        || result
            .attempts
            .iter()
            .any(|attempt| attempt.sample.is_some() == attempt.cpu_resource_outcome.is_some())
        || encoded
            .iter()
            .flatten()
            .any(|sample| sample.is_empty() || sample.len() > MAX_RUNTIME_RESPONSE_BYTES)
        || host_profile
            .as_ref()
            .is_some_and(|profile| profile.is_empty() || profile.len() > MAX_RUNTIME_RESPONSE_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded Runtime response",
        ));
    }
    stream.write_all(&[0])?;
    stream.write_all(&(version.len() as u16).to_be_bytes())?;
    stream.write_all(version)?;
    stream.write_all(
        &u32::try_from(host_profile.as_ref().map_or(0, Vec::len))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bounded Host Profile"))?
            .to_be_bytes(),
    )?;
    if let Some(host_profile) = host_profile {
        stream.write_all(&host_profile)?;
    }
    stream.write_all(&(result.attempts.len() as u16).to_be_bytes())?;
    for (attempt, sample) in result.attempts.iter().zip(encoded) {
        stream.write_all(&attempt.sequence.to_be_bytes())?;
        stream.write_all(&[match attempt.cpu_resource_outcome {
            None => 0,
            Some(SystemStateResourceAcquisitionFailure::Unavailable) => 1,
            Some(SystemStateResourceAcquisitionFailure::Malformed) => 2,
            Some(SystemStateResourceAcquisitionFailure::ActivationBudgetExhausted) => 3,
        }])?;
        if let Some(sample) = sample {
            stream.write_all(&(sample.len() as u32).to_be_bytes())?;
            stream.write_all(&sample)?;
        }
    }
    stream.flush()
}

fn unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn write_window_failure(stream: &mut UnixStream) -> io::Result<()> {
    stream.write_all(&[1])?;
    stream.flush()
}

fn read_u16(stream: &mut UnixStream) -> io::Result<u16> {
    let mut bytes = [0; 2];
    stream.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(stream: &mut UnixStream) -> io::Result<u32> {
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(stream: &mut UnixStream) -> io::Result<u64> {
    let mut bytes = [0; 8];
    stream.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        os::fd::AsRawFd,
        os::unix::net::{UnixListener, UnixStream},
    };

    use super::*;

    struct UnusedProvider;

    impl SystemStateProvider for UnusedProvider {
        fn pull_system_state(
            &mut self,
            _request: SystemStatePullRequest,
        ) -> Result<SystemStateResourceResult, SystemStateResourceAcquisitionFailure> {
            Err(SystemStateResourceAcquisitionFailure::Unavailable)
        }
    }

    #[test]
    fn one_broken_connection_does_not_end_the_runtime_listener() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let socket = temporary.path().join("runtime.sock");
        let listener = UnixListener::bind(&socket).expect("listener");
        let server = std::thread::spawn(move || {
            ObservationRuntimeServer::new(UnusedProvider)
                .serve_listener_connections(&listener, Some(2))
        });

        let mut broken = UnixStream::connect(&socket).expect("first connection");
        broken.write_all(b"malformed").expect("first request");
        drop(broken);

        let mut accepted = UnixStream::connect(&socket).expect("second connection");
        accepted.write_all(b"malformed").expect("second request");
        accepted
            .shutdown(std::net::Shutdown::Write)
            .expect("finish request");
        let mut status = [0_u8; 1];
        accepted.read_exact(&mut status).expect("failure response");
        assert_eq!(status, [1]);
        server
            .join()
            .expect("server thread")
            .expect("listener stays up");
    }

    #[test]
    fn recoverable_accept_errors_continue_but_listener_failures_exit() {
        let accepted = UnixStream::pair().expect("Unix stream pair");
        let mut peer = accepted.1;
        peer.write_all(b"malformed").expect("request");
        peer.shutdown(std::net::Shutdown::Write)
            .expect("finish request");
        ObservationRuntimeServer::new(UnusedProvider)
            .serve_incoming(
                [
                    Err(io::Error::from(io::ErrorKind::Interrupted)),
                    Err(io::Error::from(io::ErrorKind::ConnectionAborted)),
                    Ok(accepted.0),
                ],
                Some(1),
            )
            .expect("recoverable accept errors are connection-local");

        let failure = ObservationRuntimeServer::new(UnusedProvider)
            .serve_incoming(
                [Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "listener is invalid",
                ))],
                None,
            )
            .expect_err("listener-level errors stop the runtime");
        assert_eq!(failure.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn activation_fd_must_be_the_single_listening_unix_stream() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let listener =
            UnixListener::bind(temporary.path().join("runtime.sock")).expect("Unix listener");
        validate_systemd_listener_fd(listener.as_raw_fd(), std::process::id(), 1)
            .expect("valid activation descriptor");
        assert!(
            validate_systemd_listener_fd(listener.as_raw_fd(), std::process::id() + 1, 1).is_err()
        );
        assert!(validate_systemd_listener_fd(listener.as_raw_fd(), std::process::id(), 2).is_err());

        let (stream, _) = UnixStream::pair().expect("Unix stream pair");
        assert!(validate_systemd_listener_fd(stream.as_raw_fd(), std::process::id(), 1).is_err());
        let tcp = TcpListener::bind("127.0.0.1:0").expect("TCP listener");
        assert!(validate_systemd_listener_fd(tcp.as_raw_fd(), std::process::id(), 1).is_err());
    }

    #[test]
    fn window_deadline_covers_all_attempts_at_both_valid_cadence_bounds() {
        assert_eq!(
            runtime_window_deadline(Duration::from_secs(1)),
            Some(Duration::from_secs(14))
        );
        assert_eq!(
            runtime_window_deadline(Duration::from_secs(200)),
            Some(Duration::from_secs(611))
        );
        assert!(ObservationWindowRequest::new(Duration::from_secs(1)).is_some());
        assert!(ObservationWindowRequest::new(Duration::from_secs(200)).is_some());
    }
}

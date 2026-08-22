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
    metrics::{CpuCounterRecord, CpuCounterSnapshot, collect_cpu_metrics_from_counter_records},
    protocol::enoki::v1::MetricSample,
};

pub const CPU_COUNTERS_RESOURCE: &str = "official.cpu-counters";
pub const MAX_CPU_COUNTERS_BYTES: usize = 64 * 1024;
pub const CPU_COUNTERS_PULL: &[u8] = b"enoki.cpu-counters.v1\n";
pub const OBSERVATION_WINDOW_PULL: &[u8] = b"enoki.observation-window.v2\n";
pub const OBSERVATION_RUNTIME_SOCKET: &str = "/run/enoki-observation-runtime.sock";
pub const CPU_PROVIDER_SOCKET: &str = "/run/enoki-cpu-resource-provider.sock";
const MAX_RUNTIME_RESPONSE_BYTES: usize = 256 * 1024;
const PROVIDER_DEADLINE: Duration = Duration::from_secs(2);
const RUNTIME_WINDOW_DEADLINE: Duration = Duration::from_secs(20);
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
    CpuCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectorResourceDescriptor {
    pub id: &'static str,
    pub access: ResourceAccess,
    pub max_result_bytes: usize,
    pub max_results_per_attempt: u8,
    pub request_accepts_caller_input: bool,
}

const CPU_COUNTERS_DESCRIPTOR: CollectorResourceDescriptor = CollectorResourceDescriptor {
    id: CPU_COUNTERS_RESOURCE,
    access: ResourceAccess::CpuCounters,
    max_result_bytes: MAX_CPU_COUNTERS_BYTES,
    max_results_per_attempt: 1,
    request_accepts_caller_input: false,
};

/// 注册表是闭合的构建产物，不是运行时插件表。
pub struct StaticCollectorRegistry;

impl StaticCollectorRegistry {
    pub fn resource(&self, id: &str) -> Option<&'static CollectorResourceDescriptor> {
        (id == CPU_COUNTERS_RESOURCE).then_some(&CPU_COUNTERS_DESCRIPTOR)
    }
}

pub fn static_collector_registry() -> StaticCollectorRegistry {
    StaticCollectorRegistry
}

/// CPU Provider 唯一接受的空请求，调用者无法注入路径、命令或次数。
pub struct CpuCountersPullRequest(());

impl CpuCountersPullRequest {
    fn fixed() -> Self {
        Self(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CpuCountersResourceResult {
    counters: Vec<CpuCounterRecord>,
}

impl CpuCountersResourceResult {
    pub fn from_records(counters: Vec<CpuCounterRecord>) -> Option<Self> {
        (!counters.is_empty() && counters.len() <= 4096).then_some(Self { counters })
    }

    fn counters(&self) -> &[CpuCounterRecord] {
        &self.counters
    }
}

pub trait CpuCountersProvider {
    fn pull_cpu_counters(
        &mut self,
        request: CpuCountersPullRequest,
    ) -> Result<CpuCountersResourceResult, CpuResourceAcquisitionFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuResourceAcquisitionFailure {
    ActivationBudgetExhausted,
    Malformed,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservationWindowRequest {
    cadence_seconds: u16,
}

impl ObservationWindowRequest {
    pub fn new(cadence: Duration) -> Option<Self> {
        let seconds = cadence.as_secs();
        (cadence.subsec_nanos() == 0
            && seconds >= u64::from(MIN_COLLECTION_CADENCE_SECONDS)
            && seconds <= u64::from(MAX_COLLECTION_CADENCE_SECONDS))
        .then_some(Self {
            cadence_seconds: seconds as u16,
        })
    }

    pub fn cadence(self) -> Duration {
        Duration::from_secs(u64::from(self.cadence_seconds))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationRuntimeFailure {
    CpuResourceUnavailable,
    CpuResourceMalformed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ObservationWindowResult {
    pub cpu_resource_outcome: Option<CpuResourceAcquisitionFailure>,
    pub samples: Vec<MetricSample>,
}

/// Runtime 持有 Collector cadence、计算和跨窗口采样状态。
pub struct ObservationRuntime<P> {
    provider: P,
    previous_cpu_counters: Option<CpuCounterSnapshot>,
}

impl<P> ObservationRuntime<P>
where
    P: CpuCountersProvider,
{
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            previous_cpu_counters: None,
        }
    }

    pub fn observe(
        &mut self,
        request: ObservationWindowRequest,
    ) -> Result<MetricSample, ObservationRuntimeFailure> {
        self.observe_at(request, unix_time_ms())
            .map_err(|failure| match failure {
                CpuResourceAcquisitionFailure::Malformed => {
                    ObservationRuntimeFailure::CpuResourceMalformed
                }
                CpuResourceAcquisitionFailure::ActivationBudgetExhausted
                | CpuResourceAcquisitionFailure::Unavailable => {
                    ObservationRuntimeFailure::CpuResourceUnavailable
                }
            })
    }

    fn observe_at(
        &mut self,
        _request: ObservationWindowRequest,
        collected_at_ms: i64,
    ) -> Result<MetricSample, CpuResourceAcquisitionFailure> {
        // 一次尝试只激活一次 Provider；同一不可变结果同时派生 CPU 汇总、
        // 分项和每核心结果。
        let resource = self
            .provider
            .pull_cpu_counters(CpuCountersPullRequest::fixed())?;
        let cpu = collect_cpu_metrics_from_counter_records(
            resource.counters(),
            self.previous_cpu_counters.as_ref(),
        )
        .ok_or(CpuResourceAcquisitionFailure::Malformed)?;
        self.previous_cpu_counters = Some(cpu.snapshot.clone());

        Ok(MetricSample {
            collected_at_ms,
            cpu_cores: cpu.cores,
            cpu_percent: Some(cpu.aggregate_percent),
            cpu_idle_percent: Some(cpu.breakdown.idle_percent),
            cpu_iowait_percent: Some(cpu.breakdown.iowait_percent),
            cpu_steal_percent: Some(cpu.breakdown.steal_percent),
            cpu_system_percent: Some(cpu.breakdown.system_percent),
            cpu_user_percent: Some(cpu.breakdown.user_percent),
            ..MetricSample::default()
        })
    }

    pub fn collect_next_window(
        &mut self,
        request: ObservationWindowRequest,
        sleeper: &mut impl ObservationRuntimeSleeper,
    ) -> ObservationWindowResult {
        let mut samples = Vec::with_capacity(CPU_SAMPLES_PER_WINDOW);
        for _ in 0..CPU_SAMPLES_PER_WINDOW {
            sleeper.sleep(request.cadence());
            match self.observe_at(request, sleeper.now_ms()) {
                Ok(sample) => samples.push(sample),
                Err(outcome) => {
                    return ObservationWindowResult {
                        cpu_resource_outcome: Some(outcome),
                        samples: Vec::new(),
                    };
                }
            }
        }
        ObservationWindowResult {
            cpu_resource_outcome: None,
            samples,
        }
    }

    pub fn into_provider(self) -> P {
        self.provider
    }
}

pub struct UnixCpuCountersProvider {
    socket_path: PathBuf,
}

impl UnixCpuCountersProvider {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }
}

impl CpuCountersProvider for UnixCpuCountersProvider {
    fn pull_cpu_counters(
        &mut self,
        _request: CpuCountersPullRequest,
    ) -> Result<CpuCountersResourceResult, CpuResourceAcquisitionFailure> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|error| {
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionRefused
            ) {
                CpuResourceAcquisitionFailure::ActivationBudgetExhausted
            } else {
                CpuResourceAcquisitionFailure::Unavailable
            }
        })?;
        configure_deadline(&stream, PROVIDER_DEADLINE)
            .map_err(|_| CpuResourceAcquisitionFailure::Unavailable)?;
        stream
            .write_all(CPU_COUNTERS_PULL)
            .map_err(|_| CpuResourceAcquisitionFailure::Unavailable)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| CpuResourceAcquisitionFailure::Unavailable)?;

        let len =
            read_u32(&mut stream).map_err(|_| CpuResourceAcquisitionFailure::Unavailable)? as usize;
        if len == 0 || len > MAX_CPU_COUNTERS_BYTES {
            return Err(CpuResourceAcquisitionFailure::Malformed);
        }
        let mut encoded = vec![0; len];
        stream
            .read_exact(&mut encoded)
            .map_err(|_| CpuResourceAcquisitionFailure::Unavailable)?;
        if stream
            .read(&mut [0; 1])
            .map_err(|_| CpuResourceAcquisitionFailure::Unavailable)?
            != 0
        {
            return Err(CpuResourceAcquisitionFailure::Malformed);
        }
        let counters =
            decode_cpu_counter_records(&encoded).ok_or(CpuResourceAcquisitionFailure::Malformed)?;
        CpuCountersResourceResult::from_records(counters)
            .ok_or(CpuResourceAcquisitionFailure::Malformed)
    }
}

fn decode_cpu_counter_records(bytes: &[u8]) -> Option<Vec<CpuCounterRecord>> {
    if bytes.len() < 2 || bytes.len() > MAX_CPU_COUNTERS_BYTES {
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

pub struct ObservationRuntimeServer<P> {
    runtime: ObservationRuntime<P>,
}

impl<P> ObservationRuntimeServer<P>
where
    P: CpuCountersProvider,
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
        configure_deadline(&stream, RUNTIME_WINDOW_DEADLINE)?;
        let Some(request) = read_window_request(&mut stream)? else {
            return write_window_failure(&mut stream);
        };
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
        for (index, connection) in listener.incoming().enumerate() {
            let connection = connection?;
            let _ = self.serve_connection(connection);
            if maximum_connections == Some(index + 1) {
                break;
            }
        }
        Ok(())
    }

    pub fn serve_fixed_probe_listener(&mut self, listener: &UnixListener) -> io::Result<()> {
        for connection in listener.incoming() {
            let connection = connection?;
            if require_peer_uid(connection.as_raw_fd(), c"enoki-probe").is_err() {
                continue;
            }
            let _ = self.serve_connection(connection);
        }
        Ok(())
    }
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
    ) -> Result<ObservationWindowResult, ObservationClientError>;
}

impl ObservationWindowClient for UnixObservationRuntimeClient {
    fn request_finalized_window(
        &self,
        cadence: Duration,
    ) -> Result<ObservationWindowResult, ObservationClientError> {
        UnixObservationRuntimeClient::request_finalized_window(self, cadence)
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
    ) -> Result<ObservationWindowResult, ObservationClientError> {
        let request =
            ObservationWindowRequest::new(cadence).ok_or(ObservationClientError::InvalidRequest)?;
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|_| ObservationClientError::Unavailable)?;
        configure_deadline(&stream, RUNTIME_WINDOW_DEADLINE)
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
        let sample_count =
            read_u16(&mut stream).map_err(|_| ObservationClientError::InvalidResponse)?;
        let mut outcome = [0; 1];
        stream
            .read_exact(&mut outcome)
            .map_err(|_| ObservationClientError::InvalidResponse)?;
        let cpu_resource_outcome = match outcome[0] {
            0 => None,
            1 => Some(CpuResourceAcquisitionFailure::Unavailable),
            2 => Some(CpuResourceAcquisitionFailure::Malformed),
            3 => Some(CpuResourceAcquisitionFailure::ActivationBudgetExhausted),
            _ => return Err(ObservationClientError::InvalidResponse),
        };
        if sample_count as usize > CPU_SAMPLES_PER_WINDOW
            || (cpu_resource_outcome.is_none() && sample_count as usize != CPU_SAMPLES_PER_WINDOW)
            || (cpu_resource_outcome.is_some() && sample_count != 0)
        {
            return Err(ObservationClientError::InvalidResponse);
        }
        let mut samples = Vec::with_capacity(sample_count as usize);
        for _ in 0..sample_count {
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
            samples.push(
                MetricSample::decode(encoded.as_slice())
                    .map_err(|_| ObservationClientError::InvalidResponse)?,
            );
        }
        if stream
            .read(&mut [0; 1])
            .map_err(|_| ObservationClientError::InvalidResponse)?
            != 0
        {
            return Err(ObservationClientError::InvalidResponse);
        }
        Ok(ObservationWindowResult {
            cpu_resource_outcome,
            samples,
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

fn read_window_request(stream: &mut UnixStream) -> io::Result<Option<ObservationWindowRequest>> {
    let mut request = Vec::with_capacity(OBSERVATION_WINDOW_PULL.len() + 2);
    stream
        .take((OBSERVATION_WINDOW_PULL.len() + 3) as u64)
        .read_to_end(&mut request)?;
    if request.len() != OBSERVATION_WINDOW_PULL.len() + 2
        || !request.starts_with(OBSERVATION_WINDOW_PULL)
    {
        return Ok(None);
    }
    let seconds = u16::from_be_bytes(request[OBSERVATION_WINDOW_PULL.len()..].try_into().unwrap());
    Ok(ObservationWindowRequest::new(Duration::from_secs(
        u64::from(seconds),
    )))
}

fn encode_window_request(request: ObservationWindowRequest) -> Vec<u8> {
    let mut encoded = OBSERVATION_WINDOW_PULL.to_vec();
    encoded.extend_from_slice(&request.cadence_seconds.to_be_bytes());
    encoded
}

fn write_window_success(
    stream: &mut UnixStream,
    version: &str,
    result: &ObservationWindowResult,
) -> io::Result<()> {
    let version = version.as_bytes();
    let encoded = result
        .samples
        .iter()
        .map(Message::encode_to_vec)
        .collect::<Vec<_>>();
    if version.is_empty()
        || version.len() > u16::MAX as usize
        || encoded.len() > CPU_SAMPLES_PER_WINDOW
        || (result.cpu_resource_outcome.is_none() && encoded.len() != CPU_SAMPLES_PER_WINDOW)
        || (result.cpu_resource_outcome.is_some() && !encoded.is_empty())
        || encoded
            .iter()
            .any(|sample| sample.is_empty() || sample.len() > MAX_RUNTIME_RESPONSE_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded Runtime response",
        ));
    }
    stream.write_all(&[0])?;
    stream.write_all(&(version.len() as u16).to_be_bytes())?;
    stream.write_all(version)?;
    stream.write_all(&(encoded.len() as u16).to_be_bytes())?;
    stream.write_all(&[match result.cpu_resource_outcome {
        None => 0,
        Some(CpuResourceAcquisitionFailure::Unavailable) => 1,
        Some(CpuResourceAcquisitionFailure::Malformed) => 2,
        Some(CpuResourceAcquisitionFailure::ActivationBudgetExhausted) => 3,
    }])?;
    for sample in encoded {
        stream.write_all(&(sample.len() as u32).to_be_bytes())?;
        stream.write_all(&sample)?;
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

    impl CpuCountersProvider for UnusedProvider {
        fn pull_cpu_counters(
            &mut self,
            _request: CpuCountersPullRequest,
        ) -> Result<CpuCountersResourceResult, CpuResourceAcquisitionFailure> {
            Err(CpuResourceAcquisitionFailure::Unavailable)
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
}

//! 构建期固定、单次有界的 CPU 观测 Runtime。

use std::{
    ffi::CStr,
    io::{self, Read, Write},
    os::fd::{AsRawFd, RawFd},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    time::Duration,
};

use prost::Message;

use crate::{
    metrics::{CpuCounterRecord, CpuCounterSnapshot, collect_cpu_metrics_from_counter_records},
    protocol::enoki::v1::MetricSample,
};

pub const CPU_COUNTERS_RESOURCE: &str = "official.cpu-counters";
pub const MAX_CPU_COUNTERS_BYTES: usize = 64 * 1024;
pub const CPU_COUNTERS_PULL: &[u8] = b"enoki.cpu-counters.v1\n";
pub const OBSERVATION_WINDOW_PULL: &[u8] = b"enoki.observation-window.v1\n";
pub const OBSERVATION_RUNTIME_SOCKET: &str = "/run/enoki-observation-runtime.sock";
pub const CPU_PROVIDER_SOCKET: &str = "/run/enoki-cpu-resource-provider.sock";
const MAX_RUNTIME_RESPONSE_BYTES: usize = 256 * 1024;
const PROVIDER_DEADLINE: Duration = Duration::from_secs(2);
const RUNTIME_WINDOW_DEADLINE: Duration = Duration::from_secs(20);
pub const CPU_COLLECTION_CADENCE: Duration = Duration::from_secs(5);
const CPU_SAMPLES_PER_WINDOW: usize = 3;

pub trait ObservationRuntimeSleeper {
    fn sleep(&mut self, duration: Duration);
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
    type Error;

    fn pull_cpu_counters(
        &mut self,
        request: CpuCountersPullRequest,
    ) -> Result<CpuCountersResourceResult, Self::Error>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObservationWindowRequest {
    _private: (),
}

impl ObservationWindowRequest {
    pub fn next() -> Self {
        Self { _private: () }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationRuntimeFailure {
    CpuResourceUnavailable,
    CpuResourceMalformed,
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
        _request: ObservationWindowRequest,
    ) -> Result<MetricSample, ObservationRuntimeFailure> {
        // 一次尝试只激活一次 Provider；同一不可变结果同时派生 CPU 汇总、
        // 分项和每核心结果。
        let resource = self
            .provider
            .pull_cpu_counters(CpuCountersPullRequest::fixed())
            .map_err(|_| ObservationRuntimeFailure::CpuResourceUnavailable)?;
        let cpu = collect_cpu_metrics_from_counter_records(
            resource.counters(),
            self.previous_cpu_counters.as_ref(),
        )
        .ok_or(ObservationRuntimeFailure::CpuResourceMalformed)?;
        self.previous_cpu_counters = Some(cpu.snapshot.clone());

        Ok(MetricSample {
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
        sleeper: &mut impl ObservationRuntimeSleeper,
    ) -> Result<Vec<MetricSample>, ObservationRuntimeFailure> {
        let mut samples = Vec::with_capacity(CPU_SAMPLES_PER_WINDOW);
        for _ in 0..CPU_SAMPLES_PER_WINDOW {
            sleeper.sleep(CPU_COLLECTION_CADENCE);
            samples.push(self.observe(ObservationWindowRequest::next())?);
        }
        Ok(samples)
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
    type Error = ();

    fn pull_cpu_counters(
        &mut self,
        _request: CpuCountersPullRequest,
    ) -> Result<CpuCountersResourceResult, Self::Error> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|_| ())?;
        configure_deadline(&stream, PROVIDER_DEADLINE).map_err(|_| ())?;
        stream.write_all(CPU_COUNTERS_PULL).map_err(|_| ())?;
        stream.shutdown(std::net::Shutdown::Write).map_err(|_| ())?;

        let len = read_u32(&mut stream).map_err(|_| ())? as usize;
        if len == 0 || len > MAX_CPU_COUNTERS_BYTES {
            return Err(());
        }
        let mut encoded = vec![0; len];
        stream.read_exact(&mut encoded).map_err(|_| ())?;
        if stream.read(&mut [0; 1]).map_err(|_| ())? != 0 {
            return Err(());
        }
        let counters = decode_cpu_counter_records(&encoded).ok_or(())?;
        CpuCountersResourceResult::from_records(counters).ok_or(())
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
        if !read_bounded_request(&mut stream, OBSERVATION_WINDOW_PULL)? {
            return write_window_failure(&mut stream);
        }
        match self.runtime.collect_next_window(sleeper) {
            Ok(metrics) => {
                write_window_success(&mut stream, crate::version::probe_version(), &metrics)
            }
            Err(_) => write_window_failure(&mut stream),
        }
    }

    pub fn serve_listener(&mut self, listener: &UnixListener) -> io::Result<()> {
        for connection in listener.incoming() {
            self.serve_connection(connection?)?;
        }
        Ok(())
    }

    pub fn serve_fixed_probe_listener(&mut self, listener: &UnixListener) -> io::Result<()> {
        for connection in listener.incoming() {
            let connection = connection?;
            if require_peer_uid(connection.as_raw_fd(), c"enoki-probe").is_err() {
                continue;
            }
            self.serve_connection(connection)?;
        }
        Ok(())
    }
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

pub struct UnixObservationRuntimeClient {
    socket_path: PathBuf,
    expected_bundle_version: String,
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

    pub fn request_finalized_window(&self) -> Result<Vec<MetricSample>, ObservationClientError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|_| ObservationClientError::Unavailable)?;
        configure_deadline(&stream, RUNTIME_WINDOW_DEADLINE)
            .map_err(|_| ObservationClientError::Unavailable)?;
        stream
            .write_all(OBSERVATION_WINDOW_PULL)
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
        if sample_count == 0 || sample_count as usize > CPU_SAMPLES_PER_WINDOW {
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
        Ok(samples)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationClientError {
    BundleIncoherent,
    InvalidResponse,
    Unavailable,
    WindowFailed,
}

fn configure_deadline(stream: &UnixStream, deadline: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(deadline))?;
    stream.set_write_timeout(Some(deadline))
}

fn read_bounded_request(stream: &mut UnixStream, expected: &[u8]) -> io::Result<bool> {
    let mut request = Vec::with_capacity(expected.len());
    stream
        .take((expected.len() + 1) as u64)
        .read_to_end(&mut request)?;
    Ok(request.as_slice() == expected)
}

fn write_window_success(
    stream: &mut UnixStream,
    version: &str,
    metrics: &[MetricSample],
) -> io::Result<()> {
    let version = version.as_bytes();
    let encoded = metrics
        .iter()
        .map(Message::encode_to_vec)
        .collect::<Vec<_>>();
    if version.is_empty()
        || version.len() > u16::MAX as usize
        || encoded.is_empty()
        || encoded.len() > CPU_SAMPLES_PER_WINDOW
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
    for sample in encoded {
        stream.write_all(&(sample.len() as u32).to_be_bytes())?;
        stream.write_all(&sample)?;
    }
    stream.flush()
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

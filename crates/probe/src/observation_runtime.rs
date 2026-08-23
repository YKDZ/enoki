//! 构建期固定、单次有界的 System State 观测 Runtime。

use std::{
    collections::BTreeMap,
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
        BatteryMetrics, CpuCounterRecord, CpuCounterSnapshot, DiskCounterSnapshot,
        FilesystemCapacity, LoadMetrics, MemoryMetrics, NetworkCounterSnapshot,
        collect_cpu_metrics_from_counter_records,
        collect_default_route_interfaces_from_proc_routes,
        collect_disk_counters_from_proc_diskstats_at, collect_disk_metrics_from_mounts,
        collect_network_metrics_from_proc_net_dev,
    },
    protocol::enoki::v1::{
        CollectorFailure, CollectorFailurePhase, CollectorOutcome, CollectorOutcomeState,
        HostProfileResourceFacts, HostProfileSnapshot, MetricSample,
        SystemStateResourceResult as WireSystemStateResourceResult,
    },
};

pub const SYSTEM_STATE_RESOURCE: &str = "official.system-state";
pub const MAX_SYSTEM_STATE_BYTES: usize = 256 * 1024;
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

/// System State Provider 唯一接受的空请求，调用者无法注入路径、命令或次数。
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
    proc_net_dev: String,
    proc_net_route: String,
    proc_net_ipv6_route: String,
    proc_mounts: String,
    proc_diskstats: String,
    disk_counters_collected_at_ms: i64,
    filesystem_capacities: BTreeMap<String, FilesystemCapacity>,
    temperature_inputs: Vec<String>,
    battery_supplies: Vec<BatteryMetrics>,
    network_failure_code: Option<String>,
    disk_failure_code: Option<String>,
    temperature_failure_code: Option<String>,
    battery_failure_code: Option<String>,
}

impl SystemStateResourceResult {
    pub fn from_records(counters: Vec<CpuCounterRecord>) -> Option<Self> {
        (!counters.is_empty() && counters.len() <= 4096).then_some(Self {
            counters: Some(counters),
            load: None,
            memory: None,
            uptime_seconds: None,
            host_profile_facts: None,
            proc_net_dev: String::new(),
            proc_net_route: String::new(),
            proc_net_ipv6_route: String::new(),
            proc_mounts: String::new(),
            proc_diskstats: String::new(),
            disk_counters_collected_at_ms: 0,
            filesystem_capacities: BTreeMap::new(),
            temperature_inputs: Vec::new(),
            battery_supplies: Vec::new(),
            network_failure_code: None,
            disk_failure_code: None,
            temperature_failure_code: None,
            battery_failure_code: None,
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
    previous_network_counters: Option<NetworkCounterSnapshot>,
    previous_disk_counters: Option<DiskCounterSnapshot>,
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
            previous_network_counters: None,
            previous_disk_counters: None,
            host_profile: None,
        }
    }

    pub fn observe(
        &mut self,
        request: ObservationWindowRequest,
    ) -> Result<MetricSample, ObservationRuntimeFailure> {
        self.observe_at(request, unix_time_ms(), true)
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
        collect_host_profile: bool,
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
                "official.cpu.counters-malformed",
            ));
        }
        for (id, produced_value, code) in [
            (
                "official.load",
                resource.load.is_some(),
                "official.load.facts-malformed",
            ),
            (
                "official.memory",
                resource.memory.is_some(),
                "official.memory.facts-malformed",
            ),
            (
                "official.uptime",
                resource.uptime_seconds.is_some(),
                "official.uptime.facts-malformed",
            ),
        ] {
            sample.collector_outcomes.push(if produced_value {
                produced(id)
            } else {
                calculation_failed(id, code)
            });
        }
        let routes = collect_default_route_interfaces_from_proc_routes(
            Some(&resource.proc_net_route),
            Some(&resource.proc_net_ipv6_route),
        );
        if let Some(code) = resource.network_failure_code.as_deref() {
            sample
                .collector_outcomes
                .push(resource_failed_with_code("official.network", code));
        } else if let Some(network) = collect_network_metrics_from_proc_net_dev(
            &resource.proc_net_dev,
            routes.as_ref(),
            self.previous_network_counters.as_ref(),
        ) {
            self.previous_network_counters = Some(network.snapshot);
            sample.network_interfaces = network.interfaces;
            sample.collector_outcomes.push(produced("official.network"));
        } else {
            sample.collector_outcomes.push(no_data("official.network"));
        }

        let disk_counters = collect_disk_counters_from_proc_diskstats_at(
            &resource.proc_diskstats,
            resource.disk_counters_collected_at_ms,
        );
        if let Some(code) = resource.disk_failure_code.as_deref() {
            sample
                .collector_outcomes
                .push(resource_failed_with_code("official.disk", code));
        } else {
            sample.disks = collect_disk_metrics_from_mounts(
                &resource.proc_mounts,
                |mount_point| resource.filesystem_capacities.get(mount_point).copied(),
                disk_counters.as_ref(),
                self.previous_disk_counters.as_ref(),
            );
            if let Some(snapshot) = disk_counters {
                self.previous_disk_counters = Some(snapshot);
            }
            sample.collector_outcomes.push(if sample.disks.is_empty() {
                no_data("official.disk")
            } else {
                produced("official.disk")
            });
        }

        sample.temperature_celsius = resource
            .temperature_inputs
            .iter()
            .filter_map(|raw| raw.parse::<f64>().ok())
            .map(|raw| if raw > 1_000.0 { raw / 1_000.0 } else { raw })
            .filter(|value| (0.0..200.0).contains(value))
            .reduce(f64::max);
        sample.collector_outcomes.push(
            if let Some(code) = resource.temperature_failure_code.as_deref() {
                resource_failed_with_code("official.temperature", code)
            } else if sample.temperature_celsius.is_some() {
                produced("official.temperature")
            } else {
                no_data("official.temperature")
            },
        );

        if let Some(code) = resource.battery_failure_code.as_deref() {
            sample
                .collector_outcomes
                .push(resource_failed_with_code("official.battery", code));
        } else if let Some(battery) = resource
            .battery_supplies
            .iter()
            .max_by_key(|battery| battery.percent)
        {
            sample.battery_percent = Some(battery.percent);
            sample.battery_state = Some(battery.state.clone());
            sample.collector_outcomes.push(produced("official.battery"));
        } else {
            sample.collector_outcomes.push(no_data("official.battery"));
        }
        if collect_host_profile
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
        self.host_profile = None;
        let mut window_host_profile = None;
        let mut attempts = Vec::with_capacity(CPU_SAMPLES_PER_WINDOW);
        for offset in 0..CPU_SAMPLES_PER_WINDOW {
            sleeper.sleep(request.cadence());
            match self.observe_at(request, sleeper.now_ms(), offset == 0) {
                Ok(mut sample) => {
                    if offset == 0 {
                        window_host_profile = self.host_profile.clone();
                        sample
                            .collector_outcomes
                            .push(if window_host_profile.is_some() {
                                produced("official.host-profile")
                            } else {
                                calculation_failed(
                                    "official.host-profile",
                                    "official.host-profile.facts-malformed",
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
                    if offset == 0 {
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
            host_profile: window_host_profile,
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
        decode_system_state_resource_result(&encoded)
            .ok_or(SystemStateResourceAcquisitionFailure::Malformed)
    }
}

/// 解码构建期固定的 System State protobuf Resource Result。
pub fn decode_system_state_resource_result(bytes: &[u8]) -> Option<SystemStateResourceResult> {
    if bytes.is_empty() || bytes.len() > MAX_SYSTEM_STATE_BYTES {
        return None;
    }
    let wire = WireSystemStateResourceResult::decode(bytes).ok()?;
    if wire.encode_to_vec() != bytes {
        return None;
    }
    let counters = (!wire.cpu_counters.is_empty() && wire.cpu_counters.len() <= 4096)
        .then(|| {
            wire.cpu_counters
                .into_iter()
                .map(|fact| {
                    (!fact.name.is_empty()
                        && fact.name.len() <= 32
                        && fact.name.bytes().all(|byte| byte.is_ascii_alphanumeric()))
                    .then_some(CpuCounterRecord {
                        name: fact.name,
                        user: fact.user,
                        nice: fact.nice,
                        system: fact.system,
                        idle: fact.idle,
                        iowait: fact.iowait,
                        irq: fact.irq,
                        softirq: fact.softirq,
                        steal: fact.steal,
                    })
                })
                .collect::<Option<Vec<_>>>()
        })
        .flatten();
    let load = crate::metrics::collect_load_metrics_from_proc_loadavg(&wire.proc_loadavg);
    let memory = crate::metrics::collect_memory_metrics_from_proc_meminfo(&wire.proc_meminfo);
    let uptime_seconds = crate::metrics::collect_uptime_seconds_from_proc_uptime(&wire.proc_uptime);
    let disk_contract_malformed = wire.filesystem_capacities.len() > 4096
        || wire.filesystem_capacities.iter().any(|fact| {
            fact.mount_point.is_empty()
                || fact.mount_point.len() > 4096
                || fact.free_bytes > fact.total_bytes
                || fact.available_bytes > fact.total_bytes
        });
    let temperature_contract_malformed = wire.temperature_inputs.len() > 4096
        || wire.temperature_inputs.iter().any(|value| value.len() > 64);
    let battery_contract_malformed = wire.battery_supplies.len() > 256
        || wire.battery_supplies.iter().any(|fact| {
            fact.supply_type.len() > 64 || fact.capacity.len() > 64 || fact.status.len() > 64
        });
    Some(SystemStateResourceResult {
        counters,
        load,
        memory,
        uptime_seconds,
        host_profile_facts: wire.host_profile,
        proc_net_dev: wire.proc_net_dev,
        proc_net_route: wire.proc_net_route,
        proc_net_ipv6_route: wire.proc_net_ipv6_route,
        proc_mounts: wire.proc_mounts,
        proc_diskstats: wire.proc_diskstats,
        disk_counters_collected_at_ms: wire.disk_counters_collected_at_ms,
        filesystem_capacities: wire
            .filesystem_capacities
            .into_iter()
            .filter(|fact| !fact.mount_point.is_empty() && fact.mount_point.len() <= 4096)
            .map(|fact| {
                (
                    fact.mount_point,
                    FilesystemCapacity {
                        total_bytes: fact.total_bytes,
                        free_bytes: fact.free_bytes,
                        available_bytes: fact.available_bytes,
                    },
                )
            })
            .take(4096)
            .collect(),
        temperature_inputs: wire
            .temperature_inputs
            .into_iter()
            .filter(|value| value.len() <= 64)
            .take(4096)
            .collect(),
        battery_supplies: wire
            .battery_supplies
            .into_iter()
            .filter_map(|fact| {
                (fact.supply_type == "Battery")
                    .then(|| fact.capacity.parse::<u32>().ok())
                    .flatten()
                    .filter(|percent| *percent <= 100)
                    .map(|percent| BatteryMetrics {
                        percent,
                        state: if fact.status.is_empty() || fact.status.len() > 64 {
                            "Unknown".to_owned()
                        } else {
                            fact.status
                        },
                    })
            })
            .take(256)
            .collect(),
        network_failure_code: bounded_resource_code(
            wire.network_failure_code,
            "official.network.resource-result-malformed",
        ),
        disk_failure_code: contract_resource_code(
            wire.disk_failure_code,
            disk_contract_malformed,
            "official.disk.resource-result-malformed",
        ),
        temperature_failure_code: contract_resource_code(
            wire.temperature_failure_code,
            temperature_contract_malformed,
            "official.temperature.resource-result-malformed",
        ),
        battery_failure_code: contract_resource_code(
            wire.battery_failure_code,
            battery_contract_malformed,
            "official.battery.resource-result-malformed",
        ),
    })
}

fn produced(id: &str) -> CollectorOutcome {
    CollectorOutcome {
        collector_id: id.to_owned(),
        state: CollectorOutcomeState::Produced as i32,
        failure: None,
    }
}
fn no_data(id: &str) -> CollectorOutcome {
    CollectorOutcome {
        collector_id: id.to_owned(),
        state: CollectorOutcomeState::NoData as i32,
        failure: None,
    }
}
fn resource_failed_with_code(id: &str, code: &str) -> CollectorOutcome {
    CollectorOutcome {
        collector_id: id.to_owned(),
        state: CollectorOutcomeState::Failed as i32,
        failure: Some(CollectorFailure {
            phase: CollectorFailurePhase::Resource as i32,
            legacy_code: 0,
            code: code.to_owned(),
        }),
    }
}

fn bounded_resource_code(code: String, malformed: &'static str) -> Option<String> {
    if code.is_empty() {
        None
    } else if code.len() <= 128
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        Some(code)
    } else {
        Some(malformed.to_owned())
    }
}

fn contract_resource_code(
    code: String,
    contract_malformed: bool,
    malformed: &'static str,
) -> Option<String> {
    if contract_malformed {
        Some(malformed.to_owned())
    } else {
        bounded_resource_code(code, malformed)
    }
}
fn calculation_failed(id: &str, code: &'static str) -> CollectorOutcome {
    CollectorOutcome {
        collector_id: id.to_owned(),
        state: CollectorOutcomeState::Failed as i32,
        failure: Some(CollectorFailure {
            phase: CollectorFailurePhase::Calculation as i32,
            legacy_code: legacy_failure_code(code),
            code: code.to_owned(),
        }),
    }
}

fn resource_failure_sample(
    collected_at_ms: i64,
    failure: SystemStateResourceAcquisitionFailure,
) -> MetricSample {
    MetricSample {
        collected_at_ms,
        collector_outcomes: [
            "official.cpu",
            "official.load",
            "official.memory",
            "official.uptime",
            "official.network",
            "official.disk",
            "official.temperature",
            "official.battery",
        ]
        .into_iter()
        .map(|id| CollectorOutcome {
            collector_id: id.to_owned(),
            state: CollectorOutcomeState::Failed as i32,
            failure: Some(CollectorFailure {
                phase: CollectorFailurePhase::Resource as i32,
                legacy_code: legacy_resource_failure_code(id, failure),
                code: resource_failure_code(id, failure),
            }),
        })
        .collect(),
        ..MetricSample::default()
    }
}

fn host_profile_resource_failed(
    failure: SystemStateResourceAcquisitionFailure,
) -> CollectorOutcome {
    CollectorOutcome {
        collector_id: "official.host-profile".to_owned(),
        state: CollectorOutcomeState::Failed as i32,
        failure: Some(CollectorFailure {
            phase: CollectorFailurePhase::Resource as i32,
            legacy_code: legacy_resource_failure_code("official.host-profile", failure),
            code: resource_failure_code("official.host-profile", failure),
        }),
    }
}

fn legacy_failure_code(code: &str) -> u32 {
    match code {
        "official.cpu.counters-malformed" => 4,
        "official.load.facts-malformed" => 5,
        "official.memory.facts-malformed" => 6,
        "official.uptime.facts-malformed" => 7,
        "official.host-profile.facts-malformed" => 8,
        _ => 0,
    }
}

fn legacy_resource_failure_code(
    collector_id: &str,
    failure: SystemStateResourceAcquisitionFailure,
) -> u32 {
    match (collector_id, failure) {
        ("official.host-profile", SystemStateResourceAcquisitionFailure::Unavailable) => 9,
        (
            "official.host-profile",
            SystemStateResourceAcquisitionFailure::ActivationBudgetExhausted,
        ) => 10,
        ("official.host-profile", SystemStateResourceAcquisitionFailure::Malformed) => 8,
        (_, SystemStateResourceAcquisitionFailure::Unavailable) => 1,
        (_, SystemStateResourceAcquisitionFailure::Malformed) => 2,
        (_, SystemStateResourceAcquisitionFailure::ActivationBudgetExhausted) => 3,
    }
}

fn resource_failure_code(
    collector_id: &str,
    failure: SystemStateResourceAcquisitionFailure,
) -> String {
    debug_assert!(matches!(
        collector_id,
        "official.cpu"
            | "official.load"
            | "official.memory"
            | "official.uptime"
            | "official.network"
            | "official.disk"
            | "official.temperature"
            | "official.battery"
            | "official.host-profile"
    ));
    let suffix = match failure {
        SystemStateResourceAcquisitionFailure::Unavailable => "resource-unavailable",
        SystemStateResourceAcquisitionFailure::Malformed => "resource-malformed",
        SystemStateResourceAcquisitionFailure::ActivationBudgetExhausted => {
            "activation-budget-exhausted"
        }
    };
    format!("{collector_id}.{suffix}")
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

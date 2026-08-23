//! 构建期固定、单次有界的 System State 观测 Runtime。

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CStr,
    io::{self, Read, Write},
    os::fd::{AsRawFd, RawFd},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use prost::Message;

use crate::{
    metrics::{
        BatteryMetrics, CpuCounterRecord, CpuCounterSnapshot, DiskCounterSnapshot,
        FilesystemCapacity, LoadMetrics, MemoryMetrics, NetworkCounterSnapshot,
        collect_cpu_metrics_from_counter_records,
        collect_default_route_interfaces_from_proc_routes,
        collect_disk_counters_from_proc_diskstats_at,
        collect_disk_health_metrics_from_smartctl_json, collect_disk_metrics_from_mounts,
        collect_network_metrics_from_proc_net_dev,
    },
    protocol::enoki::v1::{
        CollectorFailure, CollectorFailurePhase, CollectorOutcome, CollectorOutcomeState,
        DiskHealthCollectorCapability, DiskHealthCollectorCapabilityStatus,
        DiskHealthResourceResult as WireDiskHealthResourceResult, HostProfileResourceFacts,
        HostProfileSnapshot, MetricSample,
        SystemStateResourceResult as WireSystemStateResourceResult,
    },
};

pub const SYSTEM_STATE_RESOURCE: &str = "official.system-state";
pub const MAX_SYSTEM_STATE_BYTES: usize = 256 * 1024;
pub const SYSTEM_STATE_PULL: &[u8] = b"enoki.system-state.v1\n";
pub const OBSERVATION_WINDOW_PULL: &[u8] = b"enoki.observation-window.v2\n";
pub const OBSERVATION_RUNTIME_SOCKET: &str = "/run/enoki-observation-runtime.sock";
pub const CPU_PROVIDER_SOCKET: &str = "/run/enoki-cpu-resource-provider.sock";
pub const DISK_HEALTH_PROVIDER_SOCKET: &str = "/run/enoki-disk-health-resource-provider.sock";
pub const DISK_HEALTH_PULL: &[u8] = b"enoki.disk-health.v1\n";
pub const DISK_HEALTH_RESOURCE: &str = "official.disk-health";
pub const MAX_DISK_HEALTH_BYTES: usize = 512 * 1024;
const MAX_RUNTIME_RESPONSE_BYTES: usize = 256 * 1024;
const PROVIDER_DEADLINE: Duration = Duration::from_secs(2);
const DISK_HEALTH_PROVIDER_DEADLINE: Duration = Duration::from_secs(9);
const RUNTIME_REQUEST_DEADLINE: Duration = Duration::from_secs(3);
const RUNTIME_WINDOW_HEADROOM: Duration = Duration::from_secs(5);
const RUNTIME_PROGRESS_INTERVAL: Duration = Duration::from_secs(10);
const ADMISSION_POLL_INTERVAL: Duration = Duration::from_millis(10);
const CPU_SAMPLES_PER_WINDOW: usize = 3;
const MIN_COLLECTION_CADENCE_SECONDS: u16 = 1;
const MAX_COLLECTION_CADENCE_SECONDS: u16 = 200;

pub trait ObservationRuntimeSleeper {
    fn sleep(&mut self, duration: Duration);
    fn sleep_with_progress(
        &mut self,
        duration: Duration,
        progress: &mut dyn ObservationRuntimeProgressNotifier,
    ) -> io::Result<()> {
        self.sleep(duration);
        progress.notify_progress()
    }
    fn now_ms(&self) -> i64 {
        unix_time_ms()
    }
}

pub struct ThreadObservationRuntimeSleeper;

impl ObservationRuntimeSleeper for ThreadObservationRuntimeSleeper {
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn sleep_with_progress(
        &mut self,
        duration: Duration,
        progress: &mut dyn ObservationRuntimeProgressNotifier,
    ) -> io::Result<()> {
        let mut remaining = duration;
        while !remaining.is_zero() {
            let step = remaining.min(RUNTIME_PROGRESS_INTERVAL);
            std::thread::sleep(step);
            remaining = remaining.saturating_sub(step);
            progress.notify_progress()?;
        }
        Ok(())
    }
}

pub trait ObservationRuntimeProgressNotifier {
    fn notify_ready(&mut self) -> io::Result<()>;
    fn notify_progress(&mut self) -> io::Result<()>;
}

struct InertRuntimeProgressNotifier;

impl ObservationRuntimeProgressNotifier for InertRuntimeProgressNotifier {
    fn notify_ready(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn notify_progress(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceAccess {
    SystemState,
    DiskHealth,
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
const DISK_HEALTH_DESCRIPTOR: CollectorResourceDescriptor = CollectorResourceDescriptor {
    id: DISK_HEALTH_RESOURCE,
    access: ResourceAccess::DiskHealth,
    max_result_bytes: MAX_DISK_HEALTH_BYTES,
    max_results_per_attempt: 1,
    request_accepts_caller_input: false,
};

/// 注册表是闭合的构建产物，不是运行时插件表。
pub struct StaticCollectorRegistry;

impl StaticCollectorRegistry {
    pub fn resource(&self, id: &str) -> Option<&'static CollectorResourceDescriptor> {
        match id {
            SYSTEM_STATE_RESOURCE => Some(&SYSTEM_STATE_DESCRIPTOR),
            DISK_HEALTH_RESOURCE => Some(&DISK_HEALTH_DESCRIPTOR),
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
    block_device_topology: BTreeMap<String, String>,
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
            block_device_topology: BTreeMap::new(),
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

pub struct DiskHealthPullRequest(());

impl DiskHealthPullRequest {
    fn fixed() -> Self {
        Self(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiskHealthResourceResult {
    devices: Vec<(String, Vec<u8>, i32)>,
    capability_status: DiskHealthCollectorCapabilityStatus,
    failure_code: Option<String>,
    unraid_disks_ini: String,
}

pub trait DiskHealthProvider {
    fn pull_disk_health(
        &mut self,
        request: DiskHealthPullRequest,
    ) -> Result<DiskHealthResourceResult, DiskHealthResourceAcquisitionFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiskHealthResourceAcquisitionFailure {
    ActivationBudgetExhausted,
    Malformed,
    Unavailable,
}

struct UnavailableDiskHealthProvider;

impl DiskHealthProvider for UnavailableDiskHealthProvider {
    fn pull_disk_health(
        &mut self,
        _request: DiskHealthPullRequest,
    ) -> Result<DiskHealthResourceResult, DiskHealthResourceAcquisitionFailure> {
        Err(DiskHealthResourceAcquisitionFailure::Unavailable)
    }
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
        .checked_add(DISK_HEALTH_PROVIDER_DEADLINE)?
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
    disk_health_provider: Box<dyn DiskHealthProvider>,
    previous_cpu_counters: Option<CpuCounterSnapshot>,
    previous_network_counters: Option<NetworkCounterSnapshot>,
    previous_disk_counters: Option<DiskCounterSnapshot>,
    host_profile: Option<HostProfileSnapshot>,
    disk_health_capability: DiskHealthCollectorCapability,
}

impl<P> ObservationRuntime<P>
where
    P: SystemStateProvider,
{
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            disk_health_provider: Box::new(UnavailableDiskHealthProvider),
            previous_cpu_counters: None,
            previous_network_counters: None,
            previous_disk_counters: None,
            host_profile: None,
            disk_health_capability: DiskHealthCollectorCapability {
                status: DiskHealthCollectorCapabilityStatus::Unspecified as i32,
                diagnostic: String::new(),
            },
        }
    }

    pub fn with_disk_health_provider<D>(mut self, provider: D) -> Self
    where
        D: DiskHealthProvider + 'static,
    {
        self.disk_health_provider = Box::new(provider);
        self
    }

    pub fn observe(
        &mut self,
        request: ObservationWindowRequest,
    ) -> Result<MetricSample, ObservationRuntimeFailure> {
        self.observe_at(request, request.sequence_start, unix_time_ms(), true)
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
        sequence: u64,
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

        sample.temperature_celsius = temperature_celsius_from_inputs(&resource.temperature_inputs);
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
                .as_ref()
                .filter(|facts| crate::host_profile::valid_host_profile_resource_facts(facts))
                .cloned()
        {
            self.host_profile = Some(crate::host_profile::host_profile_from_resource_facts(facts));
            if let Some(profile) = self.host_profile.as_mut() {
                crate::host_profile::set_disk_health_capability(
                    profile,
                    self.disk_health_capability.clone(),
                );
            }
        }
        if sequence.is_multiple_of(12) {
            self.collect_disk_health(
                &resource.proc_mounts,
                &resource.filesystem_capacities,
                &resource.block_device_topology,
                &mut sample,
            );
        }
        Ok(sample)
    }

    fn collect_disk_health(
        &mut self,
        proc_mounts: &str,
        filesystem_capacities: &BTreeMap<String, FilesystemCapacity>,
        block_device_topology: &BTreeMap<String, String>,
        sample: &mut MetricSample,
    ) {
        let resource = match self
            .disk_health_provider
            .pull_disk_health(DiskHealthPullRequest::fixed())
        {
            Ok(resource) => resource,
            Err(failure) => {
                let code = match failure {
                    DiskHealthResourceAcquisitionFailure::Unavailable => {
                        "official.disk-health.resource-unavailable"
                    }
                    DiskHealthResourceAcquisitionFailure::Malformed => {
                        "official.disk-health.resource-malformed"
                    }
                    DiskHealthResourceAcquisitionFailure::ActivationBudgetExhausted => {
                        "official.disk-health.activation-budget-exhausted"
                    }
                };
                sample
                    .collector_outcomes
                    .push(resource_failed_with_code("official.disk-health", code));
                return;
            }
        };
        if let Some(code) = resource.failure_code.as_deref() {
            if stable_disk_health_capability(resource.capability_status) {
                self.set_disk_health_capability(resource.capability_status, code);
            }
            sample
                .collector_outcomes
                .push(resource_failed_with_code("official.disk-health", code));
            return;
        }

        let mut metrics = Vec::new();
        let mut unsupported = 0_usize;
        let mut malformed = 0_usize;
        for (device_name, json, exit_code) in resource.devices {
            if exit_code != 0 && json.is_empty() {
                sample.collector_outcomes.push(resource_failed_with_code(
                    "official.disk-health",
                    "official.disk-health.smartctl-failed",
                ));
                return;
            }
            let Ok(json) = std::str::from_utf8(&json) else {
                malformed += 1;
                continue;
            };
            match collect_disk_health_metrics_from_smartctl_json(&device_name, json) {
                Ok(Some(metric)) => metrics.push(metric),
                Ok(None) => unsupported += 1,
                Err(_) => malformed += 1,
            }
        }
        let failed = if metrics.is_empty() && malformed > 0 {
            Some((
                DiskHealthCollectorCapabilityStatus::MalformedOutput,
                "official.disk-health.output-malformed",
            ))
        } else if metrics.is_empty() && unsupported > 0 {
            Some((
                DiskHealthCollectorCapabilityStatus::UnsupportedSmartData,
                "official.disk-health.unsupported-smart-data",
            ))
        } else {
            None
        };
        if let Some((status, code)) = failed {
            if stable_disk_health_capability(status) {
                self.set_disk_health_capability(status, code);
            }
            sample
                .collector_outcomes
                .push(calculation_failed("official.disk-health", code));
            return;
        }
        crate::metrics::disk_health::enrich_disk_health_metrics_with_resource_facts(
            &mut metrics,
            proc_mounts,
            filesystem_capacities,
            &resource.unraid_disks_ini,
            block_device_topology,
        );
        sample.disk_health = metrics;
        self.set_disk_health_capability(DiskHealthCollectorCapabilityStatus::Available, "");
        sample
            .collector_outcomes
            .push(if sample.disk_health.is_empty() {
                no_data("official.disk-health")
            } else {
                produced("official.disk-health")
            });
    }

    fn set_disk_health_capability(
        &mut self,
        status: DiskHealthCollectorCapabilityStatus,
        diagnostic: &str,
    ) {
        self.disk_health_capability = DiskHealthCollectorCapability {
            status: status as i32,
            diagnostic: diagnostic.to_owned(),
        };
        if let Some(profile) = self.host_profile.as_mut() {
            crate::host_profile::set_disk_health_capability(
                profile,
                self.disk_health_capability.clone(),
            );
        }
    }

    pub fn collect_next_window(
        &mut self,
        request: ObservationWindowRequest,
        sleeper: &mut impl ObservationRuntimeSleeper,
    ) -> ObservationWindowResult {
        self.collect_next_window_with_progress(request, sleeper, &mut InertRuntimeProgressNotifier)
            .expect("inert Runtime progress notifier cannot fail")
    }

    pub fn collect_next_window_with_progress(
        &mut self,
        request: ObservationWindowRequest,
        sleeper: &mut impl ObservationRuntimeSleeper,
        progress: &mut dyn ObservationRuntimeProgressNotifier,
    ) -> io::Result<ObservationWindowResult> {
        self.host_profile = None;
        let mut window_host_profile = None;
        let mut attempts = Vec::with_capacity(CPU_SAMPLES_PER_WINDOW);
        for offset in 0..CPU_SAMPLES_PER_WINDOW {
            sleeper.sleep_with_progress(request.cadence(), progress)?;
            match self.observe_at(
                request,
                request.sequence_start + offset as u64,
                sleeper.now_ms(),
                offset == 0,
            ) {
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
                    let sequence = request.sequence_start + offset as u64;
                    if sequence.is_multiple_of(12) {
                        self.collect_disk_health(
                            "",
                            &BTreeMap::new(),
                            &BTreeMap::new(),
                            &mut sample,
                        );
                    }
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
            progress.notify_progress()?;
        }
        Ok(ObservationWindowResult {
            attempts,
            host_profile: window_host_profile,
        })
    }

    pub fn into_provider(self) -> P {
        self.provider
    }
}

fn stable_disk_health_capability(status: DiskHealthCollectorCapabilityStatus) -> bool {
    matches!(
        status,
        DiskHealthCollectorCapabilityStatus::Available
            | DiskHealthCollectorCapabilityStatus::MissingSmartctl
            | DiskHealthCollectorCapabilityStatus::InsufficientLocalPrivilege
            | DiskHealthCollectorCapabilityStatus::UnsupportedSmartData
    )
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

pub struct UnixDiskHealthProvider {
    socket_path: PathBuf,
}

impl UnixDiskHealthProvider {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }
}

impl DiskHealthProvider for UnixDiskHealthProvider {
    fn pull_disk_health(
        &mut self,
        _request: DiskHealthPullRequest,
    ) -> Result<DiskHealthResourceResult, DiskHealthResourceAcquisitionFailure> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|error| {
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionRefused
            ) {
                DiskHealthResourceAcquisitionFailure::ActivationBudgetExhausted
            } else {
                DiskHealthResourceAcquisitionFailure::Unavailable
            }
        })?;
        configure_deadline(&stream, DISK_HEALTH_PROVIDER_DEADLINE)
            .map_err(|_| DiskHealthResourceAcquisitionFailure::Unavailable)?;
        stream
            .write_all(DISK_HEALTH_PULL)
            .map_err(|_| DiskHealthResourceAcquisitionFailure::Unavailable)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|_| DiskHealthResourceAcquisitionFailure::Unavailable)?;
        let len = read_u32(&mut stream)
            .map_err(|_| DiskHealthResourceAcquisitionFailure::Unavailable)?
            as usize;
        if len == 0 || len > MAX_DISK_HEALTH_BYTES {
            return Err(DiskHealthResourceAcquisitionFailure::Malformed);
        }
        let mut encoded = vec![0; len];
        stream
            .read_exact(&mut encoded)
            .map_err(|_| DiskHealthResourceAcquisitionFailure::Unavailable)?;
        if stream
            .read(&mut [0; 1])
            .map_err(|_| DiskHealthResourceAcquisitionFailure::Unavailable)?
            != 0
        {
            return Err(DiskHealthResourceAcquisitionFailure::Malformed);
        }
        decode_disk_health_resource_result(&encoded)
            .ok_or(DiskHealthResourceAcquisitionFailure::Malformed)
    }
}

pub fn decode_disk_health_resource_result(bytes: &[u8]) -> Option<DiskHealthResourceResult> {
    if bytes.is_empty() || bytes.len() > MAX_DISK_HEALTH_BYTES {
        return None;
    }
    let wire = WireDiskHealthResourceResult::decode(bytes).ok()?;
    if wire.encode_to_vec() != bytes
        || wire.devices.len() > 128
        || wire.unraid_disks_ini.len() > 256 * 1024
    {
        return None;
    }
    let capability_status = DiskHealthCollectorCapabilityStatus::try_from(wire.capability_status)
        .ok()
        .filter(|status| *status != DiskHealthCollectorCapabilityStatus::Unspecified)?;
    let failure_code = bounded_resource_code(
        wire.failure_code,
        "official.disk-health.resource-result-malformed",
    );
    if failure_code.is_none()
        != (capability_status == DiskHealthCollectorCapabilityStatus::Available)
    {
        return None;
    }
    let mut names = std::collections::BTreeSet::new();
    let devices = wire
        .devices
        .into_iter()
        .map(|fact| {
            let valid_name = fact.device_name.starts_with("/dev/")
                && fact.device_name.len() <= 128
                && !fact.device_name[5..].contains('/')
                && fact.device_name[5..]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
            (valid_name
                && names.insert(fact.device_name.clone())
                && fact.smartctl_json.len() <= 64 * 1024)
                .then_some((fact.device_name, fact.smartctl_json, fact.exit_code))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(DiskHealthResourceResult {
        devices,
        capability_status,
        failure_code,
        unraid_disks_ini: wire.unraid_disks_ini,
    })
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
    let mut topology_sources = BTreeSet::new();
    let topology_contract_malformed = wire.block_device_topology.len() > 512
        || wire.block_device_topology.iter().any(|fact| {
            !canonical_device_path(&fact.source)
                || !canonical_device_path(&fact.physical_device)
                || !topology_sources.insert(fact.source.as_str())
        });
    let disk_contract_malformed = wire.filesystem_capacities.len() > 4096
        || topology_contract_malformed
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
        block_device_topology: if topology_contract_malformed {
            BTreeMap::new()
        } else {
            wire.block_device_topology
                .into_iter()
                .map(|fact| (fact.source, fact.physical_device))
                .collect()
        },
    })
}

fn canonical_device_path(value: &str) -> bool {
    let Some(relative) = value.strip_prefix("/dev/") else {
        return false;
    };
    !relative.is_empty()
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && relative
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn temperature_celsius_from_inputs(inputs: &[String]) -> Option<f64> {
    inputs
        .iter()
        .filter_map(|raw| raw.parse::<f64>().ok())
        .map(|raw| if raw > 1_000.0 { raw / 1_000.0 } else { raw })
        .filter(|value| (0.0..200.0).contains(value))
        .reduce(f64::max)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowAdmissionDecision {
    Admit,
    Reject,
}

#[derive(Default)]
struct ObservationWindowAdmission {
    active: bool,
    last_request_sequence_start: Option<u64>,
    last_delivered_sequence_end: Option<u64>,
    next_eligible_at: Option<Instant>,
}

impl ObservationWindowAdmission {
    fn arrive(
        &mut self,
        request: ObservationWindowRequest,
        now: Instant,
    ) -> WindowAdmissionDecision {
        if self.active
            || self
                .last_request_sequence_start
                .is_some_and(|last| request.sequence_start <= last)
            || self
                .last_delivered_sequence_end
                .is_some_and(|last| request.sequence_start <= last)
            || self.next_eligible_at.is_some_and(|eligible| now < eligible)
        {
            return WindowAdmissionDecision::Reject;
        }
        let Some(window_span) = request.cadence().checked_mul(CPU_SAMPLES_PER_WINDOW as u32) else {
            return WindowAdmissionDecision::Reject;
        };
        let Some(next_eligible_at) = now.checked_add(window_span) else {
            return WindowAdmissionDecision::Reject;
        };
        self.active = true;
        self.last_request_sequence_start = Some(request.sequence_start);
        self.next_eligible_at = Some(next_eligible_at);
        WindowAdmissionDecision::Admit
    }

    fn complete(&mut self, delivered_sequence_end: Option<u64>) {
        self.last_delivered_sequence_end =
            delivered_sequence_end.or(self.last_delivered_sequence_end);
        self.active = false;
    }
}

pub struct ObservationRuntimeServer<P> {
    runtime: ObservationRuntime<P>,
    admission: ObservationWindowAdmission,
}

struct AdmittedWindow {
    request: ObservationWindowRequest,
    stream: UnixStream,
}

enum AdmittedWindowError {
    Connection(io::Error),
    Progress(io::Error),
}

impl AdmittedWindowError {
    fn into_io_error(self) -> io::Error {
        match self {
            Self::Connection(error) | Self::Progress(error) => error,
        }
    }
}

enum AdmissionMessage {
    Window(AdmittedWindow),
    ListenerFailed(io::Error),
}

impl<P> ObservationRuntimeServer<P>
where
    P: SystemStateProvider,
{
    pub fn new(provider: P) -> Self {
        Self {
            runtime: ObservationRuntime::new(provider),
            admission: ObservationWindowAdmission::default(),
        }
    }

    pub fn with_disk_health_provider<D>(provider: P, disk_health_provider: D) -> Self
    where
        D: DiskHealthProvider + 'static,
    {
        Self {
            runtime: ObservationRuntime::new(provider)
                .with_disk_health_provider(disk_health_provider),
            admission: ObservationWindowAdmission::default(),
        }
    }

    pub fn serve_connection(&mut self, stream: UnixStream) -> io::Result<()> {
        let mut sleeper = ThreadObservationRuntimeSleeper;
        self.serve_connection_with_sleeper(stream, &mut sleeper)
    }

    pub fn serve_connection_with_sleeper(
        &mut self,
        stream: UnixStream,
        sleeper: &mut impl ObservationRuntimeSleeper,
    ) -> io::Result<()> {
        self.serve_connection_with_sleeper_and_progress(
            stream,
            sleeper,
            &mut InertRuntimeProgressNotifier,
        )
    }

    pub fn serve_connection_with_sleeper_and_progress(
        &mut self,
        mut stream: UnixStream,
        sleeper: &mut impl ObservationRuntimeSleeper,
        progress: &mut dyn ObservationRuntimeProgressNotifier,
    ) -> io::Result<()> {
        configure_deadline(&stream, RUNTIME_REQUEST_DEADLINE)?;
        let Some(request) = read_runtime_request(&mut stream)? else {
            return write_window_failure(&mut stream);
        };
        let RuntimeRequest::Window(request) = request;
        if self.admission.arrive(request, Instant::now()) == WindowAdmissionDecision::Reject {
            return write_window_failure(&mut stream);
        }
        let delivered = self.serve_admitted_window(stream, request, sleeper, progress);
        self.admission.complete(delivered.as_ref().ok().copied());
        delivered
            .map(|_| ())
            .map_err(AdmittedWindowError::into_io_error)
    }

    fn serve_admitted_window(
        &mut self,
        mut stream: UnixStream,
        request: ObservationWindowRequest,
        sleeper: &mut impl ObservationRuntimeSleeper,
        progress: &mut dyn ObservationRuntimeProgressNotifier,
    ) -> Result<u64, AdmittedWindowError> {
        let deadline = runtime_window_deadline(request.cadence()).ok_or_else(|| {
            AdmittedWindowError::Connection(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bounded Runtime deadline",
            ))
        })?;
        configure_deadline(&stream, deadline).map_err(AdmittedWindowError::Connection)?;
        let result = self
            .runtime
            .collect_next_window_with_progress(request, sleeper, progress)
            .map_err(AdmittedWindowError::Progress)?;
        let delivered_sequence_end = result
            .attempts
            .last()
            .map(|attempt| attempt.sequence)
            .ok_or_else(|| {
                AdmittedWindowError::Connection(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty Runtime window",
                ))
            })?;
        write_window_success(&mut stream, crate::version::probe_version(), &result)
            .map_err(AdmittedWindowError::Connection)?;
        Ok(delivered_sequence_end)
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
        self.serve_fixed_probe_listener_with_progress(listener, &mut InertRuntimeProgressNotifier)
    }

    pub fn serve_fixed_probe_listener_with_progress(
        &mut self,
        listener: &UnixListener,
        progress: &mut dyn ObservationRuntimeProgressNotifier,
    ) -> io::Result<()> {
        let listener = listener.try_clone()?;
        listener.set_nonblocking(true)?;
        let (admission_sender, admission_receiver) = std::sync::mpsc::sync_channel(1);
        let (completion_sender, completion_receiver) = std::sync::mpsc::sync_channel(1);
        let mut admission = std::mem::take(&mut self.admission);
        // admission 线程只接收、校验与拒绝连接；它绝不发送 watchdog 进度，
        // 因而不能掩盖主线程中的 Collector 或 Provider 停滞。
        let admission_thread = std::thread::Builder::new()
            .name("enoki-runtime-admission".to_owned())
            .spawn(move || {
                serve_runtime_admission(
                    &listener,
                    &mut admission,
                    &admission_sender,
                    &completion_receiver,
                )
            })?;
        let serve_result =
            self.serve_admitted_windows(&admission_receiver, &completion_sender, progress);
        drop(completion_sender);
        let _ = admission_thread.join();
        serve_result
    }

    fn serve_admitted_windows(
        &mut self,
        admission_receiver: &std::sync::mpsc::Receiver<AdmissionMessage>,
        completion_sender: &std::sync::mpsc::SyncSender<Option<u64>>,
        progress: &mut dyn ObservationRuntimeProgressNotifier,
    ) -> io::Result<()> {
        progress.notify_ready()?;
        loop {
            let admitted = match admission_receiver.recv_timeout(RUNTIME_PROGRESS_INTERVAL) {
                Ok(AdmissionMessage::Window(admitted)) => admitted,
                Ok(AdmissionMessage::ListenerFailed(error)) => return Err(error),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    progress.notify_progress()?;
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Runtime admission stopped",
                    ));
                }
            };
            let mut sleeper = ThreadObservationRuntimeSleeper;
            let delivered = self.serve_admitted_window(
                admitted.stream,
                admitted.request,
                &mut sleeper,
                progress,
            );
            let delivered_sequence_end = delivered.as_ref().ok().copied();
            if completion_sender.send(delivered_sequence_end).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Runtime admission completion failed",
                ));
            }
            if let Err(AdmittedWindowError::Progress(error)) = delivered {
                return Err(error);
            }
        }
    }
}

fn serve_runtime_admission(
    listener: &UnixListener,
    admission: &mut ObservationWindowAdmission,
    sender: &std::sync::mpsc::SyncSender<AdmissionMessage>,
    completion_receiver: &std::sync::mpsc::Receiver<Option<u64>>,
) {
    loop {
        let mut accepted_connection = false;
        loop {
            let mut connection = match listener.accept() {
                Ok((connection, _)) => connection,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if recoverable_accept_error(&error) => continue,
                Err(error) => {
                    let _ = sender.send(AdmissionMessage::ListenerFailed(error));
                    return;
                }
            };
            accepted_connection = true;
            if require_peer_uid(connection.as_raw_fd(), c"enoki-probe").is_err() {
                continue;
            }
            if admission.active {
                let _ = configure_deadline(&connection, RUNTIME_REQUEST_DEADLINE)
                    .and_then(|()| write_window_failure(&mut connection));
                continue;
            }
            if configure_deadline(&connection, RUNTIME_REQUEST_DEADLINE).is_err() {
                continue;
            }
            let request = match read_runtime_request(&mut connection) {
                Ok(Some(RuntimeRequest::Window(request))) => request,
                Ok(None) => {
                    let _ = write_window_failure(&mut connection);
                    continue;
                }
                Err(_) => continue,
            };
            if admission.arrive(request, Instant::now()) == WindowAdmissionDecision::Reject {
                let _ = write_window_failure(&mut connection);
                continue;
            }
            if sender
                .send(AdmissionMessage::Window(AdmittedWindow {
                    request,
                    stream: connection,
                }))
                .is_err()
            {
                return;
            }
        }

        match completion_receiver.try_recv() {
            Ok(delivered_sequence_end) => admission.complete(delivered_sequence_end),
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
        }
        if !accepted_connection {
            std::thread::sleep(ADMISSION_POLL_INTERVAL);
        }
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

    #[test]
    fn normal_multi_connection_schedule_admits_only_after_the_current_window_completes() {
        let cadence = Duration::from_secs(1);
        let first = ObservationWindowRequest::new(cadence).unwrap();
        let next = first.with_sequence_start(4).unwrap();
        let started_at = Instant::now();
        let next_window_at = started_at + cadence * CPU_SAMPLES_PER_WINDOW as u32;
        let mut admission = ObservationWindowAdmission::default();

        assert_eq!(
            admission.arrive(first, started_at),
            WindowAdmissionDecision::Admit
        );
        assert_eq!(
            admission.arrive(next, next_window_at),
            WindowAdmissionDecision::Reject
        );
        admission.complete(Some(3));
        assert_eq!(
            admission.arrive(next, next_window_at),
            WindowAdmissionDecision::Admit
        );
    }

    #[test]
    fn uncompleted_delivery_releases_only_the_accepted_sequence() {
        let cadence = Duration::from_secs(1);
        let first = ObservationWindowRequest::new(cadence).unwrap();
        let recovery = first.with_sequence_start(2).unwrap();
        let started_at = Instant::now();
        let recovery_at = started_at + cadence * CPU_SAMPLES_PER_WINDOW as u32;
        let mut admission = ObservationWindowAdmission::default();

        assert_eq!(
            admission.arrive(first, started_at),
            WindowAdmissionDecision::Admit
        );
        admission.complete(None);
        assert_eq!(
            admission.arrive(recovery, recovery_at),
            WindowAdmissionDecision::Admit
        );
    }

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
            Some(Duration::from_secs(23))
        );
        assert_eq!(
            runtime_window_deadline(Duration::from_secs(200)),
            Some(Duration::from_secs(620))
        );
        assert!(ObservationWindowRequest::new(Duration::from_secs(1)).is_some());
        assert!(ObservationWindowRequest::new(Duration::from_secs(200)).is_some());
    }

    #[test]
    fn disk_health_capability_only_tracks_stable_support_facts() {
        for (status, expected) in [
            (DiskHealthCollectorCapabilityStatus::Available, true),
            (DiskHealthCollectorCapabilityStatus::MissingSmartctl, true),
            (
                DiskHealthCollectorCapabilityStatus::InsufficientLocalPrivilege,
                true,
            ),
            (
                DiskHealthCollectorCapabilityStatus::UnsupportedSmartData,
                true,
            ),
            (DiskHealthCollectorCapabilityStatus::HelperFailed, false),
            (DiskHealthCollectorCapabilityStatus::ScanFailed, false),
            (DiskHealthCollectorCapabilityStatus::MalformedOutput, false),
        ] {
            assert_eq!(
                stable_disk_health_capability(status),
                expected,
                "{status:?}"
            );
        }
    }

    #[test]
    fn typed_resource_facts_preserve_temperature_and_battery_calculation_inputs() {
        let wire = WireSystemStateResourceResult {
            temperature_inputs: vec!["42000".to_owned(), "38".to_owned()],
            battery_supplies: vec![crate::protocol::enoki::v1::BatterySupplyResourceFact {
                supply_type: "Battery".to_owned(),
                capacity: "87".to_owned(),
                status: "Discharging".to_owned(),
            }],
            ..Default::default()
        };
        let resource = decode_system_state_resource_result(&wire.encode_to_vec())
            .expect("typed System State result");

        assert_eq!(
            temperature_celsius_from_inputs(&resource.temperature_inputs),
            Some(42.0),
        );
        assert_eq!(
            resource.battery_supplies,
            vec![BatteryMetrics {
                percent: 87,
                state: "Discharging".to_owned(),
            }],
        );
    }
}

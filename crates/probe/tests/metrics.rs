use enoki_probe::host_profile::collect_local_host_profile;
use enoki_probe::local_privilege_boundary::PrivilegedCollectorHelperId;
use enoki_probe::metrics::{
    CollectorCadence, CollectorCadenceSchedule, CollectorDefinition, CollectorError, CollectorId,
    CollectorRegistry, DiskHealthAvailability, DiskHealthCollection, DiskHealthCollectionError,
    DiskHealthMetricCollector, DiskHealthMetricsRunner, FilesystemCapacity, MetricCollector,
    MetricsCollectionConfig, collect_battery_metrics_from_sysfs,
    collect_cpu_metrics_from_proc_stat, collect_default_route_interfaces_from_proc_routes,
    collect_disk_counters_from_proc_diskstats, collect_disk_health_metrics_from_smartctl_json,
    collect_disk_health_metrics_with_smartctl_at, collect_disk_metrics_from_mounts,
    collect_load_metrics_from_proc_loadavg, collect_memory_metrics_from_proc_meminfo,
    collect_network_metrics_from_proc_net_dev, collect_temperature_celsius_from_sysfs,
    collect_uptime_seconds_from_proc_uptime,
};
use enoki_probe::privileged_collector_helpers::run_compiled_privileged_collector_helper;
use enoki_probe::protocol::enoki::v1::MetricSample;
use enoki_probe::protocol::enoki::v1::{DiskHealthCollectorCapabilityStatus, DiskHealthMetric};
use std::{
    ffi::OsString, fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::Mutex, time::Duration,
};

static SMARTCTL_PATH_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn collector_registry_reports_only_collectors_due_for_their_cadence_class() {
    let mut registry = CollectorRegistry::from_collectors(vec![
        Box::new(FakeCollector {
            cadence: CollectorCadence::EveryTick,
            field: FakeMetricField::Cpu,
            calls: 0,
            fail: false,
        }),
        Box::new(FakeCollector {
            cadence: CollectorCadence::Every12Ticks,
            field: FakeMetricField::Load,
            calls: 0,
            fail: false,
        }),
    ]);
    let schedule = CollectorCadenceSchedule::new(Duration::from_secs(5));
    let config = MetricsCollectionConfig::all_enabled();

    let first = registry
        .collect_due(2, Duration::from_secs(5), schedule, &config)
        .expect("high-frequency collector emits the first sample");
    assert_eq!(first.sequence, 2);
    assert_eq!(first.cpu_percent, Some(42.0));
    assert_eq!(first.load_1, None);

    let second = registry
        .collect_due(3, Duration::from_secs(60), schedule, &config)
        .expect("every-tick and every-12-ticks collectors emit when due");
    assert_eq!(second.sequence, 3);
    assert_eq!(second.cpu_percent, Some(43.0));
    assert_eq!(second.load_1, Some(1.0));
}

#[test]
fn collector_registry_returns_no_sample_when_no_collector_produces_new_data() {
    let mut registry = CollectorRegistry::from_collectors(vec![Box::new(FakeCollector {
        cadence: CollectorCadence::Every12Ticks,
        field: FakeMetricField::Load,
        calls: 0,
        fail: false,
    })]);
    let schedule = CollectorCadenceSchedule::new(Duration::from_secs(5));
    let config = MetricsCollectionConfig::all_enabled();

    assert!(
        registry
            .collect_due(2, Duration::from_secs(5), schedule, &config)
            .is_none()
    );

    assert_eq!(
        registry
            .collect_due(3, Duration::from_secs(60), schedule, &config)
            .expect("every-12-ticks collector is due")
            .load_1,
        Some(1.0),
    );
    assert!(
        registry
            .collect_due(4, Duration::from_secs(65), schedule, &config)
            .is_none()
    );
}

#[test]
fn collector_registry_skips_collectors_not_enabled_by_id() {
    let mut registry = CollectorRegistry::from_collectors(vec![
        Box::new(FakeCollector {
            cadence: CollectorCadence::EveryTick,
            field: FakeMetricField::Cpu,
            calls: 0,
            fail: false,
        }),
        Box::new(FakeCollector {
            cadence: CollectorCadence::EveryTick,
            field: FakeMetricField::Memory,
            calls: 0,
            fail: false,
        }),
    ]);
    let schedule = CollectorCadenceSchedule::new(Duration::from_secs(5));
    let config = MetricsCollectionConfig::from_enabled_collectors([CollectorId::Memory]);

    let sample = registry
        .collect_due(2, Duration::from_secs(5), schedule, &config)
        .expect("enabled collector emits");

    assert_eq!(sample.cpu_percent, None);
    assert_eq!(sample.memory_used_bytes, Some(1024));
}

#[test]
fn startup_collectors_emit_only_on_the_first_tick() {
    let mut registry = CollectorRegistry::from_collectors(vec![Box::new(FakeCollector {
        cadence: CollectorCadence::Startup,
        field: FakeMetricField::Load,
        calls: 0,
        fail: false,
    })]);
    let schedule = CollectorCadenceSchedule::new(Duration::from_secs(5));
    let config = MetricsCollectionConfig::all_enabled();

    assert_eq!(
        registry
            .collect_due(2, Duration::from_secs(5), schedule, &config)
            .expect("startup collector emits on the first tick")
            .load_1,
        Some(1.0),
    );
    assert!(
        registry
            .collect_due(3, Duration::from_secs(10), schedule, &config)
            .is_none()
    );
}

#[test]
fn collector_registry_isolates_failed_collectors_from_successful_collectors() {
    let mut registry = CollectorRegistry::from_collectors(vec![
        Box::new(FakeCollector {
            cadence: CollectorCadence::EveryTick,
            field: FakeMetricField::Cpu,
            calls: 0,
            fail: true,
        }),
        Box::new(FakeCollector {
            cadence: CollectorCadence::EveryTick,
            field: FakeMetricField::Memory,
            calls: 0,
            fail: false,
        }),
    ]);
    let schedule = CollectorCadenceSchedule::new(Duration::from_secs(5));

    let sample = registry
        .collect_due(
            2,
            Duration::from_secs(5),
            schedule,
            &MetricsCollectionConfig::all_enabled(),
        )
        .expect("successful collector still emits");

    assert_eq!(sample.cpu_percent, None);
    assert_eq!(sample.memory_used_bytes, Some(1024));
}

#[test]
fn failed_collectors_wait_for_their_cadence_before_retrying() {
    let mut registry = CollectorRegistry::from_collectors(vec![
        Box::new(FakeCollector {
            cadence: CollectorCadence::EveryTick,
            field: FakeMetricField::Cpu,
            calls: 0,
            fail: false,
        }),
        Box::new(FakeCollector {
            cadence: CollectorCadence::Every12Ticks,
            field: FakeMetricField::Load,
            calls: 0,
            fail: true,
        }),
    ]);
    let schedule = CollectorCadenceSchedule::new(Duration::from_secs(5));
    let config = MetricsCollectionConfig::all_enabled();

    let first = registry
        .collect_due(2, Duration::from_secs(60), schedule, &config)
        .expect("every-tick collector still emits");
    assert_eq!(first.cpu_percent, Some(42.0));
    assert_eq!(first.load_1, None);

    let second = registry
        .collect_due(3, Duration::from_secs(65), schedule, &config)
        .expect("only every-tick collector is retried before every-12-ticks cadence");
    assert_eq!(second.cpu_percent, Some(43.0));
    assert_eq!(second.load_1, None);

    let third = registry
        .collect_due(4, Duration::from_secs(120), schedule, &config)
        .expect("every-12-ticks collector is retried once its cadence elapses");
    assert_eq!(third.cpu_percent, Some(44.0));
    assert_eq!(third.load_1, None);
}

#[test]
fn failed_collector_partial_writes_do_not_leak_into_successful_sample() {
    let mut registry = CollectorRegistry::from_collectors(vec![
        Box::new(FakeCollector {
            cadence: CollectorCadence::EveryTick,
            field: FakeMetricField::Cpu,
            calls: 0,
            fail: true,
        }),
        Box::new(FakeCollector {
            cadence: CollectorCadence::EveryTick,
            field: FakeMetricField::Memory,
            calls: 0,
            fail: false,
        }),
    ]);
    let schedule = CollectorCadenceSchedule::new(Duration::from_secs(5));

    let sample = registry
        .collect_due(
            2,
            Duration::from_secs(5),
            schedule,
            &MetricsCollectionConfig::all_enabled(),
        )
        .expect("successful collector still emits");

    assert_eq!(sample.cpu_percent, None);
    assert_eq!(sample.memory_used_bytes, Some(1024));
}

#[test]
fn smartctl_json_fixture_parses_disk_health_metrics() {
    let metrics = collect_disk_health_metrics_from_smartctl_json(
        "/dev/sda",
        r#"{
          "model_name": "Samsung SSD 870 EVO 1TB",
          "serial_number": "S6PTEST",
          "smart_status": { "passed": true },
          "temperature": { "current": 31 },
          "power_on_time": { "hours": 12345 }
        }"#,
    )
    .expect("healthy smartctl fixture parses")
    .expect("SMART data is available");

    assert_eq!(metrics.device_name, "/dev/sda");
    assert_eq!(metrics.model, "Samsung SSD 870 EVO 1TB");
    assert_eq!(metrics.serial_number, "S6PTEST");
    assert!(metrics.passed);
    assert_eq!(metrics.temperature_celsius, Some(31.0));
    assert_eq!(metrics.power_on_hours, Some(12_345));
}

#[test]
fn smartctl_json_fixture_reports_unavailable_when_smart_is_unsupported() {
    let unavailable = collect_disk_health_metrics_from_smartctl_json(
        "/dev/vda",
        r#"{
          "model_name": "QEMU HARDDISK",
          "smart_support": { "available": false }
        }"#,
    )
    .expect("unsupported SMART fixture is a parsed capability result");

    assert_eq!(unavailable, None);
}

#[test]
fn smartctl_json_fixture_parses_warning_disk_health_without_optional_fields() {
    let metrics = collect_disk_health_metrics_from_smartctl_json(
        "/dev/sdb",
        r#"{
          "smart_status": { "passed": false }
        }"#,
    )
    .expect("warning smartctl fixture parses")
    .expect("SMART status is available");

    assert_eq!(metrics.device_name, "/dev/sdb");
    assert_eq!(metrics.model, "");
    assert_eq!(metrics.serial_number, "");
    assert!(!metrics.passed);
    assert_eq!(metrics.temperature_celsius, None);
    assert_eq!(metrics.power_on_hours, None);
}

#[test]
fn smartctl_json_fixture_rejects_malformed_output() {
    let error = collect_disk_health_metrics_from_smartctl_json("/dev/sdc", "{")
        .expect_err("malformed smartctl JSON is rejected");

    assert!(error.is_eof() || error.is_syntax());
}

#[test]
fn smartctl_capability_detection_distinguishes_parser_errors_from_unavailable_disks() {
    assert_eq!(
        DiskHealthAvailability::from_smartctl_result(Ok(
            collect_disk_health_metrics_from_smartctl_json(
                "/dev/sdb",
                r#"{"smart_status":{"passed":false}}"#,
            )
            .expect("fixture parses"),
        )),
        DiskHealthAvailability::Available,
    );
    assert_eq!(
        DiskHealthAvailability::from_smartctl_result(Ok(None)),
        DiskHealthAvailability::Unavailable,
    );
    assert_eq!(
        DiskHealthAvailability::from_smartctl_result(
            collect_disk_health_metrics_from_smartctl_json("/dev/sdb", "{")
        ),
        DiskHealthAvailability::Unavailable,
    );
}

#[test]
fn smartctl_device_failure_without_stdout_is_reported_as_helper_failure() {
    let _lock = SMARTCTL_PATH_TEST_LOCK.lock().expect("smartctl PATH lock");
    let tempdir = tempfile::tempdir().expect("tempdir");
    let smartctl = tempdir.path().join("smartctl");
    fs::write(
        &smartctl,
        r#"#!/bin/sh
if [ "$1" = "--scan-open" ]; then
  printf '{"devices":[{"name":"/dev/sdz"}]}'
  exit 0
fi
if [ "$1" = "-a" ]; then
  exit 4
fi
exit 2
"#,
    )
    .expect("fake smartctl");
    fs::set_permissions(&smartctl, fs::Permissions::from_mode(0o755))
        .expect("fake smartctl is executable");
    let error = collect_disk_health_metrics_with_smartctl_at(&smartctl)
        .expect_err("smartctl -a failure with no stdout is not silently skipped");

    assert_eq!(
        error.status,
        DiskHealthCollectorCapabilityStatus::HelperFailed
    );
    assert_eq!(error.diagnostic, "smartctl failed for /dev/sdz");
}

#[test]
fn privileged_disk_health_helper_ignores_path_injected_smartctl() {
    let _lock = SMARTCTL_PATH_TEST_LOCK.lock().expect("smartctl PATH lock");
    let tempdir = tempfile::tempdir().expect("tempdir");
    let smartctl = tempdir.path().join("smartctl");
    let marker = tempdir.path().join("path-injected-smartctl-ran");
    fs::write(
        &smartctl,
        r#"#!/bin/sh
printf ran > "$ENOKI_SMARTCTL_MARKER"
if [ "$1" = "--scan-open" ]; then
  printf '{"devices":[{"name":"/dev/path-injected"}]}'
  exit 0
fi
if [ "$1" = "-a" ]; then
  printf '{"smart_status":{"passed":true}}'
  exit 0
fi
exit 0
"#,
    )
    .expect("fake smartctl");
    fs::set_permissions(&smartctl, fs::Permissions::from_mode(0o755))
        .expect("fake smartctl is executable");
    let path_guard = PathRestoreGuard::new();
    let marker_guard = EnvVarRestoreGuard::new("ENOKI_SMARTCTL_MARKER");
    let fake_path = match path_guard.original_path.as_ref() {
        Some(path) => {
            let mut paths = vec![PathBuf::from(tempdir.path())];
            paths.extend(std::env::split_paths(path));
            std::env::join_paths(paths).expect("joined PATH")
        }
        None => tempdir.path().as_os_str().to_os_string(),
    };

    unsafe {
        std::env::set_var("PATH", &fake_path);
        std::env::set_var("ENOKI_SMARTCTL_MARKER", &marker);
    }
    let _path_guard = path_guard;
    let _marker_guard = marker_guard;
    let output =
        run_compiled_privileged_collector_helper(PrivilegedCollectorHelperId::DiskHealthSmartctl)
            .expect("compiled disk health helper returns a typed collection");

    assert!(!marker.exists());
    assert!(!output.contains("/dev/path-injected"));
}

struct PathRestoreGuard {
    original_path: Option<OsString>,
}

impl PathRestoreGuard {
    fn new() -> Self {
        Self {
            original_path: std::env::var_os("PATH"),
        }
    }
}

impl Drop for PathRestoreGuard {
    fn drop(&mut self) {
        if let Some(path) = self.original_path.take() {
            unsafe {
                std::env::set_var("PATH", path);
            }
        } else {
            unsafe {
                std::env::remove_var("PATH");
            }
        }
    }
}

struct EnvVarRestoreGuard {
    name: &'static str,
    original_value: Option<OsString>,
}

impl EnvVarRestoreGuard {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            original_value: std::env::var_os(name),
        }
    }
}

impl Drop for EnvVarRestoreGuard {
    fn drop(&mut self) {
        if let Some(value) = self.original_value.take() {
            unsafe {
                std::env::set_var(self.name, value);
            }
        } else {
            unsafe {
                std::env::remove_var(self.name);
            }
        }
    }
}

#[test]
fn disk_health_collector_uses_low_frequency_cadence_and_reports_only_new_results() {
    let mut registry = CollectorRegistry::from_collectors(vec![Box::new(
        DiskHealthMetricCollector::new(FakeDiskHealthRunner {
            batches: vec![vec![DiskHealthMetric {
                device_name: "/dev/sda".to_string(),
                model: "Samsung SSD 870 EVO 1TB".to_string(),
                passed: true,
                power_on_hours: Some(12_345),
                role: String::new(),
                serial_number: "S6PTEST".to_string(),
                temperature_celsius: Some(31.0),
                total_bytes: None,
                usage_mount_point: String::new(),
                used_bytes: None,
            }]],
        }),
    )]);
    let schedule = CollectorCadenceSchedule::new(Duration::from_secs(5));

    assert!(
        registry
            .collect_due(
                1,
                Duration::from_secs(5),
                schedule,
                &MetricsCollectionConfig::all_enabled(),
            )
            .is_none()
    );

    let low_frequency_sample = registry
        .collect_due(
            2,
            Duration::from_secs(60),
            schedule,
            &MetricsCollectionConfig::all_enabled(),
        )
        .expect("Disk Health emits when the low-frequency cadence is due");
    assert_eq!(low_frequency_sample.disk_health.len(), 1);
    assert_eq!(low_frequency_sample.disk_health[0].device_name, "/dev/sda");

    assert!(
        registry
            .collect_due(
                3,
                Duration::from_secs(65),
                schedule,
                &MetricsCollectionConfig::all_enabled(),
            )
            .is_none()
    );
}

#[test]
fn disk_health_collector_result_updates_host_profile_capability() {
    let mut sample = MetricSample::default();
    let mut successful_collector = DiskHealthMetricCollector::new(FakeDiskHealthRunner {
        batches: vec![vec![DiskHealthMetric {
            device_name: "/dev/sda".to_string(),
            model: "Samsung SSD 870 EVO 1TB".to_string(),
            passed: true,
            power_on_hours: Some(12_345),
            role: String::new(),
            serial_number: "S6PTEST".to_string(),
            temperature_celsius: Some(31.0),
            total_bytes: None,
            usage_mount_point: String::new(),
            used_bytes: None,
        }]],
    });

    assert!(
        successful_collector
            .collect(&mut sample)
            .expect("successful disk health collection emits metrics")
    );
    assert_eq!(local_disk_health_capability(), Some(true));

    let mut unsupported_collector = DiskHealthMetricCollector::new(FakeDiskHealthRunner {
        batches: vec![vec![]],
    });
    assert!(
        !unsupported_collector
            .collect(&mut sample)
            .expect("unsupported SMART is a successful unavailable result")
    );
    assert_eq!(local_disk_health_capability(), Some(false));

    let mut failing_collector = DiskHealthMetricCollector::new(FailingDiskHealthRunner {
        status: DiskHealthCollectorCapabilityStatus::InsufficientLocalPrivilege,
        diagnostic: "smartctl permission denied",
    });
    assert!(failing_collector.collect(&mut sample).is_err());
    assert_eq!(local_disk_health_capability(), Some(false));
}

#[test]
fn disk_health_success_updates_host_profile_with_domain_status() {
    let mut sample = MetricSample::default();
    let mut collector = DiskHealthMetricCollector::new(FakeDiskHealthRunner {
        batches: vec![vec![DiskHealthMetric {
            device_name: "/dev/sda".to_string(),
            model: "Samsung SSD 870 EVO 1TB".to_string(),
            passed: true,
            power_on_hours: Some(12_345),
            role: String::new(),
            serial_number: "S6PTEST".to_string(),
            temperature_celsius: Some(31.0),
            total_bytes: None,
            usage_mount_point: String::new(),
            used_bytes: None,
        }]],
    });

    assert!(
        collector
            .collect(&mut sample)
            .expect("successful disk health collection emits metrics")
    );

    assert_eq!(
        local_disk_health_capability_status(),
        Some(DiskHealthCollectorCapabilityStatus::Available)
    );
}

#[test]
fn disk_health_failures_update_host_profile_with_domain_status() {
    for (status, diagnostic) in [
        (
            DiskHealthCollectorCapabilityStatus::MissingSmartctl,
            "smartctl is not installed",
        ),
        (
            DiskHealthCollectorCapabilityStatus::InsufficientLocalPrivilege,
            "sudo rejected privileged helper execution",
        ),
        (
            DiskHealthCollectorCapabilityStatus::HelperFailed,
            "privileged helper failed",
        ),
        (
            DiskHealthCollectorCapabilityStatus::ScanFailed,
            "smartctl scan failed",
        ),
        (
            DiskHealthCollectorCapabilityStatus::MalformedOutput,
            "smartctl output malformed",
        ),
        (
            DiskHealthCollectorCapabilityStatus::UnsupportedSmartData,
            "SMART data is unsupported",
        ),
    ] {
        let mut sample = MetricSample::default();
        let mut collector =
            DiskHealthMetricCollector::new(FailingDiskHealthRunner { status, diagnostic });

        assert!(collector.collect(&mut sample).is_err());
        assert_eq!(local_disk_health_capability_status(), Some(status));
        assert_eq!(
            local_disk_health_capability_diagnostic(),
            Some(diagnostic.to_string())
        );
    }
}

struct FakeDiskHealthRunner {
    batches: Vec<Vec<DiskHealthMetric>>,
}

impl DiskHealthMetricsRunner for FakeDiskHealthRunner {
    fn collect_disk_health_metrics(
        &mut self,
    ) -> Result<DiskHealthCollection, DiskHealthCollectionError> {
        let metrics = self.batches.pop().unwrap_or_default();
        if metrics.is_empty() {
            return Ok(DiskHealthCollection::unavailable(
                DiskHealthCollectorCapabilityStatus::UnsupportedSmartData,
                "SMART data is unsupported",
            ));
        }

        Ok(DiskHealthCollection::available(metrics))
    }
}

struct FailingDiskHealthRunner {
    status: DiskHealthCollectorCapabilityStatus,
    diagnostic: &'static str,
}

impl DiskHealthMetricsRunner for FailingDiskHealthRunner {
    fn collect_disk_health_metrics(
        &mut self,
    ) -> Result<DiskHealthCollection, DiskHealthCollectionError> {
        Err(DiskHealthCollectionError::new(self.status, self.diagnostic))
    }
}

fn local_disk_health_capability() -> Option<bool> {
    collect_local_host_profile()
        .collector_capabilities
        .and_then(|capabilities| capabilities.official)
        .and_then(|official| official.disk_health)
        .map(|capability| capability.status() == DiskHealthCollectorCapabilityStatus::Available)
}

fn local_disk_health_capability_status() -> Option<DiskHealthCollectorCapabilityStatus> {
    collect_local_host_profile()
        .collector_capabilities
        .and_then(|capabilities| capabilities.official)
        .and_then(|official| official.disk_health)
        .map(|capability| capability.status())
}

fn local_disk_health_capability_diagnostic() -> Option<String> {
    collect_local_host_profile()
        .collector_capabilities
        .and_then(|capabilities| capabilities.official)
        .and_then(|official| official.disk_health)
        .map(|capability| capability.diagnostic)
}

#[derive(Clone, Copy)]
enum FakeMetricField {
    Cpu,
    Load,
    Memory,
}

struct FakeCollector {
    cadence: CollectorCadence,
    field: FakeMetricField,
    calls: u32,
    fail: bool,
}

impl MetricCollector for FakeCollector {
    fn definition(&self) -> CollectorDefinition {
        CollectorDefinition::new(self.field.collector_id(), self.cadence)
    }

    fn collect(&mut self, sample: &mut MetricSample) -> Result<bool, CollectorError> {
        self.calls += 1;
        match self.field {
            FakeMetricField::Cpu => sample.cpu_percent = Some(41.0 + f64::from(self.calls)),
            FakeMetricField::Load => sample.load_1 = Some(f64::from(self.calls)),
            FakeMetricField::Memory => sample.memory_used_bytes = Some(1024),
        }

        if self.fail {
            return Err(CollectorError::new("fake collector failed"));
        }

        Ok(true)
    }
}

impl FakeMetricField {
    fn collector_id(self) -> CollectorId {
        match self {
            FakeMetricField::Cpu => CollectorId::Cpu,
            FakeMetricField::Load => CollectorId::Load,
            FakeMetricField::Memory => CollectorId::Memory,
        }
    }
}

#[test]
fn cpu_metrics_compute_usage_from_counter_deltas() {
    let previous = collect_cpu_metrics_from_proc_stat(
        [
            "cpu  100 10 40 850 0 0 0 0 0 0",
            "cpu0 60 5 20 400 0 0 0 0 0 0",
            "cpu1 40 5 20 450 0 0 0 0 0 0",
            "",
        ]
        .join("\n")
        .as_str(),
        None,
    )
    .expect("previous cpu metrics parse");
    let current_proc_stat = [
        "cpu  110 15 45 930 0 0 0 0 0 0",
        "cpu0 70 5 25 450 0 0 0 0 0 0",
        "cpu1 40 10 20 480 0 0 0 0 0 0",
        "",
    ]
    .join("\n");

    assert_close(previous.aggregate_percent, 0.0);
    assert!(previous.cores.iter().all(|core| core.usage_percent == 0.0));

    let metrics = collect_cpu_metrics_from_proc_stat(&current_proc_stat, Some(&previous.snapshot))
        .expect("current cpu metrics parse");

    assert_close(metrics.aggregate_percent, 20.0);
    assert_close(metrics.breakdown.user_percent, 15.0);
    assert_close(metrics.breakdown.system_percent, 5.0);
    assert_close(metrics.breakdown.idle_percent, 80.0);
    assert_eq!(
        metrics
            .cores
            .iter()
            .map(|core| (&core.name, core.user, core.nice, core.system, core.idle))
            .collect::<Vec<_>>(),
        vec![
            (&"cpu0".to_string(), 70, 5, 25, 450),
            (&"cpu1".to_string(), 40, 10, 20, 480),
        ],
    );
    assert_close(metrics.cores[0].usage_percent, 23.076923076923077);
    assert_close(metrics.cores[1].usage_percent, 14.285714285714285);
}

#[test]
fn cpu_metrics_parse_proc_stat_per_core_counters_and_establish_baseline() {
    let proc_stat = [
        "cpu  100 10 40 850 0 0 0 0 0 0",
        "cpu0 60 5 20 400 0 0 0 0 0 0",
        "cpu1 40 5 20 450 0 0 0 0 0 0",
        "",
    ]
    .join("\n");

    let metrics = collect_cpu_metrics_from_proc_stat(&proc_stat, None).expect("cpu metrics parse");

    assert_close(metrics.aggregate_percent, 0.0);
    assert_eq!(
        metrics
            .cores
            .iter()
            .map(|core| (&core.name, core.user, core.nice, core.system, core.idle))
            .collect::<Vec<_>>(),
        vec![
            (&"cpu0".to_string(), 60, 5, 20, 400),
            (&"cpu1".to_string(), 40, 5, 20, 450),
        ],
    );
    assert_close(metrics.cores[0].usage_percent, 0.0);
    assert_close(metrics.cores[1].usage_percent, 0.0);
}

#[test]
fn memory_load_and_uptime_metrics_parse_linux_host_sources() {
    let meminfo = [
        "MemTotal:        2048000 kB",
        "MemFree:          128000 kB",
        "MemAvailable:    1536000 kB",
        "Buffers:           64000 kB",
        "Cached:           256000 kB",
        "SReclaimable:      32000 kB",
        "Shmem:             16000 kB",
        "SwapTotal:       1024000 kB",
        "SwapFree:         768000 kB",
        "",
    ]
    .join("\n");

    let memory = collect_memory_metrics_from_proc_meminfo(&meminfo).expect("memory parses");
    let load =
        collect_load_metrics_from_proc_loadavg("0.12 0.34 0.56 1/234 5678").expect("load parses");
    let uptime =
        collect_uptime_seconds_from_proc_uptime("12345.67 89012.34").expect("uptime parses");

    assert_eq!(memory.total_bytes, 2_097_152_000);
    assert_eq!(memory.used_bytes, 524_288_000);
    assert_eq!(memory.cache_bytes, 344_064_000);
    assert_eq!(memory.swap_total_bytes, 1_048_576_000);
    assert_eq!(memory.swap_used_bytes, 262_144_000);
    assert_close(load.one, 0.12);
    assert_close(load.five, 0.34);
    assert_close(load.fifteen, 0.56);
    assert_eq!(uptime, 12_345);
}

#[test]
fn disk_metrics_include_real_mounts_and_exclude_pseudo_runtime_and_duplicates() {
    let mounts = [
        "/dev/vda1 / ext4 rw,relatime 0 0",
        "tmpfs /run tmpfs rw,nosuid,nodev 0 0",
        "proc /proc proc rw,nosuid,nodev,noexec 0 0",
        "overlay /var/lib/docker/overlay2 overlay rw 0 0",
        "/dev/vdb1 /srv/data xfs rw,relatime 0 0",
        "/dev/vdb1 /srv/data xfs rw,relatime 0 0",
        "/dev/vdb1 /srv/data-bind xfs rw,bind 0 0",
        "/dev/vdc1 /mnt/empty ext4 rw,relatime 0 0",
        "/dev/vdd1 /media/My\\040Disk ext4 rw,relatime 0 0",
        "",
    ]
    .join("\n");

    let disks = collect_disk_metrics_from_mounts(
        &mounts,
        |mount_point| match mount_point {
            "/" => Some(FilesystemCapacity {
                available_bytes: 300,
                free_bytes: 250,
                total_bytes: 1_000,
            }),
            "/srv/data" => Some(FilesystemCapacity {
                available_bytes: 1_000,
                free_bytes: 900,
                total_bytes: 4_000,
            }),
            "/srv/data-bind" => Some(FilesystemCapacity {
                available_bytes: 1_100,
                free_bytes: 950,
                total_bytes: 4_000,
            }),
            "/mnt/empty" => Some(FilesystemCapacity {
                available_bytes: 0,
                free_bytes: 0,
                total_bytes: 0,
            }),
            "/media/My Disk" => Some(FilesystemCapacity {
                available_bytes: 2_000,
                free_bytes: 1_500,
                total_bytes: 5_000,
            }),
            _ => None,
        },
        None,
        None,
    );

    assert_eq!(
        disks
            .iter()
            .map(|disk| {
                (
                    disk.mount_point.as_str(),
                    disk.filesystem_type.as_str(),
                    disk.used_bytes,
                    disk.total_bytes,
                )
            })
            .collect::<Vec<_>>(),
        vec![
            ("/", "ext4", 750, 1_000),
            ("/media/My Disk", "ext4", 3_500, 5_000),
            ("/srv/data", "xfs", 3_100, 4_000),
        ],
    );
}

#[test]
fn disk_metrics_include_io_deltas_when_diskstats_match_mount_source() {
    let previous = collect_disk_counters_from_proc_diskstats(
        " 253 0 vda1 10 0 20 40 30 0 50 60 0 70 80 0 0 0 0\n",
    )
    .expect("previous diskstats");
    std::thread::sleep(std::time::Duration::from_millis(2));
    let current = collect_disk_counters_from_proc_diskstats(
        " 253 0 vda1 15 0 28 50 34 0 58 72 0 78 90 0 0 0 0\n",
    )
    .expect("current diskstats");

    let disks = collect_disk_metrics_from_mounts(
        "/dev/vda1 / ext4 rw,relatime 0 0\n",
        |_| {
            Some(FilesystemCapacity {
                available_bytes: 300,
                free_bytes: 250,
                total_bytes: 1_000,
            })
        },
        Some(&current),
        Some(&previous),
    );

    assert_eq!(disks.len(), 1);
    assert_eq!(disks[0].read_bytes_delta, 8 * 512);
    assert_eq!(disks[0].write_bytes_delta, 8 * 512);
    assert_close(disks[0].read_await_ms.unwrap_or_default(), 2.0);
    assert_close(disks[0].write_await_ms.unwrap_or_default(), 3.0);
    assert!(disks[0].io_utilization_percent.unwrap_or_default() >= 0.0);
}

#[test]
fn network_metrics_exclude_loopback_and_compute_deltas_per_interface() {
    let previous = collect_network_metrics_from_proc_net_dev(
        [
            "Inter-|   Receive                                                |  Transmit",
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
            "    lo: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0",
            "  eth0: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0",
            "",
        ]
        .join("\n")
        .as_str(),
        None,
        None,
    )
    .expect("previous network metrics parse");

    let current = collect_network_metrics_from_proc_net_dev(
        [
            "Inter-|   Receive                                                |  Transmit",
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
            "    lo: 1500 15 0 0 0 0 0 0 2600 26 0 0 0 0 0 0",
            "  eth0: 9000 90 0 0 0 0 0 0 9000 90 0 0 0 0 0 0",
            "",
        ]
        .join("\n")
        .as_str(),
        None,
        Some(&previous.snapshot),
    )
    .expect("current network metrics parse");

    assert_eq!(
        current
            .interfaces
            .iter()
            .map(|interface| {
                (
                    interface.name.as_str(),
                    interface.rx_bytes,
                    interface.tx_bytes,
                    interface.rx_bytes_delta,
                    interface.tx_bytes_delta,
                )
            })
            .collect::<Vec<_>>(),
        vec![("eth0", 9_000, 9_000, 4_000, 2_000),],
    );
}

#[test]
fn network_metrics_keep_only_default_route_interfaces_when_known() {
    let included_interfaces = collect_default_route_interfaces_from_proc_routes(
        Some(
            [
                "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
                "docker0\t00000000\t010011AC\t0003\t0\t0\t200\t00000000\t0\t0\t0",
                "eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0",
                "br-app\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0",
            ]
            .join("\n")
            .as_str(),
        ),
        None,
    )
    .expect("default route interfaces");

    let current = collect_network_metrics_from_proc_net_dev(
        [
            "Inter-|   Receive                                                |  Transmit",
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
            "  eth0: 9000 90 0 0 0 0 0 0 9000 90 0 0 0 0 0 0",
            "docker0: 7000 70 0 0 0 0 0 0 8000 80 0 0 0 0 0 0",
            "br-app: 6000 60 0 0 0 0 0 0 7000 70 0 0 0 0 0 0",
            "veth1: 5000 50 0 0 0 0 0 0 6000 60 0 0 0 0 0 0",
            "",
        ]
        .join("\n")
        .as_str(),
        Some(&included_interfaces),
        None,
    )
    .expect("network metrics parse");

    assert_eq!(
        current
            .interfaces
            .iter()
            .map(|interface| interface.name.as_str())
            .collect::<Vec<_>>(),
        vec!["eth0"],
    );
}

#[test]
fn temperature_and_battery_metrics_parse_linux_sysfs() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let hwmon = tempdir.path().join("hwmon0");
    std::fs::create_dir(&hwmon).expect("hwmon dir");
    std::fs::write(hwmon.join("name"), "coretemp\n").expect("sensor name");
    std::fs::write(hwmon.join("temp1_input"), "42000\n").expect("temperature");

    assert_close(
        collect_temperature_celsius_from_sysfs(tempdir.path()).expect("temperature"),
        42.0,
    );

    let powerdir = tempfile::tempdir().expect("power dir");
    let battery = powerdir.path().join("BAT0");
    std::fs::create_dir(&battery).expect("battery dir");
    std::fs::write(battery.join("type"), "Battery\n").expect("battery type");
    std::fs::write(battery.join("capacity"), "87\n").expect("battery capacity");
    std::fs::write(battery.join("status"), "Discharging\n").expect("battery status");

    let metrics = collect_battery_metrics_from_sysfs(powerdir.path()).expect("battery");
    assert_eq!(metrics.percent, 87);
    assert_eq!(metrics.state, "Discharging");
}

#[test]
fn default_route_interfaces_include_equal_metric_ipv4_and_ipv6_routes() {
    let interfaces = collect_default_route_interfaces_from_proc_routes(
        Some(
            [
                "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
                "eth1\t00000000\t010011AC\t0003\t0\t0\t10\t00000000\t0\t0\t0",
                "eth0\t00000000\t010011AC\t0003\t0\t0\t10\t00000000\t0\t0\t0",
            ]
            .join("\n")
            .as_str(),
        ),
        Some(
            [
                "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 0000000a 00000001 00000000 00200200 wg0",
                "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo",
            ]
            .join("\n")
            .as_str(),
        ),
    )
    .expect("default route interfaces");

    assert_eq!(
        interfaces.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["eth0", "eth1", "wg0"],
    );
}

fn assert_close(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < 0.000_000_1,
        "expected {actual} to be close to {expected}",
    );
}

use enoki_probe::observation_runtime::{
    DISK_HEALTH_RESOURCE, DiskHealthProvider, ObservationRuntime, ObservationWindowRequest,
    ResourceAccess, SYSTEM_STATE_RESOURCE, SystemStateProvider, SystemStateResourceResult,
    decode_disk_health_resource_result, decode_system_state_resource_result,
    static_collector_registry,
};
use enoki_probe::protocol::enoki::v1::{
    BatterySupplyResourceFact, CpuCounterResourceFact, DiskHealthCollectorCapabilityStatus,
    DiskHealthDeviceResourceFact, DiskHealthResourceResult as WireDiskHealthResourceResult,
    FilesystemCapacityResourceFact, SystemStateResourceResult as WireSystemStateResourceResult,
};
use prost::Message;
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

    let batch = runtime.collect_next_window(
        ObservationWindowRequest::new(Duration::from_secs(5)).unwrap(),
        &mut sleeper,
    );

    assert_eq!(batch.attempts.len(), 3);
    assert_eq!(
        batch
            .attempts
            .iter()
            .map(|attempt| attempt.sample.as_ref().unwrap().collected_at_ms)
            .collect::<Vec<_>>(),
        [5_000, 10_000, 15_000]
    );
    assert_eq!(sleeper.sleeps, vec![Duration::from_secs(5); 3]);
    assert_eq!(runtime.into_provider().calls, 3);
}

#[test]
fn cpu_observation_window_uses_one_fixed_resource_result_and_keeps_delta_state_in_runtime() {
    let descriptor = static_collector_registry()
        .resource(SYSTEM_STATE_RESOURCE)
        .expect("CPU counters Resource is build-fixed");
    assert_eq!(descriptor.access, ResourceAccess::SystemState);
    assert_eq!(descriptor.max_results_per_attempt, 1);
    assert!(!descriptor.request_accepts_caller_input);

    let provider = RecordingCpuProvider::new([
        "cpu  100 0 0 900 0 0 0 0 0 0\ncpu0 100 0 0 900 0 0 0 0 0 0\n",
        "cpu  120 0 0 980 0 0 0 0 0 0\ncpu0 120 0 0 980 0 0 0 0 0 0\n",
    ]);
    let mut runtime = ObservationRuntime::new(provider);

    let first = runtime
        .observe(ObservationWindowRequest::new(Duration::from_secs(5)).unwrap())
        .expect("first bounded CPU observation succeeds");
    let second = runtime
        .observe(ObservationWindowRequest::new(Duration::from_secs(5)).unwrap())
        .expect("second bounded CPU observation succeeds");

    let provider = runtime.into_provider();
    assert_eq!(provider.calls, 2);
    assert_eq!(first.cpu_percent, Some(0.0));
    assert_eq!(second.cpu_percent, Some(20.0));
}

#[test]
fn one_immutable_provider_result_populates_load_memory_and_uptime() {
    let descriptor = static_collector_registry()
        .resource(SYSTEM_STATE_RESOURCE)
        .expect("system state Resource is build-fixed");
    assert_eq!(descriptor.access, ResourceAccess::SystemState);
    assert_eq!(descriptor.max_results_per_attempt, 1);
    assert!(!descriptor.request_accepts_caller_input);

    let mut runtime = ObservationRuntime::new(FixedSystemStateProvider { calls: 0 });
    let sample = runtime
        .observe(ObservationWindowRequest::new(Duration::from_secs(5)).unwrap())
        .unwrap();
    assert_eq!(
        (sample.load_1, sample.load_5, sample.load_15),
        (Some(1.0), Some(2.0), Some(3.0))
    );
    assert_eq!(sample.memory_total_bytes, Some(8_192));
    assert_eq!(sample.memory_used_bytes, Some(4_096));
    assert_eq!(sample.uptime_seconds, Some(123));
    assert_eq!(runtime.into_provider().calls, 1);
}

#[test]
fn typed_system_state_envelope_round_trips_all_independent_facts() {
    let wire = WireSystemStateResourceResult {
        cpu_counters: vec![CpuCounterResourceFact {
            name: "cpu".into(),
            user: 100,
            idle: 900,
            ..Default::default()
        }],
        proc_loadavg: "1.00 2.00 3.00 1/2 3\n".into(),
        proc_meminfo:
            "MemTotal: 8 kB\nMemAvailable: 4 kB\nCached: 1 kB\nSwapTotal: 2 kB\nSwapFree: 1 kB\n"
                .into(),
        proc_uptime: "123.50 0.0\n".into(),
        host_profile: None,
        ..Default::default()
    };
    let decoded = decode_system_state_resource_result(&wire.encode_to_vec()).unwrap();
    let mut runtime = ObservationRuntime::new(OneResultProvider(Some(decoded)));
    let sample = runtime
        .observe(ObservationWindowRequest::new(Duration::from_secs(5)).unwrap())
        .unwrap();

    assert_eq!(
        (sample.load_1, sample.load_5, sample.load_15),
        (Some(1.0), Some(2.0), Some(3.0))
    );
    assert_eq!(sample.memory_total_bytes, Some(8 * 1024));
    assert_eq!(sample.uptime_seconds, Some(123));
    assert_eq!(sample.cpu_percent, Some(0.0));
}

#[test]
fn one_device_resource_pull_is_shared_and_runtime_owns_device_delta_state() {
    struct DeviceProvider(std::collections::VecDeque<SystemStateResourceResult>);
    impl SystemStateProvider for DeviceProvider {
        fn pull_system_state(
            &mut self,
            _request: enoki_probe::observation_runtime::SystemStatePullRequest,
        ) -> Result<
            SystemStateResourceResult,
            enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
        > {
            Ok(self.0.pop_front().unwrap())
        }
    }
    fn result(
        rx: u64,
        tx: u64,
        read_sectors: u64,
        collected_at_ms: i64,
    ) -> SystemStateResourceResult {
        let wire = WireSystemStateResourceResult {
            cpu_counters: vec![CpuCounterResourceFact {
                name: "cpu".into(),
                user: 100,
                idle: 900,
                ..Default::default()
            }],
            proc_net_dev: format!(
                "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: {rx} 1 0 0 0 0 0 0 {tx} 1 0 0 0 0 0 0\n"
            ),
            proc_mounts: "/dev/sda1 / ext4 rw 0 0\n".into(),
            proc_diskstats: format!("8 1 sda1 1 0 {read_sectors} 10 1 0 4 20 0 30 40 0 0 0 0\n"),
            disk_counters_collected_at_ms: collected_at_ms,
            filesystem_capacities: vec![FilesystemCapacityResourceFact {
                mount_point: "/".into(),
                total_bytes: 1_000,
                free_bytes: 400,
                available_bytes: 300,
            }],
            temperature_inputs: vec!["42000".into(), "39".into()],
            battery_supplies: vec![BatterySupplyResourceFact {
                supply_type: "Battery".into(),
                capacity: "72".into(),
                status: "Discharging".into(),
            }],
            ..Default::default()
        };
        decode_system_state_resource_result(&wire.encode_to_vec()).unwrap()
    }

    let mut runtime = ObservationRuntime::new(DeviceProvider(
        [result(100, 200, 2, 1_000), result(160, 280, 6, 2_000)].into(),
    ));
    let request = ObservationWindowRequest::new(Duration::from_secs(5)).unwrap();
    let first = runtime.observe(request).unwrap();
    let second = runtime.observe(request).unwrap();

    assert_eq!(first.network_interfaces[0].rx_bytes_delta, 0);
    assert_eq!(second.network_interfaces[0].rx_bytes_delta, 60);
    assert_eq!(second.network_interfaces[0].tx_bytes_delta, 80);
    assert_eq!(first.disks[0].used_bytes, 600);
    assert_eq!(second.disks[0].read_bytes_delta, 2_048);
    assert_eq!(second.temperature_celsius, Some(42.0));
    assert_eq!(second.battery_percent, Some(72));
    assert_eq!(second.battery_state.as_deref(), Some("Discharging"));
    assert_eq!(runtime.into_provider().0.len(), 0);
}

#[test]
fn malformed_typed_envelope_is_rejected() {
    assert!(decode_system_state_resource_result(&[0xff]).is_none());
    assert!(decode_system_state_resource_result(&[0xa0, 0x06, 0x01]).is_none());
}

#[test]
fn one_device_fact_failure_does_not_discard_other_collector_results() {
    let wire = WireSystemStateResourceResult {
        cpu_counters: vec![CpuCounterResourceFact {
            name: "cpu".into(),
            user: 100,
            idle: 900,
            ..Default::default()
        }],
        network_failure_code: "official.network.resource-unavailable".into(),
        temperature_inputs: vec!["41000".into()],
        battery_supplies: vec![BatterySupplyResourceFact {
            supply_type: "Battery".into(),
            capacity: "80".into(),
            status: "Charging".into(),
        }],
        ..Default::default()
    };
    let decoded = decode_system_state_resource_result(&wire.encode_to_vec()).unwrap();
    let mut runtime = ObservationRuntime::new(OneResultProvider(Some(decoded)));
    let sample = runtime
        .observe(ObservationWindowRequest::new(Duration::from_secs(5)).unwrap())
        .unwrap();

    let network = sample
        .collector_outcomes
        .iter()
        .find(|outcome| outcome.collector_id == "official.network")
        .unwrap();
    assert_eq!(
        network.failure.as_ref().unwrap().code,
        "official.network.resource-unavailable"
    );
    assert_eq!(sample.temperature_celsius, Some(41.0));
    assert_eq!(sample.battery_percent, Some(80));
}

#[test]
fn disk_health_uses_a_distinct_fixed_resource_and_runtime_owned_cadence() {
    let descriptor = static_collector_registry()
        .resource(DISK_HEALTH_RESOURCE)
        .expect("Disk Health Resource is build-fixed");
    assert_eq!(descriptor.access, ResourceAccess::DiskHealth);
    assert_eq!(descriptor.max_results_per_attempt, 1);
    assert!(!descriptor.request_accepts_caller_input);

    struct FixedDiskHealthProvider {
        calls: std::rc::Rc<std::cell::Cell<usize>>,
        result: enoki_probe::observation_runtime::DiskHealthResourceResult,
    }
    impl DiskHealthProvider for FixedDiskHealthProvider {
        fn pull_disk_health(
            &mut self,
            _request: enoki_probe::observation_runtime::DiskHealthPullRequest,
        ) -> Result<
            enoki_probe::observation_runtime::DiskHealthResourceResult,
            enoki_probe::observation_runtime::DiskHealthResourceAcquisitionFailure,
        > {
            self.calls.set(self.calls.get() + 1);
            Ok(self.result.clone())
        }
    }
    let wire = WireDiskHealthResourceResult {
        devices: vec![DiskHealthDeviceResourceFact {
            device_name: "/dev/sda".into(),
            smartctl_json: br#"{"smart_status":{"passed":true},"model_name":"Example","user_capacity":{"bytes":1000}}"#.to_vec(),
            exit_code: 0,
        }],
        capability_status: DiskHealthCollectorCapabilityStatus::Available as i32,
        ..Default::default()
    };
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut runtime = ObservationRuntime::new(FixedSystemStateProvider { calls: 0 })
        .with_disk_health_provider(FixedDiskHealthProvider {
            calls: calls.clone(),
            result: decode_disk_health_resource_result(&wire.encode_to_vec()).unwrap(),
        });
    let request = ObservationWindowRequest::new(Duration::from_secs(5)).unwrap();
    let before_due = runtime
        .observe(request.with_sequence_start(11).unwrap())
        .unwrap();
    let due = runtime
        .observe(request.with_sequence_start(12).unwrap())
        .unwrap();

    assert!(before_due.disk_health.is_empty());
    assert_eq!(calls.get(), 1);
    assert_eq!(due.disk_health.len(), 1);
    assert_eq!(due.disk_health[0].device_name, "/dev/sda");
    assert!(due.collector_outcomes.iter().any(|outcome| {
        outcome.collector_id == "official.disk-health"
            && outcome.state
                == enoki_probe::protocol::enoki::v1::CollectorOutcomeState::Produced as i32
    }));
}

#[test]
fn disk_health_resource_envelope_rejects_noncanonical_or_unbounded_fields() {
    let valid = WireDiskHealthResourceResult {
        devices: vec![DiskHealthDeviceResourceFact {
            device_name: "/dev/sda".into(),
            smartctl_json: br#"{"smart_status":{"passed":true}}"#.to_vec(),
            exit_code: 0,
        }],
        capability_status: DiskHealthCollectorCapabilityStatus::Available as i32,
        ..Default::default()
    };
    assert!(decode_disk_health_resource_result(&valid.encode_to_vec()).is_some());

    let mut noncanonical = valid.encode_to_vec();
    noncanonical.extend_from_slice(&[0x98, 0x06, 0x00]);
    assert!(decode_disk_health_resource_result(&noncanonical).is_none());

    let invalid_device = WireDiskHealthResourceResult {
        devices: vec![DiskHealthDeviceResourceFact {
            device_name: "../../dev/sda".into(),
            smartctl_json: Vec::new(),
            exit_code: 0,
        }],
        capability_status: DiskHealthCollectorCapabilityStatus::Available as i32,
        ..Default::default()
    };
    assert!(decode_disk_health_resource_result(&invalid_device.encode_to_vec()).is_none());
}

#[test]
fn malformed_cpu_fact_does_not_discard_valid_memory_fact() {
    let wire = WireSystemStateResourceResult {
        cpu_counters: vec![CpuCounterResourceFact {
            name: "x".repeat(33),
            ..Default::default()
        }],
        proc_meminfo: "MemTotal: 8 kB\nMemAvailable: 4 kB\n".into(),
        ..Default::default()
    };
    let decoded = decode_system_state_resource_result(&wire.encode_to_vec()).unwrap();
    let mut runtime = ObservationRuntime::new(OneResultProvider(Some(decoded)));
    let sample = runtime
        .observe(ObservationWindowRequest::new(Duration::from_secs(5)).unwrap())
        .unwrap();

    assert_eq!(sample.memory_total_bytes, Some(8 * 1024));
    assert_eq!(sample.cpu_percent, None);
    assert_eq!(
        sample.collector_outcomes[0].failure.as_ref().unwrap().code,
        "official.cpu.counters-malformed"
    );
}

struct OneResultProvider(Option<SystemStateResourceResult>);

impl SystemStateProvider for OneResultProvider {
    fn pull_system_state(
        &mut self,
        _request: enoki_probe::observation_runtime::SystemStatePullRequest,
    ) -> Result<
        SystemStateResourceResult,
        enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
    > {
        Ok(self.0.take().unwrap())
    }
}

struct FixedSystemStateProvider {
    calls: usize,
}

impl SystemStateProvider for FixedSystemStateProvider {
    fn pull_system_state(
        &mut self,
        _request: enoki_probe::observation_runtime::SystemStatePullRequest,
    ) -> Result<
        SystemStateResourceResult,
        enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
    > {
        self.calls += 1;
        Ok(SystemStateResourceResult::from_records(
            enoki_probe::metrics::parse_linux_proc_stat_cpu_counters("cpu 100 0 0 900 0 0 0 0\n")
                .unwrap(),
        )
        .unwrap()
        .with_system_state(
            Some(enoki_probe::metrics::LoadMetrics {
                one: 1.0,
                five: 2.0,
                fifteen: 3.0,
            }),
            Some(enoki_probe::metrics::MemoryMetrics {
                cache_bytes: 512,
                swap_total_bytes: 1024,
                swap_used_bytes: 256,
                total_bytes: 8192,
                used_bytes: 4096,
            }),
            Some(123),
        ))
    }
}

#[test]
fn every_due_attempt_has_its_own_immutable_success_or_typed_outcome() {
    struct MixedProvider {
        attempts: std::collections::VecDeque<
            Result<
                &'static str,
                enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
            >,
        >,
    }
    impl SystemStateProvider for MixedProvider {
        fn pull_system_state(
            &mut self,
            _request: enoki_probe::observation_runtime::SystemStatePullRequest,
        ) -> Result<
            SystemStateResourceResult,
            enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
        > {
            let counters = self
                .attempts
                .pop_front()
                .expect("one result per due attempt")?;
            SystemStateResourceResult::from_records(
                enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(counters).unwrap(),
            )
            .ok_or(
                enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure::Malformed,
            )
        }
    }
    let mut runtime = ObservationRuntime::new(MixedProvider {
        attempts: [
            Ok("cpu 100 0 0 900 0 0 0 0\n"),
            Err(enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure::Unavailable),
            Ok("cpu 130 0 0 970 0 0 0 0\n"),
        ]
        .into_iter()
        .collect(),
    });
    let mut sleeper = RecordingSleeper::default();
    let result = runtime.collect_next_window(
        ObservationWindowRequest::new(Duration::from_secs(1))
            .unwrap()
            .with_sequence_start(41)
            .unwrap(),
        &mut sleeper,
    );

    assert_eq!(
        result
            .attempts
            .iter()
            .map(|attempt| attempt.sequence)
            .collect::<Vec<_>>(),
        [41, 42, 43]
    );
    assert!(result.attempts[0].sample.is_some());
    assert!(result.attempts[1].cpu_resource_outcome.is_none());
    assert_eq!(
        result.attempts[1]
            .sample
            .as_ref()
            .unwrap()
            .collector_outcomes
            .iter()
            .map(|outcome| outcome.collector_id.as_str())
            .collect::<Vec<_>>(),
        [
            "official.cpu",
            "official.load",
            "official.memory",
            "official.uptime",
            "official.network",
            "official.disk",
            "official.temperature",
            "official.battery",
        ]
    );
    assert!(result.attempts[2].sample.is_some());
    assert_eq!(sleeper.sleeps, vec![Duration::from_secs(1); 3]);
}

#[test]
fn malformed_host_profile_facts_are_a_typed_collector_failure_not_a_window_failure() {
    struct Provider;
    impl SystemStateProvider for Provider {
        fn pull_system_state(
            &mut self,
            _request: enoki_probe::observation_runtime::SystemStatePullRequest,
        ) -> Result<
            SystemStateResourceResult,
            enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
        > {
            Ok(SystemStateResourceResult::from_records(
                enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(
                    "cpu 100 0 0 900 0 0 0 0\n",
                )
                .unwrap(),
            )
            .unwrap()
            .with_host_profile_facts(Default::default()))
        }
    }
    let result = ObservationRuntime::new(Provider).collect_next_window(
        ObservationWindowRequest::new(Duration::from_secs(1)).unwrap(),
        &mut RecordingSleeper::default(),
    );

    assert!(result.host_profile.is_none());
    assert_eq!(result.attempts.len(), 3);
    let outcome = result.attempts[0]
        .sample
        .as_ref()
        .unwrap()
        .collector_outcomes
        .iter()
        .find(|outcome| outcome.collector_id == "official.host-profile")
        .unwrap();
    assert_eq!(outcome.state, 3);
    assert_eq!(
        outcome.failure.as_ref().unwrap().code,
        "official.host-profile.facts-malformed"
    );
}

#[test]
fn later_attempt_success_cannot_contradict_the_due_host_profile_failure() {
    struct Provider {
        call: usize,
    }
    impl SystemStateProvider for Provider {
        fn pull_system_state(
            &mut self,
            _request: enoki_probe::observation_runtime::SystemStatePullRequest,
        ) -> Result<
            SystemStateResourceResult,
            enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
        > {
            self.call += 1;
            if self.call == 1 {
                return Err(
                    enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure::Unavailable,
                );
            }
            Ok(system_state_with_host("later-host"))
        }
    }
    let result = ObservationRuntime::new(Provider { call: 0 }).collect_next_window(
        ObservationWindowRequest::new(Duration::from_secs(1)).unwrap(),
        &mut RecordingSleeper::default(),
    );

    assert!(result.host_profile.is_none());
    assert!(
        result.attempts[0]
            .sample
            .as_ref()
            .unwrap()
            .collector_outcomes
            .iter()
            .any(|outcome| outcome.collector_id == "official.host-profile" && outcome.state == 3)
    );
    assert!(result.attempts[1..].iter().all(|attempt| {
        attempt
            .sample
            .as_ref()
            .unwrap()
            .collector_outcomes
            .iter()
            .all(|outcome| outcome.collector_id != "official.host-profile")
    }));
}

#[test]
fn each_window_refreshes_the_current_host_profile_snapshot() {
    struct Provider {
        call: usize,
    }
    impl SystemStateProvider for Provider {
        fn pull_system_state(
            &mut self,
            _request: enoki_probe::observation_runtime::SystemStatePullRequest,
        ) -> Result<
            SystemStateResourceResult,
            enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
        > {
            self.call += 1;
            Ok(system_state_with_host(if self.call <= 3 {
                "first-host"
            } else {
                "changed-host"
            }))
        }
    }
    let mut runtime = ObservationRuntime::new(Provider { call: 0 });
    let request = ObservationWindowRequest::new(Duration::from_secs(1)).unwrap();
    let first = runtime.collect_next_window(request, &mut RecordingSleeper::default());
    let second = runtime.collect_next_window(request, &mut RecordingSleeper::default());

    assert_eq!(first.host_profile.unwrap().hostname, "first-host");
    assert_eq!(second.host_profile.unwrap().hostname, "changed-host");
    assert!(
        second.attempts[0]
            .sample
            .as_ref()
            .unwrap()
            .collector_outcomes
            .iter()
            .any(|outcome| outcome.collector_id == "official.host-profile" && outcome.state == 1)
    );
}

fn system_state_with_host(hostname: &str) -> SystemStateResourceResult {
    SystemStateResourceResult::from_records(
        enoki_probe::metrics::parse_linux_proc_stat_cpu_counters("cpu 100 0 0 900 0 0 0 0\n")
            .unwrap(),
    )
    .unwrap()
    .with_host_profile_facts(enoki_probe::protocol::enoki::v1::HostProfileResourceFacts {
        architecture: "x86_64".to_owned(),
        cpu_count: 1,
        hostname: hostname.to_owned(),
        kernel: "6.8.0".to_owned(),
        os: "linux".to_owned(),
        ..Default::default()
    })
}

#[test]
fn transient_disk_health_execution_failure_does_not_replace_stable_capability() {
    struct HostProvider;
    impl SystemStateProvider for HostProvider {
        fn pull_system_state(
            &mut self,
            _request: enoki_probe::observation_runtime::SystemStatePullRequest,
        ) -> Result<
            SystemStateResourceResult,
            enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
        > {
            Ok(system_state_with_host("host"))
        }
    }
    struct DiskProvider {
        results: std::collections::VecDeque<WireDiskHealthResourceResult>,
    }
    impl DiskHealthProvider for DiskProvider {
        fn pull_disk_health(
            &mut self,
            _request: enoki_probe::observation_runtime::DiskHealthPullRequest,
        ) -> Result<
            enoki_probe::observation_runtime::DiskHealthResourceResult,
            enoki_probe::observation_runtime::DiskHealthResourceAcquisitionFailure,
        > {
            decode_disk_health_resource_result(
                &self
                    .results
                    .pop_front()
                    .expect("due result")
                    .encode_to_vec(),
            )
            .ok_or(
                enoki_probe::observation_runtime::DiskHealthResourceAcquisitionFailure::Malformed,
            )
        }
    }
    let available = WireDiskHealthResourceResult {
        capability_status: DiskHealthCollectorCapabilityStatus::Available as i32,
        ..Default::default()
    };
    let transient_failure = WireDiskHealthResourceResult {
        capability_status: DiskHealthCollectorCapabilityStatus::ScanFailed as i32,
        failure_code: "official.disk-health.scan-failed".to_owned(),
        ..Default::default()
    };
    let mut runtime =
        ObservationRuntime::new(HostProvider).with_disk_health_provider(DiskProvider {
            results: [available, transient_failure].into_iter().collect(),
        });
    let request = ObservationWindowRequest::new(Duration::from_secs(1)).unwrap();
    let first = runtime.collect_next_window(
        request.with_sequence_start(12).unwrap(),
        &mut RecordingSleeper::default(),
    );
    let second = runtime.collect_next_window(
        request.with_sequence_start(24).unwrap(),
        &mut RecordingSleeper::default(),
    );

    for window in [&first, &second] {
        let capability = window
            .host_profile
            .as_ref()
            .and_then(|profile| profile.collector_capabilities.as_ref())
            .and_then(|capabilities| capabilities.official.as_ref())
            .and_then(|official| official.disk_health.as_ref())
            .expect("Runtime finalized profile has stable capability");
        assert_eq!(
            capability.status(),
            DiskHealthCollectorCapabilityStatus::Available
        );
    }
    assert!(
        second.attempts[0]
            .sample
            .as_ref()
            .unwrap()
            .collector_outcomes
            .iter()
            .any(|outcome| outcome.collector_id == "official.disk-health"
                && outcome
                    .failure
                    .as_ref()
                    .is_some_and(|failure| failure.code == "official.disk-health.scan-failed"))
    );
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

impl SystemStateProvider for RecordingCpuProvider {
    fn pull_system_state(
        &mut self,
        _request: enoki_probe::observation_runtime::SystemStatePullRequest,
    ) -> Result<
        SystemStateResourceResult,
        enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure,
    > {
        self.calls += 1;
        SystemStateResourceResult::from_records(
            enoki_probe::metrics::parse_linux_proc_stat_cpu_counters(
                self.results.pop_front().expect("one result per request"),
            )
            .expect("typed CPU counters"),
        )
        .ok_or(enoki_probe::observation_runtime::SystemStateResourceAcquisitionFailure::Malformed)
    }
}

#[derive(Default)]
struct RecordingSleeper {
    sleeps: Vec<Duration>,
    now_ms: i64,
}

impl enoki_probe::observation_runtime::ObservationRuntimeSleeper for RecordingSleeper {
    fn sleep(&mut self, duration: Duration) {
        self.sleeps.push(duration);
        self.now_ms += i64::try_from(duration.as_millis()).unwrap();
    }

    fn now_ms(&self) -> i64 {
        self.now_ms
    }
}

use enoki_probe::{
    inventory::{
        collect_local_inventory, host_profile_from_inventory, host_profile_hash, inventory_hash,
        stable_inventory,
    },
    protocol::enoki::v1::{
        CollectorAvailability, CollectorCapabilities, FilesystemInventory, HostProfileSnapshot,
        Inventory, MetricSample, NetworkInterfaceInventory, OfficialCollectorCapabilities,
    },
    report::{regular_report, startup_report},
};

#[test]
fn probe_report_startup_sends_full_inventory_and_regular_reports_send_hash_only() {
    let inventory = sample_inventory();
    let expected_hash = inventory_hash(&inventory);

    let startup = startup_report(
        "probe_01",
        "boot_01",
        1,
        "default-v1",
        inventory.clone(),
        Vec::new(),
    );

    assert_eq!(startup.inventory_hash, expected_hash);
    assert_eq!(
        startup
            .inventory
            .as_ref()
            .expect("startup report includes full Inventory")
            .hostname,
        "managed-host-01",
    );
    assert!(startup.metrics.is_empty());

    let regular = regular_report(
        "probe_01",
        "boot_01",
        2,
        2,
        "default-v1",
        &inventory,
        vec![MetricSample {
            cpu_percent: Some(12.5),
            collected_at_ms: 1_725_000_000_000,
            memory_used_bytes: Some(1024),
            sequence: 2,
            ..MetricSample::default()
        }],
    );

    assert_eq!(regular.inventory_hash, expected_hash);
    assert!(regular.inventory.is_none());
    assert_eq!(regular.metrics.len(), 1);
}

#[test]
fn regular_probe_report_sends_host_profile_snapshot_hash_without_payload() {
    let host_profile = sample_host_profile();
    let expected_hash = host_profile_hash(&host_profile);

    let report = regular_report(
        "probe_01",
        "boot_01",
        2,
        2,
        "default-v1",
        &host_profile,
        vec![MetricSample {
            cpu_percent: Some(12.5),
            collected_at_ms: 1_725_000_000_000,
            memory_used_bytes: Some(1024),
            sequence: 2,
            ..MetricSample::default()
        }],
    );

    assert!(report.inventory.is_none());
    assert_eq!(report.snapshots.len(), 1);
    assert_eq!(report.snapshots[0].collector_id, "official.host-profile");
    assert_eq!(report.snapshots[0].snapshot_hash, expected_hash);
    assert!(report.snapshots[0].payload.is_none());
    assert_eq!(report.metrics.len(), 1);
}

#[test]
fn inventory_hash_uses_stable_inventory_ordering() {
    let inventory = sample_inventory();
    let reordered = Inventory {
        filesystems: inventory.filesystems.iter().cloned().rev().collect(),
        network_interfaces: inventory.network_interfaces.iter().cloned().rev().collect(),
        ..inventory.clone()
    };

    assert_eq!(inventory_hash(&inventory), inventory_hash(&reordered));
    assert_eq!(
        stable_inventory(reordered).network_interfaces[0].addresses,
        vec!["10.0.0.10".to_string(), "2001:db8::10".to_string()],
    );
}

#[test]
fn host_profile_hash_uses_stable_repeated_field_ordering() {
    let host_profile = sample_host_profile();
    let reordered = HostProfileSnapshot {
        filesystems: host_profile.filesystems.iter().cloned().rev().collect(),
        network_interfaces: host_profile
            .network_interfaces
            .iter()
            .cloned()
            .rev()
            .collect(),
        ..host_profile.clone()
    };

    assert_eq!(
        host_profile_hash(&host_profile),
        host_profile_hash(&reordered)
    );
}

#[test]
fn collector_capability_changes_are_inventory_changes_not_metric_samples() {
    let available_inventory = Inventory {
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                disk: Some(CollectorAvailability { available: true }),
                ..OfficialCollectorCapabilities::default()
            }),
        }),
        ..sample_inventory()
    };
    let unavailable_inventory = Inventory {
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                disk: Some(CollectorAvailability { available: false }),
                ..OfficialCollectorCapabilities::default()
            }),
        }),
        ..sample_inventory()
    };

    assert_ne!(
        inventory_hash(&available_inventory),
        inventory_hash(&unavailable_inventory)
    );

    let report = startup_report(
        "probe_01",
        "boot_01",
        1,
        "default-v1",
        unavailable_inventory,
        vec![MetricSample {
            collected_at_ms: 1_725_000_000_000,
            disks: Vec::new(),
            sequence: 1,
            ..MetricSample::default()
        }],
    );

    assert!(
        !report
            .inventory
            .and_then(|inventory| inventory.collector_capabilities)
            .and_then(|capabilities| capabilities.official)
            .and_then(|official| official.disk)
            .expect("disk capability")
            .available
    );
    assert_eq!(report.metrics.len(), 1);
    assert!(report.metrics[0].disks.is_empty());
}

#[test]
fn inventory_hash_matches_the_cross_runtime_canonical_fixture() {
    let inventory = Inventory {
        filesystems: vec![
            FilesystemInventory {
                available_bytes: 30_000,
                filesystem_type: "ext4".to_string(),
                mount_point: "/var".to_string(),
                total_bytes: 80_000,
            },
            FilesystemInventory {
                available_bytes: 60_000,
                filesystem_type: "ext4".to_string(),
                mount_point: "/".to_string(),
                total_bytes: 100_000,
            },
        ],
        network_interfaces: vec![NetworkInterfaceInventory {
            addresses: vec![
                "2001:db8::10".to_string(),
                "10.0.0.10".to_string(),
                "10.0.0.10".to_string(),
            ],
            name: "eth0".to_string(),
        }],
        ..sample_inventory()
    };

    assert_eq!(
        inventory_hash(&inventory),
        "a7fc5121ed9ae767df33d0bb6e4ca06cbda5d9f2a29e96916719392e70e2b916",
    );
}

#[test]
fn host_profile_hash_matches_the_cross_runtime_canonical_fixture() {
    let host_profile = HostProfileSnapshot {
        filesystems: vec![
            FilesystemInventory {
                available_bytes: 20_000,
                filesystem_type: "zfs".to_string(),
                mount_point: "/a".to_string(),
                total_bytes: 70_000,
            },
            FilesystemInventory {
                available_bytes: 30_000,
                filesystem_type: "ext4".to_string(),
                mount_point: "/B".to_string(),
                total_bytes: 80_000,
            },
            FilesystemInventory {
                available_bytes: 40_000,
                filesystem_type: "xfs".to_string(),
                mount_point: "/😀".to_string(),
                total_bytes: 90_000,
            },
            FilesystemInventory {
                available_bytes: 10_000,
                filesystem_type: "apfs".to_string(),
                mount_point: "/B".to_string(),
                total_bytes: 60_000,
            },
        ],
        hostname: "fixture-host".to_string(),
        network_interfaces: vec![
            NetworkInterfaceInventory {
                addresses: vec![
                    "fd00::2".to_string(),
                    "10.0.0.2".to_string(),
                    "10.0.0.2".to_string(),
                    "2001:db8::2".to_string(),
                ],
                name: "eth1".to_string(),
            },
            NetworkInterfaceInventory {
                addresses: vec!["fe80::1".to_string()],
                name: "Éth0".to_string(),
            },
            NetworkInterfaceInventory {
                addresses: vec!["192.0.2.10".to_string()],
                name: "Eth0".to_string(),
            },
            NetworkInterfaceInventory {
                addresses: vec!["203.0.113.10".to_string()],
                name: "😀0".to_string(),
            },
        ],
        ..sample_host_profile()
    };

    assert_eq!(
        host_profile_hash(&host_profile),
        "928378a1b8ba549304607f856b21f97c6ddc06f43bcbebe86f3dc5f9cb44bb06",
    );
}

#[test]
fn local_inventory_snapshot_contains_host_capacity_and_probe_version() {
    let inventory = collect_local_inventory();

    assert_eq!(inventory.probe_version, "dev");
    assert!(!inventory.architecture.is_empty());
    assert!(inventory.cpu_count >= 1);
    assert!(inventory.memory_total_bytes > 0);
    assert!(inventory.process_count >= 1);
    assert!(inventory.thread_count >= inventory.process_count);
    assert!(
        inventory
            .network_interfaces
            .iter()
            .flat_map(|network_interface| &network_interface.addresses)
            .any(|address| !address.is_empty())
    );
    assert!(
        !inventory
            .network_interfaces
            .iter()
            .any(|network_interface| network_interface.name == "lo")
    );
}

fn sample_inventory() -> Inventory {
    Inventory {
        architecture: "x86_64".to_string(),
        cpu_base_frequency_mhz: 2_100,
        cpu_cache_l3_bytes: 36 * 1024 * 1024,
        cpu_count: 2,
        cpu_model: "Intel(R) Xeon(R) Gold 6252 CPU @ 2.10GHz".to_string(),
        cpu_physical_count: 1,
        cpu_socket_count: 1,
        collector_capabilities: Some(CollectorCapabilities {
            official: Some(OfficialCollectorCapabilities {
                cpu: Some(CollectorAvailability { available: true }),
                disk: Some(CollectorAvailability { available: true }),
                load: Some(CollectorAvailability { available: true }),
                memory: Some(CollectorAvailability { available: true }),
                network: Some(CollectorAvailability { available: true }),
                uptime: Some(CollectorAvailability { available: true }),
                ..OfficialCollectorCapabilities::default()
            }),
        }),
        filesystems: vec![
            FilesystemInventory {
                available_bytes: 50_000,
                filesystem_type: "ext4".to_string(),
                mount_point: "/var".to_string(),
                total_bytes: 100_000,
            },
            FilesystemInventory {
                available_bytes: 500_000,
                filesystem_type: "ext4".to_string(),
                mount_point: "/".to_string(),
                total_bytes: 1_000_000,
            },
        ],
        hostname: "managed-host-01".to_string(),
        kernel: "6.8.0".to_string(),
        memory_total_bytes: 2_147_483_648,
        network_interfaces: vec![
            NetworkInterfaceInventory {
                addresses: vec!["2001:db8::10".to_string(), "10.0.0.10".to_string()],
                name: "eth0".to_string(),
            },
            NetworkInterfaceInventory {
                addresses: vec!["127.0.0.1".to_string()],
                name: "lo".to_string(),
            },
        ],
        os: "linux".to_string(),
        process_count: 123,
        probe_version: "0.1.0".to_string(),
        thread_count: 456,
    }
}

fn sample_host_profile() -> HostProfileSnapshot {
    host_profile_from_inventory(sample_inventory())
}

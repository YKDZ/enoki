use enoki_probe::{
    inventory::{collect_local_inventory, inventory_hash, stable_inventory},
    protocol::enoki::v1::{
        FilesystemInventory, Inventory, MetricSample, NetworkInterfaceInventory,
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
        "659998d328a0f2fa591214691efcde583f2561c6063a84d16cf9d6be3f302dc3",
    );
}

#[test]
fn local_inventory_snapshot_contains_host_capacity_and_probe_version() {
    let inventory = collect_local_inventory();

    assert_eq!(inventory.probe_version, "0.1.0");
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

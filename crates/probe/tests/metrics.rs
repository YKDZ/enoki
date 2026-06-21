use enoki_probe::metrics::{
    FilesystemCapacity, collect_cpu_metrics_from_proc_stat,
    collect_default_route_interfaces_from_proc_routes, collect_disk_metrics_from_mounts,
    collect_load_metrics_from_proc_loadavg, collect_memory_metrics_from_proc_meminfo,
    collect_network_metrics_from_proc_net_dev, collect_uptime_seconds_from_proc_uptime,
};

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

    let disks = collect_disk_metrics_from_mounts(&mounts, |mount_point| match mount_point {
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
    });

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

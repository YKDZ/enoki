//! 固定的一次性 System State Resource Provider。

use std::{
    collections::BTreeSet,
    ffi::CString,
    fs,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    os::unix::ffi::OsStrExt,
    path::Path,
    process::ExitCode,
};

use enoki_probe::{
    host_profile::collect_local_host_profile_resource_facts_with_filesystems,
    metrics::{collect_memory_metrics_from_proc_meminfo, parse_linux_proc_stat_cpu_counters},
    observation_runtime::{MAX_SYSTEM_STATE_BYTES, SYSTEM_STATE_PULL, require_peer_uid},
    protocol::enoki::v1::{
        BatterySupplyResourceFact, BlockDeviceTopologyResourceFact, CpuCounterResourceFact,
        FilesystemCapacityResourceFact, FilesystemProfile, SystemStateResourceResult,
    },
    system_state_resource_sandbox::enforce_system_state_resource_read_allowlist,
};
use prost::Message;

const MAX_REQUEST_BYTES: usize = 128;

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        return ExitCode::from(2);
    }
    let input = io::stdin();
    if !stdin_is_socket(input.as_raw_fd())
        || require_peer_uid(input.as_raw_fd(), c"enoki-observation-runtime").is_err()
        || enforce_system_state_resource_read_allowlist().is_err()
    {
        return ExitCode::from(2);
    }
    match run(input, io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::from(2),
    }
}

fn stdin_is_socket(fd: std::os::fd::RawFd) -> bool {
    let mut kind: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: fd 是当前进程已继承的 stdin，输出缓冲区及长度均有效。
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        ) == 0
    }
}

fn run(input: impl Read, mut output: impl Write) -> Result<(), ()> {
    let mut request = Vec::with_capacity(SYSTEM_STATE_PULL.len());
    input
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut request)
        .map_err(|_| ())?;
    if request.len() > MAX_REQUEST_BYTES {
        return Err(());
    }

    if request.as_slice() != SYSTEM_STATE_PULL {
        return Err(());
    }

    let proc_stat = fs::read_to_string("/proc/stat").unwrap_or_default();
    if proc_stat.len() > MAX_SYSTEM_STATE_BYTES {
        return Err(());
    }
    let cpu_counters = parse_linux_proc_stat_cpu_counters(&proc_stat)
        .unwrap_or_default()
        .into_iter()
        .map(|record| CpuCounterResourceFact {
            name: record.name,
            user: record.user,
            nice: record.nice,
            system: record.system,
            idle: record.idle,
            iowait: record.iowait,
            irq: record.irq,
            softirq: record.softirq,
            steal: record.steal,
        })
        .collect();
    let load = fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let memory = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let uptime = fs::read_to_string("/proc/uptime").unwrap_or_default();
    let (proc_net_dev, network_failure_code) =
        bounded_device_read("/proc/net/dev", "official.network.resource-unavailable");
    let proc_net_route = bounded_read("/proc/net/route");
    let proc_net_ipv6_route = bounded_read("/proc/net/ipv6_route");
    let (proc_mounts, mounts_failure) =
        bounded_device_read("/proc/mounts", "official.disk.resource-unavailable");
    let (proc_diskstats, diskstats_failure) =
        bounded_device_read("/proc/diskstats", "official.disk.resource-unavailable");
    let disk_failure_code = if mounts_failure.is_empty() {
        diskstats_failure
    } else {
        mounts_failure
    };
    let memory_total_bytes =
        collect_memory_metrics_from_proc_meminfo(&memory).map_or(0, |metrics| metrics.total_bytes);
    let filesystem_capacities = collect_filesystem_capacities(&proc_mounts);
    let block_device_topology = collect_block_device_topology(&proc_mounts);
    let host_profile_filesystems =
        collect_host_profile_filesystems(&proc_mounts, &filesystem_capacities);
    let (temperature_inputs, temperature_failure_code) = collect_temperature_inputs();
    let (battery_supplies, battery_failure_code) = collect_battery_supplies();
    let encoded = SystemStateResourceResult {
        cpu_counters,
        proc_loadavg: load,
        proc_meminfo: memory,
        proc_uptime: uptime,
        host_profile: Some(collect_local_host_profile_resource_facts_with_filesystems(
            memory_total_bytes,
            host_profile_filesystems,
        )),
        proc_net_dev,
        proc_net_route,
        proc_net_ipv6_route,
        filesystem_capacities,
        proc_mounts,
        proc_diskstats,
        disk_counters_collected_at_ms: unix_time_ms(),
        temperature_inputs,
        battery_supplies,
        network_failure_code,
        disk_failure_code,
        temperature_failure_code,
        battery_failure_code,
        block_device_topology,
    }
    .encode_to_vec();
    if encoded.len() > MAX_SYSTEM_STATE_BYTES {
        return Err(());
    }
    let length = u32::try_from(encoded.len()).map_err(|_| ())?;
    output.write_all(&length.to_be_bytes()).map_err(|_| ())?;
    output.write_all(&encoded).map_err(|_| ())?;
    output.flush().map_err(|_| ())
}

fn collect_host_profile_filesystems(
    mounts: &str,
    capacities: &[FilesystemCapacityResourceFact],
) -> Vec<FilesystemProfile> {
    const EXCLUDED: &[&str] = &[
        "cgroup", "cgroup2", "debugfs", "devtmpfs", "fusectl", "overlay", "proc", "squashfs",
        "sysfs", "tmpfs", "tracefs",
    ];
    let by_mount = capacities
        .iter()
        .map(|capacity| (capacity.mount_point.as_str(), capacity))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut filesystems = mounts
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let _source = parts.next()?;
            let mount_point = parts.next()?.replace("\\040", " ");
            let filesystem_type = parts.next()?.to_owned();
            let capacity = by_mount.get(mount_point.as_str())?;
            (!EXCLUDED.contains(&filesystem_type.as_str())
                && !is_runtime_mount_path(&mount_point)
                && capacity.total_bytes > 0)
                .then_some(FilesystemProfile {
                    mount_point,
                    filesystem_type,
                    total_bytes: capacity.total_bytes,
                    available_bytes: capacity.available_bytes,
                })
        })
        .collect::<Vec<_>>();
    filesystems.sort_by(|left, right| left.mount_point.cmp(&right.mount_point));
    filesystems.dedup_by(|left, right| left.mount_point == right.mount_point);
    filesystems
}

fn is_runtime_mount_path(path: &str) -> bool {
    matches!(path, "/dev" | "/proc" | "/run" | "/sys")
        || path.starts_with("/dev/")
        || path.starts_with("/proc/")
        || path.starts_with("/run/")
        || path.starts_with("/sys/")
}

fn bounded_read(path: &str) -> String {
    fs::read_to_string(path)
        .ok()
        .filter(|contents| contents.len() <= MAX_SYSTEM_STATE_BYTES)
        .unwrap_or_default()
}

fn bounded_device_read(path: &str, failure_code: &str) -> (String, String) {
    match fs::read_to_string(path) {
        Ok(contents) if contents.len() <= MAX_SYSTEM_STATE_BYTES => (contents, String::new()),
        Ok(_) => (
            String::new(),
            failure_code.replace("unavailable", "result-too-large"),
        ),
        Err(_) => (String::new(), failure_code.to_owned()),
    }
}

fn collect_filesystem_capacities(mounts: &str) -> Vec<FilesystemCapacityResourceFact> {
    mounts
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(|value| value.replace("\\040", " "))
        .filter_map(|mount_point| {
            let path = CString::new(Path::new(&mount_point).as_os_str().as_bytes()).ok()?;
            let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            // SAFETY: path 是 NUL 结尾的固定 mount table 派生路径，stat 指向可写缓冲区。
            if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
                return None;
            }
            // SAFETY: statvfs 成功后已初始化 stat。
            let stat = unsafe { stat.assume_init() };
            Some(FilesystemCapacityResourceFact {
                mount_point,
                total_bytes: stat.f_blocks.saturating_mul(stat.f_frsize),
                free_bytes: stat.f_bfree.saturating_mul(stat.f_frsize),
                available_bytes: stat.f_bavail.saturating_mul(stat.f_frsize),
            })
        })
        .take(512)
        .collect()
}

fn collect_block_device_topology(mounts: &str) -> Vec<BlockDeviceTopologyResourceFact> {
    let class_entries = collect_block_class_entries();
    let mut seen = BTreeSet::new();
    mounts
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(unescape_mount_value)
        .filter(|source| source.starts_with("/dev/") && seen.insert(source.clone()))
        .filter_map(|source| {
            physical_device_name(&source, &class_entries).map(|physical_device| {
                BlockDeviceTopologyResourceFact {
                    source,
                    physical_device,
                }
            })
        })
        .take(512)
        .collect()
}

fn unescape_mount_value(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BlockClassEntry {
    kernel_name: String,
    device_mapper_name: Option<String>,
    slaves: Vec<String>,
}

fn collect_block_class_entries() -> Vec<BlockClassEntry> {
    let Ok(entries) = fs::read_dir("/sys/class/block") else {
        return Vec::new();
    };
    let mut facts = entries
        .flatten()
        .take(512)
        .filter_map(|entry| {
            let kernel_name = entry.file_name().to_str()?.to_owned();
            let device_mapper_name = read_trimmed(entry.path().join("dm/name"));
            let mut slaves = fs::read_dir(entry.path().join("slaves"))
                .ok()
                .into_iter()
                .flat_map(|entries| entries.flatten())
                .take(256)
                .filter_map(|slave| slave.file_name().to_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>();
            slaves.sort();
            Some(BlockClassEntry {
                kernel_name,
                device_mapper_name: (!device_mapper_name.is_empty()).then_some(device_mapper_name),
                slaves,
            })
        })
        .collect::<Vec<_>>();
    facts.sort_by(|left, right| left.kernel_name.cmp(&right.kernel_name));
    facts
}

fn physical_device_name(source: &str, class_entries: &[BlockClassEntry]) -> Option<String> {
    let name = source.strip_prefix("/dev/")?;
    if let Some(name) = physical_device_name_from_direct_block_name(name) {
        return Some(name);
    }
    let kernel_name = name.strip_prefix("mapper/").map_or_else(
        || Some(name),
        |mapper_name| {
            class_entries
                .iter()
                .find(|entry| entry.device_mapper_name.as_deref() == Some(mapper_name))
                .map(|entry| entry.kernel_name.as_str())
        },
    )?;
    let mut visited = BTreeSet::new();
    let names = physical_device_names_from_topology(kernel_name, class_entries, &mut visited, 0);
    (names.len() == 1)
        .then(|| names.into_iter().next())
        .flatten()
}

fn physical_device_names_from_topology(
    block_name: &str,
    class_entries: &[BlockClassEntry],
    visited: &mut BTreeSet<String>,
    depth: usize,
) -> BTreeSet<String> {
    let mut physical_names = BTreeSet::new();
    if depth >= 32 || !visited.insert(block_name.to_owned()) {
        return physical_names;
    }
    if let Some(name) = physical_device_name_from_direct_block_name(block_name) {
        physical_names.insert(name);
        return physical_names;
    }
    let Some(entry) = class_entries
        .iter()
        .find(|entry| entry.kernel_name == block_name)
    else {
        return physical_names;
    };
    for slave_name in entry.slaves.iter().take(256) {
        physical_names.extend(physical_device_names_from_topology(
            slave_name,
            class_entries,
            visited,
            depth + 1,
        ));
    }
    physical_names
}

fn physical_device_name_from_direct_block_name(name: &str) -> Option<String> {
    if name.starts_with("mapper/") || name.starts_with("md") || name.starts_with("dm-") {
        return None;
    }
    Some(format!("/dev/{}", physical_device_basename(name)?))
}

fn physical_device_basename(name: &str) -> Option<String> {
    if let Some(controller) = nvme_controller_name(name) {
        return Some(controller);
    }
    let trimmed = name
        .trim_end_matches(|character: char| character.is_ascii_digit())
        .trim_end_matches('p');
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn nvme_controller_name(name: &str) -> Option<String> {
    let rest = name.strip_prefix("nvme")?;
    let digits = rest
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() || !rest[digits.len()..].starts_with('n') {
        return None;
    }
    Some(format!("nvme{digits}"))
}

fn collect_temperature_inputs() -> (Vec<String>, String) {
    let directories = match fixed_child_directories("/sys/class/hwmon", 128) {
        Ok(directories) => directories,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return (Vec::new(), String::new());
        }
        Err(_) => {
            return (
                Vec::new(),
                "official.temperature.resource-unavailable".to_owned(),
            );
        }
    };
    let inputs = directories
        .into_iter()
        .flat_map(|directory| fixed_numbered_files(&directory, "temp", "_input", 128))
        .filter_map(|path| fs::read_to_string(path).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .take(4096)
        .collect();
    (inputs, String::new())
}

fn collect_battery_supplies() -> (Vec<BatterySupplyResourceFact>, String) {
    let directories = match fixed_child_directories("/sys/class/power_supply", 256) {
        Ok(directories) => directories,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return (Vec::new(), String::new());
        }
        Err(_) => {
            return (
                Vec::new(),
                "official.battery.resource-unavailable".to_owned(),
            );
        }
    };
    let supplies = directories
        .into_iter()
        .map(|directory| BatterySupplyResourceFact {
            supply_type: read_trimmed(directory.join("type")),
            capacity: read_trimmed(directory.join("capacity")),
            status: read_trimmed(directory.join("status")),
        })
        .take(256)
        .collect();
    (supplies, String::new())
}

fn fixed_child_directories(root: &str, maximum: usize) -> io::Result<Vec<std::path::PathBuf>> {
    let mut paths = fs::read_dir(root)?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .take(maximum)
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn fixed_numbered_files(
    root: &Path,
    prefix: &str,
    suffix: &str,
    maximum: usize,
) -> Vec<std::path::PathBuf> {
    let mut paths = fs::read_dir(root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.flatten())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix) && name.ends_with(suffix))
        })
        .take(maximum)
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn read_trimmed(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| value.len() <= 64)
        .unwrap_or_default()
}

fn unix_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{BlockClassEntry, physical_device_name, unescape_mount_value};

    fn entry(kernel_name: &str, mapper_name: Option<&str>, slaves: &[&str]) -> BlockClassEntry {
        BlockClassEntry {
            kernel_name: kernel_name.to_owned(),
            device_mapper_name: mapper_name.map(ToOwned::to_owned),
            slaves: slaves.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    #[test]
    fn pure_topology_resolves_direct_nvme_dm_mapper_and_md_devices() {
        let topology = [
            entry("dm-0", Some("vg-root"), &["nvme0n1p3"]),
            entry("md0", None, &["sda1"]),
        ];

        assert_eq!(
            physical_device_name("/dev/sda1", &topology).as_deref(),
            Some("/dev/sda")
        );
        assert_eq!(
            physical_device_name("/dev/nvme0n1p1", &topology).as_deref(),
            Some("/dev/nvme0")
        );
        assert_eq!(
            physical_device_name("/dev/dm-0", &topology).as_deref(),
            Some("/dev/nvme0")
        );
        assert_eq!(
            physical_device_name("/dev/mapper/vg-root", &topology).as_deref(),
            Some("/dev/nvme0")
        );
        assert_eq!(
            physical_device_name("/dev/md0", &topology).as_deref(),
            Some("/dev/sda")
        );
    }

    #[test]
    fn topology_recursion_is_bounded_and_cycles_produce_no_fact() {
        let topology = [
            entry("dm-0", None, &["dm-1"]),
            entry("dm-1", None, &["dm-0"]),
        ];

        assert_eq!(physical_device_name("/dev/dm-0", &topology), None);
    }

    #[test]
    fn mount_source_uses_kernel_mount_escape_rules() {
        assert_eq!(
            unescape_mount_value(r"/dev/mapper/vg\040root"),
            "/dev/mapper/vg root"
        );
    }
}

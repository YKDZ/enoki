use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};

use prost::Message;
use sha2::{Digest, Sha256};

use crate::metrics::{
    CollectorCadence, CollectorDefinition, CollectorId, DiskHealthAvailability,
    last_disk_health_collector_availability,
};
use crate::protocol::enoki::v1::{
    CollectorAvailability, CollectorCapabilities, FilesystemInventory, HostProfileSnapshot,
    Inventory, NetworkInterfaceInventory, OfficialCollectorCapabilities,
};

const EXCLUDED_FILESYSTEMS: &[&str] = &[
    "cgroup", "cgroup2", "debugfs", "devtmpfs", "fusectl", "overlay", "proc", "squashfs", "sysfs",
    "tmpfs", "tracefs",
];

pub fn collect_local_inventory() -> Inventory {
    InventoryCollectorRegistry::official().collect_startup()
}

trait InventoryCollector {
    fn definition(&self) -> CollectorDefinition;

    fn collect(&mut self, context: &InventoryCollectionContext, inventory: &mut Inventory);
}

struct RegisteredInventoryCollector {
    definition: CollectorDefinition,
    collector: Box<dyn InventoryCollector>,
}

struct InventoryCollectorRegistry {
    collectors: Vec<RegisteredInventoryCollector>,
}

impl InventoryCollectorRegistry {
    fn official() -> Self {
        Self::from_collectors(vec![
            Box::new(SystemInventoryCollector),
            Box::new(CpuInventoryCollector),
            Box::new(MemoryInventoryCollector),
            Box::new(DiskInventoryCollector),
            Box::new(NetworkInventoryCollector),
            Box::new(ProcessInventoryCollector),
        ])
    }

    fn from_collectors(collectors: Vec<Box<dyn InventoryCollector>>) -> Self {
        Self {
            collectors: collectors
                .into_iter()
                .map(|collector| RegisteredInventoryCollector {
                    definition: collector.definition(),
                    collector,
                })
                .collect(),
        }
    }

    fn collect_startup(mut self) -> Inventory {
        let context = InventoryCollectionContext::read();
        let mut inventory = Inventory::default();

        for collector in &mut self.collectors {
            if collector.definition.cadence != CollectorCadence::Startup {
                continue;
            }

            collector.collector.collect(&context, &mut inventory);
        }

        inventory.collector_capabilities = Some(official_collector_capabilities(
            inventory.cpu_count,
            inventory.memory_total_bytes,
            &inventory.filesystems,
            &inventory.network_interfaces,
        ));

        inventory
    }
}

struct InventoryCollectionContext {
    cpu_count: u32,
    cpuinfo: String,
    filesystems: Vec<FilesystemInventory>,
    memory_total_bytes: u64,
    network_interfaces: Vec<NetworkInterfaceInventory>,
    process_snapshot: ProcessSnapshot,
}

impl InventoryCollectionContext {
    fn read() -> Self {
        let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let cpu_count = std::thread::available_parallelism()
            .map(|count| count.get() as u32)
            .unwrap_or(1);

        Self {
            cpu_count,
            cpuinfo,
            filesystems: collect_filesystems(),
            memory_total_bytes: read_memory_total_bytes().unwrap_or(0),
            network_interfaces: collect_network_interfaces(),
            process_snapshot: collect_process_snapshot(),
        }
    }
}

struct SystemInventoryCollector;

impl InventoryCollector for SystemInventoryCollector {
    fn definition(&self) -> CollectorDefinition {
        CollectorDefinition::new(CollectorId::Uptime, CollectorCadence::Startup)
    }

    fn collect(&mut self, _context: &InventoryCollectionContext, inventory: &mut Inventory) {
        inventory.architecture = std::env::consts::ARCH.to_string();
        inventory.hostname = read_trimmed("/proc/sys/kernel/hostname")
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_default();
        inventory.kernel = read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_default();
        inventory.os = read_os_release().unwrap_or_else(|| std::env::consts::OS.to_string());
        inventory.probe_version = crate::version::probe_version().to_string();
    }
}

struct CpuInventoryCollector;

impl InventoryCollector for CpuInventoryCollector {
    fn definition(&self) -> CollectorDefinition {
        CollectorDefinition::new(CollectorId::Cpu, CollectorCadence::Startup)
    }

    fn collect(&mut self, context: &InventoryCollectionContext, inventory: &mut Inventory) {
        inventory.cpu_base_frequency_mhz =
            read_cpu_base_frequency_mhz(&context.cpuinfo).unwrap_or(0);
        inventory.cpu_cache_l3_bytes = read_cpu_l3_cache_bytes(&context.cpuinfo).unwrap_or(0);
        inventory.cpu_count = context.cpu_count;
        inventory.cpu_model = read_cpu_model(&context.cpuinfo).unwrap_or_default();
        inventory.cpu_physical_count = read_cpu_physical_count(&context.cpuinfo).unwrap_or(0);
        inventory.cpu_socket_count = read_cpu_socket_count(&context.cpuinfo).unwrap_or(0);
    }
}

struct MemoryInventoryCollector;

impl InventoryCollector for MemoryInventoryCollector {
    fn definition(&self) -> CollectorDefinition {
        CollectorDefinition::new(CollectorId::Memory, CollectorCadence::Startup)
    }

    fn collect(&mut self, context: &InventoryCollectionContext, inventory: &mut Inventory) {
        inventory.memory_total_bytes = context.memory_total_bytes;
    }
}

struct DiskInventoryCollector;

impl InventoryCollector for DiskInventoryCollector {
    fn definition(&self) -> CollectorDefinition {
        CollectorDefinition::new(CollectorId::Disk, CollectorCadence::Startup)
    }

    fn collect(&mut self, context: &InventoryCollectionContext, inventory: &mut Inventory) {
        inventory.filesystems = context.filesystems.clone();
    }
}

struct NetworkInventoryCollector;

impl InventoryCollector for NetworkInventoryCollector {
    fn definition(&self) -> CollectorDefinition {
        CollectorDefinition::new(CollectorId::Network, CollectorCadence::Startup)
    }

    fn collect(&mut self, context: &InventoryCollectionContext, inventory: &mut Inventory) {
        inventory.network_interfaces = context.network_interfaces.clone();
    }
}

struct ProcessInventoryCollector;

impl InventoryCollector for ProcessInventoryCollector {
    fn definition(&self) -> CollectorDefinition {
        CollectorDefinition::new(CollectorId::Load, CollectorCadence::Startup)
    }

    fn collect(&mut self, context: &InventoryCollectionContext, inventory: &mut Inventory) {
        inventory.process_count = context.process_snapshot.process_count;
        inventory.thread_count = context.process_snapshot.thread_count;
    }
}

fn official_collector_capabilities(
    cpu_count: u32,
    memory_total_bytes: u64,
    filesystems: &[FilesystemInventory],
    network_interfaces: &[NetworkInterfaceInventory],
) -> CollectorCapabilities {
    CollectorCapabilities {
        official: Some(OfficialCollectorCapabilities {
            battery: Some(CollectorAvailability {
                available: Path::new("/sys/class/power_supply").exists(),
            }),
            cpu: Some(CollectorAvailability {
                available: cpu_count > 0,
            }),
            disk: Some(CollectorAvailability {
                available: !filesystems.is_empty(),
            }),
            disk_health: Some(CollectorAvailability {
                available: disk_health_available(),
            }),
            inventory: Some(CollectorAvailability { available: true }),
            load: Some(CollectorAvailability { available: true }),
            memory: Some(CollectorAvailability {
                available: memory_total_bytes > 0,
            }),
            network: Some(CollectorAvailability {
                available: !network_interfaces.is_empty(),
            }),
            temperature: Some(CollectorAvailability {
                available: Path::new("/sys/class/thermal").exists(),
            }),
            uptime: Some(CollectorAvailability { available: true }),
        }),
    }
}

fn disk_health_available() -> bool {
    match last_disk_health_collector_availability() {
        Some(DiskHealthAvailability::Available) => true,
        Some(DiskHealthAvailability::Unavailable) => false,
        None => Path::new("/usr/sbin/smartctl").exists() || Path::new("/usr/bin/smartctl").exists(),
    }
}

fn read_cpu_model(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;

        (key.trim() == "model name")
            .then(|| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn read_cpu_base_frequency_mhz(cpuinfo: &str) -> Option<u32> {
    read_trimmed("/sys/devices/system/cpu/cpu0/cpufreq/base_frequency")
        .and_then(|value| value.parse::<u64>().ok())
        .map(|kilohertz| (kilohertz / 1000) as u32)
        .filter(|value| *value > 0)
        .or_else(|| {
            cpuinfo.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                if key.trim() != "cpu MHz" {
                    return None;
                }

                value
                    .trim()
                    .parse::<f64>()
                    .ok()
                    .filter(|value| value.is_finite() && *value > 0.0)
                    .map(|value| value.round() as u32)
            })
        })
}

fn read_cpu_l3_cache_bytes(cpuinfo: &str) -> Option<u64> {
    read_trimmed("/sys/devices/system/cpu/cpu0/cache/index3/size")
        .as_deref()
        .and_then(parse_capacity)
        .or_else(|| {
            cpuinfo.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                if key.trim() != "cache size" {
                    return None;
                }

                parse_capacity(value.trim())
            })
        })
}

fn read_cpu_socket_count(cpuinfo: &str) -> Option<u32> {
    let physical_ids = cpuinfo_values(cpuinfo, "physical id");

    if physical_ids.is_empty() {
        return None;
    }

    Some(physical_ids.len() as u32)
}

fn read_cpu_physical_count(cpuinfo: &str) -> Option<u32> {
    let core_ids = cpuinfo
        .split("\n\n")
        .filter_map(|block| {
            let physical_id = cpuinfo_block_value(block, "physical id")?;
            let core_id = cpuinfo_block_value(block, "core id")?;

            Some(format!("{physical_id}:{core_id}"))
        })
        .collect::<BTreeSet<_>>();

    if !core_ids.is_empty() {
        return Some(core_ids.len() as u32);
    }

    cpuinfo
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "cpu cores").then(|| value.trim().parse::<u32>().ok())?
        })
        .filter(|value| *value > 0)
}

fn cpuinfo_values(cpuinfo: &str, key: &str) -> BTreeSet<String> {
    cpuinfo
        .lines()
        .filter_map(|line| {
            let (candidate_key, value) = line.split_once(':')?;

            (candidate_key.trim() == key)
                .then(|| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .collect()
}

fn cpuinfo_block_value(block: &str, key: &str) -> Option<String> {
    block.lines().find_map(|line| {
        let (candidate_key, value) = line.split_once(':')?;

        (candidate_key.trim() == key)
            .then(|| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn parse_capacity(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let digits = trimmed
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    let amount = digits.parse::<u64>().ok()?;
    let unit = trimmed[digits.len()..].trim().to_ascii_lowercase();
    let multiplier = match unit.as_str() {
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "" => 1,
        _ => return None,
    };

    Some(amount.saturating_mul(multiplier))
}

fn collect_process_snapshot() -> ProcessSnapshot {
    let mut snapshot = ProcessSnapshot::default();
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return snapshot,
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if !name.chars().all(|character| character.is_ascii_digit()) {
            continue;
        }

        snapshot.process_count = snapshot.process_count.saturating_add(1);
        snapshot.thread_count = snapshot
            .thread_count
            .saturating_add(read_process_thread_count(entry.path()).unwrap_or(1));
    }

    snapshot
}

fn read_process_thread_count(process_path: impl AsRef<Path>) -> Option<u32> {
    let contents = fs::read_to_string(process_path.as_ref().join("status")).ok()?;

    contents.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key == "Threads").then(|| value.trim().parse::<u32>().ok())?
    })
}

pub fn inventory_hash(inventory: &Inventory) -> String {
    let canonical = stable_inventory(inventory.clone());
    let digest = Sha256::digest(canonical.encode_to_vec());

    hex_lower(&digest)
}

pub fn host_profile_hash(host_profile: &HostProfileSnapshot) -> String {
    let canonical = stable_host_profile(host_profile.clone());
    let digest = Sha256::digest(canonical.encode_to_vec());

    hex_lower(&digest)
}

pub fn host_profile_from_inventory(inventory: Inventory) -> HostProfileSnapshot {
    HostProfileSnapshot {
        architecture: inventory.architecture,
        collector_capabilities: inventory.collector_capabilities,
        cpu_base_frequency_mhz: inventory.cpu_base_frequency_mhz,
        cpu_cache_l3_bytes: inventory.cpu_cache_l3_bytes,
        cpu_count: inventory.cpu_count,
        cpu_model: inventory.cpu_model,
        cpu_physical_count: inventory.cpu_physical_count,
        cpu_socket_count: inventory.cpu_socket_count,
        filesystems: inventory.filesystems,
        hostname: inventory.hostname,
        kernel: inventory.kernel,
        memory_total_bytes: inventory.memory_total_bytes,
        network_interfaces: inventory.network_interfaces,
        os: inventory.os,
        probe_version: inventory.probe_version,
        process_count: inventory.process_count,
        thread_count: inventory.thread_count,
    }
}

pub fn stable_inventory(mut inventory: Inventory) -> Inventory {
    inventory.filesystems.sort_by(|left, right| {
        left.mount_point
            .cmp(&right.mount_point)
            .then_with(|| left.filesystem_type.cmp(&right.filesystem_type))
    });
    for network_interface in &mut inventory.network_interfaces {
        network_interface.addresses.sort();
        network_interface.addresses.dedup();
    }
    inventory
        .network_interfaces
        .sort_by(|left, right| left.name.cmp(&right.name));

    inventory
}

pub fn stable_host_profile(mut host_profile: HostProfileSnapshot) -> HostProfileSnapshot {
    host_profile.filesystems.sort_by(|left, right| {
        left.mount_point
            .cmp(&right.mount_point)
            .then_with(|| left.filesystem_type.cmp(&right.filesystem_type))
    });
    for network_interface in &mut host_profile.network_interfaces {
        network_interface.addresses.sort();
        network_interface.addresses.dedup();
    }
    host_profile
        .network_interfaces
        .sort_by(|left, right| left.name.cmp(&right.name));

    host_profile
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    let value = fs::read_to_string(path).ok()?.trim().to_string();

    (!value.is_empty()).then_some(value)
}

fn read_os_release() -> Option<String> {
    let contents = fs::read_to_string("/etc/os-release").ok()?;

    read_os_release_key(&contents, "PRETTY_NAME").or_else(|| read_os_release_key(&contents, "ID"))
}

fn read_os_release_key(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let (candidate_key, value) = line.split_once('=')?;

        (candidate_key == key).then(|| value.trim_matches('"').to_string())
    })
}

fn read_memory_total_bytes() -> Option<u64> {
    let contents = fs::read_to_string("/proc/meminfo").ok()?;
    let line = contents
        .lines()
        .find(|line| line.starts_with("MemTotal:"))?;
    let kilobytes = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;

    Some(kilobytes * 1024)
}

fn collect_filesystems() -> Vec<FilesystemInventory> {
    let contents = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mut filesystems = contents
        .lines()
        .filter_map(parse_mount)
        .filter(|mount| !EXCLUDED_FILESYSTEMS.contains(&mount.filesystem_type.as_str()))
        .filter(|mount| !is_runtime_mount_path(&mount.mount_point))
        .filter_map(|mount| {
            filesystem_capacity(&mount.mount_point).map(|capacity| (mount, capacity))
        })
        .filter(|(_, capacity)| capacity.total_bytes > 0)
        .map(|(mount, capacity)| FilesystemInventory {
            available_bytes: capacity.available_bytes,
            filesystem_type: mount.filesystem_type,
            mount_point: mount.mount_point,
            total_bytes: capacity.total_bytes,
        })
        .collect::<Vec<_>>();

    filesystems.sort_by(|left, right| left.mount_point.cmp(&right.mount_point));
    filesystems
}

fn parse_mount(line: &str) -> Option<MountEntry> {
    let mut parts = line.split_whitespace();
    let _device = parts.next()?;
    let mount_point = unescape_mount_value(parts.next()?);
    let filesystem_type = parts.next()?.to_string();

    Some(MountEntry {
        filesystem_type,
        mount_point,
    })
}

fn unescape_mount_value(value: &str) -> String {
    value.replace("\\040", " ")
}

fn is_runtime_mount_path(path: &str) -> bool {
    matches!(path, "/dev" | "/proc" | "/run" | "/sys")
        || path.starts_with("/dev/")
        || path.starts_with("/proc/")
        || path.starts_with("/run/")
        || path.starts_with("/sys/")
}

fn filesystem_capacity(path: &str) -> Option<FilesystemCapacity> {
    let c_path = CString::new(path).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: c_path is a valid nul-terminated path and stat points to writable memory.
    let result = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };

    if result != 0 {
        return None;
    }

    // SAFETY: statvfs returned success and initialized stat.
    let stat = unsafe { stat.assume_init() };
    let fragment_size = stat.f_frsize;

    Some(FilesystemCapacity {
        available_bytes: stat.f_bavail.saturating_mul(fragment_size),
        total_bytes: stat.f_blocks.saturating_mul(fragment_size),
    })
}

fn collect_network_interfaces() -> Vec<NetworkInterfaceInventory> {
    let mut addresses_by_name = BTreeMap::<String, Vec<String>>::new();
    let mut ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes ifaddrs on success and it is released with freeifaddrs below.
    let result = unsafe { libc::getifaddrs(&mut ifaddrs) };

    if result != 0 {
        return Vec::new();
    }

    let mut cursor = ifaddrs;
    while !cursor.is_null() {
        // SAFETY: cursor is provided by getifaddrs and remains valid until freeifaddrs.
        let ifaddr = unsafe { &*cursor };

        if !ifaddr.ifa_addr.is_null() {
            let name = unsafe { CStr::from_ptr(ifaddr.ifa_name) }
                .to_string_lossy()
                .into_owned();
            if name == "lo" || ifaddr.ifa_flags & libc::IFF_LOOPBACK as u32 != 0 {
                cursor = ifaddr.ifa_next;
                continue;
            }
            if let Some(address) = socket_address(ifaddr.ifa_addr) {
                addresses_by_name.entry(name).or_default().push(address);
            }
        }

        cursor = ifaddr.ifa_next;
    }

    // SAFETY: ifaddrs was initialized by getifaddrs above.
    unsafe { libc::freeifaddrs(ifaddrs) };

    addresses_by_name
        .into_iter()
        .map(|(name, mut addresses)| {
            addresses.sort();
            addresses.dedup();

            NetworkInterfaceInventory { addresses, name }
        })
        .collect()
}

fn socket_address(address: *const libc::sockaddr) -> Option<String> {
    // SAFETY: caller passes a non-null sockaddr pointer from getifaddrs.
    match unsafe { (*address).sa_family as i32 } {
        libc::AF_INET => {
            // SAFETY: family indicates sockaddr_in layout.
            let address = unsafe { *(address as *const libc::sockaddr_in) };
            Some(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)).to_string())
        }
        libc::AF_INET6 => {
            // SAFETY: family indicates sockaddr_in6 layout.
            let address = unsafe { *(address as *const libc::sockaddr_in6) };
            Some(Ipv6Addr::from(address.sin6_addr.s6_addr).to_string())
        }
        _ => None,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

struct MountEntry {
    filesystem_type: String,
    mount_point: String,
}

struct FilesystemCapacity {
    available_bytes: u64,
    total_bytes: u64,
}

#[derive(Default)]
struct ProcessSnapshot {
    process_count: u32,
    thread_count: u32,
}

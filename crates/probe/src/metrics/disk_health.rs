use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::enoki::v1::DiskHealthMetric;

pub fn collect_disk_health_metrics_from_smartctl_json(
    device_name: &str,
    contents: &str,
) -> Result<Option<DiskHealthMetric>, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(contents)?;

    if value
        .pointer("/smart_support/available")
        .and_then(serde_json::Value::as_bool)
        == Some(false)
    {
        return Ok(None);
    }

    let Some(passed) = value
        .pointer("/smart_status/passed")
        .and_then(serde_json::Value::as_bool)
    else {
        return Ok(None);
    };

    Ok(Some(DiskHealthMetric {
        device_name: device_name.to_string(),
        model: json_string(&value, "/model_name").unwrap_or_default(),
        power_on_hours: json_u64(&value, "/power_on_time/hours"),
        role: String::new(),
        serial_number: json_string(&value, "/serial_number").unwrap_or_default(),
        passed,
        temperature_celsius: json_f64(&value, "/temperature/current"),
        total_bytes: json_u64(&value, "/user_capacity/bytes"),
        usage_mount_point: String::new(),
        used_bytes: None,
    }))
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DiskPhysicalUsage {
    mount_point: String,
    role: String,
    total_bytes: u64,
    used_bytes: u64,
}

pub(crate) fn enrich_disk_health_metrics_with_resource_facts(
    metrics: &mut [DiskHealthMetric],
    mounts: &str,
    capacities: &BTreeMap<String, crate::metrics::FilesystemCapacity>,
    unraid_disks_ini: &str,
    block_device_topology: &BTreeMap<String, String>,
) {
    let usage_by_device = if unraid_disks_ini.is_empty() {
        disk_usage_by_device_from_mounts_and_capacities(mounts, capacities, block_device_topology)
    } else {
        disk_usage_by_device_from_unraid_disks_ini_contents(unraid_disks_ini)
    };
    for metric in metrics {
        if let Some(usage) = usage_by_device.get(&metric.device_name) {
            apply_disk_physical_usage(metric, usage);
        }
    }
}

fn disk_usage_by_device_from_mounts_and_capacities(
    contents: &str,
    capacities: &BTreeMap<String, crate::metrics::FilesystemCapacity>,
    block_device_topology: &BTreeMap<String, String>,
) -> BTreeMap<String, DiskPhysicalUsage> {
    let mut usage_by_device = BTreeMap::new();
    let mut seen_sources = BTreeSet::new();
    for mount in contents.lines().filter_map(parse_mount) {
        if EXCLUDED_USAGE_FILESYSTEMS.contains(&mount.filesystem_type.as_str())
            || mount.mount_point.starts_with("/run/")
            || mount.mount_point.starts_with("/var/lib/docker/")
            || !seen_sources.insert((mount.source.clone(), mount.mount_point.clone()))
        {
            continue;
        }
        let Some(device_name) = physical_device_name(&mount.source, block_device_topology) else {
            continue;
        };
        let Some(capacity) = capacities.get(&mount.mount_point) else {
            continue;
        };
        if capacity.total_bytes == 0 {
            continue;
        }
        merge_disk_usage(
            &mut usage_by_device,
            &device_name,
            DiskPhysicalUsage {
                mount_point: mount.mount_point,
                role: String::new(),
                total_bytes: capacity.total_bytes,
                used_bytes: capacity.total_bytes.saturating_sub(capacity.free_bytes),
            },
        );
    }
    usage_by_device
}

fn apply_disk_physical_usage(metric: &mut DiskHealthMetric, usage: &DiskPhysicalUsage) {
    metric.role = usage.role.clone();
    metric.total_bytes = metric.total_bytes.or(Some(usage.total_bytes));
    metric.usage_mount_point = usage.mount_point.clone();
    metric.used_bytes = Some(usage.used_bytes);
}

fn disk_usage_by_device_from_unraid_disks_ini_contents(
    contents: &str,
) -> BTreeMap<String, DiskPhysicalUsage> {
    let mut usage_by_device = BTreeMap::new();
    let mut current = UnraidDiskSection::default();

    for line in contents.lines() {
        if line.starts_with("[\"") && line.ends_with("\"]") {
            insert_unraid_disk_usage(&mut usage_by_device, &current);
            current = UnraidDiskSection::default();
            current.name = line
                .trim_start_matches("[\"")
                .trim_end_matches("\"]")
                .to_string();
            continue;
        }

        let Some((key, value)) = parse_ini_assignment(line) else {
            continue;
        };
        match key {
            "device" => current.device = value,
            "fsMountpoint" => current.mount_point = value,
            "fsSize" => current.total_kib = value.parse().ok(),
            "fsUsed" => current.used_kib = value.parse().ok(),
            "type" => current.role = value,
            _ => {}
        }
    }

    insert_unraid_disk_usage(&mut usage_by_device, &current);
    usage_by_device
}

fn insert_unraid_disk_usage(
    usage_by_device: &mut BTreeMap<String, DiskPhysicalUsage>,
    section: &UnraidDiskSection,
) {
    let Some(total_kib) = section.total_kib else {
        return;
    };
    let Some(used_kib) = section.used_kib else {
        return;
    };
    if section.device.is_empty() || section.mount_point.is_empty() || total_kib == 0 {
        return;
    }

    let usage = DiskPhysicalUsage {
        mount_point: section.mount_point.clone(),
        role: if section.role.is_empty() {
            section.name.clone()
        } else {
            section.role.clone()
        },
        total_bytes: total_kib.saturating_mul(1024),
        used_bytes: used_kib.saturating_mul(1024),
    };

    for device_name in smartctl_device_aliases(&section.device) {
        merge_disk_usage(usage_by_device, &device_name, usage.clone());
    }
}

fn merge_disk_usage(
    usage_by_device: &mut BTreeMap<String, DiskPhysicalUsage>,
    device_name: &str,
    usage: DiskPhysicalUsage,
) {
    usage_by_device
        .entry(device_name.to_string())
        .and_modify(|current| {
            current.total_bytes = current.total_bytes.saturating_add(usage.total_bytes);
            current.used_bytes = current.used_bytes.saturating_add(usage.used_bytes);
            if !current.mount_point.contains(&usage.mount_point) {
                if !current.mount_point.is_empty() {
                    current.mount_point.push_str(", ");
                }
                current.mount_point.push_str(&usage.mount_point);
            }
        })
        .or_insert(usage);
}

fn parse_ini_assignment(line: &str) -> Option<(&str, String)> {
    let (key, raw_value) = line.split_once('=')?;
    Some((key.trim(), raw_value.trim().trim_matches('"').to_string()))
}

fn parse_mount(line: &str) -> Option<MountEntry> {
    let mut parts = line.split_whitespace();
    let source = unescape_mount_value(parts.next()?);
    let mount_point = unescape_mount_value(parts.next()?);
    let filesystem_type = parts.next()?.to_string();

    Some(MountEntry {
        filesystem_type,
        mount_point,
        source,
    })
}

fn physical_device_name(
    source: &str,
    block_device_topology: &BTreeMap<String, String>,
) -> Option<String> {
    block_device_topology
        .get(source)
        .cloned()
        .or_else(|| physical_device_name_from_direct_block_name(source.strip_prefix("/dev/")?))
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
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn smartctl_device_aliases(device: &str) -> Vec<String> {
    let mut aliases = vec![format!("/dev/{device}")];
    if let Some(controller) = nvme_controller_name(device) {
        aliases.push(format!("/dev/{controller}"));
    }

    aliases
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

fn unescape_mount_value(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[derive(Default)]
struct UnraidDiskSection {
    device: String,
    mount_point: String,
    name: String,
    role: String,
    total_kib: Option<u64>,
    used_kib: Option<u64>,
}

struct MountEntry {
    filesystem_type: String,
    mount_point: String,
    source: String,
}

const EXCLUDED_USAGE_FILESYSTEMS: &[&str] = &[
    "cgroup",
    "cgroup2",
    "debugfs",
    "devtmpfs",
    "fuse.shfs",
    "fusectl",
    "overlay",
    "proc",
    "squashfs",
    "sysfs",
    "tmpfs",
    "tracefs",
];

fn json_string(value: &serde_json::Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn json_u64(value: &serde_json::Value, pointer: &str) -> Option<u64> {
    value.pointer(pointer).and_then(serde_json::Value::as_u64)
}

fn json_f64(value: &serde_json::Value, pointer: &str) -> Option<f64> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_f64)
        .filter(|value| value.is_finite())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unraid_disks_ini_maps_devices_to_usage_bytes() {
        let usage = disk_usage_by_device_from_unraid_disks_ini_contents(
            r#"["disk1"]
name="disk1"
device="sdc"
type="Data"
fsMountpoint="/mnt/disk1"
fsSize="100"
fsUsed="40"
["cache"]
name="cache"
device="nvme0n1"
type="Cache"
fsMountpoint="/mnt/cache"
fsSize="200"
fsUsed="90"
"#,
        );

        assert_eq!(
            usage.get("/dev/sdc"),
            Some(&DiskPhysicalUsage {
                mount_point: "/mnt/disk1".to_string(),
                role: "Data".to_string(),
                total_bytes: 100 * 1024,
                used_bytes: 40 * 1024,
            }),
        );
        assert_eq!(
            usage.get("/dev/nvme0"),
            Some(&DiskPhysicalUsage {
                mount_point: "/mnt/cache".to_string(),
                role: "Cache".to_string(),
                total_bytes: 200 * 1024,
                used_bytes: 90 * 1024,
            }),
        );
    }

    #[test]
    fn physical_device_names_match_smartctl_device_names() {
        assert_eq!(
            physical_device_name("/dev/sda1", &BTreeMap::new()).as_deref(),
            Some("/dev/sda")
        );
        assert_eq!(
            physical_device_name("/dev/nvme0n1p1", &BTreeMap::new()).as_deref(),
            Some("/dev/nvme0"),
        );
        assert_eq!(physical_device_name("/dev/md1p1", &BTreeMap::new()), None);
        assert_eq!(
            physical_device_name("/dev/mapper/vg-root", &BTreeMap::new()),
            None,
        );
    }

    #[test]
    fn smartctl_json_preserves_physical_user_capacity() {
        let metric = collect_disk_health_metrics_from_smartctl_json(
            "/dev/nvme0",
            r#"{
  "model_name": "GVL-1TB",
  "serial_number": "0009462008226",
  "smart_support": { "available": true },
  "smart_status": { "passed": true },
  "temperature": { "current": 40 },
  "power_on_time": { "hours": 24773 },
  "user_capacity": { "blocks": 2000409264, "bytes": 1024209543168 }
}"#,
        )
        .expect("smartctl json parses")
        .expect("smartctl metric is available");

        assert_eq!(metric.total_bytes, Some(1_024_209_543_168));
    }

    #[test]
    fn disk_usage_enrichment_does_not_override_physical_capacity() {
        let mut metric = DiskHealthMetric {
            device_name: "/dev/nvme0".to_string(),
            model: "GVL-1TB".to_string(),
            passed: true,
            power_on_hours: Some(24_773),
            role: String::new(),
            serial_number: "0009462008226".to_string(),
            temperature_celsius: Some(40.0),
            total_bytes: Some(1_024_209_543_168),
            usage_mount_point: String::new(),
            used_bytes: None,
        };

        apply_disk_physical_usage(
            &mut metric,
            &DiskPhysicalUsage {
                mount_point: "/boot, /boot/efi".to_string(),
                role: String::new(),
                total_bytes: 3_165_372_416,
                used_bytes: 216_649_728,
            },
        );

        assert_eq!(metric.total_bytes, Some(1_024_209_543_168));
        assert_eq!(metric.used_bytes, Some(216_649_728));
        assert_eq!(metric.usage_mount_point, "/boot, /boot/efi");
    }

    #[test]
    fn provider_topology_maps_lvm_to_single_physical_nvme_controller() {
        let topology = BTreeMap::from([("/dev/dm-0".to_owned(), "/dev/nvme0".to_owned())]);

        assert_eq!(
            physical_device_name("/dev/dm-0", &topology).as_deref(),
            Some("/dev/nvme0"),
        );
    }
}

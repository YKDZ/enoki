//! 固定的一次性 Disk Health Resource Provider。

use std::{
    fs,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    process::{Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

use enoki_probe::{
    disk_health_resource_sandbox::{
        SMARTCTL_CANDIDATES, enforce_disk_health_resource_read_allowlist,
    },
    observation_runtime::{DISK_HEALTH_PULL, MAX_DISK_HEALTH_BYTES, require_peer_uid},
    protocol::enoki::v1::{
        DiskHealthCollectorCapabilityStatus, DiskHealthDeviceResourceFact, DiskHealthResourceResult,
    },
};
use prost::Message;

const MAX_REQUEST_BYTES: usize = 128;
const MAX_SMARTCTL_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_DEVICES: usize = 128;
const CHILD_DEADLINE: Duration = Duration::from_secs(2);
const PROVIDER_DEADLINE: Duration = Duration::from_secs(8);

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        return ExitCode::from(2);
    }
    let input = io::stdin();
    if !stdin_is_socket(input.as_raw_fd())
        || require_peer_uid(input.as_raw_fd(), c"enoki-observation-runtime").is_err()
        || enforce_disk_health_resource_read_allowlist().is_err()
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
    // SAFETY: fd 是当前进程继承的 stdin，输出缓冲区与长度均有效。
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
    let mut request = Vec::with_capacity(DISK_HEALTH_PULL.len());
    input
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut request)
        .map_err(|_| ())?;
    if request.as_slice() != DISK_HEALTH_PULL {
        return Err(());
    }
    let encoded = collect_resource().encode_to_vec();
    if encoded.is_empty() || encoded.len() > MAX_DISK_HEALTH_BYTES {
        return Err(());
    }
    let length = u32::try_from(encoded.len()).map_err(|_| ())?;
    output.write_all(&length.to_be_bytes()).map_err(|_| ())?;
    output.write_all(&encoded).map_err(|_| ())?;
    output.flush().map_err(|_| ())
}

fn collect_resource() -> DiskHealthResourceResult {
    let Some(smartctl) = SMARTCTL_CANDIDATES
        .iter()
        .copied()
        .find(|path| std::path::Path::new(path).is_file())
    else {
        return failed(
            DiskHealthCollectorCapabilityStatus::MissingSmartctl,
            "official.disk-health.smartctl-missing",
        );
    };
    let deadline = Instant::now() + PROVIDER_DEADLINE;
    let scan = match run_bounded(smartctl, &["--scan-open", "--json"], deadline) {
        Ok(result) if result.exit_code == 0 => result.stdout,
        Ok(_) => {
            return failed(
                DiskHealthCollectorCapabilityStatus::ScanFailed,
                "official.disk-health.scan-failed",
            );
        }
        Err(CommandFailure::TimedOut) => {
            return failed(
                DiskHealthCollectorCapabilityStatus::HelperFailed,
                "official.disk-health.command-timeout",
            );
        }
        Err(CommandFailure::Unavailable | CommandFailure::OutputTooLarge) => {
            return failed(
                DiskHealthCollectorCapabilityStatus::HelperFailed,
                "official.disk-health.command-failed",
            );
        }
    };
    let Some(devices) = parse_scan_devices(&scan) else {
        return failed(
            DiskHealthCollectorCapabilityStatus::MalformedOutput,
            "official.disk-health.scan-malformed",
        );
    };
    let mut facts = Vec::with_capacity(devices.len());
    for device in devices {
        let result = match run_bounded(smartctl, &["-a", "--json", &device], deadline) {
            Ok(result) => result,
            Err(CommandFailure::TimedOut) => {
                return failed(
                    DiskHealthCollectorCapabilityStatus::HelperFailed,
                    "official.disk-health.command-timeout",
                );
            }
            Err(CommandFailure::Unavailable | CommandFailure::OutputTooLarge) => {
                return failed(
                    DiskHealthCollectorCapabilityStatus::HelperFailed,
                    "official.disk-health.command-failed",
                );
            }
        };
        facts.push(DiskHealthDeviceResourceFact {
            device_name: device,
            smartctl_json: result.stdout,
            exit_code: result.exit_code,
        });
    }
    DiskHealthResourceResult {
        devices: facts,
        capability_status: DiskHealthCollectorCapabilityStatus::Available as i32,
        failure_code: String::new(),
        unraid_disks_ini: fs::read_to_string("/var/local/emhttp/disks.ini")
            .ok()
            .filter(|contents| contents.len() <= 256 * 1024)
            .unwrap_or_default(),
    }
}

fn failed(
    status: DiskHealthCollectorCapabilityStatus,
    code: &'static str,
) -> DiskHealthResourceResult {
    DiskHealthResourceResult {
        devices: Vec::new(),
        capability_status: status as i32,
        failure_code: code.to_owned(),
        unraid_disks_ini: String::new(),
    }
}

fn parse_scan_devices(bytes: &[u8]) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let devices = value
        .pointer("/devices")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .map(|device| device.pointer("/name")?.as_str())
        .map(|name| {
            name.filter(|name| valid_device_name(name))
                .map(str::to_owned)
        })
        .collect::<Option<Vec<_>>>()?;
    (devices.len() <= MAX_DEVICES).then_some(devices)
}

fn valid_device_name(name: &str) -> bool {
    name.starts_with("/dev/")
        && name.len() <= 128
        && !name[5..].contains('/')
        && name[5..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandFailure {
    OutputTooLarge,
    TimedOut,
    Unavailable,
}

struct CommandResult {
    exit_code: i32,
    stdout: Vec<u8>,
}

fn run_bounded(
    program: &str,
    args: &[&str],
    provider_deadline: Instant,
) -> Result<CommandResult, CommandFailure> {
    let child_deadline = (Instant::now() + CHILD_DEADLINE).min(provider_deadline);
    if Instant::now() >= child_deadline {
        return Err(CommandFailure::TimedOut);
    }
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CommandFailure::Unavailable)?;
    let stdout = child.stdout.take().ok_or(CommandFailure::Unavailable)?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take((MAX_SMARTCTL_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| CommandFailure::Unavailable)? {
            break status;
        }
        if Instant::now() >= child_deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err(CommandFailure::TimedOut);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = reader
        .join()
        .map_err(|_| CommandFailure::Unavailable)?
        .map_err(|_| CommandFailure::Unavailable)?;
    if stdout.len() > MAX_SMARTCTL_OUTPUT_BYTES {
        return Err(CommandFailure::OutputTooLarge);
    }
    Ok(CommandResult {
        exit_code: status.code().unwrap_or(-1),
        stdout,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_scan_devices, valid_device_name};

    #[test]
    fn scan_contract_accepts_only_bounded_device_facts() {
        assert_eq!(
            parse_scan_devices(br#"{"devices":[{"name":"/dev/sda"},{"name":"/dev/nvme0"}]}"#)
                .unwrap(),
            ["/dev/sda", "/dev/nvme0"]
        );
        assert!(valid_device_name("/dev/sda"));
        assert!(!valid_device_name("sda"));
    }
}

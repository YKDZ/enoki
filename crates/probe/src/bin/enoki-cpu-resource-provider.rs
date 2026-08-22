//! 固定的一次性 System State Resource Provider。

use std::{
    fs,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    process::ExitCode,
};

use enoki_probe::{
    host_profile::collect_local_host_profile_resource_facts_with_memory_total,
    metrics::{collect_memory_metrics_from_proc_meminfo, parse_linux_proc_stat_cpu_counters},
    observation_runtime::{MAX_SYSTEM_STATE_BYTES, SYSTEM_STATE_PULL, require_peer_uid},
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
    let counters = parse_linux_proc_stat_cpu_counters(&proc_stat).unwrap_or_default();
    let cpu = encode_records(&counters)?;
    let load = fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let memory = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let uptime = fs::read_to_string("/proc/uptime").unwrap_or_default();
    let mut encoded = Vec::with_capacity(cpu.len() + load.len() + memory.len() + uptime.len() + 6);
    encoded.extend_from_slice(&u32::try_from(cpu.len()).map_err(|_| ())?.to_be_bytes());
    encoded.extend_from_slice(&cpu);
    encoded.extend_from_slice(load.as_bytes());
    encoded.push(0);
    encoded.extend_from_slice(memory.as_bytes());
    encoded.push(0);
    encoded.extend_from_slice(uptime.as_bytes());
    encoded.push(0);
    let memory_total_bytes =
        collect_memory_metrics_from_proc_meminfo(&memory).map_or(0, |metrics| metrics.total_bytes);
    let host_profile_facts =
        collect_local_host_profile_resource_facts_with_memory_total(memory_total_bytes)
            .encode_to_vec();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in host_profile_facts {
        encoded.push(HEX[(byte >> 4) as usize]);
        encoded.push(HEX[(byte & 0x0f) as usize]);
    }
    if encoded.len() > MAX_SYSTEM_STATE_BYTES {
        return Err(());
    }
    let length = u32::try_from(encoded.len()).map_err(|_| ())?;
    output.write_all(&length.to_be_bytes()).map_err(|_| ())?;
    output.write_all(&encoded).map_err(|_| ())?;
    output.flush().map_err(|_| ())
}

fn encode_records(records: &[enoki_probe::metrics::CpuCounterRecord]) -> Result<Vec<u8>, ()> {
    if records.len() > 4096 {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(records.len() * 80);
    bytes.extend_from_slice(&(records.len() as u16).to_be_bytes());
    for record in records {
        let name = record.name.as_bytes();
        if name.is_empty() || name.len() > 32 {
            return Err(());
        }
        bytes.push(name.len() as u8);
        bytes.extend_from_slice(name);
        for value in [
            record.user,
            record.nice,
            record.system,
            record.idle,
            record.iowait,
            record.irq,
            record.softirq,
            record.steal,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    (bytes.len() <= MAX_SYSTEM_STATE_BYTES)
        .then_some(bytes)
        .ok_or(())
}

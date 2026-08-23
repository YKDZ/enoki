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
    protocol::enoki::v1::{CpuCounterResourceFact, SystemStateResourceResult},
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
    let memory_total_bytes =
        collect_memory_metrics_from_proc_meminfo(&memory).map_or(0, |metrics| metrics.total_bytes);
    let encoded = SystemStateResourceResult {
        cpu_counters,
        proc_loadavg: load,
        proc_meminfo: memory,
        proc_uptime: uptime,
        host_profile: Some(collect_local_host_profile_resource_facts_with_memory_total(
            memory_total_bytes,
        )),
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

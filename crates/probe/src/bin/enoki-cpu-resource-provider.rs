//! 固定的一次性 CPU Resource Provider。

use std::{
    fs,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    process::ExitCode,
};

use enoki_probe::{
    metrics::parse_linux_proc_stat_cpu_counters,
    observation_runtime::{CPU_COUNTERS_PULL, MAX_CPU_COUNTERS_BYTES, require_peer_uid},
};

const MAX_REQUEST_BYTES: usize = 128;

fn main() -> ExitCode {
    let input = io::stdin();
    if !stdin_is_socket(input.as_raw_fd())
        || require_peer_uid(input.as_raw_fd(), c"enoki-observation-runtime").is_err()
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
    let mut request = Vec::with_capacity(CPU_COUNTERS_PULL.len());
    input
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut request)
        .map_err(|_| ())?;
    if request.len() > MAX_REQUEST_BYTES || request.as_slice() != CPU_COUNTERS_PULL {
        return Err(());
    }

    let proc_stat = fs::read_to_string("/proc/stat").map_err(|_| ())?;
    if proc_stat.is_empty() || proc_stat.len() > MAX_CPU_COUNTERS_BYTES {
        return Err(());
    }
    let counters = parse_linux_proc_stat_cpu_counters(&proc_stat).ok_or(())?;
    let encoded = encode_records(&counters)?;
    let length = u32::try_from(encoded.len()).map_err(|_| ())?;
    output.write_all(&length.to_be_bytes()).map_err(|_| ())?;
    output.write_all(&encoded).map_err(|_| ())?;
    output.flush().map_err(|_| ())
}

fn encode_records(records: &[enoki_probe::metrics::CpuCounterRecord]) -> Result<Vec<u8>, ()> {
    if records.is_empty() || records.len() > 4096 {
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
    (bytes.len() <= MAX_CPU_COUNTERS_BYTES)
        .then_some(bytes)
        .ok_or(())
}

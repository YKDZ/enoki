//! 独立、短生命周期的本机生命周期角色入口。

use std::{io::Read, process::ExitCode};

use enoki_probe::upgrader::{
    HttpProbeUpgraderValidationTransport, resume_lifecycle_companion, run_lifecycle_companion,
};
use enoki_probe_bootstrap::lifecycle::{
    LifecycleRequest, LifecycleRequestAuthority, LifecycleResponse, MAX_LIFECYCLE_REQUEST_BYTES,
};

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        return ExitCode::from(2);
    }
    let mut bytes = Vec::new();
    if std::io::stdin()
        .take(MAX_LIFECYCLE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_LIFECYCLE_REQUEST_BYTES
    {
        return write_response(LifecycleResponse::failed("lifecycle.invalid_request"));
    }
    let peer_uid = stdin_peer_uid();
    let process_uid = unsafe { libc::getuid() };
    let mut transport = HttpProbeUpgraderValidationTransport;
    if bytes.is_empty() {
        if peer_uid.is_some() || process_uid != 0 {
            return write_response(LifecycleResponse::failed("lifecycle.invalid_authority"));
        }
        return write_response(resume_lifecycle_companion(&mut transport));
    }
    let Ok(request) = LifecycleRequest::decode(&bytes) else {
        return write_response(LifecycleResponse::failed("lifecycle.invalid_request"));
    };
    if !caller_is_authorized(request.authority(), peer_uid, process_uid) {
        return write_response(LifecycleResponse::failed("lifecycle.invalid_authority"));
    }
    write_response(run_lifecycle_companion(&request, &mut transport))
}

fn caller_is_authorized(
    authority: &LifecycleRequestAuthority,
    peer_uid: Option<u32>,
    process_uid: u32,
) -> bool {
    match authority {
        LifecycleRequestAuthority::HubOperation { .. } => peer_uid.is_some(),
        LifecycleRequestAuthority::LocalRoot { .. } => {
            peer_uid.map_or(process_uid == 0, |uid| uid == 0)
        }
    }
}

fn stdin_peer_uid() -> Option<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            libc::STDIN_FILENO,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    (result == 0 && length as usize == std::mem::size_of::<libc::ucred>())
        .then_some(credentials.uid)
}

fn write_response(response: LifecycleResponse) -> ExitCode {
    use std::io::Write;

    if std::io::stdout().write_all(&response.encode()).is_err() {
        return ExitCode::from(1);
    }
    match response.status() {
        enoki_probe_bootstrap::lifecycle::LifecycleResultStatus::Succeeded => ExitCode::SUCCESS,
        enoki_probe_bootstrap::lifecycle::LifecycleResultStatus::Failed
        | enoki_probe_bootstrap::lifecycle::LifecycleResultStatus::NotEnabled => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hub_authority() -> LifecycleRequestAuthority {
        LifecycleRequest::hub_uninstall(
            "probe_01",
            "operation_01",
            "token",
            &"a".repeat(64),
            &"b".repeat(64),
            "1.2.3",
        )
        .unwrap()
        .authority()
        .clone()
    }

    fn local_authority() -> LifecycleRequestAuthority {
        LifecycleRequest::local_uninstall("probe_01", &"a".repeat(64), &"b".repeat(64), "1.2.3")
            .unwrap()
            .authority()
            .clone()
    }

    #[test]
    fn hub_authority_requires_an_authenticated_socket_peer() {
        assert!(caller_is_authorized(&hub_authority(), Some(1000), 0));
        assert!(!caller_is_authorized(&hub_authority(), None, 0));
    }

    #[test]
    fn local_authority_requires_the_root_caller_not_only_the_root_service() {
        assert!(caller_is_authorized(&local_authority(), Some(0), 0));
        assert!(!caller_is_authorized(&local_authority(), Some(1000), 0));
        assert!(caller_is_authorized(&local_authority(), None, 0));
        assert!(!caller_is_authorized(&local_authority(), None, 1000));
    }
}

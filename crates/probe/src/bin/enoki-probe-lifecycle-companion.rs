//! 独立、短生命周期的本机生命周期角色入口。

use std::{
    io::{Read, Write},
    process::ExitCode,
};

use enoki_probe::upgrader::{
    HttpProbeUpgraderValidationTransport, finalize_lifecycle_companion_binary,
    resume_lifecycle_companion, run_lifecycle_companion_from_peer,
    run_upgrade_lifecycle_companion_from_peer,
};
use enoki_probe_bootstrap::lifecycle::{
    LifecycleRequest, LifecycleRequestAuthority, LifecycleResponse, MAX_LIFECYCLE_REQUEST_BYTES,
};
use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let mode = match std::env::args_os().skip(1).collect::<Vec<_>>().as_slice() {
        [] => CompanionMode::General,
        [argument] if argument == "--upgrade" => CompanionMode::Upgrade,
        [argument] if argument == "record-runtime-failure" => CompanionMode::RecordRuntimeFailure,
        [argument] if argument == "retry-runtime" => CompanionMode::RetryRuntime,
        _ => return ExitCode::from(2),
    };
    run(mode)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompanionMode {
    General,
    Upgrade,
    RecordRuntimeFailure,
    RetryRuntime,
}

fn run(mode: CompanionMode) -> ExitCode {
    if mode == CompanionMode::RecordRuntimeFailure {
        return match enoki_probe::runtime_failure::record_runtime_failure() {
            Ok(_) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    if mode == CompanionMode::RetryRuntime {
        return match enoki_probe::runtime_failure::retry_runtime() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    if mode == CompanionMode::Upgrade && unsafe { libc::getuid() } != 0 {
        return ExitCode::from(2);
    }
    let mut bytes = Vec::new();
    if let Err(error) = std::io::stdin()
        .take(MAX_LIFECYCLE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
    {
        lifecycle_companion_diagnostic(&format!(
            "phase=request_read outcome=error {}",
            io_error_summary(&error)
        ));
        return write_response(LifecycleResponse::failed("lifecycle.invalid_request"));
    }
    lifecycle_companion_diagnostic(&format!(
        "phase=request_read outcome=ok bytes={}",
        bytes.len()
    ));
    if bytes.len() > MAX_LIFECYCLE_REQUEST_BYTES {
        lifecycle_companion_diagnostic("phase=request_size outcome=too_large");
        return write_response(LifecycleResponse::failed("lifecycle.invalid_request"));
    }
    let peer_uid = stdin_peer_uid();
    let process_uid = unsafe { libc::getuid() };
    let mut transport = HttpProbeUpgraderValidationTransport;
    if bytes.is_empty() {
        if mode == CompanionMode::Upgrade || peer_uid.is_some() || process_uid != 0 {
            return write_response(LifecycleResponse::failed("lifecycle.invalid_authority"));
        }
        return write_lifecycle_response(resume_lifecycle_companion(&mut transport));
    }
    let request = match LifecycleRequest::decode(&bytes) {
        Ok(request) => {
            lifecycle_companion_diagnostic("phase=request_decode outcome=ok");
            request
        }
        Err(_) => {
            lifecycle_companion_diagnostic("phase=request_decode outcome=error");
            return write_response(LifecycleResponse::failed("lifecycle.invalid_request"));
        }
    };
    if !mode_accepts(mode, request.transition()) {
        return write_response(LifecycleResponse::not_enabled());
    }
    if !caller_is_authorized(request.authority(), peer_uid, process_uid) {
        return write_response(LifecycleResponse::failed("lifecycle.invalid_authority"));
    }
    let response = if mode == CompanionMode::Upgrade {
        run_upgrade_lifecycle_companion_from_peer(&request, peer_uid)
    } else {
        run_lifecycle_companion_from_peer(&request, &mut transport, peer_uid)
    };
    lifecycle_companion_diagnostic(&format!(
        "phase=lifecycle_execute outcome=returned status={:?} code={}",
        response.status(),
        response.code()
    ));
    if request.transition() == enoki_probe_bootstrap::lifecycle::LifecycleTransition::Repair {
        write_response(response)
    } else {
        write_lifecycle_response(response)
    }
}

fn mode_accepts(
    mode: CompanionMode,
    transition: enoki_probe_bootstrap::lifecycle::LifecycleTransition,
) -> bool {
    if matches!(
        mode,
        CompanionMode::RecordRuntimeFailure | CompanionMode::RetryRuntime
    ) {
        return false;
    }
    (mode == CompanionMode::Upgrade)
        == (transition == enoki_probe_bootstrap::lifecycle::LifecycleTransition::Upgrade)
}

fn write_lifecycle_response(response: LifecycleResponse) -> ExitCode {
    write_lifecycle_response_with(
        response,
        &mut std::io::stdout(),
        finalize_lifecycle_companion_binary,
    )
}

fn write_lifecycle_response_with(
    response: LifecycleResponse,
    writer: &mut impl Write,
    finalize: impl FnOnce() -> bool,
) -> ExitCode {
    write_lifecycle_response_with_diagnostics(
        response,
        writer,
        finalize,
        lifecycle_companion_diagnostic,
    )
}

fn write_lifecycle_response_with_diagnostics(
    response: LifecycleResponse,
    writer: &mut impl Write,
    finalize: impl FnOnce() -> bool,
    mut diagnostic: impl FnMut(&str),
) -> ExitCode {
    let frame = response.encode();
    diagnostic(&response_frame_summary("response_encoded", &frame));
    if let Err(error) = writer.write_all(&frame) {
        diagnostic(&format!(
            "phase=response_write outcome=error {}",
            io_error_summary(&error)
        ));
        return ExitCode::from(1);
    }
    diagnostic("phase=response_write outcome=ok");
    if let Err(error) = writer.flush() {
        diagnostic(&format!(
            "phase=response_flush outcome=error {}",
            io_error_summary(&error)
        ));
        return ExitCode::from(1);
    }
    diagnostic("phase=response_flush outcome=ok");
    if response != LifecycleResponse::succeeded() {
        return lifecycle_response_exit(&response);
    }
    if finalize() {
        diagnostic("phase=companion_finalization outcome=ok");
        // unlink 成功后直接返回；这里之后没有 writer、filesystem 或其他
        // 可失败端口调用，客户端只在进程关闭形成 EOF 后观察到成功。
        return ExitCode::SUCCESS;
    }
    // binary 仍在，可由固定空 Resume 再试。追加 JSON 协议外字节并刷新，
    // 确保客户端不会把这次本机未完成误判为 canonical success。
    let _ = writer.write_all(b"\n").and_then(|()| writer.flush());
    diagnostic("phase=companion_finalization outcome=error");
    ExitCode::from(1)
}

fn caller_is_authorized(
    authority: &LifecycleRequestAuthority,
    peer_uid: Option<u32>,
    process_uid: u32,
) -> bool {
    match authority {
        LifecycleRequestAuthority::HubUpgrade { .. }
        | LifecycleRequestAuthority::HubOperation { .. } => peer_uid.is_some(),
        LifecycleRequestAuthority::LocalRoot { .. }
        | LifecycleRequestAuthority::LocalRepair { .. } => {
            peer_uid.map_or(process_uid == 0, |uid| uid == 0)
        }
        LifecycleRequestAuthority::ReplacementEnrollment { .. } => {
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
    let mut stdout = std::io::stdout();
    let frame = response.encode();
    lifecycle_companion_diagnostic(&response_frame_summary("response_encoded", &frame));
    if let Err(error) = stdout.write_all(&frame) {
        lifecycle_companion_diagnostic(&format!(
            "phase=response_write outcome=error {}",
            io_error_summary(&error)
        ));
        return ExitCode::from(1);
    }
    lifecycle_companion_diagnostic("phase=response_write outcome=ok");
    if let Err(error) = stdout.flush() {
        lifecycle_companion_diagnostic(&format!(
            "phase=response_flush outcome=error {}",
            io_error_summary(&error)
        ));
        return ExitCode::from(1);
    }
    lifecycle_companion_diagnostic("phase=response_flush outcome=ok");
    lifecycle_response_exit(&response)
}

fn lifecycle_companion_diagnostic(event: &str) {
    write_lifecycle_companion_diagnostic(&mut std::io::stderr(), event);
}

fn write_lifecycle_companion_diagnostic(writer: &mut impl Write, event: &str) {
    let _ = writeln!(writer, "enoki.lifecycle.diagnostic role=companion {event}");
}

fn response_frame_summary(phase: &str, frame: &[u8]) -> String {
    format!(
        "phase={phase} bytes={} sha256={:x}",
        frame.len(),
        Sha256::digest(frame)
    )
}

fn io_error_summary(error: &std::io::Error) -> String {
    let class = match error.kind() {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::ConnectionRefused => "connection_refused",
        std::io::ErrorKind::ConnectionReset => "connection_reset",
        std::io::ErrorKind::ConnectionAborted => "connection_aborted",
        std::io::ErrorKind::NotConnected => "not_connected",
        std::io::ErrorKind::BrokenPipe => "broken_pipe",
        std::io::ErrorKind::AlreadyExists => "already_exists",
        std::io::ErrorKind::WouldBlock => "would_block",
        std::io::ErrorKind::InvalidInput => "invalid_input",
        std::io::ErrorKind::InvalidData => "invalid_data",
        std::io::ErrorKind::TimedOut => "timed_out",
        std::io::ErrorKind::WriteZero => "write_zero",
        std::io::ErrorKind::Interrupted => "interrupted",
        std::io::ErrorKind::UnexpectedEof => "unexpected_eof",
        _ => "other",
    };
    match error.raw_os_error() {
        Some(errno) => format!("class={class} errno={errno}"),
        None => format!("class={class} errno=none"),
    }
}

fn lifecycle_response_exit(response: &LifecycleResponse) -> ExitCode {
    match response.status() {
        enoki_probe_bootstrap::lifecycle::LifecycleResultStatus::Succeeded => ExitCode::SUCCESS,
        enoki_probe_bootstrap::lifecycle::LifecycleResultStatus::Failed
        | enoki_probe_bootstrap::lifecycle::LifecycleResultStatus::NotEnabled => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_mode_accepts_only_upgrade_and_general_mode_never_accepts_upgrade() {
        use enoki_probe_bootstrap::lifecycle::LifecycleTransition;

        assert!(mode_accepts(
            CompanionMode::Upgrade,
            LifecycleTransition::Upgrade
        ));
        assert!(!mode_accepts(
            CompanionMode::Upgrade,
            LifecycleTransition::Uninstall
        ));
        assert!(!mode_accepts(
            CompanionMode::General,
            LifecycleTransition::Upgrade
        ));
        assert!(mode_accepts(
            CompanionMode::General,
            LifecycleTransition::Uninstall
        ));
        assert!(mode_accepts(
            CompanionMode::General,
            LifecycleTransition::Repair
        ));
        assert!(!mode_accepts(
            CompanionMode::RecordRuntimeFailure,
            LifecycleTransition::Repair
        ));
    }

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        calls: Vec<&'static str>,
        fail_write: bool,
        fail_flush: bool,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls.push("write");
            if self.fail_write {
                return Err(std::io::Error::other("ordinary write failure"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.calls.push("flush");
            if self.fail_flush {
                return Err(std::io::Error::other("ordinary flush failure"));
            }
            Ok(())
        }
    }

    struct FailingDiagnosticWriter;

    impl Write for FailingDiagnosticWriter {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("diagnostic sink unavailable"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

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

    fn replacement_authority() -> LifecycleRequestAuthority {
        let enrollment = enoki_probe_bootstrap::handoff::Enrollment::from_install_input(
            "https://hub.example",
            br#"{"hubOrigin":"https://hub.example","enrollmentToken":"enk_enroll_test","replacementMigration":{"enrollmentId":"enr_0123456789abcdef","expectedProbeId":"probe_old_01","sourceProbeSha256":["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],"sourceProbeVersion":"1.2.2","targetAssetSetDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","targetHostId":"7","targetProbeVersion":"1.2.3"},"schemaVersion":1}"#,
        )
        .unwrap();
        LifecycleRequest::replacement_migration(
            &enrollment,
            &format!("sha256:{}", "a".repeat(64)),
            "x86_64-unknown-linux-gnu",
            &"b".repeat(64),
            "1.2.3",
        )
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

    #[test]
    fn replacement_enrollment_requires_the_root_activator_caller() {
        assert!(caller_is_authorized(&replacement_authority(), Some(0), 0));
        assert!(!caller_is_authorized(
            &replacement_authority(),
            Some(1000),
            0
        ));
        assert!(caller_is_authorized(&replacement_authority(), None, 0));
        assert!(!caller_is_authorized(&replacement_authority(), None, 1000));
    }

    #[test]
    fn response_write_or_flush_failure_never_starts_self_finalization() {
        for mut writer in [
            RecordingWriter {
                fail_write: true,
                ..RecordingWriter::default()
            },
            RecordingWriter {
                fail_flush: true,
                ..RecordingWriter::default()
            },
        ] {
            let mut finalized = false;
            let exit =
                write_lifecycle_response_with(LifecycleResponse::succeeded(), &mut writer, || {
                    finalized = true;
                    true
                });
            assert_eq!(exit, ExitCode::from(1));
            assert!(!finalized);
        }
    }

    #[test]
    fn response_write_failure_records_only_a_non_sensitive_phase_summary() {
        let mut writer = RecordingWriter {
            fail_write: true,
            ..RecordingWriter::default()
        };
        let mut diagnostics = Vec::new();

        let exit = write_lifecycle_response_with_diagnostics(
            LifecycleResponse::succeeded(),
            &mut writer,
            || true,
            |event| diagnostics.push(event.to_owned()),
        );

        assert_eq!(exit, ExitCode::from(1));
        assert!(writer.bytes.is_empty());
        assert_eq!(writer.calls, ["write"]);
        assert!(
            diagnostics
                .iter()
                .any(|event| event.starts_with("phase=response_encoded bytes="))
        );
        assert!(
            diagnostics
                .iter()
                .any(|event| event == "phase=response_write outcome=error class=other errno=none")
        );
        assert!(diagnostics.iter().all(|event| !event.contains("token")));
    }

    #[test]
    fn response_diagnostics_preserve_the_success_frame_and_finalization_order() {
        let response = LifecycleResponse::succeeded();
        let expected = response.encode();
        let mut writer = RecordingWriter::default();
        let mut diagnostics = Vec::new();
        let mut events = Vec::new();

        let exit = write_lifecycle_response_with_diagnostics(
            response,
            &mut writer,
            || {
                events.push("finalize");
                true
            },
            |event| diagnostics.push(event.to_owned()),
        );

        assert_eq!(exit, ExitCode::SUCCESS);
        assert_eq!(writer.bytes, expected);
        assert_eq!(writer.calls, ["write", "flush"]);
        assert_eq!(events, ["finalize"]);
        assert!(
            diagnostics
                .iter()
                .any(|event| event.starts_with("phase=response_encoded bytes="))
        );
        assert_eq!(
            diagnostics.last().map(String::as_str),
            Some("phase=companion_finalization outcome=ok")
        );
    }

    #[test]
    fn unavailable_diagnostic_sink_preserves_response_exit_and_finalization() {
        let response = LifecycleResponse::succeeded();
        let expected = response.encode();
        let mut writer = RecordingWriter::default();
        let mut diagnostic_sink = FailingDiagnosticWriter;
        let mut finalized = false;

        let exit = write_lifecycle_response_with_diagnostics(
            response,
            &mut writer,
            || {
                finalized = true;
                true
            },
            |event| write_lifecycle_companion_diagnostic(&mut diagnostic_sink, event),
        );

        assert_eq!(exit, ExitCode::SUCCESS);
        assert_eq!(writer.bytes, expected);
        assert_eq!(writer.calls, ["write", "flush"]);
        assert!(finalized);
    }

    #[test]
    fn unlink_failure_invalidates_the_flushed_success_frame_and_keeps_resume_possible() {
        let mut writer = RecordingWriter::default();
        let exit =
            write_lifecycle_response_with(LifecycleResponse::succeeded(), &mut writer, || false);

        assert_eq!(exit, ExitCode::from(1));
        assert!(LifecycleResponse::decode(&writer.bytes).is_err());
        assert_eq!(writer.calls, ["write", "flush", "write", "flush"]);
    }

    #[test]
    fn successful_unlink_is_the_last_fallible_effect() {
        let mut writer = RecordingWriter::default();
        let mut events = Vec::new();
        let exit =
            write_lifecycle_response_with(LifecycleResponse::succeeded(), &mut writer, || {
                events.push("unlink");
                true
            });

        assert_eq!(exit, ExitCode::SUCCESS);
        assert_eq!(writer.calls, ["write", "flush"]);
        assert_eq!(events, ["unlink"]);
        assert_eq!(
            LifecycleResponse::decode(&writer.bytes),
            Ok(LifecycleResponse::succeeded())
        );
    }
}

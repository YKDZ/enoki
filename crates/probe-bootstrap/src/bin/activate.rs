//! The separately compiled root-only Bootstrap role.
use std::{
    fs::File,
    io,
    os::{fd::FromRawFd, unix::net::UnixStream},
    process::ExitCode,
};

use enoki_probe_bootstrap::{
    activation::ActivationError, generation::GenerationStateError, handoff::HandoffError,
};

/// 59 有界取证：在原兜底文本旁保留固定阶段与既有封闭错误变体名，不输出任何载荷内容。
/// Install 仍由下方既有 `error.diagnostic()` 承担，不重做错误体系。
/// 退休触发见票 59：充分因果形成后、对应真实重装修复交付前删除本函数与其输出。
fn activation_failure_category(error: &ActivationError) -> &'static str {
    match error {
        ActivationError::BuildTrustUnavailable => "build-trust-unavailable",
        ActivationError::Generation(error) => match error {
            GenerationStateError::InvalidCandidate => "generation-invalid-candidate",
            GenerationStateError::InsecureState => "generation-insecure-state",
            GenerationStateError::Io => "generation-io",
            GenerationStateError::Malformed => "generation-malformed",
            GenerationStateError::NotRoot => "generation-not-root",
            GenerationStateError::Rollback => "generation-rollback",
        },
        ActivationError::Handoff(error) => match error {
            HandoffError::InvalidEnrollment => "handoff-invalid-enrollment",
            HandoffError::InvalidHeader => "handoff-invalid-header",
            HandoffError::InvalidSection => "handoff-invalid-section",
            HandoffError::Io => "handoff-io",
            HandoffError::MissingSection => "handoff-missing-section",
            HandoffError::TooLarge => "handoff-too-large",
        },
        ActivationError::NotRoot => "not-root",
        ActivationError::Verification => "verification",
        ActivationError::Io => "io",
        ActivationError::Install(_) => "install",
        ActivationError::Replacement => "replacement",
    }
}

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--render-observation-integration-v1") {
        use std::io::Write;
        return match std::io::stdout()
            .lock()
            .write_all(&enoki_probe_bootstrap::install::render_observation_integration_v1())
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    let result = if std::env::args().nth(1).as_deref() == Some("--fd-handoff") {
        // SAFETY: acquirer transfers sole ownership of the private socket on
        // fd 1 and the sealed executable receipt on fd 0 across sudo/exec.
        let mut receipt = unsafe { File::from_raw_fd(libc::STDIN_FILENO) };
        let mut input = unsafe { UnixStream::from_raw_fd(libc::STDOUT_FILENO) };
        enoki_probe_bootstrap::activation::activate_from_socket(&mut input, &mut receipt)
    } else {
        enoki_probe_bootstrap::activation::activate_from_stdin(&mut io::stdin().lock())
    };
    match result {
        Ok(verified) => match verified.activate_fixed_current_probe() {
            Ok(()) => ExitCode::SUCCESS,
            Err(ActivationError::Install(error)) => {
                eprintln!("Probe Bootstrap activation failed ({})", error.diagnostic());
                ExitCode::from(error.exit_code())
            }
            Err(error) => {
                eprintln!(
                    "Probe Bootstrap activation failed (stage=verified-activation category={})",
                    activation_failure_category(&error)
                );
                ExitCode::from(1)
            }
        },
        Err(ActivationError::NotRoot) => {
            eprintln!("Probe Bootstrap activation must run as root");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!(
                "Probe Bootstrap activation failed (stage=receive category={})",
                activation_failure_category(&error)
            );
            ExitCode::from(1)
        }
    }
}

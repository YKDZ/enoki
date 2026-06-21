use std::{
    error::Error,
    fmt, fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgraderRunInput {
    pub bootstrap_config_path: PathBuf,
    pub operation_id: String,
    pub target_probe_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgraderNoopResult {
    pub error_code: String,
    pub operation_id: String,
    pub status: String,
}

#[derive(Debug)]
pub enum ProbeUpgraderRunError {
    InvalidConfig(&'static str),
    Io(std::io::Error),
    MissingToken,
    TokenValidation(String),
}

impl fmt::Display for ProbeUpgraderRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid Probe bootstrap config: {message}")
            }
            Self::Io(_) => write!(formatter, "failed to read Probe bootstrap config"),
            Self::MissingToken => write!(formatter, "missing Probe Operation Token on stdin"),
            Self::TokenValidation(message) => {
                write!(
                    formatter,
                    "Probe Operation Token validation failed: {message}"
                )
            }
        }
    }
}

impl Error for ProbeUpgraderRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidConfig(_) | Self::MissingToken | Self::TokenValidation(_) => None,
        }
    }
}

impl From<std::io::Error> for ProbeUpgraderRunError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub trait ProbeUpgraderValidationTransport {
    fn post_token_validation(
        &mut self,
        url: &str,
        bearer_secret: &str,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError>;
}

pub struct HttpProbeUpgraderValidationTransport;

impl ProbeUpgraderValidationTransport for HttpProbeUpgraderValidationTransport {
    fn post_token_validation(
        &mut self,
        url: &str,
        bearer_secret: &str,
        body: &str,
    ) -> Result<(), ProbeUpgraderRunError> {
        ureq::post(url)
            .set("accept", "application/json")
            .set("authorization", &format!("Bearer {bearer_secret}"))
            .set("content-type", "application/json")
            .send_string(body)
            .map_err(|error| ProbeUpgraderRunError::TokenValidation(error.to_string()))?;

        Ok(())
    }
}

pub fn run_probe_upgrader(
    input: ProbeUpgraderRunInput,
    stdin: &str,
    transport: &mut impl ProbeUpgraderValidationTransport,
) -> Result<ProbeUpgraderNoopResult, ProbeUpgraderRunError> {
    let token = stdin.trim();
    if token.is_empty() {
        return Err(ProbeUpgraderRunError::MissingToken);
    }

    let bootstrap_config = read_upgrader_bootstrap_config(&input.bootstrap_config_path)?;
    let hub_url = bootstrap_config
        .hub_url
        .ok_or(ProbeUpgraderRunError::InvalidConfig("missing Hub URL"))?;
    let probe_secret =
        bootstrap_config
            .probe_secret
            .ok_or(ProbeUpgraderRunError::InvalidConfig(
                "missing Probe Identity secret",
            ))?;
    let body = format!(
        "{{\"targetProbeVersion\":\"{}\",\"token\":\"{}\"}}",
        json_string_fragment(&input.target_probe_version),
        json_string_fragment(token),
    );

    transport.post_token_validation(
        &format!(
            "{}/api/probe/operations/{}/token/validate",
            hub_url.trim_end_matches('/'),
            input.operation_id,
        ),
        &probe_secret,
        &body,
    )?;

    Ok(ProbeUpgraderNoopResult {
        error_code: "probe_upgrader_noop".to_string(),
        operation_id: input.operation_id,
        status: "failed".to_string(),
    })
}

struct ProbeUpgraderBootstrapConfig {
    hub_url: Option<String>,
    probe_secret: Option<String>,
}

fn read_upgrader_bootstrap_config(
    path: &PathBuf,
) -> Result<ProbeUpgraderBootstrapConfig, ProbeUpgraderRunError> {
    let contents = fs::read_to_string(path).map_err(ProbeUpgraderRunError::Io)?;
    let value = contents
        .parse::<toml::Value>()
        .map_err(|_| ProbeUpgraderRunError::InvalidConfig("invalid TOML"))?;

    Ok(ProbeUpgraderBootstrapConfig {
        hub_url: string_value(&value, "hub_url")?,
        probe_secret: string_value(&value, "probe_secret")?,
    })
}

fn string_value(
    value: &toml::Value,
    key: &'static str,
) -> Result<Option<String>, ProbeUpgraderRunError> {
    match value.get(key) {
        Some(toml::Value::String(string)) => Ok(Some(string.clone())),
        Some(_) => Err(ProbeUpgraderRunError::InvalidConfig(
            "expected string values",
        )),
        None => Ok(None),
    }
}

fn json_string_fragment(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgraderLaunch {
    pub bootstrap_config_path: PathBuf,
    pub install_path: PathBuf,
    pub operation_id: String,
    pub target_probe_version: String,
    pub token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeUpgraderLaunchError {
    InsufficientPrivilege(String),
    UnsupportedInstallation(String),
}

pub trait ProbeUpgraderCommandRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[String],
        stdin: &str,
    ) -> Result<(), ProbeUpgraderLaunchError>;
}

pub struct SystemProbeUpgraderCommandRunner;

impl ProbeUpgraderCommandRunner for SystemProbeUpgraderCommandRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[String],
        stdin: &str,
    ) -> Result<(), ProbeUpgraderLaunchError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    ProbeUpgraderLaunchError::UnsupportedInstallation(
                        "sudo is not available for Probe Upgrader launch".to_string(),
                    )
                } else {
                    ProbeUpgraderLaunchError::InsufficientPrivilege(error.to_string())
                }
            })?;

        let mut child_stdin = child.stdin.take().ok_or_else(|| {
            ProbeUpgraderLaunchError::UnsupportedInstallation(
                "Probe Upgrader stdin pipe is unavailable".to_string(),
            )
        })?;
        child_stdin
            .write_all(stdin.as_bytes())
            .map_err(|error| ProbeUpgraderLaunchError::InsufficientPrivilege(error.to_string()))?;
        drop(child_stdin);

        let output = child
            .wait_with_output()
            .map_err(|error| ProbeUpgraderLaunchError::InsufficientPrivilege(error.to_string()))?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(ProbeUpgraderLaunchError::InsufficientPrivilege(
            if stderr.is_empty() {
                format!("Probe Upgrader launch exited with {}", output.status)
            } else {
                stderr
            },
        ))
    }
}

pub fn launch_systemd_probe_upgrader(
    input: ProbeUpgraderLaunch,
    runner: &mut impl ProbeUpgraderCommandRunner,
) -> Result<(), ProbeUpgraderLaunchError> {
    let args = vec![
        "/usr/bin/systemd-run".to_string(),
        "--collect".to_string(),
        "--pipe".to_string(),
        "--wait".to_string(),
        format!("--unit=enoki-probe-upgrader-{}", input.operation_id),
        "--property=Type=exec".to_string(),
        input.install_path.display().to_string(),
        "internal-upgrader".to_string(),
        "--config".to_string(),
        input.bootstrap_config_path.display().to_string(),
        "--operation-id".to_string(),
        input.operation_id,
        "--target-probe-version".to_string(),
        input.target_probe_version,
    ];

    runner.run("sudo", &args, &input.token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[derive(Default)]
    struct RecordingCommandRunner {
        args: Vec<String>,
        program: String,
        stdin: String,
    }

    #[derive(Default)]
    struct RecordingValidationTransport {
        body: String,
        bearer_secret: String,
        url: String,
    }

    impl ProbeUpgraderValidationTransport for RecordingValidationTransport {
        fn post_token_validation(
            &mut self,
            url: &str,
            bearer_secret: &str,
            body: &str,
        ) -> Result<(), ProbeUpgraderRunError> {
            self.url = url.to_string();
            self.bearer_secret = bearer_secret.to_string();
            self.body = body.to_string();

            Ok(())
        }
    }

    impl ProbeUpgraderCommandRunner for RecordingCommandRunner {
        fn run(
            &mut self,
            program: &str,
            args: &[String],
            stdin: &str,
        ) -> Result<(), ProbeUpgraderLaunchError> {
            self.program = program.to_string();
            self.args = args.to_vec();
            self.stdin = stdin.to_string();

            Ok(())
        }
    }

    #[test]
    fn systemd_probe_upgrader_launch_uses_typed_entrypoint_and_stdin_token() {
        let mut runner = RecordingCommandRunner::default();

        launch_systemd_probe_upgrader(
            ProbeUpgraderLaunch {
                bootstrap_config_path: PathBuf::from("/etc/enoki/probe-bootstrap.toml"),
                install_path: PathBuf::from("/usr/local/bin/enoki-probe"),
                operation_id: "42".to_string(),
                target_probe_version: "0.2.0".to_string(),
                token: "probe-operation-token".to_string(),
            },
            &mut runner,
        )
        .expect("launch succeeds");

        assert_eq!(runner.program, "sudo");
        assert_eq!(
            runner.args,
            vec![
                "/usr/bin/systemd-run",
                "--collect",
                "--pipe",
                "--wait",
                "--unit=enoki-probe-upgrader-42",
                "--property=Type=exec",
                "/usr/local/bin/enoki-probe",
                "internal-upgrader",
                "--config",
                "/etc/enoki/probe-bootstrap.toml",
                "--operation-id",
                "42",
                "--target-probe-version",
                "0.2.0",
            ],
        );
        assert_eq!(runner.stdin, "probe-operation-token");
        assert!(!runner.args.iter().any(|arg| arg == "probe-operation-token"));
    }

    #[test]
    fn internal_probe_upgrader_rejects_missing_stdin_token() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_secret = \"enk_probe_secret\"",
                "",
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport::default();

        let error = run_probe_upgrader(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
                operation_id: "42".to_string(),
                target_probe_version: "0.2.0".to_string(),
            },
            "",
            &mut transport,
        )
        .expect_err("missing token fails");

        assert!(matches!(error, ProbeUpgraderRunError::MissingToken));
        assert_eq!(transport.url, "");
    }

    #[test]
    fn internal_probe_upgrader_validates_stdin_token_with_hub_before_noop_result() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bootstrap_config_path = temp.path().join("probe-bootstrap.toml");
        fs::write(
            &bootstrap_config_path,
            [
                "hub_url = \"https://hub.example\"",
                "probe_secret = \"enk_probe_secret\"",
                "",
            ]
            .join("\n"),
        )
        .expect("write bootstrap config");
        let mut transport = RecordingValidationTransport::default();

        let result = run_probe_upgrader(
            ProbeUpgraderRunInput {
                bootstrap_config_path,
                operation_id: "42".to_string(),
                target_probe_version: "0.2.0".to_string(),
            },
            "probe-operation-token\n",
            &mut transport,
        )
        .expect("token validates");

        assert_eq!(
            transport.url,
            "https://hub.example/api/probe/operations/42/token/validate",
        );
        assert_eq!(transport.bearer_secret, "enk_probe_secret");
        assert_eq!(
            transport.body,
            "{\"targetProbeVersion\":\"0.2.0\",\"token\":\"probe-operation-token\"}",
        );
        assert_eq!(
            result,
            ProbeUpgraderNoopResult {
                error_code: "probe_upgrader_noop".to_string(),
                operation_id: "42".to_string(),
                status: "failed".to_string(),
            },
        );
    }
}

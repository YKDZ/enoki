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
    InvalidMetadata(&'static str),
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
            Self::InvalidMetadata(message) => {
                write!(
                    formatter,
                    "invalid Probe Upgrader operation metadata: {message}"
                )
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
            Self::InvalidConfig(_)
            | Self::InvalidMetadata(_)
            | Self::MissingToken
            | Self::TokenValidation(_) => None,
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
    let operation = read_operation_metadata(stdin)?;
    if operation.token.is_empty() {
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
        json_string_fragment(&operation.target_probe_version),
        json_string_fragment(&operation.token),
    );

    transport.post_token_validation(
        &format!(
            "{}/api/probe/operations/{}/token/validate",
            hub_url.trim_end_matches('/'),
            operation.operation_id,
        ),
        &probe_secret,
        &body,
    )?;

    Ok(ProbeUpgraderNoopResult {
        error_code: "probe_upgrader_noop".to_string(),
        operation_id: operation.operation_id,
        status: "failed".to_string(),
    })
}

struct ProbeUpgraderOperationMetadata {
    operation_id: String,
    target_probe_version: String,
    token: String,
}

fn read_operation_metadata(
    stdin: &str,
) -> Result<ProbeUpgraderOperationMetadata, ProbeUpgraderRunError> {
    if stdin.trim().is_empty() {
        return Err(ProbeUpgraderRunError::MissingToken);
    }

    let value = stdin
        .parse::<toml::Value>()
        .map_err(|_| ProbeUpgraderRunError::InvalidMetadata("invalid TOML"))?;
    let operation_id = required_metadata_string(&value, "operation_id")?;
    let target_probe_version = required_metadata_string(&value, "target_probe_version")?;
    let token = required_metadata_string(&value, "token")?;

    Ok(ProbeUpgraderOperationMetadata {
        operation_id,
        target_probe_version,
        token,
    })
}

fn required_metadata_string(
    value: &toml::Value,
    key: &'static str,
) -> Result<String, ProbeUpgraderRunError> {
    match value.get(key) {
        Some(toml::Value::String(string)) => Ok(string.clone()),
        Some(_) => Err(ProbeUpgraderRunError::InvalidMetadata(
            "expected string values",
        )),
        None => Err(ProbeUpgraderRunError::InvalidMetadata("missing field")),
    }
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
pub struct ProbeUpgraderCommandOutput {
    pub stdout: String,
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
    ) -> Result<ProbeUpgraderCommandOutput, ProbeUpgraderLaunchError>;
}

pub struct SystemProbeUpgraderCommandRunner;

impl ProbeUpgraderCommandRunner for SystemProbeUpgraderCommandRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[String],
        stdin: &str,
    ) -> Result<ProbeUpgraderCommandOutput, ProbeUpgraderLaunchError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
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
            return Ok(ProbeUpgraderCommandOutput {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            });
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
) -> Result<ProbeUpgraderCommandOutput, ProbeUpgraderLaunchError> {
    let args = vec![
        "/usr/bin/systemd-run".to_string(),
        "--collect".to_string(),
        "--pipe".to_string(),
        "--wait".to_string(),
        "--unit=enoki-probe-upgrader".to_string(),
        "--property=Type=exec".to_string(),
        "--".to_string(),
        input.install_path.display().to_string(),
        "internal-upgrader".to_string(),
        "--config".to_string(),
        input.bootstrap_config_path.display().to_string(),
    ];
    let stdin = render_probe_upgrader_stdin(&input);

    runner.run("sudo", &args, &stdin)
}

pub fn render_probe_upgrader_stdin(input: &ProbeUpgraderLaunch) -> String {
    [
        format!("operation_id = {}", toml_string(&input.operation_id)),
        format!(
            "target_probe_version = {}",
            toml_string(&input.target_probe_version),
        ),
        format!("token = {}", toml_string(&input.token)),
        String::new(),
    ]
    .join("\n")
}

pub fn format_probe_upgrader_noop_result(result: &ProbeUpgraderNoopResult) -> String {
    format!(
        "Probe Upgrader no-op result: operation={} status={} error_code={}",
        result.operation_id, result.status, result.error_code
    )
}

pub fn parse_probe_upgrader_noop_result(output: &str) -> Option<ProbeUpgraderNoopResult> {
    output.lines().find_map(|line| {
        let rest = line.strip_prefix("Probe Upgrader no-op result: ")?;
        let mut operation_id = None;
        let mut status = None;
        let mut error_code = None;

        for field in rest.split_whitespace() {
            if let Some(value) = field.strip_prefix("operation=") {
                operation_id = Some(value.to_string());
            } else if let Some(value) = field.strip_prefix("status=") {
                status = Some(value.to_string());
            } else if let Some(value) = field.strip_prefix("error_code=") {
                error_code = Some(value.to_string());
            }
        }

        Some(ProbeUpgraderNoopResult {
            error_code: error_code?,
            operation_id: operation_id?,
            status: status?,
        })
    })
}

fn toml_string(value: &str) -> String {
    let escaped = value
        .chars()
        .flat_map(|character| character.escape_default())
        .collect::<String>();

    format!("\"{escaped}\"")
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
        ) -> Result<ProbeUpgraderCommandOutput, ProbeUpgraderLaunchError> {
            self.program = program.to_string();
            self.args = args.to_vec();
            self.stdin = stdin.to_string();

            Ok(ProbeUpgraderCommandOutput {
                stdout: String::new(),
            })
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
                "--unit=enoki-probe-upgrader",
                "--property=Type=exec",
                "--",
                "/usr/local/bin/enoki-probe",
                "internal-upgrader",
                "--config",
                "/etc/enoki/probe-bootstrap.toml",
            ],
        );
        assert_eq!(
            runner.stdin,
            [
                "operation_id = \"42\"",
                "target_probe_version = \"0.2.0\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
        );
        assert!(!runner.args.iter().any(|arg| arg == "probe-operation-token"));
        assert!(!runner.args.iter().any(|arg| arg == "42"));
        assert!(!runner.args.iter().any(|arg| arg == "0.2.0"));
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
                bootstrap_config_path: bootstrap_config_path.clone(),
            },
            &[
                "operation_id = \"42\"",
                "target_probe_version = \"0.2.0\"",
                "token = \"probe-operation-token\"",
                "",
            ]
            .join("\n"),
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
        assert_eq!(
            parse_probe_upgrader_noop_result(&format_probe_upgrader_noop_result(&result)),
            Some(result),
        );
    }
}

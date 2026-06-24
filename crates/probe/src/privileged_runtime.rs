use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkAccess {
    Disabled,
    Enabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectorRuntimeProfile {
    pub timeout: Duration,
    pub network_access: NetworkAccess,
}

pub const DEFAULT_COLLECTOR_RUNTIME_PROFILE: CollectorRuntimeProfile = CollectorRuntimeProfile {
    timeout: Duration::from_secs(10),
    network_access: NetworkAccess::Disabled,
};

pub const DISK_HEALTH_SMARTCTL_RUNTIME_PROFILE: CollectorRuntimeProfile = CollectorRuntimeProfile {
    timeout: Duration::from_secs(10),
    network_access: NetworkAccess::Disabled,
};

impl Default for CollectorRuntimeProfile {
    fn default() -> Self {
        DEFAULT_COLLECTOR_RUNTIME_PROFILE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegedCollectorId {
    DiskHealthSmartctl,
    FixedCollector,
    NetworkEnabledCollector,
    TimeoutCollector,
}

impl PrivilegedCollectorId {
    pub fn as_internal_arg(self) -> &'static str {
        match self {
            Self::DiskHealthSmartctl => "disk-health.smartctl",
            Self::FixedCollector => "fixed.collector",
            Self::NetworkEnabledCollector => "network.collector",
            Self::TimeoutCollector => "timeout.collector",
        }
    }

    pub fn from_internal_arg(value: &str) -> Option<Self> {
        match value {
            "disk-health.smartctl" => Some(Self::DiskHealthSmartctl),
            "fixed.collector" => Some(Self::FixedCollector),
            "network.collector" => Some(Self::NetworkEnabledCollector),
            "timeout.collector" => Some(Self::TimeoutCollector),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompiledPrivilegedCollectorSpec {
    pub id: PrivilegedCollectorId,
    pub profile: CollectorRuntimeProfile,
}

pub const COMPILED_PRIVILEGED_COLLECTOR_SPECS: &[CompiledPrivilegedCollectorSpec] =
    &[CompiledPrivilegedCollectorSpec {
        id: PrivilegedCollectorId::DiskHealthSmartctl,
        profile: DISK_HEALTH_SMARTCTL_RUNTIME_PROFILE,
    }];

pub fn compiled_privileged_collector_specs() -> &'static [CompiledPrivilegedCollectorSpec] {
    COMPILED_PRIVILEGED_COLLECTOR_SPECS
}

pub fn compiled_privileged_collector_spec(
    collector_id: PrivilegedCollectorId,
) -> Option<&'static CompiledPrivilegedCollectorSpec> {
    COMPILED_PRIVILEGED_COLLECTOR_SPECS
        .iter()
        .find(|spec| spec.id == collector_id)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivilegedRuntimeError {
    CollectorFailed(String),
    TimedOut { timeout: Duration },
}

impl PrivilegedRuntimeError {
    pub fn collector_failed(message: impl Into<String>) -> Self {
        Self::CollectorFailed(message.into())
    }
}

impl fmt::Display for PrivilegedRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CollectorFailed(message) => formatter.write_str(message),
            Self::TimedOut { timeout } => {
                write!(
                    formatter,
                    "privileged collector timed out after {timeout:?}"
                )
            }
        }
    }
}

impl Error for PrivilegedRuntimeError {}

pub trait PrivilegedCollector {
    fn collector_id(&self) -> PrivilegedCollectorId;

    fn runtime_profile(&self) -> &'static CollectorRuntimeProfile {
        &DEFAULT_COLLECTOR_RUNTIME_PROFILE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivilegedRuntimeInvocation {
    pub collector_id: PrivilegedCollectorId,
    pub profile: CollectorRuntimeProfile,
}

pub trait PrivilegedRuntimeRunner {
    fn run(
        &mut self,
        invocation: PrivilegedRuntimeInvocation,
    ) -> Result<PrivilegedRuntimeOutput, PrivilegedRuntimeError>;
}

impl<T> PrivilegedRuntimeRunner for &mut T
where
    T: PrivilegedRuntimeRunner,
{
    fn run(
        &mut self,
        invocation: PrivilegedRuntimeInvocation,
    ) -> Result<PrivilegedRuntimeOutput, PrivilegedRuntimeError> {
        (**self).run(invocation)
    }
}

pub struct PrivilegedCollectorRuntime<R> {
    runner: R,
}

impl<R> PrivilegedCollectorRuntime<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R> PrivilegedCollectorRuntime<R>
where
    R: PrivilegedRuntimeRunner,
{
    pub fn run(
        &mut self,
        collector: &dyn PrivilegedCollector,
    ) -> Result<PrivilegedRuntimeOutput, PrivilegedRuntimeError> {
        self.runner.run(PrivilegedRuntimeInvocation {
            collector_id: collector.collector_id(),
            profile: *collector.runtime_profile(),
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivilegedRuntimeOutput {
    pub stdout: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegedRuntimeNetworkBoundary {
    PrivateNetwork,
    HostNetwork,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivilegedRuntimeExecutionPlan {
    pub probe_binary: PathBuf,
    pub probe_args: Vec<String>,
    pub timeout: Duration,
    pub network_boundary: PrivilegedRuntimeNetworkBoundary,
    pub systemd_properties: Vec<String>,
}

impl PrivilegedRuntimeExecutionPlan {
    pub fn new(probe_binary: impl Into<PathBuf>, invocation: PrivilegedRuntimeInvocation) -> Self {
        let timeout_seconds = invocation.profile.timeout.as_secs().max(1);
        let network_boundary = match invocation.profile.network_access {
            NetworkAccess::Disabled => PrivilegedRuntimeNetworkBoundary::PrivateNetwork,
            NetworkAccess::Enabled => PrivilegedRuntimeNetworkBoundary::HostNetwork,
        };
        let mut systemd_properties = vec![format!("RuntimeMaxSec={timeout_seconds}")];

        if network_boundary == PrivilegedRuntimeNetworkBoundary::PrivateNetwork {
            systemd_properties.push("PrivateNetwork=yes".to_string());
        }

        Self {
            probe_binary: probe_binary.into(),
            probe_args: vec![
                "internal-privileged-collector".to_string(),
                "--collector".to_string(),
                invocation.collector_id.as_internal_arg().to_string(),
            ],
            timeout: invocation.profile.timeout,
            network_boundary,
            systemd_properties,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivilegedRuntimeProcessOutput {
    pub stdout: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivilegedRuntimeProcessError {
    Failed(String),
    TimedOut { timeout: Duration },
}

pub trait PrivilegedRuntimeProcessRunner {
    fn run(
        &mut self,
        plan: &PrivilegedRuntimeExecutionPlan,
    ) -> Result<PrivilegedRuntimeProcessOutput, PrivilegedRuntimeProcessError>;
}

impl<T> PrivilegedRuntimeProcessRunner for &mut T
where
    T: PrivilegedRuntimeProcessRunner,
{
    fn run(
        &mut self,
        plan: &PrivilegedRuntimeExecutionPlan,
    ) -> Result<PrivilegedRuntimeProcessOutput, PrivilegedRuntimeProcessError> {
        (**self).run(plan)
    }
}

pub struct LocalPrivilegedRuntimeRunner<P = AutoPrivilegedRuntimeProcessRunner> {
    probe_binary: PathBuf,
    process_runner: P,
}

impl<P> LocalPrivilegedRuntimeRunner<P> {
    pub fn new(probe_binary: impl Into<PathBuf>, process_runner: P) -> Self {
        Self {
            probe_binary: probe_binary.into(),
            process_runner,
        }
    }
}

impl<P> PrivilegedRuntimeRunner for LocalPrivilegedRuntimeRunner<P>
where
    P: PrivilegedRuntimeProcessRunner,
{
    fn run(
        &mut self,
        invocation: PrivilegedRuntimeInvocation,
    ) -> Result<PrivilegedRuntimeOutput, PrivilegedRuntimeError> {
        let plan = PrivilegedRuntimeExecutionPlan::new(&self.probe_binary, invocation);

        self.process_runner
            .run(&plan)
            .map(|output| PrivilegedRuntimeOutput {
                stdout: output.stdout,
            })
            .map_err(|error| match error {
                PrivilegedRuntimeProcessError::Failed(message) => {
                    PrivilegedRuntimeError::collector_failed(message)
                }
                PrivilegedRuntimeProcessError::TimedOut { timeout } => {
                    PrivilegedRuntimeError::TimedOut { timeout }
                }
            })
    }
}

#[derive(Default)]
pub struct AutoPrivilegedRuntimeProcessRunner {
    systemd_runner: SystemdPrivilegedRuntimeProcessRunner,
}

impl PrivilegedRuntimeProcessRunner for AutoPrivilegedRuntimeProcessRunner {
    fn run(
        &mut self,
        plan: &PrivilegedRuntimeExecutionPlan,
    ) -> Result<PrivilegedRuntimeProcessOutput, PrivilegedRuntimeProcessError> {
        if !systemd_runtime_available() {
            return Err(PrivilegedRuntimeProcessError::Failed(
                "systemd privileged runtime is unavailable".to_string(),
            ));
        }

        self.systemd_runner.run(plan)
    }
}

#[derive(Default)]
pub struct SystemdPrivilegedRuntimeProcessRunner;

impl PrivilegedRuntimeProcessRunner for SystemdPrivilegedRuntimeProcessRunner {
    fn run(
        &mut self,
        plan: &PrivilegedRuntimeExecutionPlan,
    ) -> Result<PrivilegedRuntimeProcessOutput, PrivilegedRuntimeProcessError> {
        let mut command = Command::new("sudo");
        command.args([
            "-n",
            "/usr/bin/systemd-run",
            "--quiet",
            "--pipe",
            "--wait",
            "--collect",
        ]);

        for property in &plan.systemd_properties {
            command.arg(format!("--property={property}"));
        }

        command.arg(Path::new(&plan.probe_binary));
        command.args(&plan.probe_args);

        let output = command.output().map_err(|error| {
            PrivilegedRuntimeProcessError::Failed(format!(
                "privileged runtime boundary unavailable: {error}"
            ))
        })?;

        if output.status.success() {
            return Ok(PrivilegedRuntimeProcessOutput {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            });
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(PrivilegedRuntimeProcessError::Failed(format!(
            "privileged runtime child failed: {}",
            stderr.trim()
        )))
    }
}

fn systemd_runtime_available() -> bool {
    systemd_runtime_available_at(
        Path::new("/usr/bin/systemd-run"),
        Path::new("/run/systemd/system"),
    )
}

fn systemd_runtime_available_at(systemd_run: &Path, runtime_dir: &Path) -> bool {
    systemd_run.exists() && runtime_dir.exists()
}

#[cfg(test)]
mod tests {
    use super::systemd_runtime_available_at;

    #[test]
    fn systemd_runtime_requires_binary_and_runtime_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let systemd_run = temp.path().join("systemd-run");
        let runtime_dir = temp.path().join("systemd");

        assert!(!systemd_runtime_available_at(&systemd_run, &runtime_dir));

        std::fs::write(&systemd_run, "").expect("systemd-run marker");
        assert!(!systemd_runtime_available_at(&systemd_run, &runtime_dir));

        std::fs::create_dir(&runtime_dir).expect("runtime dir");
        assert!(systemd_runtime_available_at(&systemd_run, &runtime_dir));
    }
}

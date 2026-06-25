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
pub struct CollectorHelperProfile {
    pub timeout: Duration,
    pub network_access: NetworkAccess,
}

pub const DEFAULT_COLLECTOR_HELPER_PROFILE: CollectorHelperProfile = CollectorHelperProfile {
    timeout: Duration::from_secs(10),
    network_access: NetworkAccess::Disabled,
};

pub const DISK_HEALTH_SMARTCTL_HELPER_PROFILE: CollectorHelperProfile = CollectorHelperProfile {
    timeout: Duration::from_secs(10),
    network_access: NetworkAccess::Disabled,
};

impl Default for CollectorHelperProfile {
    fn default() -> Self {
        DEFAULT_COLLECTOR_HELPER_PROFILE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegedCollectorHelperId {
    DiskHealthSmartctl,
    FixedCollector,
    NetworkEnabledCollector,
    TimeoutCollector,
}

impl PrivilegedCollectorHelperId {
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
pub struct PrivilegedCollectorHelperEntrypoint {
    pub command: &'static str,
    pub helper_arg: &'static str,
    pub executable: PrivilegedCollectorHelperExecutable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegedCollectorHelperExecutable {
    DiskHealthSmartctl,
}

#[derive(Clone, Copy, Debug)]
pub struct CompiledPrivilegedCollectorHelperSpec {
    pub id: PrivilegedCollectorHelperId,
    pub profile: CollectorHelperProfile,
    pub entrypoint: PrivilegedCollectorHelperEntrypoint,
    pub exposure_predicate: fn(&dyn CollectorHelperExposureEnvironment) -> bool,
}

pub const COMPILED_PRIVILEGED_COLLECTOR_HELPER_SPECS: &[CompiledPrivilegedCollectorHelperSpec] =
    &[CompiledPrivilegedCollectorHelperSpec {
        id: PrivilegedCollectorHelperId::DiskHealthSmartctl,
        profile: DISK_HEALTH_SMARTCTL_HELPER_PROFILE,
        entrypoint: PrivilegedCollectorHelperEntrypoint {
            command: "internal-privileged-collector-helper",
            helper_arg: "disk-health.smartctl",
            executable: PrivilegedCollectorHelperExecutable::DiskHealthSmartctl,
        },
        exposure_predicate: disk_health_smartctl_exposed,
    }];

pub type CompiledPrivilegedCollectorHelperSpecs = [CompiledPrivilegedCollectorHelperSpec];

pub fn compiled_privileged_collector_helper_specs()
-> &'static CompiledPrivilegedCollectorHelperSpecs {
    COMPILED_PRIVILEGED_COLLECTOR_HELPER_SPECS
}

pub fn compiled_privileged_collector_helper_spec(
    helper_id: PrivilegedCollectorHelperId,
) -> Option<&'static CompiledPrivilegedCollectorHelperSpec> {
    COMPILED_PRIVILEGED_COLLECTOR_HELPER_SPECS
        .iter()
        .find(|spec| spec.id == helper_id)
}

pub trait CollectorHelperExposureEnvironment {
    fn tool_exists(&self, path: &Path) -> bool;
}

pub const DISK_HEALTH_SMARTCTL_PATHS: [&str; 2] = ["/usr/sbin/smartctl", "/usr/bin/smartctl"];

pub fn disk_health_smartctl_path(
    environment: &dyn CollectorHelperExposureEnvironment,
) -> Option<PathBuf> {
    DISK_HEALTH_SMARTCTL_PATHS
        .iter()
        .map(Path::new)
        .find(|path| environment.tool_exists(path))
        .map(Path::to_path_buf)
}

#[derive(Default)]
pub struct LocalCollectorHelperExposureEnvironment;

impl CollectorHelperExposureEnvironment for LocalCollectorHelperExposureEnvironment {
    fn tool_exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectorHelperSudoersPlanInput {
    pub service_user: String,
    pub probe_binary: PathBuf,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CollectorHelperSudoersPlan {
    pub lines: Vec<String>,
    pub content: Option<String>,
}

pub struct CollectorHelperSudoersPlanner<'a> {
    environment: &'a dyn CollectorHelperExposureEnvironment,
}

impl<'a> CollectorHelperSudoersPlanner<'a> {
    pub fn new(environment: &'a dyn CollectorHelperExposureEnvironment) -> Self {
        Self { environment }
    }

    pub fn plan(&self, input: CollectorHelperSudoersPlanInput) -> CollectorHelperSudoersPlan {
        let lines = compiled_privileged_collector_helper_specs()
            .iter()
            .filter(|spec| (spec.exposure_predicate)(self.environment))
            .map(|spec| render_collector_helper_sudoers_line(&input, spec))
            .collect::<Vec<_>>();

        let content = if lines.is_empty() {
            None
        } else {
            Some(format!(
                "# Managed by Enoki Probe installer.\n{}\n",
                lines.join("\n")
            ))
        };

        CollectorHelperSudoersPlan { lines, content }
    }
}

fn render_collector_helper_sudoers_line(
    input: &CollectorHelperSudoersPlanInput,
    spec: &CompiledPrivilegedCollectorHelperSpec,
) -> String {
    let plan = LocalPrivilegeBoundaryExecutionPlan::new(
        &input.probe_binary,
        PrivilegedCollectorHelperInvocation {
            helper_id: spec.id,
            profile: spec.profile,
        },
    );
    let mut line = format!(
        "{} ALL=(root) NOPASSWD: /usr/bin/systemd-run --quiet --pipe --wait --collect",
        input.service_user,
    );

    for property in &plan.systemd_properties {
        line.push_str(&format!(" --property={property}"));
    }

    line.push(' ');
    line.push_str(&plan.probe_binary.display().to_string());
    for arg in [
        spec.entrypoint.command,
        "--helper",
        spec.entrypoint.helper_arg,
    ] {
        line.push(' ');
        line.push_str(arg);
    }

    line
}

fn disk_health_smartctl_exposed(environment: &dyn CollectorHelperExposureEnvironment) -> bool {
    disk_health_smartctl_path(environment).is_some()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivilegedCollectorHelperError {
    CollectorFailed(String),
    LocalPrivilegeBoundaryUnavailable(String),
    TimedOut { timeout: Duration },
}

impl PrivilegedCollectorHelperError {
    pub fn collector_failed(message: impl Into<String>) -> Self {
        Self::CollectorFailed(message.into())
    }

    pub fn local_privilege_boundary_unavailable(message: impl Into<String>) -> Self {
        Self::LocalPrivilegeBoundaryUnavailable(message.into())
    }
}

impl fmt::Display for PrivilegedCollectorHelperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CollectorFailed(message) => formatter.write_str(message),
            Self::LocalPrivilegeBoundaryUnavailable(message) => formatter.write_str(message),
            Self::TimedOut { timeout } => {
                write!(
                    formatter,
                    "privileged collector helper timed out after {timeout:?}"
                )
            }
        }
    }
}

impl Error for PrivilegedCollectorHelperError {}

pub trait PrivilegedCollectorHelper {
    fn helper_id(&self) -> PrivilegedCollectorHelperId;

    fn helper_profile(&self) -> &'static CollectorHelperProfile {
        &DEFAULT_COLLECTOR_HELPER_PROFILE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivilegedCollectorHelperInvocation {
    pub helper_id: PrivilegedCollectorHelperId,
    pub profile: CollectorHelperProfile,
}

pub trait PrivilegedCollectorHelperRunner {
    fn run(
        &mut self,
        invocation: PrivilegedCollectorHelperInvocation,
    ) -> Result<PrivilegedCollectorHelperOutput, PrivilegedCollectorHelperError>;
}

impl<T> PrivilegedCollectorHelperRunner for &mut T
where
    T: PrivilegedCollectorHelperRunner,
{
    fn run(
        &mut self,
        invocation: PrivilegedCollectorHelperInvocation,
    ) -> Result<PrivilegedCollectorHelperOutput, PrivilegedCollectorHelperError> {
        (**self).run(invocation)
    }
}

pub struct ProbeLocalPrivilegeBoundary<R> {
    runner: R,
}

impl<R> ProbeLocalPrivilegeBoundary<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R> ProbeLocalPrivilegeBoundary<R>
where
    R: PrivilegedCollectorHelperRunner,
{
    pub fn run(
        &mut self,
        collector: &dyn PrivilegedCollectorHelper,
    ) -> Result<PrivilegedCollectorHelperOutput, PrivilegedCollectorHelperError> {
        self.runner.run(PrivilegedCollectorHelperInvocation {
            helper_id: collector.helper_id(),
            profile: *collector.helper_profile(),
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivilegedCollectorHelperOutput {
    pub stdout: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPrivilegeNetworkBoundary {
    PrivateNetwork,
    HostNetwork,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPrivilegeBoundaryExecutionPlan {
    pub probe_binary: PathBuf,
    pub probe_args: Vec<String>,
    pub timeout: Duration,
    pub network_boundary: LocalPrivilegeNetworkBoundary,
    pub systemd_properties: Vec<String>,
}

impl LocalPrivilegeBoundaryExecutionPlan {
    pub fn new(
        probe_binary: impl Into<PathBuf>,
        invocation: PrivilegedCollectorHelperInvocation,
    ) -> Self {
        let timeout_seconds = invocation.profile.timeout.as_secs().max(1);
        let network_boundary = match invocation.profile.network_access {
            NetworkAccess::Disabled => LocalPrivilegeNetworkBoundary::PrivateNetwork,
            NetworkAccess::Enabled => LocalPrivilegeNetworkBoundary::HostNetwork,
        };
        let mut systemd_properties = vec![format!("RuntimeMaxSec={timeout_seconds}")];

        if network_boundary == LocalPrivilegeNetworkBoundary::PrivateNetwork {
            systemd_properties.push("PrivateNetwork=yes".to_string());
        }

        Self {
            probe_binary: probe_binary.into(),
            probe_args: vec![
                "internal-privileged-collector-helper".to_string(),
                "--helper".to_string(),
                invocation.helper_id.as_internal_arg().to_string(),
            ],
            timeout: invocation.profile.timeout,
            network_boundary,
            systemd_properties,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalPrivilegeBoundaryProcessOutput {
    pub stdout: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalPrivilegeBoundaryProcessError {
    Failed(String),
    TimedOut { timeout: Duration },
}

pub trait LocalPrivilegeBoundaryProcessRunner {
    fn run(
        &mut self,
        plan: &LocalPrivilegeBoundaryExecutionPlan,
    ) -> Result<LocalPrivilegeBoundaryProcessOutput, LocalPrivilegeBoundaryProcessError>;
}

impl<T> LocalPrivilegeBoundaryProcessRunner for &mut T
where
    T: LocalPrivilegeBoundaryProcessRunner,
{
    fn run(
        &mut self,
        plan: &LocalPrivilegeBoundaryExecutionPlan,
    ) -> Result<LocalPrivilegeBoundaryProcessOutput, LocalPrivilegeBoundaryProcessError> {
        (**self).run(plan)
    }
}

pub struct LocalPrivilegeBoundaryRunner<P = AutoLocalPrivilegeBoundaryProcessRunner> {
    probe_binary: PathBuf,
    process_runner: P,
}

impl<P> LocalPrivilegeBoundaryRunner<P> {
    pub fn new(probe_binary: impl Into<PathBuf>, process_runner: P) -> Self {
        Self {
            probe_binary: probe_binary.into(),
            process_runner,
        }
    }
}

impl<P> PrivilegedCollectorHelperRunner for LocalPrivilegeBoundaryRunner<P>
where
    P: LocalPrivilegeBoundaryProcessRunner,
{
    fn run(
        &mut self,
        invocation: PrivilegedCollectorHelperInvocation,
    ) -> Result<PrivilegedCollectorHelperOutput, PrivilegedCollectorHelperError> {
        let plan = LocalPrivilegeBoundaryExecutionPlan::new(&self.probe_binary, invocation);

        self.process_runner
            .run(&plan)
            .map(|output| PrivilegedCollectorHelperOutput {
                stdout: output.stdout,
            })
            .map_err(|error| match error {
                LocalPrivilegeBoundaryProcessError::Failed(message) => {
                    PrivilegedCollectorHelperError::local_privilege_boundary_unavailable(message)
                }
                LocalPrivilegeBoundaryProcessError::TimedOut { timeout } => {
                    PrivilegedCollectorHelperError::TimedOut { timeout }
                }
            })
    }
}

#[derive(Default)]
pub struct AutoLocalPrivilegeBoundaryProcessRunner {
    systemd_runner: SystemdLocalPrivilegeBoundaryProcessRunner,
}

impl LocalPrivilegeBoundaryProcessRunner for AutoLocalPrivilegeBoundaryProcessRunner {
    fn run(
        &mut self,
        plan: &LocalPrivilegeBoundaryExecutionPlan,
    ) -> Result<LocalPrivilegeBoundaryProcessOutput, LocalPrivilegeBoundaryProcessError> {
        if !systemd_runtime_available() {
            return Err(LocalPrivilegeBoundaryProcessError::Failed(
                "systemd local privilege boundary is unavailable".to_string(),
            ));
        }

        self.systemd_runner.run(plan)
    }
}

#[derive(Default)]
pub struct SystemdLocalPrivilegeBoundaryProcessRunner;

impl LocalPrivilegeBoundaryProcessRunner for SystemdLocalPrivilegeBoundaryProcessRunner {
    fn run(
        &mut self,
        plan: &LocalPrivilegeBoundaryExecutionPlan,
    ) -> Result<LocalPrivilegeBoundaryProcessOutput, LocalPrivilegeBoundaryProcessError> {
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
            LocalPrivilegeBoundaryProcessError::Failed(format!(
                "local privilege boundary unavailable: {error}"
            ))
        })?;

        if output.status.success() {
            return Ok(LocalPrivilegeBoundaryProcessOutput {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            });
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(LocalPrivilegeBoundaryProcessError::Failed(format!(
            "privileged collector helper failed: {}",
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

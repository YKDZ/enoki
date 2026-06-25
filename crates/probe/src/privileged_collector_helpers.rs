use std::{error::Error, fmt};

use crate::{
    local_privilege_boundary::{
        PrivilegedCollectorHelperExecutable, PrivilegedCollectorHelperId,
        compiled_privileged_collector_helper_spec,
    },
    metrics::{
        DiskHealthCollection, collect_disk_health_metrics_with_smartctl,
        format_disk_health_collection_json,
    },
};

#[derive(Debug)]
pub enum CompiledPrivilegedCollectorHelperError {
    CollectorFailed(String),
    NotCompiled(PrivilegedCollectorHelperId),
}

impl fmt::Display for CompiledPrivilegedCollectorHelperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CollectorFailed(message) => formatter.write_str(message),
            Self::NotCompiled(helper_id) => {
                write!(
                    formatter,
                    "no compiled privileged collector helper entrypoint linked for {helper_id:?}"
                )
            }
        }
    }
}

impl Error for CompiledPrivilegedCollectorHelperError {}

pub fn run_compiled_privileged_collector_helper(
    helper_id: PrivilegedCollectorHelperId,
) -> Result<String, CompiledPrivilegedCollectorHelperError> {
    let spec = compiled_privileged_collector_helper_spec(helper_id).ok_or(
        CompiledPrivilegedCollectorHelperError::NotCompiled(helper_id),
    )?;

    run_compiled_privileged_collector_helper_executable(spec.entrypoint.executable)
}

fn run_compiled_privileged_collector_helper_executable(
    executable: PrivilegedCollectorHelperExecutable,
) -> Result<String, CompiledPrivilegedCollectorHelperError> {
    match executable {
        PrivilegedCollectorHelperExecutable::DiskHealthSmartctl => run_disk_health_smartctl(),
    }
}

fn run_disk_health_smartctl() -> Result<String, CompiledPrivilegedCollectorHelperError> {
    let collection = match collect_disk_health_metrics_with_smartctl() {
        Ok(metrics) => DiskHealthCollection::available(metrics),
        Err(error) => DiskHealthCollection::unavailable(error.status, error.diagnostic),
    };

    Ok(format_disk_health_collection_json(&collection))
}

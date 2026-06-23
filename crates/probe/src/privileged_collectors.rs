use std::{error::Error, fmt};

use crate::{
    metrics::{collect_disk_health_metrics_with_smartctl, format_disk_health_metrics_json},
    privileged_runtime::{PrivilegedCollectorId, compiled_privileged_collector_spec},
};

#[derive(Debug)]
pub enum CompiledPrivilegedCollectorError {
    CollectorFailed(String),
    NotCompiled(PrivilegedCollectorId),
}

impl fmt::Display for CompiledPrivilegedCollectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CollectorFailed(message) => formatter.write_str(message),
            Self::NotCompiled(collector_id) => {
                write!(
                    formatter,
                    "no compiled privileged collector entrypoint linked for {collector_id:?}"
                )
            }
        }
    }
}

impl Error for CompiledPrivilegedCollectorError {}

struct CompiledPrivilegedCollectorEntrypoint {
    collector_id: PrivilegedCollectorId,
    run: fn() -> Result<String, CompiledPrivilegedCollectorError>,
}

const COMPILED_PRIVILEGED_COLLECTOR_ENTRYPOINTS: &[CompiledPrivilegedCollectorEntrypoint] =
    &[CompiledPrivilegedCollectorEntrypoint {
        collector_id: PrivilegedCollectorId::DiskHealthSmartctl,
        run: run_disk_health_smartctl,
    }];

pub fn run_compiled_privileged_collector(
    collector_id: PrivilegedCollectorId,
) -> Result<String, CompiledPrivilegedCollectorError> {
    let _spec = compiled_privileged_collector_spec(collector_id)
        .ok_or(CompiledPrivilegedCollectorError::NotCompiled(collector_id))?;
    let entrypoint = COMPILED_PRIVILEGED_COLLECTOR_ENTRYPOINTS
        .iter()
        .find(|entrypoint| entrypoint.collector_id == collector_id)
        .ok_or(CompiledPrivilegedCollectorError::NotCompiled(collector_id))?;

    (entrypoint.run)()
}

fn run_disk_health_smartctl() -> Result<String, CompiledPrivilegedCollectorError> {
    collect_disk_health_metrics_with_smartctl()
        .map(|metrics| format_disk_health_metrics_json(&metrics))
        .map_err(|error| CompiledPrivilegedCollectorError::CollectorFailed(error.to_string()))
}

//! 独立、短生命周期的本机生命周期角色入口。

use std::{io::Read, process::ExitCode};

use enoki_probe_bootstrap::lifecycle::{LifecyclePlan, LifecycleTransition};
use serde::Deserialize;

const MAX_REQUEST_BYTES: u64 = 8 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LifecycleRequest {
    schema_version: u16,
    transition: String,
}

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        return ExitCode::from(2);
    }
    let mut bytes = Vec::new();
    if std::io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.is_empty()
        || bytes.len() as u64 > MAX_REQUEST_BYTES
    {
        return ExitCode::from(2);
    }
    let Ok(request) = serde_json::from_slice::<LifecycleRequest>(&bytes) else {
        return ExitCode::from(2);
    };
    if request.schema_version != 1 {
        return ExitCode::from(2);
    }
    let transition = match request.transition.as_str() {
        "fresh-install" => LifecycleTransition::FreshInstall,
        "upgrade" => LifecycleTransition::Upgrade,
        "repair" => LifecycleTransition::Repair,
        "replacement-migration" => LifecycleTransition::ReplacementMigration,
        "uninstall" => LifecycleTransition::Uninstall,
        _ => return ExitCode::from(2),
    };
    match LifecyclePlan::for_transition(transition) {
        Ok(_) => ExitCode::from(1),
        Err(error) => {
            eprintln!("Probe Local Lifecycle rejected: code={}", error.code());
            ExitCode::from(3)
        }
    }
}

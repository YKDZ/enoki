//! Probe Repair 的封闭 coordinator Module。
//!
//! 顶层 dispatcher 只交付完整 lifecycle request 与 peer 事实；本 Module 独占
//! 两种封闭 eligibility 的 wire authority、安装/身份绑定和失败映射。

use super::{
    PRODUCTION_BOOTSTRAP_ACQUIRER_PATH, PRODUCTION_INSTALL_METADATA_PATH, ProbeRepairResult,
    ProbeRepairRunError, ProbeUpgraderRunError, read_trusted_probe_install_metadata,
    read_trusted_probe_install_preflight,
};
use enoki_probe_bootstrap::{
    acquisition::remove_verified_probe_upgrade_stage,
    install::{
        FixedInstallPaths, RepairIntentState, SystemSystemd, complete_authorized_probe_repair,
        consume_probe_repair_authority, execute_authorized_probe_repair,
        issue_probe_repair_evidence, persist_probe_repair_execution_failure,
        resume_probe_repair_intent,
    },
    lifecycle::{
        LifecycleRequest, LifecycleRequestAuthority, LifecycleResponse, RepairAuthorityV1,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
};

pub(super) fn coordinate(request: &LifecycleRequest, peer_uid: Option<u32>) -> LifecycleResponse {
    let metadata_path = Path::new(PRODUCTION_INSTALL_METADATA_PATH);
    let metadata = match read_trusted_probe_install_metadata(metadata_path, None) {
        Ok(metadata) => metadata,
        Err(_) => return LifecycleResponse::failed("lifecycle.install_state_invalid"),
    };
    let identity = match read_trusted_probe_install_preflight(metadata_path, None) {
        Ok(identity) => identity,
        Err(_) => return LifecycleResponse::failed("lifecycle.identity_invalid"),
    };
    let LifecycleRequestAuthority::LocalRepair {
        probe_id,
        install_state_sha256,
        target_manifest_sha256,
        bundle_version,
        invoking_uid,
        invoking_gid,
    } = request.authority()
    else {
        return LifecycleResponse::failed("lifecycle.invalid_authority");
    };
    if peer_uid != Some(0)
        || identity.probe_id != *probe_id
        || metadata.install_state_sha256.as_deref() != Some(install_state_sha256)
        || metadata.target_manifest_sha256.as_deref() != Some(target_manifest_sha256)
        || metadata.bundle_version.as_deref() != Some(bundle_version)
    {
        return LifecycleResponse::failed("lifecycle.authority_mismatch");
    }
    response(run_authorized_for_invoking_admin(
        *invoking_uid,
        *invoking_gid,
    ))
}

pub(super) fn response(
    result: Result<ProbeRepairResult, ProbeRepairRunError>,
) -> LifecycleResponse {
    match result {
        Ok(_) => LifecycleResponse::succeeded(),
        Err(error) if error.code() == "probe_manual_reinstall_required" => {
            LifecycleResponse::failed("probe_manual_reinstall_required")
        }
        Err(_) => LifecycleResponse::failed("lifecycle.repair_unresolved"),
    }
}

fn run_authorized_for_invoking_admin(
    invoking_uid: u32,
    invoking_gid: u32,
) -> Result<ProbeRepairResult, ProbeRepairRunError> {
    if unsafe { libc::geteuid() } != 0 || invoking_uid == 0 || invoking_gid == 0 {
        return Err(ProbeRepairRunError::RootRequired);
    }
    let paths = FixedInstallPaths::production();
    let resumable_upgrade = resume_probe_repair_intent(&paths)
        .map_err(|_| ProbeUpgraderRunError::ManualProbeReinstallRequired)?;
    let upgrade_failure_is_current = resumable_upgrade.is_some()
        || issue_probe_repair_evidence(&paths, 1, 2, "repair_dispatch_probe").is_ok();
    let installed_failure_is_current =
        crate::runtime_failure::installed_bundle_failure_is_current();
    if installed_failure_is_current && upgrade_failure_is_current {
        return Err(ProbeUpgraderRunError::ManualProbeReinstallRequired.into());
    }
    if installed_failure_is_current {
        return run_installed_bundle_repair(invoking_uid, invoking_gid);
    }
    if Path::new("/var/lib/enoki-probe/runtime-failure/latch").exists() {
        return Err(ProbeUpgraderRunError::ManualProbeReinstallRequired.into());
    }
    let consumed = if let Some(consumed) = resumable_upgrade {
        consumed
    } else {
        let (request_nonce, now_ms) = fresh_exchange_facts()?;
        let signed = issue_probe_repair_evidence(
            &paths,
            now_ms,
            now_ms.saturating_add(60_000),
            &request_nonce,
        )
        .map_err(|_| ProbeUpgraderRunError::ManualProbeReinstallRequired)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct RepairAuthorizationRequest<'a> {
            evidence: &'a enoki_probe_bootstrap::lifecycle::RepairEvidenceV1,
            evidence_signature: &'a str,
        }
        let request = serde_json::to_vec(&RepairAuthorizationRequest {
            evidence: &signed.evidence,
            evidence_signature: &signed.signature,
        })
        .map_err(|_| contract_failure("probe_repair_request_invalid"))?;
        let output = exchange_authority(&request, invoking_uid, invoking_gid)?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RepairAuthorizationResponse {
            authority: RepairAuthorityV1,
            signature: String,
        }
        let response: RepairAuthorizationResponse = serde_json::from_slice(&output)
            .map_err(|_| contract_failure("probe_repair_authority_invalid"))?;
        consume_probe_repair_authority(
            &paths,
            &signed.evidence,
            &signed.signature,
            &response.authority,
            &response.signature,
            now_ms,
        )
        .map_err(|_| contract_failure("probe_repair_authority_invalid"))?
    };
    let mut systemd = SystemSystemd::for_live_upgrade();
    let repaired = if consumed.state == RepairIntentState::CompletionPending {
        complete_authorized_probe_repair(&paths, &consumed)
    } else {
        execute_authorized_probe_repair(
            &paths,
            &consumed,
            &mut systemd,
            |operation_id, owner_uid| {
                remove_verified_probe_upgrade_stage(operation_id, owner_uid)
                    .map_err(|_| enoki_probe_bootstrap::install::InstallError::Io)
            },
        )
    };
    if repaired.is_err() {
        persist_probe_repair_execution_failure(&paths, &consumed)
            .map_err(|_| contract_failure("probe_repair_intent_persist_failed"))?;
        return Err(contract_failure("probe_repair_recovery_pending"));
    }
    Ok(ProbeRepairResult {
        probe_id: consumed.probe_id,
        repaired_version: consumed.target_bundle_version,
    })
}

fn run_installed_bundle_repair(
    invoking_uid: u32,
    invoking_gid: u32,
) -> Result<ProbeRepairResult, ProbeRepairRunError> {
    if let Some(resumable) = crate::runtime_failure::resume_installed_bundle_repair()
        .map_err(|_| contract_failure("probe_repair_intent_invalid"))?
    {
        return adapt_installed_bundle_result(
            crate::runtime_failure::drive_live_installed_bundle_repair(resumable),
        );
    }
    let (request_nonce, now_ms) = fresh_exchange_facts()?;
    let signed = crate::runtime_failure::issue_installed_bundle_failure_evidence(
        now_ms,
        now_ms.saturating_add(60_000),
        &request_nonce,
    )
    .map_err(|_| ProbeUpgraderRunError::ManualProbeReinstallRequired)?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Request<'a> {
        evidence: &'a enoki_probe_bootstrap::lifecycle::InstalledBundleFailureEvidenceV1,
        evidence_signature: &'a str,
    }
    let request = serde_json::to_vec(&Request {
        evidence: &signed.evidence,
        evidence_signature: &signed.signature,
    })
    .map_err(|_| contract_failure("probe_repair_request_invalid"))?;
    let output = exchange_authority(&request, invoking_uid, invoking_gid)?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Response {
        authority: enoki_probe_bootstrap::lifecycle::InstalledBundleRepairAuthorityV1,
        signature: String,
        stage_receipt: enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
    }
    let response: Response = serde_json::from_slice(&output)
        .map_err(|_| contract_failure("probe_repair_authority_invalid"))?;
    let grant = crate::runtime_failure::validate_installed_bundle_repair_authority(
        &signed,
        &response.authority,
        &response.signature,
        now_ms,
    )
    .map_err(|_| ProbeUpgraderRunError::ManualProbeReinstallRequired)?;
    let identity_metadata =
        fs::symlink_metadata("/var/lib/enoki-probe/identity/probe-bootstrap.toml")
            .map_err(|_| ProbeUpgraderRunError::ManualProbeReinstallRequired)?;
    let session = crate::runtime_failure::begin_installed_bundle_repair(
        grant,
        response.stage_receipt,
        identity_metadata.uid(),
    )
    .map_err(|_| contract_failure("probe_repair_intent_persist_failed"))?;
    adapt_installed_bundle_result(crate::runtime_failure::drive_live_installed_bundle_repair(
        session,
    ))
}

fn adapt_installed_bundle_result(
    result: Result<
        crate::runtime_failure::InstalledBundleRepairOutcome,
        crate::runtime_failure::LiveInstalledBundleRepairError,
    >,
) -> Result<ProbeRepairResult, ProbeRepairRunError> {
    result
        .map(|outcome| ProbeRepairResult {
            probe_id: outcome.probe_id,
            repaired_version: outcome.repaired_version,
        })
        .map_err(|error| match error {
            crate::runtime_failure::LiveInstalledBundleRepairError::ManualReinstallRequired => {
                ProbeUpgraderRunError::ManualProbeReinstallRequired.into()
            }
            crate::runtime_failure::LiveInstalledBundleRepairError::Contract(code) => {
                contract_failure(code)
            }
        })
}

pub(super) fn acquirer_exit_failure(code: Option<i32>) -> Option<ProbeRepairRunError> {
    (code == Some(3)).then(|| ProbeUpgraderRunError::ManualProbeReinstallRequired.into())
}

fn fresh_exchange_facts() -> Result<(String, u64), ProbeRepairRunError> {
    let mut nonce = [0_u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut nonce))
        .map_err(|_| contract_failure("probe_repair_random_failed"))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| contract_failure("probe_repair_clock_invalid"))?
        .as_millis()
        .try_into()
        .map_err(|_| contract_failure("probe_repair_clock_invalid"))?;
    Ok((
        nonce.iter().map(|byte| format!("{byte:02x}")).collect(),
        now_ms,
    ))
}

fn exchange_authority(
    request: &[u8],
    invoking_uid: u32,
    invoking_gid: u32,
) -> Result<Vec<u8>, ProbeRepairRunError> {
    let mut acquirer = Command::new(PRODUCTION_BOOTSTRAP_ACQUIRER_PATH);
    acquirer.arg("--repair-authorize");
    configure_acquirer_privileges(&mut acquirer, invoking_uid, invoking_gid);
    let mut child = acquirer
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| contract_failure("probe_repair_authority_acquire_failed"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| contract_failure("probe_repair_authority_acquire_failed"))?
        .write_all(request)
        .map_err(|_| contract_failure("probe_repair_authority_acquire_failed"))?;
    let output = child
        .wait_with_output()
        .map_err(|_| contract_failure("probe_repair_authority_acquire_failed"))?;
    if let Some(error) = acquirer_exit_failure(output.status.code()) {
        return Err(error);
    }
    if !output.status.success() || output.stdout.is_empty() || output.stdout.len() > 8 * 1024 {
        return Err(contract_failure("probe_repair_authority_acquire_failed"));
    }
    Ok(output.stdout)
}

fn configure_acquirer_privileges(command: &mut Command, uid: u32, gid: u32) {
    command.env_clear();
    // SAFETY：该 hook 在 fork 后、exec 前的子进程中执行，仅使用捕获的标量调用
    // async-signal-safe 凭据 syscall。
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn contract_failure(code: &'static str) -> ProbeRepairRunError {
    ProbeRepairRunError::ServiceReconstruction {
        code,
        message: "explicit Probe Repair remains unresolved".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquirer_exit_three_is_the_only_manual_reinstall_classification() {
        assert!(matches!(
            acquirer_exit_failure(Some(3)),
            Some(ProbeRepairRunError::Installation(
                ProbeUpgraderRunError::ManualProbeReinstallRequired
            ))
        ));
        assert!(acquirer_exit_failure(Some(1)).is_none());
        assert!(acquirer_exit_failure(None).is_none());
    }

    #[test]
    fn response_keeps_manual_reinstall_distinct_from_unresolved_repair() {
        assert_eq!(
            response(Err(
                ProbeUpgraderRunError::ManualProbeReinstallRequired.into()
            )),
            LifecycleResponse::failed("probe_manual_reinstall_required")
        );
        assert_eq!(
            response(Err(contract_failure("probe_repair_recovery_pending"))),
            LifecycleResponse::failed("lifecycle.repair_unresolved")
        );
    }
}

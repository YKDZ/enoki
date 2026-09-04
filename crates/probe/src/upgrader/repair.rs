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
    acquisition::{
        INSTALLED_BUNDLE_REPAIR_STAGE_ROOT, discard_unadmitted_installed_bundle_repair_stage,
        prepare_installed_bundle_repair_stage, remove_verified_probe_upgrade_stage,
    },
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
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::process::CommandExt,
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
    let mut dependencies = ProductionRepairDependencies;
    response(run_authorized_for_invoking_admin_with(
        *invoking_uid,
        *invoking_gid,
        &mut dependencies,
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

fn run_authorized_for_invoking_admin_with(
    invoking_uid: u32,
    invoking_gid: u32,
    dependencies: &mut impl RepairDependencies,
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
        return run_installed_bundle_repair(invoking_uid, invoking_gid, dependencies);
    }
    if Path::new("/var/lib/enoki-probe/runtime-failure/latch").exists() {
        return Err(ProbeUpgraderRunError::ManualProbeReinstallRequired.into());
    }
    let consumed = if let Some(consumed) = resumable_upgrade {
        consumed
    } else {
        let (request_nonce, now_ms) = fresh_exchange_facts_with(dependencies)?;
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
        let output = exchange_authority_with(dependencies, &request, invoking_uid, invoking_gid)?;
        let response: RepairAuthorizationResponse = decode_authority_response(&output)?;
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
    dependencies: &mut impl RepairDependencies,
) -> Result<ProbeRepairResult, ProbeRepairRunError> {
    if let Some(resumable) = crate::runtime_failure::resume_installed_bundle_repair()
        .map_err(|_| contract_failure("probe_repair_intent_invalid"))?
    {
        return adapt_installed_bundle_result(
            crate::runtime_failure::drive_live_installed_bundle_repair(resumable),
        );
    }
    let (request_nonce, now_ms) = fresh_exchange_facts_with(dependencies)?;
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
    prepare_installed_bundle_repair_stage(invoking_uid, invoking_gid)
        .map_err(|_| contract_failure("probe_repair_stage_prepare_failed"))?;
    let output = match exchange_installed_bundle_authority_with(
        dependencies,
        &request,
        invoking_uid,
        invoking_gid,
    ) {
        Ok(output) => output,
        Err(error) => {
            cleanup_unadmitted_installed_bundle_stage(invoking_uid)?;
            return Err(error);
        }
    };
    let response: InstalledBundleRepairAuthorizationResponse =
        match decode_authority_response(&output) {
            Ok(response) => response,
            Err(error) => {
                cleanup_unadmitted_installed_bundle_stage(invoking_uid)?;
                return Err(error);
            }
        };
    let grant = match crate::runtime_failure::validate_installed_bundle_repair_authority(
        &signed,
        &response.authority,
        &response.signature,
        now_ms,
    ) {
        Ok(grant) => grant,
        Err(_) => {
            cleanup_unadmitted_installed_bundle_stage(invoking_uid)?;
            return Err(ProbeUpgraderRunError::ManualProbeReinstallRequired.into());
        }
    };
    let session = match crate::runtime_failure::begin_installed_bundle_repair(
        grant,
        response.stage_receipt.clone(),
        invoking_uid,
    ) {
        Ok(session) => session,
        Err(_) => {
            if matches!(
                crate::runtime_failure::resume_installed_bundle_repair(),
                Ok(None)
            ) {
                cleanup_unadmitted_installed_bundle_stage(invoking_uid)?;
            }
            return Err(contract_failure("probe_repair_intent_persist_failed"));
        }
    };
    adapt_installed_bundle_result(crate::runtime_failure::drive_live_installed_bundle_repair(
        session,
    ))
}

fn cleanup_unadmitted_installed_bundle_stage(invoking_uid: u32) -> Result<(), ProbeRepairRunError> {
    discard_unadmitted_installed_bundle_repair_stage(invoking_uid)
        .map_err(|_| contract_failure("probe_repair_stage_cleanup_failed"))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepairDependencyFailure {
    Random,
    Clock,
    Spawn(Option<i32>),
    Write,
    Wait,
}

#[derive(Debug)]
struct RepairAuthorityOutput {
    code: Option<i32>,
    stdout: Vec<u8>,
    successful: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepairAuthorizationResponse {
    authority: RepairAuthorityV1,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstalledBundleRepairAuthorizationResponse {
    authority: enoki_probe_bootstrap::lifecycle::InstalledBundleRepairAuthorityV1,
    signature: String,
    stage_receipt: enoki_probe_bootstrap::acquisition::VerifiedUpgradeStageReceipt,
}

fn decode_authority_response<T: DeserializeOwned>(output: &[u8]) -> Result<T, ProbeRepairRunError> {
    serde_json::from_slice(output).map_err(|_| contract_failure("probe_repair_authority_invalid"))
}

/// Repair coordinator 的内部事实与 authority exchange Interface。
/// production 与 deterministic tests 各自提供一个真实 Adapter。
trait RepairDependencies {
    fn fill_nonce(&mut self, nonce: &mut [u8]) -> Result<(), RepairDependencyFailure>;
    fn now_ms(&mut self) -> Result<u64, RepairDependencyFailure>;
    fn exchange_authority(
        &mut self,
        request: &[u8],
        invoking_uid: u32,
        invoking_gid: u32,
    ) -> Result<RepairAuthorityOutput, RepairDependencyFailure>;
    fn exchange_installed_bundle_authority(
        &mut self,
        request: &[u8],
        invoking_uid: u32,
        invoking_gid: u32,
    ) -> Result<RepairAuthorityOutput, RepairDependencyFailure>;
}

struct ProductionRepairDependencies;

impl RepairDependencies for ProductionRepairDependencies {
    fn fill_nonce(&mut self, nonce: &mut [u8]) -> Result<(), RepairDependencyFailure> {
        fs::File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(nonce))
            .map_err(|_| RepairDependencyFailure::Random)
    }

    fn now_ms(&mut self) -> Result<u64, RepairDependencyFailure> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| RepairDependencyFailure::Clock)?
            .as_millis()
            .try_into()
            .map_err(|_| RepairDependencyFailure::Clock)
    }

    fn exchange_authority(
        &mut self,
        request: &[u8],
        invoking_uid: u32,
        invoking_gid: u32,
    ) -> Result<RepairAuthorityOutput, RepairDependencyFailure> {
        let mut acquirer = Command::new(PRODUCTION_BOOTSTRAP_ACQUIRER_PATH);
        acquirer.arg("--repair-authorize");
        run_acquirer(acquirer, request, invoking_uid, invoking_gid)
    }

    fn exchange_installed_bundle_authority(
        &mut self,
        request: &[u8],
        invoking_uid: u32,
        invoking_gid: u32,
    ) -> Result<RepairAuthorityOutput, RepairDependencyFailure> {
        let mut acquirer = Command::new(PRODUCTION_BOOTSTRAP_ACQUIRER_PATH);
        // 该专用语义入口在 root child 降权前固定 cwd；调用方既不能选择 path/FD，
        // 降权后的 acquirer 也无需 traverse root-private Bootstrap parent。
        acquirer
            .arg("--repair-authorize")
            .current_dir(INSTALLED_BUNDLE_REPAIR_STAGE_ROOT);
        run_acquirer(acquirer, request, invoking_uid, invoking_gid)
    }
}

fn run_acquirer(
    mut acquirer: Command,
    request: &[u8],
    invoking_uid: u32,
    invoking_gid: u32,
) -> Result<RepairAuthorityOutput, RepairDependencyFailure> {
    configure_acquirer_privileges(&mut acquirer, invoking_uid, invoking_gid);
    let mut child = acquirer
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| {
            let failure = RepairDependencyFailure::Spawn(error.raw_os_error());
            if let Some(diagnostic) = repair_dependency_diagnostic(failure) {
                eprintln!("{diagnostic}");
            }
            failure
        })?;
    child
        .stdin
        .take()
        .ok_or(RepairDependencyFailure::Write)?
        .write_all(request)
        .map_err(|_| RepairDependencyFailure::Write)?;
    let output = child
        .wait_with_output()
        .map_err(|_| RepairDependencyFailure::Wait)?;
    let output = RepairAuthorityOutput {
        code: output.status.code(),
        stdout: output.stdout,
        successful: output.status.success(),
    };
    eprintln!("{}", acquirer_exit_diagnostic(&output));
    Ok(output)
}

fn fresh_exchange_facts_with(
    dependencies: &mut impl RepairDependencies,
) -> Result<(String, u64), ProbeRepairRunError> {
    let mut nonce = [0_u8; 16];
    dependencies
        .fill_nonce(&mut nonce)
        .map_err(|_| contract_failure("probe_repair_random_failed"))?;
    let now_ms = dependencies
        .now_ms()
        .map_err(|_| contract_failure("probe_repair_clock_invalid"))?;
    Ok((
        nonce.iter().map(|byte| format!("{byte:02x}")).collect(),
        now_ms,
    ))
}

fn exchange_authority_with(
    dependencies: &mut impl RepairDependencies,
    request: &[u8],
    invoking_uid: u32,
    invoking_gid: u32,
) -> Result<Vec<u8>, ProbeRepairRunError> {
    let output = dependencies
        .exchange_authority(request, invoking_uid, invoking_gid)
        .map_err(|_| contract_failure("probe_repair_authority_acquire_failed"))?;
    validate_acquirer_output(output)
}

fn exchange_installed_bundle_authority_with(
    dependencies: &mut impl RepairDependencies,
    request: &[u8],
    invoking_uid: u32,
    invoking_gid: u32,
) -> Result<Vec<u8>, ProbeRepairRunError> {
    let output = dependencies
        .exchange_installed_bundle_authority(request, invoking_uid, invoking_gid)
        .map_err(|_| contract_failure("probe_repair_authority_acquire_failed"))?;
    validate_acquirer_output(output)
}

fn validate_acquirer_output(output: RepairAuthorityOutput) -> Result<Vec<u8>, ProbeRepairRunError> {
    if let Some(error) = acquirer_exit_failure(output.code) {
        return Err(error);
    }
    if !output.successful || output.stdout.is_empty() || output.stdout.len() > 8 * 1024 {
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
                return Err(pre_exec_failure(
                    b"enoki.lifecycle.diagnostic role=companion phase=acquirer_pre_exec \
outcome=error syscall=setgroups errno=",
                ));
            }
            if libc::setgid(gid) != 0 {
                return Err(pre_exec_failure(
                    b"enoki.lifecycle.diagnostic role=companion phase=acquirer_pre_exec \
outcome=error syscall=setgid errno=",
                ));
            }
            if libc::setuid(uid) != 0 {
                return Err(pre_exec_failure(
                    b"enoki.lifecycle.diagnostic role=companion phase=acquirer_pre_exec \
outcome=error syscall=setuid errno=",
                ));
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(pre_exec_failure(
                    b"enoki.lifecycle.diagnostic role=companion phase=acquirer_pre_exec \
outcome=error syscall=prctl_no_new_privs errno=",
                ));
            }
            Ok(())
        });
    }
}

fn pre_exec_failure(diagnostic: &[u8]) -> std::io::Error {
    let error = std::io::Error::last_os_error();
    let errno = error.raw_os_error().unwrap_or(0).unsigned_abs();
    let mut digits = [0_u8; 10];
    let mut start = digits.len();
    let mut remaining = errno;
    loop {
        start -= 1;
        digits[start] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    let newline = b"\n";
    let vectors = [
        libc::iovec {
            iov_base: diagnostic.as_ptr().cast_mut().cast(),
            iov_len: diagnostic.len(),
        },
        libc::iovec {
            iov_base: digits[start..].as_ptr().cast_mut().cast(),
            iov_len: digits.len() - start,
        },
        libc::iovec {
            iov_base: newline.as_ptr().cast_mut().cast(),
            iov_len: newline.len(),
        },
    ];
    // SAFETY：fork 后只以 async-signal-safe writev 写入固定前缀、原始 errno 数字与换行。
    unsafe {
        libc::writev(libc::STDERR_FILENO, vectors.as_ptr(), vectors.len() as i32);
    }
    error
}

fn repair_dependency_diagnostic(failure: RepairDependencyFailure) -> Option<String> {
    let RepairDependencyFailure::Spawn(Some(errno)) = failure else {
        return None;
    };
    Some(format!(
        "enoki.lifecycle.diagnostic role=companion phase=acquirer_spawn \
outcome=error errno={errno}"
    ))
}

fn acquirer_exit_diagnostic(output: &RepairAuthorityOutput) -> String {
    let class = match (output.code, output.successful) {
        (Some(0), true) => "succeeded",
        (Some(3), false) => "manual_reinstall_required",
        (Some(_), false) => "unresolved_failure",
        (None, false) => "terminated_without_exit_code",
        _ => "incoherent_status",
    };
    format!(
        "enoki.lifecycle.diagnostic role=companion phase=acquirer_exit \
outcome=observed class={class}"
    )
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

    struct DeterministicRepairDependencies {
        failure: Option<RepairDependencyFailure>,
        now_ms: u64,
        nonce: [u8; 16],
        output: RepairAuthorityOutput,
    }

    impl DeterministicRepairDependencies {
        fn successful(stdout: Vec<u8>) -> Self {
            Self {
                failure: None,
                now_ms: 1_234,
                nonce: [0xab; 16],
                output: RepairAuthorityOutput {
                    code: Some(0),
                    stdout,
                    successful: true,
                },
            }
        }

        fn failing(failure: RepairDependencyFailure) -> Self {
            Self {
                failure: Some(failure),
                ..Self::successful(b"{}".to_vec())
            }
        }
    }

    impl RepairDependencies for DeterministicRepairDependencies {
        fn fill_nonce(&mut self, nonce: &mut [u8]) -> Result<(), RepairDependencyFailure> {
            if self.failure == Some(RepairDependencyFailure::Random) {
                return Err(RepairDependencyFailure::Random);
            }
            nonce.copy_from_slice(&self.nonce);
            Ok(())
        }

        fn now_ms(&mut self) -> Result<u64, RepairDependencyFailure> {
            if self.failure == Some(RepairDependencyFailure::Clock) {
                return Err(RepairDependencyFailure::Clock);
            }
            Ok(self.now_ms)
        }

        fn exchange_authority(
            &mut self,
            _request: &[u8],
            _invoking_uid: u32,
            _invoking_gid: u32,
        ) -> Result<RepairAuthorityOutput, RepairDependencyFailure> {
            if let Some(
                failure @ (RepairDependencyFailure::Spawn(_)
                | RepairDependencyFailure::Write
                | RepairDependencyFailure::Wait),
            ) = self.failure
            {
                return Err(failure);
            }
            Ok(RepairAuthorityOutput {
                code: self.output.code,
                stdout: self.output.stdout.clone(),
                successful: self.output.successful,
            })
        }

        fn exchange_installed_bundle_authority(
            &mut self,
            request: &[u8],
            invoking_uid: u32,
            invoking_gid: u32,
        ) -> Result<RepairAuthorityOutput, RepairDependencyFailure> {
            self.exchange_authority(request, invoking_uid, invoking_gid)
        }
    }

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

    #[test]
    fn deterministic_dependency_maps_random_failure() {
        let mut dependencies =
            DeterministicRepairDependencies::failing(RepairDependencyFailure::Random);

        let error = fresh_exchange_facts_with(&mut dependencies).unwrap_err();

        assert_eq!(error.code(), "probe_repair_random_failed");
    }

    #[test]
    fn deterministic_dependency_maps_clock_failure() {
        let mut dependencies =
            DeterministicRepairDependencies::failing(RepairDependencyFailure::Clock);

        let error = fresh_exchange_facts_with(&mut dependencies).unwrap_err();

        assert_eq!(error.code(), "probe_repair_clock_invalid");
    }

    #[test]
    fn deterministic_dependency_supplies_bounded_exchange_facts() {
        let mut dependencies = DeterministicRepairDependencies::successful(b"{}".to_vec());

        let facts = fresh_exchange_facts_with(&mut dependencies).unwrap();

        assert_eq!(
            facts,
            ("abababababababababababababababab".to_owned(), 1_234)
        );
    }

    #[test]
    fn deterministic_dependency_maps_spawn_write_and_wait_failures() {
        for failure in [
            RepairDependencyFailure::Spawn(Some(libc::EPERM)),
            RepairDependencyFailure::Write,
            RepairDependencyFailure::Wait,
        ] {
            let mut dependencies = DeterministicRepairDependencies::failing(failure);

            let error =
                exchange_authority_with(&mut dependencies, b"request", 1000, 1000).unwrap_err();

            assert_eq!(error.code(), "probe_repair_authority_acquire_failed");
        }
    }

    #[test]
    fn spawn_dependency_diagnostic_preserves_errno_without_sensitive_payload() {
        let diagnostic =
            repair_dependency_diagnostic(RepairDependencyFailure::Spawn(Some(libc::EPERM)));

        assert_eq!(
            diagnostic.as_deref(),
            Some(
                "enoki.lifecycle.diagnostic role=companion phase=acquirer_spawn \
outcome=error errno=1"
            )
        );
        assert!(!diagnostic.unwrap().contains("request"));
    }

    #[test]
    fn acquirer_exit_diagnostic_uses_only_closed_exit_classes() {
        let cases = [
            (Some(0), true, "succeeded"),
            (Some(3), false, "manual_reinstall_required"),
            (Some(1), false, "unresolved_failure"),
            (None, false, "terminated_without_exit_code"),
        ];

        for (code, successful, expected_class) in cases {
            let diagnostic = acquirer_exit_diagnostic(&RepairAuthorityOutput {
                code,
                stdout: b"must-not-appear".to_vec(),
                successful,
            });

            assert_eq!(
                diagnostic,
                format!(
                    "enoki.lifecycle.diagnostic role=companion phase=acquirer_exit \
outcome=observed class={expected_class}"
                )
            );
            assert!(!diagnostic.contains("must-not-appear"));
        }
    }

    #[test]
    fn deterministic_dependency_maps_exit_and_bounded_output_failures() {
        let cases = [
            RepairAuthorityOutput {
                code: Some(1),
                stdout: b"failure".to_vec(),
                successful: false,
            },
            RepairAuthorityOutput {
                code: None,
                stdout: b"failure".to_vec(),
                successful: false,
            },
            RepairAuthorityOutput {
                code: Some(0),
                stdout: Vec::new(),
                successful: true,
            },
            RepairAuthorityOutput {
                code: Some(0),
                stdout: vec![b'x'; 8 * 1024 + 1],
                successful: true,
            },
        ];
        for output in cases {
            let mut dependencies = DeterministicRepairDependencies {
                output,
                ..DeterministicRepairDependencies::successful(b"{}".to_vec())
            };

            let error =
                exchange_authority_with(&mut dependencies, b"request", 1000, 1000).unwrap_err();

            assert_eq!(error.code(), "probe_repair_authority_acquire_failed");
        }
    }

    #[test]
    fn deterministic_dependency_keeps_manual_reinstall_exit_distinct() {
        let mut dependencies = DeterministicRepairDependencies {
            output: RepairAuthorityOutput {
                code: Some(3),
                stdout: Vec::new(),
                successful: false,
            },
            ..DeterministicRepairDependencies::successful(b"{}".to_vec())
        };

        let error = exchange_authority_with(&mut dependencies, b"request", 1000, 1000).unwrap_err();

        assert_eq!(error.code(), "probe_manual_reinstall_required");
    }

    #[test]
    fn malformed_authority_response_has_a_stable_failure_mapping() {
        let error = decode_authority_response::<RepairAuthorizationResponse>(
            br#"{"authority":{},"signature":3}"#,
        )
        .unwrap_err();

        assert_eq!(error.code(), "probe_repair_authority_invalid");
    }
}

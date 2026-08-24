//! Unprivileged, bounded Probe Asset acquisition.
//!
//! This module owns the hostile HTTP and staging boundary.  Its only success
//! value is an already-open, unlinked verified archive plus the deterministic
//! handoff metadata; elevated activation never receives a staging pathname.
//!
//! This module is deliberately crate-private until the component-only handoff
//! protocol replaces the legacy archive handoff.  Keeping its policy-bearing
//! constructor internal prevents a caller from selecting trust values.
#![allow(dead_code)]

use std::{
    ffi::CString,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Seek, Write},
    os::fd::{FromRawFd, OwnedFd},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    time::{Duration, Instant},
};

use url::Url;

use sha2::{Digest, Sha256};

use crate::{
    generation::{DelegationGenerationLease, acquire_delegation_generation},
    handoff::{Enrollment, Handoff},
    trust::{BootstrapRole, embedded_production_trust_for},
    verifier::{
        MAX_COMPONENT_BYTES, VerificationPolicy, VerifiedBundle, read_bundle_manifest,
        verify_metadata, verify_outer_metadata,
    },
};

const MAX_REPAIR_EXCHANGE_BYTES: u64 = 8 * 1024;

/// Exchanges a fresh root-signed Repair Evidence bearer for one short-lived
/// Repair Authority. The unprivileged acquirer never receives installation
/// keys or the long-lived Probe identity credential.
pub fn acquire_probe_repair_authority_once(
    request_body: &[u8],
) -> Result<Vec<u8>, AcquisitionFailure> {
    if unsafe { libc::geteuid() } == 0 || request_body.is_empty() || request_body.len() > 8 * 1024 {
        return Err(AcquisitionFailure::RootRefused);
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Envelope<T> {
        evidence: T,
        evidence_signature: String,
    }
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum ClosedRepairEvidence {
        FailedUpgrade(Envelope<crate::lifecycle::RepairEvidenceV1>),
        InstalledBundleFailure(Envelope<crate::lifecycle::InstalledBundleFailureEvidenceV1>),
    }
    let envelope: ClosedRepairEvidence =
        serde_json::from_slice(request_body).map_err(|_| AcquisitionFailure::Permanent)?;
    let (url, installed_evidence) = match envelope {
        ClosedRepairEvidence::FailedUpgrade(envelope) => {
            if envelope.evidence_signature.len() != 64
                || !valid_stage_identifier(&envelope.evidence.failed_operation_id)
            {
                return Err(AcquisitionFailure::Permanent);
            }
            let origin = exact_origin(&envelope.evidence.hub_origin)
                .ok_or(AcquisitionFailure::InvalidOrigin)?;
            let url = format!(
                "{origin}/api/probe/operations/{}/repair-authorize",
                envelope.evidence.failed_operation_id
            );
            (url, None)
        }
        ClosedRepairEvidence::InstalledBundleFailure(envelope) => {
            if envelope.evidence_signature.len() != 64
                || envelope.evidence.kind != "installed_bundle_failure"
                || !valid_stage_identifier(&envelope.evidence.generation)
            {
                return Err(AcquisitionFailure::Permanent);
            }
            let origin = exact_origin(&envelope.evidence.hub_origin)
                .ok_or(AcquisitionFailure::InvalidOrigin)?;
            let url = format!(
                "{origin}/api/probe/runtime-failures/{}/repair-authorize",
                envelope.evidence.generation
            );
            (url, Some(envelope.evidence))
        }
    };
    let response = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(10))
        .timeout_write(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build()
        .post(&url)
        .set("content-type", "application/json")
        .send_bytes(request_body);
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            let retry_after_ms = response
                .header("retry-after")
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|seconds| *seconds <= 300)
                .map(|seconds| seconds.saturating_mul(1_000));
            let mut body = Vec::new();
            response
                .into_reader()
                .take(MAX_REPAIR_EXCHANGE_BYTES + 1)
                .read_to_end(&mut body)
                .map_err(|_| AcquisitionFailure::Temporary {
                    retry_after_ms: None,
                })?;
            return Err(classify_repair_authorization_error(
                status,
                &body,
                retry_after_ms,
            ));
        }
        Err(ureq::Error::Transport(_)) => {
            return Err(AcquisitionFailure::Temporary {
                retry_after_ms: None,
            });
        }
    };
    let mut output = Vec::new();
    response
        .into_reader()
        .take(MAX_REPAIR_EXCHANGE_BYTES + 1)
        .read_to_end(&mut output)
        .map_err(|_| AcquisitionFailure::Temporary {
            retry_after_ms: None,
        })?;
    if output.is_empty() || output.len() as u64 > MAX_REPAIR_EXCHANGE_BYTES {
        return Err(AcquisitionFailure::Permanent);
    }
    let Some(evidence) = installed_evidence else {
        return Ok(output);
    };
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct InstalledExchange {
        authority: crate::lifecycle::InstalledBundleRepairAuthorityV1,
        signature: String,
        target_asset_set_digest: String,
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct InstalledAcquisition {
        authority: crate::lifecycle::InstalledBundleRepairAuthorityV1,
        signature: String,
        stage_receipt: VerifiedUpgradeStageReceipt,
    }
    let exchange: InstalledExchange =
        serde_json::from_slice(&output).map_err(|_| AcquisitionFailure::Permanent)?;
    if !exchange.authority.matches_evidence(&evidence)
        || exchange.authority.target_asset_set_digest != exchange.target_asset_set_digest
        || exchange.signature.len() != 64
        || !valid_stage_identifier(&exchange.authority.repair_operation_id)
    {
        return Err(AcquisitionFailure::Permanent);
    }
    let stage_receipt = acquire_probe_upgrade_once(ProbeUpgradeAcquisition {
        hub_origin: evidence.hub_origin,
        operation_id: exchange.authority.repair_operation_id.clone(),
        target_asset_set_digest: exchange.target_asset_set_digest,
        target_version: evidence.bundle_version,
    })?;
    serde_json::to_vec(&InstalledAcquisition {
        authority: exchange.authority,
        signature: exchange.signature,
        stage_receipt,
    })
    .map_err(|_| AcquisitionFailure::Local)
}

fn classify_repair_authorization_error(
    status: u16,
    body: &[u8],
    retry_after_ms: Option<u64>,
) -> AcquisitionFailure {
    if body.is_empty() || body.len() as u64 > MAX_REPAIR_EXCHANGE_BYTES {
        return AcquisitionFailure::Permanent;
    }
    if status == 429 {
        return AcquisitionFailure::Temporary { retry_after_ms };
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    enum RepairDisposition {
        ManualReinstallRequired,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ErrorEnvelope {
        disposition: RepairDisposition,
    }
    match serde_json::from_slice::<ErrorEnvelope>(body) {
        Ok(ErrorEnvelope {
            disposition: RepairDisposition::ManualReinstallRequired,
        }) if status == 409 => AcquisitionFailure::ManualReinstallRequired,
        _ => AcquisitionFailure::Permanent,
    }
}

pub const PROBE_UPGRADE_STAGE_ROOT: &str = "/var/lib/enoki-probe/upgrade-stages";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeUpgradeAcquisition {
    pub hub_origin: String,
    pub operation_id: String,
    pub target_asset_set_digest: String,
    pub target_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedUpgradeStageReceipt {
    pub operation_id: String,
    pub target_asset_set_digest: String,
    pub target_manifest_sha256: String,
    pub target_version: String,
    pub verified_stage_sha256: String,
}

pub struct VerifiedProbeUpgradeStage {
    pub probe: File,
    pub observation_runtime: File,
    pub system_state_provider: File,
    pub disk_health_provider: File,
    pub lifecycle_companion: File,
    pub bootstrap_acquirer: File,
    pub bootstrap_activator: File,
    pub bundle: VerifiedBundle,
    _generation: DelegationGenerationLease,
}

/// root只从构建期固定stage目录打开同一operation的文件，并独立复验签名、
/// generation floor与固定5+2角色收据。
pub fn open_verified_probe_upgrade_stage(
    receipt: &VerifiedUpgradeStageReceipt,
    expected_owner_uid: u32,
) -> Result<VerifiedProbeUpgradeStage, AcquisitionFailure> {
    open_verified_probe_upgrade_stage_at(
        Path::new(PROBE_UPGRADE_STAGE_ROOT),
        receipt,
        expected_owner_uid,
    )
}

fn open_verified_probe_upgrade_stage_at(
    root: &Path,
    receipt: &VerifiedUpgradeStageReceipt,
    expected_owner_uid: u32,
) -> Result<VerifiedProbeUpgradeStage, AcquisitionFailure> {
    if unsafe { libc::geteuid() } != 0 || !valid_stage_identifier(&receipt.operation_id) {
        return Err(AcquisitionFailure::RootRefused);
    }
    let directory = root.join(&receipt.operation_id);
    validate_stage_directory(root, expected_owner_uid)?;
    validate_stage_directory(&directory, expected_owner_uid)?;
    let delegation = read_stage_metadata(&directory, "trust-delegation.json", expected_owner_uid)?;
    let delegation_signature =
        read_stage_metadata(&directory, "trust-delegation.json.sig", expected_owner_uid)?;
    let manifest = read_stage_metadata(&directory, "manifest.json", expected_owner_uid)?;
    let manifest_signature =
        read_stage_metadata(&directory, "manifest.json.sig", expected_owner_uid)?;
    let signing_key = read_stage_metadata(&directory, "signing-key.pem", expected_owner_uid)?;
    let bundle_manifest =
        read_stage_metadata(&directory, "bundle-manifest.json", expected_owner_uid)?;
    let handoff = Handoff {
        delegation,
        delegation_signature,
        manifest,
        manifest_signature,
        signing_key,
        bundle_manifest,
    };
    let trust = embedded_production_trust_for(BootstrapRole::Activator)
        .ok_or(AcquisitionFailure::BuildTrustUnavailable)?;
    let metadata = verify_metadata(
        &handoff,
        &VerificationPolicy {
            distribution: trust.distribution,
            expected_target: trust.target,
            highest_accepted_delegation_generation: 0,
            external_root_fingerprint: trust.root_fingerprint.to_owned(),
            external_root_pem: Some(trust.root_pem.as_bytes()),
        },
    )
    .map_err(|_| AcquisitionFailure::Permanent)?;
    let bundle = metadata.bundle().clone();
    if bundle.version != receipt.target_version
        || receipt.target_asset_set_digest.strip_prefix("sha256:")
            != Some(bundle.asset_set_manifest_sha256.as_str())
        || bundle.manifest_sha256 != receipt.target_manifest_sha256
    {
        return Err(AcquisitionFailure::Permanent);
    }
    let mut files = Vec::new();
    let mut stage_digest = Sha256::new();
    for (name, bytes) in [
        ("trust-delegation.json", handoff.delegation.as_slice()),
        (
            "trust-delegation.json.sig",
            handoff.delegation_signature.as_slice(),
        ),
        ("manifest.json", handoff.manifest.as_slice()),
        ("manifest.json.sig", handoff.manifest_signature.as_slice()),
        ("signing-key.pem", handoff.signing_key.as_slice()),
        ("bundle-manifest.json", handoff.bundle_manifest.as_slice()),
    ] {
        update_stage_digest(&mut stage_digest, name, bytes);
    }
    for name in [
        "enoki-probe",
        "enoki-observation-runtime",
        "enoki-cpu-resource-provider",
        "enoki-disk-health-resource-provider",
        "enoki-probe-lifecycle-companion",
        "enoki-probe-bootstrap-acquire",
        "enoki-probe-bootstrap-activate",
    ] {
        let mut file = open_stage_file(&directory, name, expected_owner_uid, MAX_COMPONENT_BYTES)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| AcquisitionFailure::Local)?;
        update_stage_digest(&mut stage_digest, name, &bytes);
        file.rewind().map_err(|_| AcquisitionFailure::Local)?;
        files.push(file);
    }
    if format!("{:x}", stage_digest.finalize()) != receipt.verified_stage_sha256 {
        return Err(AcquisitionFailure::Permanent);
    }
    let mut probe = files.remove(0);
    let mut observation_runtime = files.remove(0);
    let mut system_state_provider = files.remove(0);
    let mut disk_health_provider = files.remove(0);
    let mut lifecycle_companion = files.remove(0);
    let mut bootstrap_acquirer = files.remove(0);
    let mut bootstrap_activator = files.remove(0);
    crate::verifier::verify_upgrade_role_receipts(
        &mut probe,
        &mut observation_runtime,
        &mut system_state_provider,
        &mut disk_health_provider,
        &mut lifecycle_companion,
        &bundle,
    )
    .map_err(|_| AcquisitionFailure::Permanent)?;
    crate::verifier::verify_acquirer_receipt(&mut bootstrap_acquirer, &bundle)
        .map_err(|_| AcquisitionFailure::Permanent)?;
    crate::verifier::verify_activator_receipt(&mut bootstrap_activator, &bundle)
        .map_err(|_| AcquisitionFailure::Permanent)?;
    let generation = acquire_delegation_generation(bundle.delegation_generation())
        .map_err(|_| AcquisitionFailure::Permanent)?;
    Ok(VerifiedProbeUpgradeStage {
        probe,
        observation_runtime,
        system_state_provider,
        disk_health_provider,
        lifecycle_companion,
        bootstrap_acquirer,
        bootstrap_activator,
        bundle,
        _generation: generation,
    })
}

fn validate_stage_directory(path: &Path, expected_uid: u32) -> Result<(), AcquisitionFailure> {
    let metadata = fs::symlink_metadata(path).map_err(|_| AcquisitionFailure::Local)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(AcquisitionFailure::Permanent);
    }
    Ok(())
}

fn read_stage_metadata(
    directory: &Path,
    name: &str,
    expected_uid: u32,
) -> Result<Vec<u8>, AcquisitionFailure> {
    let mut file = open_stage_file(directory, name, expected_uid, MAX_METADATA_BYTES as u64)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| AcquisitionFailure::Local)?;
    Ok(bytes)
}

fn open_stage_file(
    directory: &Path,
    name: &str,
    expected_uid: u32,
    maximum: u64,
) -> Result<File, AcquisitionFailure> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(name))
        .map_err(|_| AcquisitionFailure::Local)?;
    let metadata = file.metadata().map_err(|_| AcquisitionFailure::Local)?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(AcquisitionFailure::Permanent);
    }
    Ok(file)
}

fn update_stage_digest(digest: &mut Sha256, name: &str, bytes: &[u8]) {
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

/// The only network boundary used by acquisition.  Production uses a client
/// with redirects disabled; tests can provide a deterministic peer.
pub(crate) trait Transport {
    /// `timeout` is the remaining total acquisition budget, not a fresh
    /// per-request allowance.
    fn get(
        &mut self,
        request: HttpRequest,
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError>;
}

/// The production HTTP boundary.  Redirect handling is disabled rather than
/// delegated to URL-library defaults, so a metadata or archive request can
/// never silently cross the configured Hub origin.
pub(crate) struct UreqTransport;

impl Default for UreqTransport {
    fn default() -> Self {
        Self
    }
}

impl Transport for UreqTransport {
    fn get(
        &mut self,
        request: HttpRequest,
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        if timeout.is_zero() {
            return Err(TransportError::Interrupted);
        }
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .timeout_write(timeout)
            .timeout(timeout)
            .build();
        let mut get = agent.get(&request.url);
        for (name, value) in request.headers {
            get = get.set(name, value);
        }
        match get.call() {
            Ok(response) => Ok(ureq_response(response)),
            Err(ureq::Error::Status(_, response)) => Ok(ureq_response(response)),
            Err(_) => Err(TransportError::Unavailable),
        }
    }
}

fn ureq_response(response: ureq::Response) -> HttpResponse {
    let headers = response
        .headers_names()
        .into_iter()
        .filter_map(|name| response.header(&name).map(|value| (name, value.to_owned())))
        .collect();
    HttpResponse {
        status: response.status(),
        headers,
        body: Box::new(response.into_reader()),
    }
}

pub(crate) struct HttpRequest {
    pub url: String,
    pub headers: Vec<(&'static str, &'static str)>,
}

pub(crate) struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn Read>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum TransportError {
    Interrupted,
    Unavailable,
}

/// Boundary used only to make the root refusal testable.  Production passes
/// the process effective uid directly rather than accepting a caller value.
pub(crate) trait PrivilegeProbe {
    fn is_root(&self) -> bool;
}

pub(crate) struct EffectivePrivilege;

impl PrivilegeProbe for EffectivePrivilege {
    fn is_root(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }
}

pub(crate) trait Clock {
    fn now_ms(&self) -> u64;
}

pub(crate) trait Random {
    /// Returns a uniformly chosen integer in `0..upper_exclusive`.
    fn below(&mut self, upper_exclusive: u64) -> u64;
}

pub(crate) trait Sleeper {
    fn sleep_ms(&mut self, duration_ms: u64);
}

pub(crate) struct MonotonicClock(Instant);

impl Default for MonotonicClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
    }
}

pub(crate) struct OsRandom;

impl Random for OsRandom {
    fn below(&mut self, upper_exclusive: u64) -> u64 {
        if upper_exclusive <= 1 {
            return 0;
        }
        let mut value = 0_u64;
        let received = unsafe {
            libc::getrandom(
                std::ptr::addr_of_mut!(value).cast(),
                std::mem::size_of::<u64>(),
                0,
            )
        };
        if received != std::mem::size_of::<u64>() as isize {
            // Failing closed on jitter would turn a temporary delivery fault
            // into an endless tight retry.  This fallback only affects timing,
            // never authentication or integrity, and remains bounded.
            value = Instant::now().elapsed().as_nanos() as u64 ^ process::id() as u64;
        }
        value % upper_exclusive
    }
}

pub(crate) struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep_ms(&mut self, duration_ms: u64) {
        std::thread::sleep(Duration::from_millis(duration_ms));
    }
}

pub(crate) struct AcquisitionDependencies<'a, T, P, C, R, S> {
    transport: &'a mut T,
    privilege: P,
    clock: C,
    random: R,
    sleeper: S,
}

impl<'a, T, P, C, R, S> AcquisitionDependencies<'a, T, P, C, R, S> {
    #[cfg(test)]
    fn for_test(transport: &'a mut T, privilege: P, clock: C, random: R, sleeper: S) -> Self {
        Self {
            transport,
            privilege,
            clock,
            random,
            sleeper,
        }
    }
}

/// Crate-private specifically so callers cannot substitute distribution trust
/// policy.  The future CLI constructor will use build-fixed distribution and
/// root values, while root activation supplies its own persisted generation.
pub(crate) struct AcquisitionRequest<'a> {
    pub hub_origin: String,
    pub policy: VerificationPolicy<'a>,
    pub staging_dir: PathBuf,
    pub deadline_ms: u64,
}

pub(crate) struct ProductionAcquisition<'a> {
    pub hub_origin: String,
    pub staging_dir: PathBuf,
    pub policy: VerificationPolicy<'a>,
    pub deadline_ms: u64,
}

/// Production acquire entrypoint. The only caller configuration is the
/// enrollment capability; the distribution trust and target are compiled in.
pub fn acquire_and_activate_from_environment(
    input: &mut impl Read,
) -> Result<(), AcquisitionFailure> {
    let hub_origin =
        std::env::var("ENOKI_HUB_URL").map_err(|_| AcquisitionFailure::InvalidOrigin)?;
    let token = read_enrollment_token(input)?;
    let enrollment =
        Enrollment::new(&hub_origin, &token).map_err(|_| AcquisitionFailure::InvalidEnrollment)?;
    let trust = embedded_production_trust_for(BootstrapRole::Acquirer)
        .ok_or(AcquisitionFailure::BuildTrustUnavailable)?;
    let policy = VerificationPolicy {
        distribution: trust.distribution,
        expected_target: trust.target,
        highest_accepted_delegation_generation: 0,
        external_root_fingerprint: trust.root_fingerprint.to_owned(),
        external_root_pem: Some(trust.root_pem.as_bytes()),
    };
    let asset_dir = std::env::var_os("ENOKI_PROBE_LOCAL_ASSET_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(AcquisitionFailure::Local)?;
    let archive_path = std::env::var_os("ENOKI_PROBE_LOCAL_BUNDLE_ARCHIVE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(AcquisitionFailure::Local)?;
    let mut acquired = acquire_local(&asset_dir, &archive_path, &policy)?;
    acquired.launch_authenticated_activator(&enrollment)
}

fn read_enrollment_token(input: &mut impl Read) -> Result<String, AcquisitionFailure> {
    let mut bytes = Vec::new();
    input
        .take(256)
        .read_to_end(&mut bytes)
        .map_err(|_| AcquisitionFailure::InvalidEnrollment)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(AcquisitionFailure::InvalidEnrollment);
    }
    String::from_utf8(bytes).map_err(|_| AcquisitionFailure::InvalidEnrollment)
}

/// Production entry point. It consults the process effective uid directly;
/// neither command arguments nor a remote response can ask a root process to
/// acquire an archive. The policy-bearing input remains crate-private until a
/// build-fixed bootstrap configuration owns those constants.
pub(crate) fn acquire_production(
    request: ProductionAcquisition<'_>,
) -> Result<VerifiedAcquisition, AcquisitionFailure> {
    let mut transport = UreqTransport;
    let mut dependencies = AcquisitionDependencies {
        transport: &mut transport,
        privilege: EffectivePrivilege,
        clock: MonotonicClock::default(),
        random: OsRandom,
        sleeper: ThreadSleeper,
    };
    acquire(
        AcquisitionRequest {
            hub_origin: request.hub_origin,
            policy: request.policy,
            staging_dir: request.staging_dir,
            deadline_ms: request.deadline_ms,
        },
        &mut dependencies,
    )
}

/// 为一次显式 Probe Upgrade 完成单次下载、完整验证与固定stage发布。
/// 此入口不包含自动重试；失败后的下一次尝试只能来自新的Hub操作。
pub fn acquire_probe_upgrade_once(
    request: ProbeUpgradeAcquisition,
) -> Result<VerifiedUpgradeStageReceipt, AcquisitionFailure> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(AcquisitionFailure::RootRefused);
    }
    let trust = embedded_production_trust_for(BootstrapRole::Acquirer)
        .ok_or(AcquisitionFailure::BuildTrustUnavailable)?;
    let Some(origin) = exact_origin(&request.hub_origin) else {
        return Err(AcquisitionFailure::InvalidOrigin);
    };
    let stage_root = PathBuf::from(PROBE_UPGRADE_STAGE_ROOT);
    let mut transport = UreqTransport;
    let mut dependencies = AcquisitionDependencies {
        transport: &mut transport,
        privilege: EffectivePrivilege,
        clock: MonotonicClock::default(),
        random: OsRandom,
        sleeper: ThreadSleeper,
    };
    let acquisition_request = AcquisitionRequest {
        hub_origin: request.hub_origin.clone(),
        policy: VerificationPolicy {
            distribution: trust.distribution,
            expected_target: trust.target,
            highest_accepted_delegation_generation: 0,
            external_root_fingerprint: trust.root_fingerprint.to_owned(),
            external_root_pem: Some(trust.root_pem.as_bytes()),
        },
        staging_dir: stage_root.clone(),
        deadline_ms: 60_000,
    };
    let deadline_at = dependencies.clock.now_ms().saturating_add(60_000);
    let mut acquired = acquire_once(
        &acquisition_request,
        &mut dependencies,
        &origin,
        deadline_at,
    )?;
    if acquired.bundle.version != request.target_version
        || request.target_asset_set_digest.strip_prefix("sha256:")
            != Some(acquired.bundle.asset_set_manifest_sha256.as_str())
    {
        return Err(AcquisitionFailure::Permanent);
    }
    let verified_stage_sha256 =
        acquired.persist_upgrade_stage_at(&stage_root, &request.operation_id)?;
    Ok(VerifiedUpgradeStageReceipt {
        operation_id: request.operation_id,
        target_asset_set_digest: request.target_asset_set_digest,
        target_manifest_sha256: acquired.bundle.manifest_sha256,
        target_version: request.target_version,
        verified_stage_sha256,
    })
}

pub(crate) struct VerifiedAcquisition {
    pub handoff: Handoff,
    pub bundle: VerifiedBundle,
    component: File,
    runtime: File,
    cpu_provider: File,
    disk_health_provider: File,
    lifecycle_companion: File,
    bootstrap_acquirer: File,
    activator: File,
}

impl VerifiedAcquisition {
    /// The same unlinked descriptor that was downloaded and verified.  This is
    /// intentionally not a staging path.
    pub fn component(&mut self) -> Result<&mut File, AcquisitionFailure> {
        self.component
            .rewind()
            .map_err(|_| AcquisitionFailure::Local)?;
        Ok(&mut self.component)
    }

    pub fn write_handoff_with_enrollment(
        &mut self,
        enrollment: &Enrollment,
        output: &mut impl Write,
    ) -> Result<(), AcquisitionFailure> {
        let component_len = self.bundle.component_len;
        let (_, runtime_len) = self
            .bundle
            .component_receipt("observation-runtime")
            .ok_or(AcquisitionFailure::Permanent)?;
        let (_, cpu_provider_len) = self
            .bundle
            .component_receipt("system-state-provider")
            .ok_or(AcquisitionFailure::Permanent)?;
        let (_, disk_health_provider_len) = self
            .bundle
            .component_receipt("disk-health-provider")
            .ok_or(AcquisitionFailure::Permanent)?;
        let (_, lifecycle_companion_len) = self
            .bundle
            .component_receipt("lifecycle-companion")
            .ok_or(AcquisitionFailure::Permanent)?;
        let (acquirer_sha256, acquirer_len) = self
            .bundle
            .acquirer_receipt()
            .ok_or(AcquisitionFailure::Permanent)?;
        let mut acquirer = File::open("/proc/self/exe").map_err(|_| AcquisitionFailure::Local)?;
        verify_open_file(&mut acquirer, acquirer_sha256, acquirer_len)?;
        let handoff = self.handoff.clone();
        self.component
            .rewind()
            .map_err(|_| AcquisitionFailure::Local)?;
        self.runtime
            .rewind()
            .map_err(|_| AcquisitionFailure::Local)?;
        self.cpu_provider
            .rewind()
            .map_err(|_| AcquisitionFailure::Local)?;
        self.disk_health_provider
            .rewind()
            .map_err(|_| AcquisitionFailure::Local)?;
        self.lifecycle_companion
            .rewind()
            .map_err(|_| AcquisitionFailure::Local)?;
        handoff
            .write_from(
                enrollment,
                &mut self.component,
                component_len,
                &mut self.runtime,
                runtime_len,
                &mut self.cpu_provider,
                cpu_provider_len,
                &mut self.disk_health_provider,
                disk_health_provider_len,
                &mut self.lifecycle_companion,
                lifecycle_companion_len,
                &mut acquirer,
                acquirer_len,
                output,
            )
            .map_err(|_| AcquisitionFailure::Local)
    }

    fn launch_authenticated_activator(
        &mut self,
        enrollment: &Enrollment,
    ) -> Result<(), AcquisitionFailure> {
        let (expected_sha256, expected_size) = self
            .bundle
            .activator_receipt()
            .ok_or(AcquisitionFailure::Permanent)?;
        let activator = sealed_activator_fd(&mut self.activator, expected_sha256, expected_size)?;
        let (mut sender, receiver) = UnixStream::pair().map_err(|_| AcquisitionFailure::Local)?;
        let receiver: OwnedFd = receiver.into();
        let mut child = Command::new("/usr/bin/sudo")
            .args(["--", "/proc/self/fd/0", "--fd-handoff"])
            .env_clear()
            .stdin(Stdio::from(activator))
            .stdout(Stdio::from(receiver))
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| AcquisitionFailure::Local)?;
        let sent = self.write_handoff_with_enrollment(enrollment, &mut sender);
        let _ = sender.shutdown(std::net::Shutdown::Write);
        let status = child.wait().map_err(|_| AcquisitionFailure::Local)?;
        sent?;
        status
            .success()
            .then_some(())
            .ok_or(AcquisitionFailure::Local)
    }

    fn persist_upgrade_stage_at(
        &mut self,
        root: &Path,
        operation_id: &str,
    ) -> Result<String, AcquisitionFailure> {
        if !valid_stage_identifier(operation_id) {
            return Err(AcquisitionFailure::Permanent);
        }
        ensure_private_staging(root)?;
        let pending = root.join(format!(".pending-{operation_id}"));
        let destination = root.join(operation_id);
        let _ = fs::remove_dir_all(&pending);
        DirBuilder::new()
            .mode(0o700)
            .create(&pending)
            .map_err(|_| AcquisitionFailure::Local)?;
        let result = (|| {
            let mut digest = Sha256::new();
            for (name, bytes) in [
                ("trust-delegation.json", self.handoff.delegation.as_slice()),
                (
                    "trust-delegation.json.sig",
                    self.handoff.delegation_signature.as_slice(),
                ),
                ("manifest.json", self.handoff.manifest.as_slice()),
                (
                    "manifest.json.sig",
                    self.handoff.manifest_signature.as_slice(),
                ),
                ("signing-key.pem", self.handoff.signing_key.as_slice()),
                (
                    "bundle-manifest.json",
                    self.handoff.bundle_manifest.as_slice(),
                ),
            ] {
                write_stage_bytes(&pending, name, bytes, &mut digest)?;
            }
            for (name, file) in [
                ("enoki-probe", &mut self.component),
                ("enoki-observation-runtime", &mut self.runtime),
                ("enoki-cpu-resource-provider", &mut self.cpu_provider),
                (
                    "enoki-disk-health-resource-provider",
                    &mut self.disk_health_provider,
                ),
                (
                    "enoki-probe-lifecycle-companion",
                    &mut self.lifecycle_companion,
                ),
                (
                    "enoki-probe-bootstrap-acquire",
                    &mut self.bootstrap_acquirer,
                ),
                ("enoki-probe-bootstrap-activate", &mut self.activator),
            ] {
                file.rewind().map_err(|_| AcquisitionFailure::Local)?;
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)
                    .map_err(|_| AcquisitionFailure::Local)?;
                file.rewind().map_err(|_| AcquisitionFailure::Local)?;
                write_stage_bytes(&pending, name, &bytes, &mut digest)?;
            }
            File::open(&pending)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| AcquisitionFailure::Local)?;
            fs::rename(&pending, &destination).map_err(|_| AcquisitionFailure::Local)?;
            File::open(root)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| AcquisitionFailure::Local)?;
            Ok(format!("{:x}", digest.finalize()))
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&pending);
        }
        result
    }
}

impl VerifiedProbeUpgradeStage {
    pub fn persist_generation_before_activation(&mut self) -> Result<(), AcquisitionFailure> {
        self._generation
            .persist_before_mutation()
            .map_err(|_| AcquisitionFailure::Permanent)
    }
}

pub fn remove_verified_probe_upgrade_stage(
    operation_id: &str,
    expected_owner_uid: u32,
) -> Result<(), AcquisitionFailure> {
    if unsafe { libc::geteuid() } != 0 || !valid_stage_identifier(operation_id) {
        return Err(AcquisitionFailure::RootRefused);
    }
    let root = Path::new(PROBE_UPGRADE_STAGE_ROOT);
    let directory = root.join(operation_id);
    validate_stage_directory(root, expected_owner_uid)?;
    match fs::symlink_metadata(&directory) {
        Ok(_) => {
            validate_stage_directory(&directory, expected_owner_uid)?;
            fs::remove_dir_all(&directory).map_err(|_| AcquisitionFailure::Local)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(AcquisitionFailure::Local),
    }
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AcquisitionFailure::Local)
}

/// admission 失败时由创建者清理本次固定 stage。root 仍只能走独立的
/// 激活后清理入口，避免把此函数变成可跨 uid 删除的权限面。
pub fn discard_unadmitted_probe_upgrade_stage(
    operation_id: &str,
) -> Result<(), AcquisitionFailure> {
    let owner_uid = unsafe { libc::geteuid() };
    if owner_uid == 0 || !valid_stage_identifier(operation_id) {
        return Err(AcquisitionFailure::RootRefused);
    }
    let root = Path::new(PROBE_UPGRADE_STAGE_ROOT);
    let directory = root.join(operation_id);
    validate_stage_directory(root, owner_uid)?;
    validate_stage_directory(&directory, owner_uid)?;
    fs::remove_dir_all(&directory).map_err(|_| AcquisitionFailure::Local)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AcquisitionFailure::Local)
}

fn write_stage_bytes(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    digest: &mut Sha256,
) -> Result<(), AcquisitionFailure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))
        .map_err(|_| AcquisitionFailure::Local)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| AcquisitionFailure::Local)?;
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(())
}

fn valid_stage_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn sealed_activator_fd(
    source: &mut File,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<File, AcquisitionFailure> {
    source.rewind().map_err(|_| AcquisitionFailure::Local)?;
    let name =
        CString::new("enoki-probe-bootstrap-activate").map_err(|_| AcquisitionFailure::Local)?;
    let descriptor =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if descriptor < 0 {
        return Err(AcquisitionFailure::Local);
    }
    let mut sealed = unsafe { File::from_raw_fd(descriptor) };
    let copied = io::copy(source, &mut sealed).map_err(|_| AcquisitionFailure::Local)?;
    if copied != expected_size {
        return Err(AcquisitionFailure::Permanent);
    }
    sealed.sync_all().map_err(|_| AcquisitionFailure::Local)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(descriptor, libc::F_ADD_SEALS, seals) } != 0
        || unsafe { libc::fcntl(descriptor, libc::F_GET_SEALS) } != seals
    {
        return Err(AcquisitionFailure::Local);
    }
    verify_open_file(&mut sealed, expected_sha256, expected_size)?;
    Ok(sealed)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AcquisitionFailure {
    BuildTrustUnavailable,
    InvalidEnrollment,
    RootRefused,
    InvalidOrigin,
    Local,
    ManualReinstallRequired,
    Permanent,
    Temporary { retry_after_ms: Option<u64> },
}

fn acquire_local(
    asset_dir: &Path,
    archive_path: &Path,
    policy: &VerificationPolicy<'_>,
) -> Result<VerifiedAcquisition, AcquisitionFailure> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(AcquisitionFailure::RootRefused);
    }
    ensure_private_staging(asset_dir)?;
    let provisional = Handoff {
        delegation: read_local_metadata(asset_dir, "trust-delegation.json")?,
        delegation_signature: read_local_metadata(asset_dir, "trust-delegation.json.sig")?,
        manifest: read_local_metadata(asset_dir, "manifest.json")?,
        manifest_signature: read_local_metadata(asset_dir, "manifest.json.sig")?,
        signing_key: read_local_metadata(asset_dir, "signing-key.pem")?,
        bundle_manifest: Vec::new(),
    };
    let outer =
        verify_outer_metadata(&provisional, policy).map_err(|_| AcquisitionFailure::Permanent)?;
    if archive_path.file_name().and_then(|name| name.to_str()) != Some(outer.archive_file()) {
        return Err(AcquisitionFailure::Permanent);
    }
    let mut archive = open_local_regular(archive_path, outer.archive_len())?;
    verify_open_file(&mut archive, outer.archive_sha256(), outer.archive_len())?;
    let bundle_manifest =
        read_bundle_manifest(&mut archive).map_err(|_| AcquisitionFailure::Permanent)?;
    let handoff = Handoff {
        bundle_manifest,
        ..provisional
    };
    let metadata = verify_metadata(&handoff, policy).map_err(|_| AcquisitionFailure::Permanent)?;
    let mut component = create_exclusive_staging_file(asset_dir)?;
    let mut runtime = create_exclusive_staging_file(asset_dir)?;
    let mut cpu_provider = create_exclusive_staging_file(asset_dir)?;
    let mut disk_health_provider = create_exclusive_staging_file(asset_dir)?;
    let mut lifecycle_companion = create_exclusive_staging_file(asset_dir)?;
    let mut bootstrap_acquirer = create_exclusive_staging_file(asset_dir)?;
    let mut activator = create_exclusive_staging_file(asset_dir)?;
    let bundle = crate::verifier::verify_archive_and_extract_lifecycle_roles(
        &mut archive,
        &handoff,
        &metadata,
        &mut component,
        &mut runtime,
        &mut cpu_provider,
        &mut disk_health_provider,
        &mut lifecycle_companion,
        &mut bootstrap_acquirer,
        &mut activator,
    )
    .map_err(|_| AcquisitionFailure::Permanent)?;
    component
        .sync_all()
        .map_err(|_| AcquisitionFailure::Local)?;
    runtime.sync_all().map_err(|_| AcquisitionFailure::Local)?;
    cpu_provider
        .sync_all()
        .map_err(|_| AcquisitionFailure::Local)?;
    disk_health_provider
        .sync_all()
        .map_err(|_| AcquisitionFailure::Local)?;
    lifecycle_companion
        .sync_all()
        .map_err(|_| AcquisitionFailure::Local)?;
    bootstrap_acquirer
        .sync_all()
        .map_err(|_| AcquisitionFailure::Local)?;
    activator
        .sync_all()
        .map_err(|_| AcquisitionFailure::Local)?;
    Ok(VerifiedAcquisition {
        handoff,
        bundle,
        component,
        runtime,
        cpu_provider,
        disk_health_provider,
        lifecycle_companion,
        bootstrap_acquirer,
        activator,
    })
}

fn read_local_metadata(directory: &Path, name: &str) -> Result<Vec<u8>, AcquisitionFailure> {
    let path = directory.join(name);
    let mut file = open_local_regular(&path, MAX_METADATA_BYTES as u64)?;
    let size = file
        .metadata()
        .map_err(|_| AcquisitionFailure::Local)?
        .len();
    if size == 0 || size > MAX_METADATA_BYTES as u64 {
        return Err(AcquisitionFailure::Permanent);
    }
    let mut bytes = vec![0; size as usize];
    file.read_exact(&mut bytes)
        .map_err(|_| AcquisitionFailure::Local)?;
    Ok(bytes)
}

fn open_local_regular(path: &Path, maximum: u64) -> Result<File, AcquisitionFailure> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| AcquisitionFailure::Local)?;
    let details = file.metadata().map_err(|_| AcquisitionFailure::Local)?;
    if !details.is_file()
        || details.uid() != unsafe { libc::geteuid() }
        || details.len() == 0
        || details.len() > maximum
    {
        return Err(AcquisitionFailure::Local);
    }
    Ok(file)
}

fn verify_open_file(
    file: &mut File,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<(), AcquisitionFailure> {
    if file
        .metadata()
        .map_err(|_| AcquisitionFailure::Local)?
        .len()
        != expected_size
    {
        return Err(AcquisitionFailure::Permanent);
    }
    file.rewind().map_err(|_| AcquisitionFailure::Local)?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| AcquisitionFailure::Local)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        hash.update(&buffer[..read]);
    }
    if total != expected_size || format!("{:x}", hash.finalize()) != expected_sha256 {
        return Err(AcquisitionFailure::Permanent);
    }
    file.rewind().map_err(|_| AcquisitionFailure::Local)
}

/// Acquires one bundle without allowing a root process to reach transport or
/// staging.
pub(crate) fn acquire<T: Transport, P: PrivilegeProbe, C: Clock, R: Random, S: Sleeper>(
    request: AcquisitionRequest<'_>,
    dependencies: &mut AcquisitionDependencies<'_, T, P, C, R, S>,
) -> Result<VerifiedAcquisition, AcquisitionFailure> {
    if dependencies.privilege.is_root() {
        return Err(AcquisitionFailure::RootRefused);
    }
    let Some(origin) = exact_origin(&request.hub_origin) else {
        return Err(AcquisitionFailure::InvalidOrigin);
    };
    let started_at = dependencies.clock.now_ms();
    let mut attempt = 0_u32;
    loop {
        if attempt > 0
            && dependencies.clock.now_ms().saturating_sub(started_at) >= request.deadline_ms
        {
            return Err(AcquisitionFailure::Temporary {
                retry_after_ms: None,
            });
        }
        match acquire_once(
            &request,
            dependencies,
            &origin,
            started_at.saturating_add(request.deadline_ms),
        ) {
            Ok(acquisition) => return Ok(acquisition),
            Err(AcquisitionFailure::Temporary { retry_after_ms }) => {
                let now = dependencies.clock.now_ms();
                let elapsed = now.saturating_sub(started_at);
                if elapsed >= request.deadline_ms {
                    return Err(AcquisitionFailure::Temporary { retry_after_ms });
                }
                attempt = attempt.saturating_add(1);
                let exponent = attempt.min(10);
                let cap = (100_u64.saturating_mul(1_u64 << exponent)).min(10_000);
                let remaining = request.deadline_ms.saturating_sub(elapsed);
                let delay = dependencies
                    .random
                    .below(cap.saturating_add(1))
                    .max(retry_after_ms.unwrap_or(0).min(10_000))
                    .min(remaining);
                dependencies.sleeper.sleep_ms(delay);
            }
            Err(error) => return Err(error),
        }
    }
}

fn acquire_once<T: Transport, P, C: Clock, R, S>(
    request: &AcquisitionRequest<'_>,
    dependencies: &mut AcquisitionDependencies<'_, T, P, C, R, S>,
    origin: &Url,
    deadline_at: u64,
) -> Result<VerifiedAcquisition, AcquisitionFailure> {
    let provisional = Handoff {
        delegation: fetch_metadata(
            dependencies.transport,
            origin,
            "trust-delegation.json",
            remaining_timeout(&dependencies.clock, deadline_at)?,
        )?,
        delegation_signature: fetch_metadata(
            dependencies.transport,
            origin,
            "trust-delegation.json.sig",
            remaining_timeout(&dependencies.clock, deadline_at)?,
        )?,
        manifest: fetch_metadata(
            dependencies.transport,
            origin,
            "manifest.json",
            remaining_timeout(&dependencies.clock, deadline_at)?,
        )?,
        manifest_signature: fetch_metadata(
            dependencies.transport,
            origin,
            "manifest.json.sig",
            remaining_timeout(&dependencies.clock, deadline_at)?,
        )?,
        signing_key: fetch_metadata(
            dependencies.transport,
            origin,
            "signing-key.pem",
            remaining_timeout(&dependencies.clock, deadline_at)?,
        )?,
        bundle_manifest: Vec::new(),
    };
    let outer = verify_outer_metadata(&provisional, &request.policy)
        .map_err(|_| AcquisitionFailure::Permanent)?;
    let mut archive = download_archive(
        dependencies.transport,
        origin,
        outer.archive_file(),
        outer.archive_len(),
        outer.archive_sha256(),
        &request.staging_dir,
        remaining_timeout(&dependencies.clock, deadline_at)?,
    )?;
    let bundle_manifest =
        read_bundle_manifest(&mut archive).map_err(|_| AcquisitionFailure::Permanent)?;
    let handoff = Handoff {
        bundle_manifest,
        ..provisional
    };
    let metadata =
        verify_metadata(&handoff, &request.policy).map_err(|_| AcquisitionFailure::Permanent)?;
    let mut component = create_exclusive_staging_file(&request.staging_dir)?;
    let mut runtime = create_exclusive_staging_file(&request.staging_dir)?;
    let mut cpu_provider = create_exclusive_staging_file(&request.staging_dir)?;
    let mut disk_health_provider = create_exclusive_staging_file(&request.staging_dir)?;
    let mut lifecycle_companion = create_exclusive_staging_file(&request.staging_dir)?;
    let mut bootstrap_acquirer = create_exclusive_staging_file(&request.staging_dir)?;
    let mut activator = create_exclusive_staging_file(&request.staging_dir)?;
    let bundle = crate::verifier::verify_archive_and_extract_lifecycle_roles(
        &mut archive,
        &handoff,
        &metadata,
        &mut component,
        &mut runtime,
        &mut cpu_provider,
        &mut disk_health_provider,
        &mut lifecycle_companion,
        &mut bootstrap_acquirer,
        &mut activator,
    )
    .map_err(|_| AcquisitionFailure::Permanent)?;
    for role in [
        &mut component,
        &mut runtime,
        &mut cpu_provider,
        &mut disk_health_provider,
        &mut lifecycle_companion,
        &mut bootstrap_acquirer,
        &mut activator,
    ] {
        role.sync_all().map_err(|_| AcquisitionFailure::Local)?;
    }
    Ok(VerifiedAcquisition {
        handoff,
        bundle,
        component,
        runtime,
        cpu_provider,
        disk_health_provider,
        lifecycle_companion,
        bootstrap_acquirer,
        activator,
    })
}

fn remaining_timeout(clock: &impl Clock, deadline_at: u64) -> Result<Duration, AcquisitionFailure> {
    let remaining = deadline_at.saturating_sub(clock.now_ms());
    if remaining == 0 {
        return Err(AcquisitionFailure::Temporary {
            retry_after_ms: None,
        });
    }
    Ok(Duration::from_millis(remaining))
}

fn exact_origin(value: &str) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && (url.path() == "/" || url.path().is_empty())
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

const MAX_METADATA_BYTES: usize = 256 * 1024;

fn fetch_metadata(
    transport: &mut impl Transport,
    origin: &Url,
    name: &'static str,
    timeout: Duration,
) -> Result<Vec<u8>, AcquisitionFailure> {
    let url = origin
        .join(&format!("api/probe/assets/{name}"))
        .map_err(|_| AcquisitionFailure::InvalidOrigin)?;
    let response = transport
        .get(
            HttpRequest {
                url: url.into(),
                headers: vec![("accept-encoding", "identity")],
            },
            timeout,
        )
        .map_err(transport_failure)?;
    read_exact_response(response, MAX_METADATA_BYTES)
}

fn read_exact_response(
    mut response: HttpResponse,
    maximum: usize,
) -> Result<Vec<u8>, AcquisitionFailure> {
    match response.status {
        200 => {}
        408 | 429 | 500..=599 => return Err(temporary_from_headers(&response.headers)),
        _ => return Err(AcquisitionFailure::Permanent),
    }
    if response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-range"))
        || response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-encoding") && !value.eq_ignore_ascii_case("identity")
        })
    {
        return Err(AcquisitionFailure::Permanent);
    }
    let length = exact_content_length(&response.headers, maximum)?;
    let mut bytes = vec![0; length];
    match response.body.read_exact(&mut bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(AcquisitionFailure::Temporary {
                retry_after_ms: None,
            });
        }
        Err(_) => {
            return Err(AcquisitionFailure::Temporary {
                retry_after_ms: None,
            });
        }
    }
    let mut excess = [0_u8; 1];
    match response.body.read(&mut excess) {
        Ok(0) => Ok(bytes),
        Ok(_) => Err(AcquisitionFailure::Permanent),
        Err(_) => Err(AcquisitionFailure::Temporary {
            retry_after_ms: None,
        }),
    }
}

fn transport_failure(_: TransportError) -> AcquisitionFailure {
    AcquisitionFailure::Temporary {
        retry_after_ms: None,
    }
}

fn temporary_from_headers(headers: &[(String, String)]) -> AcquisitionFailure {
    let retry_after_ms = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.trim().parse::<u64>().ok())
        .and_then(|seconds| seconds.checked_mul(1_000));
    AcquisitionFailure::Temporary { retry_after_ms }
}

fn download_archive(
    transport: &mut impl Transport,
    origin: &Url,
    file_name: &str,
    expected_len: u64,
    expected_sha256: &str,
    staging_dir: &Path,
    timeout: Duration,
) -> Result<File, AcquisitionFailure> {
    if expected_len == 0 || expected_len > MAX_COMPONENT_BYTES {
        return Err(AcquisitionFailure::Permanent);
    }
    ensure_private_staging(staging_dir)?;
    let url = origin
        .join(&format!("api/probe/assets/{file_name}"))
        .map_err(|_| AcquisitionFailure::Permanent)?;
    let response = transport
        .get(
            HttpRequest {
                url: url.into(),
                headers: vec![("accept-encoding", "identity")],
            },
            timeout,
        )
        .map_err(transport_failure)?;
    let mut archive = create_exclusive_staging_file(staging_dir)?;
    stream_archive(response, &mut archive, expected_len, expected_sha256)?;
    Ok(archive)
}

fn stream_archive(
    mut response: HttpResponse,
    archive: &mut File,
    expected_len: u64,
    expected_sha256: &str,
) -> Result<(), AcquisitionFailure> {
    match response.status {
        200 => {}
        408 | 429 | 500..=599 => return Err(temporary_from_headers(&response.headers)),
        _ => return Err(AcquisitionFailure::Permanent),
    }
    let length = exact_content_length(&response.headers, expected_len as usize)?;
    if length as u64 != expected_len {
        return Err(AcquisitionFailure::Permanent);
    }
    let mut hash = Sha256::new();
    let mut remaining = expected_len;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let take = remaining.min(buffer.len() as u64) as usize;
        let read =
            response
                .body
                .read(&mut buffer[..take])
                .map_err(|_| AcquisitionFailure::Temporary {
                    retry_after_ms: None,
                })?;
        if read == 0 {
            return Err(AcquisitionFailure::Temporary {
                retry_after_ms: None,
            });
        }
        archive
            .write_all(&buffer[..read])
            .map_err(|_| AcquisitionFailure::Local)?;
        hash.update(&buffer[..read]);
        remaining -= read as u64;
    }
    let mut excess = [0_u8; 1];
    match response.body.read(&mut excess) {
        Ok(0) => {}
        Ok(_) => return Err(AcquisitionFailure::Permanent),
        Err(_) => {
            return Err(AcquisitionFailure::Temporary {
                retry_after_ms: None,
            });
        }
    }
    archive.sync_all().map_err(|_| AcquisitionFailure::Local)?;
    if format!("{:x}", hash.finalize()) != expected_sha256 {
        return Err(AcquisitionFailure::Permanent);
    }
    archive.rewind().map_err(|_| AcquisitionFailure::Local)
}

fn exact_content_length(
    headers: &[(String, String)],
    maximum: usize,
) -> Result<usize, AcquisitionFailure> {
    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-range"))
        || headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-encoding") && !value.eq_ignore_ascii_case("identity")
        })
    {
        return Err(AcquisitionFailure::Permanent);
    }
    let lengths: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .collect();
    if lengths.len() != 1 {
        return Err(AcquisitionFailure::Permanent);
    }
    let length = lengths[0]
        .1
        .parse::<usize>()
        .map_err(|_| AcquisitionFailure::Permanent)?;
    (length > 0 && length <= maximum)
        .then_some(length)
        .ok_or(AcquisitionFailure::Permanent)
}

fn ensure_private_staging(path: &Path) -> Result<(), AcquisitionFailure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(AcquisitionFailure::Local);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|_| AcquisitionFailure::Local)?;
            return ensure_private_staging(path);
        }
        Err(_) => return Err(AcquisitionFailure::Local),
    }
    Ok(())
}

fn create_exclusive_staging_file(staging_dir: &Path) -> Result<File, AcquisitionFailure> {
    for attempt in 0..32_u8 {
        let path = staging_dir.join(format!("acquire-{}-{attempt}", process::id()));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                // The descriptor is the only reference we retain.  An
                // interrupted process therefore cannot leave a resumable
                // partial archive, and a later root boundary gets no path.
                fs::remove_file(&path).map_err(|_| AcquisitionFailure::Local)?;
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(AcquisitionFailure::Local),
        }
    }
    Err(AcquisitionFailure::Local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::VerificationPolicy;
    use std::path::PathBuf;

    struct Root;

    impl PrivilegeProbe for Root {
        fn is_root(&self) -> bool {
            true
        }
    }

    struct NeverTransport;

    impl Transport for NeverTransport {
        fn get(&mut self, _: HttpRequest, _: Duration) -> Result<HttpResponse, TransportError> {
            panic!("root acquisition must not make a network request")
        }
    }

    struct OneResponse {
        response: Option<HttpResponse>,
        requests: Vec<HttpRequest>,
    }

    struct SequenceTransport {
        responses: Vec<Result<HttpResponse, TransportError>>,
        requests: Vec<HttpRequest>,
        timeouts: Vec<Duration>,
    }

    impl Transport for SequenceTransport {
        fn get(
            &mut self,
            request: HttpRequest,
            timeout: Duration,
        ) -> Result<HttpResponse, TransportError> {
            self.requests.push(request);
            self.timeouts.push(timeout);
            self.responses.remove(0)
        }
    }

    impl Transport for OneResponse {
        fn get(
            &mut self,
            request: HttpRequest,
            _: Duration,
        ) -> Result<HttpResponse, TransportError> {
            self.requests.push(request);
            self.response.take().ok_or(TransportError::Unavailable)
        }
    }

    #[test]
    fn rejects_root_before_any_network_or_staging_side_effect() {
        let mut transport = NeverTransport;
        let mut dependencies = dependencies(&mut transport, Root);
        let result = acquire(
            AcquisitionRequest {
                hub_origin: "https://hub.example".to_owned(),
                policy: VerificationPolicy {
                    distribution: "enoki",
                    expected_target: "x86_64-unknown-linux-gnu",
                    highest_accepted_delegation_generation: 0,
                    external_root_fingerprint: "a".repeat(64),
                    external_root_pem: None,
                },
                staging_dir: PathBuf::from("/unused"),
                deadline_ms: 1_000,
            },
            &mut dependencies,
        );

        assert!(matches!(result, Err(AcquisitionFailure::RootRefused)));
    }

    #[test]
    fn rejects_non_origin_hub_urls_before_any_network_side_effect() {
        let mut transport = NeverTransport;
        for hub_origin in [
            "https://hub.example/prefix",
            "https://user@hub.example",
            "https://hub.example?query=1",
            "ftp://hub.example",
        ] {
            let mut dependencies = dependencies(&mut transport, NotRoot);
            let result = acquire(
                AcquisitionRequest {
                    hub_origin: hub_origin.to_owned(),
                    policy: VerificationPolicy {
                        distribution: "enoki",
                        expected_target: "x86_64-unknown-linux-gnu",
                        highest_accepted_delegation_generation: 0,
                        external_root_fingerprint: "a".repeat(64),
                        external_root_pem: None,
                    },
                    staging_dir: PathBuf::from("/unused"),
                    deadline_ms: 1_000,
                },
                &mut dependencies,
            );
            assert!(matches!(result, Err(AcquisitionFailure::InvalidOrigin)));
        }
    }

    #[test]
    fn rejects_metadata_without_an_exact_declared_length_before_following_metadata_paths() {
        let mut transport = OneResponse {
            response: Some(HttpResponse {
                status: 200,
                headers: vec![],
                body: Box::new(std::io::Cursor::new(b"metadata".to_vec())),
            }),
            requests: vec![],
        };
        let mut dependencies = dependencies(&mut transport, NotRoot);
        let result = acquire(request("https://hub.example"), &mut dependencies);
        assert!(matches!(result, Err(AcquisitionFailure::Permanent)));
        assert_eq!(transport.requests.len(), 1);
        assert_eq!(
            transport.requests[0].url,
            "https://hub.example/api/probe/assets/trust-delegation.json"
        );
        assert_eq!(
            transport.requests[0].headers,
            vec![("accept-encoding", "identity")]
        );
    }

    #[test]
    fn treats_redirects_and_encoded_or_ranged_metadata_as_permanent_failures() {
        for (status, headers) in [
            (302, vec![("content-length".to_owned(), "1".to_owned())]),
            (
                200,
                vec![
                    ("content-length".to_owned(), "1".to_owned()),
                    ("content-length".to_owned(), "1".to_owned()),
                ],
            ),
            (
                200,
                vec![
                    ("content-length".to_owned(), "1".to_owned()),
                    ("content-encoding".to_owned(), "gzip".to_owned()),
                ],
            ),
            (
                200,
                vec![
                    ("content-length".to_owned(), "1".to_owned()),
                    ("content-range".to_owned(), "bytes 0-0/1".to_owned()),
                ],
            ),
        ] {
            let result = read_exact_response(
                HttpResponse {
                    status,
                    headers,
                    body: Box::new(std::io::Cursor::new(vec![0])),
                },
                MAX_METADATA_BYTES,
            );
            assert!(matches!(result, Err(AcquisitionFailure::Permanent)));
        }
    }

    #[test]
    fn classifies_archive_size_lies_as_permanent_and_disconnects_as_transient() {
        let temporary = tempfile::tempdir().expect("temp staging");
        let cases = [
            (
                "false length",
                "3",
                vec![1, 2, 3],
                AcquisitionFailure::Permanent,
            ),
            (
                "truncated body",
                "4",
                vec![1, 2, 3],
                AcquisitionFailure::Temporary {
                    retry_after_ms: None,
                },
            ),
            (
                "excess body",
                "4",
                vec![1, 2, 3, 4],
                AcquisitionFailure::Permanent,
            ),
        ];
        for (name, content_length, body, expected) in cases {
            let mut archive = create_exclusive_staging_file(temporary.path()).expect("private fd");
            let result = stream_archive(
                HttpResponse {
                    status: 200,
                    headers: vec![("content-length".to_owned(), content_length.to_owned())],
                    body: Box::new(std::io::Cursor::new(body)),
                },
                &mut archive,
                4,
                &"0".repeat(64),
            );
            assert!(matches!(result, Err(error) if error == expected), "{name}");
            drop(archive);
            assert_eq!(
                std::fs::read_dir(temporary.path())
                    .expect("staging")
                    .count(),
                0,
                "{name} leaves no resumable staging file"
            );
        }
    }

    #[test]
    fn retries_only_a_transient_transport_failure_with_full_jitter_inside_its_deadline() {
        use std::{cell::RefCell, rc::Rc};
        let mut transport = SequenceTransport {
            responses: vec![
                Err(TransportError::Interrupted),
                Ok(HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: Box::new(std::io::Cursor::new(b"metadata".to_vec())),
                }),
            ],
            requests: vec![],
            timeouts: vec![],
        };
        let time = Rc::new(RefCell::new(TestTime {
            now: 0,
            slept: vec![],
        }));
        let mut dependencies = AcquisitionDependencies::for_test(
            &mut transport,
            NotRoot,
            SharedClock(time.clone()),
            UpperJitter { values: vec![200] },
            SharedSleeper(time.clone()),
        );
        let result = acquire(request("https://hub.example"), &mut dependencies);
        assert!(matches!(result, Err(AcquisitionFailure::Permanent)));
        assert_eq!(transport.requests.len(), 2);
        let time = time.borrow();
        assert_eq!(time.slept, vec![200]);
        assert!(time.slept[0] <= 200);
    }

    #[test]
    fn stops_at_the_fixed_total_deadline_without_a_resume_request() {
        use std::{cell::RefCell, rc::Rc};
        let mut transport = SequenceTransport {
            responses: vec![Err(TransportError::Unavailable)],
            requests: vec![],
            timeouts: vec![],
        };
        let time = Rc::new(RefCell::new(TestTime {
            now: 0,
            slept: vec![],
        }));
        let mut dependencies = AcquisitionDependencies::for_test(
            &mut transport,
            NotRoot,
            SharedClock(time.clone()),
            UpperJitter { values: vec![200] },
            SharedSleeper(time.clone()),
        );
        let mut bounded = request("https://hub.example");
        bounded.deadline_ms = 150;
        let result = acquire(bounded, &mut dependencies);
        assert!(matches!(
            result,
            Err(AcquisitionFailure::Temporary {
                retry_after_ms: None
            })
        ));
        assert_eq!(transport.requests.len(), 1);
        assert_eq!(time.borrow().slept, vec![150]);
        assert!(
            transport
                .requests
                .iter()
                .all(|request| !request.headers.iter().any(|(name, _)| *name == "range"))
        );
    }

    #[test]
    fn bounds_server_retry_after_inside_the_total_deadline() {
        use std::{cell::RefCell, rc::Rc};
        let mut transport = SequenceTransport {
            responses: vec![Ok(HttpResponse {
                status: 429,
                headers: vec![("retry-after".to_owned(), "99999".to_owned())],
                body: Box::new(std::io::Cursor::new(Vec::<u8>::new())),
            })],
            requests: vec![],
            timeouts: vec![],
        };
        let time = Rc::new(RefCell::new(TestTime {
            now: 0,
            slept: vec![],
        }));
        let mut dependencies = AcquisitionDependencies::for_test(
            &mut transport,
            NotRoot,
            SharedClock(time.clone()),
            UpperJitter { values: vec![0] },
            SharedSleeper(time.clone()),
        );
        let mut bounded = request("https://hub.example");
        bounded.deadline_ms = 1_000;
        let result = acquire(bounded, &mut dependencies);
        assert!(matches!(result, Err(AcquisitionFailure::Temporary { .. })));
        assert_eq!(time.borrow().slept, vec![1_000]);
    }

    #[test]
    fn passes_only_the_remaining_deadline_to_a_blocking_transport() {
        let mut transport = SequenceTransport {
            responses: vec![Ok(HttpResponse {
                status: 400,
                headers: vec![],
                body: Box::new(std::io::Cursor::new(Vec::<u8>::new())),
            })],
            requests: vec![],
            timeouts: vec![],
        };
        let mut request = request("https://hub.example");
        request.deadline_ms = 73;
        let mut dependencies = dependencies(&mut transport, NotRoot);
        assert!(matches!(
            acquire(request, &mut dependencies),
            Err(AcquisitionFailure::Permanent)
        ));
        assert_eq!(transport.timeouts, vec![Duration::from_millis(73)]);
    }

    fn request(hub_origin: &str) -> AcquisitionRequest<'static> {
        AcquisitionRequest {
            hub_origin: hub_origin.to_owned(),
            policy: VerificationPolicy {
                distribution: "enoki",
                expected_target: "x86_64-unknown-linux-gnu",
                highest_accepted_delegation_generation: 0,
                external_root_fingerprint: "a".repeat(64),
                external_root_pem: Some(b"root"),
            },
            staging_dir: PathBuf::from("/unused"),
            deadline_ms: 1_000,
        }
    }

    struct NotRoot;

    impl PrivilegeProbe for NotRoot {
        fn is_root(&self) -> bool {
            false
        }
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now_ms(&self) -> u64 {
            0
        }
    }
    struct FixedRandom;
    impl Random for FixedRandom {
        fn below(&mut self, _: u64) -> u64 {
            0
        }
    }
    struct NoSleep;
    impl Sleeper for NoSleep {
        fn sleep_ms(&mut self, _: u64) {}
    }

    fn dependencies<'a, T, P>(
        transport: &'a mut T,
        privilege: P,
    ) -> AcquisitionDependencies<'a, T, P, FixedClock, FixedRandom, NoSleep> {
        AcquisitionDependencies::for_test(transport, privilege, FixedClock, FixedRandom, NoSleep)
    }

    struct TestTime {
        now: u64,
        slept: Vec<u64>,
    }
    struct SharedClock(std::rc::Rc<std::cell::RefCell<TestTime>>);
    impl Clock for SharedClock {
        fn now_ms(&self) -> u64 {
            self.0.borrow().now
        }
    }
    struct SharedSleeper(std::rc::Rc<std::cell::RefCell<TestTime>>);
    impl Sleeper for SharedSleeper {
        fn sleep_ms(&mut self, duration_ms: u64) {
            let mut time = self.0.borrow_mut();
            time.now += duration_ms;
            time.slept.push(duration_ms);
        }
    }
    struct UpperJitter {
        values: Vec<u64>,
    }
    impl Random for UpperJitter {
        fn below(&mut self, upper_exclusive: u64) -> u64 {
            let value = self.values.remove(0);
            assert!(value < upper_exclusive);
            value
        }
    }

    #[test]
    fn repair_authorization_only_propagates_the_strict_manual_disposition() {
        assert_eq!(
            classify_repair_authorization_error(
                409,
                br#"{"disposition":"manual_reinstall_required"}"#,
                None,
            ),
            AcquisitionFailure::ManualReinstallRequired,
        );
        for body in [
            br#"{"disposition":"manual_reinstall_required","detail":"free text"}"#.as_slice(),
            br#"{"disposition":"probe_repair"}"#.as_slice(),
            br#"{"error":"manual_reinstall_required"}"#.as_slice(),
        ] {
            assert_eq!(
                classify_repair_authorization_error(409, body, None),
                AcquisitionFailure::Permanent,
            );
        }
        assert_eq!(
            classify_repair_authorization_error(429, br#"{}"#, Some(2_000)),
            AcquisitionFailure::Temporary {
                retry_after_ms: Some(2_000)
            },
        );
    }
}

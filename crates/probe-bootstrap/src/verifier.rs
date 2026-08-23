//! Offline trust verification.  Archive parsing is exposed only to the
//! unprivileged acquisition module; root activation verifies metadata and the
//! component bytes, never a compressed archive.
use crate::bundle_role::BUNDLE_COMPONENTS;
use crate::handoff::Handoff;
#[cfg(feature = "acquirer")]
use flate2::bufread::GzDecoder;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Signature as RsaSignature, VerifyingKey},
    pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding},
    signature::Verifier,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
#[cfg(feature = "acquirer")]
use std::io::{BufRead, BufReader, Write};
use std::io::{Read, Seek, SeekFrom};
#[cfg(feature = "acquirer")]
use tar::Archive;

const DELEGATION_DOMAIN: &[u8] = b"enoki/probe-trust-delegation/v1\0";
const MAX_BUNDLE_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_COMPONENT_BYTES: u64 = 512 * 1024 * 1024;
const BUNDLED_BOOTSTRAP_ASSETS: [(&str, &str, &str); 2] = [
    (
        "bootstrap/enoki-probe-bootstrap-acquire",
        "bootstrap-acquirer-v1",
        "bootstrap-acquirer",
    ),
    (
        "bootstrap/enoki-probe-bootstrap-activate",
        "bootstrap-activator-v1",
        "bootstrap-activator",
    ),
];
#[cfg(feature = "acquirer")]
const MAX_TAR_OVERHEAD_BYTES: u64 = 16 * 1024;
#[cfg(feature = "acquirer")]
const MAX_UNCOMPRESSED_ARCHIVE_BYTES: u64 =
    MAX_COMPONENT_BYTES * 5 + MAX_BUNDLE_MANIFEST_BYTES as u64 + MAX_TAR_OVERHEAD_BYTES;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerificationPolicy<'a> {
    pub distribution: &'a str,
    pub expected_target: &'a str,
    pub highest_accepted_delegation_generation: u64,
    pub external_root_fingerprint: String,
    pub external_root_pem: Option<&'a [u8]>,
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedBundle {
    pub version: String,
    pub target: String,
    pub delegation_generation: u64,
    pub component_len: u64,
    pub(crate) bootstrap_assets: Vec<BundleComponent>,
}
impl VerifiedBundle {
    pub fn delegation_generation(&self) -> u64 {
        self.delegation_generation
    }
    #[cfg(all(test, feature = "activator"))]
    pub(crate) fn with_test_observation_receipts(mut self, size: u64) -> Self {
        for (path, permission_profile, resource_contract, role) in BUNDLE_COMPONENTS {
            if matches!(
                role,
                "observation-runtime" | "system-state-provider" | "disk-health-provider"
            ) {
                self.bootstrap_assets.push(BundleComponent {
                    path: path.to_string(),
                    permission_profile: permission_profile.to_string(),
                    resource_contract: Some(resource_contract.to_string()),
                    role: role.to_string(),
                    sha256: "a".repeat(64),
                    size,
                    version: self.version.clone(),
                });
            }
        }
        self
    }

    pub(crate) fn component_receipt(&self, role: &str) -> Option<(&str, u64)> {
        self.bootstrap_assets
            .iter()
            .find(|component| component.role == role)
            .map(|component| (component.sha256.as_str(), component.size))
    }
    pub(crate) fn acquirer_receipt(&self) -> Option<(&str, u64)> {
        self.bootstrap_assets
            .iter()
            .find(|asset| asset.role == "bootstrap-acquirer")
            .map(|asset| (asset.sha256.as_str(), asset.size))
    }
    pub(crate) fn activator_receipt(&self) -> Option<(&str, u64)> {
        self.bootstrap_assets
            .iter()
            .find(|asset| asset.role == "bootstrap-activator")
            .map(|asset| (asset.sha256.as_str(), asset.size))
    }
}
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedMetadata {
    asset: Asset,
    bundle: VerifiedBundle,
}
impl VerifiedMetadata {
    pub fn bundle(&self) -> &VerifiedBundle {
        &self.bundle
    }
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VerificationError {
    RootFingerprint,
    Delegation,
    DelegationRollback,
    Manifest,
    ManifestSignature,
    TargetAsset,
    ArchiveDigest,
    ArchiveStructure,
    BundleManifest,
    Component,
    Io,
}

#[derive(Debug)]
pub struct AuthenticatedAsset {
    asset: Asset,
    version: String,
    delegation_generation: u64,
}
impl AuthenticatedAsset {
    pub fn archive_len(&self) -> u64 {
        self.asset.size
    }
    pub fn archive_file(&self) -> &str {
        &self.asset.file
    }
    #[cfg(feature = "acquirer")]
    pub(crate) fn archive_sha256(&self) -> &str {
        &self.asset.sha256
    }
}

/// Verifies every small metadata object using the externally fixed root. The
/// bundle manifest hash in the signed outer asset is checked before component
/// bytes are accepted by either side of the privilege boundary.
pub fn verify_metadata(
    handoff: &Handoff,
    policy: &VerificationPolicy<'_>,
) -> Result<VerifiedMetadata, VerificationError> {
    let outer = verify_outer_metadata(handoff, policy)?;
    if sha256_hex(&handoff.bundle_manifest) != outer.asset.bundle_manifest_sha256 {
        return Err(VerificationError::BundleManifest);
    }
    let bundle = verify_bundle_manifest(
        &handoff.bundle_manifest,
        &outer.version,
        &outer.asset,
        outer.delegation_generation,
    )?;
    Ok(VerifiedMetadata {
        asset: outer.asset,
        bundle,
    })
}

/// Authenticates root/delegation/outer manifest and selects the fixed target
/// asset. It intentionally does not yet inspect bundle bytes.
pub fn verify_outer_metadata(
    handoff: &Handoff,
    policy: &VerificationPolicy<'_>,
) -> Result<AuthenticatedAsset, VerificationError> {
    let (root, root_bytes) = trusted_root(policy)?;
    let delegation = verify_delegation(handoff, policy, &root, &root_bytes)?;
    let manifest = verify_manifest(handoff, &delegation)?;
    let asset = select_asset(&manifest, policy.expected_target)?.clone();
    Ok(AuthenticatedAsset {
        asset,
        version: manifest.version,
        delegation_generation: delegation.generation,
    })
}

/// Obtains the one bounded manifest member before it is authenticated by the
/// signed outer asset. Its bytes are still untrusted until `verify_metadata`.
#[cfg(feature = "acquirer")]
pub fn read_bundle_manifest(archive: &mut File) -> Result<Vec<u8>, VerificationError> {
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| VerificationError::Io)?;
    let mut tar = Archive::new(BoundedRead::new(GzDecoder::new(BufReader::new(archive))));
    let item = tar
        .entries()
        .map_err(|_| VerificationError::ArchiveStructure)?
        .raw(true)
        .next()
        .ok_or(VerificationError::ArchiveStructure)?;
    let mut entry = item.map_err(|_| VerificationError::ArchiveStructure)?;
    if !entry.header().entry_type().is_file()
        || entry.path_bytes().as_ref() != b"bundle-manifest.json"
        || entry.size() == 0
        || entry.size() > MAX_BUNDLE_MANIFEST_BYTES as u64
    {
        return Err(VerificationError::ArchiveStructure);
    }
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut bytes)
        .map_err(|_| VerificationError::ArchiveStructure)?;
    Ok(bytes)
}

/// Unprivileged-only archive parser. It confirms archive digest and structure,
/// requires the embedded manifest bytes to equal the already signed exact
/// handoff bytes, and writes only the allowlisted component to an opened FD.
#[cfg(feature = "acquirer")]
pub fn verify_archive_and_extract(
    archive: &mut File,
    handoff: &Handoff,
    metadata: &VerifiedMetadata,
    sink: &mut impl Write,
) -> Result<VerifiedBundle, VerificationError> {
    verify_archive_and_extract_roles(
        archive,
        handoff,
        metadata,
        sink,
        &mut std::io::sink(),
        &mut std::io::sink(),
        &mut std::io::sink(),
        &mut std::io::sink(),
        &mut std::io::sink(),
    )
}

/// 可信升级路径使用与首次安装相同的三组件 archive verifier；调用者不能提供角色表。
#[cfg(feature = "acquirer")]
pub fn verify_archive_and_extract_upgrade_roles(
    archive: &mut File,
    handoff: &Handoff,
    metadata: &VerifiedMetadata,
    probe_sink: &mut impl Write,
    runtime_sink: &mut impl Write,
    cpu_provider_sink: &mut impl Write,
    disk_health_provider_sink: &mut impl Write,
) -> Result<VerifiedBundle, VerificationError> {
    verify_archive_and_extract_lifecycle_roles(
        archive,
        handoff,
        metadata,
        probe_sink,
        runtime_sink,
        cpu_provider_sink,
        disk_health_provider_sink,
        &mut std::io::sink(),
        &mut std::io::sink(),
    )
}

/// 升级生命周期一次提取并校验三个运行时角色与两个 Bootstrap 角色。
#[cfg(feature = "acquirer")]
#[allow(clippy::too_many_arguments)]
pub fn verify_archive_and_extract_lifecycle_roles(
    archive: &mut File,
    handoff: &Handoff,
    metadata: &VerifiedMetadata,
    probe_sink: &mut impl Write,
    runtime_sink: &mut impl Write,
    cpu_provider_sink: &mut impl Write,
    disk_health_provider_sink: &mut impl Write,
    bootstrap_acquirer_sink: &mut impl Write,
    bootstrap_activator_sink: &mut impl Write,
) -> Result<VerifiedBundle, VerificationError> {
    verify_archive_and_extract_roles(
        archive,
        handoff,
        metadata,
        probe_sink,
        runtime_sink,
        cpu_provider_sink,
        disk_health_provider_sink,
        bootstrap_acquirer_sink,
        bootstrap_activator_sink,
    )
}

#[cfg(feature = "acquirer")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_archive_and_extract_roles(
    archive: &mut File,
    handoff: &Handoff,
    metadata: &VerifiedMetadata,
    component_sink: &mut impl Write,
    runtime_sink: &mut impl Write,
    cpu_provider_sink: &mut impl Write,
    disk_health_provider_sink: &mut impl Write,
    acquirer_sink: &mut impl Write,
    activator_sink: &mut impl Write,
) -> Result<VerifiedBundle, VerificationError> {
    verify_archive_digest(archive, &metadata.asset)?;
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| VerificationError::Io)?;
    let mut tar = Archive::new(BoundedRead::new(GzDecoder::new(BufReader::new(archive))));
    let mut saw_manifest = false;
    let components = metadata
        .bundle
        .bootstrap_assets
        .iter()
        .filter(|component| {
            matches!(
                component.role.as_str(),
                "probe" | "observation-runtime" | "system-state-provider" | "disk-health-provider"
            )
        })
        .collect::<Vec<_>>();
    let bootstrap_assets = metadata
        .bundle
        .bootstrap_assets
        .iter()
        .filter(|component| component.role.starts_with("bootstrap-"))
        .collect::<Vec<_>>();
    let mut saw_components = vec![false; components.len()];
    let mut saw_bootstrap_assets = vec![false; bootstrap_assets.len()];
    for item in tar
        .entries()
        .map_err(|_| VerificationError::ArchiveStructure)?
        .raw(true)
    {
        let mut entry = item.map_err(|_| VerificationError::ArchiveStructure)?;
        if !entry.header().entry_type().is_file() {
            return Err(VerificationError::ArchiveStructure);
        }
        let path = entry.path_bytes();
        if path.as_ref() == b"bundle-manifest.json" {
            if saw_manifest || entry.size() != handoff.bundle_manifest.len() as u64 {
                return Err(VerificationError::ArchiveStructure);
            }
            let mut bytes = Vec::with_capacity(handoff.bundle_manifest.len());
            entry
                .read_to_end(&mut bytes)
                .map_err(|_| VerificationError::ArchiveStructure)?;
            if bytes != handoff.bundle_manifest {
                return Err(VerificationError::BundleManifest);
            }
            saw_manifest = true;
        } else if let Some((index, component)) = components
            .iter()
            .enumerate()
            .find(|(_, component)| path.as_ref() == component.path.as_bytes())
        {
            if saw_components[index] || entry.size() != component.size {
                return Err(VerificationError::ArchiveStructure);
            }
            match component.role.as_str() {
                "probe" => stream_component(
                    &mut entry,
                    component_sink,
                    component.size,
                    component.sha256.clone(),
                )?,
                "observation-runtime" => stream_component(
                    &mut entry,
                    runtime_sink,
                    component.size,
                    component.sha256.clone(),
                )?,
                "system-state-provider" => stream_component(
                    &mut entry,
                    cpu_provider_sink,
                    component.size,
                    component.sha256.clone(),
                )?,
                "disk-health-provider" => stream_component(
                    &mut entry,
                    disk_health_provider_sink,
                    component.size,
                    component.sha256.clone(),
                )?,
                _ => return Err(VerificationError::ArchiveStructure),
            }
            saw_components[index] = true;
        } else if let Some((index, asset)) = bootstrap_assets
            .iter()
            .enumerate()
            .find(|(_, asset)| path.as_ref() == asset.path.as_bytes())
        {
            if saw_bootstrap_assets[index] || entry.size() != asset.size {
                return Err(VerificationError::ArchiveStructure);
            }
            match asset.role.as_str() {
                "bootstrap-acquirer" => stream_component(
                    &mut entry,
                    &mut *acquirer_sink,
                    asset.size,
                    asset.sha256.clone(),
                )?,
                "bootstrap-activator" => stream_component(
                    &mut entry,
                    &mut *activator_sink,
                    asset.size,
                    asset.sha256.clone(),
                )?,
                _ => return Err(VerificationError::ArchiveStructure),
            }
            saw_bootstrap_assets[index] = true;
        } else {
            return Err(VerificationError::ArchiveStructure);
        }
    }
    if !saw_manifest
        || saw_components.iter().any(|seen| !seen)
        || saw_bootstrap_assets.iter().any(|seen| !seen)
    {
        return Err(VerificationError::ArchiveStructure);
    }
    require_exact_gzip_and_tar_eof(tar.into_inner())?;
    Ok(metadata.bundle.clone())
}

/// Root's independent post-copy check. This deliberately accepts only the
/// signed component length and digest, with no caller-supplied profile/mode.
pub fn verify_component(
    component: &mut File,
    _handoff: &Handoff,
    bundle: &VerifiedBundle,
) -> Result<(), VerificationError> {
    verify_role_component(component, bundle, "probe")
}

pub(crate) fn verify_role_component(
    component: &mut File,
    bundle: &VerifiedBundle,
    role: &str,
) -> Result<(), VerificationError> {
    let (expected, expected_len) = bundle
        .component_receipt(role)
        .ok_or(VerificationError::Component)?;
    let details = component.metadata().map_err(|_| VerificationError::Io)?;
    if details.len() != expected_len || expected_len == 0 {
        return Err(VerificationError::Component);
    }
    component
        .seek(SeekFrom::Start(0))
        .map_err(|_| VerificationError::Io)?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let count = component
            .read(&mut buf)
            .map_err(|_| VerificationError::Io)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(VerificationError::Component)?;
        hash.update(&buf[..count]);
    }
    if total != expected_len || format!("{:x}", hash.finalize()) != expected {
        return Err(VerificationError::Component);
    }
    component
        .seek(SeekFrom::Start(0))
        .map_err(|_| VerificationError::Io)?;
    Ok(())
}

/// Root 对正在执行的 sealed activator FD 进行独立 receipt 复验。
pub fn verify_activator_receipt(
    activator: &mut File,
    bundle: &VerifiedBundle,
) -> Result<(), VerificationError> {
    let expected = bundle.activator_receipt();
    verify_bootstrap_receipt(activator, expected)
}

pub fn verify_acquirer_receipt(
    acquirer: &mut File,
    bundle: &VerifiedBundle,
) -> Result<(), VerificationError> {
    verify_bootstrap_receipt(acquirer, bundle.acquirer_receipt())
}

fn verify_bootstrap_receipt(
    receipt: &mut File,
    expected: Option<(&str, u64)>,
) -> Result<(), VerificationError> {
    let (expected_sha256, expected_size) = expected.ok_or(VerificationError::Component)?;
    let details = receipt.metadata().map_err(|_| VerificationError::Io)?;
    if !details.is_file() || details.len() != expected_size {
        return Err(VerificationError::Component);
    }
    receipt
        .seek(SeekFrom::Start(0))
        .map_err(|_| VerificationError::Io)?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = receipt
            .read(&mut buffer)
            .map_err(|_| VerificationError::Io)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        hash.update(&buffer[..read]);
    }
    if total != expected_size || format!("{:x}", hash.finalize()) != expected_sha256 {
        return Err(VerificationError::Component);
    }
    Ok(())
}

fn trusted_root(
    policy: &VerificationPolicy<'_>,
) -> Result<(RsaPublicKey, Vec<u8>), VerificationError> {
    if !is_sha256_hex(&policy.external_root_fingerprint) {
        return Err(VerificationError::RootFingerprint);
    }
    let pem = policy
        .external_root_pem
        .ok_or(VerificationError::RootFingerprint)?;
    let canonical = canonical_public_key(pem).ok_or(VerificationError::RootFingerprint)?;
    if sha256_hex(&canonical) != policy.external_root_fingerprint {
        return Err(VerificationError::RootFingerprint);
    }
    let key = RsaPublicKey::from_public_key_pem(
        std::str::from_utf8(&canonical).map_err(|_| VerificationError::RootFingerprint)?,
    )
    .map_err(|_| VerificationError::RootFingerprint)?;
    Ok((key, canonical))
}
fn verify_delegation(
    h: &Handoff,
    p: &VerificationPolicy<'_>,
    root: &RsaPublicKey,
    root_bytes: &[u8],
) -> Result<Delegation, VerificationError> {
    let parsed: Value =
        serde_json::from_slice(&h.delegation).map_err(|_| VerificationError::Delegation)?;
    exact(
        &parsed,
        &[
            "distribution",
            "generation",
            "kind",
            "purpose",
            "rootKeyId",
            "schemaVersion",
            "signingIdentity",
        ],
    )
    .ok_or(VerificationError::Delegation)?;
    exact(
        parsed
            .get("signingIdentity")
            .ok_or(VerificationError::Delegation)?,
        &["algorithm", "keyId", "publicKeyPem"],
    )
    .ok_or(VerificationError::Delegation)?;
    let parsed: Delegation =
        serde_json::from_value(parsed).map_err(|_| VerificationError::Delegation)?;
    let signing = canonical_public_key(parsed.signing_identity.public_key_pem.as_bytes())
        .ok_or(VerificationError::Delegation)?;
    let canonical = Delegation {
        signing_identity: SigningIdentity {
            public_key_pem: String::from_utf8(signing)
                .map_err(|_| VerificationError::Delegation)?,
            ..parsed.signing_identity
        },
        ..parsed
    };
    let bytes = canonical_json(&canonical).map_err(|_| VerificationError::Delegation)?;
    if h.delegation != bytes
        || canonical.kind != "enoki-probe-trust-delegation"
        || canonical.schema_version != 1
        || canonical.distribution != p.distribution
        || canonical.purpose != "probe-asset-signing"
        || canonical.generation == 0
        || canonical.root_key_id != sha256_hex(root_bytes)
        || !is_sha256_hex(&canonical.root_key_id)
        || canonical.signing_identity.algorithm != "rsa-sha256"
        || canonical.signing_identity.key_id
            != sha256_hex(canonical.signing_identity.public_key_pem.as_bytes())
        || !is_sha256_hex(&canonical.signing_identity.key_id)
    {
        return Err(VerificationError::Delegation);
    }
    if canonical.generation < p.highest_accepted_delegation_generation {
        return Err(VerificationError::DelegationRollback);
    }
    let sig = RsaSignature::try_from(h.delegation_signature.as_slice())
        .map_err(|_| VerificationError::Delegation)?;
    let mut signed = DELEGATION_DOMAIN.to_vec();
    signed.extend_from_slice(&bytes);
    VerifyingKey::<Sha256>::new(root.clone())
        .verify(&signed, &sig)
        .map_err(|_| VerificationError::Delegation)?;
    Ok(canonical)
}
fn verify_manifest(h: &Handoff, d: &Delegation) -> Result<AssetManifest, VerificationError> {
    let value: Value =
        serde_json::from_slice(&h.manifest).map_err(|_| VerificationError::Manifest)?;
    exact(&value, &["assets", "kind", "signature", "version"])
        .ok_or(VerificationError::Manifest)?;
    exact(
        value.get("signature").ok_or(VerificationError::Manifest)?,
        &[
            "algorithm",
            "delegationGeneration",
            "delegationKeyId",
            "file",
            "publicKey",
        ],
    )
    .ok_or(VerificationError::Manifest)?;
    let assets = value
        .get("assets")
        .and_then(Value::as_array)
        .ok_or(VerificationError::Manifest)?;
    if assets.iter().any(|a| {
        exact(
            a,
            &["bundleManifestSha256", "file", "sha256", "size", "target"],
        )
        .is_none()
    }) {
        return Err(VerificationError::Manifest);
    }
    let manifest: AssetManifest =
        serde_json::from_value(value).map_err(|_| VerificationError::Manifest)?;
    if manifest.kind != "enoki-probe-assets"
        || !is_semver(&manifest.version)
        || manifest.signature.algorithm != "rsa-sha256"
        || manifest.signature.file != "manifest.json.sig"
        || manifest.signature.public_key != "signing-key.pem"
        || manifest.signature.delegation_generation != d.generation
        || manifest.signature.delegation_key_id != d.signing_identity.key_id
    {
        return Err(VerificationError::Manifest);
    }
    let key = canonical_public_key(&h.signing_key).ok_or(VerificationError::Manifest)?;
    if key != d.signing_identity.public_key_pem.as_bytes()
        || sha256_hex(&key) != d.signing_identity.key_id
    {
        return Err(VerificationError::Manifest);
    }
    let key = RsaPublicKey::from_public_key_pem(
        std::str::from_utf8(&key).map_err(|_| VerificationError::Manifest)?,
    )
    .map_err(|_| VerificationError::Manifest)?;
    let sig = RsaSignature::try_from(h.manifest_signature.as_slice())
        .map_err(|_| VerificationError::ManifestSignature)?;
    VerifyingKey::<Sha256>::new(key)
        .verify(&h.manifest, &sig)
        .map_err(|_| VerificationError::ManifestSignature)?;
    Ok(manifest)
}
fn select_asset<'a>(m: &'a AssetManifest, target: &str) -> Result<&'a Asset, VerificationError> {
    let mut found = None;
    for a in &m.assets {
        if !safe_target(&a.target)
            || a.size == 0
            || !is_sha256_hex(&a.sha256)
            || !is_sha256_hex(&a.bundle_manifest_sha256)
            || a.file != format!("enoki-probe-{}.tar.gz", a.target)
        {
            return Err(VerificationError::TargetAsset);
        }
        if a.target == target && found.replace(a).is_some() {
            return Err(VerificationError::TargetAsset);
        }
    }
    found.ok_or(VerificationError::TargetAsset)
}
#[cfg(feature = "acquirer")]
fn verify_archive_digest(archive: &mut File, a: &Asset) -> Result<(), VerificationError> {
    if archive.metadata().map_err(|_| VerificationError::Io)?.len() != a.size {
        return Err(VerificationError::ArchiveDigest);
    }
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| VerificationError::Io)?;
    let mut hash = Sha256::new();
    let mut total = 0;
    let mut b = [0; 65536];
    loop {
        let n = archive.read(&mut b).map_err(|_| VerificationError::Io)?;
        if n == 0 {
            break;
        };
        total += n as u64;
        hash.update(&b[..n]);
    }
    if total != a.size || format!("{:x}", hash.finalize()) != a.sha256 {
        return Err(VerificationError::ArchiveDigest);
    }
    Ok(())
}
#[cfg(feature = "acquirer")]
fn stream_component(
    input: &mut impl Read,
    out: &mut impl Write,
    expected_len: u64,
    expected_digest: String,
) -> Result<(), VerificationError> {
    let mut left = expected_len;
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    while left > 0 {
        let want = left.min(b.len() as u64) as usize;
        let n = input
            .read(&mut b[..want])
            .map_err(|_| VerificationError::ArchiveStructure)?;
        if n == 0 {
            return Err(VerificationError::ArchiveStructure);
        };
        out.write_all(&b[..n]).map_err(|_| VerificationError::Io)?;
        h.update(&b[..n]);
        left -= n as u64;
    }
    if format!("{:x}", h.finalize()) != expected_digest {
        return Err(VerificationError::Component);
    }
    Ok(())
}
fn verify_bundle_manifest(
    bytes: &[u8],
    version: &str,
    a: &Asset,
    generation: u64,
) -> Result<VerifiedBundle, VerificationError> {
    if bytes.is_empty() || bytes.len() > MAX_BUNDLE_MANIFEST_BYTES {
        return Err(VerificationError::BundleManifest);
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|_| VerificationError::BundleManifest)?;
    exact(
        &v,
        &["bootstrapAssets", "components", "kind", "target", "version"],
    )
    .ok_or(VerificationError::BundleManifest)?;
    let components = v
        .get("components")
        .and_then(Value::as_array)
        .ok_or(VerificationError::BundleManifest)?;
    let bootstrap_assets = v
        .get("bootstrapAssets")
        .and_then(Value::as_array)
        .ok_or(VerificationError::BundleManifest)?;
    if components.iter().any(|c| {
        exact(
            c,
            &[
                "path",
                "permissionProfile",
                "resourceContract",
                "role",
                "sha256",
                "size",
                "version",
            ],
        )
        .is_none()
    }) {
        return Err(VerificationError::BundleManifest);
    }
    if bootstrap_assets.iter().any(|c| {
        exact(
            c,
            &[
                "path",
                "permissionProfile",
                "role",
                "sha256",
                "size",
                "version",
            ],
        )
        .is_none()
    }) {
        return Err(VerificationError::BundleManifest);
    }
    let b: BundleManifest =
        serde_json::from_value(v).map_err(|_| VerificationError::BundleManifest)?;
    if b.kind != "enoki-probe-bundle"
        || b.target != a.target
        || b.version != version
        || b.components.len() != BUNDLE_COMPONENTS.len()
        || b.bootstrap_assets.len() != BUNDLED_BOOTSTRAP_ASSETS.len()
    {
        return Err(VerificationError::BundleManifest);
    }
    for (path, permission_profile, resource_contract, role) in BUNDLE_COMPONENTS {
        let matches = b
            .components
            .iter()
            .filter(|component| component.role == role)
            .collect::<Vec<_>>();
        let [component] = matches.as_slice() else {
            return Err(VerificationError::BundleManifest);
        };
        if component.path != path
            || component.permission_profile != permission_profile
            || component.resource_contract.as_deref() != Some(resource_contract)
            || component.version != version
            || component.size == 0
            || component.size > MAX_COMPONENT_BYTES
            || !is_sha256_hex(&component.sha256)
        {
            return Err(VerificationError::BundleManifest);
        }
    }
    let probe = b
        .components
        .iter()
        .find(|component| component.role == "probe")
        .ok_or(VerificationError::BundleManifest)?;
    let probe_size = probe.size;
    for (path, permission_profile, role) in BUNDLED_BOOTSTRAP_ASSETS {
        let matches = b
            .bootstrap_assets
            .iter()
            .filter(|asset| asset.role == role)
            .collect::<Vec<_>>();
        let [asset] = matches.as_slice() else {
            return Err(VerificationError::BundleManifest);
        };
        if asset.path != path
            || asset.permission_profile != permission_profile
            || asset.version != version
            || asset.size == 0
            || asset.size > MAX_COMPONENT_BYTES
            || !is_sha256_hex(&asset.sha256)
        {
            return Err(VerificationError::BundleManifest);
        }
    }
    let mut roles = b.components;
    roles.extend(b.bootstrap_assets);
    Ok(VerifiedBundle {
        version: version.to_owned(),
        target: a.target.clone(),
        delegation_generation: generation,
        component_len: probe_size,
        bootstrap_assets: roles,
    })
}

#[cfg(feature = "acquirer")]
struct BoundedRead<R> {
    inner: R,
    total: u64,
}

#[cfg(feature = "acquirer")]
impl<R> BoundedRead<R> {
    fn new(inner: R) -> Self {
        Self { inner, total: 0 }
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

#[cfg(feature = "acquirer")]
impl<R: Read> Read for BoundedRead<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let remaining = MAX_UNCOMPRESSED_ARCHIVE_BYTES.saturating_sub(self.total);
        if remaining == 0 {
            return Err(std::io::Error::other("uncompressed archive exceeds limit"));
        }
        let maximum = output.len().min(remaining as usize);
        let read = self.inner.read(&mut output[..maximum])?;
        self.total = self.total.saturating_add(read as u64);
        Ok(read)
    }
}

#[cfg(feature = "acquirer")]
fn require_exact_gzip_and_tar_eof(
    mut bounded: BoundedRead<GzDecoder<BufReader<&mut File>>>,
) -> Result<(), VerificationError> {
    let mut byte = [0_u8; 1];
    // tar-rs stops at the first all-zero EOF record. The POSIX terminator is
    // exactly one additional zero record; accepting more would make trailing
    // tar bytes ambiguous.
    let mut remaining_zero_record = 512;
    while remaining_zero_record > 0 {
        let take = remaining_zero_record.min(byte.len());
        let read = bounded
            .read(&mut byte[..take])
            .map_err(|_| VerificationError::ArchiveStructure)?;
        if read == 0 || byte[..read].iter().any(|byte| *byte != 0) {
            return Err(VerificationError::ArchiveStructure);
        }
        remaining_zero_record -= read;
    }
    if bounded
        .read(&mut byte)
        .map_err(|_| VerificationError::ArchiveStructure)?
        != 0
    {
        return Err(VerificationError::ArchiveStructure);
    }
    let decoder = bounded.into_inner();
    let mut source = decoder.into_inner();
    // `bufread::GzDecoder` leaves bytes after its sole member in this buffer.
    // Reject rather than silently accepting concatenated members or garbage.
    if !source
        .fill_buf()
        .map_err(|_| VerificationError::ArchiveStructure)?
        .is_empty()
    {
        return Err(VerificationError::ArchiveStructure);
    }
    if source
        .read(&mut byte)
        .map_err(|_| VerificationError::ArchiveStructure)?
        != 0
    {
        return Err(VerificationError::ArchiveStructure);
    }
    Ok(())
}
fn canonical_public_key(bytes: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(bytes).ok()?;
    RsaPublicKey::from_public_key_pem(s)
        .ok()?
        .to_public_key_pem(LineEnding::LF)
        .ok()
        .map(String::into_bytes)
}
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn is_sha256_hex(x: &str) -> bool {
    x.len() == 64
        && x.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn safe_target(x: &str) -> bool {
    !x.is_empty()
        && x.len() <= 128
        && x.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}
fn is_semver(x: &str) -> bool {
    let mut p = x.split('.');
    matches!((p.next(),p.next(),p.next(),p.next()),(Some(a),Some(b),Some(c),None)if[a,b,c].into_iter().all(|x|!x.is_empty()&&x.bytes().all(|b|b.is_ascii_digit())&&(x=="0"||!x.starts_with('0'))))
}
fn exact(v: &Value, keys: &[&str]) -> Option<()> {
    let o = v.as_object()?;
    (o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k))).then_some(())
}
fn canonical_json<T: Serialize>(x: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut b = serde_json::to_vec(x)?;
    b.push(b'\n');
    Ok(b)
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningIdentity {
    algorithm: String,
    key_id: String,
    public_key_pem: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Delegation {
    distribution: String,
    generation: u64,
    kind: String,
    purpose: String,
    root_key_id: String,
    schema_version: u64,
    signing_identity: SigningIdentity,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestSignature {
    algorithm: String,
    delegation_generation: u64,
    delegation_key_id: String,
    file: String,
    public_key: String,
}
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Asset {
    bundle_manifest_sha256: String,
    file: String,
    sha256: String,
    size: u64,
    target: String,
}
#[derive(Deserialize)]
struct AssetManifest {
    assets: Vec<Asset>,
    kind: String,
    signature: ManifestSignature,
    version: String,
}
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BundleComponent {
    path: String,
    permission_profile: String,
    #[serde(default)]
    resource_contract: Option<String>,
    role: String,
    sha256: String,
    size: u64,
    version: String,
}
#[derive(Deserialize)]
struct BundleManifest {
    #[serde(default, rename = "bootstrapAssets")]
    bootstrap_assets: Vec<BundleComponent>,
    components: Vec<BundleComponent>,
    kind: String,
    target: String,
    version: String,
}

#[cfg(all(test, feature = "acquirer"))]
mod tests {
    use super::*;
    use flate2::{Compression, read::GzDecoder as ReadGzDecoder, write::GzEncoder};
    use rsa::{
        RsaPrivateKey,
        pkcs1v15::SigningKey,
        pkcs8::EncodePublicKey,
        rand_core::OsRng,
        signature::{RandomizedSigner, SignatureEncoding},
    };
    use std::{fs::File, io::Write, path::Path, process::Command};
    use tar::{Builder, Header};
    use tempfile::{NamedTempFile, tempdir};
    const TARGET: &str = "x86_64-unknown-linux-gnu";
    struct Fixture {
        archive: NamedTempFile,
        daily: RsaPrivateKey,
        h: Handoff,
        root: Vec<u8>,
        fingerprint: String,
    }
    impl Fixture {
        fn policy(&self, high: u64) -> VerificationPolicy<'_> {
            VerificationPolicy {
                distribution: "enoki",
                expected_target: TARGET,
                highest_accepted_delegation_generation: high,
                external_root_fingerprint: self.fingerprint.clone(),
                external_root_pem: Some(&self.root),
            }
        }
        fn open(&self) -> File {
            self.archive.reopen().unwrap()
        }
    }
    fn fixture() -> Fixture {
        let mut rng = OsRng;
        let root = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let daily = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let root_pem = root
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .into_bytes();
        let daily_pem = daily
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .into_bytes();
        let payload = b"probe".to_vec();
        let runtime = b"runtime".to_vec();
        let cpu_provider = b"system-state-provider".to_vec();
        let disk_health_provider = b"disk-health-provider".to_vec();
        let acquirer = b"acquirer".to_vec();
        let activator = b"activator".to_vec();
        let bundle=format!("{{\"bootstrapAssets\":[{{\"path\":\"bootstrap/enoki-probe-bootstrap-acquire\",\"permissionProfile\":\"bootstrap-acquirer-v1\",\"role\":\"bootstrap-acquirer\",\"sha256\":\"{}\",\"size\":{},\"version\":\"1.2.3\"}},{{\"path\":\"bootstrap/enoki-probe-bootstrap-activate\",\"permissionProfile\":\"bootstrap-activator-v1\",\"role\":\"bootstrap-activator\",\"sha256\":\"{}\",\"size\":{},\"version\":\"1.2.3\"}}],\"components\":[{{\"path\":\"enoki-probe\",\"permissionProfile\":\"probe-v3\",\"resourceContract\":\"hub-reporting-v1\",\"role\":\"probe\",\"sha256\":\"{}\",\"size\":5,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-observation-runtime\",\"permissionProfile\":\"observation-runtime-v3\",\"resourceContract\":\"official-observation-v2\",\"role\":\"observation-runtime\",\"sha256\":\"{}\",\"size\":{},\"version\":\"1.2.3\"}},{{\"path\":\"enoki-cpu-resource-provider\",\"permissionProfile\":\"system-state-provider-v5\",\"resourceContract\":\"system-state-v3\",\"role\":\"system-state-provider\",\"sha256\":\"{}\",\"size\":{},\"version\":\"1.2.3\"}},{{\"path\":\"enoki-disk-health-resource-provider\",\"permissionProfile\":\"disk-health-provider-v3\",\"resourceContract\":\"disk-health-v1\",\"role\":\"disk-health-provider\",\"sha256\":\"{}\",\"size\":{},\"version\":\"1.2.3\"}}],\"kind\":\"enoki-probe-bundle\",\"target\":\"{TARGET}\",\"version\":\"1.2.3\"}}\n",sha256_hex(&acquirer),acquirer.len(),sha256_hex(&activator),activator.len(),sha256_hex(&payload),sha256_hex(&runtime),runtime.len(),sha256_hex(&cpu_provider),cpu_provider.len(),sha256_hex(&disk_health_provider),disk_health_provider.len()).into_bytes();
        let gzip = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = Builder::new(gzip);
        for (name, data, kind) in [
            ("bundle-manifest.json", bundle.clone(), b'0'),
            ("enoki-probe", payload, b'0'),
            ("enoki-observation-runtime", runtime, b'0'),
            ("enoki-cpu-resource-provider", cpu_provider, b'0'),
            (
                "enoki-disk-health-resource-provider",
                disk_health_provider,
                b'0',
            ),
            ("bootstrap/enoki-probe-bootstrap-acquire", acquirer, b'0'),
            ("bootstrap/enoki-probe-bootstrap-activate", activator, b'0'),
        ] {
            let mut h = Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o600);
            h.set_entry_type(tar::EntryType::new(kind));
            h.set_cksum();
            tar.append_data(&mut h, name, &data[..]).unwrap();
        }
        let archive = tar.into_inner().unwrap().finish().unwrap();
        let delegation = Delegation {
            distribution: "enoki".into(),
            generation: 1,
            kind: "enoki-probe-trust-delegation".into(),
            purpose: "probe-asset-signing".into(),
            root_key_id: sha256_hex(&root_pem),
            schema_version: 1,
            signing_identity: SigningIdentity {
                algorithm: "rsa-sha256".into(),
                key_id: sha256_hex(&daily_pem),
                public_key_pem: String::from_utf8(daily_pem.clone()).unwrap(),
            },
        };
        let delegation_bytes = canonical_json(&delegation).unwrap();
        let mut signed = DELEGATION_DOMAIN.to_vec();
        signed.extend_from_slice(&delegation_bytes);
        let ds = SigningKey::<Sha256>::new(root)
            .sign_with_rng(&mut rng, &signed)
            .to_vec();
        let manifest=format!("{{\"assets\":[{{\"bundleManifestSha256\":\"{}\",\"file\":\"enoki-probe-{TARGET}.tar.gz\",\"sha256\":\"{}\",\"size\":{},\"target\":\"{TARGET}\"}}],\"kind\":\"enoki-probe-assets\",\"signature\":{{\"algorithm\":\"rsa-sha256\",\"delegationGeneration\":1,\"delegationKeyId\":\"{}\",\"file\":\"manifest.json.sig\",\"publicKey\":\"signing-key.pem\"}},\"version\":\"1.2.3\"}}\n",sha256_hex(&bundle),sha256_hex(&archive),archive.len(),delegation.signing_identity.key_id).into_bytes();
        let ms = SigningKey::<Sha256>::new(daily.clone())
            .sign_with_rng(&mut rng, &manifest)
            .to_vec();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&archive).unwrap();
        Fixture {
            archive: f,
            daily,
            h: Handoff {
                delegation: delegation_bytes,
                delegation_signature: ds,
                manifest,
                manifest_signature: ms,
                signing_key: daily_pem,
                bundle_manifest: bundle,
            },
            fingerprint: sha256_hex(&root_pem),
            root: root_pem,
        }
    }

    fn replace_archive(x: &mut Fixture, archive: Vec<u8>) {
        x.archive.as_file_mut().set_len(0).unwrap();
        x.archive.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        x.archive.as_file_mut().write_all(&archive).unwrap();
        x.archive.as_file_mut().sync_all().unwrap();
        let daily_id = sha256_hex(&x.h.signing_key);
        x.h.manifest = format!(
            "{{\"assets\":[{{\"bundleManifestSha256\":\"{}\",\"file\":\"enoki-probe-{TARGET}.tar.gz\",\"sha256\":\"{}\",\"size\":{},\"target\":\"{TARGET}\"}}],\"kind\":\"enoki-probe-assets\",\"signature\":{{\"algorithm\":\"rsa-sha256\",\"delegationGeneration\":1,\"delegationKeyId\":\"{daily_id}\",\"file\":\"manifest.json.sig\",\"publicKey\":\"signing-key.pem\"}},\"version\":\"1.2.3\"}}\n",
            sha256_hex(&x.h.bundle_manifest), sha256_hex(&archive), archive.len()
        ).into_bytes();
        let mut rng = OsRng;
        x.h.manifest_signature = SigningKey::<Sha256>::new(x.daily.clone())
            .sign_with_rng(&mut rng, &x.h.manifest)
            .to_vec();
    }

    fn replace_authenticated_archive(x: &mut Fixture, archive: Vec<u8>) -> VerifiedMetadata {
        let mut metadata = verify_metadata(&x.h, &x.policy(0)).unwrap();
        metadata.asset.sha256 = sha256_hex(&archive);
        metadata.asset.size = archive.len() as u64;
        replace_archive(x, archive);
        metadata
    }

    fn raw_archive_with_extra(name: &str, kind: u8) -> Vec<u8> {
        let gzip = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = Builder::new(gzip);
        let mut header = Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::new(kind));
        header.set_cksum();
        tar.append_data(&mut header, name, &[][..]).unwrap();
        tar.into_inner().unwrap().finish().unwrap()
    }

    fn raw_archive_is_rejected(bytes: &[u8]) -> bool {
        let mut archive = NamedTempFile::new().unwrap();
        archive.write_all(bytes).unwrap();
        let mut archive = archive.reopen().unwrap();
        let mut tar = Archive::new(BoundedRead::new(GzDecoder::new(BufReader::new(
            &mut archive,
        ))));
        let result = (|| {
            for entry in tar
                .entries()
                .map_err(|_| VerificationError::ArchiveStructure)?
                .raw(true)
            {
                let mut entry = entry.map_err(|_| VerificationError::ArchiveStructure)?;
                if !entry.header().entry_type().is_file() {
                    return Err(VerificationError::ArchiveStructure);
                }
                std::io::copy(&mut entry, &mut std::io::sink())
                    .map_err(|_| VerificationError::ArchiveStructure)?;
            }
            require_exact_gzip_and_tar_eof(tar.into_inner())
        })();
        result.is_err()
    }

    #[test]
    fn accepts_only_the_two_fixed_bootstrap_entries_in_the_signed_bundle_manifest() {
        let asset = Asset {
            bundle_manifest_sha256: "a".repeat(64),
            file: format!("enoki-probe-{TARGET}.tar.gz"),
            sha256: "b".repeat(64),
            size: 1,
            target: TARGET.to_owned(),
        };
        let manifest = format!(
            "{{\"bootstrapAssets\":[{{\"path\":\"bootstrap/enoki-probe-bootstrap-acquire\",\"permissionProfile\":\"bootstrap-acquirer-v1\",\"role\":\"bootstrap-acquirer\",\"sha256\":\"{}\",\"size\":1,\"version\":\"1.2.3\"}},{{\"path\":\"bootstrap/enoki-probe-bootstrap-activate\",\"permissionProfile\":\"bootstrap-activator-v1\",\"role\":\"bootstrap-activator\",\"sha256\":\"{}\",\"size\":1,\"version\":\"1.2.3\"}}],\"components\":[{{\"path\":\"enoki-probe\",\"permissionProfile\":\"probe-v3\",\"resourceContract\":\"hub-reporting-v1\",\"role\":\"probe\",\"sha256\":\"{}\",\"size\":5,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-observation-runtime\",\"permissionProfile\":\"observation-runtime-v3\",\"resourceContract\":\"official-observation-v2\",\"role\":\"observation-runtime\",\"sha256\":\"{}\",\"size\":7,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-cpu-resource-provider\",\"permissionProfile\":\"system-state-provider-v5\",\"resourceContract\":\"system-state-v3\",\"role\":\"system-state-provider\",\"sha256\":\"{}\",\"size\":12,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-disk-health-resource-provider\",\"permissionProfile\":\"disk-health-provider-v3\",\"resourceContract\":\"disk-health-v1\",\"role\":\"disk-health-provider\",\"sha256\":\"{}\",\"size\":20,\"version\":\"1.2.3\"}}],\"kind\":\"enoki-probe-bundle\",\"target\":\"{TARGET}\",\"version\":\"1.2.3\"}}\n",
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            "5".repeat(64),
            "6".repeat(64),
        );

        assert!(verify_bundle_manifest(manifest.as_bytes(), "1.2.3", &asset, 1).is_ok());

        let mixed_contract = manifest.replace("system-state-v3", "cpu-counters-v1");
        assert!(
            verify_bundle_manifest(mixed_contract.as_bytes(), "1.2.3", &asset, 1).is_err(),
            "a current manifest must reject the legacy CPU-only provider contract",
        );
        let mixed_permission_profile =
            manifest.replace("system-state-provider-v5", "system-state-provider-v3");
        assert!(
            verify_bundle_manifest(mixed_permission_profile.as_bytes(), "1.2.3", &asset, 1)
                .is_err(),
            "当前清单不得接受旧 Provider sandbox profile",
        );
    }

    #[test]
    fn rejects_the_runtime_only_packager_output_until_bootstrap_roles_are_composed() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let temporary = tempdir().unwrap();
        let binary = test_probe_elf();
        let binary_path = temporary.path().join("probe");
        std::fs::write(&binary_path, &binary).unwrap();
        std::fs::write(temporary.path().join("enoki-observation-runtime"), &binary).unwrap();
        std::fs::write(
            temporary.path().join("enoki-cpu-resource-provider"),
            &binary,
        )
        .unwrap();
        std::fs::write(
            temporary.path().join("enoki-disk-health-resource-provider"),
            &binary,
        )
        .unwrap();
        let output_dir = temporary.path().join("output");
        let status = Command::new("node")
            .arg(workspace.join("scripts/release-candidate.mjs"))
            .args([
                "package-probe",
                "--binary",
                binary_path.to_str().unwrap(),
                "--output-dir",
                output_dir.to_str().unwrap(),
                "--source-date-epoch",
                "1234567890",
                "--target",
                TARGET,
                "--version",
                "v1.2.3",
            ])
            .status()
            .unwrap();
        assert!(status.success());

        let archive_path = output_dir.join(format!("enoki-probe-{TARGET}.tar.gz"));
        let archive_bytes = std::fs::read(&archive_path).unwrap();
        let mut archive = File::open(&archive_path).unwrap();
        let bundle_manifest = read_bundle_manifest(&mut archive).unwrap();
        let asset = Asset {
            bundle_manifest_sha256: sha256_hex(&bundle_manifest),
            file: format!("enoki-probe-{TARGET}.tar.gz"),
            sha256: sha256_hex(&archive_bytes),
            size: archive_bytes.len() as u64,
            target: TARGET.to_owned(),
        };
        assert_eq!(
            verify_bundle_manifest(&bundle_manifest, "1.2.3", &asset, 1),
            Err(VerificationError::BundleManifest)
        );
    }

    #[test]
    fn rejects_nonzero_tar_trailing_bytes_and_concatenated_gzip() {
        let mut tar_bytes = Vec::new();
        ReadGzDecoder::new(fixture().open())
            .read_to_end(&mut tar_bytes)
            .unwrap();
        tar_bytes.push(1);
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(&tar_bytes).unwrap();
        let malformed = gzip.finish().unwrap();
        let mut x = fixture();
        let metadata = replace_authenticated_archive(&mut x, malformed);
        assert_eq!(
            verify_archive_and_extract(&mut x.open(), &x.h, &metadata, &mut Vec::new()),
            Err(VerificationError::ArchiveStructure)
        );

        let mut extra_member = GzEncoder::new(Vec::new(), Compression::default());
        extra_member.write_all(b"extra gzip member").unwrap();
        let mut concatenated = Vec::new();
        fixture().open().read_to_end(&mut concatenated).unwrap();
        concatenated.extend(extra_member.finish().unwrap());
        let mut x = fixture();
        let metadata = replace_authenticated_archive(&mut x, concatenated);
        assert_eq!(
            verify_archive_and_extract(&mut x.open(), &x.h, &metadata, &mut Vec::new()),
            Err(VerificationError::ArchiveStructure)
        );
    }

    fn test_probe_elf() -> Vec<u8> {
        let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
        let marker = format!("ENOKI_PROBE_TARGET={TARGET}\0ENOKI_PROBE_VERSION=v1.2.3\0");
        let header_size = 64_usize;
        let program_header_size = 56_usize;
        let mut binary =
            vec![0; header_size + program_header_size + interpreter.len() + marker.len()];
        binary[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        binary[16..18].copy_from_slice(&2_u16.to_le_bytes());
        binary[18..20].copy_from_slice(&62_u16.to_le_bytes());
        binary[20..24].copy_from_slice(&1_u32.to_le_bytes());
        binary[32..40].copy_from_slice(&(header_size as u64).to_le_bytes());
        binary[52..54].copy_from_slice(&(header_size as u16).to_le_bytes());
        binary[54..56].copy_from_slice(&(program_header_size as u16).to_le_bytes());
        binary[56..58].copy_from_slice(&1_u16.to_le_bytes());
        binary[header_size..header_size + 4].copy_from_slice(&3_u32.to_le_bytes());
        binary[header_size + 4..header_size + 8].copy_from_slice(&4_u32.to_le_bytes());
        binary[header_size + 8..header_size + 16]
            .copy_from_slice(&((header_size + program_header_size) as u64).to_le_bytes());
        binary[header_size + 32..header_size + 40]
            .copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
        binary[header_size + 40..header_size + 48]
            .copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
        let interpreter_start = header_size + program_header_size;
        binary[interpreter_start..interpreter_start + interpreter.len()]
            .copy_from_slice(interpreter);
        binary[interpreter_start + interpreter.len()..].copy_from_slice(marker.as_bytes());
        binary
    }

    #[test]
    fn authenticates_exact_bundle_bytes_and_extracts_component() {
        let x = fixture();
        assert!(
            verify_outer_metadata(&x.h, &x.policy(1)).is_ok(),
            "{:?}",
            verify_outer_metadata(&x.h, &x.policy(1))
        );
        let m = verify_metadata(&x.h, &x.policy(1)).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            verify_archive_and_extract(&mut x.open(), &x.h, &m, &mut out),
            Ok(m.bundle().clone())
        );
        assert_eq!(out, b"probe");
    }
    #[test]
    fn rejects_outer_bundle_hash_and_nonpositive_component() {
        let mut x = fixture();
        x.h.bundle_manifest[0] ^= 1;
        assert_eq!(
            verify_metadata(&x.h, &x.policy(0)),
            Err(VerificationError::BundleManifest)
        );
        let mut x = fixture();
        x.h.bundle_manifest = String::from_utf8(x.h.bundle_manifest)
            .unwrap()
            .replace("\"size\":5", "\"size\":0")
            .into_bytes();
        assert_eq!(
            verify_metadata(&x.h, &x.policy(0)),
            Err(VerificationError::BundleManifest)
        );
    }
    #[test]
    fn rejects_archive_links_extensions_specials_and_extra_paths() {
        for e in [
            ("link", b'2'),
            ("fifo", b'6'),
            // `raw(true)` makes GNU/PAX extension members visible rather
            // than applying them to an innocent-looking following member.
            ("gnu-long-name", b'L'),
            ("gnu-long-link", b'K'),
            ("pax", b'x'),
            ("global-pax", b'g'),
            ("sparse", b'S'),
        ] {
            assert!(
                raw_archive_is_rejected(&raw_archive_with_extra(e.0, e.1)),
                "{}",
                e.0
            );
        }
        let mut x = fixture();
        replace_archive(&mut x, raw_archive_with_extra("extra", b'0'));
        let metadata = verify_metadata(&x.h, &x.policy(0)).unwrap();
        assert_eq!(
            verify_archive_and_extract(&mut x.open(), &x.h, &metadata, &mut Vec::new(),),
            Err(VerificationError::ArchiveStructure)
        );
    }
    #[test]
    fn root_rechecks_component_digest() {
        let x = fixture();
        let m = verify_metadata(&x.h, &x.policy(0)).unwrap();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"wrong").unwrap();
        assert_eq!(
            verify_component(f.as_file_mut(), &x.h, m.bundle()),
            Err(VerificationError::Component)
        );
    }

    #[test]
    fn root_rechecks_the_exact_running_activator_receipt() {
        let vector = fixture();
        let metadata = verify_metadata(&vector.h, &vector.policy(0)).unwrap();
        let mut exact = NamedTempFile::new().unwrap();
        exact.write_all(b"activator").unwrap();
        assert_eq!(
            verify_activator_receipt(exact.as_file_mut(), metadata.bundle()),
            Ok(())
        );

        let mut absent = NamedTempFile::new().unwrap();
        absent.write_all(b"activate").unwrap();
        assert_eq!(
            verify_activator_receipt(absent.as_file_mut(), metadata.bundle()),
            Err(VerificationError::Component)
        );
    }
}

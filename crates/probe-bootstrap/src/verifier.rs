//! Offline trust verification.  Archive parsing is exposed only to the
//! unprivileged acquisition module; root activation verifies metadata and the
//! component bytes, never a compressed archive.
use crate::handoff::Handoff;
#[cfg(feature = "acquirer")]
use flate2::bufread::GzDecoder;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Signature as RsaSignature, VerifyingKey},
    pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding},
    signature::Verifier,
    traits::PublicKeyParts,
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
const COMPONENT_PATH: &str = "enoki-probe";
pub const MAX_COMPONENT_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(feature = "acquirer")]
const MAX_TAR_OVERHEAD_BYTES: u64 = 16 * 1024;
#[cfg(feature = "acquirer")]
const MAX_UNCOMPRESSED_ARCHIVE_BYTES: u64 =
    MAX_COMPONENT_BYTES + MAX_BUNDLE_MANIFEST_BYTES as u64 + MAX_TAR_OVERHEAD_BYTES;

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
    verify_archive_digest(archive, &metadata.asset)?;
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| VerificationError::Io)?;
    let mut tar = Archive::new(BoundedRead::new(GzDecoder::new(BufReader::new(archive))));
    let mut saw_manifest = false;
    let mut saw_component = false;
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
        } else if path.as_ref() == COMPONENT_PATH.as_bytes() {
            if saw_component || entry.size() != metadata.bundle.component_len {
                return Err(VerificationError::ArchiveStructure);
            }
            stream_component(
                &mut entry,
                sink,
                metadata.bundle.component_len,
                component_digest(&handoff.bundle_manifest)?,
            )?;
            saw_component = true;
        } else {
            return Err(VerificationError::ArchiveStructure);
        }
    }
    if !saw_manifest || !saw_component {
        return Err(VerificationError::ArchiveStructure);
    }
    require_exact_gzip_and_tar_eof(tar.into_inner())?;
    Ok(metadata.bundle.clone())
}

/// Root's independent post-copy check. This deliberately accepts only the
/// signed component length and digest, with no caller-supplied profile/mode.
pub fn verify_component(
    component: &mut File,
    handoff: &Handoff,
    bundle: &VerifiedBundle,
) -> Result<(), VerificationError> {
    let expected = component_digest(&handoff.bundle_manifest)?;
    let details = component.metadata().map_err(|_| VerificationError::Io)?;
    if details.len() != bundle.component_len || bundle.component_len == 0 {
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
    if total != bundle.component_len || format!("{:x}", hash.finalize()) != expected {
        return Err(VerificationError::Component);
    }
    component
        .seek(SeekFrom::Start(0))
        .map_err(|_| VerificationError::Io)?;
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
    if key.n().bits() != 4096 {
        return Err(VerificationError::RootFingerprint);
    }
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
    let signing_key = RsaPublicKey::from_public_key_pem(
        std::str::from_utf8(&signing).map_err(|_| VerificationError::Delegation)?,
    )
    .map_err(|_| VerificationError::Delegation)?;
    if signing_key.n().bits() != 4096 {
        return Err(VerificationError::Delegation);
    }
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

#[cfg(all(test, any(feature = "acquirer", feature = "activator")))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedHandoffVectors {
    root_public_key_pem: String,
    signing_public_key_pem: String,
    bundle_manifest_base64: String,
    #[cfg(feature = "acquirer")]
    archive_base64: String,
    generations: std::collections::BTreeMap<String, SignedHandoffGeneration>,
}

#[cfg(all(test, any(feature = "acquirer", feature = "activator")))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedHandoffGeneration {
    delegation_base64: String,
    delegation_signature_base64: String,
    manifest_base64: String,
    manifest_signature_base64: String,
}

#[cfg(all(test, feature = "acquirer"))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WeakDelegationVector {
    delegation_base64: String,
    delegation_signature_base64: String,
}

#[cfg(all(test, any(feature = "acquirer", feature = "activator")))]
pub(crate) struct SignedTestHandoff {
    #[cfg(feature = "acquirer")]
    pub(crate) archive: Vec<u8>,
    pub(crate) handoff: Handoff,
    pub(crate) root: Vec<u8>,
    #[cfg(feature = "activator")]
    pub(crate) root_fingerprint: String,
}

#[cfg(all(test, any(feature = "acquirer", feature = "activator")))]
pub(crate) fn signed_test_handoff(generation: u64) -> SignedTestHandoff {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::sync::LazyLock;

    static VECTORS: LazyLock<SignedHandoffVectors> = LazyLock::new(|| {
        serde_json::from_str(include_str!("../test-data/signed-handoff-vectors.json")).unwrap()
    });
    let vector = VECTORS.generations.get(&generation.to_string()).unwrap();
    let decode = |value: &str| STANDARD.decode(value).unwrap();
    let root = VECTORS.root_public_key_pem.as_bytes().to_vec();
    SignedTestHandoff {
        #[cfg(feature = "acquirer")]
        archive: decode(&VECTORS.archive_base64),
        handoff: Handoff {
            delegation: decode(&vector.delegation_base64),
            delegation_signature: decode(&vector.delegation_signature_base64),
            manifest: decode(&vector.manifest_base64),
            manifest_signature: decode(&vector.manifest_signature_base64),
            signing_key: VECTORS.signing_public_key_pem.as_bytes().to_vec(),
            bundle_manifest: decode(&VECTORS.bundle_manifest_base64),
        },
        #[cfg(feature = "activator")]
        root_fingerprint: sha256_hex(&root),
        root,
    }
}

#[cfg(all(test, feature = "acquirer"))]
fn weak_delegation_test_vector() -> (Vec<u8>, Vec<u8>) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let vector: WeakDelegationVector =
        serde_json::from_str(include_str!("../test-data/weak-delegation-vector.json")).unwrap();
    (
        STANDARD.decode(vector.delegation_base64).unwrap(),
        STANDARD.decode(vector.delegation_signature_base64).unwrap(),
    )
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
    exact(&v, &["components", "kind", "target", "version"])
        .ok_or(VerificationError::BundleManifest)?;
    let components = v
        .get("components")
        .and_then(Value::as_array)
        .ok_or(VerificationError::BundleManifest)?;
    if components.iter().any(|c| {
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
        || b.components.len() != 1
    {
        return Err(VerificationError::BundleManifest);
    }
    let c = &b.components[0];
    if c.role != "probe"
        || c.path != COMPONENT_PATH
        || c.permission_profile != "probe-v1"
        || c.version != version
        || c.size == 0
        || c.size > MAX_COMPONENT_BYTES
        || !is_sha256_hex(&c.sha256)
    {
        return Err(VerificationError::BundleManifest);
    }
    Ok(VerifiedBundle {
        version: version.to_owned(),
        target: a.target.clone(),
        delegation_generation: generation,
        component_len: c.size,
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
fn component_digest(bytes: &[u8]) -> Result<String, VerificationError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| VerificationError::BundleManifest)?;
    let b: BundleManifest =
        serde_json::from_value(v).map_err(|_| VerificationError::BundleManifest)?;
    b.components
        .first()
        .map(|c| c.sha256.clone())
        .ok_or(VerificationError::BundleManifest)
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
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleComponent {
    path: String,
    permission_profile: String,
    role: String,
    sha256: String,
    size: u64,
    version: String,
}
#[derive(Deserialize)]
struct BundleManifest {
    components: Vec<BundleComponent>,
    kind: String,
    target: String,
    version: String,
}

#[cfg(all(test, feature = "acquirer"))]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use rsa::{RsaPrivateKey, pkcs8::EncodePublicKey, rand_core::OsRng};
    use std::{fs::File, io::Write};
    use tar::{Builder, Header};
    use tempfile::NamedTempFile;
    const TARGET: &str = "x86_64-unknown-linux-gnu";
    struct Fixture {
        archive: NamedTempFile,
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
        let vector = signed_test_handoff(1);
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&vector.archive).unwrap();
        Fixture {
            archive: f,
            h: vector.handoff,
            fingerprint: sha256_hex(&vector.root),
            root: vector.root,
        }
    }

    fn replace_archive(x: &mut Fixture, archive: Vec<u8>) {
        x.archive.as_file_mut().set_len(0).unwrap();
        x.archive.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        x.archive.as_file_mut().write_all(&archive).unwrap();
        x.archive.as_file_mut().sync_all().unwrap();
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
    fn rejects_a_weak_rsa_distribution_root_before_delegation_verification() {
        let mut rng = OsRng;
        let weak = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let weak_pem = weak
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .into_bytes();
        let policy = VerificationPolicy {
            distribution: "enoki",
            expected_target: TARGET,
            highest_accepted_delegation_generation: 0,
            external_root_fingerprint: sha256_hex(&weak_pem),
            external_root_pem: Some(&weak_pem),
        };

        assert!(matches!(
            trusted_root(&policy),
            Err(VerificationError::RootFingerprint)
        ));
    }
    #[test]
    fn rejects_a_validly_root_signed_weak_delegated_key() {
        let mut x = fixture();
        (x.h.delegation, x.h.delegation_signature) = weak_delegation_test_vector();

        assert!(matches!(
            verify_outer_metadata(&x.h, &x.policy(0)),
            Err(VerificationError::Delegation)
        ));
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
        let mut metadata = verify_metadata(&x.h, &x.policy(0)).unwrap();
        let malformed = raw_archive_with_extra("extra", b'0');
        metadata.asset.sha256 = sha256_hex(&malformed);
        metadata.asset.size = malformed.len() as u64;
        replace_archive(&mut x, malformed);
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
}

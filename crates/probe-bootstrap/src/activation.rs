//! Root-only component receiver. It deliberately imports neither archive nor
//! network code: unprivileged acquisition owns gzip/tar/HTTP parsing.
use crate::{
    generation::{DelegationGenerationLease, GenerationStateError, acquire_delegation_generation},
    handoff::{Enrollment, Handoff, HandoffError},
    install::{
        FixedInstallPaths, InstallError, SystemAccounts, SystemSystemd,
        VerifiedCompleteFreshComponents, activate_complete_fresh_current_probe,
    },
    trust::{BootstrapRole, embedded_production_trust_for},
    verifier::{
        VerificationPolicy, VerifiedBundle, verify_acquirer_receipt, verify_activator_receipt,
        verify_component, verify_metadata, verify_role_component,
    },
};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroize;

const INBOX_DIRECTORY: &str = "inbox";
static COMPONENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Eq, PartialEq)]
pub enum ActivationError {
    BuildTrustUnavailable,
    Generation(GenerationStateError),
    Handoff(HandoffError),
    NotRoot,
    Verification,
    Io,
    Install(InstallError),
}

impl From<HandoffError> for ActivationError {
    fn from(error: HandoffError) -> Self {
        Self::Handoff(error)
    }
}

impl From<GenerationStateError> for ActivationError {
    fn from(error: GenerationStateError) -> Self {
        Self::Generation(error)
    }
}

/// An unlinked root-private verified component and the exclusive delegation
/// generation lease that authorized it. The lease remains held until this
/// value is dropped after activation completes.
pub struct ReceivedRootHandoff {
    pub handoff: Handoff,
    pub bundle: VerifiedBundle,
    component: File,
    runtime: File,
    cpu_provider: File,
    disk_health_provider: File,
    acquirer: Option<File>,
    activator: Option<File>,
    enrollment: Enrollment,
    _generation_lease: DelegationGenerationLease,
}

impl ReceivedRootHandoff {
    /// The only consumption boundary for a verified candidate. It keeps the
    /// component descriptor, enrollment capability, and generation lease in
    /// one owner until the fixed local lifecycle adapter returns.
    pub fn activate_with<T>(
        mut self,
        adapter: impl FnOnce(&mut File, &Enrollment, &VerifiedBundle) -> Result<T, ActivationError>,
    ) -> Result<T, ActivationError> {
        self.component()?;
        validate_received_role(&mut self.runtime, &self.bundle, "observation-runtime")?;
        validate_received_role(
            &mut self.cpu_provider,
            &self.bundle,
            "system-state-provider",
        )?;
        validate_received_role(
            &mut self.disk_health_provider,
            &self.bundle,
            "disk-health-provider",
        )?;
        adapter(&mut self.component, &self.enrollment, &self.bundle)
    }

    /// Production's closed activation route. It owns the generation lease
    /// through the complete filesystem and systemd transaction; neither stdin
    /// nor a candidate component selects an installer command or path.
    pub fn activate_fixed_current_probe(mut self) -> Result<(), ActivationError> {
        let trust = embedded_production_trust_for(BootstrapRole::Activator)
            .ok_or(ActivationError::BuildTrustUnavailable)?;
        let mut accounts = SystemAccounts::default();
        let mut systemd = SystemSystemd::default();
        self.component()?;
        let acquirer = self
            .acquirer
            .as_mut()
            .ok_or(ActivationError::Verification)?;
        let activator = self
            .activator
            .as_mut()
            .ok_or(ActivationError::Verification)?;
        activate_complete_fresh_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut self.component,
                observation_runtime: &mut self.runtime,
                cpu_provider: &mut self.cpu_provider,
                disk_health_provider: &mut self.disk_health_provider,
                bootstrap_acquirer: acquirer,
                bootstrap_activator: activator,
            },
            &self.enrollment,
            &self.bundle,
            &trust,
            &FixedInstallPaths::production(),
            &mut accounts,
            &mut systemd,
        )
        .map_err(ActivationError::Install)
    }
    pub fn component(&mut self) -> Result<&mut File, ActivationError> {
        validate_regular_file(&self.component, 0, 0o600)?;
        let metadata = self.component.metadata().map_err(|_| ActivationError::Io)?;
        if metadata.len() != self.bundle.component_len {
            return Err(ActivationError::Io);
        }
        self.component
            .seek(SeekFrom::Start(0))
            .map_err(|_| ActivationError::Io)?;
        Ok(&mut self.component)
    }
}

impl Drop for ReceivedRootHandoff {
    fn drop(&mut self) {
        self.enrollment.zeroize();
    }
}

fn validate_received_role(
    component: &mut File,
    bundle: &VerifiedBundle,
    role: &str,
) -> Result<(), ActivationError> {
    validate_regular_file(component, 0, 0o600)?;
    verify_role_component(component, bundle, role).map_err(|_| ActivationError::Verification)
}

/// Root orchestration boundary. The caller must construct `policy` only from
/// build-fixed distribution trust; no rollback floor is accepted from stdin.
#[allow(dead_code)]
pub(crate) fn receive_root_handoff_with_policy(
    input: &mut impl Read,
    policy: &VerificationPolicy<'_>,
) -> Result<ReceivedRootHandoff, ActivationError> {
    receive_root_handoff(
        input,
        policy,
        0,
        |candidate| acquire_delegation_generation(candidate).map_err(ActivationError::from),
        None,
    )
}

/// Root-only production receiver. It has no arguments other than stdin and
/// obtains every trust value from the compiled Bootstrap identity.
pub fn activate_from_stdin(input: &mut impl Read) -> Result<ReceivedRootHandoff, ActivationError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ActivationError::NotRoot);
    }
    let trust = embedded_production_trust_for(BootstrapRole::Activator)
        .ok_or(ActivationError::BuildTrustUnavailable)?;
    receive_root_handoff_with_policy(
        input,
        &VerificationPolicy {
            distribution: trust.distribution,
            expected_target: trust.target,
            highest_accepted_delegation_generation: 0,
            external_root_fingerprint: trust.root_fingerprint.to_owned(),
            external_root_pem: Some(trust.root_pem.as_bytes()),
        },
    )
}

/// 私有 socket 只承载 metadata/component handoff；fd 0 保留为 sudo 实际
/// 执行的 sealed activator receipt，并在任何 Host mutation 前复验。
pub fn activate_from_socket(
    input: &mut impl Read,
    activator_receipt: &mut File,
) -> Result<ReceivedRootHandoff, ActivationError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ActivationError::NotRoot);
    }
    let trust = embedded_production_trust_for(BootstrapRole::Activator)
        .ok_or(ActivationError::BuildTrustUnavailable)?;
    let policy = VerificationPolicy {
        distribution: trust.distribution,
        expected_target: trust.target,
        highest_accepted_delegation_generation: 0,
        external_root_fingerprint: trust.root_fingerprint.to_owned(),
        external_root_pem: Some(trust.root_pem.as_bytes()),
    };
    receive_root_handoff_with_receipt(input, &policy, activator_receipt)
}

fn receive_root_handoff_with_receipt(
    input: &mut impl Read,
    policy: &VerificationPolicy<'_>,
    activator_receipt: &mut File,
) -> Result<ReceivedRootHandoff, ActivationError> {
    receive_root_handoff(
        input,
        policy,
        0,
        |candidate| acquire_delegation_generation(candidate).map_err(ActivationError::from),
        Some(activator_receipt),
    )
}

fn receive_root_handoff(
    input: &mut impl Read,
    policy: &VerificationPolicy<'_>,
    expected_uid: u32,
    acquire_generation: impl FnOnce(u64) -> Result<DelegationGenerationLease, ActivationError>,
    mut activator_receipt: Option<&mut File>,
) -> Result<ReceivedRootHandoff, ActivationError> {
    let handoff = Handoff::read_metadata(input)?;

    // The first pass authenticates the root-signed candidate generation. It
    // deliberately ignores any caller-supplied floor; installed state is the
    // sole rollback authority.
    let initial_policy = VerificationPolicy {
        highest_accepted_delegation_generation: 0,
        ..policy.clone()
    };
    let initial =
        verify_metadata(&handoff, &initial_policy).map_err(|_| ActivationError::Verification)?;
    let mut generation_lease = acquire_generation(initial.bundle().delegation_generation)?;

    // Re-authenticate all metadata while holding the exclusive state lease and
    // using its root-owned rollback floor.
    let installed_policy = VerificationPolicy {
        highest_accepted_delegation_generation: generation_lease.current(),
        ..policy.clone()
    };
    let metadata =
        verify_metadata(&handoff, &installed_policy).map_err(|_| ActivationError::Verification)?;
    if let Some(receipt) = activator_receipt.as_deref_mut() {
        verify_activator_receipt(receipt, metadata.bundle())
            .map_err(|_| ActivationError::Verification)?;
    }
    // The enrollment capability is neither signed nor an authority to select
    // assets. It is consumed only after all signed metadata is authoritative.
    // A root-private component sink is staging only, never installed Host
    // state, so the generation floor must not advance until its exact content
    // has also been verified.
    let enrollment = Handoff::read_enrollment(input)?;

    let inbox = ensure_private_directory_at(
        generation_lease.state_directory().as_raw_fd(),
        INBOX_DIRECTORY,
        expected_uid,
    )?;
    let (temporary_name, mut component) = create_exclusive_component(&inbox, expected_uid)?;
    let (runtime_name, mut runtime) = create_exclusive_component(&inbox, expected_uid)?;
    let (cpu_provider_name, mut cpu_provider) = create_exclusive_component(&inbox, expected_uid)?;
    let (disk_health_provider_name, mut disk_health_provider) =
        create_exclusive_component(&inbox, expected_uid)?;
    let (acquirer_name, mut acquirer) = create_exclusive_component(&inbox, expected_uid)?;
    let (activator_name, mut activator) = create_exclusive_component(&inbox, expected_uid)?;
    let has_bootstrap_receipts = activator_receipt.is_some();
    let result = (|| {
        Handoff::read_component_into(input, &mut component, metadata.bundle().component_len)?;
        component.sync_all().map_err(|_| ActivationError::Io)?;
        verify_component(&mut component, &handoff, metadata.bundle())
            .map_err(|_| ActivationError::Verification)?;
        let (_, runtime_len) = metadata
            .bundle()
            .component_receipt("observation-runtime")
            .ok_or(ActivationError::Verification)?;
        Handoff::read_runtime_into(input, &mut runtime, runtime_len)?;
        runtime.sync_all().map_err(|_| ActivationError::Io)?;
        verify_role_component(&mut runtime, metadata.bundle(), "observation-runtime")
            .map_err(|_| ActivationError::Verification)?;
        let (_, cpu_provider_len) = metadata
            .bundle()
            .component_receipt("system-state-provider")
            .ok_or(ActivationError::Verification)?;
        Handoff::read_cpu_provider_into(input, &mut cpu_provider, cpu_provider_len)?;
        cpu_provider.sync_all().map_err(|_| ActivationError::Io)?;
        verify_role_component(
            &mut cpu_provider,
            metadata.bundle(),
            "system-state-provider",
        )
        .map_err(|_| ActivationError::Verification)?;
        let (_, disk_health_provider_len) = metadata
            .bundle()
            .component_receipt("disk-health-provider")
            .ok_or(ActivationError::Verification)?;
        Handoff::read_disk_health_provider_into(
            input,
            &mut disk_health_provider,
            disk_health_provider_len,
        )?;
        disk_health_provider
            .sync_all()
            .map_err(|_| ActivationError::Io)?;
        verify_role_component(
            &mut disk_health_provider,
            metadata.bundle(),
            "disk-health-provider",
        )
        .map_err(|_| ActivationError::Verification)?;
        if let Some(receipt) = activator_receipt {
            let (_, acquirer_len) = metadata
                .bundle()
                .acquirer_receipt()
                .ok_or(ActivationError::Verification)?;
            Handoff::read_acquirer_into(input, &mut acquirer, acquirer_len)?;
            acquirer.sync_all().map_err(|_| ActivationError::Io)?;
            verify_acquirer_receipt(&mut acquirer, metadata.bundle())
                .map_err(|_| ActivationError::Verification)?;
            receipt
                .seek(SeekFrom::Start(0))
                .map_err(|_| ActivationError::Io)?;
            let copied = std::io::copy(receipt, &mut activator).map_err(|_| ActivationError::Io)?;
            let (_, activator_len) = metadata
                .bundle()
                .activator_receipt()
                .ok_or(ActivationError::Verification)?;
            if copied != activator_len {
                return Err(ActivationError::Verification);
            }
            activator.sync_all().map_err(|_| ActivationError::Io)?;
            verify_activator_receipt(&mut activator, metadata.bundle())
                .map_err(|_| ActivationError::Verification)?;
        }
        component
            .seek(SeekFrom::Start(0))
            .map_err(|_| ActivationError::Io)?;
        unlink_at(inbox.as_raw_fd(), &temporary_name)?;
        unlink_at(inbox.as_raw_fd(), &runtime_name)?;
        unlink_at(inbox.as_raw_fd(), &cpu_provider_name)?;
        unlink_at(inbox.as_raw_fd(), &disk_health_provider_name)?;
        unlink_at(inbox.as_raw_fd(), &acquirer_name)?;
        unlink_at(inbox.as_raw_fd(), &activator_name)?;
        // The candidate has now passed every coherence, enrollment, exact
        // byte, digest, and EOF check. Persist immediately before returning
        // the sole object that can invoke a Host-mutating activation adapter.
        generation_lease.persist_before_mutation()?;
        Ok(ReceivedRootHandoff {
            handoff,
            bundle: metadata.bundle().clone(),
            component,
            runtime,
            cpu_provider,
            disk_health_provider,
            acquirer: has_bootstrap_receipts.then_some(acquirer),
            activator: has_bootstrap_receipts.then_some(activator),
            enrollment,
            _generation_lease: generation_lease,
        })
    })();
    if result.is_err() {
        let _ = unlink_at(inbox.as_raw_fd(), &temporary_name);
        let _ = unlink_at(inbox.as_raw_fd(), &runtime_name);
        let _ = unlink_at(inbox.as_raw_fd(), &cpu_provider_name);
        let _ = unlink_at(inbox.as_raw_fd(), &disk_health_provider_name);
        let _ = unlink_at(inbox.as_raw_fd(), &acquirer_name);
        let _ = unlink_at(inbox.as_raw_fd(), &activator_name);
    }
    result
}

fn ensure_private_directory_at(
    parent: RawFd,
    name: &str,
    expected_uid: u32,
) -> Result<File, ActivationError> {
    let name = c_string(name)?;
    let created = unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) } == 0;
    if !created {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(ActivationError::Io);
        }
    }
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let directory = file_from_descriptor(descriptor)?;
    if created && unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(ActivationError::Io);
    }
    validate_directory(&directory, expected_uid, 0o700)?;
    if created && unsafe { libc::fsync(parent) } != 0 {
        return Err(ActivationError::Io);
    }
    Ok(directory)
}

fn create_exclusive_component(
    inbox: &File,
    expected_uid: u32,
) -> Result<(CString, File), ActivationError> {
    for _ in 0..32 {
        let sequence = COMPONENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = c_string(&format!("component-{}-{sequence}", std::process::id()))?;
        let descriptor = unsafe {
            libc::openat(
                inbox.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor >= 0 {
            let file = file_from_descriptor(descriptor)?;
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                return Err(ActivationError::Io);
            }
            validate_regular_file(&file, expected_uid, 0o600)?;
            return Ok((name, file));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(ActivationError::Io);
        }
    }
    Err(ActivationError::Io)
}

fn validate_directory(
    file: &File,
    expected_uid: u32,
    mode: libc::mode_t,
) -> Result<(), ActivationError> {
    validate_file(file, expected_uid, libc::S_IFDIR, mode)
}

fn validate_regular_file(
    file: &File,
    expected_uid: u32,
    mode: libc::mode_t,
) -> Result<(), ActivationError> {
    validate_file(file, expected_uid, libc::S_IFREG, mode)
}

fn validate_file(
    file: &File,
    expected_uid: u32,
    expected_type: libc::mode_t,
    expected_mode: libc::mode_t,
) -> Result<(), ActivationError> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(ActivationError::Io);
    }
    let status = unsafe { status.assume_init() };
    if status.st_uid != expected_uid
        || status.st_mode & libc::S_IFMT != expected_type
        || status.st_mode & 0o7777 != expected_mode
    {
        return Err(ActivationError::Io);
    }
    Ok(())
}

fn unlink_at(directory: RawFd, name: &CString) -> Result<(), ActivationError> {
    if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } != 0 {
        return Err(ActivationError::Io);
    }
    Ok(())
}

fn file_from_descriptor(descriptor: RawFd) -> Result<File, ActivationError> {
    if descriptor < 0 {
        return Err(ActivationError::Io);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn c_string(value: &str) -> Result<CString, ActivationError> {
    CString::new(value).map_err(|_| ActivationError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generation::acquire_delegation_generation_for_test,
        handoff::{MAGIC, SCHEMA_VERSION},
    };
    use rsa::{
        RsaPrivateKey,
        pkcs1v15::SigningKey,
        pkcs8::{EncodePublicKey, LineEnding},
        rand_core::OsRng,
        signature::{RandomizedSigner, SignatureEncoding},
    };
    use sha2::{Digest, Sha256};
    use std::{fs, io::Cursor, os::unix::fs::PermissionsExt, sync::mpsc, thread, time::Duration};
    use tempfile::tempdir;

    #[test]
    fn rejects_invalid_metadata_before_creating_a_root_component() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut bytes = Vec::new();
        bytes.extend(MAGIC);
        bytes.extend(2u16.to_be_bytes());
        bytes.extend([7, 0]);
        let policy = invalid_policy();
        assert!(receive_for_test(&mut Cursor::new(bytes), &state_root, &policy).is_err());
        assert!(!state_root.join("inbox").exists());
    }

    #[test]
    fn inbox_symlink_fails_closed() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(temporary.path().join("outside"), state_root.join("inbox"))
            .unwrap();
        let state = File::open(&state_root).unwrap();
        assert!(
            ensure_private_directory_at(state.as_raw_fd(), INBOX_DIRECTORY, unsafe {
                libc::geteuid()
            })
            .is_err()
        );
    }

    #[test]
    fn rollback_is_rejected_before_a_component_sink_exists() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut installed = acquire_delegation_generation_for_test(&state_root, 2).unwrap();
        installed.persist_before_mutation().unwrap();
        drop(installed);
        let fixture = fixture(1);

        assert_eq!(
            receive_for_test(
                &mut Cursor::new(fixture.stream.as_slice()),
                &state_root,
                &fixture.policy()
            )
            .err(),
            Some(ActivationError::Generation(GenerationStateError::Rollback))
        );
        assert!(!state_root.join("inbox").exists());
    }

    #[test]
    fn same_generation_is_accepted_and_the_component_is_unlinked() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut installed = acquire_delegation_generation_for_test(&state_root, 3).unwrap();
        installed.persist_before_mutation().unwrap();
        drop(installed);
        let fixture = fixture(3);

        let mut received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &state_root,
            &fixture.policy(),
        )
        .unwrap();
        let mut bytes = Vec::new();
        received
            .component()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"probe");
        assert!(
            fs::read_dir(state_root.join("inbox"))
                .map(|entries| entries.count() == 0)
                .unwrap_or(true)
        );
    }

    #[test]
    fn truncated_component_does_not_advance_the_generation_floor() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut fixture = fixture(4);
        let component = fixture
            .stream
            .windows(b"probe".len())
            .position(|bytes| bytes == b"probe")
            .unwrap();
        fixture.stream.remove(component + b"probe".len() - 1);

        assert!(
            receive_for_test(
                &mut Cursor::new(fixture.stream.as_slice()),
                &state_root,
                &fixture.policy()
            )
            .is_err()
        );
        let floor = acquire_delegation_generation_for_test(&state_root, 4).unwrap();
        assert_eq!(floor.current(), 0);
        assert!(
            fs::read_dir(state_root.join("inbox"))
                .map(|entries| entries.count() == 0)
                .unwrap_or(true)
        );
    }

    #[test]
    fn invalid_enrollment_does_not_advance_the_generation_floor() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut fixture = fixture(4);
        let token = b"enk_enroll_test";
        let offset = fixture
            .stream
            .windows(token.len())
            .position(|bytes| bytes == token)
            .unwrap();
        fixture.stream[offset] = b'!';

        assert!(
            receive_for_test(
                &mut Cursor::new(fixture.stream.as_slice()),
                &state_root,
                &fixture.policy()
            )
            .is_err()
        );
        let floor = acquire_delegation_generation_for_test(&state_root, 4).unwrap();
        assert_eq!(floor.current(), 0);
    }

    #[test]
    fn invalid_component_does_not_advance_the_generation_floor() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let mut fixture = fixture(4);
        let component = fixture
            .stream
            .windows(b"probe".len())
            .position(|bytes| bytes == b"probe")
            .unwrap();
        fixture.stream[component] ^= 1;

        assert!(
            receive_for_test(
                &mut Cursor::new(fixture.stream.as_slice()),
                &state_root,
                &fixture.policy()
            )
            .is_err()
        );
        let floor = acquire_delegation_generation_for_test(&state_root, 4).unwrap();
        assert_eq!(floor.current(), 0);
    }

    #[test]
    fn valid_handoff_persists_the_generation_floor_before_activation() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let fixture = fixture(4);
        let received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &state_root,
            &fixture.policy(),
        )
        .unwrap();

        received
            .activate_with(|_, _, _| {
                assert_eq!(
                    fs::read_to_string(state_root.join("trust/delegation-generation")).unwrap(),
                    "4\n"
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn received_handoff_holds_the_generation_lock_until_drop() {
        let temporary = tempdir().unwrap();
        let state_root = temporary.path().join("state");
        let fixture = fixture(5);
        let received = receive_for_test(
            &mut Cursor::new(fixture.stream.as_slice()),
            &state_root,
            &fixture.policy(),
        )
        .unwrap();
        let worker_root = state_root.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let lease = acquire_delegation_generation_for_test(&worker_root, 5);
            sender.send(lease.is_ok()).unwrap();
        });
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        drop(received);
        assert!(receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        worker.join().unwrap();
    }

    #[test]
    fn root_module_never_gains_archive_or_network_dependencies() {
        let source = include_str!("activation.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            ["flat", "e2"].concat(),
            ["ta", "r::"].concat(),
            ["ur", "eq"].concat(),
            ["req", "west"].concat(),
            ["Gz", "Decoder"].concat(),
        ] {
            assert!(!production.contains(&forbidden), "{forbidden}")
        }
    }

    fn receive_for_test(
        input: &mut impl Read,
        state_root: &std::path::Path,
        policy: &VerificationPolicy<'_>,
    ) -> Result<ReceivedRootHandoff, ActivationError> {
        receive_root_handoff(
            input,
            policy,
            unsafe { libc::geteuid() },
            |candidate| {
                acquire_delegation_generation_for_test(state_root, candidate)
                    .map_err(ActivationError::from)
            },
            None,
        )
    }

    fn invalid_policy() -> VerificationPolicy<'static> {
        VerificationPolicy {
            distribution: "enoki",
            expected_target: "x86_64-unknown-linux-gnu",
            highest_accepted_delegation_generation: u64::MAX,
            external_root_fingerprint: "a".repeat(64),
            external_root_pem: None,
        }
    }

    struct Fixture {
        root: Vec<u8>,
        root_fingerprint: String,
        stream: Vec<u8>,
    }

    impl Fixture {
        fn policy(&self) -> VerificationPolicy<'_> {
            VerificationPolicy {
                distribution: "enoki",
                expected_target: "x86_64-unknown-linux-gnu",
                highest_accepted_delegation_generation: u64::MAX,
                external_root_fingerprint: self.root_fingerprint.clone(),
                external_root_pem: Some(&self.root),
            }
        }
    }

    fn fixture(generation: u64) -> Fixture {
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
        let root_id = sha256(&root_pem);
        let daily_id = sha256(&daily_pem);
        let component = b"probe";
        let bundle = format!(
            "{{\"bootstrapAssets\":[{{\"path\":\"bootstrap/enoki-probe-bootstrap-acquire\",\"permissionProfile\":\"bootstrap-acquirer-v1\",\"role\":\"bootstrap-acquirer\",\"sha256\":\"{}\",\"size\":1,\"version\":\"1.2.3\"}},{{\"path\":\"bootstrap/enoki-probe-bootstrap-activate\",\"permissionProfile\":\"bootstrap-activator-v1\",\"role\":\"bootstrap-activator\",\"sha256\":\"{}\",\"size\":1,\"version\":\"1.2.3\"}}],\"components\":[{{\"path\":\"enoki-probe\",\"permissionProfile\":\"probe-v1\",\"resourceContract\":\"hub-reporting-v1\",\"role\":\"probe\",\"sha256\":\"{}\",\"size\":5,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-observation-runtime\",\"permissionProfile\":\"observation-runtime-v1\",\"resourceContract\":\"official-observation-v2\",\"role\":\"observation-runtime\",\"sha256\":\"{}\",\"size\":7,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-cpu-resource-provider\",\"permissionProfile\":\"system-state-provider-v2\",\"resourceContract\":\"system-state-v2\",\"role\":\"system-state-provider\",\"sha256\":\"{}\",\"size\":21,\"version\":\"1.2.3\"}},{{\"path\":\"enoki-disk-health-resource-provider\",\"permissionProfile\":\"disk-health-provider-v1\",\"resourceContract\":\"disk-health-v1\",\"role\":\"disk-health-provider\",\"sha256\":\"{}\",\"size\":20,\"version\":\"1.2.3\"}}],\"kind\":\"enoki-probe-bundle\",\"target\":\"x86_64-unknown-linux-gnu\",\"version\":\"1.2.3\"}}\n",
            sha256(b"a"),
            sha256(b"b"),
            sha256(component),
            sha256(b"runtime"),
            sha256(b"system-state-provider"),
            sha256(b"disk-health-provider"),
        )
        .into_bytes();
        let delegation = format!(
            "{{\"distribution\":\"enoki\",\"generation\":{generation},\"kind\":\"enoki-probe-trust-delegation\",\"purpose\":\"probe-asset-signing\",\"rootKeyId\":\"{root_id}\",\"schemaVersion\":1,\"signingIdentity\":{{\"algorithm\":\"rsa-sha256\",\"keyId\":\"{daily_id}\",\"publicKeyPem\":{}}}}}\n",
            serde_json::to_string(std::str::from_utf8(&daily_pem).unwrap()).unwrap()
        )
        .into_bytes();
        let mut delegation_input = b"enoki/probe-trust-delegation/v1\0".to_vec();
        delegation_input.extend_from_slice(&delegation);
        let delegation_signature = SigningKey::<Sha256>::new(root)
            .sign_with_rng(&mut rng, &delegation_input)
            .to_vec();
        let manifest = format!(
            "{{\"assets\":[{{\"bundleManifestSha256\":\"{}\",\"file\":\"enoki-probe-x86_64-unknown-linux-gnu.tar.gz\",\"sha256\":\"{}\",\"size\":1,\"target\":\"x86_64-unknown-linux-gnu\"}}],\"kind\":\"enoki-probe-assets\",\"signature\":{{\"algorithm\":\"rsa-sha256\",\"delegationGeneration\":{generation},\"delegationKeyId\":\"{daily_id}\",\"file\":\"manifest.json.sig\",\"publicKey\":\"signing-key.pem\"}},\"version\":\"1.2.3\"}}\n",
            sha256(&bundle),
            "0".repeat(64)
        )
        .into_bytes();
        let manifest_signature = SigningKey::<Sha256>::new(daily)
            .sign_with_rng(&mut rng, &manifest)
            .to_vec();
        let handoff = Handoff {
            delegation,
            delegation_signature,
            manifest,
            manifest_signature,
            signing_key: daily_pem,
            bundle_manifest: bundle,
        };
        let mut stream = Vec::new();
        handoff
            .write_from(
                &crate::handoff::Enrollment::new("https://hub.example", "enk_enroll_test").unwrap(),
                &mut Cursor::new(component),
                component.len() as u64,
                &mut Cursor::new(b"runtime"),
                7,
                &mut Cursor::new(b"system-state-provider"),
                21,
                &mut Cursor::new(b"disk-health-provider"),
                20,
                &mut Cursor::new(b"a"),
                1,
                &mut stream,
            )
            .unwrap();
        assert_eq!(&stream[..8], &MAGIC);
        assert_eq!(&stream[8..10], &SCHEMA_VERSION.to_be_bytes());
        Fixture {
            root: root_pem,
            root_fingerprint: root_id,
            stream,
        }
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::account::{
        account_records_match_transaction, classify_gshadow_lookup,
        create_probe_ipc_group_with_commands, create_transaction_identity_with_commands,
        owned_ipc_group_record_matches, remove_owned_ipc_group_with_commands,
    };
    use super::upgrade::{upgrade_destinations, write_operation_status};
    use super::*;
    use crate::handoff::Enrollment;
    use crate::lifecycle::UpgradeCompletion;
    use crate::replacement::ReplacementCommitStore;
    use crate::trust::BootstrapRole;
    use hmac::{Hmac, Mac};
    use rsa::{
        RsaPrivateKey,
        pkcs8::{EncodePrivateKey, LineEnding},
        rand_core::OsRng,
    };
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;
    use tempfile::tempdir;

    #[test]
    fn installed_layout_mechanics_are_shared_without_replacement_or_repair_policy() {
        let mechanics = include_str!("installed_layout.rs");
        let repair = include_str!("bundle_restore.rs");
        let replacement = include_str!("replacement_finalize.rs");
        let compatible = include_str!("upgrade.rs");

        assert!(!mechanics.contains("ReplacementCommitFact"));
        assert!(!mechanics.contains("InstalledBundleRepairBinding"));
        assert!(!repair.contains("ReplacementCommitFact"));
        assert!(replacement.contains("ReplacementCommitFact"));
        for consumer in [repair, replacement, compatible] {
            assert!(consumer.contains("installed_layout::registry"));
        }
    }

    #[test]
    fn system_state_boundary_assigns_host_facts_only_to_the_fixed_provider() {
        for unit in [service_unit(), observation_runtime_unit()] {
            assert!(unit.contains("InaccessiblePaths=-/proc/stat"));
            assert!(unit.contains("/proc/cpuinfo"));
            assert!(unit.contains("/etc/os-release"));
            assert!(unit.contains("/sys/class/block"));
        }
        let provider = cpu_provider_unit();
        assert!(provider.contains("RestrictAddressFamilies=AF_UNIX AF_NETLINK"));
        assert!(provider.contains("IPAddressDeny=any"));
        assert!(provider.contains("ProtectHome=read-only"));
        assert!(provider.contains("BindReadOnlyPaths=/etc/os-release /usr/lib/os-release /sys/devices/system/cpu /sys/class/hwmon /sys/class/power_supply /sys/class/block"));
        assert!(provider.contains("ReadOnlyPaths=/proc/stat /proc/loadavg /proc/meminfo /proc/uptime /proc/cpuinfo /proc/mounts"));
        assert!(provider.contains("ReadOnlyPaths=/proc/net\n"));
        assert!(
            !provider
                .lines()
                .filter(|line| line.starts_with("ReadOnlyPaths="))
                .any(|line| line.contains("/proc/net/")),
            "/proc/net 的子路径会在 namespace 内解析为尚不存在的 child PID"
        );
        assert!(provider.contains("ReadOnlyPaths=/proc/stat"));
        assert!(provider.contains("/proc/diskstats"));
        assert!(provider.contains("IPAddressDeny=any"));
        assert!(provider.contains("SocketBindDeny=ipv4:any"));
    }

    #[test]
    fn proc_subset_units_make_only_already_hidden_proc_paths_optional() {
        let hidden_proc_paths = [
            "/proc/stat",
            "/proc/loadavg",
            "/proc/meminfo",
            "/proc/uptime",
            "/proc/cpuinfo",
            "/proc/mounts",
            "/proc/net/dev",
            "/proc/net/route",
            "/proc/net/ipv6_route",
            "/proc/diskstats",
            "/proc/sys/kernel/hostname",
            "/proc/sys/kernel/osrelease",
        ];

        for unit in [service_unit(), observation_runtime_unit()] {
            let inaccessible = unit
                .lines()
                .find_map(|line| line.strip_prefix("InaccessiblePaths="))
                .expect("canonical unit 必须声明 inaccessible paths");
            let tokens: Vec<_> = inaccessible.split_ascii_whitespace().collect();
            for path in hidden_proc_paths {
                assert!(tokens.contains(&format!("-{path}").as_str()));
                assert!(!tokens.contains(&path));
            }
            for mandatory in [
                "/sys/devices/system/cpu",
                "/sys/class/block",
                "/etc/os-release",
            ] {
                assert!(tokens.contains(&mandatory));
                assert!(!tokens.contains(&format!("-{mandatory}").as_str()));
            }
        }
        let runtime = observation_runtime_unit();
        let inaccessible = runtime
            .lines()
            .find_map(|line| line.strip_prefix("InaccessiblePaths="))
            .unwrap();
        assert!(
            inaccessible
                .split_ascii_whitespace()
                .any(|token| token == "/var/lib/enoki-probe/identity")
        );
        assert!(!inaccessible.contains("-/var/lib/enoki-probe/identity"));
    }

    #[test]
    fn fresh_dynamic_probe_creates_only_its_static_ipc_group() {
        let mut calls = Vec::new();
        let identity = create_probe_ipc_group_with_commands("tx-1", &mut |program, arguments| {
            calls.push(format!("{program} {}", arguments.join(" ")));
            Ok(())
        })
        .expect("创建 Probe IPC 组");

        assert_eq!(identity, ServiceIdentity { uid: 0, gid: 0 });
        assert_eq!(
            calls,
            ["/usr/sbin/groupadd --system --password !enoki-bootstrap-tx-1 enoki-probe-ipc"]
        );
        assert!(calls.iter().all(|call| !call.contains("useradd")));
    }

    #[test]
    fn transaction_marker_owns_probe_ipc_group_before_identity_receipt_is_durable() {
        let record = "enoki-probe-ipc:!enoki-bootstrap-tx-1::\n";

        assert!(owned_ipc_group_record_matches(
            PROBE_IPC_GROUP,
            "tx-1",
            None,
            record,
        ));
        assert!(owned_ipc_group_record_matches(
            PROBE_IPC_GROUP,
            "tx-1",
            Some(ServiceIdentity { uid: 0, gid: 0 }),
            record,
        ));
        assert!(!owned_ipc_group_record_matches(
            PROBE_IPC_GROUP,
            "another-tx",
            None,
            record,
        ));

        let mut removals = Vec::new();
        remove_owned_ipc_group_with_commands(
            PROBE_IPC_GROUP,
            "tx-1",
            None,
            &mut |_| Ok(Some(record.to_owned())),
            &mut |program, arguments| {
                removals.push(format!("{program} {}", arguments.join(" ")));
                Ok(())
            },
        )
        .expect("identity receipt 缺失时按 marker 补偿");
        assert_eq!(removals, ["/usr/sbin/groupdel enoki-probe-ipc"]);

        removals.clear();
        remove_owned_ipc_group_with_commands(
            PROBE_IPC_GROUP,
            "another-tx",
            None,
            &mut |_| Ok(Some(record.to_owned())),
            &mut |program, arguments| {
                removals.push(format!("{program} {}", arguments.join(" ")));
                Ok(())
            },
        )
        .expect("不删除其他事务的 IPC 组");
        assert!(removals.is_empty());

        remove_owned_ipc_group_with_commands(
            PROBE_IPC_GROUP,
            "tx-1",
            None,
            &mut |_| Ok(None),
            &mut |program, arguments| {
                removals.push(format!("{program} {}", arguments.join(" ")));
                Ok(())
            },
        )
        .expect("已补偿的 IPC 组可幂等重试");
        assert!(removals.is_empty());
        assert!(!owned_ipc_group_record_matches(
            PROBE_IPC_GROUP,
            "tx-1",
            Some(ServiceIdentity { uid: 1, gid: 1 }),
            record,
        ));
    }

    #[test]
    fn gshadow_lookup_accepts_only_record_or_absent_exit_status() {
        assert_eq!(
            classify_gshadow_lookup(Some(0), b"enoki-probe-ipc:marker::\n".to_vec()),
            Ok(Some("enoki-probe-ipc:marker::\n".to_owned())),
        );
        assert_eq!(classify_gshadow_lookup(Some(2), Vec::new()), Ok(None));
        assert_eq!(
            classify_gshadow_lookup(Some(0), vec![0xff]),
            Err(InstallError::Account),
        );
        for status in [Some(1), Some(3), None] {
            assert_eq!(
                classify_gshadow_lookup(status, b"plausible:but:unauthenticated:\n".to_vec()),
                Err(InstallError::Account),
            );
        }
    }

    #[derive(Default)]
    struct Accounts {
        calls: Vec<&'static str>,
        ipc_calls: Vec<&'static str>,
        reject: bool,
        identity_present: bool,
        ipc_present: bool,
        crash_after: Option<&'static str>,
        fail_identity: bool,
        fail_ipc: bool,
        poison_staging: Option<PathBuf>,
        break_state_on_identity: Option<(PathBuf, PathBuf)>,
    }
    impl AccountPort for Accounts {
        fn require_absent(&mut self) -> Result<(), InstallError> {
            self.calls.push("absent");
            (!self.reject)
                .then_some(())
                .ok_or(InstallError::ExistingResidue)
        }
        fn create_transaction_identity(
            &mut self,
            _transaction_id: &str,
        ) -> Result<ServiceIdentity, InstallError> {
            self.calls.push("create");
            if self.fail_identity {
                return Err(InstallError::Account);
            }
            self.identity_present = true;
            if let Some((state, backup)) = &self.break_state_on_identity {
                fs::rename(state, backup).unwrap();
                fs::write(state, b"journal-parent-fault").unwrap();
            }
            if self.crash_after == Some("identity") {
                panic!("模拟 identity effect 后进程退出");
            }
            Ok(ServiceIdentity {
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            })
        }
        fn remove_transaction_identity(
            &mut self,
            _transaction_id: &str,
            _identity: Option<ServiceIdentity>,
        ) -> Result<(), InstallError> {
            self.calls.push("remove");
            self.identity_present = false;
            Ok(())
        }
        fn owns_transaction_identity(
            &mut self,
            _transaction_id: &str,
            _identity: Option<ServiceIdentity>,
        ) -> Result<bool, InstallError> {
            self.calls.push("owns");
            Ok(self.identity_present)
        }
        fn create_observation_ipc_group(
            &mut self,
            _transaction_id: &str,
        ) -> Result<(), InstallError> {
            self.ipc_calls.push("create");
            if self.fail_ipc {
                return Err(InstallError::Account);
            }
            self.ipc_present = true;
            if let Some(state) = &self.poison_staging {
                let staging = fs::read_dir(state)
                    .unwrap()
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .find(|path| {
                        path.file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name.starts_with("activation-stage-"))
                    })
                    .unwrap();
                fs::write(staging.join("enoki-probe"), b"crash-window-residue").unwrap();
            }
            if self.crash_after == Some("ipc") {
                panic!("模拟 IPC group effect 后进程退出");
            }
            Ok(())
        }
        fn owns_observation_ipc_group(
            &mut self,
            _transaction_id: &str,
        ) -> Result<bool, InstallError> {
            self.ipc_calls.push("owns");
            Ok(self.ipc_present)
        }
        fn remove_observation_ipc_group(
            &mut self,
            _transaction_id: &str,
        ) -> Result<(), InstallError> {
            self.ipc_calls.push("remove");
            self.ipc_present = false;
            Ok(())
        }
    }
    #[derive(Default)]
    struct Systemd {
        calls: Vec<&'static str>,
        fail_reload: bool,
        fail_enable: bool,
        fail_start: bool,
        fail_ready: bool,
        fail_restart: bool,
        residue: bool,
        registration_identity: Option<PathBuf>,
    }
    impl SystemdPort for Systemd {
        fn require_absent(&mut self) -> Result<(), InstallError> {
            self.calls.push("absent");
            (!self.residue)
                .then_some(())
                .ok_or(InstallError::ExistingResidue)
        }
        fn daemon_reload(&mut self) -> Result<(), InstallError> {
            self.calls.push("reload");
            (!self.fail_reload)
                .then_some(())
                .ok_or(InstallError::Systemd)
        }
        fn enable(&mut self) -> Result<(), InstallError> {
            self.calls.push("enable");
            (!self.fail_enable)
                .then_some(())
                .ok_or(InstallError::Systemd)
        }
        fn start(&mut self) -> Result<(), InstallError> {
            self.calls.push("start");
            (!self.fail_start)
                .then_some(())
                .ok_or(InstallError::Systemd)
        }
        fn restart_canonical(&mut self) -> Result<(), InstallError> {
            self.calls.push("canonical-restart");
            (!self.fail_restart)
                .then_some(())
                .ok_or(InstallError::Systemd)
        }
        fn wait_local_activated(&mut self) -> Result<(), InstallError> {
            self.calls.push("ready");
            if self.fail_ready {
                return Err(InstallError::Systemd);
            }
            // 生产 Type=notify unit 只有在注册事务原子持久化 identity 并完成启动
            // report 后才 READY；此 seam 复现该顺序，而不把 active 伪装成注册收据。
            if let Some(identity) = &self.registration_identity {
                let pending = fs::read_to_string(identity).map_err(|_| InstallError::Io)?;
                let registered = pending.replace(
                    "enrollment_token = \"enk_enroll_secret\"\n",
                    &format!(
                        "enrollment_id = \"enrollment_01\"\nprobe_id = \"probe-registered\"\nhost_id = \"host-registered\"\nprobe_private_key_pem = {:?}\n",
                        valid_probe_private_key_pem()
                    ),
                );
                fs::write(identity, registered).map_err(|_| InstallError::Io)?;
            }
            Ok(())
        }
        fn stop(&mut self) -> Result<(), InstallError> {
            self.calls.push("stop");
            Ok(())
        }
        fn disable(&mut self) -> Result<(), InstallError> {
            self.calls.push("disable");
            Ok(())
        }
    }

    fn write_authority_upgrade_journal(
        paths: &FixedInstallPaths,
        schema_version: u16,
        phase: &str,
        activation_started: Option<bool>,
        activated_targets: usize,
        finalized_targets: usize,
    ) -> String {
        fs::create_dir_all(paths.bootstrap_state()).unwrap();
        let marker = activation_started
            .map(|started| format!("activation_started = {started}\n"))
            .unwrap_or_default();
        let journal = format!(
            "schema_version = {schema_version}\noperation_id = \"failed-upgrade-1\"\nstage_owner_uid = {}\nauthority_sha256 = {:?}\nhub_origin = \"https://hub.example\"\nhost_id = \"host-1\"\nsource_probe_id = \"probe-1\"\nsource_bundle_version = \"1.2.3\"\nsource_install_state_sha256 = {:?}\nsource_manifest_sha256 = {:?}\ntarget_bundle_version = \"1.2.4\"\ntarget_asset_set_digest = {:?}\ntarget_manifest_sha256 = {:?}\nverified_stage_sha256 = {:?}\nphase = {phase:?}\n{marker}activated_targets = {activated_targets}\nfinalized_targets = {finalized_targets}\n",
            unsafe { libc::geteuid() },
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            format!("sha256:{}", "d".repeat(64)),
            "e".repeat(64),
            "f".repeat(64),
        );
        let journal_path = paths.bootstrap_state().join("probe-upgrade-attempt.toml");
        fs::write(&journal_path, &journal).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        journal
    }
    fn trust() -> BuildTrust {
        BuildTrust {
            distribution: "enoki",
            role: BootstrapRole::Activator,
            root_pem: "",
            root_fingerprint: "a".repeat(64).leak(),
            root_key_id: "",
            target: "x86_64-unknown-linux-gnu",
            version: "v1.2.3",
        }
    }
    fn bundle() -> VerifiedBundle {
        VerifiedBundle {
            asset_set_manifest_sha256: "c".repeat(64),
            version: "1.2.3".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            manifest_sha256: "b".repeat(64),
            delegation_generation: 1,
            component_len: 5,
            bootstrap_assets: Vec::new(),
        }
    }
    fn component() -> File {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), b"probe").unwrap();
        temp.reopen().unwrap()
    }

    fn valid_probe_private_key_pem() -> &'static str {
        static KEY: OnceLock<String> = OnceLock::new();
        KEY.get_or_init(|| {
            RsaPrivateKey::new(&mut OsRng, 1024)
                .unwrap()
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap()
                .to_string()
        })
    }

    fn installed_bundle_repair_binding(
        installed: &InstalledUpgradeBinding,
        bundle: &VerifiedBundle,
        paths: &FixedInstallPaths,
    ) -> InstalledBundleRepairBinding {
        let identity = fs::read_to_string(paths.identity()).unwrap();
        let host_id = upgrade::metadata_string(&identity, "host_id").unwrap();
        let operation_id = "repair_01".to_owned();
        let asset_set = format!("sha256:{}", bundle.asset_set_manifest_sha256);
        InstalledBundleRepairBinding::for_test(
            crate::lifecycle::InstalledBundleRepairAuthorityV1 {
                kind: "installed-bundle-repair-authority".to_owned(),
                schema_version: 1,
                hub_origin: installed.hub_origin.clone(),
                host_id,
                probe_id: installed.probe_id.clone(),
                generation: "generation_01".to_owned(),
                boot_id: "boot_01".to_owned(),
                unit: "enoki-observation-runtime.service".to_owned(),
                unit_sha256: "1".repeat(64),
                identity_receipt_sha256: format!("{:x}", Sha256::digest(identity.as_bytes())),
                install_state_sha256: installed.source_install_state_sha256.clone(),
                manifest_sha256: installed.source_manifest_sha256.clone(),
                bundle_version: installed.source_bundle_version.clone(),
                target_asset_set_digest: asset_set.clone(),
                repair_operation_id: operation_id.clone(),
                repair_nonce: "nonce_01".to_owned(),
                repair_evidence_sha256: "3".repeat(64),
                expires_at_ms: 1,
            },
            unsafe { libc::geteuid() },
        )
    }

    fn replacement_commit(bundle: &VerifiedBundle) -> ReplacementCommitFact {
        ReplacementCommitFact::for_test(
            crate::replacement::ReplacementIntent {
                enrollment_id: "enrollment_01".to_owned(),
                enrollment_token_sha256: "1".repeat(64),
                host_id: "host-registered".to_owned(),
                hub_origin: "https://hub.example".to_owned(),
                old_probe_id: "probe-old".to_owned(),
                source_probe_version: "1.2.2".to_owned(),
                source_probe_sha256: "2".repeat(64),
                target_probe_version: bundle.version.clone(),
                target_asset_set_digest: format!(
                    "sha256:{}",
                    bundle.asset_set_manifest_sha256
                ),
                target_manifest_sha256: bundle.manifest_sha256.clone(),
            },
            true,
            true,
        )
    }

    struct InstalledBundleFixture {
        _temporary: tempfile::TempDir,
        paths: FixedInstallPaths,
        bundle: VerifiedBundle,
        installed: InstalledUpgradeBinding,
        repair: InstalledBundleRepairBinding,
    }

    fn installed_bundle_fixture() -> InstalledBundleFixture {
        let temporary = tempdir().unwrap();
        for parent in ["usr/local/bin", "var/lib", "etc/systemd/system", "etc/sudoers.d"] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let bundle = bundle().with_test_complete_receipts(5);
        let [mut probe, mut runtime, mut provider, mut disk, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        activate_complete_fresh_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle,
            &trust(),
            &paths,
            &mut Accounts::default(),
            &mut Systemd::default(),
        )
        .unwrap();
        let mut identity = fs::read_to_string(paths.identity()).unwrap();
        identity.push_str("probe_id = \"probe_01\"\nhost_id = \"host_01\"\nprobe_private_key_pem = \"key\"\n");
        fs::write(paths.identity(), identity).unwrap();
        fs::set_permissions(paths.identity(), fs::Permissions::from_mode(0o600)).unwrap();
        let installed = inspect_installed_probe_for_upgrade(&paths).unwrap();
        let repair = installed_bundle_repair_binding(&installed, &bundle, &paths);
        InstalledBundleFixture {
            _temporary: temporary,
            paths,
            bundle,
            installed,
            repair,
        }
    }

    fn restore_bundle_fixture(
        fixture: &InstalledBundleFixture,
        systemd: &mut Systemd,
    ) -> Result<(), InstallError> {
        let [mut probe, mut runtime, mut provider, mut disk, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        restore_installed_bundle_for_repair(
            VerifiedUpgradeComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                system_state_provider: &mut provider,
                disk_health_provider: &mut disk,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &fixture.bundle,
            &fixture.installed,
            &fixture.repair,
            &fixture.paths,
            systemd,
        )
    }

    struct FailSecondRoleFiles {
        inner: SystemInstallFiles,
        installs: usize,
        replace_first: Option<PathBuf>,
    }
    impl InstallFilePort for FailSecondRoleFiles {
        fn ensure_metadata_directory(
            &mut self,
            path: &Path,
            journal: &mut TransactionJournal,
        ) -> Result<bool, InstallError> {
            self.inner.ensure_metadata_directory(path, journal)
        }
        fn create_directory(
            &mut self,
            path: &Path,
            mode: u32,
            identity: ServiceIdentity,
            journal: &mut TransactionJournal,
            step: RollbackStep,
        ) -> Result<(), InstallError> {
            self.inner
                .create_directory(path, mode, identity, journal, step)
        }
        fn install_binary(
            &mut self,
            component: &mut File,
            path: &Path,
            journal: &mut TransactionJournal,
            step: RollbackStep,
        ) -> Result<(), InstallError> {
            self.installs += 1;
            if self.installs == 2 {
                if let Some(first) = &self.replace_first {
                    fs::remove_file(first).unwrap();
                    fs::write(first, b"replacement").unwrap();
                    fs::set_permissions(first, fs::Permissions::from_mode(0o755)).unwrap();
                }
                return Err(InstallError::Io);
            }
            self.inner.install_binary(component, path, journal, step)
        }
        fn write_owned(
            &mut self,
            path: &Path,
            contents: &[u8],
            mode: u32,
            owner: ServiceIdentity,
            journal: &mut TransactionJournal,
            step: RollbackStep,
        ) -> Result<(), InstallError> {
            self.inner
                .write_owned(path, contents, mode, owner, journal, step)
        }
        fn remove_path(&mut self, path: &Path) -> Result<(), InstallError> {
            self.inner.remove_path(path)
        }
        fn remove_directory(&mut self, path: &Path) -> Result<(), InstallError> {
            self.inner.remove_directory(path)
        }
    }

    struct FailFirstCandidateDirectoryFiles {
        inner: SystemInstallFiles,
        failed: bool,
    }

    struct FailFirstBootstrapRoleFiles {
        inner: SystemInstallFiles,
        failed: bool,
    }

    impl InstallFilePort for FailFirstBootstrapRoleFiles {
        fn ensure_metadata_directory(
            &mut self,
            path: &Path,
            journal: &mut TransactionJournal,
        ) -> Result<bool, InstallError> {
            self.inner.ensure_metadata_directory(path, journal)
        }

        fn create_directory(
            &mut self,
            path: &Path,
            mode: u32,
            identity: ServiceIdentity,
            journal: &mut TransactionJournal,
            step: RollbackStep,
        ) -> Result<(), InstallError> {
            self.inner
                .create_directory(path, mode, identity, journal, step)
        }

        fn install_binary(
            &mut self,
            component: &mut File,
            path: &Path,
            journal: &mut TransactionJournal,
            step: RollbackStep,
        ) -> Result<(), InstallError> {
            if !self.failed {
                self.failed = true;
                return Err(InstallError::Io);
            }
            self.inner.install_binary(component, path, journal, step)
        }

        fn write_owned(
            &mut self,
            path: &Path,
            contents: &[u8],
            mode: u32,
            owner: ServiceIdentity,
            journal: &mut TransactionJournal,
            step: RollbackStep,
        ) -> Result<(), InstallError> {
            self.inner
                .write_owned(path, contents, mode, owner, journal, step)
        }

        fn remove_path(&mut self, path: &Path) -> Result<(), InstallError> {
            self.inner.remove_path(path)
        }

        fn remove_directory(&mut self, path: &Path) -> Result<(), InstallError> {
            self.inner.remove_directory(path)
        }
    }

    impl InstallFilePort for FailFirstCandidateDirectoryFiles {
        fn ensure_metadata_directory(
            &mut self,
            path: &Path,
            journal: &mut TransactionJournal,
        ) -> Result<bool, InstallError> {
            self.inner.ensure_metadata_directory(path, journal)
        }

        fn create_directory(
            &mut self,
            path: &Path,
            mode: u32,
            identity: ServiceIdentity,
            journal: &mut TransactionJournal,
            step: RollbackStep,
        ) -> Result<(), InstallError> {
            if !self.failed {
                self.failed = true;
                return Err(InstallError::Io);
            }
            self.inner
                .create_directory(path, mode, identity, journal, step)
        }

        fn install_binary(
            &mut self,
            component: &mut File,
            path: &Path,
            journal: &mut TransactionJournal,
            step: RollbackStep,
        ) -> Result<(), InstallError> {
            self.inner.install_binary(component, path, journal, step)
        }

        fn write_owned(
            &mut self,
            path: &Path,
            contents: &[u8],
            mode: u32,
            owner: ServiceIdentity,
            journal: &mut TransactionJournal,
            step: RollbackStep,
        ) -> Result<(), InstallError> {
            self.inner
                .write_owned(path, contents, mode, owner, journal, step)
        }

        fn remove_path(&mut self, path: &Path) -> Result<(), InstallError> {
            self.inner.remove_path(path)
        }

        fn remove_directory(&mut self, path: &Path) -> Result<(), InstallError> {
            self.inner.remove_directory(path)
        }
    }

    #[test]
    fn account_identity_lookup_failure_rolls_back_created_user_and_group() {
        use std::cell::RefCell;

        for failed_lookup in ["-u", "-g"] {
            let calls = RefCell::new(Vec::new());
            let mut execute = |program: &str, _arguments: &[&str]| {
                calls.borrow_mut().push(program.to_string());
                Ok(())
            };
            let mut lookup = |flag: &str| {
                calls.borrow_mut().push(format!("id {flag}"));
                if flag == failed_lookup {
                    Err(InstallError::Account)
                } else {
                    Ok(123)
                }
            };

            let error = create_static_service_identity_with_commands(&mut execute, &mut lookup)
                .expect_err("failed numeric identity lookup rolls back");

            assert_eq!(error, InstallError::Account);
            let mut expected = vec![
                "/usr/sbin/groupadd".to_string(),
                "/usr/sbin/useradd".to_string(),
                "id -u".to_string(),
            ];
            if failed_lookup == "-g" {
                expected.push("id -g".to_string());
            }
            expected.extend([
                "/usr/sbin/userdel".to_string(),
                "/usr/sbin/groupdel".to_string(),
            ]);
            assert_eq!(*calls.borrow(), expected);
        }
    }

    #[test]
    fn production_diagnostic_retains_closed_cause_and_ordered_rollback_steps() {
        let error = InstallError::Rollback {
            cause: InstallErrorKind::Systemd,
            failures: vec![
                RollbackFailure::new(RollbackStep::StopService, InstallErrorKind::Systemd),
                RollbackFailure::new(RollbackStep::RemoveUnit, InstallErrorKind::Io),
            ],
        };

        assert_eq!(
            error.diagnostic(),
            "install=systemd rollback=stop_service:systemd,remove_unit:io"
        );
        assert_eq!(error.exit_code(), 23);
    }

    #[test]
    fn account_mutation_failure_exhausts_and_stably_reports_identity_compensations() {
        let mut calls = Vec::new();
        let error = create_static_service_identity_with_commands(
            &mut |program, _arguments| {
                calls.push(program.to_string());
                match program {
                    "/usr/sbin/groupadd" => Ok(()),
                    _ => Err(InstallError::Account),
                }
            },
            &mut |_flag| Ok(123),
        )
        .expect_err("useradd failure with failed cleanup must report all residue");

        assert_eq!(
            error,
            InstallError::Rollback {
                cause: InstallErrorKind::Account,
                failures: vec![RollbackFailure::new(
                    RollbackStep::RemoveServiceGroup,
                    InstallErrorKind::Account,
                )],
            }
        );
        assert_eq!(
            calls,
            [
                "/usr/sbin/groupadd",
                "/usr/sbin/useradd",
                "/usr/sbin/groupdel",
                "/usr/sbin/groupdel",
            ]
        );
    }

    #[test]
    fn failed_account_creation_never_deletes_an_identity_without_creation_ownership() {
        let mut calls = Vec::new();
        let error = create_static_service_identity_with_commands(
            &mut |program, _arguments| {
                calls.push(program.to_string());
                match program {
                    "/usr/sbin/groupadd" => Ok(()),
                    "/usr/sbin/useradd" => Err(InstallError::Account),
                    "/usr/sbin/groupdel" => Ok(()),
                    "/usr/sbin/userdel" => {
                        panic!("a failed useradd does not prove ownership of the visible user")
                    }
                    _ => unreachable!(),
                }
            },
            &mut |_flag| unreachable!(),
        )
        .expect_err("failed user creation remains an account failure");

        assert_eq!(error, InstallError::Account);
        assert_eq!(
            calls,
            [
                "/usr/sbin/groupadd",
                "/usr/sbin/useradd",
                "/usr/sbin/groupdel",
            ]
        );
    }

    #[test]
    fn account_creation_commands_bind_both_records_to_one_transaction_marker() {
        let mut calls = Vec::new();
        let identity = create_transaction_identity_with_commands(
            "0123456789abcdef",
            &mut |program, arguments| {
                calls.push((program.to_owned(), arguments.join(" ")));
                Ok(())
            },
            &mut |flag| Ok(if flag == "-u" { 123 } else { 456 }),
        )
        .unwrap();

        assert_eq!(identity, ServiceIdentity { uid: 123, gid: 456 });
        assert_eq!(calls.len(), 2);
        assert!(
            calls[0]
                .1
                .contains("--password !enoki-bootstrap-0123456789abcdef")
        );
        assert!(
            calls[1]
                .1
                .contains("--comment enoki-bootstrap-0123456789abcdef")
        );
    }

    #[test]
    fn reused_numeric_identity_without_the_transaction_marker_is_not_owned() {
        assert!(!account_records_match_transaction(
            "enoki-bootstrap-current",
            "!enoki-bootstrap-current",
            Some("enoki-probe:x:456:"),
            Some("enoki-probe:!enoki-bootstrap-previous::"),
            Some(
                "enoki-probe:x:123:456:enoki-bootstrap-previous:/var/lib/enoki-probe:/usr/sbin/nologin"
            ),
            Some(ServiceIdentity { uid: 123, gid: 456 }),
        ));
    }

    #[test]
    fn ambiguous_useradd_failure_preserves_the_visible_racing_identity() {
        use std::cell::Cell;

        let group_exists = Cell::new(false);
        let user_exists = Cell::new(false);
        let fail_useradd = Cell::new(true);
        let fail_first_userdel = Cell::new(true);
        let fail_first_groupdel = Cell::new(true);
        let mut execute = |program: &str, _arguments: &[&str]| match program {
            "/usr/sbin/groupadd" if !group_exists.replace(true) => Ok(()),
            "/usr/sbin/useradd" if fail_useradd.replace(false) => {
                user_exists.set(true);
                Err(InstallError::Account)
            }
            "/usr/sbin/useradd" if group_exists.get() && !user_exists.replace(true) => Ok(()),
            "/usr/sbin/userdel" if user_exists.get() && fail_first_userdel.replace(false) => {
                Err(InstallError::Account)
            }
            "/usr/sbin/userdel" if user_exists.replace(false) => Ok(()),
            "/usr/sbin/groupdel" if group_exists.get() && fail_first_groupdel.replace(false) => {
                Err(InstallError::Account)
            }
            "/usr/sbin/groupdel" if !user_exists.get() && group_exists.replace(false) => Ok(()),
            _ => Err(InstallError::Account),
        };
        let mut lookup = |_flag: &str| Ok(123);

        assert!(matches!(
            create_static_service_identity_with_commands(&mut execute, &mut lookup),
            Err(InstallError::Rollback {
                cause: InstallErrorKind::Account,
                ..
            })
        ));
        assert!(user_exists.get());
        assert!(group_exists.get());
    }

    #[test]
    fn fresh_verified_probe_becomes_only_the_fixed_current_service() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap();
        let binary = temporary.path().join("usr/local/bin/enoki-probe");
        assert_eq!(fs::read(binary).unwrap(), b"probe");
        let config = fs::read_to_string(
            temporary
                .path()
                .join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        )
        .unwrap();
        assert!(config.contains("hub_url = \"https://hub.example\""));
        assert!(config.contains("probe_distribution_root_sha256"));
        assert!(!config.contains("probe_asset_public_key_sha256"));
        let metadata =
            fs::read_to_string(temporary.path().join("etc/enoki/probe-install.toml")).unwrap();
        assert!(metadata.contains("schema_version = 2"));
        assert!(metadata.contains("bootstrap_state_dir = \"/var/lib/enoki-probe-bootstrap\""));
        assert_eq!(
            fs::metadata(temporary.path().join("etc/enoki"))
                .unwrap()
                .mode()
                & 0o777,
            0o755
        );
        assert!(!metadata.contains("sudoers_path"));
        assert!(!metadata.contains("probe_asset_public_key_sha256"));
        assert_eq!(
            fs::metadata(temporary.path().join("usr/local/bin/enoki-probe"))
                .unwrap()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(
                temporary
                    .path()
                    .join("var/lib/enoki-probe/identity/probe-bootstrap.toml")
            )
            .unwrap()
            .mode()
                & 0o777,
            0o600
        );
        assert_eq!(accounts.calls, ["absent", "create"]);
        assert_eq!(
            systemd.calls,
            ["absent", "reload", "enable", "start", "ready"]
        );
        assert_eq!(
            fs::read_to_string(
                temporary
                    .path()
                    .join("var/lib/enoki-probe-bootstrap/current-layout")
            )
            .unwrap(),
            "schema_version=1\nversion=1.2.3\n"
        );
        assert!(
            !temporary
                .path()
                .join("etc/enoki/.enoki-bootstrap-transaction")
                .exists()
        );
        assert!(
            !temporary
                .path()
                .join("var/lib/enoki-probe/.enoki-bootstrap-transaction")
                .exists()
        );
        assert!(
            !temporary
                .path()
                .join("var/lib/enoki-probe-bootstrap/activation-journal.json")
                .exists()
        );
        assert!(
            !temporary
                .path()
                .join("var/lib/enoki-probe-bootstrap/activation-stage")
                .exists()
        );
    }

    #[test]
    fn fresh_machine_installs_bundled_bootstrap_receipts_before_probe_activation() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let mut acquirer = component();
        let mut activator = component();
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        activate_fresh_current_probe(
            VerifiedFreshComponents {
                probe: &mut component,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap();

        for role in [
            "enoki-probe-bootstrap-acquire",
            "enoki-probe-bootstrap-activate",
        ] {
            let path = temporary.path().join("usr/local/bin").join(role);
            assert_eq!(fs::read(&path).unwrap(), b"probe");
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o755);
        }
        assert!(
            !temporary
                .path()
                .join("etc/sudoers.d/enoki-probe-collector-helpers")
                .exists(),
            "新安装不得创建已退役的采集 helper sudoers",
        );
    }

    #[test]
    fn compatible_upgrade_switches_the_complete_bundle_and_preserves_identity() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let source_bundle = bundle().with_test_complete_receipts(5);
        let [
            mut source_probe,
            mut source_runtime,
            mut source_system_state,
            mut source_disk_health,
            mut source_lifecycle,
            mut source_acquirer,
            mut source_activator,
        ] = std::array::from_fn(|_| component());
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        activate_complete_fresh_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut source_probe,
                observation_runtime: &mut source_runtime,
                cpu_provider: &mut source_system_state,
                disk_health_provider: &mut source_disk_health,
                lifecycle_companion: &mut source_lifecycle,
                bootstrap_acquirer: &mut source_acquirer,
                bootstrap_activator: &mut source_activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &source_bundle,
            &trust(),
            &paths,
            &mut accounts,
            &mut systemd,
        )
        .unwrap();
        let mut registered_identity = fs::read_to_string(paths.identity()).unwrap();
        registered_identity.push_str("probe_id = \"probe_01\"\n");
        fs::write(paths.identity(), &registered_identity).unwrap();
        fs::set_permissions(paths.identity(), fs::Permissions::from_mode(0o600)).unwrap();
        let identity_before = fs::read_to_string(paths.identity()).unwrap();
        let source = inspect_installed_probe_for_upgrade(&paths).unwrap();
        let mut target_bundle = bundle().with_test_complete_receipts(5);
        target_bundle.version = "1.2.4".to_owned();
        target_bundle.manifest_sha256 = "d".repeat(64);
        target_bundle.asset_set_manifest_sha256 = "e".repeat(64);
        let [
            mut target_probe,
            mut target_runtime,
            mut target_system_state,
            mut target_disk_health,
            mut target_lifecycle,
            mut target_acquirer,
            mut target_activator,
        ] = std::array::from_fn(|_| component());
        systemd.calls.clear();
        let attempt = consume_probe_upgrade_authority(
            &paths,
            &UpgradeAuthorityConsumption {
                operation_id: "41".to_owned(),
                stage_owner_uid: unsafe { libc::geteuid() },
                hub_origin: source.hub_origin.clone(),
                host_id: "host_01".to_owned(),
                probe_id: source.probe_id.clone(),
                source_bundle_version: source.source_bundle_version.clone(),
                source_install_state_sha256: source.source_install_state_sha256.clone(),
                source_manifest_sha256: source.source_manifest_sha256.clone(),
                target_bundle_version: target_bundle.version.clone(),
                target_asset_set_digest: format!(
                    "sha256:{}",
                    target_bundle.asset_set_manifest_sha256
                ),
                target_manifest_sha256: target_bundle.manifest_sha256.clone(),
                verified_stage_sha256: "9".repeat(64),
            },
        )
        .unwrap();

        let completion = upgrade_current_probe_for_operation(
            VerifiedUpgradeComponents {
                probe: &mut target_probe,
                observation_runtime: &mut target_runtime,
                system_state_provider: &mut target_system_state,
                disk_health_provider: &mut target_disk_health,
                lifecycle_companion: &mut target_lifecycle,
                bootstrap_acquirer: &mut target_acquirer,
                bootstrap_activator: &mut target_activator,
            },
            &target_bundle,
            &source,
            &attempt,
            &paths,
            &mut systemd,
        )
        .unwrap();

        assert_eq!(completion, UpgradeCompletion::Activated);
        assert_eq!(systemd.calls, ["stop", "reload", "start", "ready"]);
        finalize_probe_upgrade_stage_cleanup(
            &paths,
            &UpgradeRecoveryReceipt {
                operation_id: "41".to_owned(),
                probe_id: "probe_01".to_owned(),
                stage_owner_uid: unsafe { libc::geteuid() },
                source_bundle_version: "1.2.3".to_owned(),
                target_bundle_version: "1.2.4".to_owned(),
                activated: true,
            },
        )
        .unwrap();
        let identity_after = fs::read_to_string(paths.identity()).unwrap();
        assert_ne!(identity_after, identity_before);
        assert!(identity_after.contains("probe_id = \"probe_01\""));
        assert!(identity_after.contains("hub_url = \"https://hub.example\""));
        assert!(identity_after.contains("bundle_version = \"1.2.4\""));
        assert!(identity_after.contains(&format!(
            "install_state_sha256 = {:?}",
            target_bundle.install_state_sha256()
        )));
        assert!(identity_after.contains(&format!("target_manifest_sha256 = {:?}", "d".repeat(64))));
        let metadata = fs::read_to_string(paths.metadata()).unwrap();
        assert!(metadata.contains("schema_version = 5"));
        assert!(metadata.contains("bundle_version = \"1.2.4\""));
        assert!(metadata.contains(&format!("target_manifest_sha256 = {:?}", "d".repeat(64))));
        let status = fs::read_to_string(
            temporary
                .path()
                .join("var/lib/enoki-probe/probe-operation-status.toml"),
        )
        .unwrap();
        assert!(status.contains("operation_id = \"41\""));
        assert!(status.contains("target_probe_version = \"1.2.4\""));
        assert!(status.contains("status = \"running\""));
        let journal = fs::read_to_string(
            temporary
                .path()
                .join("var/lib/enoki-probe-bootstrap/probe-upgrade-attempt.toml"),
        )
        .unwrap();
        assert!(journal.contains("operation_id = \"41\""));
        assert!(journal.contains("host_id = \"host_01\""));
        assert!(journal.contains("source_probe_id = \"probe_01\""));
        assert!(journal.contains("phase = \"activated\""));
        assert!(journal.contains("schema_version = 3"));
        assert!(journal.contains("activation_started = true"));

        let next_source = inspect_installed_probe_for_upgrade(&paths).unwrap();
        let mut failed_target = bundle().with_test_complete_receipts(5);
        failed_target.version = "1.2.5".to_owned();
        failed_target.manifest_sha256 = "f".repeat(64);
        failed_target.asset_set_manifest_sha256 = "9".repeat(64);
        let [
            mut failed_probe,
            mut failed_runtime,
            mut failed_system_state,
            mut failed_disk_health,
            mut failed_lifecycle,
            mut failed_acquirer,
            mut failed_activator,
        ] = std::array::from_fn(|_| component());
        systemd.fail_start = true;
        let failed_attempt = consume_probe_upgrade_authority(
            &paths,
            &UpgradeAuthorityConsumption {
                operation_id: "42".to_owned(),
                stage_owner_uid: unsafe { libc::geteuid() },
                hub_origin: next_source.hub_origin.clone(),
                host_id: "host_01".to_owned(),
                probe_id: next_source.probe_id.clone(),
                source_bundle_version: next_source.source_bundle_version.clone(),
                source_install_state_sha256: next_source.source_install_state_sha256.clone(),
                source_manifest_sha256: next_source.source_manifest_sha256.clone(),
                target_bundle_version: failed_target.version.clone(),
                target_asset_set_digest: format!(
                    "sha256:{}",
                    failed_target.asset_set_manifest_sha256
                ),
                target_manifest_sha256: failed_target.manifest_sha256.clone(),
                verified_stage_sha256: "8".repeat(64),
            },
        )
        .unwrap();

        let completion = upgrade_current_probe_for_operation(
            VerifiedUpgradeComponents {
                probe: &mut failed_probe,
                observation_runtime: &mut failed_runtime,
                system_state_provider: &mut failed_system_state,
                disk_health_provider: &mut failed_disk_health,
                lifecycle_companion: &mut failed_lifecycle,
                bootstrap_acquirer: &mut failed_acquirer,
                bootstrap_activator: &mut failed_activator,
            },
            &failed_target,
            &next_source,
            &failed_attempt,
            &paths,
            &mut systemd,
        )
        .unwrap();

        assert_eq!(completion, UpgradeCompletion::RepairRequired);
        let status = fs::read_to_string(
            temporary
                .path()
                .join("var/lib/enoki-probe/probe-operation-status.toml"),
        )
        .unwrap();
        assert!(status.contains("operation_id = \"42\""));
        assert!(status.contains("status = \"failed\""));
        assert!(status.contains("error_code = \"lifecycle.upgrade_repair_required\""));
        assert!(status.contains("repair_eligibility_evidence"));
        let journal = fs::read_to_string(
            temporary
                .path()
                .join("var/lib/enoki-probe-bootstrap/probe-upgrade-attempt.toml"),
        )
        .unwrap();
        assert!(journal.contains("operation_id = \"42\""));
        assert!(journal.contains("phase = \"repair-required\""));
        assert!(journal.contains("schema_version = 3"));
        assert!(journal.contains("activation_started = true"));

        systemd.fail_start = false;
        systemd.calls.clear();
        assert_eq!(
            recover_incomplete_probe_upgrade(&paths, &mut systemd).unwrap(),
            Some(UpgradeRecoveryReceipt {
                operation_id: "42".to_owned(),
                probe_id: "probe_01".to_owned(),
                stage_owner_uid: unsafe { libc::geteuid() },
                source_bundle_version: "1.2.4".to_owned(),
                target_bundle_version: "1.2.5".to_owned(),
                activated: true,
            })
        );
        assert_eq!(systemd.calls, ["stop", "reload", "start", "ready"]);
        finalize_probe_upgrade_stage_cleanup(
            &paths,
            &UpgradeRecoveryReceipt {
                operation_id: "42".to_owned(),
                probe_id: "probe_01".to_owned(),
                stage_owner_uid: unsafe { libc::geteuid() },
                source_bundle_version: "1.2.4".to_owned(),
                target_bundle_version: "1.2.5".to_owned(),
                activated: true,
            },
        )
        .unwrap();
        let journal = fs::read_to_string(
            temporary
                .path()
                .join("var/lib/enoki-probe-bootstrap/probe-upgrade-attempt.toml"),
        )
        .unwrap();
        assert!(journal.contains("phase = \"activated\""));
        assert!(journal.contains("activated_targets = 21"));
        assert!(journal.contains("finalized_targets = 21"));
    }

    #[test]
    fn upgrade_authority_is_consumed_before_preparation_and_prepared_recovery_is_explicit() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let source_bundle = bundle().with_test_complete_receipts(5);
        let [
            mut source_probe,
            mut source_runtime,
            mut source_system_state,
            mut source_disk_health,
            mut source_lifecycle,
            mut source_acquirer,
            mut source_activator,
        ] = std::array::from_fn(|_| component());
        activate_complete_fresh_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut source_probe,
                observation_runtime: &mut source_runtime,
                cpu_provider: &mut source_system_state,
                disk_health_provider: &mut source_disk_health,
                lifecycle_companion: &mut source_lifecycle,
                bootstrap_acquirer: &mut source_acquirer,
                bootstrap_activator: &mut source_activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &source_bundle,
            &trust(),
            &paths,
            &mut Accounts::default(),
            &mut Systemd::default(),
        )
        .unwrap();
        let mut identity = fs::read_to_string(paths.identity()).unwrap();
        identity.push_str("probe_id = \"probe_01\"\nhost_id = \"host_01\"\n");
        fs::write(paths.identity(), identity).unwrap();
        fs::set_permissions(paths.identity(), fs::Permissions::from_mode(0o600)).unwrap();
        let source = inspect_installed_probe_for_upgrade(&paths).unwrap();
        let identity_before_failed_verification = fs::read(paths.identity()).unwrap();
        let installed_before_failed_verification = upgrade_destinations(&paths)
            .into_iter()
            .map(|path| (path.clone(), fs::read(path).unwrap()))
            .collect::<Vec<_>>();
        let mut target_bundle = bundle().with_test_complete_receipts(5);
        target_bundle.version = "1.2.4".to_owned();
        target_bundle.manifest_sha256 = "d".repeat(64);
        target_bundle.asset_set_manifest_sha256 = "e".repeat(64);
        let attempt = UpgradeAttempt {
            operation_id: "consume-1".to_owned(),
            stage_owner_uid: unsafe { libc::geteuid() },
            authority_sha256: None,
        };

        let [
            mut invalid_probe,
            mut invalid_runtime,
            mut invalid_system_state,
            mut invalid_disk_health,
            mut invalid_lifecycle,
            mut invalid_acquirer,
            mut invalid_activator,
        ] = std::array::from_fn(|_| component());
        invalid_probe.set_len(4).unwrap();
        let mut preactivation_systemd = Systemd::default();
        assert_eq!(
            upgrade_current_probe_for_operation(
                VerifiedUpgradeComponents {
                    probe: &mut invalid_probe,
                    observation_runtime: &mut invalid_runtime,
                    system_state_provider: &mut invalid_system_state,
                    disk_health_provider: &mut invalid_disk_health,
                    lifecycle_companion: &mut invalid_lifecycle,
                    bootstrap_acquirer: &mut invalid_acquirer,
                    bootstrap_activator: &mut invalid_activator,
                },
                &target_bundle,
                &source,
                &attempt,
                &paths,
                &mut preactivation_systemd,
            ),
            Err(InstallError::InvalidVerifiedComponent)
        );
        assert!(preactivation_systemd.calls.is_empty());
        assert_eq!(
            fs::read(paths.identity()).unwrap(),
            identity_before_failed_verification
        );
        for (path, contents) in installed_before_failed_verification {
            assert_eq!(fs::read(path).unwrap(), contents);
        }
        let journal_path = paths.bootstrap_state().join("probe-upgrade-attempt.toml");
        let admitted = fs::read_to_string(&journal_path).unwrap();
        assert!(admitted.contains("phase = \"admitted\""));

        let [
            mut retry_probe,
            mut retry_runtime,
            mut retry_system_state,
            mut retry_disk_health,
            mut retry_lifecycle,
            mut retry_acquirer,
            mut retry_activator,
        ] = std::array::from_fn(|_| component());
        assert_eq!(
            upgrade_current_probe_for_operation(
                VerifiedUpgradeComponents {
                    probe: &mut retry_probe,
                    observation_runtime: &mut retry_runtime,
                    system_state_provider: &mut retry_system_state,
                    disk_health_provider: &mut retry_disk_health,
                    lifecycle_companion: &mut retry_lifecycle,
                    bootstrap_acquirer: &mut retry_acquirer,
                    bootstrap_activator: &mut retry_activator,
                },
                &target_bundle,
                &source,
                &attempt,
                &paths,
                &mut Systemd::default(),
            ),
            Err(InstallError::ExistingResidue),
            "the consumed authority cannot be replayed after pre-activation failure"
        );

        fs::write(
            &journal_path,
            admitted.replace("phase = \"admitted\"", "phase = \"prepared\""),
        )
        .unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        for destination in upgrade_destinations(&paths) {
            let name = destination.file_name().unwrap().to_str().unwrap();
            fs::hard_link(
                &destination,
                destination.with_file_name(format!(".{name}.enoki-upgrade-old")),
            )
            .unwrap();
            fs::write(
                destination.with_file_name(format!(".{name}.enoki-upgrade-new")),
                b"prepared",
            )
            .unwrap();
        }
        assert_eq!(
            recover_incomplete_probe_upgrade(&paths, &mut Systemd::default()).unwrap(),
            Some(UpgradeRecoveryReceipt {
                operation_id: "consume-1".to_owned(),
                probe_id: "probe_01".to_owned(),
                stage_owner_uid: unsafe { libc::geteuid() },
                source_bundle_version: "1.2.3".to_owned(),
                target_bundle_version: "1.2.4".to_owned(),
                activated: false,
            })
        );
        let recovered = fs::read_to_string(&journal_path).unwrap();
        assert!(recovered.contains("phase = \"aborted\""));
        assert!(
            upgrade_destinations(&paths)
                .iter()
                .all(|destination| { fs::metadata(destination).unwrap().nlink() == 1 })
        );
    }

    #[test]
    fn installed_bundle_repair_restores_all_roles_only_for_the_exact_bound_manifest() {
        let temporary = tempdir().unwrap();
        for parent in ["usr/local/bin", "var/lib", "etc/systemd/system", "etc/sudoers.d"] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let installed_bundle = bundle().with_test_complete_receipts(5);
        let [mut probe, mut runtime, mut provider, mut disk, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        activate_complete_fresh_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &installed_bundle,
            &trust(),
            &paths,
            &mut Accounts::default(),
            &mut Systemd::default(),
        )
        .unwrap();
        let mut identity = fs::read_to_string(paths.identity()).unwrap();
        identity.push_str("probe_id = \"probe_01\"\nhost_id = \"host_01\"\n");
        fs::write(paths.identity(), identity).unwrap();
        fs::set_permissions(paths.identity(), fs::Permissions::from_mode(0o600)).unwrap();
        let binding = inspect_installed_probe_for_upgrade(&paths).unwrap();

        let mut wrong_manifest = installed_bundle.clone();
        wrong_manifest.manifest_sha256 = "d".repeat(64);
        let [mut probe, mut runtime, mut provider, mut disk, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        assert_eq!(
            restore_installed_bundle_for_repair(
                VerifiedUpgradeComponents {
                    probe: &mut probe,
                    observation_runtime: &mut runtime,
                    system_state_provider: &mut provider,
                    disk_health_provider: &mut disk,
                    lifecycle_companion: &mut lifecycle,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &wrong_manifest,
                &binding,
                &installed_bundle_repair_binding(&binding, &wrong_manifest, &paths),
                &paths,
                &mut Systemd::default(),
            ),
            Err(InstallError::ExistingResidue),
        );

        fs::write(paths.observation_runtime_binary(), b"bad!!").unwrap();
        let [mut probe, mut runtime, mut provider, mut disk, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        let mut systemd = Systemd::default();
        upgrade::set_repair_rename_crash(0);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = restore_installed_bundle_for_repair(
                    VerifiedUpgradeComponents {
                        probe: &mut probe,
                        observation_runtime: &mut runtime,
                        system_state_provider: &mut provider,
                        disk_health_provider: &mut disk,
                        lifecycle_companion: &mut lifecycle,
                        bootstrap_acquirer: &mut acquirer,
                        bootstrap_activator: &mut activator,
                    },
                    &installed_bundle,
                    &binding,
                    &installed_bundle_repair_binding(&binding, &installed_bundle, &paths),
                    &paths,
                    &mut systemd,
                );
            }))
            .is_err(),
            "publish effect 后必须模拟进程骤停，不能返回 ordinary effect error"
        );
        assert_eq!(systemd.calls, ["stop"]);

        let [mut probe, mut runtime, mut provider, mut disk, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        let mut systemd = Systemd::default();
        restore_installed_bundle_for_repair(
            VerifiedUpgradeComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                system_state_provider: &mut provider,
                disk_health_provider: &mut disk,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &installed_bundle,
            &binding,
            &installed_bundle_repair_binding(&binding, &installed_bundle, &paths),
            &paths,
            &mut systemd,
        )
        .unwrap();
        assert_eq!(fs::read(paths.observation_runtime_binary()).unwrap(), b"probe");
        assert_eq!(systemd.calls, ["reload"]);
        assert_eq!(inspect_installed_probe_for_upgrade(&paths).unwrap(), binding);
    }

    #[test]
    fn installed_bundle_repair_resumes_every_filesystem_receipt_window() {
        let mut crash_points = vec![
            "journal-publish".to_owned(),
            "stop".to_owned(),
            "reload".to_owned(),
            "complete".to_owned(),
        ];
        for phase in ["prepare", "backup", "publish", "cleanup"] {
            crash_points.extend((0..21).map(|index| format!("{phase}:{index}")));
        }

        for crash_point in crash_points {
            let fixture = installed_bundle_fixture();
            bundle_restore::set_crash(&crash_point);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = restore_bundle_fixture(&fixture, &mut Systemd::default());
                }))
                .is_err(),
                "{crash_point} 必须切断真实 effect/receipt 窗口"
            );

            let mut resumed_systemd = Systemd::default();
            restore_bundle_fixture(&fixture, &mut resumed_systemd)
                .unwrap_or_else(|error| panic!("{crash_point} 恢复失败: {error:?}"));
            let journal = fixture
                .paths
                .bootstrap_state()
                .join("installed-bundle-repair.json");
            assert!(journal.exists(), "complete custody 必须保留到 Repair 整体成功");
            for destination in upgrade_destinations(&fixture.paths) {
                assert!(destination.is_file(), "{} 缺失", destination.display());
                let name = destination.file_name().unwrap().to_string_lossy();
                assert!(!destination.with_file_name(format!(".{name}.enoki-repair-new")).exists());
                assert!(!destination.with_file_name(format!(".{name}.enoki-repair-old")).exists());
            }
            assert_eq!(
                inspect_installed_probe_for_upgrade(&fixture.paths).unwrap(),
                fixture.installed,
                "Repair 必须保留同一 Probe Identity 与安装 binding"
            );
            let wrong_retirement = fixture
                .repair
                .clone()
                .with_test_repair_nonce("wrong_retirement_nonce");
            assert_eq!(
                cleanup_installed_bundle_repair(&wrong_retirement, &fixture.paths),
                Err(InstallError::ExistingResidue),
                "StatusPublished 后也只能由 journal 预写的 exact outer binding 释放 custody"
            );
            assert!(journal.exists());
            cleanup_installed_bundle_repair(&fixture.repair, &fixture.paths).unwrap();
            assert!(!journal.exists());
            assert_eq!(
                verify_installed_bundle_repair_complete(
                    &fixture.bundle,
                    &fixture.installed,
                    &fixture.repair,
                    &fixture.paths,
                ),
                Err(InstallError::ExistingResidue),
                "success 发布前缺失 complete journal 必须 fail closed"
            );
        }
    }

    #[test]
    fn installed_bundle_repair_rejects_wrong_resume_binding_before_effects() {
        let fixture = installed_bundle_fixture();
        bundle_restore::set_crash("prepare:0");
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = restore_bundle_fixture(&fixture, &mut Systemd::default());
            }))
            .is_err()
        );
        let journal_path = fixture
            .paths
            .bootstrap_state()
            .join("installed-bundle-repair.json");
        let journal_before = fs::read(&journal_path).unwrap();
        let residue_before = fs::read_dir(fixture.paths.binary().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        let wrong = fixture
            .repair
            .clone()
            .with_test_repair_nonce("nonce_wrong");
        let wrong_fixture = InstalledBundleFixture {
            _temporary: fixture._temporary,
            paths: fixture.paths,
            bundle: fixture.bundle,
            installed: fixture.installed,
            repair: wrong,
        };
        let mut systemd = Systemd::default();
        assert_eq!(
            restore_bundle_fixture(&wrong_fixture, &mut systemd),
            Err(InstallError::ExistingResidue)
        );
        assert!(systemd.calls.is_empty());
        assert_eq!(fs::read(journal_path).unwrap(), journal_before);
        assert_eq!(
            fs::read_dir(wrong_fixture.paths.binary().parent().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            residue_before
        );
    }

    #[test]
    fn installed_bundle_repair_rejects_changed_host_identity_before_effects() {
        let fixture = installed_bundle_fixture();
        let identity_path = fixture.paths.identity();
        let identity = fs::read_to_string(&identity_path).unwrap();
        fs::write(
            &identity_path,
            identity.replace("host_id = \"host_01\"", "host_id = \"host_wrong\""),
        )
        .unwrap();
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut systemd = Systemd::default();
        assert_eq!(
            restore_bundle_fixture(&fixture, &mut systemd),
            Err(InstallError::ExistingResidue)
        );
        assert!(systemd.calls.is_empty());
        assert!(!fixture
            .paths
            .bootstrap_state()
            .join("installed-bundle-repair.json")
            .exists());
        for destination in upgrade_destinations(&fixture.paths) {
            let name = destination.file_name().unwrap().to_string_lossy();
            assert!(!destination.with_file_name(format!(".{name}.enoki-repair-new")).exists());
            assert!(!destination.with_file_name(format!(".{name}.enoki-repair-old")).exists());
        }
    }

    #[test]
    fn outer_stage_and_generation_failures_cannot_replay_the_consumed_authority() {
        for failed_outer_step in ["stage-open", "generation-persist"] {
            let temporary = tempdir().unwrap();
            let paths = FixedInstallPaths::under(temporary.path());
            fs::create_dir_all(paths.bootstrap_state()).unwrap();
            let authority = UpgradeAuthorityConsumption {
                operation_id: format!("outer-{failed_outer_step}"),
                stage_owner_uid: unsafe { libc::geteuid() },
                hub_origin: "https://hub.example".to_owned(),
                host_id: "host_01".to_owned(),
                probe_id: "probe_01".to_owned(),
                source_bundle_version: "1.2.3".to_owned(),
                source_install_state_sha256: "a".repeat(64),
                source_manifest_sha256: "b".repeat(64),
                target_bundle_version: "1.2.4".to_owned(),
                target_asset_set_digest: format!("sha256:{}", "c".repeat(64)),
                target_manifest_sha256: "d".repeat(64),
                verified_stage_sha256: "e".repeat(64),
            };

            let error = consume_before_upgrade_outer_checks(
                &paths,
                &authority,
                |_| -> Result<(), &'static str> {
                    let journal = fs::read_to_string(
                        paths.bootstrap_state().join("probe-upgrade-attempt.toml"),
                    )
                    .unwrap();
                    assert!(journal.contains("phase = \"consumed\""));
                    Err(failed_outer_step)
                },
            )
            .unwrap_err();
            let ConsumeBeforeOuterError::Outer { consumed, error } = error else {
                panic!("authority must be consumed before outer checks")
            };
            assert_eq!(error, failed_outer_step);
            assert_eq!(
                consume_probe_upgrade_authority(&paths, &authority),
                Err(InstallError::ExistingResidue),
                "{failed_outer_step} failure must not permit replay"
            );
            abort_consumed_probe_upgrade_authority(&paths, &consumed).unwrap();

            let mut replacement = authority.clone();
            replacement.operation_id.push_str("-replacement");
            consume_probe_upgrade_authority(&paths, &replacement)
                .expect("a new Owner operation may replace a terminal aborted authority");
        }
    }

    #[test]
    fn signed_upgrade_consumption_persists_the_hub_canonical_authority_digest() {
        let temporary = tempdir().unwrap();
        let paths = FixedInstallPaths::under(temporary.path());
        fs::create_dir_all(paths.bootstrap_state()).unwrap();
        fs::create_dir_all(paths.metadata().parent().unwrap()).unwrap();
        let key = [0x11_u8; 32];
        fs::write(
            paths.metadata(),
            format!("lifecycle_authority_install_key = {:?}\n", "11".repeat(32)),
        )
        .unwrap();
        fs::set_permissions(paths.metadata(), fs::Permissions::from_mode(0o600)).unwrap();
        let canonical = br#"{"schemaVersion":1,"hubOrigin":"https://hub.example"}"#;
        let mut signer = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        signer.update(b"enoki/lifecycle-upgrade-authority/hmac-sha256/v1\0");
        signer.update(canonical);
        let signature: String = signer
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let authority = UpgradeAuthorityConsumption {
            operation_id: "operation-1".to_owned(),
            stage_owner_uid: unsafe { libc::geteuid() },
            hub_origin: "https://hub.example".to_owned(),
            host_id: "host-1".to_owned(),
            probe_id: "probe-1".to_owned(),
            source_bundle_version: "1.2.3".to_owned(),
            source_install_state_sha256: "a".repeat(64),
            source_manifest_sha256: "b".repeat(64),
            target_bundle_version: "1.2.4".to_owned(),
            target_asset_set_digest: format!("sha256:{}", "c".repeat(64)),
            target_manifest_sha256: "d".repeat(64),
            verified_stage_sha256: "e".repeat(64),
        };

        consume_signed_before_upgrade_outer_checks(
            &paths,
            &authority,
            canonical,
            &signature,
            |_| Ok::<_, ()>(()),
        )
        .unwrap();

        let journal =
            fs::read_to_string(paths.bootstrap_state().join("probe-upgrade-attempt.toml")).unwrap();
        assert!(journal.contains(&format!(
            "authority_sha256 = {:?}",
            format!("{:x}", Sha256::digest(canonical))
        )));
    }

    #[test]
    fn repair_evidence_is_fresh_and_closes_over_root_owned_postactivation_journal() {
        let temporary = tempdir().unwrap();
        let paths = FixedInstallPaths::under(temporary.path());
        fs::create_dir_all(paths.bootstrap_state()).unwrap();
        fs::create_dir_all(paths.metadata().parent().unwrap()).unwrap();
        fs::create_dir_all(paths.state()).unwrap();
        fs::write(
            paths.metadata(),
            format!("lifecycle_authority_install_key = {:?}\n", "11".repeat(32)),
        )
        .unwrap();
        fs::set_permissions(paths.metadata(), fs::Permissions::from_mode(0o600)).unwrap();
        let journal = concat!(
            "schema_version = 2\n",
            "operation_id = \"failed-upgrade-1\"\n",
            "stage_owner_uid = 1000\n",
            "authority_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "hub_origin = \"https://hub.example\"\n",
            "host_id = \"host-1\"\n",
            "source_probe_id = \"probe-1\"\n",
            "source_bundle_version = \"1.2.3\"\n",
            "source_install_state_sha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n",
            "source_manifest_sha256 = \"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"\n",
            "target_bundle_version = \"1.2.4\"\n",
            "target_asset_set_digest = \"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"\n",
            "target_manifest_sha256 = \"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"\n",
            "verified_stage_sha256 = \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"\n",
            "phase = \"repair-required\"\n",
            "activation_started = true\n",
            "activated_targets = 3\n",
            "finalized_targets = 0\n",
        );
        let journal_path = paths.bootstrap_state().join("probe-upgrade-attempt.toml");
        fs::write(&journal_path, journal).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();

        let signed = issue_probe_repair_evidence(
            &paths,
            1_725_000_000_000,
            1_725_000_060_000,
            "request-nonce-1",
        )
        .unwrap();

        assert_eq!(signed.evidence.host_id, "host-1");
        assert_eq!(signed.evidence.failed_operation_id, "failed-upgrade-1");
        assert_eq!(signed.evidence.journal_phase, "repair-required");
        assert_eq!(signed.evidence.issued_at_ms, 1_725_000_000_000);
        assert_eq!(signed.evidence.expires_at_ms, 1_725_000_060_000);
        assert_eq!(signed.evidence.request_nonce, "request-nonce-1");
        assert_eq!(signed.signature.len(), 64);
        let migrated_journal = fs::read_to_string(&journal_path).unwrap();
        assert_eq!(
            signed.evidence.journal_sha256,
            format!("{:x}", Sha256::digest(migrated_journal.as_bytes()))
        );

        let eligibility = issue_probe_repair_eligibility(&paths).unwrap();
        assert_eq!(eligibility.evidence.failed_operation_id, "failed-upgrade-1");
        assert_eq!(eligibility.evidence.journal_phase, "repair-required");
        assert_eq!(
            eligibility.evidence.target_asset_set_digest,
            format!("sha256:{}", "d".repeat(64))
        );
        assert_eq!(eligibility.signature.len(), 64);
        assert_ne!(eligibility.signature, signed.signature);

        write_operation_status(
            &paths,
            &UpgradeAttempt {
                operation_id: "failed-upgrade-1".to_owned(),
                stage_owner_uid: 1000,
                authority_sha256: Some("a".repeat(64)),
            },
            "1.2.4",
            "failed",
            Some("lifecycle.upgrade_repair_required"),
        )
        .unwrap();
        let status = fs::read_to_string(paths.state().join("probe-operation-status.toml")).unwrap();
        let eligibility_canonical =
            String::from_utf8(eligibility.evidence.canonical_bytes()).unwrap();
        assert!(status.contains(&format!(
            "repair_eligibility_evidence = {:?}",
            eligibility_canonical
        )));
        assert!(status.contains(&format!(
            "repair_eligibility_signature = {:?}",
            eligibility.signature
        )));
    }

    #[test]
    fn failed_activation_boundary_write_cannot_be_laundered_into_repair_eligibility() {
        let temporary = tempdir().unwrap();
        let paths = FixedInstallPaths::under(temporary.path());
        fs::create_dir_all(paths.bootstrap_state()).unwrap();
        fs::create_dir_all(paths.metadata().parent().unwrap()).unwrap();
        fs::create_dir_all(paths.state()).unwrap();
        fs::write(
            paths.metadata(),
            format!("lifecycle_authority_install_key = {:?}\n", "11".repeat(32)),
        )
        .unwrap();
        fs::set_permissions(paths.metadata(), fs::Permissions::from_mode(0o600)).unwrap();
        let prepared = format!(
            "schema_version = 3\noperation_id = \"failed-upgrade-1\"\nstage_owner_uid = 1000\nauthority_sha256 = {:?}\nhub_origin = \"https://hub.example\"\nhost_id = \"host-1\"\nsource_probe_id = \"probe-1\"\nsource_bundle_version = \"1.2.3\"\nsource_install_state_sha256 = {:?}\nsource_manifest_sha256 = {:?}\ntarget_bundle_version = \"1.2.4\"\ntarget_asset_set_digest = {:?}\ntarget_manifest_sha256 = {:?}\nverified_stage_sha256 = {:?}\nphase = \"prepared\"\nactivation_started = false\nactivated_targets = 0\nfinalized_targets = 0\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            format!("sha256:{}", "d".repeat(64)),
            "e".repeat(64),
            "f".repeat(64),
        );
        let journal_path = paths.bootstrap_state().join("probe-upgrade-attempt.toml");
        fs::write(&journal_path, &prepared).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();

        upgrade::fail_next_atomic_write_containing("phase = \"activation-started\"");
        assert_eq!(
            upgrade::write_upgrade_attempt_from_journal(
                &paths,
                &prepared,
                "activation-started",
                0,
                0,
            ),
            Err(InstallError::Io),
        );
        assert!(
            fs::read_to_string(&journal_path)
                .unwrap()
                .contains("phase = \"prepared\"")
        );
        assert_eq!(
            upgrade::transition_upgrade_attempt_phase(
                &paths,
                upgrade::UpgradeAttemptTerminalTransition::RequireRepair,
            ),
            Err(InstallError::ExistingResidue),
        );
        upgrade::transition_upgrade_attempt_phase(
            &paths,
            upgrade::UpgradeAttemptTerminalTransition::AbortPreactivation,
        )
        .unwrap();
        write_operation_status(
            &paths,
            &UpgradeAttempt {
                operation_id: "failed-upgrade-1".to_owned(),
                stage_owner_uid: 1000,
                authority_sha256: Some("a".repeat(64)),
            },
            "1.2.4",
            "failed",
            Some("lifecycle.upgrade_failed_before_activation"),
        )
        .unwrap();

        assert_eq!(
            issue_probe_repair_eligibility(&paths),
            Err(InstallError::ExistingResidue),
            "a later writable error tail must not manufacture the activation boundary",
        );
        assert_eq!(
            issue_probe_repair_evidence(
                &paths,
                1_725_000_000_000,
                1_725_000_060_000,
                "request-nonce-1",
            ),
            Err(InstallError::ExistingResidue),
        );
        let status = fs::read_to_string(paths.state().join("probe-operation-status.toml")).unwrap();
        assert!(status.contains("lifecycle.upgrade_failed_before_activation"));
        assert!(!status.contains("repair_eligibility"));

        fs::write(
            &journal_path,
            prepared
                .replace("phase = \"prepared\"", "phase = \"activation-started\"")
                .replace("activation_started = false", "activation_started = true"),
        )
        .unwrap();
        assert_eq!(
            issue_probe_repair_eligibility(&paths)
                .unwrap()
                .evidence
                .activated_targets,
            0,
            "the durable boundary precedes systemd stop and the first target rename",
        );
    }

    #[test]
    fn legacy_schema2_journals_migrate_only_with_proven_postactivation_progress() {
        for (phase, activated, finalized, accepted) in [
            ("activation-started", 0, 0, true),
            ("finalizing", 21, 7, true),
            ("repair-required", 0, 0, false),
        ] {
            let temporary = tempdir().unwrap();
            let paths = FixedInstallPaths::under(temporary.path());
            fs::create_dir_all(paths.bootstrap_state()).unwrap();
            fs::create_dir_all(paths.metadata().parent().unwrap()).unwrap();
            fs::write(
                paths.metadata(),
                format!("lifecycle_authority_install_key = {:?}\n", "11".repeat(32)),
            )
            .unwrap();
            fs::set_permissions(paths.metadata(), fs::Permissions::from_mode(0o600)).unwrap();
            let journal = format!(
                "schema_version = 2\noperation_id = \"legacy-v2\"\nstage_owner_uid = 1000\nauthority_sha256 = {:?}\nhub_origin = \"https://hub.example\"\nhost_id = \"host-1\"\nsource_probe_id = \"probe-1\"\nsource_bundle_version = \"1.2.3\"\nsource_install_state_sha256 = {:?}\nsource_manifest_sha256 = {:?}\ntarget_bundle_version = \"1.2.4\"\ntarget_asset_set_digest = {:?}\ntarget_manifest_sha256 = {:?}\nverified_stage_sha256 = {:?}\nphase = {phase:?}\nactivated_targets = {activated}\nfinalized_targets = {finalized}\n",
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                format!("sha256:{}", "d".repeat(64)),
                "e".repeat(64),
                "f".repeat(64),
            );
            let journal_path = paths.bootstrap_state().join("probe-upgrade-attempt.toml");
            fs::write(&journal_path, journal).unwrap();
            fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();

            let result = issue_probe_repair_eligibility(&paths);
            assert_eq!(result.is_ok(), accepted, "legacy phase {phase}");
            let persisted = fs::read_to_string(journal_path).unwrap();
            if accepted {
                assert!(persisted.contains("schema_version = 3"));
                assert!(persisted.contains("activation_started = true"));
            } else {
                assert!(persisted.contains("schema_version = 2"));
            }
        }
    }

    #[test]
    fn legacy_migration_failure_and_incoherent_schema3_are_zero_side_effect() {
        for (schema, phase, marker, activated, finalized, fail_migration) in [
            (2, "activation-started", None, 0, 0, true),
            (1, "repair-required", None, 0, 0, false),
            (3, "activation-started", Some(false), 0, 0, false),
            (3, "finalizing", Some(true), 19, 7, false),
        ] {
            let temporary = tempdir().unwrap();
            let paths = FixedInstallPaths::under(temporary.path());
            let original = write_authority_upgrade_journal(
                &paths, schema, phase, marker, activated, finalized,
            );
            let destinations = upgrade_destinations(&paths);
            fs::create_dir_all(destinations[0].parent().unwrap()).unwrap();
            fs::write(&destinations[0], b"unchanged").unwrap();
            let staged = destinations[0].with_file_name(format!(
                ".{}.enoki-upgrade-new",
                destinations[0].file_name().unwrap().to_str().unwrap(),
            ));
            fs::write(&staged, b"staged").unwrap();
            if fail_migration {
                upgrade::fail_next_atomic_write_containing("schema_version = 3");
            }

            let mut systemd = Systemd::default();
            assert!(recover_incomplete_probe_upgrade(&paths, &mut systemd).is_err());
            assert!(systemd.calls.is_empty());
            assert_eq!(fs::read(&destinations[0]).unwrap(), b"unchanged");
            assert_eq!(fs::read(&staged).unwrap(), b"staged");
            assert_eq!(
                fs::read_to_string(paths.bootstrap_state().join("probe-upgrade-attempt.toml"))
                    .unwrap(),
                original,
            );
        }
    }

    #[test]
    fn finalizing_recovery_never_reactivates_and_preserves_progress_on_a_second_failure() {
        let temporary = tempdir().unwrap();
        let paths = FixedInstallPaths::under(temporary.path());
        fs::create_dir_all(paths.metadata().parent().unwrap()).unwrap();
        fs::write(
            paths.metadata(),
            format!("lifecycle_authority_install_key = {:?}\n", "11".repeat(32)),
        )
        .unwrap();
        fs::set_permissions(paths.metadata(), fs::Permissions::from_mode(0o600)).unwrap();
        write_authority_upgrade_journal(&paths, 3, "finalizing", Some(true), 21, 7);
        let destinations = upgrade_destinations(&paths);
        for destination in &destinations {
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
        }
        let blocked_backup = destinations[7].with_file_name(format!(
            ".{}.enoki-upgrade-old",
            destinations[7].file_name().unwrap().to_str().unwrap(),
        ));
        fs::create_dir(&blocked_backup).unwrap();

        let mut systemd = Systemd::default();
        assert_eq!(
            recover_incomplete_probe_upgrade(&paths, &mut systemd),
            Err(InstallError::Io),
        );
        assert!(systemd.calls.is_empty());
        let failed =
            fs::read_to_string(paths.bootstrap_state().join("probe-upgrade-attempt.toml")).unwrap();
        assert!(failed.contains("phase = \"repair-required\""));
        assert!(failed.contains("activated_targets = 21"));
        assert!(failed.contains("finalized_targets = 7"));
        assert_eq!(
            issue_probe_repair_eligibility(&paths)
                .unwrap()
                .evidence
                .finalized_targets,
            7,
        );

        assert_eq!(
            recover_incomplete_probe_upgrade(&paths, &mut systemd),
            Err(InstallError::Io),
        );
        assert!(systemd.calls.is_empty());
        let failed_again =
            fs::read_to_string(paths.bootstrap_state().join("probe-upgrade-attempt.toml")).unwrap();
        assert!(failed_again.contains("phase = \"repair-required\""));
        assert!(failed_again.contains("activated_targets = 21"));
        assert!(failed_again.contains("finalized_targets = 7"));
    }

    #[test]
    fn stale_upgrade_attempt_cas_cannot_overwrite_a_newer_tuple() {
        let temporary = tempdir().unwrap();
        let paths = FixedInstallPaths::under(temporary.path());
        let stale = write_authority_upgrade_journal(&paths, 3, "prepared", Some(false), 0, 0);
        upgrade::write_upgrade_attempt_from_journal(&paths, &stale, "activation-started", 0, 0)
            .unwrap();

        assert_eq!(
            upgrade::write_upgrade_attempt_from_journal(&paths, &stale, "activation-started", 1, 0,),
            Err(InstallError::ExistingResidue),
        );
        let current =
            fs::read_to_string(paths.bootstrap_state().join("probe-upgrade-attempt.toml")).unwrap();
        assert!(current.contains("activated_targets = 0"));
    }

    #[test]
    fn repair_authority_is_offline_verified_and_consumed_once_in_an_independent_journal() {
        let temporary = tempdir().unwrap();
        let paths = FixedInstallPaths::under(temporary.path());
        fs::create_dir_all(paths.bootstrap_state()).unwrap();
        fs::create_dir_all(paths.metadata().parent().unwrap()).unwrap();
        fs::create_dir_all(paths.state()).unwrap();
        let key = [0x11_u8; 32];
        fs::write(
            paths.metadata(),
            format!("lifecycle_authority_install_key = {:?}\n", "11".repeat(32)),
        )
        .unwrap();
        fs::set_permissions(paths.metadata(), fs::Permissions::from_mode(0o600)).unwrap();
        let journal = format!(
            "schema_version = 2\noperation_id = \"failed-upgrade-1\"\nstage_owner_uid = 1000\nauthority_sha256 = {:?}\nhub_origin = \"https://hub.example\"\nhost_id = \"host-1\"\nsource_probe_id = \"probe-1\"\nsource_bundle_version = \"1.2.3\"\nsource_install_state_sha256 = {:?}\nsource_manifest_sha256 = {:?}\ntarget_bundle_version = \"1.2.4\"\ntarget_asset_set_digest = {:?}\ntarget_manifest_sha256 = {:?}\nverified_stage_sha256 = {:?}\nphase = \"repair-required\"\nactivation_started = true\nactivated_targets = 3\nfinalized_targets = 0\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            format!("sha256:{}", "d".repeat(64)),
            "e".repeat(64),
            "f".repeat(64),
        );
        let journal_path = paths.bootstrap_state().join("probe-upgrade-attempt.toml");
        fs::write(&journal_path, journal).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        let signed = issue_probe_repair_evidence(
            &paths,
            1_725_000_000_000,
            1_725_000_060_000,
            "request-nonce-1",
        )
        .unwrap();
        let authority = crate::lifecycle::RepairAuthorityV1 {
            schema_version: 1,
            hub_origin: signed.evidence.hub_origin.clone(),
            host_id: signed.evidence.host_id.clone(),
            probe_id: signed.evidence.probe_id.clone(),
            failed_operation_id: signed.evidence.failed_operation_id.clone(),
            repair_operation_id: "repair-operation-1".to_owned(),
            repair_nonce: "repair-nonce-1".to_owned(),
            repair_evidence_sha256: signed.evidence.sha256(),
            target_bundle_version: signed.evidence.target_bundle_version.clone(),
            target_asset_set_digest: signed.evidence.target_asset_set_digest.clone(),
            target_manifest_sha256: signed.evidence.target_manifest_sha256.clone(),
            verified_stage_sha256: signed.evidence.verified_stage_sha256.clone(),
            expires_at_ms: 1_725_000_060_000,
        };
        let mut signer = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        signer.update(b"enoki/lifecycle-repair-authority/hmac-sha256/v1\0");
        signer.update(&authority.canonical_bytes());
        let authority_signature: String = signer
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        let consumed = consume_probe_repair_authority(
            &paths,
            &signed.evidence,
            &signed.signature,
            &authority,
            &authority_signature,
            1_725_000_001_000,
        )
        .unwrap();
        assert_eq!(consumed.repair_operation_id, "repair-operation-1");
        let repair_journal =
            fs::read_to_string(paths.bootstrap_state().join("probe-repair-attempt.toml")).unwrap();
        assert!(repair_journal.contains("state = \"consumed\""));
        assert!(repair_journal.contains("repair_evidence_sha256 = "));
        assert!(repair_journal.contains("capsule_mac = "));
        fs::write(
            paths.bootstrap_state().join("probe-repair-attempt.toml"),
            repair_journal.replace("state = \"consumed\"", "state = \"completion-pending\""),
        )
        .unwrap();
        assert_eq!(
            resume_probe_repair_intent(&paths),
            Err(InstallError::ExistingResidue),
        );
        fs::write(
            paths.bootstrap_state().join("probe-repair-attempt.toml"),
            &repair_journal,
        )
        .unwrap();
        assert_eq!(
            consume_probe_repair_authority(
                &paths,
                &signed.evidence,
                &signed.signature,
                &authority,
                &authority_signature,
                1_725_000_001_001,
            )
            .unwrap(),
            consumed,
        );
        let progressed = fs::read_to_string(&journal_path)
            .unwrap()
            .replace("phase = \"repair-required\"", "phase = \"activated\"")
            .replace("activated_targets = 3", "activated_targets = 21")
            .replace("finalized_targets = 0", "finalized_targets = 21");
        fs::write(&journal_path, &progressed).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            resume_probe_repair_intent(&paths).unwrap(),
            Some(consumed.clone())
        );
        mark_probe_repair_unresolved(&paths, &consumed).unwrap();
        assert!(
            fs::read_to_string(paths.bootstrap_state().join("probe-repair-attempt.toml"))
                .unwrap()
                .contains("state = \"unresolved\"")
        );
        let status = fs::read_to_string(paths.state().join("probe-operation-status.toml")).unwrap();
        assert!(status.contains("operation_id = \"repair-operation-1\""));
        assert!(status.contains("status = \"failed\""));
        assert!(status.contains("error_code = \"lifecycle.repair_unresolved\""));
        assert!(resume_probe_repair_intent(&paths).unwrap().is_none());
        let repair_journal_path = paths.bootstrap_state().join("probe-repair-attempt.toml");
        let unresolved_capsule = fs::read_to_string(&repair_journal_path).unwrap();
        let unresolved_status = status.clone();
        let mut rejected_systemd = Systemd::default();
        let mut rejected_cleanup = false;
        assert_eq!(
            execute_authorized_probe_repair(&paths, &consumed, &mut rejected_systemd, |_, _| {
                rejected_cleanup = true;
                Ok(())
            },),
            Err(InstallError::ExistingResidue),
        );
        assert_eq!(
            fs::read_to_string(&repair_journal_path).unwrap(),
            unresolved_capsule
        );
        assert_eq!(
            fs::read_to_string(paths.state().join("probe-operation-status.toml")).unwrap(),
            unresolved_status
        );
        assert!(rejected_systemd.calls.is_empty());
        assert!(!rejected_cleanup);

        let repair_required = progressed
            .replace("phase = \"activated\"", "phase = \"repair-required\"")
            .replace("activated_targets = 21", "activated_targets = 3")
            .replace("finalized_targets = 21", "finalized_targets = 0");
        fs::write(&journal_path, &repair_required).unwrap();
        let fresh = issue_probe_repair_evidence(
            &paths,
            1_725_000_002_000,
            1_725_000_062_000,
            "request-nonce-2",
        )
        .unwrap();
        let fresh_authority = crate::lifecycle::RepairAuthorityV1 {
            schema_version: 1,
            hub_origin: fresh.evidence.hub_origin.clone(),
            host_id: fresh.evidence.host_id.clone(),
            probe_id: fresh.evidence.probe_id.clone(),
            failed_operation_id: fresh.evidence.failed_operation_id.clone(),
            repair_operation_id: "repair-operation-2".to_owned(),
            repair_nonce: "repair-nonce-2".to_owned(),
            repair_evidence_sha256: fresh.evidence.sha256(),
            target_bundle_version: fresh.evidence.target_bundle_version.clone(),
            target_asset_set_digest: fresh.evidence.target_asset_set_digest.clone(),
            target_manifest_sha256: fresh.evidence.target_manifest_sha256.clone(),
            verified_stage_sha256: fresh.evidence.verified_stage_sha256.clone(),
            expires_at_ms: 1_725_000_062_000,
        };
        let mut fresh_signer = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        fresh_signer.update(b"enoki/lifecycle-repair-authority/hmac-sha256/v1\0");
        fresh_signer.update(&fresh_authority.canonical_bytes());
        let fresh_authority_signature: String = fresh_signer
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            consume_probe_repair_authority(
                &paths,
                &fresh.evidence,
                &fresh.signature,
                &authority,
                &authority_signature,
                1_725_000_003_000,
            ),
            Err(InstallError::ExistingResidue),
        );
        let resumed = consume_probe_repair_authority(
            &paths,
            &fresh.evidence,
            &fresh.signature,
            &fresh_authority,
            &fresh_authority_signature,
            1_725_000_003_000,
        )
        .unwrap();
        assert_eq!(resumed.repair_operation_id, "repair-operation-2");
        let cleanup_required = repair_required
            .replace(
                "phase = \"repair-required\"",
                "phase = \"stage-cleanup-required\"",
            )
            .replace("activated_targets = 3", "activated_targets = 21")
            .replace("finalized_targets = 0", "finalized_targets = 21");
        fs::write(&journal_path, cleanup_required).unwrap();

        let repair_write = paths
            .bootstrap_state()
            .join(".probe-repair-attempt.toml.enoki-write");
        fs::create_dir(&repair_write).unwrap();
        fs::write(repair_write.join("blocks-replace"), b"fault").unwrap();
        let repair_running_status =
            fs::read_to_string(paths.state().join("probe-operation-status.toml")).unwrap();
        let mut systemd = Systemd::default();
        assert_eq!(
            execute_authorized_probe_repair(&paths, &resumed, &mut systemd, |_, _| { Ok(()) }),
            Err(InstallError::Io),
        );
        assert_eq!(
            fs::read_to_string(paths.state().join("probe-operation-status.toml")).unwrap(),
            repair_running_status,
            "Repair finalization must not republish the failed Upgrade status",
        );
        assert!(
            fs::read_to_string(&journal_path)
                .unwrap()
                .contains("phase = \"activated\"")
        );
        persist_probe_repair_execution_failure(&paths, &resumed).unwrap();
        let resumed = resume_probe_repair_intent(&paths).unwrap().unwrap();
        assert_eq!(resumed.state, RepairIntentState::Consumed);
        assert!(systemd.calls.is_empty());
        fs::remove_dir_all(&repair_write).unwrap();

        let status_write = paths
            .state()
            .join(".probe-operation-status.toml.enoki-write");
        fs::create_dir(&status_write).unwrap();
        fs::write(status_write.join("blocks-replace"), b"fault").unwrap();
        assert_eq!(
            execute_authorized_probe_repair(&paths, &resumed, &mut systemd, |_, _| {
                panic!("an activated Upgrade must not reacquire or clean a stage")
            }),
            Err(InstallError::Io),
        );
        let pending = resume_probe_repair_intent(&paths).unwrap().unwrap();
        assert_eq!(pending.state, RepairIntentState::CompletionPending);
        fs::remove_dir_all(&status_write).unwrap();
        assert_eq!(
            mark_probe_repair_unresolved(&paths, &pending),
            Err(InstallError::ExistingResidue),
        );
        assert_eq!(
            resume_probe_repair_intent(&paths).unwrap().unwrap().state,
            RepairIntentState::CompletionPending,
        );

        fs::create_dir(&repair_write).unwrap();
        fs::write(repair_write.join("blocks-replace"), b"fault").unwrap();
        assert_eq!(
            complete_authorized_probe_repair(&paths, &pending),
            Err(InstallError::Io),
        );
        persist_probe_repair_execution_failure(&paths, &pending).unwrap();
        let still_pending = resume_probe_repair_intent(&paths).unwrap().unwrap();
        assert_eq!(still_pending.state, RepairIntentState::CompletionPending);
        let status = fs::read_to_string(paths.state().join("probe-operation-status.toml")).unwrap();
        assert!(status.contains("status = \"running\""));
        assert!(!status.contains("status = \"failed\""));
        fs::remove_dir_all(&repair_write).unwrap();
        complete_authorized_probe_repair(&paths, &pending).unwrap();
        assert!(resume_probe_repair_intent(&paths).unwrap().is_none());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn consumed_recovery_persistence_failures_stay_preactivation_until_explicit_retry() {
        #[derive(Clone, Copy)]
        enum Failure {
            Cleanup,
            AbortJournal,
            Status,
        }

        for failure in [Failure::Cleanup, Failure::AbortJournal, Failure::Status] {
            let temporary = tempdir().unwrap();
            let paths = FixedInstallPaths::under(temporary.path());
            fs::create_dir_all(paths.bootstrap_state()).unwrap();
            fs::create_dir_all(paths.state()).unwrap();
            consume_probe_upgrade_authority(
                &paths,
                &UpgradeAuthorityConsumption {
                    operation_id: "consumed-recovery".to_owned(),
                    stage_owner_uid: unsafe { libc::geteuid() },
                    hub_origin: "https://hub.example".to_owned(),
                    host_id: "host_01".to_owned(),
                    probe_id: "probe_01".to_owned(),
                    source_bundle_version: "1.2.3".to_owned(),
                    source_install_state_sha256: "a".repeat(64),
                    source_manifest_sha256: "b".repeat(64),
                    target_bundle_version: "1.2.4".to_owned(),
                    target_asset_set_digest: format!("sha256:{}", "c".repeat(64)),
                    target_manifest_sha256: "d".repeat(64),
                    verified_stage_sha256: "e".repeat(64),
                },
            )
            .unwrap();

            let destinations = upgrade_destinations(&paths);
            for destination in &destinations {
                fs::create_dir_all(destination.parent().unwrap()).unwrap();
                fs::write(destination, b"old-source").unwrap();
            }
            let failed_path = match failure {
                Failure::Cleanup => destinations[0].with_file_name(format!(
                    ".{}.enoki-upgrade-new",
                    destinations[0].file_name().unwrap().to_str().unwrap(),
                )),
                Failure::AbortJournal => paths
                    .bootstrap_state()
                    .join(".probe-upgrade-attempt.toml.enoki-write"),
                Failure::Status => paths
                    .state()
                    .join(".probe-operation-status.toml.enoki-write"),
            };
            fs::create_dir(&failed_path).unwrap();
            fs::write(failed_path.join("blocks-removal"), b"fault").unwrap();

            let mut systemd = Systemd::default();
            assert_eq!(
                recover_incomplete_probe_upgrade(&paths, &mut systemd),
                Err(InstallError::Io),
            );
            let journal_path = paths.bootstrap_state().join("probe-upgrade-attempt.toml");
            let failed_phase = fs::read_to_string(&journal_path).unwrap();
            match failure {
                Failure::Status => assert!(failed_phase.contains("phase = \"aborted\"")),
                Failure::Cleanup | Failure::AbortJournal => {
                    assert!(failed_phase.contains("phase = \"consumed\""));
                }
            }
            assert!(systemd.calls.is_empty());

            fs::remove_dir_all(&failed_path).unwrap();
            let receipt = recover_incomplete_probe_upgrade(&paths, &mut systemd)
                .unwrap()
                .expect("explicit retry must complete the preactivation cleanup");
            assert!(!receipt.activated);
            assert!(systemd.calls.is_empty());
            assert!(
                fs::read_to_string(&journal_path)
                    .unwrap()
                    .contains("phase = \"aborted\"")
            );
            finalize_probe_upgrade_stage_cleanup(&paths, &receipt).unwrap();
            assert!(
                destinations
                    .iter()
                    .all(|destination| fs::read(destination).unwrap() == b"old-source")
            );
        }
    }

    #[test]
    fn observation_units_keep_callers_roles_and_deadlines_fixed() {
        let probe = service_unit();
        let runtime_socket = observation_runtime_socket_unit();
        let runtime = observation_runtime_unit();
        let provider_socket = cpu_provider_socket_unit();
        let provider = cpu_provider_unit();
        let disk_provider_socket = disk_health_provider_socket_unit();
        let disk_provider = disk_health_provider_unit();
        let upgrade_socket = lifecycle_upgrade_socket_unit();
        let upgrade = lifecycle_upgrade_unit();

        assert!(probe.contains("Wants=network-online.target enoki-observation-runtime.socket\n"));
        assert!(!probe.contains("Requires=enoki-cpu-resource-provider.socket"));
        assert!(probe.contains("DynamicUser=true"));
        assert!(probe.contains("SupplementaryGroups=enoki-probe-ipc"));
        assert!(probe.contains("StateDirectory=enoki-probe"));
        assert!(probe.contains("StateDirectoryMode=0750"));
        assert!(probe.contains(
            "Wants=enoki-probe-lifecycle-companion.socket enoki-probe-lifecycle-upgrade.socket"
        ));
        assert!(runtime_socket.contains("SocketGroup=enoki-probe-ipc"));
        assert!(runtime.contains("User=enoki-observation-runtime"));
        assert!(runtime.contains("PrivateNetwork=true"));
        assert!(runtime.contains("SupplementaryGroups=enoki-observation-ipc"));
        assert!(provider_socket.contains("SocketGroup=enoki-observation-ipc"));
        assert!(provider_socket.contains("MaxConnections=1"));
        assert!(provider_socket.contains("TriggerLimitBurst=12"));
        assert!(provider.contains("ExecStart=/usr/local/bin/enoki-cpu-resource-provider\n"));
        assert!(provider.contains("RuntimeMaxSec=3s"));
        assert!(provider.contains("KillMode=control-group"));
        assert!(provider.contains("RestrictAddressFamilies=AF_UNIX AF_NETLINK"));
        assert!(provider.contains("IPAddressDeny=any"));
        assert!(provider.contains("SocketBindDeny=ipv4:any"));
        assert!(provider.contains("SocketBindDeny=ipv6:any"));
        assert!(provider.contains("ReadOnlyPaths=/proc/stat"));
        assert!(
            !provider.contains("ProcSubset=pid"),
            "CPU Provider 必须能读取非进程类顶层 /proc/stat"
        );
        assert!(!provider.contains('%'));
        assert!(runtime.contains(
            "Requires=enoki-cpu-resource-provider.socket enoki-disk-health-resource-provider.socket"
        ));
        assert!(disk_provider_socket.contains("SocketGroup=enoki-observation-ipc"));
        assert!(disk_provider_socket.contains("MaxConnections=1"));
        assert!(disk_provider_socket.contains("TriggerLimitBurst=2"));
        assert!(
            disk_provider.contains("ExecStart=/usr/local/bin/enoki-disk-health-resource-provider")
        );
        assert!(disk_provider.contains("RuntimeMaxSec=10s"));
        assert!(disk_provider.contains("KillMode=control-group"));
        assert!(disk_provider.contains("CapabilityBoundingSet=CAP_SYS_RAWIO"));
        assert!(disk_provider.contains("DevicePolicy=closed"));
        assert!(disk_provider.contains("DeviceAllow=block-* rw"));
        assert!(disk_provider.contains("IPAddressDeny=any"));
        assert!(disk_provider.contains("SocketBindDeny=any"));
        assert!(disk_provider.contains("BindReadOnlyPaths=-/usr/sbin/smartctl -/usr/bin/smartctl"));
        assert!(upgrade_socket.contains("ListenStream=/run/enoki-probe-lifecycle-upgrade.sock"));
        assert!(upgrade_socket.contains("SocketGroup=enoki-probe-ipc"));
        assert!(
            upgrade.contains("ExecStart=/usr/local/bin/enoki-probe-lifecycle-companion --upgrade")
        );
        assert!(upgrade.contains("PrivateNetwork=true"));
        assert!(upgrade.contains("RestrictAddressFamilies=AF_UNIX"));
        assert!(upgrade.contains("IPAddressDeny=any"));
    }

    #[test]
    fn signed_execution_roles_render_the_closed_systemd_policy_floor() {
        let role_units = fixed_execution_role_units();
        assert_eq!(
            role_units.each_ref().map(|(profile, _)| *profile),
            [
                "probe-v5",
                "observation-runtime-v4",
                "system-state-provider-v5",
                "disk-health-provider-v3",
                "lifecycle-companion-v3",
            ],
        );
        for (role, unit) in &role_units {
            let unit = std::str::from_utf8(unit).expect("canonical unit 为 UTF-8");
            for property in [
                "NoNewPrivileges=true",
                "CapabilityBoundingSet=",
                "AmbientCapabilities=",
                "PrivateTmp=true",
                "ProtectSystem=strict",
                "ProtectControlGroups=true",
                "ProtectKernelTunables=true",
                "ProtectKernelModules=true",
                "ProtectKernelLogs=true",
                "ProtectClock=true",
                "RestrictSUIDSGID=true",
                "RestrictRealtime=true",
                "RestrictNamespaces=true",
                "LockPersonality=true",
                "MemoryDenyWriteExecute=true",
                "SystemCallArchitectures=native",
                "SystemCallFilter=@system-service",
                "TasksMax=64",
                "UMask=0077",
            ] {
                assert!(unit.contains(property), "{role} 缺少 {property}");
            }
            assert!(unit.contains("MemoryMax="), "{role} 缺少内存上限");
        }

        for unit in [
            service_unit(),
            observation_runtime_unit(),
            cpu_provider_unit(),
        ] {
            assert!(unit.contains("PrivateDevices=true"));
        }
        for provider in [cpu_provider_unit(), disk_health_provider_unit()] {
            assert!(provider.contains(
                "SystemCallFilter=landlock_create_ruleset landlock_add_rule landlock_restrict_self"
            ));
        }
        let disk_health = disk_health_provider_unit();
        assert!(disk_health.contains("DevicePolicy=closed"));
        assert!(disk_health.contains("DeviceAllow=block-* rw"));
        assert!(!disk_health.contains("PrivateDevices=true"));
    }

    #[test]
    fn observation_runtime_has_a_fixed_progress_watchdog_and_crash_budget() {
        let runtime = observation_runtime_unit();

        for property in [
            "StartLimitIntervalSec=60s",
            "StartLimitBurst=3",
            "Type=notify",
            "NotifyAccess=main",
            "WatchdogSec=30s",
            "KillMode=control-group",
            "Restart=on-failure",
            "RestartSec=5s",
        ] {
            assert!(runtime.contains(property), "Runtime 缺少 {property}");
        }
    }

    #[test]
    fn runtime_budget_exhaustion_wakes_a_fixed_networkless_recorder() {
        let runtime = observation_runtime_unit();
        let recorder = observation_runtime_failure_recorder_unit();

        assert!(runtime.contains("OnFailure=enoki-observation-runtime-failure.service"));
        for property in [
            "Type=oneshot",
            "User=root",
            "Group=root",
            "ExecStart=/usr/local/bin/enoki-probe-lifecycle-companion record-runtime-failure",
            "PrivateNetwork=true",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "RestrictAddressFamilies=AF_UNIX",
            "IPAddressDeny=any",
            "SocketBindDeny=any",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/enoki-probe/runtime-failure",
        ] {
            assert!(recorder.contains(property), "failure recorder 缺少 {property}");
        }
        assert!(!recorder.contains("Environment="));
        assert!(!recorder.contains("StandardInput=socket"));
    }

    #[test]
    fn production_state_parent_and_root_failure_child_have_distinct_custody() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());

        activate_complete_fresh_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk_health,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle().with_test_observation_receipts(5),
            &trust(),
            &paths,
            &mut accounts,
            &mut systemd,
        )
        .unwrap();

        let state = fs::symlink_metadata(paths.state()).unwrap();
        let identity = fs::symlink_metadata(paths.identity()).unwrap();
        assert_eq!(state.mode() & 0o7777, 0o750);
        assert_eq!((state.uid(), state.gid()), (identity.uid(), identity.gid()));
        let recorder = fs::read_to_string(paths.observation_runtime_failure_recorder_unit())
            .unwrap();
        assert!(recorder.contains("StateDirectory=enoki-probe/runtime-failure"));
        assert!(recorder.contains("StateDirectoryMode=0700"));
        assert!(recorder.contains("User=root\nGroup=root"));
    }

    #[test]
    fn probe_startup_does_not_propagate_runtime_crash_budget_exhaustion() {
        let probe = service_unit();

        assert!(probe.contains("After=network-online.target enoki-observation-runtime.socket\n"));
        assert!(probe.contains("Wants=network-online.target enoki-observation-runtime.socket\n"));
        assert!(!probe.contains("Requires=enoki-observation-runtime.socket\n"));
    }

    #[test]
    fn fixed_provider_role_closure_bounds_each_activation_and_the_global_total() {
        let sockets = [
            (
                cpu_provider_socket_unit(),
                "Service=enoki-cpu-resource-provider@.service",
                "TriggerLimitIntervalSec=10s",
                "TriggerLimitBurst=12",
            ),
            (
                disk_health_provider_socket_unit(),
                "Service=enoki-disk-health-resource-provider@.service",
                "TriggerLimitIntervalSec=60s",
                "TriggerLimitBurst=2",
            ),
        ];
        assert_eq!(
            sockets.len(),
            2,
            "签名角色闭包固定全局最多两个 Provider 实例"
        );
        for (socket, service, interval, burst) in sockets {
            for property in [
                "Accept=true",
                "SocketMode=0660",
                "SocketUser=root",
                "SocketGroup=enoki-observation-ipc",
                "MaxConnections=1",
                "MaxConnectionsPerSource=1",
                "Backlog=1",
                service,
                interval,
                burst,
            ] {
                assert!(socket.contains(property), "Provider socket 缺少 {property}");
            }
        }
        for service in [cpu_provider_unit(), disk_health_provider_unit()] {
            for property in [
                "RuntimeMaxSec=",
                "TimeoutStartSec=",
                "TimeoutStopSec=1s",
                "KillMode=control-group",
                "SendSIGKILL=yes",
                "OOMPolicy=kill",
            ] {
                assert!(
                    service.contains(property),
                    "Provider service 缺少 {property}"
                );
            }
        }
    }

    #[test]
    fn canonical_roles_expose_only_their_declared_transport_and_resource_surfaces() {
        let probe = service_unit();
        assert!(probe.contains("Wants=network-online.target enoki-observation-runtime.socket\n"));
        assert!(!probe.contains("Requires=enoki-cpu-resource-provider.socket"));
        assert!(probe.contains("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"));
        assert!(probe.contains("ReadWritePaths=/var/lib/enoki-probe"));
        for control_path in [
            "-/run/systemd/private",
            "-/run/systemd/system",
            "-/run/dbus/system_bus_socket",
        ] {
            assert!(probe.contains(control_path));
        }

        let runtime = observation_runtime_unit();
        assert!(runtime.contains("PrivateNetwork=true"));
        assert!(runtime.contains("RestrictAddressFamilies=AF_UNIX"));
        assert!(runtime.contains("IPAddressDeny=any"));
        assert!(runtime.contains("/var/lib/enoki-probe/identity"));
        assert!(runtime.contains("SupplementaryGroups=enoki-observation-ipc"));

        let system_state = cpu_provider_unit();
        assert!(system_state.contains("CapabilityBoundingSet=\n"));
        assert!(system_state.contains("RestrictAddressFamilies=AF_UNIX AF_NETLINK"));
        assert!(system_state.contains("ReadOnlyPaths=/proc/stat"));
        assert!(!system_state.contains("DeviceAllow=block-*"));

        let disk_health = disk_health_provider_unit();
        assert!(disk_health.contains("CapabilityBoundingSet=CAP_SYS_RAWIO"));
        assert!(disk_health.contains("RestrictAddressFamilies=AF_UNIX\n"));
        assert!(!disk_health.contains("RestrictAddressFamilies=\n"));
        assert!(disk_health.contains("BindReadOnlyPaths=-/usr/sbin/smartctl"));
        assert!(!disk_health.contains("ReadOnlyPaths=/proc/stat"));

        let lifecycle = lifecycle_companion_unit();
        assert!(lifecycle.contains("ExecStart=/usr/local/bin/enoki-probe-lifecycle-companion"));
        assert!(lifecycle.contains("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"));
        assert!(lifecycle.contains("SocketBindDeny=ipv4:any"));
        assert!(lifecycle.contains("ReadWritePaths=/etc/enoki /etc/systemd/system /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers.d"));
        assert!(!lifecycle.contains("Environment="));
        assert!(!lifecycle.contains("PrivateNetwork=true"));
        let lifecycle_socket = lifecycle_companion_socket_unit();
        assert!(lifecycle_socket.contains("SocketGroup=enoki-probe-ipc"));
        assert!(lifecycle_socket.contains("Accept=yes"));

        assert!(observation_runtime_socket_unit().contains("SocketGroup=enoki-probe-ipc"));
        for socket in [
            cpu_provider_socket_unit(),
            disk_health_provider_socket_unit(),
        ] {
            assert!(socket.contains("SocketGroup=enoki-observation-ipc"));
            assert!(socket.contains("SocketMode=0660"));
        }
    }

    #[test]
    fn schema_four_omits_the_retired_operation_launcher_and_authority_path() {
        let config = bootstrap_config(
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            None,
        );
        assert!(!config.contains("upgrader_launch"));
        assert!(!config.contains("operation_sudoers_path"));

        let metadata = install_metadata(
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            true,
            "test-transaction",
        )
        .expect("test metadata");
        assert!(!metadata.contains("operation_sudoers_path"));
    }

    #[test]
    fn complete_observation_install_owns_and_rolls_back_the_static_ipc_group() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let mut probe = component();
        let mut runtime = component();
        let mut provider = component();
        let mut disk_health_provider = component();
        let mut lifecycle_companion = component();
        let mut acquirer = component();
        let mut activator = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            fail_start: true,
            ..Systemd::default()
        };

        let result = activate_complete_fresh_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk_health_provider,
                lifecycle_companion: &mut lifecycle_companion,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle().with_test_observation_receipts(5),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        );

        assert!(result.is_err());
        assert_eq!(accounts.ipc_calls, ["create", "remove"]);
        assert!(
            !temporary
                .path()
                .join("usr/local/bin/enoki-observation-runtime")
                .exists()
        );
    }

    fn assert_committed_replacement_resumes_after(failed_effect: &str) {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            fail_reload: failed_effect == "reload",
            fail_enable: failed_effect == "enable",
            fail_start: failed_effect == "start",
            fail_ready: failed_effect == "ready",
            ..Systemd::default()
        };
        let replacement_bundle = bundle().with_test_complete_receipts(5);
        let replacement_commit = replacement_commit(&replacement_bundle);
        let resume_binding = replacement_commit.resume_binding();

        let result = activate_complete_replacement_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk_health,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &replacement_bundle,
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
            &resume_binding,
        );

        assert_eq!(result, Err(InstallError::Systemd));
        assert!(temporary.path().join("usr/local/bin/enoki-probe").exists());
        assert!(temporary
            .path()
            .join("var/lib/enoki-probe/identity/probe-bootstrap.toml")
            .exists());
        assert!(temporary
            .path()
            .join("var/lib/enoki-probe-bootstrap/activation-journal.json")
            .exists());
        assert!(!accounts.calls.contains(&"remove"));
        assert!(!accounts.ipc_calls.contains(&"remove"));
        assert!(!systemd.calls.contains(&"disable"));
        assert!(!systemd.calls.contains(&"stop"));

        systemd.fail_reload = false;
        systemd.fail_enable = false;
        systemd.fail_start = false;
        systemd.fail_ready = false;
        systemd.registration_identity =
            Some(FixedInstallPaths::under(temporary.path()).identity());
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        activate_complete_replacement_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk_health,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &replacement_bundle,
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
            &resume_binding,
        )
        .expect("exact committed candidate resumes to the current layout");
        assert!(
            !accounts.calls.contains(&"remove"),
            "已提交 Replacement 恢复不得删除候选 identity"
        );
        assert!(
            !accounts.ipc_calls.contains(&"remove"),
            "已提交 Replacement 恢复不得删除候选 IPC group"
        );
        assert!(!systemd.calls.contains(&"disable"));
        assert!(!systemd.calls.contains(&"stop"));
        assert!(temporary
            .path()
            .join("var/lib/enoki-probe-bootstrap/current-layout")
            .exists());
        assert!(temporary
            .path()
            .join("var/lib/enoki-probe-bootstrap/activation-journal.json")
            .exists());
        finalize_complete_replacement_current_probe(
            &FixedInstallPaths::under(temporary.path()),
            &resume_binding,
            &replacement_bundle,
            &replacement_commit,
        )
        .unwrap();
        assert!(!temporary
            .path()
            .join("var/lib/enoki-probe-bootstrap/activation-journal.json")
            .exists());
    }

    #[test]
    fn committed_replacement_resumes_every_systemd_receipt_without_deleting_the_candidate() {
        for failed_effect in ["reload", "enable", "start", "ready"] {
            assert_committed_replacement_resumes_after(failed_effect);
        }
    }

    #[test]
    fn replacement_registration_drop_in_is_transient_and_canonical_restart_has_no_capsule_dependency() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let replacement_bundle = bundle().with_test_complete_receipts(5);
        let commit = replacement_commit(&replacement_bundle);
        let resume = commit.resume_binding();
        let registration = commit
            .registration_binding(&replacement_bundle.target)
            .expect("valid registration projection");
        let source = paths.replacement_registration_attempt_source();
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        crate::secure_file::atomic_write(
            &source,
            b"root-private-attempt",
            0o600,
            Some((paths.expected_root_uid(), paths.expected_root_gid())),
        )
        .unwrap();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            fail_ready: true,
            ..Systemd::default()
        };
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        let first = activate_complete_replacement_current_probe_with_registration(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk_health,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &replacement_bundle,
            &trust(),
            &paths,
            &mut accounts,
            &mut systemd,
            &resume,
            &registration,
        );
        assert_eq!(first, Err(InstallError::Systemd));
        assert!(!systemd.calls.contains(&"canonical-restart"));
        let drop_in = paths.replacement_registration_drop_in();
        assert!(drop_in.exists(), "Readiness ambiguity retains one-shot delivery");
        let canonical_unit = fs::read_to_string(paths.unit()).unwrap();
        assert!(!canonical_unit.contains("LoadCredential="));

        systemd.fail_ready = false;
        systemd.registration_identity = Some(paths.identity());
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        activate_complete_replacement_current_probe_with_registration(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk_health,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &replacement_bundle,
            &trust(),
            &paths,
            &mut accounts,
            &mut systemd,
            &resume,
            &registration,
        )
        .expect("fresh activation resumes and retires transient delivery");
        assert!(!drop_in.exists());
        assert!(source.exists(), "activation cleanup alone cannot retire authority");
        assert!(!fs::read_to_string(paths.unit()).unwrap().contains("LoadCredential="));
        systemd.start().expect("canonical production restart needs no capsule");
        finalize_complete_replacement_current_probe(
            &paths,
            &resume,
            &replacement_bundle,
            &commit,
        )
        .unwrap();
        retire_replacement_registration_attempt_source(&paths).unwrap();
        assert!(!source.exists(), "root authority retires only after finalization");
        assert!(!source.parent().unwrap().exists(), "retirement leaves no state residue");
        systemd.start().expect("post-retirement canonical restart succeeds");
    }

    #[test]
    fn replacement_registration_production_recovery_windows() {
        if let Some(root) = std::env::var_os("ENOKI_TEST_REPLACEMENT_LIFECYCLE_ROOT") {
            run_replacement_lifecycle_recovery_child(Path::new(&root));
            return;
        }

        assert_eq!(unsafe { libc::geteuid() }, 0, "test requires root custody");
        assert_eq!(unsafe { libc::getegid() }, 0, "test requires root custody");
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let source = paths.replacement_registration_attempt_source();
        let drop_in = paths.replacement_registration_drop_in();
        let commit_path = paths
            .bootstrap_state()
            .join("replacement-migration.json");
        let runtime_credential = temporary
            .path()
            .join("run/credentials/enoki-probe.service/registration-attempt");
        fs::create_dir_all(paths.bootstrap_state()).unwrap();
        fs::set_permissions(
            paths.bootstrap_state(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let replacement_bundle = bundle().with_test_complete_receipts(5);
        let replacement_commit = replacement_commit(&replacement_bundle);
        FileReplacementCommitStore::at(&commit_path, unsafe { libc::geteuid() })
            .persist(&replacement_commit)
            .unwrap();

        assert!(!run_replacement_lifecycle_child(
            temporary.path(),
            "publish-source",
            Some((&source, "before-rename")),
        ));
        assert!(!source.exists());
        assert!(run_replacement_lifecycle_child(
            temporary.path(),
            "publish-source",
            None,
        ));
        let capsule: serde_json::Value =
            serde_json::from_slice(&fs::read(&source).unwrap()).unwrap();

        for point in ["before-rename", "after-rename"] {
            assert!(!run_replacement_lifecycle_child(
                temporary.path(),
                "activate",
                Some((&drop_in, point)),
            ));
            assert!(source.exists());
        }
        assert!(drop_in.exists());
        assert!(run_replacement_lifecycle_child(
            temporary.path(),
            "ready-timeout",
            None,
        ));
        assert!(drop_in.exists(), "Readiness ambiguity retains delivery");
        assert!(source.exists(), "Readiness ambiguity retains root material");

        assert!(!run_replacement_lifecycle_child(
            temporary.path(),
            "activate",
            Some((&drop_in, "before-unlink")),
        ));
        assert!(drop_in.exists());
        let registered_identity = fs::read_to_string(paths.identity()).unwrap();
        let capsule_key = capsule["candidatePrivateKeyPem"].as_str().unwrap();
        let other_key = valid_probe_private_key_pem();
        assert_ne!(other_key, capsule_key);
        fs::write(
            paths.identity(),
            registered_identity.replace(
                &format!("probe_private_key_pem = {capsule_key:?}"),
                &format!("probe_private_key_pem = {other_key:?}"),
            ),
        )
        .unwrap();
        assert!(run_replacement_lifecycle_child(
            temporary.path(),
            "reject-identity",
            None,
        ));
        fs::write(paths.identity(), &registered_identity).unwrap();
        fs::write(
            paths.identity(),
            registered_identity.replace(
                capsule["signedAttemptSha256"].as_str().unwrap(),
                &"e".repeat(64),
            ),
        )
        .unwrap();
        assert!(run_replacement_lifecycle_child(
            temporary.path(),
            "reject-identity",
            None,
        ));
        fs::write(paths.identity(), &registered_identity).unwrap();
        assert!(!run_replacement_lifecycle_child(
            temporary.path(),
            "activate",
            Some((&drop_in, "after-unlink")),
        ));
        assert!(!drop_in.exists());
        assert!(run_replacement_lifecycle_child(
            temporary.path(),
            "activate",
            None,
        ));
        assert!(!drop_in.exists());
        assert!(source.exists());
        assert!(commit_path.exists(), "未完成 Readiness 必须保留 commit custody");
        assert!(runtime_credential.exists());
        assert!(!fs::read_to_string(paths.unit()).unwrap().contains("LoadCredential="));

        for tampered in [
            registered_identity
                .lines()
                .filter(|line| !line.starts_with("registration_signed_attempt_sha256"))
                .map(|line| format!("{line}\n"))
                .collect::<String>(),
            format!("{registered_identity}registration_unknown = \"tamper\"\n"),
            format!(
                "{registered_identity}registration_host_id = \"host-registered\"\n"
            ),
        ] {
            fs::write(paths.identity(), tampered).unwrap();
            assert!(run_replacement_lifecycle_child(
                temporary.path(),
                "reject-retirement",
                None,
            ));
            assert!(source.exists());
            assert!(commit_path.exists());
        }
        fs::write(paths.identity(), &registered_identity).unwrap();

        fs::write(
            paths.identity(),
            registered_identity.replace(
                &format!("probe_private_key_pem = {capsule_key:?}"),
                &format!("probe_private_key_pem = {other_key:?}"),
            ),
        )
        .unwrap();
        assert!(run_replacement_lifecycle_child(
            temporary.path(),
            "reject-retirement",
            None,
        ));
        assert!(source.exists(), "wrong candidate key retains capsule");
        assert!(commit_path.exists(), "wrong candidate key retains commit");
        fs::write(
            paths.identity(),
            registered_identity.replace("probe-registered", "probe-tampered"),
        )
        .unwrap();
        assert!(run_replacement_lifecycle_child(
            temporary.path(),
            "reject-canonical-restart",
            None,
        ));
        assert!(source.exists(), "wrong Probe ID retains capsule");
        assert!(commit_path.exists(), "wrong Probe ID retains commit");
        fs::write(paths.identity(), &registered_identity).unwrap();

        for point in ["before-rename", "after-rename"] {
            assert!(!run_replacement_lifecycle_child(
                temporary.path(),
                "retire-source",
                Some((&paths.identity(), point)),
            ));
            assert!(source.exists(), "config rewrite crash retains capsule");
            assert!(commit_path.exists(), "config rewrite crash retains commit");
        }
        assert!(
            !fs::read_to_string(paths.identity())
                .unwrap()
                .lines()
                .any(|line| line.starts_with("registration_")),
            "after-rename retry starts from the closed canonical identity shape"
        );

        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!run_replacement_lifecycle_child(
            temporary.path(),
            "retire-source",
            None,
        ));
        assert!(source.exists());
        assert!(commit_path.exists());
        assert!(runtime_credential.exists());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();

        fs::create_dir_all(drop_in.parent().unwrap()).unwrap();
        fs::set_permissions(
            drop_in.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(&drop_in, b"stale delivery").unwrap();
        fs::set_permissions(&drop_in, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!run_replacement_lifecycle_child(
            temporary.path(),
            "retire-source",
            None,
        ));
        assert!(source.exists());
        assert!(commit_path.exists());
        assert!(runtime_credential.exists());
        fs::remove_file(&drop_in).unwrap();
        fs::remove_dir(drop_in.parent().unwrap()).unwrap();

        for point in ["fail-restart", "before-restart"] {
            assert!(!run_replacement_lifecycle_child(
                temporary.path(),
                "retire-source",
                Some((&runtime_credential, point)),
            ));
            assert!(source.exists());
            assert!(commit_path.exists());
            assert!(runtime_credential.exists());
        }
        assert!(!run_replacement_lifecycle_child(
            temporary.path(),
            "retire-source",
            Some((&runtime_credential, "after-restart")),
        ));
        assert!(source.exists());
        assert!(commit_path.exists());
        assert!(!runtime_credential.exists());

        assert!(!run_replacement_lifecycle_child(
            temporary.path(),
            "retire-source",
            Some((&source, "before-unlink")),
        ));
        assert!(source.exists());
        assert!(!run_replacement_lifecycle_child(
            temporary.path(),
            "retire-source",
            Some((&source, "after-unlink")),
        ));
        assert!(!source.exists());
        assert!(commit_path.exists(), "registration retirement 中断必须保留 commit");
        for point in ["fail-restart", "before-restart"] {
            assert!(!run_replacement_lifecycle_child(
                temporary.path(),
                "retire-source",
                Some((&runtime_credential, point)),
            ));
            assert!(!source.exists(), "source-absent retry 不得重建 capsule");
            assert!(
                commit_path.exists(),
                "source-absent retry 仍必须 fresh restart 后才可退休 commit"
            );
        }
        let canonical_identity = fs::read_to_string(paths.identity()).unwrap();
        for tampered in [
            canonical_identity.replace("probe-registered", "probe-tampered"),
            canonical_identity.replace(
                &format!("probe_private_key_pem = {capsule_key:?}"),
                &format!("probe_private_key_pem = {other_key:?}"),
            ),
        ] {
            assert_ne!(tampered, canonical_identity);
            fs::write(paths.identity(), tampered).unwrap();
            assert!(run_replacement_lifecycle_child(
                temporary.path(),
                "reject-canonical-restart",
                None,
            ));
            assert!(!source.exists());
            assert!(
                commit_path.exists(),
                "Hub-authenticated canonical restart 失败必须保留 commit"
            );
        }
        fs::write(paths.identity(), canonical_identity).unwrap();
        assert!(!run_replacement_lifecycle_child(
            temporary.path(),
            "retire-source",
            Some((&commit_path, "before-unlink")),
        ));
        assert!(commit_path.exists());
        assert!(!run_replacement_lifecycle_child(
            temporary.path(),
            "retire-source",
            Some((&commit_path, "after-unlink")),
        ));
        assert!(!commit_path.exists());
        assert!(run_replacement_lifecycle_child(
            temporary.path(),
            "retire-source",
            None,
        ));
        assert!(!source.parent().unwrap().exists());
        assert!(!commit_path.exists());
        assert!(
            !fs::read_to_string(paths.identity())
                .unwrap()
                .lines()
                .any(|line| line.starts_with("registration_")),
            "Replacement retirement 必须原子收敛为不含 one-shot metadata 的 canonical identity config"
        );
        assert!(
            !runtime_credential.exists(),
            "Replacement finalizer 成功返回前必须收敛为无注册 credential 的 canonical invocation"
        );
        assert!(run_replacement_lifecycle_child(
            temporary.path(),
            "canonical-start",
            None,
        ));
    }

    fn run_replacement_lifecycle_child(
        root: &Path,
        action: &str,
        crash: Option<(&Path, &str)>,
    ) -> bool {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "install::tests::replacement_registration_production_recovery_windows",
                "--nocapture",
            ])
            .env("ENOKI_TEST_REPLACEMENT_LIFECYCLE_ROOT", root)
            .env("ENOKI_TEST_REPLACEMENT_LIFECYCLE_ACTION", action);
        if let Some((path, point)) = crash {
            command
                .env("ENOKI_TEST_SECURE_FILE_PATH", path)
                .env("ENOKI_TEST_SECURE_FILE_CRASH_POINT", point);
        }
        command.status().unwrap().success()
    }

    fn run_replacement_lifecycle_recovery_child(root: &Path) {
        let paths = FixedInstallPaths::under(root);
        match std::env::var("ENOKI_TEST_REPLACEMENT_LIFECYCLE_ACTION")
            .unwrap()
            .as_str()
        {
            "publish-source" => {
                let source = paths.replacement_registration_attempt_source();
                fs::create_dir_all(source.parent().unwrap()).unwrap();
                fs::set_permissions(
                    source.parent().unwrap(),
                    fs::Permissions::from_mode(0o700),
                )
                .unwrap();
                let capsule = serde_json::to_vec(&serde_json::json!({
                    "candidatePrivateKeyPem": valid_probe_private_key_pem(),
                    "enrollmentTokenSha256": "e".repeat(64),
                    "hubOrigin": "https://hub.example",
                    "localClockReferenceMs": 1_725_000_000_000_u64,
                    "requestHex": "00",
                    "schemaVersion": 1,
                    "signedAttemptSha256": "f".repeat(64),
                }))
                .unwrap();
                crate::secure_file::atomic_write(
                    &source,
                    &capsule,
                    0o600,
                    Some((paths.expected_root_uid(), paths.expected_root_gid())),
                )
                .unwrap();
            }
            "activate" | "ready-timeout" | "reject-identity" => {
                let bundle = bundle().with_test_complete_receipts(5);
                let commit = replacement_commit(&bundle);
                let resume = commit.resume_binding();
                let registration = commit
                    .registration_binding(&bundle.target)
                    .expect("valid registration binding");
                let journal = paths.bootstrap_state().join("activation-journal.json");
                let resumed = journal.exists();
                let mut accounts = Accounts {
                    identity_present: resumed,
                    ipc_present: resumed,
                    ..Accounts::default()
                };
                let mut systemd = ProductionRecoverySystemd {
                    paths: &paths,
                    timeout: std::env::var("ENOKI_TEST_REPLACEMENT_LIFECYCLE_ACTION")
                        .as_deref()
                        == Ok("ready-timeout"),
                };
                let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
                    std::array::from_fn(|_| component());
                let result = activate_complete_replacement_current_probe_with_registration(
                    VerifiedCompleteFreshComponents {
                        probe: &mut probe,
                        observation_runtime: &mut runtime,
                        cpu_provider: &mut provider,
                        disk_health_provider: &mut disk_health,
                        lifecycle_companion: &mut lifecycle,
                        bootstrap_acquirer: &mut acquirer,
                        bootstrap_activator: &mut activator,
                    },
                    &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                    &bundle,
                    &trust(),
                    &paths,
                    &mut accounts,
                    &mut systemd,
                    &resume,
                    &registration,
                );
                if std::env::var("ENOKI_TEST_REPLACEMENT_LIFECYCLE_ACTION").as_deref()
                    == Ok("reject-identity")
                {
                    assert_eq!(result, Err(InstallError::ExistingResidue));
                } else if systemd.timeout {
                    assert_eq!(result, Err(InstallError::Systemd));
                } else {
                    result.unwrap();
                }
            }
            "retire-source" | "reject-retirement" | "reject-canonical-restart" => {
                let bundle = bundle().with_test_complete_receipts(5);
                let commit = replacement_commit(&bundle);
                let mut store = FileReplacementCommitStore::at(
                    paths
                        .bootstrap_state()
                        .join("replacement-migration.json"),
                    unsafe { libc::geteuid() },
                );
                let mut systemd = ProductionRecoverySystemd {
                    paths: &paths,
                    timeout: false,
                };
                let result = finalize_and_retire_complete_replacement_current_probe(
                    &paths,
                    &commit.resume_binding(),
                    &bundle,
                    &commit,
                    &mut store,
                    &mut systemd,
                );
                match std::env::var("ENOKI_TEST_REPLACEMENT_LIFECYCLE_ACTION").as_deref() {
                    Ok("reject-retirement") => {
                        assert_eq!(result, Err(InstallError::ExistingResidue));
                    }
                    Ok("reject-canonical-restart") => {
                        assert_eq!(result, Err(InstallError::Systemd));
                    }
                    _ => result.unwrap(),
                }
            }
            "canonical-start" => {
                ProductionRecoverySystemd {
                    paths: &paths,
                    timeout: false,
                }
                .start()
                .unwrap();
            }
            action => panic!("unknown recovery action {action}"),
        }
    }

    struct ProductionRecoverySystemd<'a> {
        paths: &'a FixedInstallPaths,
        timeout: bool,
    }

    impl SystemdPort for ProductionRecoverySystemd<'_> {
        fn require_absent(&mut self) -> Result<(), InstallError> {
            Ok(())
        }

        fn daemon_reload(&mut self) -> Result<(), InstallError> {
            Ok(())
        }

        fn enable(&mut self) -> Result<(), InstallError> {
            Ok(())
        }

        fn start(&mut self) -> Result<(), InstallError> {
            let unit = fs::read_to_string(self.paths.unit()).map_err(|_| InstallError::Io)?;
            if unit.contains("LoadCredential=") {
                return Err(InstallError::ExistingResidue);
            }
            if self.paths.replacement_registration_drop_in().exists()
                && !self
                    .paths
                    .replacement_registration_attempt_source()
                    .exists()
            {
                return Err(InstallError::ExistingResidue);
            }
            if self.paths.replacement_registration_drop_in().exists() {
                let credential = self
                    .paths
                    .root
                    .join("run/credentials/enoki-probe.service/registration-attempt");
                fs::create_dir_all(credential.parent().unwrap()).map_err(|_| InstallError::Io)?;
                fs::write(credential, b"invocation-owned").map_err(|_| InstallError::Io)?;
            }
            Ok(())
        }

        fn restart_canonical(&mut self) -> Result<(), InstallError> {
            if std::env::var("ENOKI_TEST_REPLACEMENT_LIFECYCLE_ACTION").as_deref()
                == Ok("reject-canonical-restart")
            {
                return Err(InstallError::Systemd);
            }
            let credential = self
                .paths
                .root
                .join("run/credentials/enoki-probe.service/registration-attempt");
            let selected = std::env::var_os("ENOKI_TEST_SECURE_FILE_PATH").as_deref()
                == Some(credential.as_os_str());
            let point = std::env::var("ENOKI_TEST_SECURE_FILE_CRASH_POINT").ok();
            if selected && point.as_deref() == Some("fail-restart") {
                return Err(InstallError::Systemd);
            }
            if selected && point.as_deref() == Some("before-restart") {
                std::process::abort();
            }
            match fs::remove_file(&credential) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(InstallError::Systemd),
            }
            if selected && point.as_deref() == Some("after-restart") {
                std::process::abort();
            }
            self.start()
        }

        fn wait_local_activated(&mut self) -> Result<(), InstallError> {
            if self.timeout {
                return Err(InstallError::Systemd);
            }
            let identity = self.paths.identity();
            let pending = fs::read_to_string(&identity).map_err(|_| InstallError::Io)?;
            if pending.contains("enrollment_token = \"enk_enroll_secret\"") {
                let capsule: serde_json::Value = serde_json::from_slice(
                    &fs::read(self.paths.replacement_registration_attempt_source())
                        .map_err(|_| InstallError::Io)?,
                )
                .map_err(|_| InstallError::Io)?;
                let candidate_private_key = capsule["candidatePrivateKeyPem"]
                    .as_str()
                    .ok_or(InstallError::Io)?;
                let signed_attempt_sha256 = capsule["signedAttemptSha256"]
                    .as_str()
                    .ok_or(InstallError::Io)?;
                let registered = pending.replace(
                    "enrollment_token = \"enk_enroll_secret\"\n",
                    &format!(
                        "enrollment_id = \"enrollment_01\"\nprobe_id = \"probe-registered\"\nhost_id = \"host-registered\"\nprobe_private_key_pem = {candidate_private_key:?}\nregistration_signed_attempt_sha256 = {signed_attempt_sha256:?}\n",
                    ),
                );
                fs::write(identity, registered).map_err(|_| InstallError::Io)?;
            }
            Ok(())
        }

        fn stop(&mut self) -> Result<(), InstallError> {
            Ok(())
        }

        fn disable(&mut self) -> Result<(), InstallError> {
            Ok(())
        }
    }

    #[test]
    fn committed_replacement_rejects_a_stale_journal_from_another_enrollment() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            fail_reload: true,
            ..Systemd::default()
        };
        let candidate_a = ReplacementResumeBinding::for_test("candidate-a");
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        assert_eq!(
            activate_complete_replacement_current_probe(
                VerifiedCompleteFreshComponents {
                    probe: &mut probe,
                    observation_runtime: &mut runtime,
                    cpu_provider: &mut provider,
                    disk_health_provider: &mut disk_health,
                    lifecycle_companion: &mut lifecycle,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_candidate_a").unwrap(),
                &bundle().with_test_observation_receipts(5),
                &trust(),
                &paths,
                &mut accounts,
                &mut systemd,
                &candidate_a,
            ),
            Err(InstallError::Systemd)
        );

        systemd.fail_reload = false;
        let effects_before = (accounts.calls.len(), accounts.ipc_calls.len(), systemd.calls.len());
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        assert_eq!(
            activate_complete_fresh_current_probe(
                VerifiedCompleteFreshComponents {
                    probe: &mut probe,
                    observation_runtime: &mut runtime,
                    cpu_provider: &mut provider,
                    disk_health_provider: &mut disk_health,
                    lifecycle_companion: &mut lifecycle,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_fresh").unwrap(),
                &bundle().with_test_observation_receipts(5),
                &trust(),
                &paths,
                &mut accounts,
                &mut systemd,
            ),
            Err(InstallError::ExistingResidue)
        );
        assert_eq!(
            (accounts.calls.len(), accounts.ipc_calls.len(), systemd.calls.len()),
            effects_before,
            "Fresh 入口不得 rollback committed Replacement custody"
        );
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());

        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        let candidate_b = ReplacementResumeBinding::for_test("candidate-b");
        assert_eq!(
            activate_complete_replacement_current_probe(
                VerifiedCompleteFreshComponents {
                    probe: &mut probe,
                    observation_runtime: &mut runtime,
                    cpu_provider: &mut provider,
                    disk_health_provider: &mut disk_health,
                    lifecycle_companion: &mut lifecycle,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_candidate_b").unwrap(),
                &bundle().with_test_observation_receipts(5),
                &trust(),
                &paths,
                &mut accounts,
                &mut systemd,
                &candidate_b,
            ),
            Err(InstallError::ExistingResidue)
        );
        assert_eq!(
            (accounts.calls.len(), accounts.ipc_calls.len(), systemd.calls.len()),
            effects_before,
            "错误绑定必须在任何新 Host 效果前关闭"
        );
    }

    #[test]
    fn fresh_interface_preserves_layout_committed_replacement_custody() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib/enoki-probe-bootstrap",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        fs::set_permissions(
            paths.bootstrap_state(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let journal = TransactionJournal::begin_with_binding(
            &paths.bootstrap_state(),
            Some("committed-candidate"),
        )
        .unwrap();
        fs::write(
            paths.bootstrap_state().join("current-layout"),
            "schema_version=1\nversion=1.2.3\n",
        )
        .unwrap();
        drop(journal);

        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        assert_eq!(
            activate_complete_fresh_current_probe(
                VerifiedCompleteFreshComponents {
                    probe: &mut probe,
                    observation_runtime: &mut runtime,
                    cpu_provider: &mut provider,
                    disk_health_provider: &mut disk_health,
                    lifecycle_companion: &mut lifecycle,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_fresh").unwrap(),
                &bundle().with_test_observation_receipts(5),
                &trust(),
                &paths,
                &mut accounts,
                &mut systemd,
            ),
            Err(InstallError::ExistingResidue)
        );
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());
        assert!(paths.bootstrap_state().join("current-layout").exists());
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn successful_replacement_keeps_exact_custody_until_candidate_receipt_is_acknowledged() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let mut paths = FixedInstallPaths::under(temporary.path());
        let replacement_bundle = bundle().with_test_complete_receipts(5);
        let commit = replacement_commit(&replacement_bundle);
        let binding = commit.resume_binding();
        let probe_identity = ServiceIdentity {
            uid: 12_345,
            gid: 12_346,
        };
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            registration_identity: Some(paths.identity()),
            ..Systemd::default()
        };
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        activate_complete_replacement_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk_health,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &replacement_bundle,
            &trust(),
            &paths,
            &mut accounts,
            &mut systemd,
            &binding,
        )
        .unwrap();
        assert!(paths.bootstrap_state().join("current-layout").exists());
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());
        let observed_identity = fs::symlink_metadata(paths.identity()).unwrap();
        let test_root_owner = ServiceIdentity {
            uid: observed_identity.uid(),
            gid: observed_identity.gid(),
        };
        paths.map_identity_owner_for_test(test_root_owner, test_root_owner);
        assert_eq!(
            finalize_complete_replacement_current_probe(
                &paths,
                &binding,
                &replacement_bundle,
                &commit,
            ),
            Err(InstallError::ExistingResidue),
            "root-owned pending identity 不能冒充 DynamicUser 注册结果"
        );
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());
        paths.map_identity_owner_for_test(
            probe_identity,
            test_root_owner,
        );
        assert_ne!(probe_identity.uid, paths.expected_root_uid());

        let journal_path = paths.bootstrap_state().join("activation-journal.json");
        let mut production_shape_journal: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
        for receipt in production_shape_journal["paths"].as_array_mut().unwrap() {
            if receipt["path"] == serde_json::json!(paths.state())
                || receipt["path"] == serde_json::json!(paths.identity_dir())
            {
                receipt["uid"] = serde_json::json!(42_424_u32);
                receipt["gid"] = serde_json::json!(42_425_u32);
            }
        }
        let original_journal = serde_json::to_vec(&production_shape_journal).unwrap();
        fs::write(&journal_path, &original_journal).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        for case in ["empty", "missing", "duplicate", "unknown", "wrong-receipt"] {
            let mut changed: serde_json::Value =
                serde_json::from_slice(&original_journal).unwrap();
            let entries = changed["paths"].as_array_mut().unwrap();
            match case {
                "empty" => entries.clear(),
                "missing" => {
                    entries.pop();
                }
                "duplicate" => entries.push(entries[0].clone()),
                "unknown" => {
                    entries[0]["path"] = serde_json::json!(temporary.path().join("unknown"));
                }
                "wrong-receipt" => {
                    entries[0]["size"] = serde_json::json!(u64::MAX);
                }
                _ => unreachable!(),
            }
            fs::write(&journal_path, serde_json::to_vec(&changed).unwrap()).unwrap();
            fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                finalize_complete_replacement_current_probe(
                    &paths,
                    &binding,
                    &replacement_bundle,
                    &commit,
                ),
                Err(InstallError::ExistingResidue),
                "activation journal {case} 必须 fail closed"
            );
            assert!(journal_path.exists());
        }
        fs::write(&journal_path, original_journal).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();

        let effects_before = (accounts.calls.len(), accounts.ipc_calls.len(), systemd.calls.len());
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        assert_eq!(
            activate_complete_fresh_current_probe(
                VerifiedCompleteFreshComponents {
                    probe: &mut probe,
                    observation_runtime: &mut runtime,
                    cpu_provider: &mut provider,
                    disk_health_provider: &mut disk_health,
                    lifecycle_companion: &mut lifecycle,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_other").unwrap(),
                &bundle().with_test_observation_receipts(5),
                &trust(),
                &paths,
                &mut accounts,
                &mut systemd,
            ),
            Err(InstallError::ExistingResidue)
        );
        assert_eq!(
            (accounts.calls.len(), accounts.ipc_calls.len(), systemd.calls.len()),
            effects_before
        );

        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        activate_complete_replacement_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk_health,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &replacement_bundle,
            &trust(),
            &paths,
            &mut accounts,
            &mut systemd,
            &binding,
        )
        .unwrap();
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());
        assert_eq!(
            finalize_complete_replacement_current_probe(
                &paths,
                &ReplacementResumeBinding::for_test("wrong-candidate"),
                &replacement_bundle,
                &commit,
            ),
            Err(InstallError::ExistingResidue)
        );
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());
        let identity_backup = paths.identity().with_extension("identity-backup");
        fs::rename(paths.identity(), &identity_backup).unwrap();
        std::os::unix::fs::symlink("/dev/zero", paths.identity()).unwrap();
        assert_eq!(
            finalize_complete_replacement_current_probe(
                &paths,
                &binding,
                &replacement_bundle,
                &commit,
            ),
            Err(InstallError::ExistingResidue),
            "identity 必须在读取前以 O_NOFOLLOW 拒绝 /dev/zero symlink"
        );
        assert!(journal_path.exists());
        fs::remove_file(paths.identity()).unwrap();
        fs::rename(identity_backup, paths.identity()).unwrap();
        let registered_identity = fs::read_to_string(paths.identity()).unwrap();
        fs::write(
            paths.identity(),
            registered_identity.replace(
                &format!(
                    "probe_private_key_pem = {:?}",
                    valid_probe_private_key_pem()
                ),
                "probe_private_key_pem = \"not-a-private-key\"",
            ),
        )
        .unwrap();
        fs::set_permissions(paths.identity(), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            finalize_complete_replacement_current_probe(
                &paths,
                &binding,
                &replacement_bundle,
                &commit,
            ),
            Err(InstallError::ExistingResidue),
            "非空垃圾字符串不是生产可用的 PKCS#8/RSA Probe Identity"
        );
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());
        fs::write(paths.identity(), registered_identity).unwrap();
        fs::set_permissions(paths.identity(), fs::Permissions::from_mode(0o600)).unwrap();
        let registered_identity = fs::read_to_string(paths.identity()).unwrap();
        fs::write(
            paths.identity(),
            registered_identity.replace("enrollment_01", "enrollment_wrong"),
        )
        .unwrap();
        fs::set_permissions(paths.identity(), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            finalize_complete_replacement_current_probe(
                &paths,
                &binding,
                &replacement_bundle,
                &commit,
            ),
            Err(InstallError::ExistingResidue),
            "registration Enrollment receipt 必须绑定当前 Replacement commit"
        );
        assert!(journal_path.exists());
        fs::write(paths.identity(), registered_identity).unwrap();
        fs::set_permissions(paths.identity(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(paths.binary(), b"pr0be").unwrap();
        fs::set_permissions(paths.binary(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            finalize_complete_replacement_current_probe(
                &paths,
                &binding,
                &replacement_bundle,
                &commit,
            ),
            Err(InstallError::ExistingResidue),
            "同 owner/mode/length 的 payload 篡改必须保留 Replacement custody"
        );
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());
        fs::write(paths.binary(), b"probe").unwrap();
        fs::set_permissions(paths.binary(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(paths.metadata(), fs::Permissions::from_mode(0o4600)).unwrap();
        assert_eq!(
            finalize_complete_replacement_current_probe(
                &paths,
                &binding,
                &replacement_bundle,
                &commit,
            ),
            Err(InstallError::ExistingResidue),
            "exact mode 必须拒绝额外 setuid/setgid/sticky bits"
        );
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());
        fs::set_permissions(paths.metadata(), fs::Permissions::from_mode(0o600)).unwrap();
        finalize_complete_replacement_current_probe(
            &paths,
            &binding,
            &replacement_bundle,
            &commit,
        )
        .unwrap();
        assert!(!paths.bootstrap_state().join("activation-journal.json").exists());
        assert!(paths.etc_enoki().is_dir());
        for guarded in [paths.identity(), paths.metadata()] {
            let backup = guarded.with_extension("safe-open-backup");
            fs::rename(&guarded, &backup).unwrap();
            std::os::unix::fs::symlink("/dev/zero", &guarded).unwrap();
            assert_eq!(
                finalize_complete_replacement_current_probe(
                    &paths,
                    &binding,
                    &replacement_bundle,
                    &commit,
                ),
                Err(InstallError::ExistingResidue),
                "journal absent 重算必须在读取前拒绝 /dev/zero symlink"
            );
            fs::remove_file(&guarded).unwrap();
            fs::rename(backup, guarded).unwrap();
        }
        fs::write(paths.binary(), b"pr0be").unwrap();
        fs::set_permissions(paths.binary(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            finalize_complete_replacement_current_probe(
                &paths,
                &binding,
                &replacement_bundle,
                &commit,
            ),
            Err(InstallError::ExistingResidue),
            "journal 已清理的幂等 finalize 仍必须重算真实 payload digest"
        );
        fs::write(paths.binary(), b"probe").unwrap();
        fs::set_permissions(paths.binary(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_file(paths.binary()).unwrap();
        assert_eq!(
            finalize_complete_replacement_current_probe(
                &paths,
                &binding,
                &replacement_bundle,
                &commit,
            ),
            Err(InstallError::ExistingResidue),
            "Hub/commit fact 不得替代本机完整安装收据"
        );
        fs::remove_file(paths.bootstrap_state().join("current-layout")).unwrap();
        assert_eq!(
            finalize_complete_replacement_current_probe(
                &paths,
                &binding,
                &replacement_bundle,
                &commit,
            ),
            Err(InstallError::ExistingResidue),
            "Hub/commit fact 不得替代本机 committed layout receipt"
        );
    }

    #[test]
    fn committed_replacement_resumes_after_identity_and_partial_layout_receipts() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let mut files = FailFirstCandidateDirectoryFiles {
            inner: SystemInstallFiles,
            failed: false,
        };
        let resume_binding = ReplacementResumeBinding::for_test("candidate-a");

        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        assert_eq!(
            activate_verified_fresh_install(
                &mut probe,
                Some((
                    &mut runtime,
                    &mut provider,
                    &mut disk_health,
                    &mut lifecycle,
                )),
                Some((&mut acquirer, &mut activator)),
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle().with_test_observation_receipts(5),
                &trust(),
                &paths,
                &mut InstallPorts {
                    accounts: &mut accounts,
                    systemd: &mut systemd,
                    files: &mut files,
                },
                InstallFailureSemantics::CommittedReplacement(&resume_binding),
            ),
            Err(InstallError::Io)
        );
        assert!(accounts.calls.contains(&"create"));
        assert!(!accounts.calls.contains(&"remove"));
        assert!(paths.etc_enoki().exists());
        let interrupted: serde_json::Value = serde_json::from_slice(
            &fs::read(paths.bootstrap_state().join("activation-journal.json")).unwrap(),
        )
        .unwrap();
        assert!(
            interrupted["paths"]
                .as_array()
                .unwrap()
                .iter()
                .all(|receipt| receipt["path"] != serde_json::json!(paths.etc_enoki()))
        );
        assert_eq!(
            interrupted["pre_existing_paths"][0]["path"],
            serde_json::json!(paths.etc_enoki())
        );

        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        activate_verified_fresh_install(
            &mut probe,
            Some((
                &mut runtime,
                &mut provider,
                &mut disk_health,
                &mut lifecycle,
            )),
            Some((&mut acquirer, &mut activator)),
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle().with_test_observation_receipts(5),
            &trust(),
            &paths,
            &mut InstallPorts {
                accounts: &mut accounts,
                systemd: &mut systemd,
                files: &mut files,
            },
            InstallFailureSemantics::CommittedReplacement(&resume_binding),
        )
        .expect("已提交 Replacement 从首个缺失 candidate effect 继续");

        assert_eq!(accounts.calls.iter().filter(|call| **call == "create").count(), 1);
        assert!(!accounts.calls.contains(&"remove"));
        assert!(!accounts.ipc_calls.contains(&"remove"));
        assert!(paths.bootstrap_state().join("current-layout").exists());
    }

    #[test]
    fn committed_replacement_resumes_account_effect_crash_windows_without_recreating_them() {
        for crash_after in ["identity", "ipc"] {
            let temporary = tempdir().unwrap();
            for parent in [
                "usr/local/bin",
                "var/lib",
                "etc/systemd/system",
                "etc/sudoers.d",
            ] {
                fs::create_dir_all(temporary.path().join(parent)).unwrap();
            }
            let paths = FixedInstallPaths::under(temporary.path());
            let mut accounts = Accounts {
                crash_after: Some(crash_after),
                ..Accounts::default()
            };
            let mut systemd = Systemd::default();
            let resume_binding = ReplacementResumeBinding::for_test("candidate-account-window");
            let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
                    std::array::from_fn(|_| component());
                let _ = activate_complete_replacement_current_probe(
                    VerifiedCompleteFreshComponents {
                        probe: &mut probe,
                        observation_runtime: &mut runtime,
                        cpu_provider: &mut provider,
                        disk_health_provider: &mut disk_health,
                        lifecycle_companion: &mut lifecycle,
                        bootstrap_acquirer: &mut acquirer,
                        bootstrap_activator: &mut activator,
                    },
                    &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                    &bundle().with_test_observation_receipts(5),
                    &trust(),
                    &paths,
                    &mut accounts,
                    &mut systemd,
                    &resume_binding,
                );
            }));
            assert!(crashed.is_err());
            assert!(paths.bootstrap_state().join("activation-journal.json").exists());

            accounts.crash_after = None;
            let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
                std::array::from_fn(|_| component());
            activate_complete_replacement_current_probe(
                VerifiedCompleteFreshComponents {
                    probe: &mut probe,
                    observation_runtime: &mut runtime,
                    cpu_provider: &mut provider,
                    disk_health_provider: &mut disk_health,
                    lifecycle_companion: &mut lifecycle,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle().with_test_observation_receipts(5),
                &trust(),
                &paths,
                &mut accounts,
                &mut systemd,
                &resume_binding,
            )
            .unwrap();

            assert_eq!(
                accounts.calls.iter().filter(|call| **call == "create").count(),
                1,
                "identity effect 后崩溃必须由 transaction marker 恢复"
            );
            assert_eq!(
                accounts
                    .ipc_calls
                    .iter()
                    .filter(|call| **call == "create")
                    .count(),
                1,
                "IPC group effect 后崩溃必须由 transaction marker 恢复"
            );
        }
    }

    #[test]
    fn committed_replacement_preserves_preparation_receipts_on_account_result_errors() {
        for failed_effect in ["identity", "ipc", "stage"] {
            let temporary = tempdir().unwrap();
            for parent in [
                "usr/local/bin",
                "var/lib",
                "etc/systemd/system",
                "etc/sudoers.d",
            ] {
                fs::create_dir_all(temporary.path().join(parent)).unwrap();
            }
            let paths = FixedInstallPaths::under(temporary.path());
            let binding = ReplacementResumeBinding::for_test("candidate-account-result");
            let mut accounts = Accounts {
                fail_identity: failed_effect == "identity",
                fail_ipc: failed_effect == "ipc",
                poison_staging: (failed_effect == "stage")
                    .then(|| paths.bootstrap_state()),
                ..Accounts::default()
            };
            let mut systemd = Systemd::default();
            let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
                std::array::from_fn(|_| component());
            assert_eq!(
                activate_complete_replacement_current_probe(
                    VerifiedCompleteFreshComponents {
                        probe: &mut probe,
                        observation_runtime: &mut runtime,
                        cpu_provider: &mut provider,
                        disk_health_provider: &mut disk_health,
                        lifecycle_companion: &mut lifecycle,
                        bootstrap_acquirer: &mut acquirer,
                        bootstrap_activator: &mut activator,
                    },
                    &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                    &bundle().with_test_observation_receipts(5),
                    &trust(),
                    &paths,
                    &mut accounts,
                    &mut systemd,
                    &binding,
                ),
                Err(if failed_effect == "stage" {
                    InstallError::Io
                } else {
                    InstallError::Account
                })
            );
            assert!(paths.bootstrap_state().join("activation-journal.json").exists());
            assert!(paths.bootstrap_acquirer().exists());
            assert!(paths.bootstrap_activator().exists());
            assert!(!accounts.calls.contains(&"remove"));
            assert!(!accounts.ipc_calls.contains(&"remove"));

            accounts.fail_identity = false;
            accounts.fail_ipc = false;
            accounts.poison_staging = None;
            let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
                std::array::from_fn(|_| component());
            activate_complete_replacement_current_probe(
                VerifiedCompleteFreshComponents {
                    probe: &mut probe,
                    observation_runtime: &mut runtime,
                    cpu_provider: &mut provider,
                    disk_health_provider: &mut disk_health,
                    lifecycle_companion: &mut lifecycle,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle().with_test_observation_receipts(5),
                &trust(),
                &paths,
                &mut accounts,
                &mut systemd,
                &binding,
            )
            .unwrap();
            assert!(!accounts.calls.contains(&"remove"));
            assert!(!accounts.ipc_calls.contains(&"remove"));
        }
    }

    #[test]
    fn committed_replacement_preserves_journal_when_bootstrap_role_publication_returns_error() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let binding = ReplacementResumeBinding::for_test("candidate-bootstrap-role");
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let mut files = FailFirstBootstrapRoleFiles {
            inner: SystemInstallFiles,
            failed: false,
        };
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        assert_eq!(
            activate_verified_fresh_install(
                &mut probe,
                Some((
                    &mut runtime,
                    &mut provider,
                    &mut disk_health,
                    &mut lifecycle,
                )),
                Some((&mut acquirer, &mut activator)),
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle().with_test_observation_receipts(5),
                &trust(),
                &paths,
                &mut InstallPorts {
                    accounts: &mut accounts,
                    systemd: &mut systemd,
                    files: &mut files,
                },
                InstallFailureSemantics::CommittedReplacement(&binding),
            ),
            Err(InstallError::Io)
        );
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());
        assert!(!accounts.calls.contains(&"remove"));
        assert!(!accounts.ipc_calls.contains(&"remove"));

        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        activate_verified_fresh_install(
            &mut probe,
            Some((
                &mut runtime,
                &mut provider,
                &mut disk_health,
                &mut lifecycle,
            )),
            Some((&mut acquirer, &mut activator)),
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle().with_test_observation_receipts(5),
            &trust(),
            &paths,
            &mut InstallPorts {
                accounts: &mut accounts,
                systemd: &mut systemd,
                files: &mut files,
            },
            InstallFailureSemantics::CommittedReplacement(&binding),
        )
        .unwrap();
        assert!(paths.bootstrap_state().join("current-layout").exists());
    }

    #[test]
    fn committed_replacement_preserves_identity_effect_when_its_receipt_write_fails() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let backup = temporary.path().join("activation-state-backup");
        let binding = ReplacementResumeBinding::for_test("candidate-identity-receipt");
        let mut accounts = Accounts {
            break_state_on_identity: Some((paths.bootstrap_state(), backup.clone())),
            ..Accounts::default()
        };
        let mut systemd = Systemd::default();
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        assert_eq!(
            activate_complete_replacement_current_probe(
                VerifiedCompleteFreshComponents {
                    probe: &mut probe,
                    observation_runtime: &mut runtime,
                    cpu_provider: &mut provider,
                    disk_health_provider: &mut disk_health,
                    lifecycle_companion: &mut lifecycle,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle().with_test_observation_receipts(5),
                &trust(),
                &paths,
                &mut accounts,
                &mut systemd,
                &binding,
            ),
            Err(InstallError::Io)
        );
        assert!(accounts.identity_present);
        assert!(!accounts.calls.contains(&"remove"));
        fs::remove_file(paths.bootstrap_state()).unwrap();
        fs::rename(&backup, paths.bootstrap_state()).unwrap();
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());

        accounts.break_state_on_identity = None;
        let [mut probe, mut runtime, mut provider, mut disk_health, mut lifecycle, mut acquirer, mut activator] =
            std::array::from_fn(|_| component());
        activate_complete_replacement_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk_health,
                lifecycle_companion: &mut lifecycle,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle().with_test_observation_receipts(5),
            &trust(),
            &paths,
            &mut accounts,
            &mut systemd,
            &binding,
        )
        .unwrap();
        assert_eq!(
            accounts.calls.iter().filter(|call| **call == "create").count(),
            1
        );
        assert!(!accounts.calls.contains(&"remove"));
    }

    #[test]
    fn complete_fresh_install_does_not_publish_the_retired_operation_entrypoint() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let mut probe = component();
        let mut runtime = component();
        let mut provider = component();
        let mut disk_health_provider = component();
        let mut lifecycle_companion = component();
        let mut acquirer = component();
        let mut activator = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        activate_complete_fresh_current_probe(
            VerifiedCompleteFreshComponents {
                probe: &mut probe,
                observation_runtime: &mut runtime,
                cpu_provider: &mut provider,
                disk_health_provider: &mut disk_health_provider,
                lifecycle_companion: &mut lifecycle_companion,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle().with_test_observation_receipts(5),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap();

        let config = fs::read_to_string(
            temporary
                .path()
                .join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        )
        .unwrap();
        let metadata =
            fs::read_to_string(temporary.path().join("etc/enoki/probe-install.toml")).unwrap();
        assert!(metadata.contains("probe_ipc_group = \"enoki-probe-ipc\""));
        assert!(metadata.contains("probe_ipc_group_ownership = \"!enoki-bootstrap-"));
        assert!(!config.contains("upgrader_launch"));
        assert!(!config.contains("operation_sudoers_path"));
        assert!(
            !temporary
                .path()
                .join("etc/sudoers.d/enoki-probe-operations")
                .exists()
        );

        let installed_probe_unit = fs::read(
            temporary
                .path()
                .join("etc/systemd/system/enoki-probe.service"),
        )
        .unwrap();
        assert_eq!(installed_probe_unit, fixed_execution_role_units()[0].1);
        for (name, expected) in [
            "enoki-observation-runtime.service",
            "enoki-observation-runtime.socket",
            "enoki-cpu-resource-provider@.service",
            "enoki-cpu-resource-provider.socket",
            "enoki-disk-health-resource-provider@.service",
            "enoki-disk-health-resource-provider.socket",
            "enoki-probe-lifecycle-companion@.service",
            "enoki-probe-lifecycle-companion.socket",
            "enoki-observation-runtime-failure.service",
        ]
        .into_iter()
        .zip(fixed_observation_unit_contents())
        {
            assert_eq!(
                fs::read(temporary.path().join("etc/systemd/system").join(name)).unwrap(),
                expected,
                "fresh install 必须发布 canonical {name}",
            );
        }
    }

    #[test]
    fn second_bootstrap_role_failure_cleans_the_first_receipt_and_allows_retry() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let mut acquirer = component();
        let mut activator = component();
        let mut probe = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let mut files = FailSecondRoleFiles {
            inner: SystemInstallFiles,
            installs: 0,
            replace_first: None,
        };

        assert_eq!(
            activate_current_probe_with_files(
                &mut probe,
                Some((&mut acquirer, &mut activator)),
                &Enrollment::new("https://hub.example", "enk_enroll_failure").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut InstallPorts {
                    accounts: &mut accounts,
                    systemd: &mut systemd,
                    files: &mut files,
                },
            ),
            Err(InstallError::Io)
        );
        assert!(!paths.bootstrap_acquirer().exists());
        assert!(!paths.bootstrap_activator().exists());
        assert!(
            !paths
                .bootstrap_state()
                .join("activation-journal.json")
                .exists()
        );

        activate_fresh_current_probe(
            VerifiedFreshComponents {
                probe: &mut probe,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
            &bundle(),
            &trust(),
            &paths,
            &mut Accounts::default(),
            &mut Systemd::default(),
        )
        .expect("ordinary early abort leaves a restart-safe fresh retry");
    }

    #[test]
    fn early_abort_preserves_a_replaced_role_and_restart_reports_closed_residue() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let mut acquirer = component();
        let mut activator = component();
        let mut probe = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let mut files = FailSecondRoleFiles {
            inner: SystemInstallFiles,
            installs: 0,
            replace_first: Some(paths.bootstrap_acquirer()),
        };

        let error = activate_current_probe_with_files(
            &mut probe,
            Some((&mut acquirer, &mut activator)),
            &Enrollment::new("https://hub.example", "enk_enroll_replaced").unwrap(),
            &bundle(),
            &trust(),
            &paths,
            &mut InstallPorts {
                accounts: &mut accounts,
                systemd: &mut systemd,
                files: &mut files,
            },
        )
        .unwrap_err();

        assert_eq!(
            error,
            InstallError::Rollback {
                cause: InstallErrorKind::Io,
                failures: vec![RollbackFailure::new(
                    RollbackStep::RemoveBootstrapAcquirer,
                    InstallErrorKind::ExistingResidue,
                )],
            }
        );
        assert_eq!(
            fs::read(paths.bootstrap_acquirer()).unwrap(),
            b"replacement"
        );
        assert_eq!(accounts.calls, ["absent", "remove"]);
        assert!(
            fs::read_dir(paths.bootstrap_state())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("activation-stage-")),
            "a path ownership failure must not skip later staging compensation"
        );
        assert!(
            paths
                .bootstrap_state()
                .join("activation-journal.json")
                .exists()
        );

        assert!(matches!(
            activate_fresh_current_probe(
                VerifiedFreshComponents {
                    probe: &mut probe,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_restart").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut Accounts::default(),
                &mut Systemd::default(),
            ),
            Err(InstallError::Rollback { failures, .. })
                if failures.contains(&RollbackFailure::new(
                    RollbackStep::RemoveBootstrapAcquirer,
                    InstallErrorKind::ExistingResidue,
                ))
        ));
        assert_eq!(
            fs::read(paths.bootstrap_acquirer()).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn account_creation_failure_cleans_both_roles_and_allows_retry() {
        struct FailCreation {
            calls: Vec<&'static str>,
        }
        impl AccountPort for FailCreation {
            fn require_absent(&mut self) -> Result<(), InstallError> {
                self.calls.push("absent");
                Ok(())
            }
            fn create_transaction_identity(
                &mut self,
                _transaction_id: &str,
            ) -> Result<ServiceIdentity, InstallError> {
                self.calls.push("create");
                Err(InstallError::Account)
            }
            fn remove_transaction_identity(
                &mut self,
                _transaction_id: &str,
                identity: Option<ServiceIdentity>,
            ) -> Result<(), InstallError> {
                assert_eq!(identity, None);
                self.calls.push("remove");
                Ok(())
            }
        }

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let mut acquirer = component();
        let mut activator = component();
        let mut probe = component();
        let mut accounts = FailCreation { calls: Vec::new() };

        assert_eq!(
            activate_fresh_current_probe(
                VerifiedFreshComponents {
                    probe: &mut probe,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_account").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut accounts,
                &mut Systemd::default(),
            ),
            Err(InstallError::Account)
        );
        assert_eq!(accounts.calls, ["absent", "create", "remove"]);
        assert!(!paths.bootstrap_acquirer().exists());
        assert!(!paths.bootstrap_activator().exists());
        assert!(
            !paths
                .bootstrap_state()
                .join("activation-journal.json")
                .exists()
        );

        activate_fresh_current_probe(
            VerifiedFreshComponents {
                probe: &mut probe,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
            &bundle(),
            &trust(),
            &paths,
            &mut Accounts::default(),
            &mut Systemd::default(),
        )
        .expect("account abort leaves a restart-safe fresh retry");
    }

    #[test]
    fn record_identity_and_layout_staging_failures_clean_every_prepared_receipt() {
        #[derive(Clone, Copy, Debug)]
        enum PreparedFailure {
            RecordIdentity,
            StageLayout,
        }
        struct FailPreparedStep {
            failure: PreparedFailure,
            state: PathBuf,
        }
        impl AccountPort for FailPreparedStep {
            fn require_absent(&mut self) -> Result<(), InstallError> {
                Ok(())
            }
            fn create_transaction_identity(
                &mut self,
                transaction_id: &str,
            ) -> Result<ServiceIdentity, InstallError> {
                match self.failure {
                    PreparedFailure::RecordIdentity => {
                        fs::remove_file(self.state.join("activation-journal.json")).unwrap();
                        fs::create_dir(self.state.join("activation-journal.json")).unwrap();
                    }
                    PreparedFailure::StageLayout => {
                        fs::write(
                            self.state
                                .join(format!("activation-stage-{transaction_id}"))
                                .join("enoki-probe"),
                            b"collision",
                        )
                        .unwrap();
                    }
                }
                Ok(ServiceIdentity {
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                })
            }
            fn remove_transaction_identity(
                &mut self,
                _transaction_id: &str,
                _identity: Option<ServiceIdentity>,
            ) -> Result<(), InstallError> {
                if matches!(self.failure, PreparedFailure::RecordIdentity) {
                    fs::remove_dir(self.state.join("activation-journal.json")).unwrap();
                }
                Ok(())
            }
        }

        for failure in [
            PreparedFailure::RecordIdentity,
            PreparedFailure::StageLayout,
        ] {
            let temporary = tempdir().unwrap();
            for parent in [
                "usr/local/bin",
                "var/lib",
                "etc/systemd/system",
                "etc/sudoers.d",
            ] {
                fs::create_dir_all(temporary.path().join(parent)).unwrap();
            }
            let paths = FixedInstallPaths::under(temporary.path());
            let mut acquirer = component();
            let mut activator = component();
            let mut probe = component();
            let mut accounts = FailPreparedStep {
                failure,
                state: paths.bootstrap_state(),
            };

            assert_eq!(
                activate_fresh_current_probe(
                    VerifiedFreshComponents {
                        probe: &mut probe,
                        bootstrap_acquirer: &mut acquirer,
                        bootstrap_activator: &mut activator,
                    },
                    &Enrollment::new("https://hub.example", "enk_enroll_prepared").unwrap(),
                    &bundle(),
                    &trust(),
                    &paths,
                    &mut accounts,
                    &mut Systemd::default(),
                ),
                Err(InstallError::Io),
                "{failure:?}"
            );
            assert!(!paths.bootstrap_acquirer().exists(), "{failure:?}");
            assert!(!paths.bootstrap_activator().exists(), "{failure:?}");
            assert!(
                !paths
                    .bootstrap_state()
                    .join("activation-journal.json")
                    .exists(),
                "{failure:?}"
            );

            activate_fresh_current_probe(
                VerifiedFreshComponents {
                    probe: &mut probe,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut Accounts::default(),
                &mut Systemd::default(),
            )
            .unwrap_or_else(|error| panic!("{failure:?} retry failed: {error:?}"));
        }
    }

    #[test]
    fn fresh_role_publication_rolls_back_with_the_probe_transaction_and_retries() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        let mut acquirer = component();
        let mut activator = component();
        let mut probe = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            fail_start: true,
            ..Systemd::default()
        };

        assert_eq!(
            activate_fresh_current_probe(
                VerifiedFreshComponents {
                    probe: &mut probe,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut accounts,
                &mut systemd,
            ),
            Err(InstallError::Systemd)
        );
        assert!(!paths.bootstrap_acquirer().exists());
        assert!(!paths.bootstrap_activator().exists());
        assert!(
            !paths
                .bootstrap_state()
                .join("activation-journal.json")
                .exists()
        );

        systemd.fail_start = false;
        activate_fresh_current_probe(
            VerifiedFreshComponents {
                probe: &mut probe,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
            &bundle(),
            &trust(),
            &paths,
            &mut accounts,
            &mut systemd,
        )
        .expect("the complete fresh transaction is retryable");
    }

    #[test]
    fn fresh_role_publication_preserves_preexisting_paths() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let paths = FixedInstallPaths::under(temporary.path());
        fs::write(paths.bootstrap_acquirer(), b"preexisting").unwrap();
        let mut acquirer = component();
        let mut activator = component();
        let mut probe = component();

        assert_eq!(
            activate_fresh_current_probe(
                VerifiedFreshComponents {
                    probe: &mut probe,
                    bootstrap_acquirer: &mut acquirer,
                    bootstrap_activator: &mut activator,
                },
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut Accounts::default(),
                &mut Systemd::default(),
            ),
            Err(InstallError::ExistingResidue)
        );
        assert_eq!(
            fs::read(paths.bootstrap_acquirer()).unwrap(),
            b"preexisting"
        );
        assert!(!paths.bootstrap_activator().exists());
    }

    #[test]
    fn fresh_activation_recovers_an_interrupted_owned_layout_before_retrying() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib/enoki-probe-bootstrap",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        fs::set_permissions(
            temporary.path().join("var/lib/enoki-probe-bootstrap"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        write_bootstrap_roles(temporary.path());
        let paths = FixedInstallPaths::under(temporary.path());
        fs::write(paths.binary(), "interrupted-owned-binary").unwrap();
        let mut journal = TransactionJournal::begin(&paths.bootstrap_state()).unwrap();
        journal
            .record_identity(unsafe { libc::geteuid() }, unsafe { libc::getegid() })
            .unwrap();
        journal
            .record_path(
                OwnedPath::capture(&paths.binary(), false, RollbackStep::RemoveBinary).unwrap(),
            )
            .unwrap();
        drop(journal);

        let mut component = component();
        let mut accounts = Accounts {
            identity_present: true,
            ..Accounts::default()
        };
        let mut systemd = Systemd::default();
        activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_restart").unwrap(),
            &bundle(),
            &trust(),
            &paths,
            &mut accounts,
            &mut systemd,
        )
        .expect("restart recovery removes only journal-owned partial state");

        assert_eq!(fs::read(paths.binary()).unwrap(), b"probe");
        assert_eq!(accounts.calls, ["owns", "remove", "absent", "create"]);
        assert_eq!(
            systemd.calls,
            ["reload", "absent", "reload", "enable", "start", "ready"]
        );
    }

    #[test]
    fn abnormal_recovery_account_lookup_keeps_the_journal_for_retry() {
        struct LookupFailureAccounts;
        impl AccountPort for LookupFailureAccounts {
            fn require_absent(&mut self) -> Result<(), InstallError> {
                unreachable!()
            }
            fn create_transaction_identity(
                &mut self,
                _transaction_id: &str,
            ) -> Result<ServiceIdentity, InstallError> {
                unreachable!()
            }
            fn remove_transaction_identity(
                &mut self,
                _transaction_id: &str,
                _identity: Option<ServiceIdentity>,
            ) -> Result<(), InstallError> {
                unreachable!()
            }
            fn owns_transaction_identity(
                &mut self,
                _transaction_id: &str,
                identity: Option<ServiceIdentity>,
            ) -> Result<bool, InstallError> {
                assert_eq!(identity, None);
                Err(InstallError::Account)
            }
        }

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib/enoki-probe-bootstrap",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        fs::set_permissions(
            temporary.path().join("var/lib/enoki-probe-bootstrap"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        write_bootstrap_roles(temporary.path());
        let paths = FixedInstallPaths::under(temporary.path());
        drop(TransactionJournal::begin(&paths.bootstrap_state()).unwrap());

        let error = activate_current_probe(
            &mut component(),
            &Enrollment::new("https://hub.example", "enk_enroll_restart").unwrap(),
            &bundle(),
            &trust(),
            &paths,
            &mut LookupFailureAccounts,
            &mut Systemd::default(),
        )
        .expect_err("异常 account lookup 必须中止 recovery");

        assert_eq!(
            error,
            InstallError::Rollback {
                cause: InstallErrorKind::Io,
                failures: vec![RollbackFailure::new(
                    RollbackStep::RemoveServiceIdentity,
                    InstallErrorKind::Account,
                )],
            }
        );
        assert!(
            paths
                .bootstrap_state()
                .join("activation-journal.json")
                .exists()
        );
    }

    #[test]
    fn fresh_retry_recovers_journal_owned_bootstrap_roles() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib/enoki-probe-bootstrap",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        fs::set_permissions(
            temporary.path().join("var/lib/enoki-probe-bootstrap"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let paths = FixedInstallPaths::under(temporary.path());
        let mut journal = TransactionJournal::begin(&paths.bootstrap_state()).unwrap();
        for role in bootstrap_role_registry(&paths) {
            fs::write(&role.path, b"interrupted").unwrap();
            fs::set_permissions(&role.path, fs::Permissions::from_mode(0o755)).unwrap();
            journal
                .record_path(OwnedPath::capture(&role.path, false, role.rollback).unwrap())
                .unwrap();
        }
        drop(journal);

        let mut acquirer = component();
        let mut activator = component();
        let mut probe = component();
        activate_fresh_current_probe(
            VerifiedFreshComponents {
                probe: &mut probe,
                bootstrap_acquirer: &mut acquirer,
                bootstrap_activator: &mut activator,
            },
            &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
            &bundle(),
            &trust(),
            &paths,
            &mut Accounts::default(),
            &mut Systemd::default(),
        )
        .expect("retry recovers and republishes both fixed Bootstrap roles");
        assert_eq!(fs::read(paths.bootstrap_acquirer()).unwrap(), b"probe");
        assert_eq!(fs::read(paths.bootstrap_activator()).unwrap(), b"probe");
    }

    #[test]
    fn account_mutation_observes_its_durable_transaction_marker() {
        struct IntentCheckingAccounts {
            state: PathBuf,
            checked: bool,
        }
        impl AccountPort for IntentCheckingAccounts {
            fn require_absent(&mut self) -> Result<(), InstallError> {
                Ok(())
            }
            fn create_transaction_identity(
                &mut self,
                transaction_id: &str,
            ) -> Result<ServiceIdentity, InstallError> {
                let bytes = fs::read(self.state.join("activation-journal.json")).unwrap();
                let text = String::from_utf8(bytes).unwrap();
                assert!(text.contains(transaction_id));
                self.checked = true;
                Err(InstallError::Account)
            }
            fn remove_transaction_identity(
                &mut self,
                _transaction_id: &str,
                _identity: Option<ServiceIdentity>,
            ) -> Result<(), InstallError> {
                Ok(())
            }
        }

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let paths = FixedInstallPaths::under(temporary.path());
        let mut accounts = IntentCheckingAccounts {
            state: paths.bootstrap_state(),
            checked: false,
        };
        let error = activate_current_probe(
            &mut component(),
            &Enrollment::new("https://hub.example", "enk_enroll_intent").unwrap(),
            &bundle(),
            &trust(),
            &paths,
            &mut accounts,
            &mut Systemd::default(),
        )
        .unwrap_err();

        assert_eq!(error, InstallError::Account);
        assert!(accounts.checked);
    }

    #[test]
    fn existing_or_symlinked_enoki_residue_fails_before_any_host_authority() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            "/not-a-probe",
            temporary.path().join("usr/local/bin/enoki-probe"),
        )
        .unwrap();
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap_err();
        assert_eq!(error, InstallError::ExistingResidue);
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
        assert!(!format!("{error:?}").contains("enk_enroll_secret"));
    }

    #[test]
    fn unsafe_existing_metadata_directory_fails_before_any_host_authority() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        fs::set_permissions(
            temporary.path().join("etc/enoki"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect_err("unsafe metadata directory fails closed");

        assert_eq!(error, InstallError::ExistingResidue);
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_metadata_directory_fails_before_any_host_authority() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let target = temporary.path().join("outside");
        fs::create_dir(&target).unwrap();
        symlink(&target, temporary.path().join("etc/enoki")).unwrap();
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect_err("symlinked metadata directory fails closed");

        assert_eq!(error, InstallError::ExistingResidue);
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn start_failure_rolls_back_only_this_attempt_and_allows_a_fresh_retry() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            fail_start: true,
            ..Systemd::default()
        };
        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .unwrap_err();
        assert_eq!(error, InstallError::Systemd);
        assert_eq!(
            systemd.calls,
            [
                "absent", "reload", "enable", "start", "stop", "disable", "reload"
            ]
        );
        assert_eq!(accounts.calls, ["absent", "create", "remove"]);
        assert!(!temporary.path().join("usr/local/bin/enoki-probe").exists());
        assert!(!temporary.path().join("var/lib/enoki-probe").exists());
        assert!(
            !temporary
                .path()
                .join("etc/enoki/probe-install.toml")
                .exists()
        );
        assert!(
            !temporary
                .path()
                .join("etc/systemd/system/enoki-probe.service")
                .exists()
        );
        assert!(temporary.path().join("etc/enoki").is_dir());
        assert!(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-acquire")
                .exists()
        );
        assert!(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-activate")
                .exists()
        );
        systemd.fail_start = false;
        activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect("a transient start failure leaves a retryable fresh install");
        assert!(temporary.path().join("usr/local/bin/enoki-probe").exists());
        assert!(
            temporary
                .path()
                .join("etc/enoki/probe-install.toml")
                .exists()
        );
    }

    #[test]
    fn rollback_attempts_every_compensation_and_reports_failures_in_stable_order() {
        struct FailingAccounts {
            calls: Vec<&'static str>,
        }
        impl AccountPort for FailingAccounts {
            fn require_absent(&mut self) -> Result<(), InstallError> {
                self.calls.push("absent");
                Ok(())
            }
            fn create_transaction_identity(
                &mut self,
                _transaction_id: &str,
            ) -> Result<ServiceIdentity, InstallError> {
                self.calls.push("create");
                Ok(ServiceIdentity {
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                })
            }
            fn remove_transaction_identity(
                &mut self,
                _transaction_id: &str,
                _identity: Option<ServiceIdentity>,
            ) -> Result<(), InstallError> {
                self.calls.push("remove");
                Err(InstallError::Account)
            }
        }
        struct FailingSystemd {
            calls: Vec<&'static str>,
            unit: PathBuf,
            reloads: usize,
        }
        impl SystemdPort for FailingSystemd {
            fn require_absent(&mut self) -> Result<(), InstallError> {
                self.calls.push("absent");
                Ok(())
            }
            fn daemon_reload(&mut self) -> Result<(), InstallError> {
                self.calls.push("reload");
                self.reloads += 1;
                if self.reloads == 2 {
                    Err(InstallError::Systemd)
                } else {
                    Ok(())
                }
            }
            fn enable(&mut self) -> Result<(), InstallError> {
                self.calls.push("enable");
                Ok(())
            }
            fn start(&mut self) -> Result<(), InstallError> {
                self.calls.push("start");
                fs::remove_file(&self.unit).unwrap();
                fs::create_dir(&self.unit).unwrap();
                Err(InstallError::Systemd)
            }
            fn wait_local_activated(&mut self) -> Result<(), InstallError> {
                unreachable!()
            }
            fn stop(&mut self) -> Result<(), InstallError> {
                self.calls.push("stop");
                Err(InstallError::Systemd)
            }
            fn disable(&mut self) -> Result<(), InstallError> {
                self.calls.push("disable");
                Err(InstallError::Systemd)
            }
        }

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = FailingAccounts { calls: Vec::new() };
        let unit = temporary
            .path()
            .join("etc/systemd/system/enoki-probe.service");
        let mut systemd = FailingSystemd {
            calls: Vec::new(),
            unit,
            reloads: 0,
        };

        let error = activate_current_probe(
            &mut component,
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &bundle(),
            &trust(),
            &FixedInstallPaths::under(temporary.path()),
            &mut accounts,
            &mut systemd,
        )
        .expect_err("start and rollback failures must remain observable");

        assert_eq!(
            error,
            InstallError::Rollback {
                cause: InstallErrorKind::Systemd,
                failures: vec![
                    RollbackFailure::new(RollbackStep::StopService, InstallErrorKind::Systemd),
                    RollbackFailure::new(RollbackStep::DisableService, InstallErrorKind::Systemd),
                    RollbackFailure::new(
                        RollbackStep::RemoveUnit,
                        InstallErrorKind::ExistingResidue,
                    ),
                    RollbackFailure::new(RollbackStep::ReloadSystemd, InstallErrorKind::Systemd),
                    RollbackFailure::new(
                        RollbackStep::RemoveServiceIdentity,
                        InstallErrorKind::Account,
                    ),
                ],
            }
        );
        assert_eq!(
            systemd.calls,
            [
                "absent", "reload", "enable", "start", "stop", "disable", "reload"
            ]
        );
        assert_eq!(accounts.calls, ["absent", "create", "remove"]);
        assert!(
            fs::symlink_metadata(
                temporary
                    .path()
                    .join("etc/systemd/system/enoki-probe.service")
            )
            .unwrap()
            .is_dir(),
            "a replacement is preserved and reported as closed residue"
        );
        assert!(
            !temporary.path().join("var/lib/enoki-probe").exists(),
            "a unit cleanup failure must not stop later filesystem compensations"
        );
        assert!(
            !temporary
                .path()
                .join("etc/enoki/probe-install.toml")
                .exists()
        );
        assert!(
            temporary
                .path()
                .join("var/lib/enoki-probe-bootstrap/activation-journal.json")
                .exists(),
            "account removal 异常时保留 journal 供补偿重试"
        );
    }

    #[test]
    fn every_filesystem_mutation_failure_rolls_back_to_a_retryable_fresh_state() {
        struct FaultFiles {
            inner: SystemInstallFiles,
            fail_at: usize,
            mutation: usize,
        }
        impl FaultFiles {
            fn before_mutation(&mut self) -> Result<(), InstallError> {
                let current = self.mutation;
                self.mutation += 1;
                if current == self.fail_at {
                    Err(InstallError::Io)
                } else {
                    Ok(())
                }
            }
        }
        impl InstallFilePort for FaultFiles {
            fn ensure_metadata_directory(
                &mut self,
                path: &Path,
                journal: &mut TransactionJournal,
            ) -> Result<bool, InstallError> {
                self.before_mutation()?;
                self.inner.ensure_metadata_directory(path, journal)
            }
            fn create_directory(
                &mut self,
                path: &Path,
                mode: u32,
                identity: ServiceIdentity,
                journal: &mut TransactionJournal,
                step: RollbackStep,
            ) -> Result<(), InstallError> {
                self.before_mutation()?;
                self.inner
                    .create_directory(path, mode, identity, journal, step)
            }
            fn install_binary(
                &mut self,
                component: &mut File,
                path: &Path,
                journal: &mut TransactionJournal,
                step: RollbackStep,
            ) -> Result<(), InstallError> {
                self.before_mutation()?;
                self.inner.install_binary(component, path, journal, step)
            }
            fn write_owned(
                &mut self,
                path: &Path,
                contents: &[u8],
                mode: u32,
                owner: ServiceIdentity,
                journal: &mut TransactionJournal,
                step: RollbackStep,
            ) -> Result<(), InstallError> {
                self.before_mutation()?;
                self.inner
                    .write_owned(path, contents, mode, owner, journal, step)
            }
            fn remove_path(&mut self, path: &Path) -> Result<(), InstallError> {
                self.inner.remove_path(path)
            }
            fn remove_directory(&mut self, path: &Path) -> Result<(), InstallError> {
                self.inner.remove_directory(path)
            }
        }

        for fail_at in 0..7 {
            let temporary = tempdir().unwrap();
            for parent in [
                "usr/local/bin",
                "var/lib",
                "etc",
                "etc/systemd/system",
                "etc/sudoers.d",
            ] {
                fs::create_dir_all(temporary.path().join(parent)).unwrap();
            }
            write_bootstrap_roles(temporary.path());
            let paths = FixedInstallPaths::under(temporary.path());
            let mut component = component();
            let mut accounts = Accounts::default();
            let mut systemd = Systemd::default();
            let mut files = FaultFiles {
                inner: SystemInstallFiles,
                fail_at,
                mutation: 0,
            };

            assert_eq!(
                activate_current_probe_with_files(
                    &mut component,
                    None,
                    &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                    &bundle(),
                    &trust(),
                    &paths,
                    &mut InstallPorts {
                        accounts: &mut accounts,
                        systemd: &mut systemd,
                        files: &mut files,
                    },
                ),
                Err(InstallError::Io),
                "filesystem mutation {fail_at} must preserve the initiating failure"
            );
            for residue in [
                "usr/local/bin/enoki-probe",
                "var/lib/enoki-probe",
                "etc/enoki",
                "etc/systemd/system/enoki-probe.service",
            ] {
                assert!(
                    !temporary.path().join(residue).exists(),
                    "filesystem mutation {fail_at} left {residue}"
                );
            }
            assert!(paths.bootstrap_acquirer().exists());
            assert!(paths.bootstrap_activator().exists());

            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut Accounts::default(),
                &mut Systemd::default(),
            )
            .expect("rollback must permit a fresh retry");
        }
    }

    #[test]
    fn rollback_never_removes_state_not_created_by_this_transaction() {
        struct RacingFiles {
            inner: SystemInstallFiles,
        }
        impl InstallFilePort for RacingFiles {
            fn ensure_metadata_directory(
                &mut self,
                path: &Path,
                journal: &mut TransactionJournal,
            ) -> Result<bool, InstallError> {
                self.inner.ensure_metadata_directory(path, journal)
            }
            fn create_directory(
                &mut self,
                path: &Path,
                mode: u32,
                identity: ServiceIdentity,
                journal: &mut TransactionJournal,
                step: RollbackStep,
            ) -> Result<(), InstallError> {
                self.inner
                    .create_directory(path, mode, identity, journal, step)
            }
            fn install_binary(
                &mut self,
                _component: &mut File,
                path: &Path,
                _journal: &mut TransactionJournal,
                _step: RollbackStep,
            ) -> Result<(), InstallError> {
                fs::write(path, b"preexisting-race").unwrap();
                Err(InstallError::ExistingResidue)
            }
            fn write_owned(
                &mut self,
                path: &Path,
                contents: &[u8],
                mode: u32,
                owner: ServiceIdentity,
                journal: &mut TransactionJournal,
                step: RollbackStep,
            ) -> Result<(), InstallError> {
                self.inner
                    .write_owned(path, contents, mode, owner, journal, step)
            }
            fn remove_path(&mut self, path: &Path) -> Result<(), InstallError> {
                self.inner.remove_path(path)
            }
            fn remove_directory(&mut self, path: &Path) -> Result<(), InstallError> {
                self.inner.remove_directory(path)
            }
        }

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let paths = FixedInstallPaths::under(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        let mut files = RacingFiles {
            inner: SystemInstallFiles,
        };

        assert_eq!(
            activate_current_probe_with_files(
                &mut component,
                None,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut InstallPorts {
                    accounts: &mut accounts,
                    systemd: &mut systemd,
                    files: &mut files,
                },
            ),
            Err(InstallError::ExistingResidue)
        );
        assert_eq!(fs::read(paths.binary()).unwrap(), b"preexisting-race");
        assert!(!paths.state().exists());
        assert!(!paths.metadata().exists());
        assert!(!paths.unit().exists());

        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut Accounts::default(),
                &mut Systemd::default(),
            ),
            Err(InstallError::ExistingResidue),
            "retry must preserve and report the authoritative pre-existing state"
        );
        assert_eq!(fs::read(paths.binary()).unwrap(), b"preexisting-race");
    }

    #[test]
    fn every_systemd_mutation_failure_compensates_uncertain_partial_state() {
        struct FailOnceSystemd {
            calls: Vec<&'static str>,
            fail_on: &'static str,
            failed: bool,
        }
        impl FailOnceSystemd {
            fn call(&mut self, action: &'static str) -> Result<(), InstallError> {
                self.calls.push(action);
                if action == self.fail_on && !self.failed {
                    self.failed = true;
                    Err(InstallError::Systemd)
                } else {
                    Ok(())
                }
            }
        }
        impl SystemdPort for FailOnceSystemd {
            fn require_absent(&mut self) -> Result<(), InstallError> {
                self.call("absent")
            }
            fn daemon_reload(&mut self) -> Result<(), InstallError> {
                self.call("reload")
            }
            fn enable(&mut self) -> Result<(), InstallError> {
                self.call("enable")
            }
            fn start(&mut self) -> Result<(), InstallError> {
                self.call("start")
            }
            fn wait_local_activated(&mut self) -> Result<(), InstallError> {
                self.call("ready")
            }
            fn stop(&mut self) -> Result<(), InstallError> {
                self.call("stop")
            }
            fn disable(&mut self) -> Result<(), InstallError> {
                self.call("disable")
            }
        }

        for fail_on in ["reload", "enable", "start", "ready"] {
            let temporary = tempdir().unwrap();
            for parent in [
                "usr/local/bin",
                "var/lib",
                "etc",
                "etc/systemd/system",
                "etc/sudoers.d",
            ] {
                fs::create_dir_all(temporary.path().join(parent)).unwrap();
            }
            write_bootstrap_roles(temporary.path());
            let paths = FixedInstallPaths::under(temporary.path());
            let mut component = component();
            let mut accounts = Accounts::default();
            let mut systemd = FailOnceSystemd {
                calls: Vec::new(),
                fail_on,
                failed: false,
            };

            assert_eq!(
                activate_current_probe(
                    &mut component,
                    &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                    &bundle(),
                    &trust(),
                    &paths,
                    &mut accounts,
                    &mut systemd,
                ),
                Err(InstallError::Systemd)
            );
            if fail_on == "enable" {
                assert!(
                    systemd.calls.contains(&"disable"),
                    "a failed mutating enable has uncertain partial state and must be disabled"
                );
            }
            if matches!(fail_on, "start" | "ready") {
                assert!(systemd.calls.contains(&"stop"));
                assert!(systemd.calls.contains(&"disable"));
            }
            assert_eq!(accounts.calls, ["absent", "create", "remove"]);
            assert!(!paths.binary().exists());
            assert!(!paths.state().exists());
            assert!(!paths.metadata().exists());
            assert!(!paths.unit().exists());

            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_retry").unwrap(),
                &bundle(),
                &trust(),
                &paths,
                &mut Accounts::default(),
                &mut Systemd::default(),
            )
            .expect("systemd compensation must permit a fresh retry");
        }
    }

    #[test]
    fn loaded_systemd_residue_fails_before_creating_the_service_account_or_files() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd {
            residue: true,
            ..Systemd::default()
        };
        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd
            ),
            Err(InstallError::ExistingResidue)
        );
        assert_eq!(accounts.calls, ["absent"]);
        assert_eq!(systemd.calls, ["absent"]);
        assert!(!temporary.path().join("var/lib/enoki-probe").exists());
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_roles_must_be_root_owned_regular_0755_files_and_are_never_cleaned_on_failure() {
        use std::os::unix::fs::symlink;
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc/enoki",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let acquirer = temporary
            .path()
            .join("usr/local/bin/enoki-probe-bootstrap-acquire");
        symlink("/untrusted", &acquirer).unwrap();
        fs::write(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-activate"),
            "role",
        )
        .unwrap();
        fs::set_permissions(
            temporary
                .path()
                .join("usr/local/bin/enoki-probe-bootstrap-activate"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();
        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd
            ),
            Err(InstallError::ExistingResidue)
        );
        assert!(
            fs::symlink_metadata(acquirer)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn missing_bootstrap_role_fails_before_creating_the_metadata_directory() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd,
            ),
            Err(InstallError::ExistingResidue)
        );
        assert!(
            !temporary.path().join("etc/enoki").exists(),
            "preflight rejection must leave the Host filesystem unchanged"
        );
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[test]
    fn acquirer_trust_cannot_enter_the_fixed_activation_transaction() {
        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var/lib",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        write_bootstrap_roles(temporary.path());
        let mut wrong_role = trust();
        wrong_role.role = BootstrapRole::Acquirer;
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &wrong_role,
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd,
            ),
            Err(InstallError::InvalidVerifiedComponent)
        );
        assert!(!temporary.path().join("etc/enoki").exists());
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_destination_parent_fails_before_creating_identity_or_metadata() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        for parent in [
            "usr/local/bin",
            "var",
            "etc",
            "etc/systemd/system",
            "etc/sudoers.d",
            "outside",
        ] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        symlink(
            temporary.path().join("outside"),
            temporary.path().join("var/lib"),
        )
        .unwrap();
        write_bootstrap_roles(temporary.path());
        let mut component = component();
        let mut accounts = Accounts::default();
        let mut systemd = Systemd::default();

        assert_eq!(
            activate_current_probe(
                &mut component,
                &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
                &bundle(),
                &trust(),
                &FixedInstallPaths::under(temporary.path()),
                &mut accounts,
                &mut systemd,
            ),
            Err(InstallError::Io)
        );
        assert!(!temporary.path().join("etc/enoki").exists());
        assert!(accounts.calls.is_empty());
        assert!(systemd.calls.is_empty());
    }

    fn write_bootstrap_roles(root: &Path) {
        for role in [
            "enoki-probe-bootstrap-acquire",
            "enoki-probe-bootstrap-activate",
        ] {
            let path = root.join("usr/local/bin").join(role);
            fs::write(&path, "bootstrap role").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}

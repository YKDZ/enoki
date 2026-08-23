#[cfg(test)]
mod tests {
    use super::*;
    use super::account::{
        account_records_match_transaction, create_transaction_identity_with_commands,
    };
    use crate::handoff::Enrollment;
    use crate::trust::BootstrapRole;
    use tempfile::tempdir;

    #[test]
    fn system_state_boundary_assigns_host_facts_only_to_the_fixed_provider() {
        for unit in [service_unit(), observation_runtime_unit()] {
            assert!(unit.contains("InaccessiblePaths=/proc/stat"));
            assert!(unit.contains("/proc/cpuinfo"));
            assert!(unit.contains("/etc/os-release"));
        }
        let provider = cpu_provider_unit();
        assert!(provider.contains("RestrictAddressFamilies=AF_NETLINK"));
        assert!(provider.contains("IPAddressDeny=any"));
        assert!(provider.contains("ProtectHome=read-only"));
        assert!(provider.contains("BindReadOnlyPaths=/etc/os-release /usr/lib/os-release /sys/devices/system/cpu /sys/class/hwmon /sys/class/power_supply"));
        assert!(provider.contains("ReadOnlyPaths=/proc/stat /proc/loadavg /proc/meminfo /proc/uptime /proc/cpuinfo /proc/mounts"));
        assert!(provider.contains("/proc/net/dev /proc/net/route /proc/net/ipv6_route /proc/diskstats"));
        assert!(provider.contains("IPAddressDeny=any"));
        assert!(provider.contains("SocketBindDeny=ipv4:any"));
    }

    #[derive(Default)]
    struct Accounts {
        calls: Vec<&'static str>,
        ipc_calls: Vec<&'static str>,
        reject: bool,
    }
    impl AccountPort for Accounts {
        fn require_absent(&mut self) -> Result<(), InstallError> {
            self.calls.push("absent");
            (!self.reject)
                .then_some(())
                .ok_or(InstallError::ExistingResidue)
        }
        fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
            self.calls.push("create");
            Ok(ServiceIdentity {
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            })
        }
        fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
            self.calls.push("remove");
            Ok(())
        }
        fn owns_static_service_identity(
            &mut self,
            _identity: ServiceIdentity,
        ) -> Result<bool, InstallError> {
            self.calls.push("owns");
            Ok(true)
        }
        fn create_observation_ipc_group(
            &mut self,
            _transaction_id: &str,
        ) -> Result<(), InstallError> {
            self.ipc_calls.push("create");
            Ok(())
        }
        fn remove_observation_ipc_group(
            &mut self,
            _transaction_id: &str,
        ) -> Result<(), InstallError> {
            self.ipc_calls.push("remove");
            Ok(())
        }
    }
    #[derive(Default)]
    struct Systemd {
        calls: Vec<&'static str>,
        fail_start: bool,
        residue: bool,
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
            Ok(())
        }
        fn enable(&mut self) -> Result<(), InstallError> {
            self.calls.push("enable");
            Ok(())
        }
        fn start(&mut self) -> Result<(), InstallError> {
            self.calls.push("start");
            (!self.fail_start)
                .then_some(())
                .ok_or(InstallError::Systemd)
        }
        fn wait_local_activated(&mut self) -> Result<(), InstallError> {
            self.calls.push("ready");
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
            version: "1.2.3".into(),
            target: "x86_64-unknown-linux-gnu".into(),
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
                    "/usr/sbin/userdel" => panic!(
                        "a failed useradd does not prove ownership of the visible user"
                    ),
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
        assert!(calls[0]
            .1
            .contains("--password !enoki-bootstrap-0123456789abcdef"));
        assert!(calls[1].1.contains("--comment enoki-bootstrap-0123456789abcdef"));
    }

    #[test]
    fn reused_numeric_identity_without_the_transaction_marker_is_not_owned() {
        assert!(!account_records_match_transaction(
            "enoki-bootstrap-current",
            "!enoki-bootstrap-current",
            Some("enoki-probe:x:456:"),
            Some("enoki-probe:!enoki-bootstrap-previous::"),
            Some("enoki-probe:x:123:456:enoki-bootstrap-previous:/var/lib/enoki-probe:/usr/sbin/nologin"),
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

        assert!(probe.contains("Requires=enoki-observation-runtime.socket enoki-cpu-resource-provider.socket"));
        assert!(runtime_socket.contains("SocketGroup=enoki-probe"));
        assert!(runtime.contains("User=enoki-observation-runtime"));
        assert!(runtime.contains("PrivateNetwork=true"));
        assert!(runtime.contains("SupplementaryGroups=enoki-observation-ipc"));
        assert!(provider_socket.contains("SocketGroup=enoki-observation-ipc"));
        assert!(provider_socket.contains("MaxConnections=1"));
        assert!(provider_socket.contains("TriggerLimitBurst=12"));
        assert!(provider.contains("ExecStart=/usr/local/bin/enoki-cpu-resource-provider\n"));
        assert!(provider.contains("RuntimeMaxSec=3s"));
        assert!(provider.contains("KillMode=control-group"));
        assert!(provider.contains("RestrictAddressFamilies=AF_NETLINK"));
        assert!(provider.contains("IPAddressDeny=any"));
        assert!(provider.contains("SocketBindDeny=ipv4:any"));
        assert!(provider.contains("SocketBindDeny=ipv6:any"));
        assert!(provider.contains("ReadOnlyPaths=/proc/stat"));
        assert!(
            !provider.contains("ProcSubset=pid"),
            "CPU Provider 必须能读取非进程类顶层 /proc/stat"
        );
        assert!(!provider.contains('%'));
        assert!(runtime.contains("Requires=enoki-cpu-resource-provider.socket enoki-disk-health-resource-provider.socket"));
        assert!(disk_provider_socket.contains("SocketGroup=enoki-observation-ipc"));
        assert!(disk_provider_socket.contains("MaxConnections=1"));
        assert!(disk_provider_socket.contains("TriggerLimitBurst=2"));
        assert!(disk_provider.contains("ExecStart=/usr/local/bin/enoki-disk-health-resource-provider"));
        assert!(disk_provider.contains("RuntimeMaxSec=10s"));
        assert!(disk_provider.contains("KillMode=control-group"));
        assert!(disk_provider.contains("CapabilityBoundingSet=CAP_SYS_RAWIO"));
        assert!(disk_provider.contains("DevicePolicy=closed"));
        assert!(disk_provider.contains("DeviceAllow=block-* rw"));
        assert!(disk_provider.contains("IPAddressDeny=any"));
        assert!(disk_provider.contains("SocketBindDeny=any"));
        assert!(disk_provider.contains("BindReadOnlyPaths=-/usr/sbin/smartctl -/usr/bin/smartctl"));
    }

    #[test]
    fn schema_three_persists_the_trusted_operation_launcher_and_authority_paths() {
        let config = bootstrap_config(
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &trust(),
            true,
        );
        assert!(config.contains("upgrader_launch = \"systemd\""));
        assert!(config.contains(
            "operation_sudoers_path = \"/etc/sudoers.d/enoki-probe-operations\""
        ));

        let metadata = install_metadata(
            &Enrollment::new("https://hub.example", "enk_enroll_secret").unwrap(),
            &trust(),
            true,
        );
        assert!(metadata.contains(
            "operation_sudoers_path = \"/etc/sudoers.d/enoki-probe-operations\""
        ));
        assert!(operation_sudoers().contains("internal-upgrader --config"));
        assert!(operation_sudoers().contains("internal-uninstaller --config"));
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
        assert!(!temporary
            .path()
            .join("usr/local/bin/enoki-observation-runtime")
            .exists());
    }

    #[test]
    fn complete_fresh_install_publishes_the_real_operation_entrypoint_transactionally() {
        let temporary = tempdir().unwrap();
        for parent in ["usr/local/bin", "var/lib", "etc/systemd/system", "etc/sudoers.d"] {
            fs::create_dir_all(temporary.path().join(parent)).unwrap();
        }
        let mut probe = component();
        let mut runtime = component();
        let mut provider = component();
        let mut disk_health_provider = component();
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
            temporary.path().join("var/lib/enoki-probe/identity/probe-bootstrap.toml"),
        )
        .unwrap();
        let sudoers = fs::read_to_string(
            temporary.path().join("etc/sudoers.d/enoki-probe-operations"),
        )
        .unwrap();
        assert!(config.contains("upgrader_launch = \"systemd\""));
        assert!(sudoers.contains("systemd-run --collect --pipe --wait"));
        assert!(sudoers.contains("internal-upgrader --config /var/lib/enoki-probe/identity/probe-bootstrap.toml"));
        assert!(sudoers.contains("internal-uninstaller --config /var/lib/enoki-probe/identity/probe-bootstrap.toml"));
        assert_eq!(fs::metadata(temporary.path().join("etc/sudoers.d/enoki-probe-operations")).unwrap().mode() & 0o777, 0o440);
    }

    #[test]
    fn second_bootstrap_role_failure_cleans_the_first_receipt_and_allows_retry() {
        let temporary = tempdir().unwrap();
        for parent in ["usr/local/bin", "var/lib", "etc/systemd/system", "etc/sudoers.d"] {
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
        assert!(!paths.bootstrap_state().join("activation-journal.json").exists());

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
        for parent in ["usr/local/bin", "var/lib", "etc/systemd/system", "etc/sudoers.d"] {
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
        assert_eq!(fs::read(paths.bootstrap_acquirer()).unwrap(), b"replacement");
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
        assert!(paths.bootstrap_state().join("activation-journal.json").exists());

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
        assert_eq!(fs::read(paths.bootstrap_acquirer()).unwrap(), b"replacement");
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
            fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
                unreachable!()
            }
            fn create_transaction_identity(
                &mut self,
                _transaction_id: &str,
            ) -> Result<ServiceIdentity, InstallError> {
                self.calls.push("create");
                Err(InstallError::Account)
            }
            fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
                unreachable!()
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
        for parent in ["usr/local/bin", "var/lib", "etc/systemd/system", "etc/sudoers.d"] {
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
        assert!(!paths.bootstrap_state().join("activation-journal.json").exists());

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
            fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
                unreachable!()
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
            fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
                unreachable!()
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

        for failure in [PreparedFailure::RecordIdentity, PreparedFailure::StageLayout] {
            let temporary = tempdir().unwrap();
            for parent in ["usr/local/bin", "var/lib", "etc/systemd/system", "etc/sudoers.d"] {
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
                !paths.bootstrap_state().join("activation-journal.json").exists(),
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
        assert!(!paths.bootstrap_state().join("activation-journal.json").exists());

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
        assert_eq!(fs::read(paths.bootstrap_acquirer()).unwrap(), b"preexisting");
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
        let mut accounts = Accounts::default();
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
            fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
                unreachable!()
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
            fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
                unreachable!()
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
        for parent in ["usr/local/bin", "var/lib", "etc/systemd/system", "etc/sudoers.d"] {
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
            calls: Vec::new(),
            fail_start: true,
            residue: false,
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
            fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
                self.calls.push("create");
                Ok(ServiceIdentity {
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                })
            }
            fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
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
            calls: Vec::new(),
            fail_start: false,
            residue: true,
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

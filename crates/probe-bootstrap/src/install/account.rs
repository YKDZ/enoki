use super::*;
/// 生产 account adapter 的可执行文件与参数完全固定，执行前清空进程环境。
#[derive(Default)]
pub struct SystemAccounts {
    command_deadline: Option<Instant>,
}
impl AccountPort for SystemAccounts {
    fn set_command_deadline(&mut self, deadline: Instant) {
        self.command_deadline = Some(deadline);
    }
    fn require_absent(&mut self) -> Result<(), InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        let group = command_presence("/usr/bin/getent", &["group", SERVICE_GROUP], 2, deadline)?;
        let user = command_presence("/usr/bin/id", &["-u", SERVICE_USER], 1, deadline)?;
        let ipc_group = command_presence(
            "/usr/bin/getent",
            &["group", OBSERVATION_IPC_GROUP],
            2,
            deadline,
        )?;
        if group || user || ipc_group {
            Err(InstallError::ExistingResidue)
        } else {
            Ok(())
        }
    }
    fn create_static_service_identity(&mut self) -> Result<ServiceIdentity, InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        create_static_service_identity_with_commands(
            &mut |program, arguments| {
                require_success(program, arguments, InstallError::Account, deadline)
            },
            &mut |flag| numeric_id(flag, deadline),
        )
    }
    fn remove_static_service_identity(&mut self) -> Result<(), InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        remove_static_service_identity_with_commands(&mut |program, arguments| {
            require_success(program, arguments, InstallError::Account, deadline)
        })
    }
    fn owns_static_service_identity(
        &mut self,
        identity: ServiceIdentity,
    ) -> Result<bool, InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        let uid = numeric_id("-u", deadline)?;
        let gid = numeric_id("-g", deadline)?;
        Ok(uid == identity.uid && gid == identity.gid)
    }
    fn create_transaction_identity(
        &mut self,
        transaction_id: &str,
    ) -> Result<ServiceIdentity, InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        create_transaction_identity_with_commands(
            transaction_id,
            &mut |program, arguments| {
                require_success(program, arguments, InstallError::Account, deadline)
            },
            &mut |flag| numeric_id(flag, deadline),
        )
    }
    fn owns_transaction_identity(
        &mut self,
        transaction_id: &str,
        identity: Option<ServiceIdentity>,
    ) -> Result<bool, InstallError> {
        inspect_transaction_identity(transaction_id, identity, self.command_deadline)
    }
    fn remove_transaction_identity(
        &mut self,
        transaction_id: &str,
        identity: Option<ServiceIdentity>,
    ) -> Result<(), InstallError> {
        remove_transaction_identity(transaction_id, identity, self.command_deadline)
    }
    fn create_observation_ipc_group(&mut self, transaction_id: &str) -> Result<(), InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        let marker = group_account_marker(transaction_id);
        require_success(
            "/usr/sbin/groupadd",
            &["--system", "--password", &marker, OBSERVATION_IPC_GROUP],
            InstallError::Account,
            deadline,
        )
    }
    fn remove_observation_ipc_group(&mut self, transaction_id: &str) -> Result<(), InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        let output = run_bounded(
            "/usr/bin/getent",
            &["gshadow", OBSERVATION_IPC_GROUP],
            InstallError::Account,
            deadline,
            COMMAND_STEP_BUDGET,
        )?;
        if output.status.code() == Some(2) {
            return Ok(());
        }
        let record = String::from_utf8(output.stdout).map_err(|_| InstallError::Account)?;
        let fields = record.trim_end().split(':').collect::<Vec<_>>();
        if fields.len() != 4
            || fields[0] != OBSERVATION_IPC_GROUP
            || fields[1] != group_account_marker(transaction_id)
        {
            return Err(InstallError::ExistingResidue);
        }
        require_success(
            "/usr/sbin/groupdel",
            &[OBSERVATION_IPC_GROUP],
            InstallError::Account,
            deadline,
        )
    }
}

fn account_marker(transaction_id: &str) -> String {
    format!("enoki-bootstrap-{transaction_id}")
}

fn group_account_marker(transaction_id: &str) -> String {
    format!("!{}", account_marker(transaction_id))
}

pub(super) fn create_transaction_identity_with_commands(
    transaction_id: &str,
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
    lookup_id: &mut impl FnMut(&str) -> Result<u32, InstallError>,
) -> Result<ServiceIdentity, InstallError> {
    let marker = account_marker(transaction_id);
    let group_marker = group_account_marker(transaction_id);
    execute(
        "/usr/sbin/groupadd",
        &["--system", "--password", &group_marker, SERVICE_GROUP],
    )?;
    execute(
        "/usr/sbin/useradd",
        &[
            "--system",
            "--gid",
            SERVICE_GROUP,
            "--comment",
            &marker,
            "--home-dir",
            STATE,
            "--shell",
            "/usr/sbin/nologin",
            SERVICE_USER,
        ],
    )?;
    Ok(ServiceIdentity {
        uid: lookup_id("-u")?,
        gid: lookup_id("-g")?,
    })
}

fn inspect_transaction_identity(
    transaction_id: &str,
    identity: Option<ServiceIdentity>,
    deadline: Option<Instant>,
) -> Result<bool, InstallError> {
    let deadline = deadline.unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
    let marker = account_marker(transaction_id);
    let group = run_bounded(
        "/usr/bin/getent",
        &["group", SERVICE_GROUP],
        InstallError::Account,
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
    let user = run_bounded(
        "/usr/bin/getent",
        &["passwd", SERVICE_USER],
        InstallError::Account,
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
    let group_shadow = run_bounded(
        "/usr/bin/getent",
        &["gshadow", SERVICE_GROUP],
        InstallError::Account,
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
    let group_text = String::from_utf8(group.stdout).map_err(|_| InstallError::Account)?;
    let user_text = String::from_utf8(user.stdout).map_err(|_| InstallError::Account)?;
    let group_shadow_text =
        String::from_utf8(group_shadow.stdout).map_err(|_| InstallError::Account)?;
    let group_absent = group.status.code() == Some(2);
    let user_absent = user.status.code() == Some(2);
    let group_shadow_absent = group_shadow.status.code() == Some(2);
    if group_absent && user_absent {
        return Ok(false);
    }
    Ok(account_records_match_transaction(
        &marker,
        &group_account_marker(transaction_id),
        (!group_absent).then_some(group_text.as_str()),
        (!group_shadow_absent).then_some(group_shadow_text.as_str()),
        (!user_absent).then_some(user_text.as_str()),
        identity,
    ))
}

pub(super) fn account_records_match_transaction(
    user_marker: &str,
    group_marker: &str,
    group_record: Option<&str>,
    group_shadow_record: Option<&str>,
    user_record: Option<&str>,
    identity: Option<ServiceIdentity>,
) -> bool {
    let group_fields = group_record.map(|record| record.trim_end().split(':').collect::<Vec<_>>());
    let user_fields = user_record.map(|record| record.trim_end().split(':').collect::<Vec<_>>());
    let group_shadow_fields =
        group_shadow_record.map(|record| record.trim_end().split(':').collect::<Vec<_>>());
    let group_owned = group_fields
        .as_ref()
        .is_some_and(|fields| fields.len() == 4 && fields[0] == SERVICE_GROUP)
        && group_shadow_fields.as_ref().is_some_and(|fields| {
            fields.len() == 4 && fields[0] == SERVICE_GROUP && fields[1] == group_marker
        });
    let user_owned = user_fields.as_ref().is_some_and(|fields| {
        fields.len() == 7 && fields[0] == SERVICE_USER && fields[4] == user_marker
    });
    if group_fields.is_some() != group_owned
        || user_fields.is_some() != user_owned
        || group_fields.is_some() != group_shadow_fields.is_some()
        || (!group_owned && !user_owned)
    {
        return false;
    }
    identity.is_none_or(|identity| {
        (!group_owned
            || group_fields
                .as_ref()
                .is_some_and(|fields| fields[2].parse::<u32>() == Ok(identity.gid)))
            && (!user_owned
                || user_fields.as_ref().is_some_and(|fields| {
                    fields[2].parse::<u32>() == Ok(identity.uid)
                        && fields[3].parse::<u32>() == Ok(identity.gid)
                }))
    })
}

fn remove_transaction_identity(
    transaction_id: &str,
    identity: Option<ServiceIdentity>,
    deadline: Option<Instant>,
) -> Result<(), InstallError> {
    if !inspect_transaction_identity(transaction_id, identity, deadline)? {
        return Ok(());
    }
    let deadline = deadline.unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
    let marker = account_marker(transaction_id);
    let user = run_bounded(
        "/usr/bin/getent",
        &["passwd", SERVICE_USER],
        InstallError::Account,
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
    if String::from_utf8(user.stdout)
        .is_ok_and(|record| record.split(':').nth(4) == Some(marker.as_str()))
    {
        require_success(
            "/usr/sbin/userdel",
            &[SERVICE_USER],
            InstallError::Account,
            deadline,
        )?;
    }
    let group = run_bounded(
        "/usr/bin/getent",
        &["gshadow", SERVICE_GROUP],
        InstallError::Account,
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
    if String::from_utf8(group.stdout).is_ok_and(|record| {
        record.split(':').nth(1) == Some(group_account_marker(transaction_id).as_str())
    }) {
        require_success(
            "/usr/sbin/groupdel",
            &[SERVICE_GROUP],
            InstallError::Account,
            deadline,
        )?;
    }
    Ok(())
}

/// account 事务仅补偿由成功命令和持久 journal 共同证明归属的身份。
pub(super) fn create_static_service_identity_with_commands(
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
    lookup_id: &mut impl FnMut(&str) -> Result<u32, InstallError>,
) -> Result<ServiceIdentity, InstallError> {
    execute("/usr/sbin/groupadd", &["--system", SERVICE_GROUP])?;
    if let Err(error) = execute(
        "/usr/sbin/useradd",
        &[
            "--system",
            "--gid",
            SERVICE_GROUP,
            "--home-dir",
            STATE,
            "--shell",
            "/usr/sbin/nologin",
            SERVICE_USER,
        ],
    ) {
        return rollback_account_creation(error, rollback_created_group(execute));
    }
    let uid = match lookup_id("-u") {
        Ok(uid) => uid,
        Err(error) => {
            return rollback_account_creation(error, rollback_created_identity(execute));
        }
    };
    let gid = match lookup_id("-g") {
        Ok(gid) => gid,
        Err(error) => {
            return rollback_account_creation(error, rollback_created_identity(execute));
        }
    };
    Ok(ServiceIdentity { uid, gid })
}

pub(super) fn rollback_account_creation(
    cause: InstallError,
    failures: Vec<RollbackFailure>,
) -> Result<ServiceIdentity, InstallError> {
    if failures.is_empty() {
        Err(cause)
    } else {
        Err(InstallError::Rollback {
            cause: cause.kind(),
            failures,
        })
    }
}

pub(super) fn rollback_created_group(
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
) -> Vec<RollbackFailure> {
    let first = execute("/usr/sbin/groupdel", &[SERVICE_GROUP]);
    let final_result = if first.is_err() {
        execute("/usr/sbin/groupdel", &[SERVICE_GROUP])
    } else {
        first
    };
    final_result.err().map_or_else(Vec::new, |error| {
        vec![RollbackFailure::new(
            RollbackStep::RemoveServiceGroup,
            error.kind(),
        )]
    })
}

pub(super) fn rollback_created_identity(
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
) -> Vec<RollbackFailure> {
    remove_static_service_identity_with_commands(execute)
        .err()
        .and_then(|error| match error {
            InstallError::Rollback { failures, .. } => Some(failures),
            _ => None,
        })
        .unwrap_or_default()
}

pub(super) fn remove_static_service_identity_with_commands(
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
) -> Result<(), InstallError> {
    let first_user = execute("/usr/sbin/userdel", &[SERVICE_USER]);
    let first_group = execute("/usr/sbin/groupdel", &[SERVICE_GROUP]);
    let final_user = if first_user.is_err() {
        execute("/usr/sbin/userdel", &[SERVICE_USER])
    } else {
        first_user
    };
    let final_group = if first_group.is_err() {
        execute("/usr/sbin/groupdel", &[SERVICE_GROUP])
    } else {
        first_group
    };
    let mut failures = Vec::new();
    record_rollback(&mut failures, RollbackStep::RemoveServiceUser, final_user);
    record_rollback(&mut failures, RollbackStep::RemoveServiceGroup, final_group);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(InstallError::Rollback {
            cause: InstallErrorKind::Account,
            failures,
        })
    }
}

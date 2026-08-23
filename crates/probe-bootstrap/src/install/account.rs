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
        let probe_ipc_group =
            command_presence("/usr/bin/getent", &["group", PROBE_IPC_GROUP], 2, deadline)?;
        if group || user || ipc_group || probe_ipc_group {
            Err(InstallError::ExistingResidue)
        } else {
            Ok(())
        }
    }
    fn create_transaction_identity(
        &mut self,
        transaction_id: &str,
    ) -> Result<ServiceIdentity, InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        create_probe_ipc_group_with_commands(transaction_id, &mut |program, arguments| {
            require_success(program, arguments, InstallError::Account, deadline)
        })
    }
    fn owns_transaction_identity(
        &mut self,
        transaction_id: &str,
        identity: Option<ServiceIdentity>,
    ) -> Result<bool, InstallError> {
        inspect_owned_ipc_group(
            PROBE_IPC_GROUP,
            transaction_id,
            identity,
            self.command_deadline,
        )
    }
    fn remove_transaction_identity(
        &mut self,
        transaction_id: &str,
        identity: Option<ServiceIdentity>,
    ) -> Result<(), InstallError> {
        remove_owned_ipc_group(
            PROBE_IPC_GROUP,
            transaction_id,
            identity,
            self.command_deadline,
        )
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

fn inspect_owned_ipc_group(
    group_name: &str,
    transaction_id: &str,
    identity: Option<ServiceIdentity>,
    deadline: Option<Instant>,
) -> Result<bool, InstallError> {
    if identity != Some(ServiceIdentity { uid: 0, gid: 0 }) {
        return Ok(false);
    }
    let deadline = deadline.unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
    let output = run_bounded(
        "/usr/bin/getent",
        &["gshadow", group_name],
        InstallError::Account,
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
    if output.status.code() == Some(2) {
        return Ok(false);
    }
    let record = String::from_utf8(output.stdout).map_err(|_| InstallError::Account)?;
    let fields = record.trim_end().split(':').collect::<Vec<_>>();
    Ok(fields.len() == 4
        && fields[0] == group_name
        && fields[1] == group_account_marker(transaction_id))
}

fn remove_owned_ipc_group(
    group_name: &str,
    transaction_id: &str,
    identity: Option<ServiceIdentity>,
    deadline: Option<Instant>,
) -> Result<(), InstallError> {
    if !inspect_owned_ipc_group(group_name, transaction_id, identity, deadline)? {
        return Ok(());
    }
    require_success(
        "/usr/sbin/groupdel",
        &[group_name],
        InstallError::Account,
        deadline.unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET),
    )
}

fn account_marker(transaction_id: &str) -> String {
    format!("enoki-bootstrap-{transaction_id}")
}

fn group_account_marker(transaction_id: &str) -> String {
    format!("!{}", account_marker(transaction_id))
}

pub(super) fn create_probe_ipc_group_with_commands(
    transaction_id: &str,
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
) -> Result<ServiceIdentity, InstallError> {
    let marker = group_account_marker(transaction_id);
    execute(
        "/usr/sbin/groupadd",
        &["--system", "--password", &marker, PROBE_IPC_GROUP],
    )?;
    Ok(ServiceIdentity { uid: 0, gid: 0 })
}

#[cfg(test)]
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

#[cfg(test)]
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

/// account 事务仅补偿由成功命令和持久 journal 共同证明归属的身份。
#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

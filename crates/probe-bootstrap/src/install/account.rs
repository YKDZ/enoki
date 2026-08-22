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
        if group || user {
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

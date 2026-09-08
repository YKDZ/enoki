use super::*;

const FIXED_IPC_GROUPS: [&str; 2] = [PROBE_IPC_GROUP, OBSERVATION_IPC_GROUP];

fn is_fixed_ipc_group(group_name: &str) -> bool {
    FIXED_IPC_GROUPS.contains(&group_name)
}

fn production_group_marker(marker: &str) -> bool {
    marker
        .strip_prefix("!enoki-bootstrap-")
        .is_some_and(|transaction| {
            transaction.len() == 32
                && transaction
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}

fn exact_record<'a>(database: &'a str, name: &str) -> Option<Vec<&'a str>> {
    let mut records = database
        .lines()
        .filter(|line| line.split(':').next() == Some(name));
    let record = records.next()?.split(':').collect::<Vec<_>>();
    records.next().is_none().then_some(record)
}

fn has_record(database: &str, name: &str) -> bool {
    database
        .lines()
        .any(|line| line.split(':').next() == Some(name))
}

fn nss_group_matches(record: &str, group_name: &str, gid: u32) -> bool {
    let mut records = record.lines();
    let fields = records
        .next()
        .map(|line| line.split(':').collect::<Vec<_>>());
    records.next().is_none()
        && fields.is_some_and(|fields| {
            fields.len() == 4
                && fields[0] == group_name
                && fields[2].parse::<u32>() == Ok(gid)
                && fields[3].is_empty()
        })
}

/// 仅对两个编译期 IPC group 的本机账户记录施加 Formal130 无害性谓词。
/// NSS 输出须由调用者使用 name 与 observed numeric GID 的 keyed lookup 分别提供。
pub fn fixed_ipc_group_is_harmless_records(
    group_name: &str,
    local_group: &str,
    local_gshadow: &str,
    local_passwd: &str,
    nss_by_name: &str,
    nss_by_gid: &str,
) -> bool {
    if !is_fixed_ipc_group(group_name) {
        return false;
    }
    let Some(group) = exact_record(local_group, group_name) else {
        return false;
    };
    let Some(gshadow) = exact_record(local_gshadow, group_name) else {
        return false;
    };
    if group.len() != 4
        || group[0] != group_name
        || group[1] != "x"
        || !group[3].is_empty()
        || gshadow.len() != 4
        || gshadow[0] != group_name
        || !production_group_marker(gshadow[1])
        || !gshadow[2].is_empty()
        || !gshadow[3].is_empty()
    {
        return false;
    }
    let Ok(gid) = group[2].parse::<u32>() else {
        return false;
    };
    if gid == 0
        || !nss_group_matches(nss_by_name, group_name, gid)
        || !nss_group_matches(nss_by_gid, group_name, gid)
    {
        return false;
    }
    let other_name = FIXED_IPC_GROUPS
        .iter()
        .copied()
        .find(|name| *name != group_name)
        .expect("fixed IPC group has one peer");
    if exact_record(local_group, other_name)
        .is_some_and(|other| other.len() != 4 || other[2].parse::<u32>() == Ok(gid))
    {
        return false;
    }
    local_passwd.lines().all(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        fields.len() == 7
            && !FIXED_IPC_GROUPS.contains(&fields[0])
            && fields[3]
                .parse::<u32>()
                .is_ok_and(|primary_gid| primary_gid != gid)
    })
}

fn read_local_account_file(path: &str) -> Result<String, InstallError> {
    fs::read_to_string(path).map_err(|_| InstallError::Account)
}

fn nss_group_lookup(key: &str, deadline: Instant) -> Result<Option<String>, InstallError> {
    let output = run_bounded(
        "/usr/bin/getent",
        &["group", key],
        InstallError::Account,
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
    match output.status.code() {
        Some(0) => String::from_utf8(output.stdout)
            .map(Some)
            .map_err(|_| InstallError::Account),
        Some(2) => Ok(None),
        _ => Err(InstallError::Account),
    }
}

fn fixed_ipc_group_is_harmless(group_name: &str, deadline: Instant) -> Result<bool, InstallError> {
    let local_group = read_local_account_file("/etc/group")?;
    let local_gshadow = read_local_account_file("/etc/gshadow")?;
    let local_passwd = read_local_account_file("/etc/passwd")?;
    let Some(group) = exact_record(&local_group, group_name) else {
        return Ok(false);
    };
    if group.len() != 4 {
        return Ok(false);
    }
    let Ok(gid) = group[2].parse::<u32>() else {
        return Ok(false);
    };
    let Some(nss_by_name) = nss_group_lookup(group_name, deadline)? else {
        return Ok(false);
    };
    let Some(nss_by_gid) = nss_group_lookup(&gid.to_string(), deadline)? else {
        return Ok(false);
    };
    Ok(fixed_ipc_group_is_harmless_records(
        group_name,
        &local_group,
        &local_gshadow,
        &local_passwd,
        &nss_by_name,
        &nss_by_gid,
    ))
}

fn fixed_ipc_group_is_absent(group_name: &str, deadline: Instant) -> Result<bool, InstallError> {
    let local_group = read_local_account_file("/etc/group")?;
    let local_gshadow = read_local_account_file("/etc/gshadow")?;
    if has_record(&local_group, group_name) || has_record(&local_gshadow, group_name) {
        return Ok(false);
    }
    Ok(nss_group_lookup(group_name, deadline)?.is_none())
}

fn fixed_ipc_group_is_absent_or_harmless(
    group_name: &str,
    deadline: Instant,
) -> Result<bool, InstallError> {
    if fixed_ipc_group_is_absent(group_name, deadline)? {
        return Ok(true);
    }
    fixed_ipc_group_is_harmless(group_name, deadline)
}

fn fixed_ipc_group_is_current_transaction(
    group_name: &str,
    transaction_id: &str,
    deadline: Instant,
) -> Result<bool, InstallError> {
    if !fixed_ipc_group_is_harmless(group_name, deadline)? {
        return Ok(false);
    }
    let gshadow = read_local_account_file("/etc/gshadow")?;
    Ok(exact_record(&gshadow, group_name).is_some_and(|record| {
        record.get(1) == Some(&group_account_marker(transaction_id).as_str())
    }))
}

fn acquire_fixed_ipc_group(
    group_name: &str,
    transaction_id: &str,
    deadline: Instant,
) -> Result<(), InstallError> {
    let marker = group_account_marker(transaction_id);
    if fixed_ipc_group_is_absent(group_name, deadline)? {
        require_success(
            "/usr/sbin/groupadd",
            &["--system", "--password", &marker, group_name],
            InstallError::Account,
            deadline,
        )?;
    } else if fixed_ipc_group_is_harmless(group_name, deadline)? {
        require_success(
            "/usr/sbin/groupmod",
            &["--password", &marker, group_name],
            InstallError::Account,
            deadline,
        )?;
    } else {
        return Err(InstallError::ExistingResidue);
    }
    fixed_ipc_group_is_current_transaction(group_name, transaction_id, deadline)?
        .then_some(())
        .ok_or(InstallError::ExistingResidue)
}
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
        let observation_ipc_group =
            fixed_ipc_group_is_absent_or_harmless(OBSERVATION_IPC_GROUP, deadline)?;
        let probe_ipc_group = fixed_ipc_group_is_absent_or_harmless(PROBE_IPC_GROUP, deadline)?;
        if group || user || !observation_ipc_group || !probe_ipc_group {
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
        acquire_fixed_ipc_group(PROBE_IPC_GROUP, transaction_id, deadline)?;
        Ok(ServiceIdentity { uid: 0, gid: 0 })
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
        acquire_fixed_ipc_group(OBSERVATION_IPC_GROUP, transaction_id, deadline)
    }
    fn owns_observation_ipc_group(&mut self, transaction_id: &str) -> Result<bool, InstallError> {
        inspect_owned_ipc_group(
            OBSERVATION_IPC_GROUP,
            transaction_id,
            None,
            self.command_deadline,
        )
    }
    fn fixed_ipc_group_is_harmless(&mut self, group_name: &str) -> Result<bool, InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        fixed_ipc_group_is_harmless(group_name, deadline)
    }
    fn fixed_ipc_group_is_absent_or_harmless(
        &mut self,
        group_name: &str,
    ) -> Result<bool, InstallError> {
        let deadline = self
            .command_deadline
            .unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
        fixed_ipc_group_is_absent_or_harmless(group_name, deadline)
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
        let Some(record) = classify_gshadow_lookup(output.status.code(), output.stdout)? else {
            return fixed_ipc_group_is_absent_or_harmless(OBSERVATION_IPC_GROUP, deadline)?
                .then_some(())
                .ok_or(InstallError::ExistingResidue);
        };
        let fields = record.trim_end().split(':').collect::<Vec<_>>();
        if fields.len() != 4
            || fields[0] != OBSERVATION_IPC_GROUP
            || fields[1] != group_account_marker(transaction_id)
        {
            if fixed_ipc_group_is_harmless(OBSERVATION_IPC_GROUP, deadline)? {
                return Ok(());
            }
            return Err(InstallError::ExistingResidue);
        }
        match require_success(
            "/usr/sbin/groupdel",
            &[OBSERVATION_IPC_GROUP],
            InstallError::Account,
            deadline,
        ) {
            Ok(()) => Ok(()),
            Err(_) if fixed_ipc_group_is_harmless(OBSERVATION_IPC_GROUP, deadline)? => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn inspect_owned_ipc_group(
    group_name: &str,
    transaction_id: &str,
    identity: Option<ServiceIdentity>,
    deadline: Option<Instant>,
) -> Result<bool, InstallError> {
    if identity.is_some_and(|identity| identity != ServiceIdentity { uid: 0, gid: 0 }) {
        return Ok(false);
    }
    let deadline = deadline.unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
    fixed_ipc_group_is_current_transaction(group_name, transaction_id, deadline)
}

pub(super) fn owned_ipc_group_record_matches(
    group_name: &str,
    transaction_id: &str,
    identity: Option<ServiceIdentity>,
    record: &str,
) -> bool {
    // transaction marker 在 groupadd 前已随 journal 持久化；numeric receipt 只是附加约束，
    // 不能让 groupadd 与 receipt 落盘之间的崩溃窗口失去补偿所有权。
    if identity.is_some_and(|identity| identity != ServiceIdentity { uid: 0, gid: 0 }) {
        return false;
    }
    let fields = record.trim_end().split(':').collect::<Vec<_>>();
    fields.len() == 4
        && fields[0] == group_name
        && fields[1] == group_account_marker(transaction_id)
}

fn remove_owned_ipc_group(
    group_name: &str,
    transaction_id: &str,
    identity: Option<ServiceIdentity>,
    deadline: Option<Instant>,
) -> Result<(), InstallError> {
    let deadline = deadline.unwrap_or_else(|| Instant::now() + COMMAND_STEP_BUDGET);
    let output = run_bounded(
        "/usr/bin/getent",
        &["gshadow", group_name],
        InstallError::Account,
        deadline,
        COMMAND_STEP_BUDGET,
    )?;
    let Some(record) = classify_gshadow_lookup(output.status.code(), output.stdout)? else {
        return if is_fixed_ipc_group(group_name)
            && fixed_ipc_group_is_absent_or_harmless(group_name, deadline)?
        {
            Ok(())
        } else {
            Err(InstallError::ExistingResidue)
        };
    };
    if !owned_ipc_group_record_matches(group_name, transaction_id, identity, &record) {
        return if is_fixed_ipc_group(group_name)
            && fixed_ipc_group_is_harmless(group_name, deadline)?
        {
            Ok(())
        } else {
            Err(InstallError::ExistingResidue)
        };
    }
    match require_success(
        "/usr/sbin/groupdel",
        &[group_name],
        InstallError::Account,
        deadline,
    ) {
        Ok(()) => Ok(()),
        Err(_error)
            if is_fixed_ipc_group(group_name)
                && fixed_ipc_group_is_harmless(group_name, deadline)? =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub(super) fn classify_gshadow_lookup(
    status: Option<i32>,
    stdout: Vec<u8>,
) -> Result<Option<String>, InstallError> {
    match status {
        Some(0) => String::from_utf8(stdout)
            .map(Some)
            .map_err(|_| InstallError::Account),
        Some(2) => Ok(None),
        Some(_) | None => Err(InstallError::Account),
    }
}

#[cfg(test)]
pub(super) fn remove_owned_ipc_group_with_commands(
    group_name: &str,
    transaction_id: &str,
    identity: Option<ServiceIdentity>,
    lookup: &mut impl FnMut(&str) -> Result<Option<String>, InstallError>,
    execute: &mut impl FnMut(&str, &[&str]) -> Result<(), InstallError>,
) -> Result<(), InstallError> {
    let Some(record) = lookup(group_name)? else {
        return Ok(());
    };
    if !owned_ipc_group_record_matches(group_name, transaction_id, identity, &record) {
        return Ok(());
    }
    execute("/usr/sbin/groupdel", &[group_name])
}

fn account_marker(transaction_id: &str) -> String {
    format!("enoki-bootstrap-{transaction_id}")
}

pub(super) fn group_account_marker(transaction_id: &str) -> String {
    format!("!{}", account_marker(transaction_id))
}

#[cfg(test)]
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

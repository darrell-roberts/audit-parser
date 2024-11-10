//! Types for an audit.log
//! <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files#sec-Understanding_Audit_Log_Files>

use std::{collections::HashMap, str::FromStr};

#[derive(Debug)]
pub struct AuditRecord<'a> {
    pub id: &'a str,
    pub data: HashMap<&'a str, &'a str>,
    pub event_type: AuditType,
}

#[derive(Debug, Copy, Clone)]
pub enum AuditType {
    SysCall,
    SockAddr,
    Cwd,
    Path,
    ProcTitle,
    UserAcct,
    CredAcq,
    UserAuth,
    UserCmd,
    UserStart,
    UserEnd,
    Login,
    CredRefr,
    CredDisp,
    DaemonEnd,
}

impl FromStr for AuditType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "SYSCALL" => Self::SysCall,
            "SOCKADDR" => Self::SockAddr,
            "CWD" => Self::Cwd,
            "PATH" => Self::Path,
            "PROCTITLE" => Self::ProcTitle,
            "USER_ACCT" => Self::UserAcct,
            "CRED_ACQ" => Self::CredAcq,
            "USER_AUTH" => Self::UserAuth,
            "USER_CMD" => Self::UserCmd,
            "USER_START" => Self::UserStart,
            "USER_END" => Self::UserEnd,
            "LOGIN" => Self::Login,
            "CRED_REFR" => Self::CredRefr,
            "CRED_DISP" => Self::CredDisp,
            "DAEMON_END" => Self::DaemonEnd,
            s => return Err(format!("Unsupported: {s}")),
        })
    }
}

/*
pub struct SysCallRecord {
    exe: String,
    success: bool,
    ppid: usize,
    pid: usize,
    uid: usize,
    gid: usize,
    comm: String,
    subj: String,
    sys_call: String,
}
*/

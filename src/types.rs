//! Types for an audit.log
//! <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files#sec-Understanding_Audit_Log_Files>
use std::{collections::HashMap, str::FromStr};

/// An audit record from the audit.log.
#[derive(Debug)]
pub struct AuditRecord<'a> {
    /// Unique event id.
    pub id: &'a str,
    /// Event type data.
    pub data: HashMap<&'a str, &'a str>,
    /// Event type.
    pub event_type: AuditType,
}

/// Audit record types.
/// Partial list from <https://access.redhat.com/articles/4409591#audit-record-types-2>
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
    UserAvc,
    Login,
    CredRefr,
    CredDisp,
    DaemonEnd,
    ServiceStart,
    ServiceStop,
    Bpf,
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
            "USER_AVC" => Self::UserAvc,
            "LOGIN" => Self::Login,
            "CRED_REFR" => Self::CredRefr,
            "CRED_DISP" => Self::CredDisp,
            "DAEMON_END" => Self::DaemonEnd,
            "SERVICE_START" => Self::ServiceStart,
            "SERVICE_STOP" => Self::ServiceStop,
            "BPF" => Self::Bpf,
            s => return Err(format!("Unsupported: {s}")),
        })
    }
}

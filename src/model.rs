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
}

impl FromStr for AuditType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "SYSCALL" => Self::SysCall,
            "SOCKADDR" => Self::SockAddr,
            "CWD" => Self::Cwd,
            "PATH" => Self::Path,
            "PROCTITLE" => Self::ProcTitle,
            _ => return Err(()),
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

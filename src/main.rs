use dns_lookup::lookup_addr;
use parse::parse_event;
use std::{cell::RefCell, collections::HashMap, io::stdin, net::IpAddr};
use types::{AuditRecord, AuditType};

mod parse;
mod types;

thread_local! {
    /// Cache of ip -> hostname entries.
    pub static HOSTNAME_MAP: RefCell<HashMap<IpAddr, String>> =
        RefCell::new(HashMap::new());
}

/// If we have a remote ip address attempt to resolve the hostname otherwise
/// return the ip address.
fn resolve_hostname(event: &AuditRecord<'_>) -> Option<String> {
    let ip_str = event.data.get("laddr")?;

    ip_str.parse::<IpAddr>().ok().and_then(|ip| {
        let val = HOSTNAME_MAP.with_borrow(|m| m.get(&ip).map(ToOwned::to_owned));

        val.or_else(|| {
            let hostname = lookup_addr(&ip).ok().unwrap_or_else(|| ip_str.to_string());
            HOSTNAME_MAP.with_borrow_mut(|m| m.insert(ip, hostname.clone()));
            Some(hostname)
        })
    })
}

#[derive(Default)]
struct UserAndExecutable {
    user: String,
    executable: String,
}

fn main() -> anyhow::Result<()> {
    let buffer = stdin();

    let mut user_exec_map: HashMap<String, UserAndExecutable> = HashMap::new();

    for line in buffer.lines() {
        let line = line?;
        let event = parse_event(&line);

        match event {
            Ok(event) => match event.event_type {
                AuditType::SysCall => {
                    let user_and_exec = user_exec_map.entry(event.id.to_string()).or_default();
                    if let Some(exe) = event.data.get("exe") {
                        user_and_exec.executable = exe.to_string();
                    }
                    if let Some(uid) = event.data.get("UID") {
                        user_and_exec.user = uid.to_string();
                    }
                }
                AuditType::SockAddr => {
                    let Some(user_and_exec) = user_exec_map.remove(event.id) else {
                        continue;
                    };

                    // Skip showing DNS lookups from ourself.
                    if user_and_exec.executable.contains("audit-parser") {
                        continue;
                    }

                    if let Some(hostname) = resolve_hostname(&event) {
                        let port = event.data.get("lport").unwrap_or(&"none");
                        println!(
                            "{} {} {} {hostname} port {port}",
                            event.formatted_time()?,
                            user_and_exec.user,
                            user_and_exec.executable,
                        );
                    } else if let Some(path) = event.data.get("path") {
                        println!(
                            "{} {} {} {path}",
                            event.formatted_time()?,
                            user_and_exec.user,
                            user_and_exec.executable
                        );
                    } else {
                        println!(
                            "{} {} {} {:?}",
                            event.formatted_time()?,
                            user_and_exec.user,
                            user_and_exec.executable,
                            event.data,
                        );
                    }
                }
                _ => {
                    if let Some(user_and_exec) = user_exec_map.remove(event.id) {
                        println!(
                            "{} {} {} {:?} {:?}",
                            event.formatted_time()?,
                            user_and_exec.user,
                            user_and_exec.executable,
                            event.event_type,
                            event.data
                        );
                    }
                }
            },
            Err(err) => {
                eprintln!("Failed to parse: {err}, record: {line}");
            }
        }
    }

    Ok(())
}

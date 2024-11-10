use anyhow::Context;
use dns_lookup::lookup_addr;
use jiff::fmt::strtime;
use parse::parse_event;
use std::{
    cell::{LazyCell, RefCell},
    collections::HashMap,
    env,
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
};
use types::{AuditRecord, AuditType};

mod parse;
mod types;

/// Cache of ip -> hostname entries.
const HOSTNAME_MAP: LazyCell<RefCell<HashMap<IpAddr, String>>> =
    LazyCell::new(|| RefCell::new(HashMap::new()));

/// If we have a remote ip address attempt to resolve the hostname otherwise
/// return the ip address.
fn resolve_hostname(event: &AuditRecord<'_>) -> Option<String> {
    let ip_str = event.data.get("laddr")?;

    ip_str.parse::<IpAddr>().ok().and_then(|ip| {
        HOSTNAME_MAP
            .borrow()
            .get(&ip)
            .map(ToOwned::to_owned)
            .or_else(|| {
                let hostname = lookup_addr(&ip).ok().unwrap_or_else(|| ip_str.to_string());
                HOSTNAME_MAP.borrow_mut().insert(ip, hostname.clone());
                Some(hostname)
            })
    })
}

fn main() -> anyhow::Result<()> {
    let input_file = env::args().nth(1).context("missing file argument")?;
    let buffer = BufReader::new(File::open(input_file)?);

    let mut exe_map = HashMap::new();
    let mut uid_map = HashMap::new();

    let mut total_syscall_connect = 0;
    let mut total_captured_connects = 0;

    for (line, line_num) in buffer.lines().zip(1..) {
        let line = line?;
        let event = parse_event(&line);

        match event {
            Ok(event) => match event.event_type {
                AuditType::SysCall => {
                    if let Some(&syscall) = event.data.get("SYSCALL") {
                        if syscall == "connect" {
                            total_syscall_connect += 1;
                        }
                    }
                    if let Some(exe) = event.data.get("exe") {
                        exe_map.insert(event.id.to_string(), exe.to_string());
                    }
                    if let Some(uid) = event.data.get("UID") {
                        uid_map.insert(event.id.to_string(), uid.to_string());
                    }
                }
                AuditType::SockAddr => {
                    let exe = exe_map.remove(event.id).unwrap_or_default();
                    let uid = uid_map.remove(event.id).unwrap_or_default();

                    if let Some(hostname) = resolve_hostname(&event) {
                        let port = event.data.get("lport").unwrap_or(&"none");
                        total_captured_connects += 1;
                        println!(
                            "{} {uid} {exe} {hostname} port {port}",
                            strtime::format("%a %-d %b %Y %T", event.time)?
                        );
                    }

                    if let Some(path) = event.data.get("path") {
                        total_captured_connects += 1;
                        println!(
                            "{} {uid} {exe} {path}",
                            strtime::format("%a %-d %b %Y %T", event.time)?
                        );
                    }
                }
                _ => (),
            },
            Err(err) => {
                println!("failed to parse {line_num}: {err}");
            }
        }
    }

    println!();
    println!("Total syscall connect {total_syscall_connect} / parsed {total_captured_connects}");

    Ok(())
}

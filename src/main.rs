use anyhow::Context;
use dns_lookup::lookup_addr;
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

const HOSTNAME_MAP: LazyCell<RefCell<HashMap<IpAddr, String>>> =
    LazyCell::new(|| RefCell::new(HashMap::new()));

fn resolve_hostname(event: &AuditRecord<'_>) -> Option<String> {
    event
        .data
        .get("laddr")
        .and_then(|s| s.parse::<IpAddr>().ok())
        .and_then(|ip| {
            HOSTNAME_MAP
                .borrow()
                .get(&ip)
                .map(ToOwned::to_owned)
                .or_else(|| {
                    let hostname = lookup_addr(&ip)
                        .ok()
                        .or_else(|| event.data.get("laddr").map(ToString::to_string));
                    if let Some(host) = hostname.as_ref() {
                        HOSTNAME_MAP.borrow_mut().insert(ip, host.to_owned());
                    }
                    hostname
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
                        println!("{uid} {exe} opened remote {hostname} port {port}");
                    }

                    if let Some(path) = event.data.get("path") {
                        total_captured_connects += 1;
                        println!("{uid} {exe} opened socket {path}");
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

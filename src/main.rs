use anyhow::Context;
use dns_lookup::lookup_addr;
use model::{AuditRecord, AuditType};
use parse::parse_event;
use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
};

mod model;
mod parse;

fn resolve_hostname(event: &AuditRecord<'_>) -> Option<String> {
    event
        .data
        .get("laddr")
        .and_then(|s| s.parse::<IpAddr>().ok())
        .and_then(|ip| lookup_addr(&ip).ok())
        .or_else(|| event.data.get("laddr").map(ToString::to_string))
}

fn main() -> anyhow::Result<()> {
    let input_file = env::args().nth(1).context("missing file argument")?;
    let buffer = BufReader::new(File::open(input_file)?);

    let mut exe_map = HashMap::new();

    for line in buffer.lines() {
        let line = line?;
        let event = parse_event(&line);

        match event {
            Ok(event) => match event.event_type {
                AuditType::SysCall => {
                    if let Some(exe) = event.data.get("exe") {
                        exe_map.insert(event.id.to_string(), exe.to_string());
                    }
                }
                AuditType::SockAddr => {
                    if let Some(hostname) = resolve_hostname(&event) {
                        let exe = exe_map.remove(event.id).unwrap_or_default();
                        let port = event.data.get("lport").unwrap_or(&"none");

                        println!("{exe} accessed {hostname} port {port}");
                    }
                }
                _ => (),
            },
            Err(_err) => {
                // println!("failed to parse line {index}: {err}");
            }
        }
    }

    Ok(())
}

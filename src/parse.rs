//! Parses a single audit record into an [`AuditRecord`].
//!
//! Combinators for parsing audit records.
use crate::types::{AuditRecord, AuditType};
use anyhow::anyhow;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_till},
    character::complete::{char, digit1, space1},
    combinator::{map_parser, map_res, peek, rest},
    multi::separated_list1,
    sequence::{delimited, separated_pair, tuple},
    IResult,
};
use std::{char, collections::HashMap};

/// <https://github.com/linux-audit/audit-documentation/wiki/SPEC-Audit-Event-Enrichment>
const ENRICHED_SEPARATOR: char = '\u{1d}';

fn parse_type(input: &str) -> IResult<&str, AuditType> {
    map_res(
        delimited(tag("type="), take_till(|c| c == ' '), space1),
        |s: &str| s.parse(),
    )(input)
}

fn parse_time(input: &str) -> IResult<&str, jiff::Timestamp> {
    let (_rest, unix_time) = take_till(|c| c == ':')(input)?;
    let parser = separated_pair(
        map_res(digit1, |s: &str| s.parse::<i64>()),
        char('.'),
        map_res(digit1, |s: &str| s.parse::<i32>()),
    );
    map_res(parser, |(seconds, nano)| {
        jiff::Timestamp::new(seconds, nano)
    })(unix_time)
}

fn parse_event_id(input: &str) -> IResult<&str, (jiff::Timestamp, &str)> {
    // peek into the portion that has the timestamp and then take the full
    // id.
    let parse = tuple((peek(parse_time), take_till(|c| c == ')')));
    delimited(tag("msg=audit("), parse, tag("): "))(input)
}

fn quoted_value(input: &str) -> IResult<&str, &str> {
    delimited(char('"'), take_till(|c| c == '"'), char('"'))(input)
}

fn parse_nvp(input: &str) -> IResult<&str, (&str, &str)> {
    let value_parser = take_till(|c| c == ' ' || c == ENRICHED_SEPARATOR);
    separated_pair(
        take_till(|c| c == '='),
        tag("="),
        map_parser(value_parser, alt((quoted_value, rest))),
    )(input)
}

fn parse_nvps(input: &str) -> IResult<&str, Vec<(&str, &str)>> {
    let separator = alt((char(' '), char(ENRICHED_SEPARATOR)));
    separated_list1(separator, parse_nvp)(input)
}

fn parse_socket_address(input: &str) -> IResult<&str, Vec<(&str, &str)>> {
    let (input, _ignore) = take_till(|c| c == '{')(input)?;
    delimited(tag("{ "), parse_nvps, tag(" }"))(input)
}

/// Parse a single audit record line into an [`AuditRecord`] type.
pub fn parse_event(input: &str) -> anyhow::Result<AuditRecord<'_>> {
    let err_fn = |e| anyhow!("Failed to parse event {}", e);
    let (rest, (event_type, (time, id))) =
        tuple((parse_type, parse_event_id))(input).map_err(err_fn)?;

    let (_rest, nvps) = if matches!(event_type, AuditType::SockAddr) {
        alt((parse_socket_address, parse_nvps))(rest).map_err(err_fn)?
    } else {
        parse_nvps(rest).map_err(err_fn)?
    };

    Ok(AuditRecord {
        id,
        time,
        event_type,
        data: HashMap::from_iter(nvps),
    })
}

#[cfg(test)]
mod test {
    use super::{parse_event, parse_time};

    const EVENT_SYSCALL: &str = r#"type=SYSCALL msg=audit(1731248208.117:6983): arch=c000003e syscall=42 success=yes exit=0 a0=b a1=7ffda809ac90 a2=10 a3=7ffda809ac34 items=0 ppid=1 pid=2405 auid=4294967295 uid=101 gid=103 euid=101 suid=101 fsuid=101 egid=103 sgid=103 fsgid=103 tty=(none) ses=4294967295 comm="systemd-resolve" exe="/usr/lib/systemd/systemd-resolved" subj=unconfined key="network_connect"ARCH=x86_64 SYSCALL=connect AUID="unset" UID="systemd-resolve" GID="systemd-resolve" EUID="systemd-resolve" SUID="systemd-resolve" FSUID="systemd-resolve" EGID="systemd-resolve" SGID="systemd-resolve" FSGID="systemd-resolve""#;

    const EVENT_SOCKADDR: &str = r#"type=SOCKADDR msg=audit(1731248208.117:6983): saddr=02000035646464640000000000000000SADDR={ saddr_fam=inet laddr=100.100.100.100 lport=53 }"#;

    #[test]
    fn test_parse_syscall_enhanced() {
        let record = parse_event(EVENT_SYSCALL).unwrap();
        assert_eq!(record.data.get("key"), Some(&"network_connect"));
        assert_eq!(record.data.get("ARCH"), Some(&"x86_64"));
        assert_eq!(
            record.data.get("exe"),
            Some(&"/usr/lib/systemd/systemd-resolved")
        );
        assert_eq!(record.data.get("SYSCALL"), Some(&"connect"));
    }

    #[test]
    fn test_parse_sockaddr_enhanced() {
        let record = parse_event(EVENT_SOCKADDR).unwrap();
        assert_eq!(record.data.get("laddr"), Some(&"100.100.100.100"));
        assert_eq!(record.data.get("lport"), Some(&"53"));
    }

    #[test]
    fn test_parse_time() {
        let test = "1731248210.306:7020";

        let (_rest, _result) = parse_time(test).unwrap();
    }
}

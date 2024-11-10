use crate::types::{AuditRecord, AuditType};
use anyhow::anyhow;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_till},
    character::complete::{char, space1},
    combinator::map_res,
    multi::separated_list1,
    sequence::{delimited, separated_pair, tuple},
    IResult,
};
use std::collections::HashMap;

fn parse_type(input: &str) -> IResult<&str, AuditType> {
    map_res(
        delimited(tag("type="), take_till(|c| c == ' '), space1),
        |s: &str| s.parse(),
    )(input)
}

fn parse_event_id(input: &str) -> IResult<&str, &str> {
    delimited(tag("msg=audit("), take_till(|c| c == ')'), tag("): "))(input)
}

fn parse_nvp(input: &str) -> IResult<&str, (&str, &str)> {
    separated_pair(take_till(|c| c == '='), tag("="), take_till(|c| c == ' '))(input)
}

fn parse_nvps(input: &str) -> IResult<&str, Vec<(&str, &str)>> {
    separated_list1(char(' '), parse_nvp)(input)
}

fn parse_socket_address(input: &str) -> IResult<&str, Vec<(&str, &str)>> {
    let (input, _ignore) = take_till(|c| c == '{')(input)?;
    delimited(tag("{ "), parse_nvps, tag(" }"))(input)
}

pub fn parse_event(input: &str) -> anyhow::Result<AuditRecord<'_>> {
    let err_fn = |e| anyhow!("Failed to parse event {}", e);
    let (rest, (event_type, id)) = tuple((parse_type, parse_event_id))(input).map_err(err_fn)?;

    let (_rest, nvps) = if matches!(event_type, AuditType::SockAddr) {
        alt((parse_socket_address, parse_nvps))(rest).map_err(err_fn)?
    } else {
        parse_nvps(rest).map_err(err_fn)?
    };

    Ok(AuditRecord {
        event_type,
        id,
        data: HashMap::from_iter(nvps),
    })
}

#[cfg(test)]
mod test {
    use super::{parse_event, parse_event_id, parse_nvps, parse_type};
    use crate::types::AuditType;
    use std::collections::HashMap;

    const EVENT_TEST_RECORD_1: &str = r#"type=SYSCALL msg=audit(1731175222.372:613194): arch=c000003e syscall=42 success=yes exit=0 a0=b a1=7ffef808d350 a2=10 a3=7ffef808d2f4 items=0 ppid=1 pid=3120 auid=4294967295 uid=101 gid=103 euid=101 suid=101 fsuid=101 egid=103 sgid=103 fsgid=103 tty=(none) ses=4294967295 comm="systemd-resolve" exe="/usr/lib/systemd/systemd-resolved" subj=unconfined key="network_connect"ARCH=x86_64 SYSCALL=connect AUID="unset" UID="systemd-resolve" GID="systemd-resolve" EUID="systemd-resolve" SUID="systemd-resolve" FSUID="systemd-resolve" EGID="systemd-resolve" SGID="systemd-resolve" FSGID="systemd-resolve""#;

    const EVENT_TEST_RECORD_2: &str = r#"type=SOCKADDR msg=audit(1731192912.282:624499): saddr=0A0001BB000000002A044E4200000000000000000000064900000000SADDR={ saddr_fam=inet6 laddr=2a04:4e42::649 lport=443 }"#;

    #[test]
    fn parse_record_test() {
        let (rest, result) = parse_type(EVENT_TEST_RECORD_1).unwrap();
        assert!(matches!(result, AuditType::SysCall));
        let (rest, result) = parse_event_id(rest).unwrap();
        assert_eq!(result, "1731175222.372:613194");
        let (_rest, nvps) = parse_nvps(rest).unwrap();
        let data: HashMap<&str, &str> = HashMap::from_iter(nvps);
        let exe = data.get("exe").unwrap();
        assert_eq!(*exe, r#""/usr/lib/systemd/systemd-resolved""#);
    }

    #[test]
    fn parse_socket_record_test() {
        let result = parse_event(EVENT_TEST_RECORD_2).unwrap();
        let ip = result.data.get("laddr").unwrap();
        assert_eq!(*ip, "2a04:4e42::649");
    }
}

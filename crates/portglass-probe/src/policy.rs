//! Destination policy. Deny by default; the probe enforces this for every session regardless of
//! what the controller's UI showed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;
use portglass_proto::{AllowRuleSummary, ErrorCode, TargetSpec};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortSet(Vec<(u16, u16)>);

impl PortSet {
    pub fn add(&mut self, lo: u16, hi: u16) {
        self.0.push((lo, hi));
    }
    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|(lo, hi)| (*lo..=*hi).contains(&port))
    }
    pub fn describe(&self) -> String {
        self.0
            .iter()
            .map(|(lo, hi)| {
                if lo == hi {
                    lo.to_string()
                } else {
                    format!("{lo}-{hi}")
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRule {
    pub network: IpNet,
    pub ports: PortSet,
    pub label: Option<String>,
}

impl AllowRule {
    pub fn summary(&self) -> AllowRuleSummary {
        AllowRuleSummary {
            network: self.network.to_string(),
            ports: self.ports.describe(),
            label: self.label.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Denial {
    pub code: ErrorCode,
    pub message: String,
}

impl Denial {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Denial {
            code,
            message: message.into(),
        }
    }
}

/// Addresses that are never valid destinations, whatever the allowlist says.
fn never_allowed(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() || v4.octets()[0] == 0 {
                Some("an unspecified/\"this network\" address")
            } else if v4.is_broadcast() {
                Some("a broadcast address")
            } else if v4.is_multicast() {
                Some("a multicast address")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                Some("an unspecified address")
            } else if v6.is_multicast() {
                Some("a multicast address")
            } else {
                None
            }
        }
    }
}

/// Loopback and link-local (which includes cloud metadata at 169.254.169.254) are reachable only
/// through a rule written specifically for them, never through a broad rule like 0.0.0.0/0.
fn special_range(ip: IpAddr) -> Option<IpNet> {
    let v4 = |a, b, c, d, p| IpNet::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), p).unwrap();
    let v6 = |s: &str, p| IpNet::new(IpAddr::V6(s.parse::<Ipv6Addr>().unwrap()), p).unwrap();
    [
        v4(127, 0, 0, 0, 8),
        v4(169, 254, 0, 0, 16),
        v6("::1", 128),
        v6("fe80::", 10),
    ]
    .into_iter()
    .find(|n| n.contains(&ip))
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Is `ip:port` allowed? Returns the matching rule.
pub fn check(rules: &[AllowRule], ip: IpAddr, port: u16) -> Result<&AllowRule, Denial> {
    let ip = canonical(ip);
    if port == 0 {
        return Err(Denial::new(
            ErrorCode::InvalidRequest,
            "port 0 is not valid",
        ));
    }
    if let Some(why) = never_allowed(ip) {
        return Err(Denial::new(
            ErrorCode::UnauthorizedTarget,
            format!("{ip} is {why} and can never be a destination"),
        ));
    }
    let special = special_range(ip);
    let mut network_matched = false;
    for rule in rules {
        if !rule.network.contains(&ip) {
            continue;
        }
        if let Some(range) = special {
            if !range.contains(&rule.network) {
                continue;
            }
        }
        network_matched = true;
        if rule.ports.contains(port) {
            return Ok(rule);
        }
    }
    let message = if network_matched {
        format!("port {port} on {ip} is not in this probe's allowlist")
    } else if special.is_some() {
        format!("{ip} is a loopback/link-local address; the probe allows it only through a rule written for that range")
    } else {
        format!("{ip} is not in this probe's allowlist")
    };
    Err(Denial::new(ErrorCode::UnauthorizedTarget, message))
}

fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Resolve and authorize a requested target. The returned address is pinned for the session so
/// later DNS answers cannot move it somewhere the policy did not approve.
pub async fn authorize(
    rules: &[AllowRule],
    target: &TargetSpec,
    dns_timeout: Duration,
) -> Result<(SocketAddr, Option<String>), Denial> {
    let host = target
        .host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        let rule = check(rules, ip, target.port)?;
        return Ok((
            SocketAddr::new(canonical(ip), target.port),
            rule.label.clone(),
        ));
    }
    if !valid_hostname(host) {
        return Err(Denial::new(
            ErrorCode::InvalidRequest,
            format!("{:?} is not a valid IP address or host name", target.host),
        ));
    }
    let lookup = tokio::time::timeout(
        dns_timeout,
        tokio::net::lookup_host((host.to_string(), target.port)),
    )
    .await;
    let addrs: Vec<SocketAddr> = match lookup {
        Ok(Ok(it)) => it.collect(),
        Ok(Err(e)) => {
            return Err(Denial::new(
                ErrorCode::DnsFailed,
                format!("the probe could not resolve {host}: {e}"),
            ))
        }
        Err(_) => {
            return Err(Denial::new(
                ErrorCode::DnsFailed,
                format!("resolving {host} timed out on the probe"),
            ))
        }
    };
    if addrs.is_empty() {
        return Err(Denial::new(
            ErrorCode::DnsFailed,
            format!("{host} has no addresses"),
        ));
    }
    // Every address the name resolves to must be allowed: a name that resolves into both an
    // allowed and a disallowed network is ambiguous, and ambiguity is denied.
    let mut chosen = None;
    for addr in &addrs {
        match check(rules, addr.ip(), target.port) {
            Ok(rule) => {
                if chosen.is_none() {
                    chosen = Some((*addr, rule.label.clone()));
                }
            }
            Err(d) => {
                return Err(Denial::new(
                    ErrorCode::UnauthorizedTarget,
                    format!("{host} resolves to {}: {}", addr.ip(), d.message),
                ))
            }
        }
    }
    let (addr, label) = chosen.expect("non-empty and all allowed");
    Ok((SocketAddr::new(canonical(addr.ip()), addr.port()), label))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(net: &str, ports: &[(u16, u16)]) -> AllowRule {
        let mut set = PortSet::default();
        for (a, b) in ports {
            set.add(*a, *b);
        }
        AllowRule {
            network: net.parse().unwrap(),
            ports: set,
            label: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn deny_by_default() {
        assert!(check(&[], ip("192.168.1.50"), 80).is_err());
    }

    #[test]
    fn network_and_port_must_both_match() {
        let rules = [rule("192.168.1.0/24", &[(80, 80), (8000, 8100)])];
        assert!(check(&rules, ip("192.168.1.50"), 80).is_ok());
        assert!(check(&rules, ip("192.168.1.50"), 8050).is_ok());
        assert!(check(&rules, ip("192.168.1.50"), 22).is_err());
        assert!(check(&rules, ip("192.168.2.50"), 80).is_err());
    }

    #[test]
    fn broad_rules_never_open_loopback_or_metadata() {
        let rules = [
            rule("0.0.0.0/0", &[(1, 65535)]),
            rule("::/0", &[(1, 65535)]),
        ];
        for bad in [
            "127.0.0.1",
            "169.254.169.254",
            "::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(check(&rules, ip(bad), 80).is_err(), "{bad}");
        }
        assert!(check(&rules, ip("10.0.0.1"), 80).is_ok());
    }

    #[test]
    fn explicit_loopback_rule_is_honoured() {
        let rules = [rule("127.0.0.1/32", &[(8080, 8080)])];
        assert!(check(&rules, ip("127.0.0.1"), 8080).is_ok());
        assert!(check(&rules, ip("127.0.0.1"), 8081).is_err());
    }

    #[test]
    fn never_allowed_addresses_stay_denied() {
        let rules = [rule("0.0.0.0/0", &[(1, 65535)])];
        for bad in ["0.0.0.0", "255.255.255.255", "224.0.0.1"] {
            assert!(check(&rules, ip(bad), 80).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn hostnames_are_validated_and_resolved_into_policy() {
        let rules = [rule("127.0.0.1/32", &[(80, 80)])];
        let t = |h: &str| TargetSpec {
            host: h.into(),
            port: 80,
        };
        assert!(authorize(&rules, &t("bad host;rm"), Duration::from_secs(2))
            .await
            .is_err());
        let (addr, _) = authorize(&rules, &t("127.0.0.1"), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(addr, "127.0.0.1:80".parse().unwrap());
    }
}

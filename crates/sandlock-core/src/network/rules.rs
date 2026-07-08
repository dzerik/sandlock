// Network policy rules: `--net-allow` / `--net-deny` parsing, DNS
// resolution to the runtime allow/deny sets, and the virtual /etc/hosts
// composition. No syscall handling lives here; the handlers consume the
// resolved sets through `SupervisorCtx`.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::SandboxError;

/// An IPv4 or IPv6 address with a prefix length, used by `--net-deny`
/// to match destination IPs by exact address (`/32`, `/128`) or by range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpCidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl IpCidr {
    /// Parse `addr` or `addr/prefix`. A bare address becomes a host route
    /// (`/32` for IPv4, `/128` for IPv6). Hostnames are rejected: the
    /// address part must parse as a literal IP.
    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        let (addr_str, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let len: u8 = p.parse().map_err(|_| {
                    SandboxError::Invalid(format!("invalid prefix length in `{}`", s))
                })?;
                (a, Some(len))
            }
            None => (s, None),
        };
        let addr: IpAddr = addr_str.parse().map_err(|_| {
            SandboxError::Invalid(format!("`{}` is not a valid IP address", s))
        })?;
        let max = match addr {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        let prefix_len = prefix.unwrap_or(max);
        if prefix_len > max {
            return Err(SandboxError::Invalid(format!(
                "prefix /{} too large for {} in `{}`",
                prefix_len,
                if max == 32 { "IPv4" } else { "IPv6" },
                s
            )));
        }
        Ok(IpCidr { addr, prefix_len })
    }

    /// True iff this CIDR is a single host (`/32` IPv4 or `/128` IPv6),
    /// i.e. it came from a bare IP literal rather than a range.
    pub fn is_single_host(&self) -> bool {
        match self.addr {
            IpAddr::V4(_) => self.prefix_len == 32,
            IpAddr::V6(_) => self.prefix_len == 128,
        }
    }

    /// True iff `ip` falls within this network. Different address
    /// families never match.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix_len);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix_len);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpCidr {
    /// A single host renders as the bare address (`1.2.3.4`, `::1`); a
    /// range keeps its prefix (`10.0.0.0/8`). Inverse of [`IpCidr::parse`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_single_host() {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix_len)
        }
    }
}

/// What a `--net-allow` / `--net-deny` rule targets at the IP layer.
///
/// `Cidr` covers both a bare IP literal (stored as a `/32` or `/128`) and
/// an explicit CIDR range. `Host` is a hostname resolved via DNS at sandbox
/// start; it is only produced for `--net-allow` (deny rejects hostnames).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetTarget {
    /// Any destination IP (the `:port` / `*:port` / `*` form).
    AnyIp,
    /// A literal IP or CIDR range. Matched by containment, no DNS.
    Cidr(IpCidr),
    /// A hostname, resolved to IPs at sandbox start (allow-only).
    Host(String),
}

/// A single `--net-allow` / `--net-deny` rule. Both flags share this
/// representation and the same grammar; they differ only in whether
/// hostnames are accepted (`--net-deny` rejects them) and in how the
/// resolved rule is enforced (allowlist vs denylist).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetRule {
    /// L4 protocol this rule applies to.
    #[serde(default = "default_protocol_tcp")]
    pub protocol: Protocol,
    /// What the rule targets at the IP layer.
    pub target: NetTarget,
    /// Permitted/denied ports. Empty when `all_ports` is true and always
    /// empty for `Protocol::Icmp`.
    pub ports: Vec<u16>,
    /// "Any port" (bare target with no `:port`, or the `*` port token).
    #[serde(default)]
    pub all_ports: bool,
}

/// `--net-allow` and `--net-deny` rules are the same shape; the aliases
/// document intent at call sites and field declarations.
pub type NetAllow = NetRule;
pub type NetDeny = NetRule;

fn default_protocol_tcp() -> Protocol {
    Protocol::Tcp
}

impl NetRule {
    /// Parse a `--net-allow` spec into a rule. Hostnames are accepted and
    /// resolved to IPs at sandbox start. Grammar (shared with `--net-deny`):
    ///
    /// - `host` / `<ip>` / `<cidr>` / `*` -- all ports (port optional; `*`
    ///   targets any IP). TCP is the default scheme.
    /// - `host:<port[,port,...]>` / `<ip>:<port>` / `<cidr>:*` / `:port`.
    /// - `[<ipv6|ipv6cidr>]:<port>` -- bracketed IPv6 with a port (a bare
    ///   `addr:port` string is itself a valid IPv6 address, so the port
    ///   form needs brackets).
    /// - `tcp://...` / `udp://...` / `icmp://...` schemes (icmp: no port).
    pub fn parse_allow(spec: &str) -> Result<NetRule, SandboxError> {
        Self::parse_spec(spec, "--net-allow", true)
    }

    /// Parse a `--net-deny` spec into a rule. Identical grammar to
    /// [`parse_allow`](Self::parse_allow), except hostnames are rejected
    /// (the target must be a literal IP/CIDR or `*`); use `--http-deny`
    /// for domain blocking.
    pub fn parse_deny(spec: &str) -> Result<NetDeny, SandboxError> {
        Self::parse_spec(spec, "--net-deny", false)
    }

    /// Shared grammar for both flags. `label` selects the error prefix and
    /// `allow_hosts` whether non-IP targets are accepted (allow) or
    /// rejected (deny).
    fn parse_spec(spec: &str, label: &str, allow_hosts: bool) -> Result<NetRule, SandboxError> {
        let (protocol, rest) = match spec.split_once("://") {
            Some((scheme, body)) => {
                let proto = Protocol::parse(scheme).ok_or_else(|| {
                    SandboxError::Invalid(format!(
                        "{}: unknown scheme `{}://` in `{}` (expected tcp, udp, icmp)",
                        label, scheme, spec
                    ))
                })?;
                (proto, body)
            }
            None => (Protocol::Tcp, spec),
        };

        // ICMP carries no port: the whole body is the target.
        if protocol == Protocol::Icmp {
            if rest.is_empty() {
                return Err(SandboxError::Invalid(format!(
                    "{}: icmp rule needs a host/IP or `*`, got `{}`",
                    label, spec
                )));
            }
            // Reject an explicit port. IPv6 literals/CIDRs also contain
            // `:`, so only flag a `:` that isn't part of a valid IP/CIDR.
            if rest != "*" && IpCidr::parse(rest).is_err() && rest.contains(':') {
                return Err(SandboxError::Invalid(format!(
                    "{}: icmp rule takes no port, got `{}`",
                    label, spec
                )));
            }
            return Ok(NetRule {
                protocol,
                target: parse_target(rest, label, allow_hosts)?,
                ports: Vec::new(),
                all_ports: true,
            });
        }

        // 1. Bracketed IPv6 with a port: `[addr]:ports`.
        if let Some(stripped) = rest.strip_prefix('[') {
            let (inside, port_part) = stripped.rsplit_once("]:").ok_or_else(|| {
                SandboxError::Invalid(format!("{}: malformed bracketed address in `{}`", label, spec))
            })?;
            let (ports, all_ports) = parse_ports(port_part, label, spec)?;
            return Ok(NetRule {
                protocol,
                target: NetTarget::Cidr(IpCidr::parse(inside)?),
                ports,
                all_ports,
            });
        }

        // An empty body must not silently mean "everything"; require an
        // explicit `*` for the any-IP target.
        if rest.is_empty() {
            return Err(SandboxError::Invalid(format!(
                "{}: empty rule in `{}` (use `*` for any host)",
                label, spec
            )));
        }

        // 2. Whole body is an IP/CIDR with no port -> all ports. Trying
        //    `IpCidr::parse` first is what makes bare IPv6 (`::1`) and IPv6
        //    CIDRs (`fc00::/7`) work despite containing colons.
        if let Ok(cidr) = IpCidr::parse(rest) {
            return Ok(NetRule {
                protocol,
                target: NetTarget::Cidr(cidr),
                ports: Vec::new(),
                all_ports: true,
            });
        }

        // 3. `target[:ports]` where target is an IP/CIDR, hostname, `*`, or
        //    empty. The port suffix is optional: a target with no `:port`
        //    covers all ports, mirroring the bare-target form above.
        let (host_part, port_part) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        let target = parse_target(host_part, label, allow_hosts)?;
        let (ports, all_ports) = match port_part {
            Some(p) => parse_ports(p, label, spec)?,
            None => (Vec::new(), true),
        };
        Ok(NetRule {
            protocol,
            target,
            ports,
            all_ports,
        })
    }
}

/// Parse a rule target: `*` / empty -> any IP, an IP/CIDR literal ->
/// `Cidr`, otherwise a hostname (`Host`) when `allow_hosts`, else an error.
fn parse_target(s: &str, label: &str, allow_hosts: bool) -> Result<NetTarget, SandboxError> {
    match s {
        "" | "*" => Ok(NetTarget::AnyIp),
        // A `/` signals CIDR intent: parse strictly so a bad prefix is a
        // clear error rather than being misread as a hostname.
        _ if s.contains('/') => Ok(NetTarget::Cidr(
            IpCidr::parse(s).map_err(|e| SandboxError::Invalid(format!("{}: {}", label, e)))?,
        )),
        _ => {
            if let Ok(cidr) = IpCidr::parse(s) {
                Ok(NetTarget::Cidr(cidr))
            } else if allow_hosts {
                Ok(NetTarget::Host(s.to_string()))
            } else {
                Err(SandboxError::Invalid(format!(
                    "{}: `{}` is not an IP or CIDR (hostnames are not allowed; \
                     use --http-deny for domains)",
                    label, s
                )))
            }
        }
    }
}

/// Parse a port suffix. `*` means all ports; mixing `*` with concrete
/// ports, port 0, and an empty list are all rejected.
fn parse_ports(s: &str, label: &str, full: &str) -> Result<(Vec<u16>, bool), SandboxError> {
    let mut ports = Vec::new();
    let mut saw_wildcard = false;
    for p in s.split(',') {
        let p = p.trim();
        if p == "*" {
            saw_wildcard = true;
            continue;
        }
        let n: u16 = p.parse().map_err(|_| {
            SandboxError::Invalid(format!("{}: invalid port `{}` in `{}`", label, p, full))
        })?;
        if n == 0 {
            return Err(SandboxError::Invalid(format!(
                "{}: port 0 is not valid in `{}`",
                label, full
            )));
        }
        ports.push(n);
    }
    if saw_wildcard && !ports.is_empty() {
        return Err(SandboxError::Invalid(format!(
            "{}: cannot mix `*` with concrete ports in `{}`",
            label, full
        )));
    }
    if !saw_wildcard && ports.is_empty() {
        return Err(SandboxError::Invalid(format!(
            "{}: at least one port required in `{}`",
            label, full
        )));
    }
    Ok((ports, saw_wildcard))
}

/// L4 protocol that a `NetAllow` rule applies to.
///
/// `Tcp` is the default if a rule has no scheme (the bare `host:port`
/// form). `Udp` and `Icmp` require an explicit scheme.
///
/// `Icmp` is the kernel's unprivileged ping socket
/// (`SOCK_DGRAM + IPPROTO_ICMP{,V6}`), gated by `ping_group_range` —
/// destinations are filterable per host. Sandlock does not expose raw
/// ICMP (`SOCK_RAW + IPPROTO_ICMP`): destination filtering at `sendto`
/// would lie because raw sockets let the agent craft the IP header,
/// and packet-crafting capabilities aren't part of the XOA threat
/// model. Workloads that genuinely need raw ICMP should run outside
/// sandlock or rely on the host's `ping_group_range` for the dgram
/// path instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Protocol {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            _ => None,
        }
    }
}

// ============================================================
// resolve_net_allow — resolve --net-allow rules to runtime allowlist
// ============================================================

/// Resolved form of `Policy::net_allow`, ready for the on-behalf path.
pub struct ResolvedNetAllow {
    /// Per-IP port rules (each concrete-host entry resolves to one or
    /// more IPs). An IP appearing here with an empty port set means
    /// "all ports for this IP" (from a `host:*` rule).
    pub per_ip: HashMap<IpAddr, HashSet<u16>>,
    /// IPs permitted on every port (from `host:*` rules after host
    /// resolution). The on-behalf path treats these the same as
    /// `PortAllow::Any` — the entry in `per_ip` is kept as a
    /// placeholder for diagnostic / `/etc/hosts` purposes.
    pub per_ip_all_ports: HashSet<IpAddr>,
    /// IP/CIDR-literal targets, matched by containment with no DNS (an
    /// exact IP literal is a `/32` or `/128`). Each carries the ports
    /// permitted to that range (`PortAllow::Any` for all-ports rules).
    pub cidrs: Vec<(IpCidr, crate::seccomp::notif::PortAllow)>,
    /// Ports permitted to any IP (the `:port` form).
    pub any_ip_ports: HashSet<u16>,
    /// Any-host any-port wildcard (`:*` / `*:*`, or `icmp://*`). When
    /// true, the per-protocol policy becomes `Unrestricted` and the
    /// on-behalf check is bypassed for that protocol.
    pub any_ip_all_ports: bool,
}

/// Per-protocol resolved allowlists. Each protocol gets its own
/// `ResolvedNetAllow`; the on-behalf path picks the right one based on
/// the dup'd fd's `SO_PROTOCOL`. `etc_hosts` is shared across all
/// protocols (the synthetic file maps every concrete host that appears
/// in any rule).
pub struct ResolvedNetAllowSet {
    pub tcp: ResolvedNetAllow,
    pub udp: ResolvedNetAllow,
    pub icmp: ResolvedNetAllow,
    /// `<ip> <hostname>\n` lines from every concrete-host rule across
    /// every protocol, in resolution order. Empty when no concrete-host
    /// rules are present. Combined with the loopback base (or, in chroot
    /// mode, the image's `/etc/hosts`) by [`compose_virtual_etc_hosts`]
    /// to build the synthetic file served to the sandbox.
    pub concrete_host_entries: String,
}

/// Resolve `--net-allow` rules into per-protocol runtime allowlists.
///
/// Rules are grouped by `Protocol` and each group is resolved
/// independently. ICMP rules carry no ports, so the resulting ICMP
/// `ResolvedNetAllow` always has empty `any_ip_ports` / per-IP port
/// sets — the on-behalf check routes ICMP through the IP-only path
/// (PortAllow::Any). A `*` host on ICMP becomes `any_ip_all_ports`,
/// which the handler reads as "no destination check."
pub async fn resolve_net_allow(
    rules: &[NetAllow],
) -> io::Result<ResolvedNetAllowSet> {
    use crate::seccomp::notif::PortAllow;
    let per_proto = |target: Protocol| async move {
        let mut per_ip: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
        let mut per_ip_all_ports: HashSet<IpAddr> = HashSet::new();
        let mut cidrs: Vec<(IpCidr, PortAllow)> = Vec::new();
        let mut any_ip_ports: HashSet<u16> = HashSet::new();
        let mut any_ip_all_ports = false;
        let mut local_etc_hosts = String::new();

        for rule in rules.iter().filter(|r| r.protocol == target) {
            match &rule.target {
                NetTarget::AnyIp => {
                    if rule.all_ports || target == Protocol::Icmp {
                        // ICMP rules never carry ports, so a wildcard-host
                        // ICMP rule (`icmp://*`) means "any destination."
                        any_ip_all_ports = true;
                    } else {
                        for &p in &rule.ports {
                            any_ip_ports.insert(p);
                        }
                    }
                }
                NetTarget::Cidr(c) => {
                    // IP/CIDR literals are matched by containment with no
                    // DNS, exactly like `--net-deny` targets.
                    let pa = if rule.all_ports || target == Protocol::Icmp {
                        PortAllow::Any
                    } else {
                        PortAllow::Specific(rule.ports.iter().copied().collect())
                    };
                    cidrs.push((*c, pa));
                }
                NetTarget::Host(host) => {
                    let addr = format!("{}:0", host);
                    let resolved = tokio::net::lookup_host(addr.as_str()).await.map_err(|e| {
                        io::Error::new(
                            e.kind(),
                            format!("failed to resolve host '{}': {}", host, e),
                        )
                    })?;
                    for socket_addr in resolved {
                        let ip = socket_addr.ip();
                        if rule.all_ports || target == Protocol::Icmp {
                            per_ip_all_ports.insert(ip);
                            per_ip.entry(ip).or_default();
                        } else {
                            let entry = per_ip.entry(ip).or_default();
                            for &p in &rule.ports {
                                entry.insert(p);
                            }
                        }
                        local_etc_hosts.push_str(&format!("{} {}\n", ip, host));
                    }
                }
            }
        }

        Ok::<_, io::Error>((
            ResolvedNetAllow {
                per_ip,
                per_ip_all_ports,
                cidrs,
                any_ip_ports,
                any_ip_all_ports,
            },
            local_etc_hosts,
        ))
    };

    let (tcp, tcp_eh) = per_proto(Protocol::Tcp).await?;
    let (udp, udp_eh) = per_proto(Protocol::Udp).await?;
    let (icmp, icmp_eh) = per_proto(Protocol::Icmp).await?;

    let mut concrete_host_entries = String::new();
    for chunk in [tcp_eh, udp_eh, icmp_eh] {
        concrete_host_entries.push_str(&chunk);
    }

    Ok(ResolvedNetAllowSet {
        tcp,
        udp,
        icmp,
        concrete_host_entries,
    })
}

/// Per-protocol resolved deny policies, ready for `NetworkState`.
pub struct ResolvedNetDenySet {
    pub tcp: crate::seccomp::notif::NetworkPolicy,
    pub udp: crate::seccomp::notif::NetworkPolicy,
    pub icmp: crate::seccomp::notif::NetworkPolicy,
}

/// Resolve `--net-deny` rules into per-protocol `DenyList` policies.
/// A protocol with no deny rules stays `Unrestricted` (allow-all).
pub fn resolve_net_deny(rules: &[NetDeny]) -> ResolvedNetDenySet {
    use crate::seccomp::notif::{NetworkPolicy, PortAllow};

    let per_proto = |target: Protocol| -> NetworkPolicy {
        let mut cidrs: Vec<(IpCidr, PortAllow)> = Vec::new();
        let mut any_ip_ports: HashSet<u16> = HashSet::new();
        let mut deny_all = false;
        let mut saw_rule = false;

        for rule in rules.iter().filter(|r| r.protocol == target) {
            saw_rule = true;
            match &rule.target {
                NetTarget::AnyIp => {
                    if rule.all_ports || target == Protocol::Icmp {
                        deny_all = true;
                    } else {
                        for &p in &rule.ports {
                            any_ip_ports.insert(p);
                        }
                    }
                }
                NetTarget::Cidr(c) => {
                    let pa = if rule.all_ports || target == Protocol::Icmp {
                        PortAllow::Any
                    } else {
                        PortAllow::Specific(rule.ports.iter().copied().collect())
                    };
                    cidrs.push((*c, pa));
                }
                // `--net-deny` rejects hostnames at parse time, so a deny
                // rule never carries a `Host` target.
                NetTarget::Host(_) => unreachable!("net-deny rejects hostnames"),
            }
        }

        if !saw_rule {
            NetworkPolicy::Unrestricted
        } else {
            NetworkPolicy::DenyList {
                cidrs,
                any_ip_ports,
                deny_all,
            }
        }
    };

    ResolvedNetDenySet {
        tcp: per_proto(Protocol::Tcp),
        udp: per_proto(Protocol::Udp),
        icmp: per_proto(Protocol::Icmp),
    }
}

/// Compose the synthetic `/etc/hosts` served to the sandbox.
///
/// - **No chroot**: emit the fixed loopback base
///   (`127.0.0.1 localhost\n::1 localhost\n`) followed by the
///   concrete-host entries from [`resolve_net_allow`]. The sandbox sees
///   the same baseline regardless of what the host's on-disk file says.
/// - **With chroot**: read `<chroot>/etc/hosts` and use it as the base
///   (an image that bakes in private-registry entries or similar keeps
///   them). Inject loopback entries only for any localhost family the
///   image doesn't already cover — never both, so we don't duplicate
///   what the image already has. Concrete-host entries are still
///   appended on top.
///
/// If a chroot is set but `<chroot>/etc/hosts` is unreadable (absent,
/// permission denied, etc.), fall back to the bare loopback base — the
/// sandbox always sees a usable hosts file.
pub fn compose_virtual_etc_hosts(
    chroot_root: Option<&std::path::Path>,
    concrete_host_entries: &str,
) -> String {
    let mut out = String::new();
    let mut has_v4_localhost = false;
    let mut has_v6_localhost = false;

    if let Some(root) = chroot_root {
        if let Ok(image) = std::fs::read_to_string(root.join("etc").join("hosts")) {
            for line in image.lines() {
                // Strip an inline `#` comment before tokenizing — the
                // hosts(5) format treats everything after `#` as a comment.
                let stripped = line.split('#').next().unwrap_or("");
                let mut parts = stripped.split_whitespace();
                let Some(ip) = parts.next() else { continue };
                for name in parts {
                    if name == "localhost" {
                        if ip == "127.0.0.1" {
                            has_v4_localhost = true;
                        } else if ip == "::1" {
                            has_v6_localhost = true;
                        }
                    }
                }
            }
            out.push_str(&image);
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
        }
    }

    if !has_v4_localhost {
        out.push_str("127.0.0.1 localhost\n");
    }
    if !has_v6_localhost {
        out.push_str("::1 localhost\n");
    }
    out.push_str(concrete_host_entries);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- NetAllow::parse tests ---

    #[test]
    fn netallow_parse_concrete_host_port() {
        let r = NetRule::parse_allow("example.com:443").unwrap();
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "example.com"));
        assert_eq!(r.ports, vec![443]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_parse_any_host_port() {
        let r = NetRule::parse_allow(":8080").unwrap();
        assert_eq!(r.target, NetTarget::AnyIp);
        assert_eq!(r.ports, vec![8080]);
        assert!(!r.all_ports);

        let r = NetRule::parse_allow("*:8080").unwrap();
        assert_eq!(r.target, NetTarget::AnyIp);
        assert_eq!(r.ports, vec![8080]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_parse_multiple_ports() {
        let r = NetRule::parse_allow("github.com:22,80,443").unwrap();
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "github.com"));
        assert_eq!(r.ports, vec![22, 80, 443]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_parse_wildcard_any_host_any_port_colon() {
        let r = NetRule::parse_allow(":*").unwrap();
        assert_eq!(r.target, NetTarget::AnyIp);
        assert!(r.ports.is_empty());
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_parse_wildcard_any_host_any_port_star() {
        let r = NetRule::parse_allow("*:*").unwrap();
        assert_eq!(r.target, NetTarget::AnyIp);
        assert!(r.ports.is_empty());
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_parse_wildcard_concrete_host_any_port() {
        let r = NetRule::parse_allow("example.com:*").unwrap();
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "example.com"));
        assert!(r.ports.is_empty());
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_parse_rejects_mixed_wildcard_and_concrete() {
        // `host:80,*` and `host:*,80` are both ambiguous: the user
        // either meant "any port" (wildcard wins) or "ports 80 plus
        // some weird placeholder". Refuse and force a clean spec.
        let err = NetRule::parse_allow("example.com:80,*").unwrap_err();
        assert!(format!("{}", err).contains("cannot mix"));
        let err = NetRule::parse_allow("example.com:*,80").unwrap_err();
        assert!(format!("{}", err).contains("cannot mix"));
    }

    #[test]
    fn netallow_parse_rejects_port_zero() {
        let err = NetRule::parse_allow("example.com:0").unwrap_err();
        assert!(format!("{}", err).contains("port 0"));
    }

    #[test]
    fn netallow_parse_rejects_empty_port() {
        let err = NetRule::parse_allow("example.com:").unwrap_err();
        assert!(format!("{}", err).contains("invalid port"));
    }

    #[test]
    fn netallow_bare_host_is_all_ports() {
        // No port suffix means "all ports" (port optional), symmetric
        // with the `host:*` form.
        let r = NetRule::parse_allow("example.com").unwrap();
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "example.com"));
        assert!(r.all_ports);
        assert!(r.ports.is_empty());
    }

    #[test]
    fn netallow_bare_star_is_any_host_all_ports() {
        let r = NetRule::parse_allow("*").unwrap();
        assert_eq!(r.target, NetTarget::AnyIp);
        assert!(r.all_ports);
        assert!(r.ports.is_empty());
    }

    #[test]
    fn netallow_empty_spec_rejected() {
        assert!(NetRule::parse_allow("").is_err());
        assert!(NetRule::parse_allow("tcp://").is_err());
    }

    #[test]
    fn netallow_cidr_target_with_port() {
        // CIDR ranges are now first-class in --net-allow (matched by
        // containment, no DNS), symmetric with --net-deny.
        let r = NetRule::parse_allow("10.0.0.0/8:80").unwrap();
        assert!(matches!(&r.target, NetTarget::Cidr(c) if !c.is_single_host()));
        assert_eq!(r.ports, vec![80]);
        assert!(!r.all_ports);
    }

    #[test]
    fn netallow_ipv6_literal_and_bracket() {
        let lo: std::net::IpAddr = "::1".parse().unwrap();
        // Bare IPv6 literal (previously mis-split on its colons).
        let r = NetRule::parse_allow("::1").unwrap();
        assert!(matches!(&r.target, NetTarget::Cidr(c) if c.addr == lo && c.is_single_host()));
        assert!(r.all_ports);
        // Bracketed IPv6 with a port.
        let r = NetRule::parse_allow("[::1]:443").unwrap();
        assert!(matches!(&r.target, NetTarget::Cidr(c) if c.addr == lo && c.is_single_host()));
        assert_eq!(r.ports, vec![443]);
        // IPv6 CIDR.
        let r = NetRule::parse_allow("fc00::/7").unwrap();
        assert!(matches!(&r.target, NetTarget::Cidr(c) if !c.is_single_host()));
        assert!(r.all_ports);
    }

    #[tokio::test]
    async fn test_resolve_net_allow_cidr_no_dns() {
        // A CIDR / IP-literal target resolves into `cidrs` directly, with
        // no DNS lookup and no `per_ip` / `/etc/hosts` entry.
        let rules = vec![
            NetAllow { protocol: Protocol::Tcp, target: NetTarget::Cidr(IpCidr::parse("10.0.0.0/8").unwrap()), ports: vec![80], all_ports: false },
            NetAllow { protocol: Protocol::Tcp, target: NetTarget::Cidr(IpCidr::parse("1.2.3.4").unwrap()), ports: vec![], all_ports: true },
        ];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert_eq!(resolved.tcp.cidrs.len(), 2);
        assert!(resolved.tcp.per_ip.is_empty());
        assert!(resolved.concrete_host_entries.is_empty());
    }

    #[test]
    fn netallow_parse_repeated_wildcard_is_idempotent() {
        // `*,*` collapses to a single wildcard — neither token contributes
        // a concrete port, so the rule remains "any port".
        let r = NetRule::parse_allow(":*,*").unwrap();
        assert!(r.all_ports);
        assert!(r.ports.is_empty());
    }

    // --- Protocol scheme prefix tests ---

    #[test]
    fn netallow_bare_form_defaults_to_tcp() {
        let r = NetRule::parse_allow("example.com:443").unwrap();
        assert_eq!(r.protocol, Protocol::Tcp);
    }

    #[test]
    fn netallow_explicit_tcp_scheme() {
        let r = NetRule::parse_allow("tcp://example.com:443").unwrap();
        assert_eq!(r.protocol, Protocol::Tcp);
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "example.com"));
        assert_eq!(r.ports, vec![443]);
    }

    #[test]
    fn netallow_udp_scheme_with_host_port() {
        let r = NetRule::parse_allow("udp://1.1.1.1:53").unwrap();
        assert_eq!(r.protocol, Protocol::Udp);
        // An IP literal becomes a single-host CIDR target (no DNS).
        let one: std::net::IpAddr = "1.1.1.1".parse().unwrap();
        assert!(matches!(&r.target, NetTarget::Cidr(c) if c.addr == one && c.is_single_host()));
        assert_eq!(r.ports, vec![53]);
    }

    #[test]
    fn netallow_udp_wildcard_any_anywhere() {
        // The "any UDP" gate, equivalent to the old `allow_udp = true`.
        let r = NetRule::parse_allow("udp://*:*").unwrap();
        assert_eq!(r.protocol, Protocol::Udp);
        assert_eq!(r.target, NetTarget::AnyIp);
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_icmp_scheme_with_host() {
        let r = NetRule::parse_allow("icmp://github.com").unwrap();
        assert_eq!(r.protocol, Protocol::Icmp);
        assert!(matches!(&r.target, NetTarget::Host(h) if h == "github.com"));
        assert!(r.ports.is_empty());
        // ICMP carries no ports, so the rule is "all ports" by convention.
        assert!(r.all_ports);
    }

    #[test]
    fn netallow_icmp_wildcard() {
        // The "any ICMP echo" gate, equivalent to the old
        // `allow_icmp = true` for the SOCK_DGRAM path.
        let r = NetRule::parse_allow("icmp://*").unwrap();
        assert_eq!(r.protocol, Protocol::Icmp);
        assert_eq!(r.target, NetTarget::AnyIp);
    }

    #[test]
    fn netallow_icmp_rejects_port() {
        // ICMP has no port — `:port` is meaningless and refused
        // explicitly so users can't write a rule that doesn't do what
        // they think.
        let err = NetRule::parse_allow("icmp://github.com:80").unwrap_err();
        assert!(format!("{}", err).contains("icmp rule takes no port"));
    }

    #[test]
    fn netallow_icmp_rejects_empty_body() {
        let err = NetRule::parse_allow("icmp://").unwrap_err();
        assert!(format!("{}", err).contains("needs a host/IP or `*`"));
    }

    #[test]
    fn netallow_unknown_scheme_rejected() {
        // Including `icmp-raw` — sandlock does not expose raw ICMP, so
        // the scheme is unknown rather than a special-case error.
        for spec in ["sctp://host:1234", "icmp-raw://*"] {
            let err = NetRule::parse_allow(spec).unwrap_err();
            assert!(format!("{}", err).contains("unknown scheme"), "spec: {}", spec);
        }
    }

    #[tokio::test]
    async fn test_resolve_net_allow_empty() {
        let resolved = resolve_net_allow(&[]).await.unwrap();
        assert!(resolved.tcp.per_ip.is_empty());
        assert!(resolved.tcp.any_ip_ports.is_empty());
        assert!(resolved.udp.per_ip.is_empty());
        assert!(resolved.icmp.per_ip.is_empty());
        // No concrete-host rules → no resolved-entry lines.
        assert!(resolved.concrete_host_entries.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_net_allow_concrete_host() {
        let rules = vec![NetAllow {
            protocol: Protocol::Tcp,
            target: NetTarget::Host("localhost".to_string()),
            ports: vec![80, 443],
            all_ports: false,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        // localhost should resolve to at least one loopback addr; only
        // the TCP set has entries.
        assert!(!resolved.tcp.per_ip.is_empty());
        for ports in resolved.tcp.per_ip.values() {
            assert!(ports.contains(&80));
            assert!(ports.contains(&443));
        }
        assert!(resolved.udp.per_ip.is_empty());
        assert!(resolved.icmp.per_ip.is_empty());
        // The resolved entry (`<ip> localhost`) surfaces in concrete_host_entries.
        assert!(resolved.concrete_host_entries.contains("127.0.0.1 localhost"));
    }

    #[tokio::test]
    async fn test_resolve_net_allow_any_ip() {
        let rules = vec![NetAllow {
            protocol: Protocol::Tcp,
            target: NetTarget::AnyIp,
            ports: vec![8080],
            all_ports: false,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(resolved.tcp.per_ip.is_empty());
        assert!(resolved.tcp.any_ip_ports.contains(&8080));
        assert!(!resolved.tcp.any_ip_all_ports);
        // Any-IP rule has no concrete host, so no resolved-entry line.
        assert!(resolved.concrete_host_entries.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_net_allow_any_ip_all_ports() {
        // `:*` — fully unrestricted egress, TCP-only.
        let rules = vec![NetAllow {
            protocol: Protocol::Tcp,
            target: NetTarget::AnyIp,
            ports: vec![],
            all_ports: true,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(resolved.tcp.any_ip_all_ports);
        assert!(resolved.tcp.per_ip.is_empty());
        assert!(resolved.tcp.per_ip_all_ports.is_empty());
        assert!(resolved.tcp.any_ip_ports.is_empty());
        // UDP/ICMP unaffected by a TCP rule.
        assert!(!resolved.udp.any_ip_all_ports);
        assert!(!resolved.icmp.any_ip_all_ports);
    }

    #[tokio::test]
    async fn test_resolve_net_allow_concrete_host_all_ports() {
        // `localhost:*` — every port to localhost only, TCP.
        let rules = vec![NetAllow {
            protocol: Protocol::Tcp,
            target: NetTarget::Host("localhost".to_string()),
            ports: vec![],
            all_ports: true,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(!resolved.tcp.any_ip_all_ports);
        assert!(
            !resolved.tcp.per_ip_all_ports.is_empty(),
            "localhost should resolve to at least one IP marked as any-port"
        );
        for ip in resolved.tcp.per_ip_all_ports.iter() {
            assert!(resolved.tcp.per_ip.contains_key(ip));
        }
        assert!(resolved.concrete_host_entries.contains("localhost"));
    }

    #[tokio::test]
    async fn test_resolve_net_allow_mixed_wildcard_and_concrete() {
        // Wildcard rule alongside concrete: wildcard sets the global
        // any-host any-port flag for TCP; concrete rule still resolves
        // into per_ip (the runtime layer chooses Unrestricted, ignoring
        // the concrete entries).
        let rules = vec![
            NetAllow {
                protocol: Protocol::Tcp,
                target: NetTarget::AnyIp,
                ports: vec![],
                all_ports: true,
            },
            NetAllow {
                protocol: Protocol::Tcp,
                target: NetTarget::Host("localhost".to_string()),
                ports: vec![22],
                all_ports: false,
            },
        ];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(resolved.tcp.any_ip_all_ports);
        assert!(!resolved.tcp.per_ip.is_empty());
    }

    // ============================================================
    // Per-protocol resolution — UDP / ICMP slices stay isolated
    // ============================================================

    #[tokio::test]
    async fn test_resolve_per_protocol_isolation() {
        // A UDP rule should not appear in the TCP set, and vice versa.
        // This is the property Phase 2 relies on for protocol routing.
        let rules = vec![
            NetAllow {
                protocol: Protocol::Tcp,
                target: NetTarget::Host("localhost".to_string()),
                ports: vec![443],
                all_ports: false,
            },
            NetAllow {
                protocol: Protocol::Udp,
                target: NetTarget::AnyIp,
                ports: vec![53],
                all_ports: false,
            },
        ];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(
            !resolved.tcp.per_ip.is_empty(),
            "TCP rule should populate tcp set"
        );
        assert!(
            resolved.udp.any_ip_ports.contains(&53),
            "UDP rule should populate udp set"
        );
        // Cross-contamination check: TCP per_ip ports must not contain 53;
        // UDP must not contain 443.
        for ports in resolved.tcp.per_ip.values() {
            assert!(!ports.contains(&53), "UDP port leaked into TCP set");
        }
        assert!(!resolved.udp.any_ip_ports.contains(&443), "TCP port leaked into UDP set");
    }

    #[tokio::test]
    async fn test_resolve_icmp_no_ports() {
        // ICMP rules carry no ports; concrete hosts go into per_ip with
        // PortAllow::Any-style empty port set, plus per_ip_all_ports.
        let rules = vec![NetAllow {
            protocol: Protocol::Icmp,
            target: NetTarget::Host("localhost".to_string()),
            ports: vec![],
            all_ports: false,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(
            !resolved.icmp.per_ip.is_empty(),
            "icmp host should populate per_ip"
        );
        assert!(
            !resolved.icmp.per_ip_all_ports.is_empty(),
            "icmp host should mark per_ip_all_ports (no port check)"
        );
        assert!(resolved.icmp.any_ip_ports.is_empty());
        // TCP/UDP unaffected.
        assert!(resolved.tcp.per_ip.is_empty());
        assert!(resolved.udp.per_ip.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_icmp_wildcard() {
        // `icmp://*` — any ICMP destination.
        let rules = vec![NetAllow {
            protocol: Protocol::Icmp,
            target: NetTarget::AnyIp,
            ports: vec![],
            all_ports: false,
        }];
        let resolved = resolve_net_allow(&rules).await.unwrap();
        assert!(resolved.icmp.any_ip_all_ports);
        assert!(!resolved.tcp.any_ip_all_ports);
    }

    // ============================================================
    // compose_virtual_etc_hosts — synthetic /etc/hosts assembly
    // ============================================================

    use std::io::Write;

    fn temp_rootfs_with_hosts(name: &str, hosts_content: Option<&str>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sandlock-test-compose-hosts-{}-{}",
            name, std::process::id()
        ));
        let _ = std::fs::create_dir_all(dir.join("etc"));
        if let Some(content) = hosts_content {
            let mut f = std::fs::File::create(dir.join("etc").join("hosts")).unwrap();
            f.write_all(content.as_bytes()).unwrap();
        }
        dir
    }

    #[test]
    fn compose_no_chroot_emits_loopback_base() {
        // Default path — no chroot, no concrete-host rules → the same
        // fixed loopback view we promise every sandbox.
        let out = compose_virtual_etc_hosts(None, "");
        assert_eq!(out, "127.0.0.1 localhost\n::1 localhost\n");
    }

    #[test]
    fn compose_no_chroot_appends_concrete_entries() {
        let out = compose_virtual_etc_hosts(None, "10.0.0.1 api\n");
        assert_eq!(out, "127.0.0.1 localhost\n::1 localhost\n10.0.0.1 api\n");
    }

    #[test]
    fn compose_chroot_seeds_from_image_and_injects_missing_loopback() {
        // Image ships an entry of its own but no localhost mapping; the
        // shim must keep the image's content and inject both loopback
        // entries on top so the always-on guarantee still holds.
        let rootfs = temp_rootfs_with_hosts(
            "no-localhost",
            Some("10.0.0.5 myimage.local\n"),
        );
        let out = compose_virtual_etc_hosts(Some(&rootfs), "");
        assert!(out.contains("10.0.0.5 myimage.local"), "image entry missing: {out}");
        assert!(out.contains("127.0.0.1 localhost"), "v4 loopback missing: {out}");
        assert!(out.contains("::1 localhost"), "v6 loopback missing: {out}");
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn compose_chroot_does_not_duplicate_existing_loopback() {
        // Image already has both loopback entries — don't append duplicates.
        let rootfs = temp_rootfs_with_hosts(
            "both-localhost",
            Some("127.0.0.1 localhost\n::1 localhost\n10.0.0.5 myimage.local\n"),
        );
        let out = compose_virtual_etc_hosts(Some(&rootfs), "");
        assert_eq!(out.matches("127.0.0.1 localhost").count(), 1, "v4 dup'd: {out}");
        assert_eq!(out.matches("::1 localhost").count(), 1, "v6 dup'd: {out}");
        assert!(out.contains("10.0.0.5 myimage.local"));
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn compose_chroot_injects_only_missing_family() {
        // Image has v4 but no v6 localhost — inject only v6, leave v4 alone.
        let rootfs = temp_rootfs_with_hosts(
            "only-v4-localhost",
            Some("127.0.0.1 localhost myimage\n"),
        );
        let out = compose_virtual_etc_hosts(Some(&rootfs), "");
        assert_eq!(out.matches("127.0.0.1 localhost").count(), 1);
        assert!(out.contains("::1 localhost"), "v6 loopback should be injected: {out}");
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn compose_chroot_missing_file_falls_back_to_loopback() {
        // Chroot exists but has no /etc/hosts — fall back to the bare
        // loopback base so the sandbox always sees a usable file.
        let rootfs = temp_rootfs_with_hosts("no-file", None);
        let out = compose_virtual_etc_hosts(Some(&rootfs), "10.0.0.1 api\n");
        assert_eq!(out, "127.0.0.1 localhost\n::1 localhost\n10.0.0.1 api\n");
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn compose_chroot_strips_inline_comments_when_detecting_loopback() {
        // hosts(5) treats `#` as a comment-start; the loopback-presence
        // check must respect it (otherwise an image line like
        // `127.0.0.1 # localhost` would be falsely treated as covering v4).
        let rootfs = temp_rootfs_with_hosts(
            "with-comments",
            Some("127.0.0.1 # localhost is a comment here\n"),
        );
        let out = compose_virtual_etc_hosts(Some(&rootfs), "");
        // Real `127.0.0.1 localhost` line must still be injected.
        assert!(
            out.lines().any(|l| l.trim() == "127.0.0.1 localhost"),
            "v4 loopback should still be injected: {out}"
        );
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    // --- IpCidr tests ---

    #[test]
    fn ipcidr_parse_bare_ipv4_is_host_route() {
        let c = IpCidr::parse("1.2.3.4").unwrap();
        assert_eq!(c.prefix_len, 32);
        assert!(c.contains("1.2.3.4".parse().unwrap()));
        assert!(!c.contains("1.2.3.5".parse().unwrap()));
    }

    #[test]
    fn ipcidr_parse_ipv4_range_contains() {
        let c = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.3.7.9".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipcidr_parse_ipv6_range_contains() {
        let c = IpCidr::parse("fc00::/7").unwrap();
        assert!(c.contains("fd00::1".parse().unwrap()));
        assert!(!c.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn ipcidr_zero_prefix_matches_all_same_family() {
        let c = IpCidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains("8.8.8.8".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap())); // family mismatch
    }

    #[test]
    fn ipcidr_rejects_hostname() {
        assert!(IpCidr::parse("example.com").is_err());
    }

    #[test]
    fn ipcidr_rejects_oversized_prefix() {
        assert!(IpCidr::parse("10.0.0.0/33").is_err());
        assert!(IpCidr::parse("fc00::/129").is_err());
    }

    // --- NetDeny::parse tests ---

    #[test]
    fn netdeny_bare_cidr_is_all_ports_tcp() {
        let rule = NetRule::parse_deny("10.0.0.0/8").unwrap();
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert!(matches!(rule.target, NetTarget::Cidr(_)));
        assert!(rule.all_ports);
    }

    #[test]
    fn netdeny_bare_ip_is_host_route_all_ports() {
        let rule = NetRule::parse_deny("169.254.169.254").unwrap();
        match &rule.target {
            NetTarget::Cidr(c) => assert_eq!(c.prefix_len, 32),
            _ => panic!("expected cidr"),
        }
        assert!(rule.all_ports);
    }

    #[test]
    fn netdeny_cidr_with_port() {
        let rule = NetRule::parse_deny("10.0.0.0/8:443").unwrap();
        assert_eq!(rule.ports, vec![443]);
        assert!(!rule.all_ports);
    }

    #[test]
    fn netdeny_any_ip_port() {
        let rule = NetRule::parse_deny(":25").unwrap();
        assert!(matches!(rule.target, NetTarget::AnyIp));
        assert_eq!(rule.ports, vec![25]);
    }

    #[test]
    fn netdeny_udp_scheme() {
        let rule = NetRule::parse_deny("udp://192.168.0.0/16:53").unwrap();
        assert_eq!(rule.protocol, Protocol::Udp);
        assert_eq!(rule.ports, vec![53]);
    }

    #[test]
    fn netdeny_ipv6_bracket_port() {
        let rule = NetRule::parse_deny("[::1]:443").unwrap();
        assert_eq!(rule.ports, vec![443]);
        match &rule.target {
            NetTarget::Cidr(c) => assert_eq!(c.prefix_len, 128),
            _ => panic!("expected cidr"),
        }
    }

    #[test]
    fn netdeny_rejects_hostname() {
        assert!(NetRule::parse_deny("evil.com:443").is_err());
        assert!(NetRule::parse_deny("evil.com").is_err());
    }

    #[test]
    fn netdeny_bare_ipv6_address_all_ports() {
        let rule = NetRule::parse_deny("::1").unwrap();
        assert!(rule.all_ports);
        match &rule.target {
            NetTarget::Cidr(c) => assert_eq!(c.prefix_len, 128),
            _ => panic!("expected cidr"),
        }
    }

    #[test]
    fn netdeny_bare_ipv6_cidr_all_ports() {
        let rule = NetRule::parse_deny("fc00::/7").unwrap();
        assert!(rule.all_ports);
        let ula: std::net::IpAddr = "fd00::1".parse().unwrap();
        assert!(matches!(&rule.target, NetTarget::Cidr(c) if c.contains(ula)));
    }

    #[test]
    fn netdeny_empty_icmp_body_is_rejected() {
        assert!(NetRule::parse_deny("icmp://").is_err());
    }

    #[test]
    fn netdeny_bare_star_is_any_ip_all_ports() {
        // `*` with no port is the any-IP, all-ports form (port optional,
        // symmetric with a bare IP/CIDR).
        let rule = NetRule::parse_deny("*").unwrap();
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert!(matches!(rule.target, NetTarget::AnyIp));
        assert!(rule.all_ports);
        assert!(rule.ports.is_empty());
    }

    #[test]
    fn netdeny_udp_bare_star_all_ports() {
        let rule = NetRule::parse_deny("udp://*").unwrap();
        assert_eq!(rule.protocol, Protocol::Udp);
        assert!(matches!(rule.target, NetTarget::AnyIp));
        assert!(rule.all_ports);
    }

    #[test]
    fn netdeny_empty_spec_rejected() {
        // An empty body must not silently mean "deny everything".
        assert!(NetRule::parse_deny("").is_err());
        assert!(NetRule::parse_deny("udp://").is_err());
    }

    // --- resolve_net_deny tests ---

    #[test]
    fn resolve_net_deny_groups_per_protocol() {
        let rule = NetRule::parse_deny("10.0.0.0/8").unwrap();
        let set = resolve_net_deny(std::slice::from_ref(&rule));
        // TCP policy denies 10.x, UDP/ICMP unaffected (still allow-all).
        assert!(!set.tcp.allows("10.0.0.1".parse().unwrap(), 443));
        assert!(set.udp.allows("10.0.0.1".parse().unwrap(), 443));
    }

    #[test]
    fn resolve_net_deny_any_ip_port() {
        let rule = NetRule::parse_deny(":25").unwrap();
        let set = resolve_net_deny(std::slice::from_ref(&rule));
        assert!(!set.tcp.allows("8.8.8.8".parse().unwrap(), 25));
        assert!(set.tcp.allows("8.8.8.8".parse().unwrap(), 80));
    }
}

// Network policy and control handlers — IP allowlist enforcement via seccomp notification.
//
// Intercepts connect/sendto/sendmsg syscalls, extracts the destination IP from
// the child's memory, and checks it against an allowlist of resolved IPs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_mem, NotifAction};
use crate::sys::structs::{SeccompNotif, ECONNREFUSED};

mod child_abi;
mod rules;
mod send_engine;
mod verdict;

// `network` is pub(crate), so this re-export is the crate-internal path for
// the rule types. The two resolved-set types are named only in re-exported
// signatures (callers bind them by inference), which trips unused_imports.
#[allow(unused_imports)]
pub use rules::{
    compose_virtual_etc_hosts, resolve_net_allow, resolve_net_deny, IpCidr, NetAllow, NetDeny,
    NetRule, NetTarget, Protocol, ResolvedNetAllow, ResolvedNetAllowSet, ResolvedNetDenySet,
};

use child_abi::{
    materialize_msg, mmsg_entry_ptr, mmsg_msglen_addr, named_unix_socket_path,
    parse_ip_from_sockaddr, parse_port_from_sockaddr, set_port_in_sockaddr, ChildMsghdr,
    MaterializedMsg, MAX_SEND_BUF,
};
use send_engine::{batch_send_step, resolve_send, wants_blocking, BatchStep};
use verdict::{check_ip_destination, destination_verdict, path_under_any, real_path_under_any};

// ============================================================
// query_socket_protocol — derive the rule Protocol from a fd via getsockopt
// ============================================================

/// Query `SO_PROTOCOL` on a dup'd socket fd to learn whether to route
/// the on-behalf check through the TCP, UDP, or ICMP policy.
///
/// Returns `None` for protocols sandlock does not gate via `net_allow`
/// (raw, SCTP, etc.) — the handler treats those as "no rule applies"
/// which collapses to the default-deny path.
pub(crate) fn query_socket_protocol(fd: RawFd) -> Option<Protocol> {
    let mut proto: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PROTOCOL,
            &mut proto as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    match proto {
        libc::IPPROTO_TCP => Some(Protocol::Tcp),
        libc::IPPROTO_UDP => Some(Protocol::Udp),
        // IPPROTO_ICMP and IPPROTO_ICMPV6 both route to the ICMP policy
        // (the policy doesn't distinguish IP versions; the rule's
        // resolved IP set already covers both via DNS).
        libc::IPPROTO_ICMP | libc::IPPROTO_ICMPV6 => Some(Protocol::Icmp),
        _ => None,
    }
}

/// True iff `fd` is an `AF_UNIX` socket, probed via `SO_DOMAIN`. `SCM_RIGHTS`
/// and `SCM_CREDENTIALS` are unix-only, so control rewriting/gating is applied
/// only to unix sockets — an IP socket's control (e.g. `IP_PKTINFO`) carries no
/// fds or credentials and passes through untouched.
fn socket_is_unix(fd: RawFd) -> bool {
    let mut domain: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            &mut domain as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    rc == 0 && domain == libc::AF_UNIX
}

// ============================================================
// connect_on_behalf — perform connect() on behalf of the child (TOCTOU-safe)
// ============================================================

/// Perform connect() on behalf of the child process (TOCTOU-safe).
///
/// 1. Copy sockaddr from child memory (our copy — immune to TOCTOU)
/// 2. Check IP against allowlist on our copy
/// 3. Duplicate child's socket fd via pidfd_getfd
/// 4. connect() in supervisor with our validated sockaddr
/// 5. Return result to child
async fn connect_on_behalf(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let args = &notif.data.args;
    let sockfd = args[0] as i32;
    let addr_ptr = args[1];
    let addr_len = args[2] as u32;

    // 1. Copy sockaddr from child memory
    let addr_bytes =
        match read_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, addr_len as usize) {
            Ok(b) => b,
            Err(_) => return NotifAction::Errno(libc::EIO),
        };

    // 2. Check destination against the per-protocol endpoint allowlist.
    // The dup we'd need anyway for the on-behalf connect doubles as
    // our SO_PROTOCOL probe — one pidfd_getfd, one getsockopt. The
    // per-protocol policy is keyed on whether the socket is TCP / UDP
    // / kernel ping (ICMP). Unknown protocol (raw, SCTP, etc.) fails
    // closed: the BPF should have prevented socket creation, so
    // reaching here with one is an unexpected case worth refusing.
    if let Some(ip) = parse_ip_from_sockaddr(&addr_bytes) {
        // Same invariant as the sendto/sendmsg handlers above: `connect()` is
        // trapped whenever the named-`AF_UNIX` gate is on (any fs grant), for
        // every address family, but with no network destination policy there
        // is nothing to enforce on an IP destination. Return it to the kernel
        // so the child's own Landlock `CONNECT_TCP` rules govern it — handling
        // it on-behalf in the unconfined supervisor would bypass that decision
        // (an empty `net_allow` deny-all would silently permit egress). See
        // `NotifPolicy::ip_connect_supervised`.
        if !ctx.policy.ip_connect_supervised(ip.is_loopback()) {
            return NotifAction::Continue;
        }
        let dest_port = parse_port_from_sockaddr(&addr_bytes);
        let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
            Ok(fd) => fd,
            Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
        };
        let protocol = match query_socket_protocol(dup_fd.as_raw_fd()) {
            Some(p) => p,
            None => return NotifAction::Errno(ECONNREFUSED),
        };
        // Decide: verdict on the immune copy, then compute the connect plan
        // (redirect / remap / passthrough) as data while the policy state is
        // locked. Everything after the lock drops is execute-only.
        let ns = ctx.network.lock().await;
        let live_policy = {
            let pfs = ctx.policy_fn.lock().await;
            pfs.live_policy.clone()
        };
        let effective = ns.effective_network_policy(notif.pid, protocol, live_policy.as_ref());
        if let Err(e) = destination_verdict(&effective, ip, dest_port) {
            return NotifAction::Errno(e);
        }
        let proxy = ns
            .http_acl_addr
            .filter(|_| dest_port.map_or(false, |p| ns.http_acl_ports.contains(&p)));
        let remap_port = if ctx.policy.port_remap && ip.is_loopback() {
            dest_port.and_then(|p| ns.port_map.get_real(p))
        } else {
            None
        };
        let orig_dest_map = ns.http_acl_orig_dest.clone();
        drop(ns);

        let plan = match plan_connect_target(&addr_bytes, proxy, remap_port) {
            Ok(p) => p,
            Err(e) => return NotifAction::Errno(e),
        };

        // Execute. Record the original destination *before* connect to prevent
        // a TOCTOU race: the proxy may receive the request before we write the
        // mapping if we did it after connect(). The IP comes from `addr_bytes`
        // (our immune copy). The dup from the SO_PROTOCOL probe above is
        // reused rather than pidfd_getfd-ing a second time.
        if plan.record_orig_dest {
            if let Some(ref map) = orig_dest_map {
                record_orig_dest(map, dup_fd.as_raw_fd(), ip.is_ipv6(), ip);
            }
        }
        connect_dup(dup_fd.as_raw_fd(), &plan.addr)
        // dup_fd dropped here, closing supervisor's copy
    } else {
        // Non-IP family. A NAMED (pathname) AF_UNIX connect is a gap Landlock
        // cannot close (it has no access right for unix-socket connect), so a
        // netns-less sandbox could reach a host service socket and escape.
        // Connecting is a WRITE on the socket inode (kernel: unix_find_other ->
        // path_permission(MAY_WRITE)), so require the path to be covered by an
        // fs-write grant, mirroring the kernel's own DAC; otherwise deny with
        // EACCES. The decision is made on `addr_bytes` (our immune copy) and we
        // never return Continue on the deny path, so it is TOCTOU-safe.
        // Abstract sockets (no path) are handled by the Landlock abstract scope.
        match named_unix_socket_path(&addr_bytes) {
            Some(path) if ctx.policy.has_unix_fs_gate => {
                if ctx.policy.chroot_root.is_some() {
                    // Chroot mode: the child's paths are virtual, so a lexical
                    // check against the (virtual) write grants is consistent,
                    // and host socket paths are absent from the chroot view
                    // anyway. Deny unless under a write grant.
                    if path_under_any(&path, &ctx.policy.chroot_writable) {
                        NotifAction::Continue
                    } else {
                        NotifAction::Errno(libc::EACCES)
                    }
                } else {
                    // Non-chroot: resolve the symlink-followed real target and
                    // connect on-behalf to the pinned inode, so a symlink inside
                    // a granted dir cannot redirect to an ungranted socket.
                    connect_named_unix_on_behalf(
                        notif.pid,
                        sockfd,
                        &path,
                        &ctx.policy.chroot_writable,
                    )
                }
            }
            // Abstract/unnamed socket, non-AF_UNIX family, or gate disabled.
            _ => NotifAction::Continue,
        }
    }
}

/// Execute-phase plan for one IP connect, computed as data by the decide
/// phase: where to actually connect and whether the original destination
/// must be recorded for the HTTP ACL proxy before connecting.
struct ConnectPlan {
    /// Sockaddr bytes to connect to: the child's original destination, the
    /// HTTP ACL proxy, or the original with a remapped loopback port.
    addr: Vec<u8>,
    /// Record (local addr, original dest IP) before connecting so the proxy
    /// can resolve the intended destination (redirect only).
    record_orig_dest: bool,
}

/// Decide phase: pick the connect target from the validated destination and
/// the redirect/remap policy. Pure: no I/O, no locks.
///
/// `proxy` is `Some` when the HTTP ACL intercepts this destination port; the
/// connect is redirected to the proxy and the original destination must be
/// recorded first. `remap_port` is the real bound port when loopback port
/// remap applies; the child sees virtual ports via getsockname(), so the
/// connect targets the real one. Remap never applies to a redirected
/// connect.
fn plan_connect_target(
    addr_bytes: &[u8],
    proxy: Option<std::net::SocketAddr>,
    remap_port: Option<u16>,
) -> Result<ConnectPlan, i32> {
    let is_ipv6 = parse_ip_from_sockaddr(addr_bytes).map_or(false, |ip| ip.is_ipv6());
    if let Some(proxy_addr) = proxy {
        let addr = if is_ipv6 {
            // IPv6 socket: redirect via the IPv4-mapped IPv6 address
            // (::ffff:127.0.0.1) so it connects to the IPv4 proxy.
            let mut sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa6.sin6_family = libc::AF_INET6 as u16;
            sa6.sin6_port = proxy_addr.port().to_be();
            let mapped = match proxy_addr {
                std::net::SocketAddr::V4(v4) => v4.ip().to_ipv6_mapped(),
                std::net::SocketAddr::V6(v6) => *v6.ip(),
            };
            sa6.sin6_addr.s6_addr = mapped.octets();
            unsafe {
                std::slice::from_raw_parts(
                    &sa6 as *const _ as *const u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                )
            }
            .to_vec()
        } else {
            // IPv4 socket: redirect directly.
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = proxy_addr.port().to_be();
            match proxy_addr {
                std::net::SocketAddr::V4(v4) => {
                    sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                }
                std::net::SocketAddr::V6(_) => {
                    // Proxy always binds to 127.0.0.1.
                    return Err(libc::EAFNOSUPPORT);
                }
            }
            unsafe {
                std::slice::from_raw_parts(
                    &sa as *const _ as *const u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                )
            }
            .to_vec()
        };
        return Ok(ConnectPlan {
            addr,
            record_orig_dest: true,
        });
    }
    let mut addr = addr_bytes.to_vec();
    if let Some(real_port) = remap_port {
        set_port_in_sockaddr(&mut addr, real_port);
    }
    Ok(ConnectPlan {
        addr,
        record_orig_dest: false,
    })
}

/// Execute-phase helper for a proxy redirect: bind an ephemeral local address
/// on `fd` (port 0, any address) and read it back with getsockname(), then
/// record (local addr, original destination IP) so the proxy can resolve the
/// intended destination of the connection it is about to receive. Failures
/// are silent, matching the prior behavior: a missed mapping degrades the
/// proxy's view of one connection, it does not block the connect.
fn record_orig_dest(
    map: &crate::transparent_proxy::OrigDestMap,
    fd: RawFd,
    is_ipv6: bool,
    orig_ip: IpAddr,
) {
    let local_addr = if is_ipv6 {
        let mut bind_sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        // port 0 + IN6ADDR_ANY = kernel picks the ephemeral port.
        bind_sa6.sin6_family = libc::AF_INET6 as u16;
        unsafe {
            libc::bind(
                fd,
                &bind_sa6 as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            );
        }
        let mut local_sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut local_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let gs_ret = unsafe {
            libc::getsockname(
                fd,
                &mut local_sa6 as *mut _ as *mut libc::sockaddr,
                &mut local_len,
            )
        };
        if gs_ret != 0 {
            return;
        }
        let local_port = u16::from_be(local_sa6.sin6_port);
        let local_ip = Ipv6Addr::from(local_sa6.sin6_addr.s6_addr);
        std::net::SocketAddr::V6(std::net::SocketAddrV6::new(local_ip, local_port, 0, 0))
    } else {
        let mut bind_sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        // port 0 + INADDR_ANY = kernel picks the ephemeral port.
        bind_sa.sin_family = libc::AF_INET as u16;
        unsafe {
            libc::bind(
                fd,
                &bind_sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
        }
        let mut local_sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut local_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let gs_ret = unsafe {
            libc::getsockname(
                fd,
                &mut local_sa as *mut _ as *mut libc::sockaddr,
                &mut local_len,
            )
        };
        if gs_ret != 0 {
            return;
        }
        let local_port = u16::from_be(local_sa.sin_port);
        let local_ip = Ipv4Addr::from(u32::from_be(local_sa.sin_addr.s_addr));
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(local_ip, local_port))
    };
    if let Ok(mut m) = map.write() {
        m.insert(local_addr, orig_ip);
    }
}

/// Execute-phase tail: connect(2) on the dup'd socket to the planned target.
/// On failure, a stale orig_dest entry is harmless: the proxy never sees this
/// connection, and the entry is overwritten by the next successful request
/// from the same local address (or dropped on shutdown).
fn connect_dup(fd: RawFd, addr: &[u8]) -> NotifAction {
    let ret = unsafe {
        libc::connect(
            fd,
            addr.as_ptr() as *const libc::sockaddr,
            addr.len() as libc::socklen_t,
        )
    };
    if ret == 0 {
        NotifAction::ReturnValue(0)
    } else {
        NotifAction::Errno(unsafe { *libc::__errno_location() })
    }
}


/// Resolve a named unix socket `sun_path` to its real, symlink-followed inode
/// in the child's root view (`/proc/<pid>/root`) and verify that inode is under
/// an fs-write grant. On success returns a pinned `O_PATH` fd to that exact
/// inode; on failure returns the deny/refuse `NotifAction`. Callers must
/// operate on the pinned fd via `/proc/self/fd` so the checked inode is the one
/// acted on, immune to a path swap after the check (TOCTOU- and symlink-safe).
fn resolve_named_unix_target(
    child_pid: u32,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> Result<OwnedFd, NotifAction> {
    // Resolve in the child's mount/root view so its symlinks (not ours) decide
    // the target. `O_PATH` follows symlinks to the real socket inode and pins
    // it without performing any I/O on the socket.
    let proc_path = format!("/proc/{}/root{}", child_pid, sun_path.display());
    let c_proc = std::ffi::CString::new(proc_path)
        .map_err(|_| NotifAction::Errno(libc::EACCES))?;
    let pinned_raw = unsafe { libc::open(c_proc.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if pinned_raw < 0 {
        // Target missing or unreachable: refuse without leaking the reason.
        return Err(NotifAction::Errno(ECONNREFUSED));
    }
    let pinned = unsafe { OwnedFd::from_raw_fd(pinned_raw) };

    // Canonical path of the pinned inode in our mount namespace.
    let real = std::fs::read_link(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .map_err(|_| NotifAction::Errno(libc::EACCES))?;
    if real_path_under_any(&real, writable) {
        Ok(pinned)
    } else {
        Err(NotifAction::Errno(libc::EACCES))
    }
}

/// Build a `sockaddr_un` addressing `/proc/self/fd/<fd>`. The kernel resolves
/// it to the exact pinned inode, so connecting/sending to it targets the inode
/// we validated rather than re-resolving a path string. Returns `None` only if
/// the rendered path would overflow `sun_path` (never, in practice).
fn proc_self_fd_sockaddr(fd: RawFd) -> Option<(libc::sockaddr_un, libc::socklen_t)> {
    let path = format!("/proc/self/fd/{}", fd);
    let bytes = path.as_bytes();
    let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= sun.sun_path.len() {
        return None;
    }
    sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, &b) in bytes.iter().enumerate() {
        sun.sun_path[i] = b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    Some((sun, len))
}

/// On-behalf `connect()` for a NAMED `AF_UNIX` socket in non-chroot mode:
/// resolve+verify the target, then connect the child's socket to the pinned
/// inode through `/proc/self/fd`.
fn connect_named_unix_on_behalf(
    child_pid: u32,
    sockfd: i32,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> NotifAction {
    let pinned = match resolve_named_unix_target(child_pid, sun_path, writable) {
        Ok(fd) => fd,
        Err(action) => return action,
    };
    let (sun, len) = match proc_self_fd_sockaddr(pinned.as_raw_fd()) {
        Some(s) => s,
        None => return NotifAction::Errno(libc::ENAMETOOLONG),
    };
    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(child_pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let ret = unsafe {
        libc::connect(
            dup_fd.as_raw_fd(),
            &sun as *const libc::sockaddr_un as *const libc::sockaddr,
            len,
        )
    };
    if ret == 0 {
        NotifAction::ReturnValue(0)
    } else {
        NotifAction::Errno(unsafe { *libc::__errno_location() })
    }
}

/// On-behalf `sendto()` for a NAMED `AF_UNIX` datagram in non-chroot mode:
/// resolve+verify the target, copy the child's data, then send to the pinned
/// inode through `/proc/self/fd`.
fn sendto_named_unix_on_behalf(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    sockfd: i32,
    buf_ptr: u64,
    buf_len: usize,
    flags: i32,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> NotifAction {
    let pinned = match resolve_named_unix_target(notif.pid, sun_path, writable) {
        Ok(fd) => fd,
        Err(action) => return action,
    };
    let (sun, len) = match proc_self_fd_sockaddr(pinned.as_raw_fd()) {
        Some(s) => s,
        None => return NotifAction::Errno(libc::ENAMETOOLONG),
    };
    let data = match read_child_mem(notif_fd, notif.id, notif.pid, buf_ptr, buf_len) {
        Ok(b) => b,
        Err(_) => return NotifAction::Errno(libc::EIO),
    };
    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    // Route through resolve_send like the sendmsg path instead of an inline
    // blocking sendto: the dup shares the child's blocking mode, so an inline
    // send on the notification loop wedges the whole loop when a child fills a
    // datagram queue it never drains — the same DoS this change fixes elsewhere.
    // The first attempt is non-blocking on the loop; a blocking child's would-
    // block is completed off-loop.
    let addr = unsafe {
        std::slice::from_raw_parts(&sun as *const libc::sockaddr_un as *const u8, len as usize)
    }
    .to_vec();
    let m = MaterializedMsg {
        data,
        control: None,
        addr,
        _scm_fds: Vec::new(),
        _pinned: Some(pinned),
    };
    let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
    resolve_send(dup_fd, m, flags, blocking)
}

/// Apply the named-unix fs gate to a `sendmsg()` whose `msg_name` may address a
/// unix socket. Returns `Some(action)` when the target is a named `AF_UNIX`
/// socket (handled here), or `None` to fall through to the IP path (connected
/// socket, IP family, abstract socket, or an unreadable header).
fn unix_sendmsg_gate(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
    sockfd: i32,
    msghdr_ptr: u64,
    flags: i32,
) -> Option<NotifAction> {
    let hdr = ChildMsghdr::read(notif, notif_fd, msghdr_ptr).ok()?;
    if hdr.connected() {
        return None; // connected socket: no address to gate
    }
    let addr_bytes =
        read_child_mem(notif_fd, notif.id, notif.pid, hdr.name_ptr, hdr.namelen as usize).ok()?;
    // None unless this is a NAMED AF_UNIX target; IP/abstract fall through.
    let path = named_unix_socket_path(&addr_bytes)?;

    if ctx.policy.chroot_root.is_some() {
        return Some(if path_under_any(&path, &ctx.policy.chroot_writable) {
            NotifAction::Continue
        } else {
            NotifAction::Errno(libc::EACCES)
        });
    }
    Some(sendmsg_named_unix_on_behalf(
        notif,
        notif_fd,
        sockfd,
        msghdr_ptr,
        flags,
        &path,
        &ctx.policy.chroot_writable,
    ))
}

/// On-behalf `sendmsg()` for a NAMED `AF_UNIX` datagram in non-chroot mode:
/// resolve+verify the target, copy the message's iovecs and control data, then
/// send to the pinned inode through `/proc/self/fd`.
fn sendmsg_named_unix_on_behalf(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    sockfd: i32,
    msghdr_ptr: u64,
    flags: i32,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> NotifAction {
    match send_named_unix_msghdr(notif, notif_fd, sockfd, msghdr_ptr, sun_path, writable) {
        Ok((dup_fd, m)) => {
            let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
            resolve_send(dup_fd, m, flags, blocking)
        }
        Err(errno) => NotifAction::Errno(errno),
    }
}

/// Core of the named-unix on-behalf `sendmsg`: resolve+verify `sun_path` and
/// copy the message's iovecs/control from the child, addressed to the pinned
/// inode via `/proc/self/fd`. Returns the dup'd socket and a [`MaterializedMsg`]
/// (which keeps the inode pin alive) for the caller to send — inline, and
/// deferred if it would block. Shared by the single-message `sendmsg` path and
/// the per-entry `sendmmsg` path.
fn send_named_unix_msghdr(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    sockfd: i32,
    msghdr_ptr: u64,
    sun_path: &std::path::Path,
    writable: &[std::path::PathBuf],
) -> Result<(OwnedFd, MaterializedMsg), i32> {
    let pinned = match resolve_named_unix_target(notif.pid, sun_path, writable) {
        Ok(fd) => fd,
        Err(NotifAction::Errno(e)) => return Err(e),
        Err(_) => return Err(libc::EACCES),
    };
    let (sun, sun_len) = proc_self_fd_sockaddr(pinned.as_raw_fd()).ok_or(libc::ENAMETOOLONG)?;

    let hdr = ChildMsghdr::read(notif, notif_fd, msghdr_ptr)?;

    // The destination is the `/proc/self/fd/<pinned>` sockaddr; `pinned` must
    // stay open (and at the same fd number) for that path to resolve, so the
    // message keeps it alive. Copy the sockaddr bytes it currently encodes.
    let addr = unsafe {
        std::slice::from_raw_parts(&sun as *const libc::sockaddr_un as *const u8, sun_len as usize)
    }
    .to_vec();

    // Named target is always AF_UNIX, so translate SCM_RIGHTS / reject creds.
    let m = materialize_msg(notif, notif_fd, &hdr, addr, true, Some(pinned))?;

    let dup_fd = crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd)
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF))?;

    Ok((dup_fd, m))
}

/// Read a `sendmmsg` entry's `msg_name` and return its NAMED `AF_UNIX` path, or
/// `None` for a connected (null-name), IP, or abstract entry. The entry's
/// `msghdr` is the first field of `struct mmsghdr`, so it begins at `entry_ptr`.
fn mmsg_entry_named_unix_path(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    entry_ptr: u64,
) -> Option<std::path::PathBuf> {
    let hdr = ChildMsghdr::read(notif, notif_fd, entry_ptr).ok()?;
    if hdr.connected() {
        return None;
    }
    let addr_bytes =
        read_child_mem(notif_fd, notif.id, notif.pid, hdr.name_ptr, hdr.namelen as usize).ok()?;
    named_unix_socket_path(&addr_bytes)
}

/// On-behalf `sendmmsg` for a batch containing NAMED `AF_UNIX` entries
/// (non-chroot). Each named-unix entry is resolved, verified, and sent to its
/// pinned inode; the loop stops at the first entry it cannot gate on-behalf
/// (connected/abstract) or that is denied, returning the count sent so far
/// (standard short-`sendmmsg` semantics). Never returns `Continue`, so a unix
/// entry cannot ride out via the binary whole-call passthrough.
fn sendmmsg_named_unix_on_behalf(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    sockfd: i32,
    msgvec_ptr: u64,
    vlen: usize,
    flags: i32,
    writable: &[std::path::PathBuf],
) -> NotifAction {
    let mut sent: usize = 0;
    let mut first_errno: Option<i32> = None;
    for i in 0..vlen {
        let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
        let path = match mmsg_entry_named_unix_path(notif, notif_fd, entry_ptr) {
            Some(p) => p,
            // Connected/abstract/unreadable entry: cannot gate on-behalf, so
            // stop here and report a short send rather than passing it through.
            None => break,
        };
        let (dup_fd, m) = match send_named_unix_msghdr(notif, notif_fd, sockfd, entry_ptr, &path, writable) {
            Ok(pair) => pair,
            Err(errno) => {
                first_errno = Some(errno);
                break;
            }
        };
        match batch_send_step(
            &dup_fd, m, flags, notif_fd, notif.id, notif.pid,
            mmsg_msglen_addr(entry_ptr), sent,
        ) {
            BatchStep::Sent => sent += 1,
            BatchStep::Done(action) => return action,
            BatchStep::Stop(errno) => {
                if sent == 0 {
                    first_errno = Some(errno);
                }
                break;
            }
        }
    }
    if sent > 0 {
        NotifAction::ReturnValue(sent as i64)
    } else {
        NotifAction::Errno(first_errno.unwrap_or(libc::EACCES))
    }
}

// ============================================================
// sendto_on_behalf / sendmsg_on_behalf — on-behalf (TOCTOU-safe)
// ============================================================

/// Perform sendto() on behalf of the child process (TOCTOU-safe).
///
/// 1. Copy sockaddr from child memory (our copy — immune to TOCTOU)
/// 2. Check IP against allowlist on our copy
/// 3. Copy data buffer from child memory
/// 4. Duplicate child's socket fd via pidfd_getfd
/// 5. sendto() in supervisor with validated sockaddr + copied data
/// 6. Return byte count or errno
///
/// Only triggers for unconnected sends (addr_ptr != NULL), which is
/// primarily UDP. Connected sockets (addr_ptr == NULL) use CONTINUE.
async fn sendto_on_behalf(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let args = &notif.data.args;
    let sockfd = args[0] as i32;
    let buf_ptr = args[1];
    let buf_len = args[2] as usize;
    if buf_len > MAX_SEND_BUF {
        return NotifAction::Errno(libc::EMSGSIZE);
    }
    let flags = args[3] as i32;
    let addr_ptr = args[4];
    let addr_len = args[5] as u32;

    if addr_ptr == 0 {
        return NotifAction::Continue; // connected socket, no addr to check
    }

    // 1. Copy sockaddr from child memory (small: 16-28 bytes)
    let addr_bytes =
        match read_child_mem(notif_fd, notif.id, notif.pid, addr_ptr, addr_len as usize) {
            Ok(b) => b,
            Err(_) => return NotifAction::Errno(libc::EIO),
        };

    // 2. Check (ip, port) against the per-protocol endpoint allowlist.
    // One pidfd_getfd serves both the SO_PROTOCOL probe and the
    // on-behalf sendto.
    if let Some(ip) = parse_ip_from_sockaddr(&addr_bytes) {
        let dest_port = parse_port_from_sockaddr(&addr_bytes);
        let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
            Ok(fd) => fd,
            Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
        };
        let protocol = match query_socket_protocol(dup_fd.as_raw_fd()) {
            Some(p) => p,
            None => return NotifAction::Errno(ECONNREFUSED),
        };
        if let Err(e) = check_ip_destination(ctx, notif.pid, protocol, ip, dest_port).await {
            return NotifAction::Errno(e);
        }

        // 3. Copy data buffer from child memory
        let data = match read_child_mem(notif_fd, notif.id, notif.pid, buf_ptr, buf_len) {
            Ok(b) => b,
            Err(_) => return NotifAction::Errno(libc::EIO),
        };

        // 4. Send on-behalf (deferred if it would block), like sendmsg — a
        // sendto is a sendmsg with a single iovec and an explicit destination.
        // The first attempt is non-blocking on the loop; a blocking child whose
        // send buffer is full defers off the loop instead of wedging it.
        let m = MaterializedMsg {
            data,
            control: None,
            addr: addr_bytes,
            _scm_fds: Vec::new(),
            _pinned: None,
        };
        let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
        resolve_send(dup_fd, m, flags, blocking)
    } else {
        // Non-IP family. Gate a NAMED AF_UNIX datagram the same way as connect:
        // sendto to a named socket is a WRITE on its inode, so deny unless the
        // resolved real target is under an fs-write grant.
        match named_unix_socket_path(&addr_bytes) {
            Some(path) if ctx.policy.has_unix_fs_gate => {
                if ctx.policy.chroot_root.is_some() {
                    if path_under_any(&path, &ctx.policy.chroot_writable) {
                        NotifAction::Continue
                    } else {
                        NotifAction::Errno(libc::EACCES)
                    }
                } else {
                    sendto_named_unix_on_behalf(
                        notif,
                        notif_fd,
                        sockfd,
                        buf_ptr,
                        buf_len,
                        flags,
                        &path,
                        &ctx.policy.chroot_writable,
                    )
                }
            }
            _ => NotifAction::Continue,
        }
    }
}

/// Perform sendmsg() on behalf of the child process (TOCTOU-safe).
///
/// 1. Copy full msghdr from child memory
/// 2. Copy sockaddr from msg_name (our copy — immune to TOCTOU)
/// 3. Check IP against allowlist on our copy
/// 4. Copy iovec data buffers from child memory
/// 5. Copy control message buffer from child memory
/// 6. Duplicate child's socket fd via pidfd_getfd
/// 7. sendmsg() in supervisor with validated sockaddr + copied data
/// 8. Return byte count or errno
async fn sendmsg_on_behalf(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let args = &notif.data.args;
    let sockfd = args[0] as i32;
    let msghdr_ptr = args[1];
    let flags = args[2] as i32;

    // Named-unix datagram gate. A named AF_UNIX `msg_name` is handled here; the
    // IP path below only covers AF_INET/AF_INET6, and would pass a unix target
    // straight through.
    if ctx.policy.has_unix_fs_gate {
        if let Some(action) = unix_sendmsg_gate(notif, ctx, notif_fd, sockfd, msghdr_ptr, flags) {
            return action;
        }
    }

    // With a destination policy active, never Continue: the kernel would
    // re-read `msg_name` from child memory, where a racing thread could swap a
    // connected (NULL) name for a denied address. Send on-behalf (including
    // connected sends) so the verdict is made on the immune copy. Without a
    // policy there is nothing to bypass, so the Continue fast path below stands.
    let dest_policy = ctx.policy.has_net_destination_policy;
    if !dest_policy {
        // Pre-scan for Continue cases (connected socket / non-IP family).
        // EFAULT on unreadable msghdr (vs. Continue, which would let the kernel
        // re-read child memory and bypass our check).
        match prescan_msghdr(notif, notif_fd, msghdr_ptr) {
            PrescanResult::ContinueWholeCall => return NotifAction::Continue,
            PrescanResult::Errno(e) => return NotifAction::Errno(e),
            PrescanResult::OnBehalf => {}
        }
    }

    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    // Resolve the protocol as `Option`: it is only consumed to validate a
    // non-connected IP destination. `query_socket_protocol` returns `None` for
    // an AF_UNIX socket (no IP protocol), and a connected send (every AF_UNIX
    // send that reaches here — its connection was gated at connect time) never
    // consumes it, so the send goes through the TOCTOU-safe on-behalf path on
    // our immune `dup_fd` rather than being refused. A non-connected send with
    // no resolvable protocol fails closed inside `send_msghdr_on_behalf`.
    //
    // On-behalf (not Continue) is load-bearing under a destination policy: a
    // Continue would let the kernel re-resolve `sockfd`/`msg_name` against the
    // live child, so a racing `dup2(inet_sock, sockfd)` after a domain check
    // could redirect the send onto an IP socket to a denied destination.
    let protocol = query_socket_protocol(dup_fd.as_raw_fd());

    match send_msghdr_on_behalf(notif, ctx, notif_fd, &dup_fd, protocol, msghdr_ptr).await {
        Ok(m) => {
            let blocking = wants_blocking(dup_fd.as_raw_fd(), flags);
            resolve_send(dup_fd, m, flags, blocking)
        }
        Err(errno) => NotifAction::Errno(errno),
    }
}

// ============================================================
// prescan_msghdr / send_msghdr_on_behalf — shared per-message work
// ============================================================

#[derive(Clone, Copy)]
enum PrescanResult {
    /// All fields present, IP-family destination — caller can take the
    /// on-behalf path with `send_msghdr_on_behalf`.
    OnBehalf,
    /// `msg_name == NULL` (connected socket) or non-IP family
    /// (AF_UNIX etc.). Caller should return `NotifAction::Continue` so
    /// the kernel handles the syscall in the child's namespace —
    /// AF_UNIX path resolution is the canonical reason we don't take
    /// these messages on behalf.
    ContinueWholeCall,
    /// Memory read failure. Caller maps to the appropriate errno
    /// (EFAULT for unreadable msghdr, EIO for the sockaddr).
    Errno(i32),
}

/// Probe one `struct msghdr` to decide whether the on-behalf path
/// applies. Used by both `sendmsg_on_behalf` (one msghdr) and
/// `sendmmsg_on_behalf` (one per `mmsghdr` entry, before doing any
/// sends — Continue is a whole-syscall decision).
fn prescan_msghdr(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    msghdr_ptr: u64,
) -> PrescanResult {
    let hdr = match ChildMsghdr::read(notif, notif_fd, msghdr_ptr) {
        Ok(h) => h,
        Err(e) => return PrescanResult::Errno(e),
    };
    if hdr.connected() {
        return PrescanResult::ContinueWholeCall;
    }
    let addr_bytes = match read_child_mem(notif_fd, notif.id, notif.pid, hdr.name_ptr, hdr.namelen as usize) {
        Ok(b) => b,
        Err(_) => return PrescanResult::Errno(libc::EIO),
    };
    if parse_ip_from_sockaddr(&addr_bytes).is_none() {
        return PrescanResult::ContinueWholeCall;
    }
    PrescanResult::OnBehalf
}

/// Validate, materialize, and send one `struct msghdr` on behalf of
/// the child. Caller is responsible for:
///   - dup'ing the child fd (`dup_fd`),
///   - resolving the socket protocol (`protocol`) via
///     `query_socket_protocol` on that dup.
///
/// `protocol` is `Option` because it is only consumed to validate a
/// *non-connected* IP destination against the allowlist. A connected send
/// (`msg_name == NULL`) — which is every send that reaches here on an AF_UNIX
/// socket, since its connection was already gated at connect time — carries no
/// destination and needs no protocol, so `None` is passed through unused. When
/// the message *is* non-connected, a missing protocol fails closed
/// (`ECONNREFUSED`), so an IP send whose protocol can't be resolved is refused
/// rather than escaping the allowlist.
///
/// Returns a [`MaterializedMsg`] the caller sends (inline and, if it would
/// block, deferred) via [`resolve_send`] / [`send_materialized`]; or an errno.
/// ECONNREFUSED is used both for "destination blocked by policy" and for
/// "couldn't parse a port from the sockaddr"; EIO for sub-buffer read failures.
async fn send_msghdr_on_behalf(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
    dup_fd: &std::os::unix::io::OwnedFd,
    protocol: Option<Protocol>,
    msghdr_ptr: u64,
) -> Result<MaterializedMsg, i32> {
    let hdr = ChildMsghdr::read(notif, notif_fd, msghdr_ptr)?;

    // A connected socket carries no per-message address (`msg_name == NULL` or
    // zero length). There is nothing to check against the destination
    // allowlist (the connection was gated at connect time), but we must still
    // send it on-behalf rather than Continue: Continue lets the kernel re-read
    // the msghdr from child memory, where a racing thread could have swapped a
    // null `msg_name` for a denied address. A non-connected entry has its IP
    // destination validated on the immune copy before the send.
    let connected = hdr.connected();
    let addr_bytes = if connected {
        Vec::new()
    } else {
        match read_child_mem(notif_fd, notif.id, notif.pid, hdr.name_ptr, hdr.namelen as usize) {
            Ok(b) => b,
            Err(_) => return Err(libc::EIO),
        }
    };
    if !connected {
        let ip = match parse_ip_from_sockaddr(&addr_bytes) {
            Some(ip) => ip,
            // A non-IP, non-connected address on an IP send path (e.g. the
            // sockaddr changed under us). Fail closed.
            None => return Err(libc::EAFNOSUPPORT),
        };
        let dest_port = parse_port_from_sockaddr(&addr_bytes);
        // A non-connected IP send must have a resolved protocol to key the
        // per-protocol allowlist. If it couldn't be resolved, fail closed.
        let protocol = protocol.ok_or(ECONNREFUSED)?;
        check_ip_destination(ctx, notif.pid, protocol, ip, dest_port).await?;
    }

    // Translate SCM_RIGHTS / reject creds only for a unix socket; an IP socket's
    // control carries no fds or credentials and passes through untouched.
    // (`addr_bytes` is already empty for a connected send.)
    materialize_msg(
        notif,
        notif_fd,
        &hdr,
        addr_bytes,
        socket_is_unix(dup_fd.as_raw_fd()),
        None,
    )
}

// ============================================================
// sendmmsg_on_behalf — multi-message variant
// ============================================================

/// Cap on the number of messages we'll process per sendmmsg call.
/// Linux's UIO_MAXIOV is 1024; lower here to bound supervisor work
/// per syscall (each entry costs at minimum a few read_child_mem
/// hops + one sendmsg).
const MAX_MMSGHDR_ENTRIES: usize = 256;

/// Perform `sendmmsg()` on behalf of the child. Pre-scans every entry
/// for Continue cases (NULL `msg_name` or non-IP family) — if any
/// entry would Continue, we Continue the whole syscall to match
/// `sendmsg_on_behalf`'s coarse-grained behavior. Otherwise dup the
/// child fd once, query SO_PROTOCOL once, then loop:
/// validate → send → write `msg_len` back to the child's mmsghdr.
///
/// On partial failure (entry K denied or send fails), returns
/// `ReturnValue(K)` matching the kernel's "messages successfully
/// transmitted" semantics. Returns the errno only when the very first
/// entry fails — otherwise the child sees a positive count and reads
/// per-entry `msg_len` to learn the per-message status.
async fn sendmmsg_on_behalf(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let args = &notif.data.args;
    let sockfd = args[0] as i32;
    let msgvec_ptr = args[1];
    let vlen = (args[2] as u32 as usize).min(MAX_MMSGHDR_ENTRIES);
    let flags = args[3] as i32;

    if vlen == 0 {
        return NotifAction::ReturnValue(0);
    }

    // Named-unix gate. If any entry targets a named AF_UNIX socket, handle the
    // whole batch here: the existing prescan below would Continue the entire
    // call on the first non-IP entry, which would let a unix entry bypass the
    // gate.
    if ctx.policy.has_unix_fs_gate {
        let mut named_unix = false;
        for i in 0..vlen {
            let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
            if mmsg_entry_named_unix_path(notif, notif_fd, entry_ptr).is_some() {
                named_unix = true;
                break;
            }
        }
        if named_unix {
            if ctx.policy.chroot_root.is_some() {
                // Chroot: lexical check; deny the whole call if any named-unix
                // entry is outside the (virtual) write grants.
                for i in 0..vlen {
                    let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
                    if let Some(path) = mmsg_entry_named_unix_path(notif, notif_fd, entry_ptr) {
                        if !path_under_any(&path, &ctx.policy.chroot_writable) {
                            return NotifAction::Errno(libc::EACCES);
                        }
                    }
                }
                // All granted: fall through to the existing path.
            } else {
                return sendmmsg_named_unix_on_behalf(
                    notif,
                    notif_fd,
                    sockfd,
                    msgvec_ptr,
                    vlen,
                    flags,
                    &ctx.policy.chroot_writable,
                );
            }
        }
    }

    // Destination policy active: handle the whole batch on-behalf and never
    // Continue. Continue would let the kernel re-read each `msghdr` from child
    // memory, where a racing thread could swap a connected (NULL `msg_name`)
    // entry for a denied address after our prescan, bypassing the allowlist on
    // an unconnected datagram socket. On-behalf sends use the immune copy and
    // validate every IP destination, so the verdict is TOCTOU-free.
    if ctx.policy.has_net_destination_policy {
        let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
            Ok(fd) => fd,
            Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
        };
        // Protocol is resolved as `Option` and consumed only by a non-connected
        // IP entry (see `send_msghdr_on_behalf`). It is `None` for an AF_UNIX
        // socket — whose connected entries send through the immune `dup_fd`
        // without a destination check — so the batch is handled on-behalf here
        // rather than refused with ECONNREFUSED. On-behalf (not Continue) keeps
        // it TOCTOU-safe against a racing fd swap.
        let protocol = query_socket_protocol(dup_fd.as_raw_fd());
        let mut sent: usize = 0;
        let mut first_errno: Option<i32> = None;
        for i in 0..vlen {
            let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
            let m = match send_msghdr_on_behalf(notif, ctx, notif_fd, &dup_fd, protocol, entry_ptr)
                .await
            {
                Ok(m) => m,
                Err(errno) => {
                    first_errno = Some(errno);
                    break;
                }
            };
            match batch_send_step(
                &dup_fd, m, flags, notif_fd, notif.id, notif.pid,
                mmsg_msglen_addr(entry_ptr), sent,
            ) {
                BatchStep::Sent => sent += 1,
                BatchStep::Done(action) => return action,
                BatchStep::Stop(errno) => {
                    if sent == 0 {
                        first_errno = Some(errno);
                    }
                    break;
                }
            }
        }
        return if sent > 0 {
            NotifAction::ReturnValue(sent as i64)
        } else {
            NotifAction::Errno(first_errno.unwrap_or(ECONNREFUSED))
        };
    }

    // No destination policy: the connected fast path is safe (nothing to
    // bypass), so Continue is acceptable. Pre-scan every entry; if any has a
    // Continue-eligible shape (NULL msg_name or non-IP family), Continue the
    // whole sendmmsg. Mixed-shape calls aren't supported because Continue is
    // binary at the syscall level.
    for i in 0..vlen {
        let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
        match prescan_msghdr(notif, notif_fd, entry_ptr) {
            PrescanResult::OnBehalf => continue,
            PrescanResult::ContinueWholeCall => return NotifAction::Continue,
            PrescanResult::Errno(e) => return NotifAction::Errno(e),
        }
    }

    let dup_fd = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, sockfd) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let protocol = match query_socket_protocol(dup_fd.as_raw_fd()) {
        Some(p) => p,
        None => return NotifAction::Errno(ECONNREFUSED),
    };

    let mut sent: usize = 0;
    let mut first_errno: Option<i32> = None;

    for i in 0..vlen {
        let entry_ptr = mmsg_entry_ptr(msgvec_ptr, i);
        // Every entry is OnBehalf (IP, non-connected) per the prescan above, so
        // the resolved protocol is always required and present here.
        let m = match send_msghdr_on_behalf(notif, ctx, notif_fd, &dup_fd, Some(protocol), entry_ptr).await {
            Ok(m) => m,
            Err(errno) => {
                first_errno = Some(errno);
                break;
            }
        };
        match batch_send_step(
            &dup_fd, m, flags, notif_fd, notif.id, notif.pid,
            mmsg_msglen_addr(entry_ptr), sent,
        ) {
            BatchStep::Sent => sent += 1,
            BatchStep::Done(action) => return action,
            BatchStep::Stop(errno) => {
                if sent == 0 {
                    first_errno = Some(errno);
                }
                break;
            }
        }
    }

    if sent > 0 {
        NotifAction::ReturnValue(sent as i64)
    } else {
        // Defensive: vlen > 0 + no successes means at least one attempt
        // failed, so first_errno is set. Fall back to ECONNREFUSED
        // rather than panicking on the unwrap if invariants ever drift.
        NotifAction::Errno(first_errno.unwrap_or(ECONNREFUSED))
    }
}

// ============================================================
// handle_net — main handler for connect/sendto/sendmsg
// ============================================================

/// Handle network-related notifications (connect, sendto, sendmsg).
///
/// All three are handled on-behalf (TOCTOU-safe): the supervisor copies data
/// from child memory, validates the destination, duplicates the socket via
/// pidfd_getfd, and performs the syscall itself. The child's memory is never
/// re-read by the kernel after validation.
///
/// Continue safety (issue #27): the on-behalf paths don't return Continue
/// at all (they return ReturnValue/Errno after performing the syscall in
/// the supervisor). The Continue cases in this module are:
///   1. Non-IP families (AF_UNIX etc.) — the IP allowlist doesn't apply;
///      Landlock IPC scoping is the enforcement boundary.
///   2. Connected sockets with addr_ptr == 0 — the address was already
///      validated at connect time, so the kernel re-read of (nothing) is
///      moot.
///   3. The fall-through case below — only reachable if the BPF filter
///      mis-routes a syscall; the kernel handles it normally.
/// In sendmsg_on_behalf, the msghdr read failure path returns
/// Errno(EFAULT) rather than Continue: a racing thread that briefly
/// unmaps the msghdr could otherwise force a fall-through that lets the
/// kernel execute sendmsg without the allowlist check. Sub-buffer read
/// failures (sockaddr/iovec/control) already return Errno(EIO) and so
/// don't bypass the check either.
pub(crate) async fn handle_net(
    notif: &SeccompNotif,
    ctx: &Arc<SupervisorCtx>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    if nr == libc::SYS_connect {
        connect_on_behalf(notif, ctx, notif_fd).await
    } else if nr == libc::SYS_sendto {
        sendto_on_behalf(notif, ctx, notif_fd).await
    } else if nr == libc::SYS_sendmsg {
        sendmsg_on_behalf(notif, ctx, notif_fd).await
    } else if nr == libc::SYS_sendmmsg {
        sendmmsg_on_behalf(notif, ctx, notif_fd).await
    } else {
        NotifAction::Continue
    }
}


// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- plan_connect_target tests (connect decide phase) ---

    fn v4_sockaddr(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as u16;
        sa.sin_port = port.to_be();
        sa.sin_addr.s_addr = u32::from_ne_bytes(ip);
        unsafe {
            std::slice::from_raw_parts(
                &sa as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            )
        }
        .to_vec()
    }

    fn v6_sockaddr(port: u16) -> Vec<u8> {
        let mut sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sa6.sin6_family = libc::AF_INET6 as u16;
        sa6.sin6_port = port.to_be();
        sa6.sin6_addr.s6_addr = std::net::Ipv6Addr::LOCALHOST.octets();
        unsafe {
            std::slice::from_raw_parts(
                &sa6 as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_in6>(),
            )
        }
        .to_vec()
    }

    #[test]
    fn plan_passthrough_keeps_original_bytes() {
        let a = v4_sockaddr([10, 0, 0, 1], 443);
        let plan = plan_connect_target(&a, None, None).unwrap();
        assert_eq!(plan.addr, a);
        assert!(!plan.record_orig_dest);
    }

    #[test]
    fn plan_remap_rewrites_only_the_port() {
        let a = v4_sockaddr([127, 0, 0, 1], 8080);
        let plan = plan_connect_target(&a, None, Some(41234)).unwrap();
        assert_eq!(parse_port_from_sockaddr(&plan.addr), Some(41234));
        assert_eq!(
            parse_ip_from_sockaddr(&plan.addr),
            parse_ip_from_sockaddr(&a)
        );
        assert!(!plan.record_orig_dest);
    }

    #[test]
    fn plan_v4_proxy_redirects_v4_destination() {
        let a = v4_sockaddr([93, 184, 216, 34], 80);
        let proxy: std::net::SocketAddr = "127.0.0.1:3128".parse().unwrap();
        let plan = plan_connect_target(&a, Some(proxy), None).unwrap();
        assert_eq!(
            parse_ip_from_sockaddr(&plan.addr),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(parse_port_from_sockaddr(&plan.addr), Some(3128));
        assert!(plan.record_orig_dest);
    }

    #[test]
    fn plan_proxy_on_v6_destination_uses_mapped_address() {
        let a = v6_sockaddr(80);
        let proxy: std::net::SocketAddr = "127.0.0.1:3128".parse().unwrap();
        let plan = plan_connect_target(&a, Some(proxy), None).unwrap();
        assert_eq!(
            parse_ip_from_sockaddr(&plan.addr),
            Some("::ffff:127.0.0.1".parse().unwrap())
        );
        assert_eq!(parse_port_from_sockaddr(&plan.addr), Some(3128));
        assert!(plan.record_orig_dest);
    }

    #[test]
    fn plan_v6_proxy_on_v4_destination_fails_closed() {
        let a = v4_sockaddr([93, 184, 216, 34], 80);
        let proxy: std::net::SocketAddr = "[::1]:3128".parse().unwrap();
        assert_eq!(
            plan_connect_target(&a, Some(proxy), None).map(|p| p.addr),
            Err(libc::EAFNOSUPPORT)
        );
    }

    #[test]
    fn plan_remap_does_not_apply_to_redirect() {
        let a = v4_sockaddr([127, 0, 0, 1], 8080);
        let proxy: std::net::SocketAddr = "127.0.0.1:3128".parse().unwrap();
        let plan = plan_connect_target(&a, Some(proxy), Some(41234)).unwrap();
        assert_eq!(parse_port_from_sockaddr(&plan.addr), Some(3128));
        assert!(plan.record_orig_dest);
    }

}

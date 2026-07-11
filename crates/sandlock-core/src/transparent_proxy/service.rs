// Per-request handling shared by the plaintext and TLS-terminated paths:
// reconstruct the absolute URL, verify the claimed host against the orig-dest
// IP, apply the HTTP ACL, and forward allowed requests upstream.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use tokio::sync::Mutex;

use super::upstream::{box_incoming, Forwarder};
use crate::credential::InjectRule;
use crate::http::{http_acl_check, HttpRule};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type OrigDestMap = Arc<std::sync::RwLock<HashMap<SocketAddr, IpAddr>>>;

const DNS_CACHE_TTL: Duration = Duration::from_secs(30);

struct DnsEntry {
    ips: Vec<IpAddr>,
    expires: Instant,
}

/// Shared, cloneable state for the request handler.
#[derive(Clone)]
pub(crate) struct AclService {
    pub(crate) allow: Arc<Vec<HttpRule>>,
    pub(crate) deny: Arc<Vec<HttpRule>>,
    pub(crate) inject: Arc<Vec<InjectRule>>,
    pub(crate) orig_dest: OrigDestMap,
    pub(crate) forwarder: Forwarder,
    dns_cache: Arc<Mutex<HashMap<String, DnsEntry>>>,
    /// Latched once the first cleartext (`http`) credential injection is warned,
    /// so a library/API caller gets the warning once per run instead of per
    /// request. See [`first_cleartext_warn`].
    cleartext_warned: Arc<AtomicBool>,
}

/// Whether this cleartext injection should emit the one-per-run warning: true the
/// first time a credential is injected over plaintext `http` (and latches `seen`),
/// false afterwards and always false for `https`. Split out so the warn-once
/// contract is unit-tested without capturing the supervisor's stderr.
fn first_cleartext_warn(scheme: &str, seen: &AtomicBool) -> bool {
    scheme == "http" && !seen.swap(true, Ordering::Relaxed)
}

/// Whether a request must be rejected because its absolute-form URI authority
/// host disagrees (case-insensitive) with its `Host` header — the split that
/// would otherwise let ACL/verify/inject key off one host while the request is
/// forwarded to the other. Origin-form requests (no URI host) and a missing /
/// unparseable Host header are not rejected. Split out so the guard is
/// unit-tested without a live `Incoming` body.
fn split_host_rejected(uri: &hyper::Uri, headers: &hyper::HeaderMap) -> bool {
    let Some(uri_host) = uri.host() else { return false };
    match headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h))
    {
        Some(hdr_host) => !uri_host.eq_ignore_ascii_case(hdr_host),
        None => false,
    }
}

impl AclService {
    pub(crate) fn new(
        allow: Vec<HttpRule>,
        deny: Vec<HttpRule>,
        inject: Arc<Vec<InjectRule>>,
        orig_dest: OrigDestMap,
        forwarder: Forwarder,
    ) -> Self {
        Self {
            allow: Arc::new(allow),
            deny: Arc::new(deny),
            inject,
            orig_dest,
            forwarder,
            dns_cache: Arc::new(Mutex::new(HashMap::new())),
            cleartext_warned: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn resolve_cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        {
            let cache = self.dns_cache.lock().await;
            if let Some(e) = cache.get(host) {
                if e.expires > Instant::now() {
                    return Some(e.ips.clone());
                }
            }
        }
        let resolved = tokio::net::lookup_host(format!("{host}:0")).await.ok()?;
        let ips: Vec<IpAddr> = resolved.map(|sa| sa.ip()).collect();
        let mut cache = self.dns_cache.lock().await;
        cache.insert(
            host.to_string(),
            DnsEntry {
                ips: ips.clone(),
                expires: Instant::now() + DNS_CACHE_TTL,
            },
        );
        Some(ips)
    }

    async fn verify_host(&self, client_addr: &SocketAddr, claimed_host: &str) -> bool {
        let orig_ip = {
            let map = self.orig_dest.read().unwrap_or_else(|e| e.into_inner());
            map.get(client_addr).copied()
        };
        let orig_ip = match orig_ip {
            Some(ip) => ip,
            None => return true,
        };
        if let Ok(ip) = claimed_host.parse::<IpAddr>() {
            return ip == orig_ip;
        }
        match self.resolve_cached(claimed_host).await {
            Some(ips) => ips.iter().any(|ip| *ip == orig_ip),
            None => false,
        }
    }

    /// Handle one request. `scheme` is "https" for the MITM path, "http" for plaintext.
    pub(crate) async fn handle(
        &self,
        client_addr: SocketAddr,
        scheme: &str,
        req: Request<hyper::body::Incoming>,
    ) -> Response<BoxBody<Bytes, BoxError>> {
        let method = req.method().as_str().to_string();
        let host = req
            .uri()
            .host()
            .map(|h| h.to_string())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|h| h.split(':').next().unwrap_or(h).to_string())
            })
            .unwrap_or_default();
        let path = req.uri().path().to_string();

        // Fail closed on a split-host request: `host` above prefers the URI
        // authority, but the outbound request is rebuilt from the Host header
        // (`host_hdr` below), and the upstream client routes by that. If the two
        // disagree, the ACL check, `verify_host`, and the credential match would
        // all key off the URI host while the request — carrying the injected
        // secret — is forwarded to the Host-header host. A malicious child could
        // then send `GET https://allowed.example/… ` with `Host: attacker` and
        // exfiltrate the credential cross-origin (and bypass the egress ACL).
        // Requiring the two to agree collapses them to one destination; origin-
        // form requests (no URI authority) are unaffected.
        if split_host_rejected(req.uri(), req.headers()) {
            return text_response(
                StatusCode::FORBIDDEN,
                "Blocked by sandlock: request-target host does not match the Host header",
            );
        }

        if !self.verify_host(&client_addr, &host).await {
            if let Ok(mut m) = self.orig_dest.write() {
                m.remove(&client_addr);
            }
            return text_response(
                StatusCode::FORBIDDEN,
                "Blocked by sandlock: Host header does not match connection destination",
            );
        }
        if let Ok(mut m) = self.orig_dest.write() {
            m.remove(&client_addr);
        }

        if !http_acl_check(&self.allow, &self.deny, &method, &host, &path) {
            return text_response(StatusCode::FORBIDDEN, "Blocked by sandlock HTTP ACL policy");
        }

        // Rebuild an absolute-URI request for the upstream client.
        let host_hdr = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| host.clone());
        let pq = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();
        let uri: hyper::Uri = match format!("{scheme}://{host_hdr}{pq}").parse() {
            Ok(u) => u,
            Err(_) => return text_response(StatusCode::BAD_GATEWAY, "bad upstream URI"),
        };

        let (mut parts, body) = req.into_parts();
        parts.uri = uri;

        // ACL passed: attach a credential if a rule matches. First match wins.
        // The secret is rendered into the outbound request only here — never on
        // the deny path above — and only its name is recorded, never the value.
        for r in self.inject.iter() {
            if r.matches(&method, &host, &path) {
                match r.apply(&mut parts) {
                    Err(()) => {
                        // Rendering failed (e.g. the secret has bytes illegal in a
                        // header) — fail the request rather than forward it with no
                        // credential, which would look like an auth bug to the caller.
                        eprintln!(
                            "sandlock: credential {:?} could not be rendered for {} {}{} — rejecting",
                            r.name, method, host, path
                        );
                        return text_response(
                            StatusCode::BAD_GATEWAY,
                            "Blocked by sandlock: credential could not be applied",
                        );
                    }
                    Ok(crate::credential::Applied::Skipped) => {
                        // add-only and the caller already set the target — keep
                        // theirs and record it truthfully (not as an injection).
                        eprintln!(
                            "sandlock: kept caller-supplied credential {:?} for {} {}{} (add-only)",
                            r.name, method, host, path
                        );
                    }
                    Ok(crate::credential::Applied::Injected) => {
                        eprintln!(
                            "sandlock: injected credential {:?} for {} {}{}",
                            r.name, method, host, path
                        );
                        // Fires for any caller (library/API, not just the CLI) since the
                        // proxy is in core: the scheme is only known here at request time.
                        // Once per run — over cleartext the secret is exposed on the wire.
                        if first_cleartext_warn(scheme, &self.cleartext_warned) {
                            eprintln!(
                                "sandlock: warning: credential {:?} injected over cleartext HTTP (no TLS) \
                                 to {} — the secret is exposed on the wire; prefer an HTTPS host \
                                 (configure MITM via --http-ca / --http-inject-ca)",
                                r.name, host
                            );
                        }
                    }
                }
                // First match wins whether it injected or deliberately kept the
                // caller's value.
                break;
            }
        }

        let out_req = Request::from_parts(parts, box_incoming(body));

        match self.forwarder.forward(out_req).await {
            Ok(resp) => resp,
            Err(_) => text_response(StatusCode::BAD_GATEWAY, "upstream error"),
        }
    }
}

fn text_response(status: StatusCode, msg: &str) -> Response<BoxBody<Bytes, BoxError>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(msg.to_string())).map_err(|e| match e {}).boxed())
        .expect("response build")
}

#[cfg(test)]
mod tests {
    use super::{first_cleartext_warn, split_host_rejected};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn cleartext_warns_once_and_https_never() {
        let seen = AtomicBool::new(false);
        // First cleartext injection warns and latches; later ones are silent.
        assert!(first_cleartext_warn("http", &seen));
        assert!(!first_cleartext_warn("http", &seen));
        // https never warns, and must not consume a fresh latch.
        let fresh = AtomicBool::new(false);
        assert!(!first_cleartext_warn("https", &fresh));
        assert!(!fresh.load(Ordering::Relaxed));
        assert!(first_cleartext_warn("http", &fresh));
    }

    fn rejected(uri: &str, host: Option<&str>) -> bool {
        let uri: hyper::Uri = uri.parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        if let Some(h) = host {
            headers.insert("host", h.parse().unwrap());
        }
        split_host_rejected(&uri, &headers)
    }

    #[test]
    fn split_host_guard_rejects_only_a_real_mismatch() {
        // The exfiltration case: absolute-form allowed host, spoofed Host header.
        assert!(rejected("http://allowed.example/v1", Some("attacker.example")));
        // Agreement (incl. case-insensitive, and a port on either side) is fine.
        assert!(!rejected("http://allowed.example/v1", Some("allowed.example")));
        assert!(!rejected("http://allowed.example/v1", Some("ALLOWED.EXAMPLE")));
        assert!(!rejected("http://allowed.example/v1", Some("allowed.example:8080")));
        assert!(!rejected("http://allowed.example:443/v1", Some("allowed.example")));
        // Origin-form (no URI authority) and a missing Host header don't reject.
        assert!(!rejected("/v1", Some("anything.example")));
        assert!(!rejected("http://allowed.example/v1", None));
    }
}

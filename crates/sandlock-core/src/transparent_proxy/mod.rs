mod service;
mod tls;
mod upstream;

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::LazyConfigAcceptor;

use crate::http::HttpRule;
use self::service::AclService;
use self::tls::CertSigner;
use self::upstream::Forwarder;

pub(crate) use self::service::OrigDestMap;

/// Handle returned by [`spawn_transparent_proxy`]. Dropping it shuts the proxy down.
pub(crate) struct HttpAclProxyHandle {
    pub(crate) addr: SocketAddr,
    pub(crate) orig_dest: OrigDestMap,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Drop for HttpAclProxyHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// A TLS record/handshake always begins with content-type 0x16 (handshake).
/// A plaintext HTTP request never does (it starts with an ASCII method letter).
fn is_tls_client_hello(first_byte: u8) -> bool {
    first_byte == 0x16
}

/// Spawn the transparent HTTP/HTTPS ACL proxy. When `ca_cert_pem`/`ca_key_pem`
/// are provided, TLS connections are MITM-terminated with a per-SNI leaf cert
/// minted from that CA; otherwise TLS connections are closed (443 is only
/// redirected here when a CA is configured) and plaintext HTTP is served.
pub(crate) async fn spawn_transparent_proxy(
    allow: Vec<HttpRule>,
    deny: Vec<HttpRule>,
    ca_cert_pem: Option<&str>,
    ca_key_pem: Option<&str>,
) -> std::io::Result<HttpAclProxyHandle> {
    // rustls 0.22 builder() uses the ring provider directly; no provider install needed.
    let orig_dest: OrigDestMap =
        Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
    let forwarder = Forwarder::new()?;
    let svc = AclService::new(allow, deny, Arc::clone(&orig_dest), forwarder);

    let signer = match (ca_cert_pem, ca_key_pem) {
        (Some(c), Some(k)) => Some(Arc::new(CertSigner::new(c, k)?)),
        _ => None,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            let accept = tokio::select! {
                _ = &mut shutdown_rx => break,
                r = listener.accept() => r,
            };
            let (stream, peer) = match accept {
                Ok(v) => v,
                Err(_) => continue,
            };
            let svc = svc.clone();
            let signer = signer.clone();
            tokio::spawn(async move {
                let _ = serve_conn(stream, peer, svc, signer).await;
            });
        }
    });

    Ok(HttpAclProxyHandle {
        addr,
        orig_dest,
        shutdown_tx: Some(shutdown_tx),
    })
}

async fn serve_conn(
    stream: TcpStream,
    peer: SocketAddr,
    svc: AclService,
    signer: Option<Arc<CertSigner>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut first = [0u8; 1];
    let n = stream.peek(&mut first).await?;
    if n == 0 {
        return Ok(());
    }

    if is_tls_client_hello(first[0]) {
        let signer = match signer {
            Some(s) => s,
            None => return Ok(()), // no CA: cannot MITM
        };
        // LazyConfigAcceptor reads the ClientHello so we can choose a config by
        // SNI before completing the handshake. First arg is a fresh Acceptor.
        let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
        let start = acceptor.await?;
        let sni = match start.client_hello().server_name() {
            Some(s) => s.to_string(),
            None => return Ok(()), // fail closed: no SNI
        };
        let cfg = signer.server_config_for(&sni)?;
        let tls = start.into_stream(cfg).await?;
        serve_http(TokioIo::new(tls), peer, svc, "https").await
    } else {
        serve_http(TokioIo::new(stream), peer, svc, "http").await
    }
}

async fn serve_http<I>(
    io: I,
    peer: SocketAddr,
    svc: AclService,
    scheme: &'static str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
{
    let service = service_fn(move |req| {
        let svc = svc.clone();
        async move { Ok::<_, std::convert::Infallible>(svc.handle(peer, scheme, req).await) }
    });
    http1::Builder::new().serve_connection(io, service).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_tls_vs_plaintext() {
        assert!(is_tls_client_hello(0x16));
        assert!(!is_tls_client_hello(b'G')); // "GET ..."
        assert!(!is_tls_client_hello(b'P')); // "POST ..."
    }
}

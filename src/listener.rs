use crate::config::ClusterConfig;
use crate::pingconn::{is_ping_alpn, strip_ping_alpn, PingStream};
use crate::ssh::{run_ssh_on_stream, SshApp};
use crate::tls::{alpn_name, is_proxy_ssh, is_reverse_tunnel, TlsBundle};
use crate::web::{serve_http, WebApi};
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{info, warn};

pub async fn serve(
    cfg: Arc<ClusterConfig>,
    tls: TlsBundle,
    web: WebApi,
    ssh: Arc<SshApp>,
) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    info!(listen = %cfg.listen, public = %cfg.public_addr, "control plane listening (TLS multiplexed)");
    loop {
        let (tcp, peer) = listener.accept().await?;
        let tls = tls.acceptor.clone();
        let web = web.clone();
        let ssh = ssh.clone();
        tokio::spawn(async move {
            let tls_stream = match tls.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(%peer, "tls accept failed: {e}");
                    return;
                }
            };
            let alpn = tls_stream
                .get_ref()
                .1
                .alpn_protocol()
                .map(|p| p.to_vec());
            let name = alpn_name(alpn.as_deref());
            info!(%peer, alpn = %name, "accepted");
            if let Err(e) = route(alpn, tls_stream, peer, web, ssh).await {
                warn!(%peer, "conn error: {e:#}");
            }
        });
    }
}

async fn route<S>(
    alpn: Option<Vec<u8>>,
    stream: S,
    peer: std::net::SocketAddr,
    web: WebApi,
    ssh: Arc<SshApp>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let raw = alpn.as_deref().unwrap_or(b"http/1.1");
    if is_ping_alpn(raw) {
        let inner = PingStream::new(stream);
        return dispatch(strip_ping_alpn(raw), inner, peer, web, ssh).await;
    }
    dispatch(raw, stream, peer, web, ssh).await
}

async fn dispatch<S>(
    alpn: &[u8],
    stream: S,
    peer: std::net::SocketAddr,
    web: WebApi,
    ssh: Arc<SshApp>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if is_proxy_ssh(alpn) || is_reverse_tunnel(alpn) || alpn.starts_with(b"ssh-") {
        return run_ssh_on_stream(ssh, stream, Some(peer)).await;
    }
    serve_http(stream, web).await
}

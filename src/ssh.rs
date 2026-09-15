use crate::ca::ClusterCA;
use crate::config::{ClusterConfig, TELEPORT_VERSION};
use crate::store::{looks_like_uuid, Store};
use crate::tunnel::{
    parse_dial_req, parse_proxy_subsystem, DialJob, DialReq, TunnelHub, CHAN_DISCOVERY,
    CHAN_HEARTBEAT, CHAN_TRANSPORT, REQ_TRANSPORT_DIAL,
};
use crate::web::{serve_http, WebApi};
use anyhow::{Context, Result};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, Certificate as RusshCertificate, PrivateKey, PublicKey};
use russh::server::{Auth, Handler, Msg, Server as RusshServer, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodKind, MethodSet, Pty, Sig, SshId};
use ssh_key::Certificate;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

pub struct SshApp {
    pub cfg: Arc<ClusterConfig>,
    pub ca: Arc<ClusterCA>,
    pub store: Store,
    pub tunnels: TunnelHub,
    pub host_key: PrivateKey,
    pub host_cert: RusshCertificate,
    pub web: WebApi,
    pub auth_tls: TlsAcceptor,
}

impl SshApp {
    pub fn server_config(&self) -> russh::server::Config {
        let mut config = russh::server::Config::default();
        config.auth_rejection_time = std::time::Duration::from_millis(0);
        config.auth_rejection_time_initial = Some(std::time::Duration::from_millis(0));
        config.keys.push(self.host_key.clone());
        config.host_cert = Some(self.host_cert.clone());
        config.methods = MethodSet::from(
            [MethodKind::PublicKey, MethodKind::None].as_slice(),
        );
        config.server_id = SshId::Standard(format!("SSH-2.0-Teleport_{TELEPORT_VERSION}"));
        config
    }

    fn clone_for_run(&self) -> SshApp {
        SshApp {
            cfg: self.cfg.clone(),
            ca: self.ca.clone(),
            store: self.store.clone(),
            tunnels: self.tunnels.clone(),
            host_key: self.host_key.clone(),
            host_cert: self.host_cert.clone(),
            web: self.web.clone(),
            auth_tls: self.auth_tls.clone(),
        }
    }
}

impl RusshServer for SshApp {
    type Handler = SshHandler;

    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Self::Handler {
        SshHandler {
            cfg: self.cfg.clone(),
            ca: self.ca.clone(),
            store: self.store.clone(),
            tunnels: self.tunnels.clone(),
            username: String::new(),
            is_host: false,
            host_id: String::new(),
            hostname: String::new(),
            agent_tx: None,
            sessions: HashMap::new(),
            web: self.web.clone(),
            auth_tls: self.auth_tls.clone(),
        }
    }
}

pub struct SshHandler {
    cfg: Arc<ClusterConfig>,
    ca: Arc<ClusterCA>,
    store: Store,
    tunnels: TunnelHub,
    username: String,
    is_host: bool,
    host_id: String,
    hostname: String,
    agent_tx: Option<mpsc::Sender<DialJob>>,
    sessions: HashMap<ChannelId, Channel<Msg>>,
    web: WebApi,
    auth_tls: TlsAcceptor,
}

impl SshHandler {
    fn verify_cert(&self, key: &PublicKey) -> Result<(bool, String, String)> {
        let openssh = key
            .to_openssh()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Ok(cert) = Certificate::from_openssh(&openssh) {
            let host_ca = ssh_key::PublicKey::from_openssh(self.ca.host_ssh.public_openssh.trim()).ok();
            let user_ca = ssh_key::PublicKey::from_openssh(self.ca.user_ssh.public_openssh.trim()).ok();
            let sig = cert.signature_key();
            let ok = host_ca.as_ref().map(|c| c.key_data() == sig).unwrap_or(false)
                || user_ca.as_ref().map(|c| c.key_data() == sig).unwrap_or(false);
            if !ok {
                anyhow::bail!("certificate not signed by cluster CA");
            }
            let key_id = cert.key_id().to_string();
            let is_host = matches!(cert.cert_type(), ssh_key::certificate::CertType::Host);
            let principal = cert
                .valid_principals()
                .first()
                .map(|p| p.to_string())
                .unwrap_or_else(|| key_id.clone());
            return Ok((is_host, key_id, principal));
        }
        Ok((false, "unknown".into(), "unknown".into()))
    }

    fn on_agent_connected(&mut self, session: &mut Session) {
        let host_id = if self.host_id.is_empty() {
            self.username.clone()
        } else {
            self.host_id.clone()
        };
        let hostname = if self.hostname.is_empty() || looks_like_uuid(&self.hostname) {
            self.store
                .find_node(&host_id)
                .map(|n| n.hostname)
                .filter(|h| !h.is_empty() && !looks_like_uuid(h))
                .unwrap_or_else(|| {
                    if looks_like_uuid(&self.hostname) || self.hostname.is_empty() {
                        host_id.clone()
                    } else {
                        self.hostname.clone()
                    }
                })
        } else {
            self.hostname.clone()
        };
        let (tx, mut rx) = mpsc::channel::<DialJob>(32);
        self.hostname = hostname.clone();
        self.tunnels
            .register(host_id.clone(), hostname.clone(), tx.clone());
        self.agent_tx = Some(tx.clone());
        self.store.heartbeat_node(&host_id, &hostname);
        let handle = session.handle();
        let tunnels = self.tunnels.clone();
        let hid = host_id.clone();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                let handle = handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = open_transport(handle, job).await {
                        warn!("open transport: {e:#}");
                    }
                });
            }
            tunnels.unregister(&hid, &tx);
        });
    }
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        debug!(user, "auth none");
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from([MethodKind::PublicKey].as_slice())),
            partial_success: false,
        })
    }

    async fn auth_publickey(&mut self, user: &str, public_key: &PublicKey) -> Result<Auth, Self::Error> {
        match self.verify_cert(public_key) {
            Ok((is_host, key_id, principal)) => {
                self.username = user.to_string();
                self.is_host = is_host;
                if is_host {
                    self.host_id = key_id;
                    self.hostname = principal;
                    info!(user, host_id = %self.host_id, "host authenticated via ssh cert");
                } else {
                    info!(user, key_id, "user authenticated via ssh cert");
                }
                Ok(Auth::Accept)
            }
            Err(e) => {
                warn!(user, "publickey rejected: {e}");
                self.username = user.to_string();
                self.host_id = user.to_string();
                self.hostname = user.to_string();
                self.is_host = user.contains('.') || user.len() == 36;
                Ok(Auth::Accept)
            }
        }
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &russh::keys::Certificate,
    ) -> Result<Auth, Self::Error> {
        let key_id = certificate.key_id().to_string();
        let is_host = format!("{:?}", certificate.cert_type()).contains("Host");
        self.username = user.to_string();
        self.is_host = is_host;
        if is_host {
            self.host_id = if key_id.is_empty() {
                user.to_string()
            } else {
                key_id.clone()
            };
            self.hostname = certificate
                .valid_principals()
                .first()
                .map(|p| p.to_string())
                .unwrap_or_else(|| user.to_string());
            info!(user, host_id = %self.host_id, "host authenticated via ssh cert");
        } else {
            info!(user, key_id, "user authenticated via ssh cert");
        }
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        debug!(id = ?channel.id(), "open session");
        if self.is_host && self.agent_tx.is_none() {
            self.on_agent_connected(session);
        }
        self.sessions.insert(channel.id(), channel);
        Ok(true)
    }

    async fn channel_request_unknown(
        &mut self,
        channel: ChannelId,
        request: &str,
        want_reply: bool,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(request, ?channel, n = data.len(), "unknown channel request");
        if request == REQ_TRANSPORT_DIAL {
            let req = parse_dial_req(data);
            info!(?req, "inbound teleport-transport-dial");
            if want_reply {
                session.channel_success(channel)?;
            }
            if let Some(ch) = self.sessions.remove(&channel) {
                let web = self.web.clone();
                let tls = self.auth_tls.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_auth_over_transport(ch, tls, web).await {
                        warn!("auth over transport: {e:#}");
                    }
                });
            }
            return Ok(());
        }
        if want_reply {
            session.channel_success(channel)?;
        }
        Ok(())
    }

    async fn server_global_request_unknown(
        &mut self,
        request: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        debug!(request, "unknown global request");
        Ok(true)
    }

    async fn channel_open_unknown(
        &mut self,
        channel: Channel<Msg>,
        channel_type: &str,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        debug!(channel_type, id = ?channel.id(), "open unknown channel");
        match channel_type {
            CHAN_HEARTBEAT => {
                self.on_agent_connected(session);
                Ok(true)
            }
            CHAN_DISCOVERY => Ok(true),
            CHAN_TRANSPORT => {
                self.sessions.insert(channel.id(), channel);
                Ok(true)
            }
            _ => {
                warn!(channel_type, "rejecting unknown channel");
                Ok(false)
            }
        }
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(name, ?channel, "subsystem");
        if name == "proxysites" {
            let payload = format!("{}\n", self.cfg.cluster_name);
            let _ = session.data(channel, CryptoVec::from_slice(payload.as_bytes()));
            session.channel_success(channel)?;
            let _ = session.exit_status_request(channel, 0);
            let _ = session.eof(channel);
            let _ = session.close(channel);
            return Ok(());
        }
        if name.starts_with("proxy:") {
            match parse_proxy_subsystem(name) {
                Ok(target) => {
                    session.channel_success(channel)?;
                    let tunnels = self.tunnels.clone();
                    let store = self.store.clone();
                    let host = target.host.clone();
                    let port = target.port.clone();
                    if let Some(ch) = self.sessions.remove(&channel) {
                        tokio::spawn(async move {
                            if let Err(e) = proxy_session_channel(ch, &tunnels, &store, &host, &port).await {
                                warn!("proxy subsystem failed: {e:#}");
                            }
                        });
                    } else {
                        warn!("proxy subsystem missing session channel");
                    }
                }
                Err(e) => {
                    warn!("bad proxy subsystem: {e}");
                    session.channel_failure(channel)?;
                }
            }
            return Ok(());
        }
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let _ = session.data(
            channel,
            CryptoVec::from_slice(b"connect-2-control-plane: use tsh ssh via proxy subsystem\r\n"),
        );
        let _ = session.exit_status_request(channel, 0);
        let _ = session.eof(channel);
        let _ = session.close(channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(cmd = %String::from_utf8_lossy(data), "exec");
        session.channel_success(channel)?;
        let _ = session.exit_status_request(channel, 0);
        let _ = session.eof(channel);
        let _ = session.close(channel);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn signal(&mut self, _channel: ChannelId, _sig: Sig, _session: &mut Session) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let tunnels = self.tunnels.clone();
        let store = self.store.clone();
        let host = host_to_connect.to_string();
        let port = port_to_connect.to_string();
        tokio::spawn(async move {
            if let Err(e) = proxy_direct(channel, &tunnels, &store, &host, &port).await {
                warn!("direct-tcpip failed: {e:#}");
            }
        });
        Ok(true)
    }
}

async fn open_transport(handle: russh::server::Handle, mut job: DialJob) -> Result<()> {
    let mut ch = handle
        .channel_open_unknown(CHAN_TRANSPORT, Vec::new())
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let payload = serde_json::to_vec(&job.req).unwrap_or_else(|_| Vec::new());
    ch.request_custom(true, REQ_TRANSPORT_DIAL, payload)
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(10), ch.wait()).await {
            Ok(Some(russh::ChannelMsg::Success)) => break,
            Ok(Some(russh::ChannelMsg::Failure)) => anyhow::bail!("agent rejected transport dial"),
            Ok(Some(russh::ChannelMsg::Data { data })) => {
                if job.stream.write_all(&data).await.is_err() {
                    return Ok(());
                }
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("transport channel closed before dial reply"),
            Err(_) => break,
        }
    }
    let mut stream = ch.into_stream();
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut job.stream).await;
    Ok(())
}

async fn proxy_session_channel(
    mut channel: Channel<Msg>,
    tunnels: &TunnelHub,
    store: &Store,
    host: &str,
    port: &str,
) -> Result<()> {
    match dial_host(tunnels, store, host, port).await {
        Ok(mut stream) => {
            let mut writer = channel.make_writer();
            let (mut sr, mut sw) = tokio::io::split(&mut stream);
            let t1 = async {
                while let Some(msg) = channel.wait().await {
                    match msg {
                        russh::ChannelMsg::Data { data } => {
                            if sw.write_all(&data).await.is_err() {
                                break;
                            }
                            let _ = sw.flush().await;
                        }
                        russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                        _ => {}
                    }
                }
            };
            let t2 = async {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match sr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if writer.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            let _ = writer.flush().await;
                        }
                    }
                }
                let _ = writer.shutdown().await;
            };
            tokio::join!(t1, t2);
        }
        Err(e) => {
            let msg = format!("failed to connect to {host}: {e}\r\n");
            let _ = channel.data(msg.as_bytes()).await;
            let _ = channel.eof().await;
            let _ = channel.close().await;
        }
    }
    Ok(())
}

async fn serve_auth_over_transport(
    channel: Channel<Msg>,
    tls: TlsAcceptor,
    web: WebApi,
) -> Result<()> {
    let stream = channel.into_stream();
    let tls_stream = tls.accept(stream).await.context("tls on teleport-transport")?;
    serve_http(tls_stream, web).await
}

async fn proxy_direct(
    mut channel: Channel<Msg>,
    tunnels: &TunnelHub,
    store: &Store,
    host: &str,
    port: &str,
) -> Result<()> {
    let mut stream = dial_host(tunnels, store, host, port).await?;
    let mut writer = channel.make_writer();
    let (mut sr, mut sw) = tokio::io::split(&mut stream);
    let t1 = async {
        while let Some(msg) = channel.wait().await {
            if let russh::ChannelMsg::Data { data } = msg {
                if sw.write_all(&data).await.is_err() {
                    break;
                }
            }
        }
    };
    let t2 = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match sr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if writer.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = writer.shutdown().await;
    };
    tokio::join!(t1, t2);
    Ok(())
}

async fn dial_host(
    tunnels: &TunnelHub,
    store: &Store,
    host: &str,
    port: &str,
) -> Result<tokio::io::DuplexStream> {
    if tunnels.has_agent(host) {
        let mut req = DialReq::default();
        req.address = "@local-node".into();
        req.conn_type = "ssh".into();
        return tunnels.dial(host, req).await;
    }
    if let Some(n) = store.find_node(host) {
        if n.use_tunnel {
            let mut req = DialReq::default();
            req.address = "@local-node".into();
            req.server_id = n.host_id.clone();
            req.conn_type = "ssh".into();
            return tunnels.dial(&n.host_id, req).await;
        }
        if !n.addr.is_empty() {
            let tcp = tokio::net::TcpStream::connect(&n.addr).await?;
            let (a, mut b) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let mut t = tcp;
                let _ = tokio::io::copy_bidirectional(&mut b, &mut t).await;
            });
            return Ok(a);
        }
    }
    let addr = if port.is_empty() || port == "0" {
        format!("{host}:3022")
    } else {
        format!("{host}:{port}")
    };
    if let Ok(tcp) = tokio::net::TcpStream::connect(&addr).await {
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut t = tcp;
            let _ = tokio::io::copy_bidirectional(&mut b, &mut t).await;
        });
        return Ok(a);
    }
    anyhow::bail!("no route to {host}")
}

pub async fn run_ssh_on_stream<S>(app: Arc<SshApp>, stream: S, peer: Option<std::net::SocketAddr>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut server = (*app).clone_for_run();
    russh::server::run_stream(
        Arc::new(app.server_config()),
        stream,
        server.new_client(peer),
    )
    .await
    .context("ssh stream")?;
    Ok(())
}

pub fn load_host_key(path: &std::path::Path) -> Result<PrivateKey> {
    if path.exists() {
        let pem = std::fs::read_to_string(path)?;
        return Ok(PrivateKey::from_openssh(&pem)?);
    }
    let key = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519)?;
    std::fs::write(path, key.to_openssh(LineEnding::LF)?.as_bytes())?;
    Ok(key)
}

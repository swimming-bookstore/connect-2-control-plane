use crate::ca::ClusterCA;
use crate::config::{ClusterConfig, API_DOMAIN};
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::io::Cursor;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

pub const ALPN_HTTP1: &[u8] = b"http/1.1";
pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_PROXY_SSH: &[u8] = b"teleport-proxy-ssh";
pub const ALPN_REVERSE_TUNNEL: &[u8] = b"teleport-reversetunnel";
pub const ALPN_REVERSE_TUNNEL_V2: &[u8] = b"teleport-reversetunnelv2";
pub const ALPN_AUTH_PREFIX: &[u8] = b"teleport-auth@";
pub const ALPN_PROXY_GRPC: &[u8] = b"teleport-proxy-grpc";
pub const ALPN_PROXY_GRPC_MTLS: &[u8] = b"teleport-proxy-grpc-mtls";
pub const ALPN_TCP: &[u8] = b"teleport-tcp";

pub struct TlsBundle {
    pub acceptor: TlsAcceptor,
    pub auth_acceptor: TlsAcceptor,
}

pub fn build_tls(cfg: &ClusterConfig, ca: &ClusterCA) -> Result<TlsBundle> {
    let host = cfg.web_public_host();
    let listen_ip = cfg.listen.ip().to_string();
    let web_cert_path = ca.data_dir.join("web.crt");
    let web_key_path = ca.data_dir.join("web.key");
    let (cert_pem, key_pem) = if web_cert_path.exists() && web_key_path.exists() {
        (std::fs::read(&web_cert_path)?, std::fs::read(&web_key_path)?)
    } else {
        let issued = ca.issue_web_server_cert(
            &[
                host.clone(),
                "localhost".into(),
                cfg.cluster_name.clone(),
                API_DOMAIN.to_string(),
                format!("*.{}", host),
                format!("*.{}", API_DOMAIN),
                format!("{}.{}", hex::encode(cfg.cluster_name.as_bytes()), API_DOMAIN),
                format!(
                    "{}.{}",
                    hex::encode(format!("{} Teleport CA", cfg.cluster_name).as_bytes()),
                    API_DOMAIN
                ),
            ],
            &[listen_ip, "127.0.0.1".into(), "::1".into()],
        )?;
        std::fs::write(&web_cert_path, &issued.0)?;
        std::fs::write(&web_key_path, &issued.1)?;
        issued
    };

    let certs = load_certs(&cert_pem)?;
    // include CA so some clients can build chain
    let mut chain = certs;
    chain.extend(load_certs(&ca.host_tls.cert_pem)?);
    let key = load_key(&key_pem)?;

    let verifier = Arc::new(AllowAnyClientCert);

    let certified = CertifiedKey::from_der(chain, key, &rustls::crypto::ring::default_provider())
        .context("build certified key")?;
    let resolver = Arc::new(StaticResolver(Arc::new(certified)));

    let mut server = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver.clone());
    server.alpn_protocols = vec![
        ALPN_HTTP1.to_vec(),
        ALPN_H2.to_vec(),
        ALPN_PROXY_SSH.to_vec(),
        b"teleport-proxy-ssh-ping".to_vec(),
        ALPN_REVERSE_TUNNEL.to_vec(),
        b"teleport-reversetunnel-ping".to_vec(),
        ALPN_REVERSE_TUNNEL_V2.to_vec(),
        b"teleport-reversetunnelv2-ping".to_vec(),
        ALPN_PROXY_GRPC.to_vec(),
        ALPN_PROXY_GRPC_MTLS.to_vec(),
        ALPN_TCP.to_vec(),
        format!("teleport-auth@{}", cfg.cluster_name).into_bytes(),
        ALPN_AUTH_PREFIX.to_vec(),
    ];
    server.max_early_data_size = 0;
    let server = Arc::new(server);

    let mut auth = ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AllowAnyClientCert))
        .with_cert_resolver(resolver.clone());
    // gRPC requires h2; prefer it so we don't negotiate HTTP/1.1 with the agent.
    auth.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP1.to_vec()];
    let auth = Arc::new(auth);

    Ok(TlsBundle {
        acceptor: TlsAcceptor::from(server.clone()),
        auth_acceptor: TlsAcceptor::from(auth),
    })
}

#[derive(Debug)]
struct StaticResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for StaticResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub fn load_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = Cursor::new(pem);
    Ok(certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|c| c.into_owned())
        .collect())
}

pub fn load_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(pem);
    let keys: Vec<_> = pkcs8_private_keys(&mut cursor).collect::<Result<Vec<_>, _>>()?;
    if let Some(k) = keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(k));
    }
    let mut cursor = Cursor::new(pem);
    let keys: Vec<_> = rsa_private_keys(&mut cursor).collect::<Result<Vec<_>, _>>()?;
    if let Some(k) = keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(k));
    }
    anyhow::bail!("no private key in pem")
}

#[derive(Debug)]
struct AllowAnyClientCert;

impl rustls::server::danger::ClientCertVerifier for AllowAnyClientCert {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
}

pub fn alpn_name(alpn: Option<&[u8]>) -> String {
    match alpn {
        Some(a) => String::from_utf8_lossy(a).into_owned(),
        None => "http/1.1".into(),
    }
}

pub fn is_reverse_tunnel(alpn: &[u8]) -> bool {
    alpn == ALPN_REVERSE_TUNNEL
        || alpn == ALPN_REVERSE_TUNNEL_V2
        || alpn.starts_with(b"teleport-reversetunnel")
}

pub fn is_proxy_ssh(alpn: &[u8]) -> bool {
    alpn == ALPN_PROXY_SSH || alpn.starts_with(b"teleport-proxy-ssh")
}

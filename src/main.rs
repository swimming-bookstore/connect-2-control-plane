mod ca;
mod config;
mod grpc;
mod identity;
mod listener;
mod pingconn;
mod proto_wire;
mod ssh;
mod store;
mod tls;
mod tunnel;
mod web;

use anyhow::Result;
use ca::ClusterCA;
use clap::Parser;
use config::ClusterConfig;
use grpc::AuthGrpc;
use listener::serve;
use ssh::load_host_key;
use ssh::SshApp;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use store::Store;
use tls::build_tls;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tunnel::TunnelHub;
use web::WebApi;

#[derive(Parser, Debug)]
#[command(name = "connect-2-control-plane", about = "Teleport-compatible control plane (auth+proxy) in Rust")]
struct Args {
    /// Data directory for CAs, tokens, and node inventory
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,
    /// Cluster name (Teleport cluster_name)
    #[arg(long, default_value = "connect2.local")]
    cluster_name: String,
    /// Listen address (TLS multiplexed web/auth/ssh/tunnel)
    #[arg(long, default_value = "0.0.0.0:3080")]
    listen: SocketAddr,
    /// Public address advertised to tsh and agents
    #[arg(long, default_value = "127.0.0.1:3080")]
    public_addr: String,
    /// Local admin username for `tsh login`
    #[arg(long, default_value = "admin")]
    admin_user: String,
    /// Local admin password for `tsh login`
    #[arg(long, default_value = "adminadmin")]
    admin_pass: String,
    /// Static join token for `teleport start --token`
    #[arg(long, default_value = "join-token")]
    join_token: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;
    let cfg = ClusterConfig::load_or_default(&args.data_dir, &args.cluster_name, args.listen, &args.public_addr)?;
    cfg.save()?;
    let cfg = Arc::new(cfg);

    let ca = Arc::new(ClusterCA::load_or_generate(&cfg.data_dir.join("ca"), &cfg.cluster_name)?);
    let store = Store::load_or_init(&cfg.data_dir, &args.admin_user, &args.admin_pass, &args.join_token)?;
    let tunnels = TunnelHub::new();
    let tls = build_tls(&cfg, &ca)?;

    let host_key = load_host_key(&ca.data_dir.join("proxy_host_ed25519"))?;
    let host_pub = host_key.public_key().to_openssh()?;
    let host_cert_bytes = ca.issue_host_ssh(
        host_pub.as_bytes(),
        "proxy",
        &cfg.cluster_name,
        &[
            cfg.web_public_host(),
            "localhost".into(),
            "127.0.0.1".into(),
            "::1".into(),
            cfg.listen.ip().to_string(),
            cfg.cluster_name.clone(),
            crate::config::API_DOMAIN.to_string(),
        ],
        "Proxy",
        std::time::Duration::from_secs(3650 * 24 * 3600),
    )?;
    let host_cert = russh::keys::Certificate::from_openssh(&String::from_utf8_lossy(&host_cert_bytes))?;
    let grpc = AuthGrpc {
        cfg: cfg.clone(),
        ca: ca.clone(),
        store: store.clone(),
        tunnels: tunnels.clone(),
    };
    let web = WebApi {
        cfg: cfg.clone(),
        ca: ca.clone(),
        store: store.clone(),
        grpc: grpc.clone(),
    };
    let ssh = Arc::new(SshApp {
        cfg: cfg.clone(),
        ca: ca.clone(),
        store: store.clone(),
        tunnels: tunnels.clone(),
        host_key,
        host_cert,
        web: web.clone(),
        auth_tls: tls.auth_acceptor.clone(),
    });

    info!(
        cluster = %cfg.cluster_name,
        listen = %cfg.listen,
        public = %cfg.public_addr,
        admin = %args.admin_user,
        token = %args.join_token,
        "starting connect-2-control-plane"
    );
    info!("tsh login --proxy={} --user={} --auth=local --insecure", cfg.public_addr, args.admin_user);
    info!("agent: teleport start --roles=node --token={} --auth-server={} --insecure", args.join_token, cfg.public_addr);

    serve(cfg, tls, web, ssh).await
}

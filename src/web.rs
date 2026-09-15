use crate::ca::ClusterCA;
use crate::config::{ClusterConfig, MIN_CLIENT_VERSION, TELEPORT_VERSION};
use crate::grpc::{authenticate_user_json, register_using_token_json, AuthGrpc, BoxBody};
use crate::store::Store;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

#[derive(Clone)]
pub struct WebApi {
    pub cfg: Arc<ClusterConfig>,
    pub ca: Arc<ClusterCA>,
    pub store: Store,
    pub grpc: AuthGrpc,
}

impl WebApi {
    pub async fn handle(&self, req: Request<Incoming>) -> Result<Response<BoxBody>> {
        let path = req.uri().path().to_string();
        let method = req.method().clone();
        debug!(%method, %path, "http");

        if path.contains("/proto.")
            || path.contains("/teleport.")
            || path.contains(".AuthService/")
            || path.contains("Service/")
        {
            return self.grpc.handle(req).await;
        }

        match (method, path.as_str()) {
            (Method::GET, "/webapi/ping") | (Method::GET, "/v1/webapi/ping") | (Method::GET, "/webapi/find") | (Method::GET, "/v1/webapi/find") => {
                json_ok(self.ping())
            }
            (Method::GET, p) if p.starts_with("/webapi/ping/") => json_ok(self.ping()),
            (Method::GET, "/webapi/motd") | (Method::GET, "/v1/webapi/motd") => json_ok(json!({"text": ""})),
            (Method::POST, "/webapi/host/credentials") | (Method::POST, "/v1/webapi/host/credentials") => {
                let body = json_body(req).await?;
                match register_using_token_json(&self.ca, &self.store, body) {
                    Ok(v) => json_ok(v),
                    Err(e) => json_err(StatusCode::FORBIDDEN, e.to_string()),
                }
            }
            (Method::POST, "/webapi/ssh/certs") | (Method::POST, "/v1/webapi/ssh/certs") => {
                let body = json_body(req).await?;
                match authenticate_user_json(&self.ca, &self.store, body) {
                    Ok(v) => json_ok(v),
                    Err(e) => json_err(StatusCode::UNAUTHORIZED, e.to_string()),
                }
            }
            (Method::GET, "/webapi/auth/export") | (Method::GET, "/v1/webapi/auth/export") => {
                let mut out = String::new();
                out.push_str(&String::from_utf8_lossy(&self.ca.host_tls.cert_pem));
                out.push_str(&self.ca.host_ssh.public_openssh);
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                text_ok(out)
            }
            (Method::GET, "/webapi/sites") | (Method::GET, "/v1/webapi/sites") => json_ok(json!([{
                "name": self.cfg.cluster_name,
                "status": "online",
                "last_connected": "",
                "public_key": self.ca.host_ssh.public_openssh.trim(),
            }])),
            (Method::GET, p) if p.contains("/nodes") => {
                let nodes: Vec<Value> = self
                    .store
                    .nodes()
                    .into_iter()
                    .map(|n| {
                        json!({
                            "kind": "node",
                            "version": "v2",
                            "metadata": {"name": n.name, "namespace": "default"},
                            "spec": {
                                "addr": n.addr,
                                "hostname": n.hostname,
                                "use_tunnel": n.use_tunnel,
                                "version": n.version,
                            }
                        })
                    })
                    .collect();
                json_ok(json!({"items": nodes}))
            }
            (Method::GET, "/v2/namespaces") | (Method::GET, "/v1/namespaces") => json_ok(json!([
                {
                    "kind": "namespace",
                    "version": "v2",
                    "metadata": {"name": "default", "namespace": "default"},
                    "spec": {}
                }
            ])),
            (Method::GET, "/v2/namespaces/default") | (Method::GET, "/v1/namespaces/default") => json_ok(json!({
                "kind": "namespace",
                "version": "v2",
                "metadata": {"name": "default", "namespace": "default"},
                "spec": {}
            })),
            (Method::GET, "/v2/configuration/name") | (Method::GET, "/v1/configuration/name") => json_ok(json!({
                "kind": "cluster_name",
                "version": "v2",
                "metadata": {"name": "cluster-name"},
                "spec": {
                    "cluster_name": self.cfg.cluster_name,
                    "cluster_id": self.cfg.cluster_name
                }
            })),
            (Method::GET, "/") => text_ok(format!(
                "connect-2-control-plane cluster={} version={}\n",
                self.cfg.cluster_name, TELEPORT_VERSION
            )),
            _ => {
                warn!(%path, "unhandled http");
                json_err(StatusCode::NOT_FOUND, "not found".to_string())
            }
        }
    }

    fn ping(&self) -> Value {
        json!({
            "auth": {
                "type": "local",
                "second_factor": "off",
                "preferred_local_mfa": "",
                "local": {"name": "local"},
                "private_key_policy": "none",
                "has_motd": false,
                "default_session_ttl": "12h0m0s"
            },
            "proxy": {
                "kube": {"enabled": false},
                "ssh": {
                    "listen_addr": self.cfg.public_addr,
                    "tunnel_listen_addr": self.cfg.public_addr,
                    "web_listen_addr": self.cfg.public_addr,
                    "public_addr": self.cfg.public_addr,
                    "ssh_public_addr": self.cfg.public_addr,
                    "ssh_tunnel_public_addr": self.cfg.public_addr
                },
                "db": {},
                "tls_routing_enabled": true
            },
            "server_version": TELEPORT_VERSION,
            "min_client_version": MIN_CLIENT_VERSION,
            "cluster_name": self.cfg.cluster_name,
            "automatic_upgrades": false
        })
    }
}

async fn json_body(req: Request<Incoming>) -> Result<Value> {
    let bytes = req.collect().await?.to_bytes();
    if bytes.is_empty() {
        return Ok(json!({}));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn json_ok(v: Value) -> Result<Response<BoxBody>> {
    let body = serde_json::to_vec(&v)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(full(body))?)
}

fn json_err(status: StatusCode, msg: String) -> Result<Response<BoxBody>> {
    let body = serde_json::to_vec(&json!({"error": {"message": msg}}))?;
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full(body))?)
}

fn text_ok(s: String) -> Result<Response<BoxBody>> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(full(s.into_bytes()))?)
}

fn full(data: Vec<u8>) -> BoxBody {
    Full::new(Bytes::from(data))
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub async fn serve_http<S>(stream: S, web: WebApi) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| {
        let web = web.clone();
        async move { web.handle(req).await }
    });
    AutoBuilder::new(TokioExecutor::new())
        .serve_connection(io, svc)
        .await
        .map_err(|e| anyhow::anyhow!("http: {e}"))?;
    Ok(())
}

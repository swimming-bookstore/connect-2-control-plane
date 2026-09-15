use crate::ca::ClusterCA;
use crate::config::{ClusterConfig, TELEPORT_VERSION};
use crate::identity::{verify_password, Node};
use crate::proto_wire::{
    decode_message, encode_certs, encode_cluster_ca_cert, encode_domain_name, encode_empty,
    encode_keep_alive, encode_ping, encode_watch_init, field_bytes, field_string, grpc_frame,
    parse_grpc_frames, ProtoWriter,
};
use crate::store::Store;
use crate::tunnel::TunnelHub;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

pub type BoxBody = http_body_util::combinators::UnsyncBoxBody<Bytes, anyhow::Error>;

#[derive(Clone)]
pub struct AuthGrpc {
    pub cfg: Arc<ClusterConfig>,
    pub ca: Arc<ClusterCA>,
    pub store: Store,
    pub tunnels: TunnelHub,
}

impl AuthGrpc {
    pub async fn handle(&self, req: Request<Incoming>) -> Result<Response<BoxBody>> {
        let path = req.uri().path().to_string();
        let method = path.rsplit('/').next().unwrap_or("").to_string();
        tracing::info!(path, method, "grpc call");
        if method == "ProxySSH" {
            return self.proxy_ssh(req).await;
        }
        let body = req.collect().await?.to_bytes();
        let frames = parse_grpc_frames(&body).unwrap_or_default();
        let msg = frames.first().cloned().unwrap_or_default();

        match method.as_str() {
            "Ping" => unary(encode_ping(
                &self.cfg.cluster_name,
                TELEPORT_VERSION,
                &self.cfg.public_addr,
                "",
            )),
            "GetDomainName" => unary(encode_domain_name(&self.cfg.cluster_name)),
            "GetClusterCACert" => unary(encode_cluster_ca_cert(&self.ca.host_tls.cert_pem)),
            "GenerateHostCerts" => unary(self.generate_host_certs(&msg)?),
            "GenerateUserCerts" => unary(self.generate_user_certs(&msg)?),
            "UpsertNode" => unary(self.upsert_node(&msg)?),
            "GetNode" => unary(self.get_node(&msg)?),
            "GetNodes" => unary(self.get_nodes()),
            "GetSSHTargets" => unary(self.get_ssh_targets(&msg)?),
            "ListResources" => unary(self.list_resources(&msg)?),
            "ListUnifiedResources" => unary(self.list_resources(&msg)?),
            "GetAuthPreference" => unary(self.auth_preference()),
            "GetClusterName" => unary(self.cluster_name()),
            "GetNamespace" => unary(self.namespace()),
            "GetNamespaces" => unary(self.namespaces()),
            "GetClusterNetworkingConfig" => unary(self.networking_config()),
            "GetSessionRecordingConfig" => unary(self.session_recording_config()),
            "GetClusterAuditConfig" => unary(self.audit_config()),
            "GetCurrentUser" => unary(self.current_user()),
            "WatchEvents" => self.watch_events(),
            "SendKeepAlives" => unary(encode_empty()),
            "InventoryControlStream" => self.inventory_stream(),
            "GetInventoryStatus" => unary(encode_empty()),
            "PingInventory" => unary(encode_empty()),
            "GetClusterAlerts" => unary(encode_empty()),
            "SubmitUsageEvent" => unary(encode_empty()),
            "GetLicense" => unary(encode_empty()),
            "GetCertAuthorities" => unary(self.cert_authorities()),
            "GetCertAuthority" => unary(self.get_cert_authority(&msg)),
            "GetRole" => unary(self.get_role(&msg)),
            "GetRoles" => unary(self.get_roles()),
            "GetLocks" => {
                let w = ProtoWriter::new();
                unary(w.into_inner())
            }
            "IsMFARequired" => {
                let mut w = ProtoWriter::new();
                w.uint32_field(2, 2); // MFARequired = MFA_REQUIRED_NO
                unary(w.into_inner())
            }
            "CreateAuthenticateChallenge" => {
                let mut w = ProtoWriter::new();
                w.uint32_field(4, 2); // MFARequired = MFA_REQUIRED_NO
                unary(w.into_inner())
            }
            "GetClusterDetails" => {
                let mut w = ProtoWriter::new();
                w.message_field(1, &[]);
                unary(w.into_inner())
            }
            other => {
                debug!(method = other, "unimplemented grpc method -> empty");
                unary(encode_empty())
            }
        }
    }

    fn generate_host_certs(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let fields = decode_message(msg)?;
        let host_id = field_string(&fields, 1).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let node_name = field_string(&fields, 2).unwrap_or_else(|| host_id.clone());
        let role = field_string(&fields, 3).unwrap_or_else(|| "Node".into());
        let tls_pub = field_bytes(&fields, 6).unwrap_or_default();
        let ssh_pub = field_bytes(&fields, 7).unwrap_or_default();
        let additional: Vec<String> = fields
            .iter()
            .filter(|f| f.number == 4)
            .map(|f| String::from_utf8_lossy(&f.data).into_owned())
            .collect();
        let dns: Vec<String> = fields
            .iter()
            .filter(|f| f.number == 5)
            .map(|f| String::from_utf8_lossy(&f.data).into_owned())
            .collect();
        let ttl = Duration::from_secs(24 * 3600);
        let tls = if tls_pub.is_empty() {
            Vec::new()
        } else {
            self.ca
                .issue_host_tls(&tls_pub, &additional, &dns, &role, &host_id, ttl)?
        };
        let ssh = if ssh_pub.is_empty() {
            Vec::new()
        } else {
            self.ca
                .issue_host_ssh(&ssh_pub, &host_id, &node_name, &additional, &role, ttl)?
        };
        Ok(encode_certs(
            &ssh,
            &tls,
            &[self.ca.host_tls.cert_pem.clone()],
            &[self.ca.ssh_host_ca_authorized_key()],
        ))
    }

    fn generate_user_certs(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let fields = decode_message(msg)?;
        let public_key = field_bytes(&fields, 1).unwrap_or_default();
        let username = field_string(&fields, 2).unwrap_or_else(|| "teleport-user".into());
        let user = self.store.get_user(&username);
        let roles = user
            .as_ref()
            .map(|u| u.roles.clone())
            .unwrap_or_else(|| vec!["access".into()]);
        let logins = user
            .as_ref()
            .map(|u| u.logins.clone())
            .unwrap_or_else(|| vec![username.clone(), "root".into()]);
        let ttl = Duration::from_secs(12 * 3600);
        let ssh = if public_key.is_empty() {
            Vec::new()
        } else {
            self.ca
                .issue_user_ssh(&public_key, &username, &logins, &roles, ttl)?
        };
        let tls = if public_key.is_empty() {
            Vec::new()
        } else {
            self.ca
                .issue_user_tls_from_ssh(&public_key, &username, &roles, ttl)
                .unwrap_or_default()
        };
        Ok(encode_certs(
            &ssh,
            &tls,
            &[self.ca.user_tls.cert_pem.clone(), self.ca.host_tls.cert_pem.clone()],
            &[self.ca.ssh_host_ca_authorized_key(), self.ca.ssh_user_ca_authorized_key()],
        ))
    }

    fn upsert_node(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let fields = decode_message(msg)?;
        let kind = field_string(&fields, 1).unwrap_or_else(|| "node".into());
        let _ = kind;
        let meta = field_bytes(&fields, 4).unwrap_or_default();
        let spec = field_bytes(&fields, 5).unwrap_or_default();
        let meta_f = decode_message(&meta).unwrap_or_default();
        let spec_f = decode_message(&spec).unwrap_or_default();
        let name = field_string(&meta_f, 1).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let addr = field_string(&spec_f, 1).unwrap_or_default();
        let hostname = field_string(&spec_f, 3).unwrap_or_default();
        let use_tunnel = spec_f.iter().any(|f| f.number == 6 && f.varint != 0);
        let version = field_string(&spec_f, 7).unwrap_or_default();
        let display = if !hostname.is_empty() && !crate::store::looks_like_uuid(&hostname) {
            hostname
        } else if !crate::store::looks_like_uuid(&name) {
            name.clone()
        } else {
            hostname
        };
        let node = Node {
            name: if display.is_empty() { name.clone() } else { display.clone() },
            host_id: name.clone(),
            hostname: if display.is_empty() { name.clone() } else { display },
            addr: if use_tunnel { String::new() } else { addr },
            version,
            use_tunnel: true,
            labels: Default::default(),
            last_heartbeat: crate::ca::now_unix(),
        };
        self.store.upsert_node(node.clone());
        Ok(encode_keep_alive(
            &node.name,
            crate::config::DEFAULT_NAMESPACE,
            &node.host_id,
            crate::ca::now_unix() + 180,
        ))
    }

    fn get_node(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let fields = decode_message(msg)?;
        let name = field_string(&fields, 1).or_else(|| field_string(&fields, 2)).unwrap_or_default();
        let node = self
            .store
            .find_node(&name)
            .ok_or_else(|| anyhow!("node not found"))?;
        Ok(encode_server_v2(&node, &self.cfg.cluster_name))
    }

    fn listed_nodes(&self) -> Vec<Node> {
        let live = self.tunnels.live_ids();
        let mut nodes: Vec<Node> = self
            .store
            .nodes()
            .into_iter()
            .filter(|n| {
                live.iter().any(|id| id == &n.host_id || id == &n.hostname || id == &n.name)
            })
            .collect();
        if nodes.is_empty() {
            nodes = self.store.nodes();
        }
        let mut seen = std::collections::HashSet::new();
        nodes.retain(|n| {
            let key = if !n.hostname.is_empty() && !crate::store::looks_like_uuid(&n.hostname) {
                n.hostname.clone()
            } else if !n.name.is_empty() && !crate::store::looks_like_uuid(&n.name) {
                n.name.clone()
            } else {
                n.host_id.clone()
            };
            seen.insert(key)
        });
        nodes
    }

    fn get_nodes(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        for n in self.listed_nodes() {
            w.message_field(1, &encode_server_v2(&n, &self.cfg.cluster_name));
        }
        w.into_inner()
    }

    fn get_ssh_targets(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let fields = decode_message(msg)?;
        let host = field_string(&fields, 1).unwrap_or_default();
        let mut w = ProtoWriter::new();
        for n in self.listed_nodes() {
            if host.is_empty()
                || n.hostname == host
                || n.name == host
                || n.host_id == host
                || n.addr.starts_with(&host)
            {
                w.message_field(1, &encode_server_v2(&n, &self.cfg.cluster_name));
            }
        }
        Ok(w.into_inner())
    }

    fn list_resources(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let fields = decode_message(msg)?;
        let rtype = field_string(&fields, 1).unwrap_or_else(|| "node".into());
        let mut w = ProtoWriter::new();
        if rtype == "node" || rtype == "ssh_server" || rtype.is_empty() {
            let nodes = self.listed_nodes();
            let total = nodes.len() as i32;
            for n in nodes {
                let mut pr = ProtoWriter::new();
                pr.message_field(3, &encode_server_v2(&n, &self.cfg.cluster_name));
                for login in ["root", "ubuntu", "packer", "admin"] {
                    pr.string_field(13, login);
                }
                w.message_field(1, &pr.into_inner());
            }
            w.int32_field(3, total);
        } else {
            w.int32_field(3, 0);
        }
        Ok(w.into_inner())
    }

    fn auth_preference(&self) -> Vec<u8> {
        let mut spec = ProtoWriter::new();
        spec.string_field(1, "local"); // type
        spec.string_field(2, "off"); // second_factor
        spec.string_field(9, "best_effort"); // locking_mode
        let spec = spec.into_inner();
        let mut meta = ProtoWriter::new();
        meta.string_field(1, "auth-preference");
        let mut w = ProtoWriter::new();
        w.string_field(1, "auth_preference");
        w.string_field(3, "v2");
        w.message_field(4, &meta.into_inner());
        w.message_field(5, &spec);
        w.into_inner()
    }

    fn networking_config(&self) -> Vec<u8> {
        let mut spec = ProtoWriter::new();
        spec.bool_field(7, true); // proxy_listener_mode / tls routing-ish
        let mut meta = ProtoWriter::new();
        meta.string_field(1, "cluster-networking-config");
        let mut w = ProtoWriter::new();
        w.string_field(1, "cluster_networking_config");
        w.string_field(3, "v2");
        w.message_field(4, &meta.into_inner());
        w.message_field(5, &spec.into_inner());
        w.into_inner()
    }

    fn session_recording_config(&self) -> Vec<u8> {
        let mut spec = ProtoWriter::new();
        spec.string_field(1, "off");
        let mut meta = ProtoWriter::new();
        meta.string_field(1, "session-recording-config");
        let mut w = ProtoWriter::new();
        w.string_field(1, "session_recording_config");
        w.string_field(3, "v2");
        w.message_field(4, &meta.into_inner());
        w.message_field(5, &spec.into_inner());
        w.into_inner()
    }

    fn audit_config(&self) -> Vec<u8> {
        let mut spec = ProtoWriter::new();
        spec.string_field(1, "off");
        let mut meta = ProtoWriter::new();
        meta.string_field(1, "cluster-audit-config");
        let mut w = ProtoWriter::new();
        w.string_field(1, "cluster_audit_config");
        w.string_field(3, "v2");
        w.message_field(4, &meta.into_inner());
        w.message_field(5, &spec.into_inner());
        w.into_inner()
    }

    fn current_user(&self) -> Vec<u8> {
        let mut spec = ProtoWriter::new();
        spec.string_field(1, "admin");
        spec.string_field(2, "access");
        spec.string_field(2, "editor");
        let mut meta = ProtoWriter::new();
        meta.string_field(1, "admin");
        let mut w = ProtoWriter::new();
        w.string_field(1, "user");
        w.string_field(3, "v2");
        w.message_field(4, &meta.into_inner());
        w.message_field(5, &spec.into_inner());
        w.into_inner()
    }

    fn cluster_name(&self) -> Vec<u8> {
        let mut spec = ProtoWriter::new();
        spec.string_field(1, &self.cfg.cluster_name);
        spec.string_field(2, &self.cfg.cluster_name);
        let mut meta = ProtoWriter::new();
        meta.string_field(1, "cluster-name");
        let mut w = ProtoWriter::new();
        w.string_field(1, "cluster_name");
        w.string_field(3, "v2");
        w.message_field(4, &meta.into_inner());
        w.message_field(5, &spec.into_inner());
        w.into_inner()
    }

    fn namespace(&self) -> Vec<u8> {
        let mut meta = ProtoWriter::new();
        meta.string_field(1, "default");
        meta.string_field(2, "default");
        let mut w = ProtoWriter::new();
        w.string_field(1, "namespace");
        w.string_field(3, "v2");
        w.message_field(4, &meta.into_inner());
        w.message_field(5, &[]);
        w.into_inner()
    }

    fn namespaces(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.message_field(1, &self.namespace());
        w.into_inner()
    }

    fn cert_authorities(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.message_field(
            1,
            &encode_ca_v2(
                "host",
                &self.ca.cluster_name,
                &self.ca.host_ssh.public_openssh,
                &self.ca.host_tls.cert_pem,
            ),
        );
        w.message_field(
            1,
            &encode_ca_v2(
                "user",
                &self.ca.cluster_name,
                &self.ca.user_ssh.public_openssh,
                &self.ca.user_tls.cert_pem,
            ),
        );
        w.into_inner()
    }

    fn get_role(&self, msg: &[u8]) -> Vec<u8> {
        let fields = decode_message(msg).unwrap_or_default();
        let name = field_string(&fields, 1).unwrap_or_else(|| "access".into());
        encode_role(&name)
    }

    fn get_roles(&self) -> Vec<u8> {
        let mut w = ProtoWriter::new();
        w.message_field(1, &encode_role("access"));
        w.message_field(1, &encode_role("editor"));
        w.into_inner()
    }

    fn get_cert_authority(&self, msg: &[u8]) -> Vec<u8> {
        let fields = decode_message(msg).unwrap_or_default();
        let typ = field_string(&fields, 1).unwrap_or_else(|| "host".into());
        if typ.eq_ignore_ascii_case("user") {
            encode_ca_v2(
                "user",
                &self.ca.cluster_name,
                &self.ca.user_ssh.public_openssh,
                &self.ca.user_tls.cert_pem,
            )
        } else {
            encode_ca_v2(
                "host",
                &self.ca.cluster_name,
                &self.ca.host_ssh.public_openssh,
                &self.ca.host_tls.cert_pem,
            )
        }
    }

    fn watch_events(&self) -> Result<Response<BoxBody>> {
        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, anyhow::Error>>(4);
        let init = grpc_frame(&encode_watch_init());
        tokio::spawn(async move {
            let _ = tx.send(Ok(Frame::data(Bytes::from(init)))).await;
            // keep stream open until client disconnects
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if tx.is_closed() {
                    break;
                }
            }
        });
        streaming(rx)
    }

    fn inventory_stream(&self) -> Result<Response<BoxBody>> {
        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, anyhow::Error>>(4);
        tokio::spawn(async move {
            // Hello / keep stream open without blocking the agent event loop for an hour.
            let hello = encode_empty();
            let _ = tx.send(Ok(Frame::data(Bytes::from(grpc_frame(&hello))))).await;
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                if tx.is_closed() {
                    break;
                }
            }
        });
        streaming(rx)
    }

    async fn proxy_ssh(&self, req: Request<Incoming>) -> Result<Response<BoxBody>> {
        let tunnels = self.tunnels.clone();
        let store = self.store.clone();
        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, anyhow::Error>>(64);
        tokio::spawn(async move {
            if let Err(e) = run_proxy_ssh(req.into_body(), tx.clone(), tunnels, store).await {
                warn!("ProxySSH: {e:#}");
                let _ = tx.send(Ok(Frame::trailers(grpc_trailers(2, &e.to_string())))).await;
            } else {
                let _ = tx.send(Ok(Frame::trailers(grpc_trailers(0, "")))).await;
            }
        });
        streaming(rx)
    }
}

fn encode_role(name: &str) -> Vec<u8> {
    let mut labels = ProtoWriter::new();
    let mut values = ProtoWriter::new();
    values.string_field(1, "*");
    let mut entry = ProtoWriter::new();
    entry.string_field(1, "*");
    entry.message_field(2, &values.into_inner());
    labels.message_field(1, &entry.into_inner());

    let mut allow = ProtoWriter::new();
    allow.string_field(1, "root");
    allow.string_field(1, "ubuntu");
    allow.string_field(1, "packer");
    allow.string_field(1, "admin");
    allow.string_field(2, "default");
    allow.message_field(3, &labels.into_inner());

    let mut spec = ProtoWriter::new();
    spec.message_field(2, &allow.into_inner());

    let mut meta = ProtoWriter::new();
    meta.string_field(1, name);
    let mut w = ProtoWriter::new();
    w.string_field(1, "role");
    w.string_field(3, "v7");
    w.message_field(4, &meta.into_inner());
    w.message_field(5, &spec.into_inner());
    w.into_inner()
}

fn encode_ca_v2(kind: &str, cluster: &str, ssh_pub: &str, tls_pem: &[u8]) -> Vec<u8> {
    let mut sshk = ProtoWriter::new();
    sshk.bytes_field(1, ssh_pub.trim().as_bytes());
    let mut tlsk = ProtoWriter::new();
    tlsk.bytes_field(1, tls_pem);
    let mut keys = ProtoWriter::new();
    keys.message_field(1, &sshk.into_inner());
    keys.message_field(2, &tlsk.into_inner());
    let mut spec = ProtoWriter::new();
    spec.string_field(1, kind);
    spec.string_field(2, cluster);
    spec.message_field(11, &keys.into_inner());
    let mut meta = ProtoWriter::new();
    meta.string_field(1, cluster);
    let mut w = ProtoWriter::new();
    w.string_field(1, "cert_authority");
    w.string_field(3, "v2");
    w.message_field(4, &meta.into_inner());
    w.message_field(5, &spec.into_inner());
    w.into_inner()
}

pub fn encode_server_v2(node: &Node, _cluster: &str) -> Vec<u8> {
    let display = if !node.hostname.is_empty() && !crate::store::looks_like_uuid(&node.hostname) {
        node.hostname.as_str()
    } else if !node.name.is_empty() && !crate::store::looks_like_uuid(&node.name) {
        node.name.as_str()
    } else if !node.hostname.is_empty() {
        node.hostname.as_str()
    } else {
        node.host_id.as_str()
    };
    let mut meta = ProtoWriter::new();
    meta.string_field(1, display);
    meta.string_field(3, crate::config::DEFAULT_NAMESPACE);
    let mut spec = ProtoWriter::new();
    // Plain hostname in Address. use_tunnel is kept internally for dialing, but
    // advertising it makes tsh print "← Tunnel" (mojibake in many terminals).
    spec.string_field(1, display);
    spec.string_field(3, display);
    spec.string_field(7, &node.version);
    let mut w = ProtoWriter::new();
    w.string_field(1, "node");
    w.string_field(3, "v2");
    w.message_field(4, &meta.into_inner());
    w.message_field(5, &spec.into_inner());
    w.into_inner()
}

fn unary(msg: Vec<u8>) -> Result<Response<BoxBody>> {
    let body = grpc_frame(&msg);
    let (tx, rx) = mpsc::channel(2);
    tokio::spawn(async move {
        let _ = tx.send(Ok(Frame::data(Bytes::from(body)))).await;
        let _ = tx.send(Ok(Frame::trailers(grpc_trailers(0, "")))).await;
    });
    streaming(rx)
}

fn streaming(
    rx: mpsc::Receiver<Result<Frame<Bytes>, anyhow::Error>>,
) -> Result<Response<BoxBody>> {
    let stream = ReceiverStream::new(rx);
    let body = StreamBody::new(stream);
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(BoxBody::new(body))?;
    Ok(resp)
}

async fn run_proxy_ssh(
    mut body: Incoming,
    tx: mpsc::Sender<Result<Frame<Bytes>, anyhow::Error>>,
    tunnels: TunnelHub,
    store: Store,
) -> Result<()> {
    let mut buf = Vec::new();
    let first = loop {
        if let Some(f) = take_grpc_frame(&mut buf) {
            break f;
        }
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    buf.extend_from_slice(&data);
                }
            }
            Some(Err(e)) => anyhow::bail!("proxy ssh body: {e}"),
            None => anyhow::bail!("proxy ssh: empty stream"),
        }
    };
    let fields = decode_message(&first).unwrap_or_default();
    let target = field_bytes(&fields, 1).unwrap_or_default();
    let tfields = decode_message(&target).unwrap_or_default();
    let host_port = field_string(&tfields, 1).unwrap_or_default();
    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or(host_port);
    tracing::info!(%host, "ProxySSH dial");
    let mut stream = dial_node(&tunnels, &store, &host).await?;

    // First response is ClusterDetails only.
    let mut details = ProtoWriter::new();
    details.message_field(1, &[]);
    if tx
        .send(Ok(Frame::data(Bytes::from(grpc_frame(&details.into_inner())))))
        .await
        .is_err()
    {
        return Ok(());
    }

    let (mut sr, mut sw) = tokio::io::split(&mut stream);
    let t1 = {
        let tx = tx.clone();
        async move {
            let mut rbuf = vec![0u8; 32 * 1024];
            loop {
                match sr.read(&mut rbuf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut inner = ProtoWriter::new();
                        inner.bytes_field(1, &rbuf[..n]);
                        let mut w = ProtoWriter::new();
                        w.message_field(2, &inner.into_inner());
                        if tx
                            .send(Ok(Frame::data(Bytes::from(grpc_frame(&w.into_inner())))))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        }
    };
    let t2 = async move {
        // leftover ssh frame on the first message
        if let Some(ssh) = field_bytes(&fields, 2) {
            let inner = decode_message(&ssh).unwrap_or_default();
            if let Some(p) = field_bytes(&inner, 1) {
                if sw.write_all(&p).await.is_ok() {
                    let _ = sw.flush().await;
                }
            }
        }
        loop {
            while let Some(frame) = take_grpc_frame(&mut buf) {
                let f = decode_message(&frame).unwrap_or_default();
                if let Some(ssh) = field_bytes(&f, 2) {
                    let inner = decode_message(&ssh).unwrap_or_default();
                    if let Some(p) = field_bytes(&inner, 1) {
                        if sw.write_all(&p).await.is_err() {
                            return;
                        }
                        let _ = sw.flush().await;
                    }
                }
            }
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        buf.extend_from_slice(&data);
                    }
                }
                _ => break,
            }
        }
        let _ = sw.shutdown().await;
    };
    tokio::join!(t1, t2);
    Ok(())
}

fn take_grpc_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 5 {
        return None;
    }
    let len = u32::from_be_bytes(buf[1..5].try_into().ok()?) as usize;
    if buf.len() < 5 + len {
        return None;
    }
    let payload = buf[5..5 + len].to_vec();
    buf.drain(..5 + len);
    Some(payload)
}

async fn dial_node(tunnels: &TunnelHub, store: &Store, host: &str) -> Result<tokio::io::DuplexStream> {
    let host = host.split('.').next().unwrap_or(host);
    let mut req = crate::tunnel::DialReq::default();
    req.address = "@local-node".into();
    req.conn_type = "ssh".into();
    if tunnels.has_agent(host) {
        return tunnels.dial(host, req).await;
    }
    if let Some(n) = store.find_node(host) {
        req.server_id = n.host_id.clone();
        if tunnels.has_agent(&n.host_id) {
            return tunnels.dial(&n.host_id, req).await;
        }
        if tunnels.has_agent(&n.hostname) {
            return tunnels.dial(&n.hostname, req).await;
        }
        if tunnels.has_agent(&n.name) {
            return tunnels.dial(&n.name, req).await;
        }
    }
    // Last resort: any live reverse tunnel (single-node demo / stale UUID from tsh).
    if let Some(id) = tunnels.live_ids().into_iter().next() {
        tracing::warn!(requested = %host, using = %id, "falling back to live reverse tunnel");
        return tunnels.dial(&id, req).await;
    }
    anyhow::bail!("no reverse tunnel for {host}")
}

fn grpc_trailers(status: u16, message: &str) -> http::HeaderMap {
    let mut trailers = http::HeaderMap::new();
    let status = if status == 0 { "0" } else { "2" };
    if let Ok(v) = http::HeaderValue::from_str(status) {
        trailers.insert("grpc-status", v);
    }
    let msg = message.replace(['\n', '\r'], " ");
    if let Ok(v) = http::HeaderValue::from_str(&msg) {
        trailers.insert("grpc-message", v);
    }
    trailers
}

pub fn register_using_token_json(ca: &ClusterCA, store: &Store, body: serde_json::Value) -> Result<serde_json::Value> {
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("token required"))?;
    store
        .get_token(token)
        .ok_or_else(|| anyhow!("invalid join token"))?;
    let host_id = body
        .get("hostID")
        .or_else(|| body.get("host_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let host_id = if host_id.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        host_id
    };
    let node_name = body
        .get("node_name")
        .and_then(|v| v.as_str())
        .unwrap_or(&host_id)
        .to_string();
    let role = body.get("role").and_then(|v| v.as_str()).unwrap_or("Node").to_string();
    let tls_pub = json_bytes(&body, "public_tls_key")?;
    let ssh_pub = json_bytes(&body, "public_ssh_key")?;
    let additional = json_string_list(&body, "additional_principals");
    let dns = json_string_list(&body, "dns_names");
    let ttl = Duration::from_secs(24 * 3600);
    let tls = if tls_pub.is_empty() {
        Vec::new()
    } else {
        ca.issue_host_tls(&tls_pub, &additional, &dns, &role, &host_id, ttl)?
    };
    let ssh = if ssh_pub.is_empty() {
        Vec::new()
    } else {
        ca.issue_host_ssh(&ssh_pub, &host_id, &node_name, &additional, &role, ttl)?
    };
    Ok(serde_json::json!({
        "ssh": b64(&ssh),
        "tls": b64(&tls),
        "tls_ca_certs": [b64(&ca.host_tls.cert_pem)],
        "ssh_ca_certs": [b64(&ca.ssh_host_ca_authorized_key())],
    }))
}

pub fn authenticate_user_json(ca: &ClusterCA, store: &Store, body: serde_json::Value) -> Result<serde_json::Value> {
    let user = body.get("user").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let rec = store.get_user(user).ok_or_else(|| anyhow!("access denied"))?;
    if !verify_password(password, &rec.password_hash) {
        return Err(anyhow!("access denied"));
    }
    let pub_key = json_bytes(&body, "pub_key")?;
    let ttl = Duration::from_secs(12 * 3600);
    let ssh = ca.issue_user_ssh(&pub_key, &rec.name, &rec.logins, &rec.roles, ttl)?;
    let tls = ca.issue_user_tls_from_ssh(&pub_key, &rec.name, &rec.roles, ttl)?;
    let ssh_ca = ca.ssh_host_ca_authorized_key();
    Ok(serde_json::json!({
        "username": rec.name,
        "cert": b64(&ssh),
        "tls_cert": b64(&tls),
        "host_signers": [{
            "domain_name": ca.cluster_name,
            "checking_keys": [b64(&ssh_ca)],
            "tls_certs": [b64(&ca.host_tls.cert_pem)],
        }]
    }))
}

fn json_bytes(v: &serde_json::Value, key: &str) -> Result<Vec<u8>> {
    match v.get(key) {
        None => Ok(Vec::new()),
        Some(serde_json::Value::String(s)) => {
            use base64::Engine;
            if let Ok(d) = base64::engine::general_purpose::STANDARD.decode(s) {
                Ok(d)
            } else {
                Ok(s.as_bytes().to_vec())
            }
        }
        Some(serde_json::Value::Array(arr)) => Ok(arr.iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect()),
        _ => Ok(Vec::new()),
    }
}

fn json_string_list(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|i| i.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

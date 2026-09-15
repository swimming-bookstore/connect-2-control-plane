use anyhow::{anyhow, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{duplex, DuplexStream};
use tokio::sync::mpsc;
use tracing::info;

pub const CHAN_HEARTBEAT: &str = "teleport-heartbeat";
pub const CHAN_DISCOVERY: &str = "teleport-discovery";
pub const CHAN_TRANSPORT: &str = "teleport-transport";
pub const REQ_TRANSPORT_DIAL: &str = "teleport-transport-dial";

#[derive(Clone)]
pub struct TunnelHub {
    inner: Arc<Inner>,
}

struct Inner {
    // host_id -> dial sender
    agents: DashMap<String, mpsc::Sender<DialJob>>,
    by_name: DashMap<String, String>,
}

pub struct DialJob {
    pub req: DialReq,
    pub stream: DuplexStream,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DialReq {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub server_id: String,
    #[serde(default)]
    pub conn_type: String,
    #[serde(default)]
    pub client_src_addr: String,
    #[serde(default)]
    pub client_dst_addr: String,
    #[serde(default)]
    pub is_agentless_node: bool,
}

impl TunnelHub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                agents: DashMap::new(),
                by_name: DashMap::new(),
            }),
        }
    }

    pub fn register(&self, host_id: String, hostname: String, tx: mpsc::Sender<DialJob>) {
        info!(%host_id, %hostname, "reverse tunnel agent registered");
        if !hostname.is_empty() && hostname != host_id {
            self.inner.by_name.insert(hostname, host_id.clone());
        }
        self.inner.agents.insert(host_id, tx);
    }

    pub fn unregister(&self, host_id: &str, tx: &mpsc::Sender<DialJob>) {
        self.inner.agents.remove_if(host_id, |_, cur| cur.same_channel(tx));
        self.inner.by_name.retain(|_, id| id != host_id);
        info!(%host_id, "reverse tunnel agent gone");
    }

    pub fn lookup(&self, host: &str) -> Option<String> {
        if self.inner.agents.contains_key(host) {
            return Some(host.to_string());
        }
        if let Some(id) = self.inner.by_name.get(host) {
            let id = id.value().clone();
            if self.inner.agents.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }

    pub async fn dial(&self, host: &str, mut req: DialReq) -> Result<DuplexStream> {
        let id = self
            .lookup(host)
            .ok_or_else(|| anyhow!("no reverse tunnel for {host}"))?;
        let tx = self
            .inner
            .agents
            .get(&id)
            .ok_or_else(|| anyhow!("agent disconnected"))?
            .clone();
        if req.server_id.is_empty() {
            req.server_id = id.clone();
        }
        if req.address.is_empty() {
            req.address = host.to_string();
        }
        let (a, b) = duplex(64 * 1024);
        tx.send(DialJob { req, stream: a })
            .await
            .map_err(|_| anyhow!("agent channel closed"))?;
        Ok(b)
    }

    pub fn has_agent(&self, host: &str) -> bool {
        self.lookup(host).is_some()
    }

    pub fn live_ids(&self) -> Vec<String> {
        self.inner.agents.iter().map(|e| e.key().clone()).collect()
    }
}

pub fn parse_dial_req(payload: &[u8]) -> DialReq {
    if let Ok(r) = serde_json::from_slice::<DialReq>(payload) {
        if !r.address.is_empty() || !r.server_id.is_empty() {
            return r;
        }
    }
    DialReq {
        address: String::from_utf8_lossy(payload).to_string(),
        ..Default::default()
    }
}

pub fn parse_proxy_subsystem(name: &str) -> Result<ProxyTarget> {
    let rest = name
        .strip_prefix("proxy:")
        .ok_or_else(|| anyhow!("not a proxy subsystem"))?;
    let parts: Vec<&str> = rest.split('@').collect();
    let (hostport, cluster) = match parts.as_slice() {
        [hp] => (*hp, ""),
        [hp, cluster] => (*hp, *cluster),
        [hp, _ns, cluster, ..] => (*hp, *cluster),
        _ => ("", ""),
    };
    let (host, port) = if hostport.is_empty() {
        (String::new(), String::new())
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        (h.to_string(), p.to_string())
    } else {
        (hostport.to_string(), "0".into())
    };
    Ok(ProxyTarget {
        host,
        port,
        cluster: cluster.to_string(),
    })
}

#[derive(Debug, Clone)]
pub struct ProxyTarget {
    pub host: String,
    pub port: String,
    pub cluster: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_subsystem_host_port() {
        let t = parse_proxy_subsystem("proxy:node.example:22").expect("parse");
        assert_eq!(t.host, "node.example");
        assert_eq!(t.port, "22");
    }

    #[test]
    fn proxy_subsystem_cluster() {
        let t = parse_proxy_subsystem("proxy:node:22@connect2.local").expect("parse");
        assert_eq!(t.host, "node");
        assert_eq!(t.cluster, "connect2.local");
    }

    #[test]
    fn proxy_subsystem_auth() {
        let t = parse_proxy_subsystem("proxy:@connect2.local").expect("parse");
        assert!(t.host.is_empty());
        assert_eq!(t.cluster, "connect2.local");
    }

    #[tokio::test]
    async fn register_and_lookup() {
        let hub = TunnelHub::new();
        let (tx, _rx) = mpsc::channel(1);
        hub.register("host-id".into(), "agent-node".into(), tx);
        assert!(hub.has_agent("agent-node"));
        assert_eq!(hub.lookup("agent-node").as_deref(), Some("host-id"));
        assert_eq!(hub.live_ids(), vec!["host-id".to_string()]);
    }
}

use crate::identity::{hash_password, Node, Role, Token, User};
use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    users: DashMap<String, User>,
    tokens: DashMap<String, Token>,
    nodes: DashMap<String, Node>,
    roles: DashMap<String, Role>,
}

#[derive(Serialize, Deserialize, Default)]
struct Snapshot {
    users: Vec<User>,
    tokens: Vec<Token>,
    nodes: Vec<Node>,
    roles: Vec<Role>,
}

impl Store {
    pub fn load_or_init(data_dir: &Path, admin_user: &str, admin_pass: &str, join_token: &str) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join("state.json");
        let store = Self {
            inner: Arc::new(Inner {
                path: path.clone(),
                users: DashMap::new(),
                tokens: DashMap::new(),
                nodes: DashMap::new(),
                roles: DashMap::new(),
            }),
        };
        if path.exists() {
            let snap: Snapshot = serde_json::from_slice(&std::fs::read(&path)?)?;
            for u in snap.users {
                store.inner.users.insert(u.name.clone(), u);
            }
            for t in snap.tokens {
                store.inner.tokens.insert(t.name.clone(), t);
            }
            for r in snap.roles {
                store.inner.roles.insert(r.name.clone(), r);
            }
            // Ignore snap.nodes — inventory is rebuilt from live reverse tunnels.
        } else {
            store.seed(admin_user, admin_pass, join_token)?;
        }
        if store.inner.tokens.is_empty() {
            store.inner.tokens.insert(
                join_token.to_string(),
                Token {
                    name: join_token.to_string(),
                    roles: vec!["Node".into()],
                    expires: None,
                },
            );
            store.persist()?;
        }
        Ok(store)
    }

    fn seed(&self, admin_user: &str, admin_pass: &str, join_token: &str) -> Result<()> {
        let logins = vec![
            "root".into(),
            "ubuntu".into(),
            "packer".into(),
            admin_user.to_string(),
        ];
        self.inner.roles.insert(
            "access".into(),
            Role {
                name: "access".into(),
                logins: logins.clone(),
                node_labels: Default::default(),
            },
        );
        self.inner.roles.insert(
            "editor".into(),
            Role {
                name: "editor".into(),
                logins: logins.clone(),
                node_labels: Default::default(),
            },
        );
        self.inner.users.insert(
            admin_user.to_string(),
            User {
                name: admin_user.to_string(),
                password_hash: hash_password(admin_pass),
                roles: vec!["access".into(), "editor".into()],
                logins,
            },
        );
        self.inner.tokens.insert(
            join_token.to_string(),
            Token {
                name: join_token.to_string(),
                roles: vec!["Node".into(), "App".into(), "Db".into(), "Kube".into(), "Proxy".into()],
                expires: None,
            },
        );
        self.persist()
    }

    pub fn persist(&self) -> Result<()> {
        let snap = Snapshot {
            users: self.inner.users.iter().map(|e| e.value().clone()).collect(),
            tokens: self.inner.tokens.iter().map(|e| e.value().clone()).collect(),
            // Nodes are live inventory; do not keep stale UUID rows across restarts.
            nodes: Vec::new(),
            roles: self.inner.roles.iter().map(|e| e.value().clone()).collect(),
        };
        let tmp = self.inner.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&snap)?)?;
        std::fs::rename(tmp, &self.inner.path)?;
        Ok(())
    }

    pub fn get_user(&self, name: &str) -> Option<User> {
        self.inner.users.get(name).map(|e| e.clone())
    }

    pub fn get_token(&self, name: &str) -> Option<Token> {
        self.inner.tokens.get(name).map(|e| e.clone())
    }

    pub fn upsert_node(&self, mut node: Node) {
        if looks_like_uuid(&node.hostname) {
            if let Some(prev) = self.inner.nodes.get(&node.host_id) {
                if !looks_like_uuid(&prev.hostname) {
                    node.hostname = prev.hostname.clone();
                }
            }
        }
        if looks_like_uuid(&node.name) && !looks_like_uuid(&node.hostname) {
            node.name = node.hostname.clone();
        }
        if node.use_tunnel {
            node.addr.clear();
        }
        let host_id = node.host_id.clone();
        let hostname = node.hostname.clone();
        self.inner.nodes.retain(|id, n| {
            id == &host_id || (hostname.is_empty() || n.hostname != hostname)
        });
        self.inner.nodes.insert(host_id, node);
    }

    pub fn heartbeat_node(&self, host_id: &str, hostname: &str) {
        let hostname = hostname.to_string();
        self.inner
            .nodes
            .entry(host_id.to_string())
            .and_modify(|n| {
                n.last_heartbeat = crate::ca::now_unix();
                n.use_tunnel = true;
                if !hostname.is_empty() && !looks_like_uuid(&hostname) {
                    n.hostname = hostname.clone();
                    n.name = hostname.clone();
                }
                n.addr.clear();
            })
            .or_insert_with(|| Node {
                name: hostname.clone(),
                host_id: host_id.to_string(),
                hostname,
                addr: String::new(),
                version: crate::config::TELEPORT_VERSION.into(),
                use_tunnel: true,
                labels: Default::default(),
                last_heartbeat: crate::ca::now_unix(),
            });
    }

    pub fn nodes(&self) -> Vec<Node> {
        let mut out: Vec<Node> = self.inner.nodes.iter().map(|e| e.value().clone()).collect();
        out.sort_by(|a, b| a.hostname.cmp(&b.hostname).then(a.host_id.cmp(&b.host_id)));
        out.dedup_by(|a, b| {
            (!a.hostname.is_empty() && a.hostname == b.hostname)
                || a.host_id == b.host_id
                || a.name == b.name
        });
        out
    }

    pub fn find_node(&self, host: &str) -> Option<Node> {
        self.inner
            .nodes
            .iter()
            .find(|n| n.name == host || n.hostname == host || n.host_id == host || n.addr == host)
            .map(|e| e.value().clone())
    }

}

pub fn looks_like_uuid(s: &str) -> bool {
    s.len() == 36 && s.bytes().filter(|b| *b == b'-').count() == 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn uuid_shape() {
        assert!(looks_like_uuid("2283f2f6-6e63-4ec1-9289-b5868699abcd"));
        assert!(!looks_like_uuid("agent-node"));
    }

    #[test]
    fn seed_and_find() {
        let dir = std::env::temp_dir().join(format!("c2cp-store-{}", Uuid::new_v4()));
        let store = Store::load_or_init(&dir, "admin", "secret", "join-token").unwrap();
        assert!(store.get_user("admin").is_some());
        assert!(store.get_token("join-token").is_some());
        store.upsert_node(Node {
            name: "agent-node".into(),
            host_id: "2283f2f6-6e63-4ec1-9289-b5868699abcd".into(),
            hostname: "agent-node".into(),
            addr: String::new(),
            version: "16.4.3".into(),
            use_tunnel: true,
            labels: Default::default(),
            last_heartbeat: 0,
        });
        assert_eq!(store.find_node("agent-node").unwrap().hostname, "agent-node");
        store.upsert_node(Node {
            name: "2283f2f6-6e63-4ec1-9289-b5868699abcd".into(),
            host_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
            hostname: "agent-node".into(),
            addr: String::new(),
            version: "16.4.3".into(),
            use_tunnel: true,
            labels: Default::default(),
            last_heartbeat: 0,
        });
        assert_eq!(store.nodes().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const TELEPORT_VERSION: &str = "16.4.3";
pub const MIN_CLIENT_VERSION: &str = "13.0.0";
pub const API_DOMAIN: &str = "teleport.cluster.local";
pub const DEFAULT_NAMESPACE: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub cluster_name: String,
    pub public_addr: String,
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    #[serde(default = "default_insecure")]
    pub insecure_skip_verify: bool,
}

fn default_insecure() -> bool {
    true
}

impl ClusterConfig {
    pub fn load_or_default(data_dir: &Path, cluster_name: &str, listen: SocketAddr, public_addr: &str) -> Result<Self> {
        let path = data_dir.join("config.yaml");
        if path.exists() {
            let raw = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            return Ok(serde_yaml::from_str(&raw)?);
        }
        Ok(Self {
            cluster_name: cluster_name.to_string(),
            public_addr: public_addr.to_string(),
            listen,
            data_dir: data_dir.to_path_buf(),
            insecure_skip_verify: true,
        })
    }

    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        let path = self.data_dir.join("config.yaml");
        std::fs::write(&path, serde_yaml::to_string(self)?)?;
        Ok(())
    }

    pub fn web_public_host(&self) -> String {
        self.public_addr
            .split(':')
            .next()
            .unwrap_or(&self.public_addr)
            .to_string()
    }
}

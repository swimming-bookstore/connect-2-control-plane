use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub password_hash: String,
    pub roles: Vec<String>,
    pub logins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub name: String,
    pub roles: Vec<String>,
    pub expires: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub name: String,
    pub host_id: String,
    pub hostname: String,
    pub addr: String,
    pub version: String,
    pub use_tunnel: bool,
    pub labels: HashMap<String, String>,
    pub last_heartbeat: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub logins: Vec<String>,
    pub node_labels: HashMap<String, String>,
}

pub fn hash_password(pw: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(pw.as_bytes()))
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    hash_password(pw) == hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("adminadmin");
        assert!(verify_password("adminadmin", &h));
        assert!(!verify_password("nope", &h));
    }
}

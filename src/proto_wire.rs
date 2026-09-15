//! Minimal protobuf encoder/decoder for the Teleport RPCs this control plane implements.

use anyhow::{anyhow, Result};

pub const WIRE_VARINT: u32 = 0;
pub const WIRE_LEN: u32 = 2;

#[derive(Clone, Debug)]
pub struct ProtoWriter {
    buf: Vec<u8>,
}

impl ProtoWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    pub fn tag(&mut self, field: u32, wire: u32) {
        self.varint(((field << 3) | wire) as u64);
    }

    pub fn varint(&mut self, mut v: u64) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            self.buf.push(b);
            if v == 0 {
                break;
            }
        }
    }

    pub fn bytes_field(&mut self, field: u32, data: &[u8]) {
        self.tag(field, WIRE_LEN);
        self.varint(data.len() as u64);
        self.buf.extend_from_slice(data);
    }

    pub fn string_field(&mut self, field: u32, s: &str) {
        self.bytes_field(field, s.as_bytes());
    }

    pub fn bool_field(&mut self, field: u32, v: bool) {
        if v {
            self.tag(field, WIRE_VARINT);
            self.varint(1);
        }
    }

    pub fn uint32_field(&mut self, field: u32, v: u32) {
        if v != 0 {
            self.tag(field, WIRE_VARINT);
            self.varint(v as u64);
        }
    }

    pub fn int32_field(&mut self, field: u32, v: i32) {
        if v != 0 {
            self.tag(field, WIRE_VARINT);
            self.varint(v as u64);
        }
    }

    pub fn int64_field(&mut self, field: u32, v: i64) {
        if v != 0 {
            self.tag(field, WIRE_VARINT);
            self.varint(v as u64);
        }
    }

    pub fn message_field(&mut self, field: u32, inner: &[u8]) {
        self.bytes_field(field, inner);
    }

    pub fn timestamp_field(&mut self, field: u32, unix_secs: i64, nanos: i32) {
        let mut inner = ProtoWriter::new();
        inner.int64_field(1, unix_secs);
        inner.int32_field(2, nanos);
        self.message_field(field, &inner.into_inner());
    }
}

impl Default for ProtoWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct Field {
    pub number: u32,
    pub wire: u32,
    pub data: Vec<u8>,
    pub varint: u64,
}

pub fn decode_message(mut buf: &[u8]) -> Result<Vec<Field>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let (tag, rest) = read_varint(buf)?;
        buf = rest;
        let number = (tag >> 3) as u32;
        let wire = (tag & 7) as u32;
        match wire {
            WIRE_VARINT => {
                let (v, rest) = read_varint(buf)?;
                buf = rest;
                out.push(Field {
                    number,
                    wire,
                    data: Vec::new(),
                    varint: v,
                });
            }
            WIRE_LEN => {
                let (len, rest) = read_varint(buf)?;
                buf = rest;
                let len = len as usize;
                if buf.len() < len {
                    return Err(anyhow!("truncated protobuf length-delimited field"));
                }
                let data = buf[..len].to_vec();
                buf = &buf[len..];
                out.push(Field {
                    number,
                    wire,
                    data,
                    varint: 0,
                });
            }
            1 => {
                if buf.len() < 8 {
                    return Err(anyhow!("truncated 64-bit field"));
                }
                buf = &buf[8..];
            }
            5 => {
                if buf.len() < 4 {
                    return Err(anyhow!("truncated 32-bit field"));
                }
                buf = &buf[4..];
            }
            other => return Err(anyhow!("unsupported protobuf wire type {other}")),
        }
    }
    Ok(out)
}

pub fn field_string(fields: &[Field], number: u32) -> Option<String> {
    fields
        .iter()
        .find(|f| f.number == number && f.wire == WIRE_LEN)
        .map(|f| String::from_utf8_lossy(&f.data).into_owned())
}

pub fn field_bytes(fields: &[Field], number: u32) -> Option<Vec<u8>> {
    fields
        .iter()
        .find(|f| f.number == number && f.wire == WIRE_LEN)
        .map(|f| f.data.clone())
}

fn read_varint(buf: &[u8]) -> Result<(u64, &[u8])> {
    let mut result = 0u64;
    let mut shift = 0;
    for (i, b) in buf.iter().enumerate() {
        result |= ((*b as u64) & 0x7f) << shift;
        if *b & 0x80 == 0 {
            return Ok((result, &buf[i + 1..]));
        }
        shift += 7;
        if shift > 63 {
            return Err(anyhow!("varint overflow"));
        }
    }
    Err(anyhow!("truncated varint"))
}

pub fn grpc_frame(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + msg.len());
    out.push(0);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

pub fn parse_grpc_frames(mut buf: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut frames = Vec::new();
    while buf.len() >= 5 {
        let compressed = buf[0];
        let len = u32::from_be_bytes(
            buf[1..5]
                .try_into()
                .map_err(|_| anyhow!("truncated grpc length"))?,
        ) as usize;
        buf = &buf[5..];
        if buf.len() < len {
            break;
        }
        let payload = buf[..len].to_vec();
        buf = &buf[len..];
        if compressed != 0 {
            return Err(anyhow!("compressed grpc frames are not supported"));
        }
        frames.push(payload);
    }
    Ok(frames)
}

pub fn encode_certs(ssh: &[u8], tls: &[u8], tls_cas: &[Vec<u8>], ssh_cas: &[Vec<u8>]) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    if !ssh.is_empty() {
        w.bytes_field(1, ssh);
    }
    if !tls.is_empty() {
        w.bytes_field(2, tls);
    }
    for ca in tls_cas {
        w.bytes_field(3, ca);
    }
    for ca in ssh_cas {
        w.bytes_field(4, ca);
    }
    w.into_inner()
}

pub fn encode_ping(cluster: &str, version: &str, public_addr: &str, remote: &str) -> Vec<u8> {
    let mut features = ProtoWriter::new();
    features.bool_field(1, true); // Kubernetes
    features.bool_field(2, true); // App
    features.bool_field(3, true); // DB
    features.bool_field(10, true); // Desktop
    // Nested feature messages so 16.5 BackfillFeatures does not nil-deref.
    features.message_field(19, &[]); // DeviceTrust
    features.message_field(21, &[]); // AccessRequests
    features.message_field(25, &[]); // AccessList
    features.message_field(26, &[]); // AccessMonitoring
    features.message_field(28, &[]); // Policy
    // Non-empty entitlements map skips BackfillFeatures entirely.
    for name in [
        "AccessLists",
        "AccessMonitoring",
        "AccessRequests",
        "App",
        "CloudAuditLogRetention",
        "DB",
        "Desktop",
        "DeviceTrust",
        "ExternalAuditStorage",
        "FeatureHiding",
        "HSM",
        "Identity",
        "JoinActiveSessions",
        "K8s",
        "MobileDeviceManagement",
        "OIDC",
        "OktaSCIM",
        "OktaUserSync",
        "Policy",
        "SAML",
        "SessionLocks",
        "UpsellAlert",
        "UsageReporting",
        "LicenseAutoUpdate",
    ] {
        let mut entry = ProtoWriter::new();
        entry.string_field(1, name);
        let mut info = ProtoWriter::new();
        if matches!(name, "App" | "DB" | "Desktop" | "K8s" | "JoinActiveSessions") {
            info.bool_field(1, true);
        }
        entry.message_field(2, &info.into_inner());
        features.message_field(35, &entry.into_inner());
    }
    let features = features.into_inner();

    let mut w = ProtoWriter::new();
    w.string_field(1, cluster);
    w.string_field(2, version);
    w.message_field(3, &features);
    w.string_field(4, public_addr);
    w.string_field(7, remote);
    w.into_inner()
}

pub fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    w.string_field(1, name);
    w.into_inner()
}

pub fn encode_cluster_ca_cert(pem: &[u8]) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    w.bytes_field(1, pem);
    w.into_inner()
}

pub fn encode_keep_alive(name: &str, namespace: &str, host_id: &str, unix_secs: i64) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    w.string_field(1, name);
    w.string_field(2, namespace);
    w.timestamp_field(4, unix_secs, 0);
    w.uint32_field(9, 1); // NODE
    w.string_field(10, host_id);
    w.into_inner()
}

pub fn encode_watch_init() -> Vec<u8> {
    // Event { Type = INIT = 0 } — zero value, empty message is valid
    // but clients look for Type field; encode Type=0 anyway
    let mut w = ProtoWriter::new();
    w.uint32_field(1, 0);
    w.into_inner()
}

pub fn encode_empty() -> Vec<u8> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_framing_roundtrip() {
        let framed = grpc_frame(b"hello");
        let parsed = parse_grpc_frames(&framed).unwrap();
        assert_eq!(parsed, vec![b"hello".to_vec()]);
    }

    #[test]
    fn certs_encode() {
        let b = encode_certs(b"ssh", b"tls", &[b"ca".to_vec()], &[b"sshca".to_vec()]);
        let f = decode_message(&b).unwrap();
        assert_eq!(f[0].number, 1);
        assert_eq!(f[1].number, 2);
    }

    #[test]
    fn ping_encode() {
        let b = encode_ping("c", "16.4.3", "127.0.0.1:3080", "1.2.3.4");
        let f = decode_message(&b).unwrap();
        assert!(f.iter().any(|x| x.number == 1));
        assert!(f.iter().any(|x| x.number == 2));
    }
}

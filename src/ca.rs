use anyhow::{anyhow, Context, Result};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::pkey::Id;
use ssh_key::{
    certificate::{Builder as CertBuilder, CertType},
    private::Ed25519Keypair as SshEd25519,
    public::{EcdsaPublicKey, KeyData},
    PublicKey as SshPublicKey,
};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;

#[derive(Clone)]
pub struct ClusterCA {
    pub cluster_name: String,
    pub data_dir: PathBuf,
    pub host_tls: TlsCA,
    pub user_tls: TlsCA,
    pub host_ssh: SshCA,
    pub user_ssh: SshCA,
}

#[derive(Clone)]
pub struct TlsCA {
    pub cert_pem: Vec<u8>,
    pub cert: X509,
    pub key: PKey<Private>,
}

#[derive(Clone)]
pub struct SshCA {
    pub public_openssh: String,
    ed25519_seed: [u8; 32],
}

impl ClusterCA {
    pub fn load_or_generate(data_dir: &Path, cluster_name: &str) -> Result<Self> {
        fs::create_dir_all(data_dir)?;
        let host_tls = TlsCA::load_or_generate(&data_dir.join("host_ca"), cluster_name)?;
        let user_tls = TlsCA::load_or_generate(&data_dir.join("user_ca"), cluster_name)?;
        let host_ssh = SshCA::load_or_generate(&data_dir.join("host_ssh_ca"))?;
        let user_ssh = SshCA::load_or_generate(&data_dir.join("user_ssh_ca"))?;
        Ok(Self {
            cluster_name: cluster_name.to_string(),
            data_dir: data_dir.to_path_buf(),
            host_tls,
            user_tls,
            host_ssh,
            user_ssh,
        })
    }

    pub fn ssh_host_ca_authorized_key(&self) -> Vec<u8> {
        format!("{}\n", self.host_ssh.public_openssh.trim()).into_bytes()
    }

    pub fn ssh_user_ca_authorized_key(&self) -> Vec<u8> {
        format!("{}\n", self.user_ssh.public_openssh.trim()).into_bytes()
    }

    pub fn issue_host_tls(
        &self,
        public_key_pem: &[u8],
        principals: &[String],
        dns_names: &[String],
        system_role: &str,
        host_id: &str,
        ttl: Duration,
    ) -> Result<Vec<u8>> {
        let pubkey = parse_public_key(public_key_pem)?;
        let mut sans = principals.to_vec();
        sans.extend(dns_names.iter().cloned());
        sans.push(self.cluster_name.clone());
        sans.push(crate::config::API_DOMAIN.to_string());
        sans.push(host_id.to_string());
        sign_leaf(
            &self.host_tls,
            &pubkey,
            host_id,
            &self.cluster_name,
            &sans,
            ttl,
            true,
            Some(system_role),
        )
    }

    pub fn issue_user_tls_from_ssh(
        &self,
        public_ssh: &[u8],
        username: &str,
        roles: &[String],
        ttl: Duration,
    ) -> Result<Vec<u8>> {
        let ssh = parse_ssh_public(public_ssh)?;
        let pubkey = ssh_public_to_pkey(&ssh)?;
        let sans = vec![username.to_string(), crate::config::API_DOMAIN.to_string()];
        sign_leaf(
            &self.user_tls,
            &pubkey,
            username,
            &self.cluster_name,
            &sans,
            ttl,
            false,
            roles.first().map(|s| s.as_str()),
        )
    }

    pub fn issue_web_server_cert(&self, dns_names: &[String], ips: &[String]) -> Result<(Vec<u8>, Vec<u8>)> {
        let rsa = Rsa::generate(2048)?;
        let key = PKey::from_rsa(rsa)?;
        let mut sans = dns_names.to_vec();
        sans.extend(ips.iter().cloned());
        sans.push(crate::config::API_DOMAIN.to_string());
        let cn = dns_names.first().cloned().unwrap_or_else(|| "teleport-proxy".into());
        let cert = sign_leaf(
            &self.host_tls,
            &key,
            &cn,
            &self.cluster_name,
            &sans,
            Duration::from_secs(3600 * 24 * 3650),
            true,
            Some("Proxy"),
        )?;
        Ok((cert, key.private_key_to_pem_pkcs8()?))
    }

    pub fn issue_host_ssh(
        &self,
        public_ssh: &[u8],
        host_id: &str,
        node_name: &str,
        principals: &[String],
        system_role: &str,
        ttl: Duration,
    ) -> Result<Vec<u8>> {
        let pubkey = parse_ssh_public(public_ssh)?;
        let mut all_principals = vec![
            node_name.to_string(),
            host_id.to_string(),
            self.cluster_name.clone(),
            crate::config::API_DOMAIN.to_string(),
        ];
        all_principals.extend(principals.iter().cloned());
        all_principals.retain(|p| !p.is_empty());
        all_principals.dedup();
        // Keep node_name first so reverse-tunnel cert principals are not a UUID.

        let mut extensions = HashMap::new();
        extensions.insert("x-teleport-role".into(), system_role.to_string());
        extensions.insert("x-teleport-authority".into(), self.cluster_name.clone());
        self.sign_ssh_cert(
            &self.host_ssh,
            &pubkey,
            CertType::Host,
            host_id,
            &all_principals,
            &extensions,
            ttl,
        )
    }

    pub fn issue_user_ssh(
        &self,
        public_ssh: &[u8],
        username: &str,
        logins: &[String],
        roles: &[String],
        ttl: Duration,
    ) -> Result<Vec<u8>> {
        let pubkey = parse_ssh_public(public_ssh)?;
        let mut principals = logins.to_vec();
        if principals.is_empty() {
            principals.push(username.to_string());
        }
        principals.push(format!("-teleport-nologin-{username}"));
        let mut extensions = HashMap::new();
        extensions.insert("permit-pty".into(), String::new());
        extensions.insert("permit-port-forwarding".into(), String::new());
        extensions.insert("permit-agent-forwarding".into(), String::new());
        extensions.insert(
            "teleport-roles".into(),
            serde_json::json!({"roles": roles}).to_string(),
        );
        extensions.insert(
            "teleport-traits".into(),
            serde_json::to_string(&serde_json::json!({"logins": logins}))
                .unwrap_or_else(|_| "{}".into()),
        );
        self.sign_ssh_cert(
            &self.user_ssh,
            &pubkey,
            CertType::User,
            username,
            &principals,
            &extensions,
            ttl,
        )
    }

    fn sign_ssh_cert(
        &self,
        ca: &SshCA,
        subject: &SshPublicKey,
        cert_type: CertType,
        key_id: &str,
        principals: &[String],
        extensions: &HashMap<String, String>,
        ttl: Duration,
    ) -> Result<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let valid_after = now.saturating_sub(60);
        let valid_before = now.saturating_add(ttl.as_secs().max(60));

        let signing = ssh_key::PrivateKey::from(SshEd25519::from_seed(&ca.ed25519_seed));
        let mut builder = CertBuilder::new_with_random_nonce(
            &mut rand::thread_rng(),
            subject.clone(),
            valid_after,
            valid_before,
        )?;
        builder.cert_type(cert_type)?;
        builder.key_id(key_id)?;
        for p in principals {
            builder.valid_principal(p)?;
        }
        for (k, v) in extensions {
            builder.extension(k, v)?;
        }
        let cert = builder.sign(&signing)?;
        Ok(cert.to_openssh()?.into_bytes())
    }

}

impl TlsCA {
    fn load_or_generate(dir: &Path, cluster_name: &str) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key");
        if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read(&cert_path)?;
            let key_pem = fs::read(&key_path)?;
            let cert = X509::from_pem(&cert_pem)?;
            let key = PKey::private_key_from_pem(&key_pem)?;
            return Ok(Self {
                cert_pem,
                cert,
                key,
            });
        }
        info!(path = %dir.display(), "generating TLS CA");
        let rsa = Rsa::generate(2048)?;
        let key = PKey::from_rsa(rsa)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_nid(Nid::COMMONNAME, &format!("{cluster_name} Teleport CA"))?;
        name.append_entry_by_nid(Nid::ORGANIZATIONNAME, cluster_name)?;
        let name = name.build();
        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&key)?;
        let mut bn = BigNum::new()?;
        bn.rand(128, MsbOption::MAYBE_ZERO, false)?;
        let serial = Asn1Integer::from_bn(&bn)?;
        builder.set_serial_number(&serial)?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(3650)?.as_ref())?;
        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .digital_signature()
                .build()?,
        )?;
        let ctx = builder.x509v3_context(None, None);
        let ski = SubjectKeyIdentifier::new().build(&ctx)?;
        builder.append_extension(ski)?;
        builder.sign(&key, MessageDigest::sha256())?;
        let cert = builder.build();
        let cert_pem = cert.to_pem()?;
        let key_pem = key.private_key_to_pem_pkcs8()?;
        fs::write(cert_path, &cert_pem)?;
        fs::write(key_path, &key_pem)?;
        Ok(Self {
            cert_pem,
            cert,
            key,
        })
    }
}

impl SshCA {
    fn load_or_generate(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let key_path = dir.join("ca");
        let pub_path = dir.join("ca.pub");
        let seed_path = dir.join("seed");
        if key_path.exists() && pub_path.exists() && seed_path.exists() {
            let mut seed = [0u8; 32];
            let raw = fs::read(&seed_path)?;
            if raw.len() != 32 {
                return Err(anyhow!("bad ssh ca seed"));
            }
            seed.copy_from_slice(&raw);
            return Ok(Self {
                public_openssh: fs::read_to_string(&pub_path)?,
                ed25519_seed: seed,
            });
        }
        info!(path = %dir.display(), "generating SSH CA");
        let kp = SshEd25519::random(&mut rand::thread_rng());
        let seed = kp.private.to_bytes();
        let private_key = ssh_key::PrivateKey::from(kp);
        let private_openssh = private_key.to_openssh(ssh_key::LineEnding::LF)?.to_string();
        let public_openssh = private_key.public_key().to_openssh()?;
        fs::write(&key_path, &private_openssh)?;
        fs::write(&pub_path, &public_openssh)?;
        fs::write(&seed_path, seed)?;
        Ok(Self {
            public_openssh,
            ed25519_seed: seed,
        })
    }
}

pub fn ssh_public_to_pkey(pk: &SshPublicKey) -> Result<PKey<Public>> {
    match pk.key_data() {
        KeyData::Ed25519(k) => PKey::public_key_from_raw_bytes(k.as_ref(), Id::ED25519)
            .context("ed25519 tls key"),
        KeyData::Rsa(k) => {
            let n = BigNum::from_slice(
                k.n.as_positive_bytes()
                    .ok_or_else(|| anyhow!("rsa n"))?,
            )?;
            let e = BigNum::from_slice(
                k.e.as_positive_bytes()
                    .ok_or_else(|| anyhow!("rsa e"))?,
            )?;
            Ok(PKey::from_rsa(Rsa::from_public_components(n, e)?)?)
        }
        KeyData::Ecdsa(k) => {
            let nid = match k {
                EcdsaPublicKey::NistP256(_) => Nid::X9_62_PRIME256V1,
                EcdsaPublicKey::NistP384(_) => Nid::SECP384R1,
                EcdsaPublicKey::NistP521(_) => Nid::SECP521R1,
            };
            let group = EcGroup::from_curve_name(nid)?;
            let mut ctx = openssl::bn::BigNumContext::new()?;
            let point = EcPoint::from_bytes(&group, k.as_sec1_bytes(), &mut ctx)?;
            let key = EcKey::from_public_key(&group, &point)?;
            Ok(PKey::from_ec_key(key)?)
        }
        other => Err(anyhow!("unsupported ssh key type for TLS: {:?}", other.algorithm())),
    }
}

fn parse_public_key(pem_or_der: &[u8]) -> Result<PKey<Public>> {
    let s = String::from_utf8_lossy(pem_or_der);
    if s.contains("BEGIN") {
        if let Ok(k) = PKey::public_key_from_pem(pem_or_der) {
            return Ok(k);
        }
        if let Ok(k) = PKey::private_key_from_pem(pem_or_der) {
            let pub_pem = k.public_key_to_pem()?;
            return Ok(PKey::public_key_from_pem(&pub_pem)?);
        }
        if let Ok(x) = X509::from_pem(pem_or_der) {
            return Ok(x.public_key()?);
        }
    }
    PKey::public_key_from_der(pem_or_der).context("parse TLS public key")
}

fn sign_leaf(
    ca: &TlsCA,
    pubkey: &PKey<impl openssl::pkey::HasPublic>,
    cn: &str,
    org: &str,
    sans: &[String],
    ttl: Duration,
    server_auth: bool,
    _role: Option<&str>,
) -> Result<Vec<u8>> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, org)?;
    if let Some(role) = _role {
        name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, role)?;
    }
    let name = name.build();
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(ca.cert.subject_name())?;
    builder.set_pubkey(pubkey)?;
    let mut bn = BigNum::new()?;
    bn.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial = Asn1Integer::from_bn(&bn)?;
    builder.set_serial_number(&serial)?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    let days = ((ttl.as_secs() / 86400) as u32).clamp(1, 3650);
    builder.set_not_after(Asn1Time::days_from_now(days)?.as_ref())?;
    builder.append_extension(BasicConstraints::new().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    let mut eku = ExtendedKeyUsage::new();
    eku.client_auth();
    if server_auth {
        eku.server_auth();
    }
    builder.append_extension(eku.build()?)?;
    if !sans.is_empty() {
        let mut san = SubjectAlternativeName::new();
        for s in sans {
            if s.parse::<std::net::IpAddr>().is_ok() {
                san.ip(s);
            } else {
                san.dns(s);
            }
        }
        let ctx = builder.x509v3_context(Some(&ca.cert), None);
        builder.append_extension(san.build(&ctx)?)?;
    }
    {
        let ctx = builder.x509v3_context(Some(&ca.cert), None);
        let ski = SubjectKeyIdentifier::new().build(&ctx)?;
        builder.append_extension(ski)?;
    }
    {
        let ctx = builder.x509v3_context(Some(&ca.cert), None);
        let aki = AuthorityKeyIdentifier::new().keyid(false).build(&ctx)?;
        builder.append_extension(aki)?;
    }
    builder.sign(&ca.key, MessageDigest::sha256())?;
    Ok(builder.build().to_pem()?)
}

fn parse_ssh_public(raw: &[u8]) -> Result<SshPublicKey> {
    let s = String::from_utf8_lossy(raw);
    let s = s.trim();
    if s.starts_with("ssh-") || s.starts_with("ecdsa-") {
        return SshPublicKey::from_openssh(s).map_err(|e| anyhow!("parse ssh public: {e}"));
    }
    if let Ok(pk) = SshPublicKey::from_bytes(raw) {
        return Ok(pk);
    }
    Err(anyhow!("unrecognized SSH public key"))
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

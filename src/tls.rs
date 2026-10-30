use crate::project::Project;
use anyhow::Result;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rcgen::{CertificateParams, DistinguishedName, DnType, PublicKeyData};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

struct RustKey {
    key: SigningKey,
    public: Vec<u8>,
}
impl RustKey {
    fn new() -> Self {
        Self::from_key(SigningKey::random(&mut rand_core::OsRng))
    }
    fn from_key(key: SigningKey) -> Self {
        let public = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self { key, public }
    }
    fn pkcs8(&self) -> Result<Vec<u8>> {
        Ok(self.key.to_pkcs8_der()?.as_bytes().to_vec())
    }
}
impl PublicKeyData for RustKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
impl rcgen::SigningKey for RustKey {
    fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        let sig: Signature = self.key.sign(msg);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls_rustcrypto::provider())
}
struct AuthorityState {
    issuer: rcgen::Issuer<'static, RustKey>,
    certificate: rcgen::Certificate,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}
pub struct Authority {
    state: std::sync::RwLock<AuthorityState>,
}
impl Authority {
    pub fn generate_key() -> Result<Vec<u8>> {
        RustKey::new().pkcs8()
    }
    pub fn load(project: &mut Project) -> Result<Self> {
        let key = match project.ca_key() {
            Some(der) => RustKey::from_key(SigningKey::from_pkcs8_der(&der)?),
            None => {
                let key = RustKey::new();
                project.set_ca_key(key.pkcs8()?)?;
                key
            }
        };
        Self::from_rust_key(key)
    }
    pub fn from_key(der: &[u8]) -> Result<Self> {
        Self::from_rust_key(RustKey::from_key(SigningKey::from_pkcs8_der(der)?))
    }
    fn from_rust_key(key: RustKey) -> Result<Self> {
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        // Explicit key-id method avoids rcgen's optional C-backed crypto feature.
        params.key_identifier_method =
            rcgen::KeyIdMethod::PreSpecified(Sha256::digest(&key.public)[..20].to_vec());
        let mut serial = Sha256::digest(&key.public)[..20].to_vec();
        serial[0] &= 0x7f;
        params.serial_number = Some(serial.into());
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Ferrite Project CA");
        params.distinguished_name = dn;
        let certificate = params.self_signed(&key)?;
        let issuer = rcgen::Issuer::new(params, key);
        Ok(Self {
            state: std::sync::RwLock::new(AuthorityState {
                issuer,
                certificate,
                cache: Mutex::new(HashMap::new()),
            }),
        })
    }
    pub fn pem(&self) -> String {
        self.state.read().unwrap().certificate.pem()
    }
    pub fn der(&self) -> CertificateDer<'static> {
        self.state.read().unwrap().certificate.der().clone()
    }
    fn issue_certificate(
        state: &AuthorityState,
        host: &str,
    ) -> Result<(rcgen::Certificate, RustKey)> {
        let key = RustKey::new();
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_identifier_method =
            rcgen::KeyIdMethod::PreSpecified(Sha256::digest(&key.public)[..20].to_vec());
        let mut serial = Sha256::digest(&key.public)[..20].to_vec();
        serial[0] &= 0x7f;
        params.serial_number = Some(serial.into());
        // Let clients distinguish this issuer from other Ferrite project CAs with
        // the same subject name, including certificates already trusted by Firefox.
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &state.issuer)?;
        Ok((cert, key))
    }
    pub fn replace(&self, authority: Self) {
        *self.state.write().unwrap() = authority.state.into_inner().unwrap();
    }
    pub fn fingerprint(&self) -> String {
        Sha256::digest(self.state.read().unwrap().certificate.der().as_ref())
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
    /// Base64 SHA-256 of the CA SubjectPublicKeyInfo (the RFC 7469 pin format
    /// accepted by Chromium's `--ignore-certificate-errors-spki-list`). Only
    /// public key material is used.
    pub fn spki_sha256_base64(&self) -> Result<String> {
        use base64::Engine as _;
        let der = self.der();
        let spki = certificate_spki(der.as_ref())
            .ok_or_else(|| anyhow::anyhow!("CA certificate has no SubjectPublicKeyInfo"))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki)))
    }
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let state = self.state.read().unwrap();
        let mut cache = state.cache.lock().unwrap();
        if let Some(config) = cache.get(host) {
            return Ok(config.clone());
        }
        let (cert, key) = Self::issue_certificate(&state, host)?;
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone(), state.certificate.der().clone()],
                PrivatePkcs8KeyDer::from(key.pkcs8()?).into(),
            )?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        if cache.len() >= 1024 {
            cache.clear();
        }
        cache.insert(host.into(), config.clone());
        Ok(config)
    }
}

/// Split one DER element into (tag, header length, total length).
fn der_element(input: &[u8]) -> Option<(u8, usize, usize)> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (length, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for index in 0..count {
            length = (length << 8) | *input.get(2 + index)? as usize;
        }
        (length, 2 + count)
    };
    let total = header.checked_add(length)?;
    (total <= input.len()).then_some((tag, header, total))
}

/// Return the encoded SubjectPublicKeyInfo of an X.509 certificate.
fn certificate_spki(certificate: &[u8]) -> Option<&[u8]> {
    const SEQUENCE: u8 = 0x30;
    let (tag, header, total) = der_element(certificate)?;
    if tag != SEQUENCE {
        return None;
    }
    let body = &certificate[header..total];
    let (tag, header, total) = der_element(body)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut fields = &body[header..total];
    // Optional explicit [0] version, then serial, signature, issuer, validity, subject.
    if fields.first() == Some(&0xa0) {
        fields = &fields[der_element(fields)?.2..];
    }
    for _ in 0..5 {
        fields = &fields[der_element(fields)?.2..];
    }
    let (tag, _, total) = der_element(fields)?;
    (tag == SEQUENCE).then(|| &fields[..total])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_pin_matches_the_ca_public_key_encoding() {
        use base64::Engine as _;
        use p256::pkcs8::EncodePublicKey;
        let mut project = Project::temporary();
        let authority = Authority::load(&mut project).unwrap();
        let key = SigningKey::from_pkcs8_der(&project.ca_key().unwrap()).unwrap();
        let spki = p256::PublicKey::from(key.verifying_key())
            .to_public_key_der()
            .unwrap();
        assert_eq!(
            authority.spki_sha256_base64().unwrap(),
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki.as_bytes()))
        );
        let other = Authority::load(&mut Project::temporary()).unwrap();
        assert_ne!(
            authority.spki_sha256_base64().unwrap(),
            other.spki_sha256_base64().unwrap()
        );
        assert!(certificate_spki(b"\x30\x03\x02\x01").is_none());
    }

    #[test]
    fn site_certificate_identifies_its_project_ca() {
        let mut project = Project::temporary();
        let authority = Authority::load(&mut project).unwrap();
        let other = Authority::load(&mut Project::temporary()).unwrap();
        let (cert, _) =
            Authority::issue_certificate(&authority.state.read().unwrap(), "www.google.com")
                .unwrap();
        let key =
            RustKey::from_key(SigningKey::from_pkcs8_der(&project.ca_key().unwrap()).unwrap());
        let digest = Sha256::digest(&key.public);
        let issuer_id = &digest[..20];
        // AuthorityKeyIdentifier is a sequence containing context tag 0 and the key identifier.
        let mut extension = vec![0x30, 0x16, 0x80, 0x14];
        extension.extend_from_slice(issuer_id);
        assert!(
            cert.der()
                .as_ref()
                .windows(extension.len())
                .any(|v| v == extension)
        );
        assert_ne!(authority.fingerprint(), other.fingerprint());
    }
}

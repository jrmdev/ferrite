use super::{Candidate, Confidence, IssueDefinition, ScanSettings, Severity};
use crate::{
    engine::Engine,
    http::Message,
    model::Exchange,
    tls::provider,
    transport::{self, Unverified},
};
use rustls::{
    RootCertStore,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor, verify_server_name,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ParsedCertificate,
};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use x509_parser::parse_x509_certificate;

pub(super) fn definitions() -> impl Iterator<Item = IssueDefinition> {
    [
        ("tls-certificate", "TLS certificate", Severity::Medium,
            "The upstream TLS certificate fails hostname, validity, trust, or certificate strength checks.",
            "Install a current certificate for the requested hostname with a valid, trusted chain and modern signature and key algorithms."),
        ("hidden-http2", "Hidden HTTP/2", Severity::Information,
            "An upstream TLS service answers HTTP/2 requests without advertising HTTP/2 through ALPN.",
            "Advertise HTTP/2 via ALPN if it is intended, or disable HTTP/2 on this listener."),
    ]
    .into_iter()
    .map(|(id, name, severity, description, remediation)| IssueDefinition {
        id: id.into(),
        name: name.into(),
        severity,
        passive: false,
        active: true,
        intrusive: false,
        description: description.into(),
        remediation: remediation.into(),
        references: vec![],
    })
}

pub(super) fn enabled(settings: &ScanSettings) -> bool {
    settings.check_enabled("tls-certificate") || settings.check_enabled("hidden-http2")
}

#[derive(Debug, Default)]
struct ObserveCertificate {
    chain: Mutex<Vec<CertificateDer<'static>>>,
}

impl ServerCertVerifier for ObserveCertificate {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.chain.lock().unwrap() = std::iter::once(leaf)
            .chain(chain)
            .map(|cert| cert.clone().into_owned())
            .collect();
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Unverified.verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Unverified.verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        Unverified.supported_verify_schemes()
    }
}

pub(super) async fn audit(engine: &Engine, scan: &ScanSettings, base: &Exchange) -> Vec<Candidate> {
    let mut settings = engine.settings();
    if !settings.scope.contains(&base.url) {
        return vec![];
    }
    if let Some(address) = engine.scanner_listener_address() {
        settings.listen = address.to_string();
    }
    let dest = &base.destination;
    if crate::model::Destination::from_url(&base.url).ok().as_ref() != Some(dest) {
        return vec![];
    }
    let timeout = Duration::from_secs(scan.timeout_secs.min(10));
    let observer = Arc::new(ObserveCertificate::default());
    let connect = async {
        let tcp = transport::connect_tcp(dest, &settings, true).await?;
        anyhow::ensure!(
            engine.settings().scope.contains(&base.url),
            "Outside current scope"
        );
        transport::connect_tls(
            tcp,
            dest,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Some(observer.clone()),
        )
        .await
    };
    let tls = tokio::time::timeout(timeout, connect)
        .await
        .ok()
        .and_then(Result::ok);
    let chain = std::mem::take(&mut *observer.chain.lock().unwrap());
    let mut findings = vec![];
    let mut add = |id: &str, confidence, detail| {
        findings.push(Candidate {
            affected: Some((dest.origin(), "TLS".into())),
            issue_id: id.into(),
            confidence,
            insertion_point: "Upstream TLS connection".into(),
            detail,
            evidence: vec![],
        })
    };
    if scan.check_enabled("tls-certificate")
        && let Some((leaf, chain)) = chain.split_first()
        && let Ok(name) = ServerName::try_from(dest.host.clone())
    {
        let mut errors = vec![];
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let now = UnixTime::now();
        match ParsedCertificate::try_from(leaf) {
            Ok(cert) => {
                if let Err(error) = verify_server_cert_signed_by_trust_anchor(
                    &cert,
                    &roots,
                    chain,
                    now,
                    provider().signature_verification_algorithms.all,
                ) {
                    errors.push(format!("Public trust validation failed: {error}"));
                }
                if verify_server_name(&cert, &name).is_err() {
                    errors.push(format!(
                        "The leaf certificate does not cover {}.",
                        dest.host
                    ));
                }
            }
            Err(error) => errors.push(format!("Malformed certificate: {error}")),
        }
        if let Ok((_, cert)) = parse_x509_certificate(leaf.as_ref()) {
            if !cert.validity().is_valid() {
                errors.push(format!(
                    "Leaf validity interval: {} to {}.",
                    cert.validity().not_before,
                    cert.validity().not_after
                ));
            }
            if let Ok(x509_parser::public_key::PublicKey::RSA(key)) = cert.public_key().parsed()
                && key.key_size() < 2048
            {
                errors.push(format!("Leaf RSA key size is {} bits.", key.key_size()));
            }
            if matches!(
                cert.signature_algorithm.algorithm.to_id_string().as_str(),
                "1.2.840.113549.1.1.4"
                    | "1.2.840.113549.1.1.5"
                    | "1.2.840.10045.4.1"
                    | "1.2.840.10040.4.3"
            ) {
                errors.push("The leaf certificate uses an obsolete MD5 or SHA-1 signature.".into());
            }
        }
        if !errors.is_empty() {
            if tls.is_none() {
                errors.push(
                    "The service presented the certificate before the handshake failed.".into(),
                );
            }
            add(
                "tls-certificate",
                if tls.is_some() {
                    Confidence::Certain
                } else {
                    Confidence::Firm
                },
                format!(
                    "{} Leaf SHA-256 fingerprint: {:x}.",
                    errors.join(" "),
                    Sha256::digest(leaf.as_ref())
                ),
            );
        }
    }
    if scan.check_enabled("hidden-http2")
        && let Some(tls) = tls
        && tls.get_ref().1.alpn_protocol() != Some(b"h2")
    {
        let connection = tls.get_ref().1;
        let alpn = connection
            .alpn_protocol()
            .map_or("no protocol".into(), |p| {
                String::from_utf8_lossy(p).into_owned()
            });
        // Send only a credential-free HEAD request on the probed connection.
        if let Ok(mut url) = url::Url::parse(&base.url)
            && {
                url.set_query(None);
                url.set_fragment(None);
                engine.settings().scope.contains(url.as_str())
            }
        {
            let request = Message {
                start: format!("HEAD {} HTTP/2", url.path()),
                headers: vec![("Host".into(), dest.authority())],
                body: vec![],
            };
            if let Ok(Ok((response, _))) = tokio::time::timeout(
                timeout,
                crate::http2::open_response(Box::new(tls), dest, &request, &settings),
            )
            .await
                && (200..600).contains(&response.status())
            {
                add(
                    "hidden-http2",
                    Confidence::Certain,
                    format!(
                        "The upstream service negotiated {alpn} after being offered h2 and http/1.1, then returned a valid HTTP/2 {} response to a HEAD request.",
                        response.status()
                    ),
                );
            }
        }
    }
    findings
}

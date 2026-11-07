use crate::{
    http::{Message, body_framing, read_head, read_message},
    model::{Destination, Settings, UpstreamKind},
    tls::provider,
};
mod response;
use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
pub(crate) use response::{IncomingResponse, LiveBody};
use rustls::{
    ClientConfig, RootCertStore,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{net::IpAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}
pub type Stream = Box<dyn AsyncIo>;

pub async fn connect(dest: &Destination, settings: &Settings) -> Result<Stream> {
    Ok(connect_protocol(dest, settings, false, false).await?.0)
}

/// A byte-preserving HTTP/1 channel, using CONNECT for HTTP upstreams.
pub async fn connect_raw(dest: &Destination, settings: &Settings) -> Result<Stream> {
    Ok(connect_protocol(dest, settings, false, true).await?.0)
}

async fn connect_protocol(
    dest: &Destination,
    settings: &Settings,
    offer_h2: bool,
    force_tunnel: bool,
) -> Result<(Stream, bool)> {
    let upstream = &settings.upstream;
    let connect_host = settings
        .dns_overrides
        .get(&dest.host)
        .cloned()
        .unwrap_or_else(|| dest.host.clone());
    let (host, port) = if upstream.kind == UpstreamKind::Direct {
        (connect_host.as_str(), dest.port)
    } else {
        (upstream.host.as_str(), upstream.port)
    };
    let mut tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("Connect to {host}:{port}"))?;
    tcp.set_nodelay(true)?;
    // Prevent a DNS/hosts redirection from sending an invisible request back to this listener.
    let bind: std::net::SocketAddr = settings.listen.parse()?;
    let peer = tcp.peer_addr()?;
    if peer.port() == bind.port() {
        ensure!(
            peer.ip() != bind.ip() && peer.ip() != tcp.local_addr()?.ip(),
            "Proxy loop detected; configure a DNS override or fallback destination"
        );
    }
    match upstream.kind {
        UpstreamKind::Direct => (),
        UpstreamKind::Http if dest.tls || force_tunnel => {
            let endpoint = Destination {
                host: connect_host.clone(),
                ..dest.clone()
            }
            .authority();
            let mut headers = format!("CONNECT {endpoint} HTTP/1.1\r\nHost: {endpoint}\r\n");
            if !upstream.username.is_empty() {
                let auth = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", upstream.username, upstream.password));
                headers.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
            }
            headers.push_str("\r\n");
            tcp.write_all(headers.as_bytes()).await?;
            // A successful CONNECT response has no HTTP entity, regardless of Content-Length.
            let mut reader = BufReader::with_capacity(1, tcp);
            let response = read_message(&mut reader, true, true, 65536).await?;
            ensure!(
                response.status() == 200,
                "HTTP upstream refused CONNECT: {}",
                response.start
            );
            tcp = reader.into_inner();
        }
        UpstreamKind::Http => (),
        UpstreamKind::Socks5 => {
            let auth = !upstream.username.is_empty();
            tcp.write_all(if auth { &[5, 1, 2] } else { &[5, 1, 0] })
                .await?;
            let mut reply = [0; 2];
            tcp.read_exact(&mut reply).await?;
            ensure!(
                reply[0] == 5 && reply[1] == if auth { 2 } else { 0 },
                "SOCKS5 authentication method refused"
            );
            if auth {
                let mut credentials = vec![1, upstream.username.len() as u8];
                credentials.extend_from_slice(upstream.username.as_bytes());
                credentials.push(upstream.password.len() as u8);
                credentials.extend_from_slice(upstream.password.as_bytes());
                tcp.write_all(&credentials).await?;
                tcp.read_exact(&mut reply).await?;
                ensure!(reply == [1, 0], "SOCKS5 credentials refused");
            }
            let mut request = vec![5, 1, 0];
            let ip = if let Ok(ip) = connect_host.parse::<IpAddr>() {
                Some(ip)
            } else if upstream.remote_dns {
                None
            } else {
                Some(
                    tokio::net::lookup_host((connect_host.as_str(), dest.port))
                        .await?
                        .next()
                        .context("No DNS records")?
                        .ip(),
                )
            };
            match ip {
                Some(IpAddr::V4(ip)) => {
                    request.push(1);
                    request.extend_from_slice(&ip.octets());
                }
                Some(IpAddr::V6(ip)) => {
                    request.push(4);
                    request.extend_from_slice(&ip.octets());
                }
                None => {
                    ensure!(connect_host.len() <= 255, "SOCKS hostname too long");
                    request.extend_from_slice(&[3, connect_host.len() as u8]);
                    request.extend_from_slice(connect_host.as_bytes());
                }
            }
            request.extend_from_slice(&dest.port.to_be_bytes());
            tcp.write_all(&request).await?;
            let mut head = [0; 4];
            tcp.read_exact(&mut head).await?;
            ensure!(
                head[0] == 5 && head[1] == 0 && head[2] == 0,
                "SOCKS5 CONNECT failed (code {})",
                head[1]
            );
            let count = match head[3] {
                1 => 4,
                4 => 16,
                3 => tcp.read_u8().await? as usize,
                _ => bail!("Invalid SOCKS address type"),
            };
            let mut discard = vec![0; count + 2];
            tcp.read_exact(&mut discard).await?;
        }
    }
    if !dest.tls {
        return Ok((Box::new(tcp), false));
    }
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = if offer_h2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    if !settings.verify_tls {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(Unverified));
    }
    let server = ServerName::try_from(dest.host.clone())?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server, tcp)
        .await?;
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    Ok((Box::new(tls), h2))
}
#[derive(Debug)]
struct Unverified;
impl ServerCertVerifier for Unverified {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            msg,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            msg,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
pub async fn send(dest: &Destination, request: &Message, settings: &Settings) -> Result<Message> {
    Ok(send_with_upgrade(dest, request, settings).await?.response)
}

pub struct HttpOutcome {
    pub response: Message,
    pub upgrade: Option<Stream>,
}

pub async fn send_with_upgrade(
    dest: &Destination,
    request: &Message,
    settings: &Settings,
) -> Result<HttpOutcome> {
    let (incoming, upgrade) = open_response(dest, request, settings, None, false).await?;
    Ok(HttpOutcome {
        response: incoming.capture(settings, None).await?.0,
        upgrade,
    })
}

pub(crate) async fn send_proxy(
    dest: &Destination,
    request: &Message,
    settings: &Settings,
    url: &str,
) -> Result<(HttpOutcome, Option<LiveBody>)> {
    let (incoming, upgrade) = open_response(dest, request, settings, None, true).await?;
    let (response, live) = incoming.capture(settings, Some(url)).await?;
    Ok((HttpOutcome { response, upgrade }, live))
}

pub(crate) async fn send_scanner(
    dest: &Destination,
    request: &Message,
    settings: &Settings,
    scope_check: &(dyn Fn() -> bool + Sync),
) -> Result<Message> {
    let (incoming, _) = open_response(dest, request, settings, Some(scope_check), false).await?;
    Ok(incoming.capture(settings, None).await?.0)
}

async fn open_response(
    dest: &Destination,
    request: &Message,
    settings: &Settings,
    scope_check: Option<&(dyn Fn() -> bool + Sync)>,
    proxy: bool,
) -> Result<(IncomingResponse, Option<Stream>)> {
    let upgrading = request.header("Upgrade").is_some();
    let (mut stream, negotiated_h2) = connect_protocol(dest, settings, !upgrading, false).await?;
    ensure!(
        scope_check.is_none_or(|check| check()),
        "Scanner request is outside current target scope"
    );
    let explicit_h2 = request
        .start
        .split_whitespace()
        .last()
        .is_some_and(|v| v.starts_with("HTTP/2"));
    // Cleartext HTTP/2 uses prior knowledge. Conventional HTTP upstreams keep absolute-form HTTP/1.
    if !upgrading
        && (negotiated_h2
            || (!dest.tls && explicit_h2 && settings.upstream.kind != UpstreamKind::Http))
    {
        let (response, body) = crate::http2::open_response(stream, dest, request, settings).await?;
        return Ok((
            IncomingResponse::http2(
                response,
                body,
                request.method() == "HEAD",
                settings.max_message_bytes,
            )?,
            None,
        ));
    }
    let mut outgoing = request.clone_head();
    outgoing.start = format!("{} {} HTTP/1.1", request.method(), request.target());
    if settings.upstream.kind == UpstreamKind::Http && !dest.tls {
        let host = settings
            .dns_overrides
            .get(&dest.host)
            .cloned()
            .unwrap_or_else(|| dest.host.clone());
        let route = Destination {
            host,
            ..dest.clone()
        };
        outgoing.start = format!(
            "{} {}{} HTTP/1.1",
            request.method(),
            route.origin(),
            request.target()
        );
        if !settings.upstream.username.is_empty() {
            let auth = base64::engine::general_purpose::STANDARD.encode(format!(
                "{}:{}",
                settings.upstream.username, settings.upstream.password
            ));
            outgoing.set("Proxy-Authorization", format!("Basic {auth}"));
        }
    }
    stream.write_all(&outgoing.encode()).await?;
    stream.write_all(&request.body).await?;
    stream.flush().await?;
    drop(outgoing);
    let mut reader = BufReader::new(stream);
    for _ in 0..16 {
        let (response, header_len) = read_head(&mut reader, settings.max_message_bytes).await?;
        let status = response.status();
        ensure!(
            (100..=599).contains(&status),
            "Invalid upstream HTTP status"
        );
        let framing = body_framing(&response, true, request.method() == "HEAD")?;
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        if response.status() == 101 {
            ensure!(upgrading, "Unsolicited HTTP upgrade");
            // Keep BufReader: it may already contain the first upgraded bytes.
            return Ok((IncomingResponse::upgrade(response), Some(Box::new(reader))));
        }
        return Ok((
            IncomingResponse::http1(
                response,
                reader,
                framing,
                header_len,
                settings.max_message_bytes,
                !proxy,
            ),
            None,
        ));
    }
    bail!("Too many informational HTTP responses")
}

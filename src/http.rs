//! Bounded HTTP/1 framing. Bytes in bodies never pass through UTF-8 conversion.
use crate::model::Destination;
use anyhow::{Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub start: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl Message {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let split = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| anyhow::anyhow!("Expected CRLF header terminator"))?;
        let text = std::str::from_utf8(&bytes[..split])?;
        let mut lines = text.split("\r\n");
        let start = lines.next().unwrap_or("").to_owned();
        ensure!(!start.is_empty(), "Missing start line");
        let mut headers = Vec::new();
        for line in lines {
            let (k, v) = line
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("Invalid header line"))?;
            ensure!(
                !k.is_empty()
                    && k.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
                "Invalid header name"
            );
            ensure!(!v.contains(['\r', '\n', '\0']), "Invalid header value");
            headers.push((k.into(), v.trim().into()));
        }
        Ok(Self {
            start,
            headers,
            body: bytes[split + 4..].to_vec(),
        })
    }
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
    pub fn remove(&mut self, key: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
    }
    pub fn set(&mut self, key: &str, value: String) {
        self.remove(key);
        self.headers.push((key.into(), value));
    }
    pub fn method(&self) -> &str {
        self.start.split_whitespace().next().unwrap_or("")
    }
    pub fn target(&self) -> &str {
        self.start.split_whitespace().nth(1).unwrap_or("/")
    }
    pub fn status(&self) -> u16 {
        self.start
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!("{}\r\n", self.start).into_bytes();
        for (k, v) in &self.headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
    pub fn decode_content(&mut self, limit: usize) -> Result<()> {
        use std::io::Read;
        let Some(encoding) = self.header("Content-Encoding") else {
            return Ok(());
        };
        let decode = |reader: &mut dyn Read| -> Result<Vec<u8>> {
            let mut out = Vec::new();
            reader.take(limit as u64 + 1).read_to_end(&mut out)?;
            ensure!(
                out.len() <= limit,
                "Decompressed body exceeds message limit"
            );
            Ok(out)
        };
        let body = if encoding.eq_ignore_ascii_case("gzip") {
            decode(&mut flate2::read::MultiGzDecoder::new(self.body.as_slice()))?
        } else if encoding.eq_ignore_ascii_case("deflate") {
            match decode(&mut flate2::read::ZlibDecoder::new(self.body.as_slice())) {
                Ok(body) => body,
                Err(_) => decode(&mut flate2::read::DeflateDecoder::new(self.body.as_slice()))?,
            }
        } else {
            return Ok(());
        };
        self.body = body;
        self.remove("Content-Encoding");
        self.normalize_length();
        Ok(())
    }
    pub fn normalize_length(&mut self) {
        self.remove("Transfer-Encoding");
        self.remove("Trailer");
        let had_length = self.header("Content-Length").is_some();
        self.remove("Content-Length");
        if had_length || !self.body.is_empty() {
            self.set("Content-Length", self.body.len().to_string());
        }
    }
    pub fn destination(
        &self,
        tls: bool,
        fallback: Option<&Destination>,
        transparent: bool,
    ) -> Result<Destination> {
        if self.target().starts_with("http://")
            || self.target().starts_with("https://")
            || self.target().starts_with("ws://")
            || self.target().starts_with("wss://")
        {
            return Destination::from_url(&if self.target().starts_with("ws") {
                self.target().replacen("ws", "http", 1)
            } else {
                self.target().into()
            });
        }
        if let Some(dest) = fallback {
            return Ok(dest.clone());
        }
        ensure!(
            transparent,
            "Origin-form requests require invisible proxy mode"
        );
        let host = self
            .header("Host")
            .ok_or_else(|| anyhow::anyhow!("Missing Host; configure fallback destination"))?;
        Destination::from_url(&format!("{}://{host}", if tls { "https" } else { "http" }))
    }
    pub fn url(&self, dest: &Destination) -> String {
        if self.target().starts_with("http://")
            || self.target().starts_with("https://")
            || self.target().starts_with("ws://")
            || self.target().starts_with("wss://")
        {
            if self.target().starts_with("ws") {
                self.target().replacen("ws", "http", 1)
            } else {
                self.target().into()
            }
        } else {
            format!("{}{}", dest.origin(), self.target())
        }
    }
    pub fn prepare_request(&mut self, dest: &Destination) -> Result<()> {
        let parts: Vec<_> = self.start.split_whitespace().collect();
        ensure!(
            parts.len() == 3 && matches!(parts[2], "HTTP/1.0" | "HTTP/1.1" | "HTTP/2" | "HTTP/2.0"),
            "Use HTTP/1.0, HTTP/1.1 or HTTP/2"
        );
        ensure!(
            parts[0]
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || b == b'-'),
            "Invalid HTTP method"
        );
        ensure!(
            self.header("Transfer-Encoding").is_none(),
            "Editors use decoded bodies; remove Transfer-Encoding and chunk delimiters"
        );
        let method = parts[0].to_string();
        let version = if parts[2].starts_with("HTTP/2") {
            "HTTP/2"
        } else {
            "HTTP/1.1"
        };
        let mut target = parts[1].to_string();
        if target.starts_with("http://")
            || target.starts_with("https://")
            || target.starts_with("ws://")
            || target.starts_with("wss://")
        {
            let u = url::Url::parse(&target)?;
            target = u.path().into();
            if let Some(q) = u.query() {
                target.push('?');
                target.push_str(q);
            }
        }
        self.start = format!("{method} {target} {version}");
        if self.header("Host").is_none() {
            self.set("Host", dest.authority());
        }
        let upgrade = self.header("Upgrade").map(str::to_owned);
        self.remove_hop_headers();
        self.remove("Expect");
        if let Some(upgrade) = upgrade {
            self.set("Upgrade", upgrade);
            self.set("Connection", "Upgrade".into());
        } else {
            self.set("Connection", "close".into());
        }
        self.normalize_length();
        Ok(())
    }
    pub fn remove_hop_headers(&mut self) {
        if let Some(tokens) = self.header("Connection").map(str::to_string) {
            for token in tokens.split(',') {
                self.remove(token.trim());
            }
        }
        for k in [
            "Proxy-Authorization",
            "Proxy-Authenticate",
            "Proxy-Connection",
            "Keep-Alive",
            "Connection",
            "Upgrade",
            "TE",
        ] {
            self.remove(k);
        }
    }
}
async fn line<R: AsyncRead + Unpin>(r: &mut BufReader<R>, budget: usize) -> Result<Vec<u8>> {
    // Byte-wise read avoids consuming a CONNECT tunnel's TLS ClientHello.
    let mut bytes = Vec::new();
    loop {
        let b = r.read_u8().await?;
        bytes.push(b);
        ensure!(bytes.len() <= budget, "HTTP line exceeds limit");
        if bytes.ends_with(b"\r\n") {
            return Ok(bytes);
        }
    }
}
async fn read_head<R: AsyncRead + Unpin>(
    r: &mut BufReader<R>,
    limit: usize,
) -> Result<(Message, usize)> {
    let mut bytes = Vec::new();
    loop {
        let l = line(r, (64 * 1024usize).min(limit).saturating_sub(bytes.len())).await?;
        let done = l == b"\r\n";
        bytes.extend(l);
        if done {
            break;
        }
    }
    let msg = Message::parse(&bytes)?;
    Ok((msg, bytes.len()))
}
pub async fn read_message<R: AsyncRead + Unpin>(
    r: &mut BufReader<R>,
    response: bool,
    head: bool,
    limit: usize,
) -> Result<Message> {
    let (msg, header_len) = read_head(r, limit).await?;
    read_body(r, msg, header_len, response, head, limit).await
}
pub async fn read_request<R: AsyncRead + AsyncWrite + Unpin>(
    r: &mut BufReader<R>,
    limit: usize,
) -> Result<Message> {
    let (msg, header_len) = read_head(r, limit).await?;
    if msg.start == "PRI * HTTP/2.0" && msg.headers.is_empty() {
        return Ok(msg);
    }
    if let Some(expect) = msg.header("Expect") {
        ensure!(
            expect.eq_ignore_ascii_case("100-continue"),
            "Unsupported Expect header"
        );
        r.get_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await?;
    }
    read_body(r, msg, header_len, false, false, limit).await
}
async fn read_body<R: AsyncRead + Unpin>(
    r: &mut BufReader<R>,
    mut msg: Message,
    header_len: usize,
    response: bool,
    head: bool,
    limit: usize,
) -> Result<Message> {
    let lengths: Vec<_> = msg
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .map(|(_, v)| v.parse::<usize>())
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        lengths.windows(2).all(|x| x[0] == x[1]),
        "Conflicting Content-Length"
    );
    let encodings: Vec<_> = msg
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Transfer-Encoding"))
        .map(|(_, v)| v.as_str())
        .collect();
    ensure!(
        encodings.is_empty() || lengths.is_empty(),
        "Ambiguous Transfer-Encoding and Content-Length"
    );
    let no_body = response
        && (head
            || (100..200).contains(&msg.status())
            || msg.status() == 204
            || msg.status() == 304)
        || (!response && msg.method() == "CONNECT");
    if no_body {
        return Ok(msg);
    }
    let remaining = limit.saturating_sub(header_len);
    if !encodings.is_empty() {
        ensure!(
            encodings.len() == 1 && encodings[0].eq_ignore_ascii_case("chunked"),
            "Unsupported transfer encoding"
        );
        let mut overhead = 0usize;
        loop {
            let l = line(r, 8192).await?;
            overhead += l.len();
            ensure!(overhead <= limit, "Chunk metadata exceeds limit");
            let text = std::str::from_utf8(&l)?.trim();
            let size = usize::from_str_radix(text.split(';').next().unwrap_or(""), 16)?;
            ensure!(
                size <= remaining.saturating_sub(msg.body.len()),
                "HTTP body exceeds limit"
            );
            if size == 0 {
                loop {
                    let trailer = line(r, 8192).await?;
                    overhead += trailer.len();
                    ensure!(overhead <= limit, "Trailers exceed limit");
                    if trailer == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            let start = msg.body.len();
            msg.body.resize(start + size, 0);
            r.read_exact(&mut msg.body[start..]).await?;
            let mut crlf = [0; 2];
            r.read_exact(&mut crlf).await?;
            ensure!(&crlf == b"\r\n", "Invalid chunk terminator");
        }
        msg.normalize_length();
    } else if let Some(size) = lengths.first().copied() {
        ensure!(size <= remaining, "HTTP body exceeds limit");
        msg.body.resize(size, 0);
        r.read_exact(&mut msg.body).await?;
    } else if response {
        r.take((remaining as u64) + 1)
            .read_to_end(&mut msg.body)
            .await?;
        ensure!(msg.body.len() <= remaining, "HTTP body exceeds limit");
    }
    if !response
        && !matches!(
            msg.start.split_whitespace().last(),
            Some("HTTP/1.0" | "HTTP/1.1")
        )
    {
        bail!("Invalid HTTP version");
    }
    Ok(msg)
}
/// Editors accept LF; normalize only the header section, preserving body bytes.
pub fn from_editor(text: &str) -> Result<Message> {
    if text.contains("\r\n\r\n") {
        return Message::parse(text.as_bytes());
    }
    let (headers, body) = text
        .split_once("\n\n")
        .ok_or_else(|| anyhow::anyhow!("Add a blank line after the headers"))?;
    let mut bytes = headers
        .replace("\r\n", "\n")
        .replace('\n', "\r\n")
        .into_bytes();
    bytes.extend_from_slice(b"\r\n\r\n");
    bytes.extend_from_slice(body.as_bytes());
    Message::parse(&bytes)
}

/// True when bytes display faithfully as editable text.
pub fn is_display_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars()
            .all(|c| !c.is_control() || matches!(c, '\r' | '\n' | '\t'))
    })
}

/// Lowercase hex in rows of 24 bytes, as used by the message editors.
pub fn hex_dump(bytes: &[u8]) -> String {
    bytes
        .chunks(24)
        .map(|row| {
            row.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse editor hex, ignoring whitespace.
pub fn parse_hex(text: &str) -> Result<Vec<u8>> {
    let s: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    ensure!(
        s.len().is_multiple_of(2) && s.is_ascii(),
        "Hex needs complete byte pairs"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}

/// Editor representation of message bytes: text when faithful, else hex.
pub fn editor_text(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(text) if is_display_text(bytes) => (text.into(), false),
        _ => (hex_dump(bytes), true),
    }
}

/// Parse an editor buffer (text or hex) into a message.
pub fn from_editor_buffer(text: &str, is_hex: bool) -> Result<Message> {
    if is_hex {
        Message::parse(&parse_hex(text)?)
    } else {
        from_editor(text)
    }
}

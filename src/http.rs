//! Bounded HTTP/1 framing. Bytes in bodies never pass through UTF-8 conversion.
use crate::model::Destination;
use anyhow::{Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

mod body;
pub(crate) use body::Http1Body;

#[derive(Debug)]
struct DecodedBodyLimit;

impl std::fmt::Display for DecodedBodyLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Decompressed body exceeds message limit")
    }
}

impl std::error::Error for DecodedBodyLimit {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub start: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl Message {
    /// Copy metadata for framing without duplicating a potentially large body.
    pub(crate) fn clone_head(&self) -> Self {
        Self {
            start: self.start.clone(),
            headers: self.headers.clone(),
            body: Vec::new(),
        }
    }

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
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(self.start.as_bytes());
        out.extend_from_slice(b"\r\n");
        for (k, v) in &self.headers {
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
    pub(crate) fn encoded_len(&self) -> usize {
        self.start.len()
            + 4
            + self.body.len()
            + self
                .headers
                .iter()
                .map(|(k, v)| k.len() + v.len() + 4)
                .sum::<usize>()
    }
    pub fn decode_content(&mut self, limit: usize) -> Result<()> {
        if let Some(body) = self.decoded_body(limit)? {
            self.body = body;
            self.remove("Content-Encoding");
            self.normalize_length();
        }
        Ok(())
    }

    fn decoded_body(&self, limit: usize) -> Result<Option<Vec<u8>>> {
        use std::io::Read;
        let Some(encoding) = self.header("Content-Encoding") else {
            return Ok(None);
        };
        let decode = |reader: &mut dyn Read| -> Result<Vec<u8>> {
            let mut out = Vec::new();
            reader.take(limit as u64 + 1).read_to_end(&mut out)?;
            ensure!(out.len() <= limit, DecodedBodyLimit);
            Ok(out)
        };
        let body = if encoding.eq_ignore_ascii_case("gzip") {
            decode(&mut flate2::read::MultiGzDecoder::new(self.body.as_slice()))?
        } else if encoding.eq_ignore_ascii_case("deflate") {
            match decode(&mut flate2::read::ZlibDecoder::new(self.body.as_slice())) {
                Ok(body) => body,
                Err(error) if error.is::<DecodedBodyLimit>() => return Err(error),
                Err(_) => decode(&mut flate2::read::DeflateDecoder::new(self.body.as_slice()))?,
            }
        } else {
            return Ok(None);
        };
        Ok(Some(body))
    }

    pub(crate) fn decode_for_proxy(&mut self, limit: usize) -> Result<bool> {
        let decoded = match self.decoded_body(limit) {
            Err(error) if error.is::<DecodedBodyLimit>() => return Ok(false),
            result => result?,
        };
        let len = decoded.as_ref().unwrap_or(&self.body).len();
        if len > 0 {
            let mut head = self.clone_head();
            if decoded.is_some() {
                head.remove("Content-Encoding");
            }
            head.remove_hop_headers();
            head.set("Connection", "close".into());
            head.normalize_body_length(len);
            if len > limit.saturating_sub(head.encoded_len()) {
                return Ok(false);
            }
        }
        if let Some(body) = decoded {
            self.body = body;
            self.remove("Content-Encoding");
            self.normalize_length();
        }
        Ok(true)
    }
    pub fn normalize_length(&mut self) {
        self.normalize_body_length(self.body.len());
    }
    pub(crate) fn normalize_body_length(&mut self, len: usize) {
        self.remove("Transfer-Encoding");
        self.remove("Trailer");
        let had_length = self.header("Content-Length").is_some();
        self.remove("Content-Length");
        if had_length || len > 0 {
            self.set("Content-Length", len.to_string());
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
pub(crate) async fn read_head<R: AsyncRead + Unpin>(
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
pub(crate) fn content_length(msg: &Message) -> Result<Option<u64>> {
    let mut length = None;
    for (_, value) in msg
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
    {
        ensure!(
            !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
            "Invalid Content-Length"
        );
        let value = value.parse::<u64>()?;
        ensure!(
            length.is_none_or(|n| n == value),
            "Conflicting Content-Length"
        );
        length = Some(value);
    }
    Ok(length)
}

pub(crate) fn response_has_body(msg: &Message, head: bool) -> bool {
    !head && !(100..200).contains(&msg.status()) && !matches!(msg.status(), 204 | 304)
}

#[derive(Clone, Copy)]
pub(crate) enum BodyFraming {
    Empty,
    Fixed(u64),
    Chunked,
    Close,
}

pub(crate) fn body_framing(msg: &Message, response: bool, head: bool) -> Result<BodyFraming> {
    let length = content_length(msg)?;
    let encodings: Vec<_> = msg
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Transfer-Encoding"))
        .map(|(_, v)| v.as_str())
        .collect();
    ensure!(
        encodings.is_empty() || length.is_none(),
        "Ambiguous Transfer-Encoding and Content-Length"
    );
    let no_body =
        response && !response_has_body(msg, head) || (!response && msg.method() == "CONNECT");
    if no_body {
        return Ok(BodyFraming::Empty);
    }
    if !encodings.is_empty() {
        ensure!(
            encodings.len() == 1 && encodings[0].eq_ignore_ascii_case("chunked"),
            "Unsupported transfer encoding"
        );
        Ok(BodyFraming::Chunked)
    } else if let Some(size) = length {
        Ok(BodyFraming::Fixed(size))
    } else if response {
        Ok(BodyFraming::Close)
    } else {
        Ok(BodyFraming::Empty)
    }
}

fn chunk_size(line: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(line)?.trim();
    let size = text.split(';').next().unwrap_or("");
    ensure!(
        !size.is_empty() && size.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid chunk size"
    );
    Ok(u64::from_str_radix(size, 16)?)
}

async fn read_body<R: AsyncRead + Unpin>(
    r: &mut BufReader<R>,
    mut msg: Message,
    header_len: usize,
    response: bool,
    head: bool,
    limit: usize,
) -> Result<Message> {
    let framing = body_framing(&msg, response, head)?;
    if (response && !response_has_body(&msg, head)) || (!response && msg.method() == "CONNECT") {
        return Ok(msg);
    }
    let remaining = limit.saturating_sub(header_len);
    if let BodyFraming::Fixed(size) = framing {
        ensure!(size <= remaining as u64, "HTTP body exceeds limit");
        msg.body.resize(size as usize, 0);
        r.read_exact(&mut msg.body).await?;
    } else {
        let mut body = Http1Body::new(framing, limit, true);
        while let Some(chunk) = body
            .next(r, (remaining - msg.body.len()).saturating_add(1))
            .await?
        {
            ensure!(
                chunk.len() <= remaining - msg.body.len(),
                "HTTP body exceeds limit"
            );
            msg.body.extend_from_slice(&chunk);
        }
        if matches!(framing, BodyFraming::Chunked) {
            msg.normalize_length();
        }
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

#[cfg(test)]
mod encoding_tests {
    use super::*;

    #[test]
    fn encoded_length_and_bytes_preserve_duplicate_headers_and_binary_bodies() {
        let head = "HTTP/1.1 200 OK\r\nX-Test: café\r\nX-Test: second\r\n\r\n";
        for body in [vec![], vec![0, 255, 13, 10], vec![42; 1024 * 1024]] {
            let mut bytes = head.as_bytes().to_vec();
            bytes.extend_from_slice(&body);
            let message = Message::parse(&bytes).unwrap();
            assert_eq!(message.encoded_len(), bytes.len());
            assert_eq!(message.encode(), bytes);
        }
        let message = Message::parse(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(message.encoded_len(), message.encode().len());
    }
}

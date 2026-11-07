use crate::{
    http::{BodyFraming, Http1Body, Message, content_length, response_has_body},
    http2::IncomingBody,
    model::{Settings, StreamReason},
};
use anyhow::{Result, ensure};
use bytes::Bytes;
use http::HeaderMap;
use tokio::io::BufReader;

enum Source {
    Http1(Http1Body, BufReader<super::Stream>),
    Http2(IncomingBody),
}

impl Source {
    async fn next(&mut self, max_read: usize) -> Result<Option<Bytes>> {
        match self {
            Self::Http1(body, reader) => body.next(reader, max_read).await,
            Self::Http2(body) => body.next().await,
        }
    }

    fn release(&mut self, bytes: usize) -> Result<()> {
        if let Self::Http2(body) = self {
            body.recv.flow_control().release_capacity(bytes)?;
        }
        Ok(())
    }

    async fn trailers(&mut self) -> Result<HeaderMap> {
        Ok(match self {
            Self::Http1(body, _) => body.take_trailers(),
            Self::Http2(body) => body.recv.trailers().await?.unwrap_or_default(),
        })
    }
}

pub(crate) struct IncomingResponse {
    head: Message,
    source: Option<Source>,
    budget: usize,
    declared: Option<u64>,
    has_body: bool,
    chunked: bool,
}

impl IncomingResponse {
    pub fn upgrade(head: Message) -> Self {
        Self {
            head,
            source: None,
            budget: 0,
            declared: None,
            has_body: false,
            chunked: false,
        }
    }

    pub fn http1(
        head: Message,
        reader: BufReader<super::Stream>,
        framing: BodyFraming,
        head_len: usize,
        limit: usize,
        strict: bool,
    ) -> Self {
        Self {
            head,
            source: Some(Source::Http1(
                Http1Body::new(framing, limit, strict),
                reader,
            )),
            budget: limit - head_len,
            declared: if let BodyFraming::Fixed(n) = framing {
                Some(n)
            } else {
                None
            },
            has_body: !matches!(framing, BodyFraming::Empty),
            chunked: matches!(framing, BodyFraming::Chunked),
        }
    }

    pub fn http2(
        head: Message,
        source: IncomingBody,
        head_request: bool,
        limit: usize,
    ) -> Result<Self> {
        let head_len = head.encoded_len();
        ensure!(head_len <= limit, "HTTP/2 headers exceed message limit");
        let has_body = response_has_body(&head, head_request);
        Ok(Self {
            declared: if has_body {
                content_length(&head)?
            } else {
                None
            },
            head,
            source: Some(Source::Http2(source)),
            budget: limit - head_len,
            has_body,
            chunked: false,
        })
    }

    pub async fn capture(
        mut self,
        settings: &Settings,
        proxy_url: Option<&str>,
    ) -> Result<(Message, Option<LiveBody>)> {
        let limit_error = if matches!(&self.source, Some(Source::Http2(_))) {
            "HTTP/2 body exceeds message limit"
        } else {
            "HTTP body exceeds limit"
        };
        if self.declared.is_some_and(|n| n > self.budget as u64) {
            ensure!(proxy_url.is_some(), "{limit_error}");
            return Ok(self.live(StreamReason::CaptureLimit, None, HeaderMap::new()));
        }
        if let Some(url) = proxy_url
            && self.has_body
            && self.declared != Some(0)
            && (self.head.header("Content-Type").is_some_and(streaming_mime)
                || settings
                    .streaming_url_patterns
                    .iter()
                    .any(|p| regex::Regex::new(p).is_ok_and(|r| r.is_match(url))))
        {
            return Ok(self.live(StreamReason::Policy, None, HeaderMap::new()));
        }

        let mut trailers = HeaderMap::new();
        if let Some(source) = &mut self.source {
            let max_read = if proxy_url.is_some() {
                usize::MAX
            } else {
                self.budget.saturating_add(1)
            };
            while let Some(chunk) = source
                .next(max_read.saturating_sub(self.head.body.len()).max(1))
                .await?
            {
                if chunk.len() > self.budget.saturating_sub(self.head.body.len()) {
                    ensure!(proxy_url.is_some(), "{limit_error}");
                    return Ok(self.live(
                        StreamReason::CaptureLimit,
                        Some(chunk),
                        HeaderMap::new(),
                    ));
                }
                self.head.body.extend_from_slice(&chunk);
                source.release(chunk.len())?;
            }
            trailers = source.trailers().await?;
            if let Source::Http2(body) = source {
                if proxy_url.is_none() {
                    let size: usize = trailers
                        .iter()
                        .map(|(k, v)| k.as_str().len() + v.len() + 4)
                        .sum();
                    ensure!(
                        size <= self.budget.saturating_sub(self.head.body.len()),
                        "HTTP/2 trailers exceed message limit"
                    );
                }
                body.finish_upload().await?;
            }
        }
        self.source = None;
        if self.has_body {
            if proxy_url.is_some() {
                if !self.head.decode_for_proxy(settings.max_message_bytes)? {
                    return Ok(self.live(StreamReason::CaptureLimit, None, trailers));
                }
            } else {
                self.head.decode_content(settings.max_message_bytes)?;
            }
        }
        if self.chunked {
            self.head.normalize_length();
        }
        Ok((self.head, None))
    }

    fn live(
        mut self,
        reason: StreamReason,
        pending: Option<Bytes>,
        trailers: HeaderMap,
    ) -> (Message, Option<LiveBody>) {
        let prefix = std::mem::take(&mut self.head.body);
        let connection_fields: Vec<_> = self
            .head
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("Connection"))
            .flat_map(|(_, value)| {
                value
                    .split(',')
                    .map(|token| token.trim().to_ascii_lowercase())
            })
            .collect();
        self.head.remove_hop_headers();
        for field in &connection_fields {
            self.head.remove(field);
        }
        self.head.remove("Transfer-Encoding");
        self.head.remove("Trailer");
        self.head.remove("Content-Length");
        if let Some(len) = self.declared {
            self.head.set("Content-Length", len.to_string());
        }
        (
            self.head,
            Some(LiveBody {
                reason,
                declared: self.declared,
                prefix,
                pending,
                source: self.source,
                trailers,
                connection_fields,
            }),
        )
    }
}

fn streaming_mime(value: &str) -> bool {
    let mime = value.split(';').next().unwrap_or("").trim();
    mime.eq_ignore_ascii_case("text/event-stream")
        || mime.eq_ignore_ascii_case("application/octet-stream")
}

pub(crate) struct LiveBody {
    pub reason: StreamReason,
    pub declared: Option<u64>,
    pub prefix: Vec<u8>,
    pending: Option<Bytes>,
    source: Option<Source>,
    trailers: HeaderMap,
    connection_fields: Vec<String>,
}

impl LiveBody {
    pub async fn next(&mut self) -> Result<Option<Bytes>> {
        if let Some(pending) = self.pending.take() {
            return Ok(Some(pending));
        }
        match &mut self.source {
            Some(source) => source.next(usize::MAX).await,
            None => Ok(None),
        }
    }

    pub fn release(&mut self, bytes: usize) -> Result<()> {
        match &mut self.source {
            Some(source) => source.release(bytes),
            None => Ok(()),
        }
    }

    pub async fn trailers(&mut self) -> Result<HeaderMap> {
        let trailers = match &mut self.source {
            Some(source) => source.trailers().await?,
            None => std::mem::take(&mut self.trailers),
        };
        let mut end_to_end = HeaderMap::new();
        for (name, value) in &trailers {
            let field = name;
            let name = name.as_str();
            if !self.connection_fields.iter().any(|token| token == name)
                && !matches!(
                    name,
                    "connection"
                        | "content-length"
                        | "transfer-encoding"
                        | "trailer"
                        | "te"
                        | "upgrade"
                        | "keep-alive"
                        | "proxy-connection"
                        | "host"
                        | "content-encoding"
                        | "content-type"
                        | "content-range"
                        | "content-disposition"
                        | "cache-control"
                        | "location"
                        | "vary"
                        | "expires"
                        | "date"
                        | "retry-after"
                        | "set-cookie"
                        | "cookie"
                        | "authorization"
                        | "proxy-authorization"
                        | "www-authenticate"
                        | "proxy-authenticate"
                )
            {
                end_to_end.append(field, value.clone());
            }
        }
        Ok(end_to_end)
    }
}

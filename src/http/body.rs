use super::{BodyFraming, chunk_size, line};
use anyhow::{Result, ensure};
use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

pub(crate) struct Http1Body {
    framing: BodyFraming,
    chunk_remaining: u64,
    chunk_started: bool,
    metadata: usize,
    limit: usize,
    strict: bool,
    trailers: HeaderMap,
}

impl Http1Body {
    pub fn new(framing: BodyFraming, limit: usize, strict: bool) -> Self {
        Self {
            framing,
            chunk_remaining: 0,
            chunk_started: false,
            metadata: 0,
            limit,
            strict,
            trailers: HeaderMap::new(),
        }
    }

    pub fn take_trailers(&mut self) -> HeaderMap {
        std::mem::take(&mut self.trailers)
    }

    pub async fn next<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut BufReader<R>,
        max_read: usize,
    ) -> Result<Option<Bytes>> {
        let remaining = match self.framing {
            BodyFraming::Empty | BodyFraming::Fixed(0) => return Ok(None),
            BodyFraming::Fixed(remaining) => remaining,
            BodyFraming::Close => u64::MAX,
            BodyFraming::Chunked => {
                if self.chunk_remaining == 0 {
                    if self.chunk_started {
                        let mut crlf = [0; 2];
                        reader.read_exact(&mut crlf).await?;
                        ensure!(&crlf == b"\r\n", "Invalid chunk terminator");
                    }
                    let l = line(reader, 8192).await?;
                    if self.strict {
                        self.metadata += l.len();
                        ensure!(self.metadata <= self.limit, "Chunk metadata exceeds limit");
                    }
                    self.chunk_remaining = chunk_size(&l)?;
                    if self.chunk_remaining == 0 {
                        self.read_trailers(reader).await?;
                        self.framing = BodyFraming::Empty;
                        return Ok(None);
                    }
                    if self.strict && max_read != usize::MAX {
                        ensure!(
                            self.chunk_remaining < max_read as u64,
                            "HTTP body exceeds limit"
                        );
                    }
                    self.chunk_started = true;
                }
                self.chunk_remaining
            }
        };
        let size = remaining.min(16 * 1024).min(max_read as u64) as usize;
        let mut data = BytesMut::with_capacity(size);
        let n = reader.take(size as u64).read_buf(&mut data).await?;
        if n == 0 {
            ensure!(
                matches!(self.framing, BodyFraming::Close),
                "Incomplete HTTP body"
            );
            return Ok(None);
        }
        match &mut self.framing {
            BodyFraming::Fixed(remaining) => *remaining -= n as u64,
            BodyFraming::Chunked => self.chunk_remaining -= n as u64,
            _ => {}
        }
        Ok(Some(data.freeze()))
    }

    async fn read_trailers<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut BufReader<R>,
    ) -> Result<()> {
        let limit = if self.strict {
            self.limit
        } else {
            self.limit.min(64 * 1024)
        };
        loop {
            let l = line(reader, 8192).await?;
            self.metadata += l.len();
            ensure!(self.metadata <= limit, "Trailers exceed limit");
            if l == b"\r\n" {
                return Ok(());
            }
            // Buffered messages historically discard trailers.
            if !self.strict {
                let text = std::str::from_utf8(&l[..l.len() - 2])?;
                let (name, value) = text
                    .split_once(':')
                    .ok_or_else(|| anyhow::anyhow!("Invalid HTTP trailer"))?;
                self.trailers.append(
                    HeaderName::from_bytes(name.as_bytes())?,
                    HeaderValue::from_str(value.trim())?,
                );
            }
        }
    }
}

use super::Engine;
use crate::{
    http::Message,
    model::Exchange,
    transport::{LiveBody, Stream},
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http::HeaderMap;
use std::{
    future::{Future, poll_fn},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, time::timeout};

impl Engine {
    pub(super) async fn relay_response(
        &self,
        flow: Exchange,
        body: LiveBody,
        mut client: Downstream<'_>,
        retain_history: bool,
    ) -> Result<()> {
        let mut history = StreamHistory::new(self, retain_history.then_some(flow.id));
        let head = Message::parse(&flow.response);
        // History already owns its record. Long-lived streams need only the ID
        // and response headers, not another copy of the originating request.
        drop(flow);
        let (deadline, idle) = {
            let settings = self.settings();
            (
                Duration::from_secs(settings.timeout_secs),
                Duration::from_secs(settings.stream_idle_timeout_secs),
            )
        };
        let result = async {
            let writer = client.open(head?, body.declared, deadline).await?;
            relay(body, writer, idle, deadline, &mut history.bytes).await
        }
        .await;
        history.finish(&result);
        result
    }
}

pub(super) enum Downstream<'a> {
    Http1 { stream: Stream, http10: bool },
    Http2(&'a mut h2::server::SendResponse<Bytes>),
}

impl Downstream<'_> {
    async fn open(
        &mut self,
        mut head: Message,
        declared: Option<u64>,
        deadline: Duration,
    ) -> Result<Writer<'_>> {
        match self {
            Self::Http1 { stream, http10 } => {
                let version = if *http10 { "HTTP/1.0" } else { "HTTP/1.1" };
                let status = http::StatusCode::from_u16(head.status())?;
                let reason = head
                    .start
                    .splitn(3, ' ')
                    .nth(2)
                    .or_else(|| status.canonical_reason())
                    .unwrap_or("");
                head.start = format!("{version} {} {reason}", status.as_u16());
                head.set("Connection", "close".into());
                let chunked = declared.is_none() && !*http10;
                if chunked {
                    head.set("Transfer-Encoding", "chunked".into());
                }
                write_http1(stream, &head.encode(), deadline).await?;
                timeout(deadline, stream.flush())
                    .await
                    .context("Client write timed out")??;
                Ok(Writer::Http1 { stream, chunked })
            }
            Self::Http2(respond) => {
                let head = crate::http2::response_head(&head)?;
                Ok(Writer::Http2(respond.send_response(head, false)?))
            }
        }
    }
}

async fn relay(
    mut body: LiveBody,
    mut writer: Writer<'_>,
    idle: Duration,
    deadline: Duration,
    bytes: &mut u64,
) -> Result<()> {
    let prefix = Bytes::from(std::mem::take(&mut body.prefix));
    for offset in (0..prefix.len()).step_by(16 * 1024) {
        let end = (offset + 16 * 1024).min(prefix.len());
        writer
            .write(prefix.slice(offset..end), deadline, bytes)
            .await?;
    }
    drop(prefix);
    while let Some(chunk) = writer.upstream(idle, body.next()).await? {
        let len = chunk.len();
        if len == 0 {
            continue;
        }
        ensure!(
            body.declared
                .is_none_or(|n| len as u64 <= n.saturating_sub(*bytes)),
            "Upstream body exceeds Content-Length"
        );
        writer.write(chunk, deadline, bytes).await?;
        body.release(len)?;
    }
    ensure!(
        body.declared.is_none_or(|n| n == *bytes),
        "Incomplete HTTP body"
    );
    let trailers = writer.upstream(idle, body.trailers()).await?;
    writer.finish(trailers, deadline).await
}

enum Writer<'a> {
    Http1 {
        stream: &'a mut Stream,
        chunked: bool,
    },
    Http2(h2::SendStream<Bytes>),
}

impl Writer<'_> {
    async fn upstream<T>(
        &mut self,
        idle: Duration,
        read: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let read = async {
            if idle.is_zero() {
                read.await
            } else {
                timeout(idle, read)
                    .await
                    .context("Upstream streaming response idle timeout")?
            }
        };
        match self {
            Self::Http1 { .. } => read.await,
            Self::Http2(stream) => tokio::select! {
                result = read => result,
                reason = poll_fn(|cx| stream.poll_reset(cx)) => anyhow::bail!("Client reset HTTP/2 stream: {}", reason?),
            },
        }
    }

    async fn write(&mut self, data: Bytes, deadline: Duration, count: &mut u64) -> Result<()> {
        match self {
            Self::Http1 { stream, chunked } => {
                if *chunked {
                    write_http1(stream, format!("{:x}\r\n", data.len()).as_bytes(), deadline)
                        .await?;
                }
                let mut pending = data.as_ref();
                while !pending.is_empty() {
                    let n = timeout(deadline, stream.write(pending))
                        .await
                        .context("Client write timed out")??;
                    ensure!(n > 0, "Client closed before body was sent");
                    *count += n as u64;
                    pending = &pending[n..];
                }
                if *chunked {
                    write_http1(stream, b"\r\n", deadline).await?;
                }
                timeout(deadline, stream.flush())
                    .await
                    .context("Client write timed out")??;
            }
            Self::Http2(stream) => {
                let mut offset = 0;
                while offset < data.len() {
                    let n = timeout(
                        deadline,
                        crate::http2::send_capacity(stream, data.len() - offset),
                    )
                    .await
                    .context("Client write timed out")??;
                    stream.send_data(data.slice(offset..offset + n), false)?;
                    offset += n;
                    *count += n as u64;
                }
            }
        }
        Ok(())
    }

    async fn finish(&mut self, trailers: HeaderMap, deadline: Duration) -> Result<()> {
        match self {
            Self::Http1 { stream, chunked } => {
                if *chunked {
                    let mut tail = b"0\r\n".to_vec();
                    for (name, value) in &trailers {
                        tail.extend_from_slice(name.as_str().as_bytes());
                        tail.extend_from_slice(b": ");
                        tail.extend_from_slice(value.as_bytes());
                        tail.extend_from_slice(b"\r\n");
                    }
                    tail.extend_from_slice(b"\r\n");
                    write_http1(stream, &tail, deadline).await?;
                }
                timeout(deadline, stream.shutdown())
                    .await
                    .context("Client write timed out")??;
            }
            Self::Http2(stream) if trailers.is_empty() => stream.send_data(Bytes::new(), true)?,
            Self::Http2(stream) => stream.send_trailers(trailers)?,
        }
        Ok(())
    }
}

async fn write_http1(stream: &mut Stream, data: &[u8], deadline: Duration) -> Result<()> {
    timeout(deadline, stream.write_all(data))
        .await
        .context("Client write timed out")??;
    Ok(())
}

struct StreamHistory<'a> {
    engine: &'a Engine,
    id: Option<u64>,
    started: Instant,
    bytes: u64,
    finished: bool,
}

impl<'a> StreamHistory<'a> {
    fn new(engine: &'a Engine, id: Option<u64>) -> Self {
        Self {
            engine,
            id,
            started: Instant::now(),
            bytes: 0,
            finished: false,
        }
    }

    fn finish(&mut self, result: &Result<()>) {
        self.finished = true;
        self.record(result.as_ref().err().map(crate::error::friendly));
    }

    fn record(&self, error: Option<String>) {
        let Some(id) = self.id else { return };
        let result = (|| -> Result<()> {
            let mut project = self.engine.project.lock().unwrap();
            if let Some(mut flow) = project.get(id)?
                && let Some(stream) = &mut flow.streamed_response
                && stream.body_bytes.is_none()
            {
                stream.body_bytes = Some(self.bytes);
                flow.duration_ms += self.started.elapsed().as_millis() as u64;
                flow.error = error;
                project.insert(flow)?;
                self.engine.activity.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.engine
                .log_error(format!("Could not finalize streaming response: {error:#}"));
        }
    }
}

impl Drop for StreamHistory<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.record(Some("Streaming response cancelled".into()));
        }
    }
}

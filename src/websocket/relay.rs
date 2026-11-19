use super::*;
use fastwebsockets::{Frame, OpCode, Role, WebSocketWrite, after_handshake_split};
use std::{
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, ReadBuf, ReadHalf, WriteHalf},
    sync::{Semaphore, mpsc},
};

type Writer = Arc<tokio::sync::Mutex<WebSocketWrite<WriteHalf<Stream>>>>;

/// Validate role-dependent masking before the codec consumes its input. The
/// codec handles frame parsing but does not reject incorrect mask directions.
struct CheckedRead<R> {
    inner: R,
    masked: bool,
    header: [u8; 14],
    used: usize,
    needed: usize,
    remaining: u64,
}
impl<R> CheckedRead<R> {
    fn new(inner: R, masked: bool) -> Self {
        Self {
            inner,
            masked,
            header: [0; 14],
            used: 0,
            needed: 2,
            remaining: 0,
        }
    }
    fn inspect(&mut self, mut bytes: &[u8]) -> std::io::Result<()> {
        while !bytes.is_empty() {
            if self.remaining > 0 {
                let n = bytes.len().min(self.remaining as usize);
                self.remaining -= n as u64;
                bytes = &bytes[n..];
                continue;
            }
            let n = bytes.len().min(self.needed - self.used);
            self.header[self.used..self.used + n].copy_from_slice(&bytes[..n]);
            self.used += n;
            bytes = &bytes[n..];
            if self.used < self.needed {
                continue;
            }
            let code = self.header[1] & 127;
            if self.needed == 2 {
                if (self.header[1] & 128 != 0) != self.masked {
                    return Err(std::io::Error::other(
                        "Incorrect WebSocket masking direction",
                    ));
                }
                self.needed += match code {
                    126 => 2,
                    127 => 8,
                    _ => 0,
                } + if self.masked { 4 } else { 0 };
                if self.used < self.needed {
                    continue;
                }
            }
            let length = match code {
                126 => u16::from_be_bytes(self.header[2..4].try_into().unwrap()) as u64,
                127 => u64::from_be_bytes(self.header[2..10].try_into().unwrap()),
                n => n as u64,
            };
            if length >> 63 != 0
                || (code == 126 && length < 126)
                || (code == 127 && length < 65536)
                || (self.header[0] & 8 != 0 && length > 125)
            {
                return Err(std::io::Error::other("Invalid WebSocket payload length"));
            }
            self.remaining = length;
            self.used = 0;
            self.needed = 2;
        }
        Ok(())
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for CheckedRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let start = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(self.inspect(&buf.filled()[start..])),
            result => result,
        }
    }
}

struct Packet {
    sequence: u64,
    kind: Kind,
    payload: Arc<[u8]>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

struct SessionGuard<'a> {
    engine: &'a Engine,
    id: u64,
}
impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        let hub = &self.engine.websockets;
        hub.active.lock().unwrap().remove(&self.id);
        hub.received
            .lock()
            .unwrap()
            .retain(|(id, _), _| *id != self.id);
        hub.batches
            .lock()
            .unwrap()
            .retain(|(id, _), _| *id != self.id);
        let mut queue = hub.pending.lock().unwrap();
        queue.retain(|_, p| p.item.session_id != self.id);
        drop(queue);
        let mut project = self.engine.project.lock().unwrap();
        if let Some(mut session) = project.ws_session(self.id) {
            if session.state == SessionState::Open {
                session.state = SessionState::Interrupted;
                session.closed_ms = Some(now());
                session.error = Some("WebSocket connection interrupted".into());
                if let Err(e) = project.put_ws_session(session) {
                    self.engine.log_error(e.to_string());
                }
            }
            for summary in project.ws_summaries(self.id) {
                if summary.disposition == Disposition::Pending
                    && let Ok(Some(mut message)) = project.ws_message(self.id, summary.sequence)
                {
                    message.summary.disposition = Disposition::Interrupted;
                    message.error = Some("Session ended before the message was forwarded".into());
                    if let Err(e) = project.put_ws_message(message) {
                        self.engine.log_error(e.to_string());
                    }
                }
            }
        }
        hub.activity.fetch_add(1, Ordering::SeqCst);
    }
}

fn opcode(kind: Kind) -> OpCode {
    match kind {
        Kind::Text => OpCode::Text,
        Kind::Binary => OpCode::Binary,
        Kind::Ping => OpCode::Ping,
        Kind::Pong => OpCode::Pong,
        Kind::Close => OpCode::Close,
    }
}

async fn write(writer: &Writer, kind: Kind, payload: &[u8], timeout: Duration) -> Result<()> {
    tokio::time::timeout(timeout, async {
        let mut writer = writer.lock().await;
        writer
            .write_frame(Frame::new(true, opcode(kind), None, payload.into()))
            .await?;
        writer.flush().await
    })
    .await
    .context("WebSocket write timed out")??;
    Ok(())
}

fn capture(
    engine: &Engine,
    id: u64,
    sequence: u64,
    direction: Direction,
    kind: Kind,
    payload: &[u8],
) -> Result<()> {
    let preview = if kind == Kind::Binary {
        payload
            .iter()
            .take(80)
            .map(|b| format!("{b:02x} "))
            .collect()
    } else {
        String::from_utf8_lossy(&payload[..payload.len().min(512)])
            .chars()
            .take(160)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    };
    let message = CapturedMessage {
        summary: MessageSummary {
            session_id: id,
            sequence,
            direction,
            timestamp_ms: now(),
            kind,
            length: payload.len(),
            disposition: Disposition::Pending,
            preview,
        },
        original: payload.to_vec(),
        forwarded: None,
        error: None,
    };
    let mut project = engine.project.lock().unwrap();
    project.put_ws_message(message)?;
    let mut session = project.ws_session(id).context("Session missing")?;
    session.message_count += 1;
    if kind == Kind::Close && payload.len() >= 2 {
        session.close_code = Some(u16::from_be_bytes([payload[0], payload[1]]));
        session.close_reason = String::from_utf8_lossy(&payload[2..]).into_owned();
    }
    project.put_ws_session(session)?;
    engine.websockets.activity.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

fn finish(
    engine: &Engine,
    history_id: Option<u64>,
    sequence: u64,
    forwarded: Option<&[u8]>,
    error: Option<String>,
) -> Result<()> {
    let Some(id) = history_id else { return Ok(()) };
    let mut project = engine.project.lock().unwrap();
    let mut message = project
        .ws_message(id, sequence)?
        .context("WebSocket message missing")?;
    message.summary.disposition = if error.is_some() {
        Disposition::Failed
    } else if let Some(sent) = forwarded {
        if sent == message.original {
            Disposition::Forwarded
        } else {
            Disposition::Modified
        }
    } else {
        Disposition::Dropped
    };
    message.forwarded = forwarded
        .filter(|sent| *sent != message.original)
        .map(<[u8]>::to_vec);
    message.error = error;
    project.put_ws_message(message)?;
    engine.websockets.activity.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn receive(
    engine: &Engine,
    id: u64,
    direction: Direction,
    read: ReadHalf<Stream>,
    write_to_peer: Writer,
    sequence: &AtomicU64,
    tx: mpsc::Sender<Packet>,
    budget: Arc<Semaphore>,
    closing: watch::Sender<bool>,
    limit: usize,
    timeout: Duration,
    retain_history: bool,
) -> Result<()> {
    let history_id = retain_history.then_some(id);
    // The dummy write side is unused: automatic control replies are disabled.
    let (mut reader, _) = after_handshake_split(
        CheckedRead::new(read, direction == Direction::ClientToServer),
        tokio::io::sink(),
        if direction == Direction::ClientToServer {
            Role::Server
        } else {
            Role::Client
        },
    );
    reader.set_auto_close(false);
    reader.set_auto_pong(false);
    reader.set_max_message_size(limit.saturating_add(1));
    let mut fragments: Option<(Kind, Vec<u8>)> = None;
    loop {
        let frame = reader
            .read_frame(&mut |_| async { Ok::<(), std::io::Error>(()) })
            .await?;
        let kind = match frame.opcode {
            OpCode::Text => Kind::Text,
            OpCode::Binary => Kind::Binary,
            OpCode::Ping => Kind::Ping,
            OpCode::Pong => Kind::Pong,
            OpCode::Close => Kind::Close,
            OpCode::Continuation => {
                fragments
                    .as_ref()
                    .context("Unexpected WebSocket continuation")?
                    .0
            }
        };
        let mut payload: Vec<u8> = frame.payload.into();
        if kind.is_data() {
            if frame.opcode == OpCode::Continuation {
                let (_, data) = fragments.as_mut().unwrap();
                ensure!(
                    payload.len() <= limit.saturating_sub(data.len()),
                    "Fragmented WebSocket message exceeds message limit"
                );
                data.extend_from_slice(&payload);
                if !frame.fin {
                    continue;
                }
                payload = fragments.take().unwrap().1;
            } else {
                ensure!(
                    fragments.is_none(),
                    "Interleaved fragmented WebSocket messages"
                );
                if !frame.fin {
                    fragments = Some((kind, payload));
                    continue;
                }
            }
            if kind == Kind::Text {
                std::str::from_utf8(&payload).context("Invalid UTF-8 WebSocket text")?;
            }
        } else if kind == Kind::Close {
            ensure!(payload.len() != 1, "Invalid WebSocket close payload");
            if payload.len() >= 2 {
                let code = u16::from_be_bytes([payload[0], payload[1]]);
                ensure!(
                    (1000..=1014).contains(&code) && !matches!(code, 1004..=1006)
                        || (3000..=4999).contains(&code),
                    "Invalid WebSocket close code"
                );
                std::str::from_utf8(&payload[2..]).context("Invalid UTF-8 close reason")?;
            }
        }
        let seq = sequence.fetch_add(1, Ordering::SeqCst);
        if retain_history {
            capture(engine, id, seq, direction, kind, &payload)?;
        }
        if kind.is_data() {
            engine
                .websockets
                .received
                .lock()
                .unwrap()
                .insert((id, direction), seq);
            let permit = match budget
                .clone()
                .try_acquire_many_owned(payload.len().max(1) as u32)
            {
                Ok(permit) => permit,
                Err(_) => {
                    finish(
                        engine,
                        history_id,
                        seq,
                        None,
                        Some("WebSocket interception byte queue is full".into()),
                    )?;
                    anyhow::bail!("WebSocket interception byte queue is full");
                }
            };
            let packet = Packet {
                sequence: seq,
                kind,
                payload: payload.into(),
                _permit: permit,
            };
            if tx.try_send(packet).is_err() {
                finish(
                    engine,
                    history_id,
                    seq,
                    None,
                    Some("WebSocket message queue is full".into()),
                )?;
                anyhow::bail!("WebSocket message queue is full");
            }
        } else {
            let result = write(&write_to_peer, kind, &payload, timeout).await;
            finish(
                engine,
                history_id,
                seq,
                Some(&payload),
                result.as_ref().err().map(crate::error::friendly),
            )?;
            result?;
            if kind == Kind::Close {
                let _ = closing.send(true);
                return Ok(());
            }
        }
    }
}

struct ForwardContext<'a> {
    engine: &'a Engine,
    id: u64,
    url: &'a str,
    direction: Direction,
    writer: Writer,
    timeout: Duration,
    retain_history: bool,
}

async fn forward(context: ForwardContext<'_>, mut rx: mpsc::Receiver<Packet>) -> Result<()> {
    let history_id = context.retain_history.then_some(context.id);
    while let Some(packet) = rx.recv().await {
        let (receiver, automatic) = {
            let mut queue = context.engine.websockets.pending.lock().unwrap();
            let automatic = context
                .engine
                .websockets
                .batches
                .lock()
                .unwrap()
                .get(&(context.id, context.direction))
                .filter(|(through, _)| packet.sequence <= *through)
                .map(|(_, decision)| *decision);
            let settings = context.engine.settings();
            if automatic.is_none()
                && context.engine.websockets.enabled()
                && (!settings.intercept_in_scope_only || settings.scope.contains(context.url))
            {
                let permit = context
                    .engine
                    .interception_slots
                    .clone()
                    .try_acquire_owned()
                    .context("Interception queue is full")?;
                let pending_id = context
                    .engine
                    .websockets
                    .next_pending
                    .fetch_add(1, Ordering::SeqCst);
                let (reply, receiver) = oneshot::channel();
                let item = Intercepted {
                    id: pending_id,
                    session_id: context.id,
                    sequence: packet.sequence,
                    url: context.url.into(),
                    direction: context.direction,
                    kind: packet.kind,
                    payload: packet.payload.clone(),
                };
                queue.insert(
                    pending_id,
                    Pending {
                        item,
                        reply,
                        _permit: permit,
                    },
                );
                (Some(receiver), automatic)
            } else {
                (None, automatic)
            }
        };
        let decision = if let Some(receiver) = receiver {
            receiver.await.context("WebSocket interception canceled")?
        } else if matches!(automatic, Some(BatchDecision::Drop)) {
            Decision::Drop
        } else {
            Decision::Forward(packet.payload.to_vec())
        };
        match decision {
            Decision::Drop => finish(context.engine, history_id, packet.sequence, None, None)?,
            Decision::Forward(payload) => {
                let result = write(&context.writer, packet.kind, &payload, context.timeout).await;
                finish(
                    context.engine,
                    history_id,
                    packet.sequence,
                    Some(&payload),
                    result.as_ref().err().map(crate::error::friendly),
                )?;
                result?;
            }
        }
    }
    Ok(())
}

pub async fn run(
    engine: &Engine,
    downstream: Stream,
    upstream: Stream,
    flow: &Exchange,
) -> Result<()> {
    run_with_history(engine, downstream, upstream, flow, true).await
}

pub(crate) async fn run_with_history(
    engine: &Engine,
    downstream: Stream,
    upstream: Stream,
    flow: &Exchange,
    retain_history: bool,
) -> Result<()> {
    if retain_history {
        let response = Message::parse(&flow.response)?;
        let session = Session {
            id: flow.id,
            url: flow.url.replacen("http", "ws", 1),
            opened_ms: now(),
            closed_ms: None,
            state: SessionState::Open,
            subprotocol: response
                .header("Sec-WebSocket-Protocol")
                .unwrap_or("")
                .into(),
            message_count: 0,
            close_code: None,
            close_reason: String::new(),
            error: None,
        };
        engine.project.lock().unwrap().put_ws_session(session)?;
    }
    let (close, mut cancel) = watch::channel(false);
    engine
        .websockets
        .active
        .lock()
        .unwrap()
        .insert(flow.id, close);
    let _guard = SessionGuard {
        engine,
        id: flow.id,
    };
    engine.websockets.activity.fetch_add(1, Ordering::SeqCst);
    let (down_read, down_write) = tokio::io::split(downstream);
    let (up_read, up_write) = tokio::io::split(upstream);
    let (_, down_writer) = after_handshake_split(tokio::io::empty(), down_write, Role::Server);
    let (_, up_writer) = after_handshake_split(tokio::io::empty(), up_write, Role::Client);
    let down_writer = Arc::new(tokio::sync::Mutex::new(down_writer));
    let up_writer = Arc::new(tokio::sync::Mutex::new(up_writer));
    let settings = engine.settings();
    let limit = settings.max_message_bytes;
    let timeout = Duration::from_secs(settings.timeout_secs);
    let sequence = AtomicU64::new(1);
    let budget = Arc::new(Semaphore::new(limit));
    let (client_tx, client_rx) = mpsc::channel(256);
    let (server_tx, server_rx) = mpsc::channel(256);
    let (closing, mut closing_rx) = watch::channel(false);
    let relay = async {
        tokio::try_join!(
            receive(
                engine,
                flow.id,
                Direction::ClientToServer,
                down_read,
                up_writer.clone(),
                &sequence,
                client_tx,
                budget.clone(),
                closing.clone(),
                limit,
                timeout,
                retain_history
            ),
            receive(
                engine,
                flow.id,
                Direction::ServerToClient,
                up_read,
                down_writer.clone(),
                &sequence,
                server_tx,
                budget,
                closing,
                limit,
                timeout,
                retain_history
            ),
            forward(
                ForwardContext {
                    engine,
                    id: flow.id,
                    url: &flow.url,
                    direction: Direction::ClientToServer,
                    writer: up_writer.clone(),
                    timeout,
                    retain_history,
                },
                client_rx,
            ),
            forward(
                ForwardContext {
                    engine,
                    id: flow.id,
                    url: &flow.url,
                    direction: Direction::ServerToClient,
                    writer: down_writer.clone(),
                    timeout,
                    retain_history,
                },
                server_rx,
            ),
        )?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::pin!(relay);
    let result = tokio::select! {
        result = &mut relay => result,
        _ = closing_rx.changed() => match tokio::time::timeout(Duration::from_secs(5), &mut relay).await { Ok(result) => result, Err(_) => Ok(()) },
        _ = cancel.changed() => {
            let _ = write(&down_writer, Kind::Close, &1000u16.to_be_bytes(), Duration::from_secs(1)).await;
            let _ = write(&up_writer, Kind::Close, &1000u16.to_be_bytes(), Duration::from_secs(1)).await;
            Ok(())
        },
    };
    if let Err(error) = &result {
        let code = if error.to_string().contains("limit")
            || error.to_string().contains("full")
            || error.to_string().contains("large")
        {
            1009u16
        } else {
            1002
        };
        let _ = write(
            &down_writer,
            Kind::Close,
            &code.to_be_bytes(),
            Duration::from_secs(1),
        )
        .await;
        let _ = write(
            &up_writer,
            Kind::Close,
            &code.to_be_bytes(),
            Duration::from_secs(1),
        )
        .await;
    }
    let mut project = engine.project.lock().unwrap();
    if let Some(mut session) = project.ws_session(flow.id) {
        session.state = if result.is_ok() {
            SessionState::Closed
        } else {
            SessionState::Error
        };
        session.error = result.as_ref().err().map(crate::error::friendly);
        session.closed_ms = Some(now());
        project.put_ws_session(session)?;
    }
    result
}

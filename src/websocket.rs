//! Captured WebSocket messages and bidirectional proxy sessions.
use crate::{engine::Engine, http::Message, model::Exchange, transport::Stream};
use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{oneshot, watch};

mod relay;
pub use relay::run;
pub(crate) use relay::run_with_history;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}
impl Direction {
    pub fn label(self) -> &'static str {
        match self {
            Self::ClientToServer => "Outgoing",
            Self::ServerToClient => "Incoming",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Kind {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}
impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Text => "Text",
            Self::Binary => "Binary",
            Self::Ping => "Ping",
            Self::Pong => "Pong",
            Self::Close => "Close",
        }
    }
    pub fn is_data(self) -> bool {
        matches!(self, Self::Text | Self::Binary)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionState {
    Open,
    Closed,
    Interrupted,
    Error,
}
impl SessionState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Closed => "Closed",
            Self::Interrupted => "Interrupted",
            Self::Error => "Error",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: u64,
    pub url: String,
    pub opened_ms: u64,
    pub closed_ms: Option<u64>,
    pub state: SessionState,
    pub subprotocol: String,
    pub message_count: u64,
    pub close_code: Option<u16>,
    pub close_reason: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Disposition {
    Pending,
    Forwarded,
    Modified,
    Dropped,
    Failed,
    Interrupted,
}
impl Disposition {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Forwarded => "Forwarded",
            Self::Modified => "Modified",
            Self::Dropped => "Dropped",
            Self::Failed => "Failed",
            Self::Interrupted => "Interrupted",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageSummary {
    pub session_id: u64,
    pub sequence: u64,
    pub direction: Direction,
    pub timestamp_ms: u64,
    pub kind: Kind,
    pub length: usize,
    pub disposition: Disposition,
    pub preview: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedMessage {
    pub summary: MessageSummary,
    pub original: Vec<u8>,
    /// Present only when the forwarded payload differs from the original.
    pub forwarded: Option<Vec<u8>>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct Intercepted {
    pub id: u64,
    pub session_id: u64,
    pub sequence: u64,
    pub url: String,
    pub direction: Direction,
    pub kind: Kind,
    pub payload: Arc<[u8]>,
}

pub enum Decision {
    Forward(Vec<u8>),
    Drop,
}
struct Pending {
    item: Intercepted,
    reply: oneshot::Sender<Decision>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Clone, Copy)]
enum BatchDecision {
    Forward,
    Drop,
}

#[derive(Default)]
pub struct Hub {
    enabled: AtomicBool,
    next_pending: AtomicU64,
    pending: Mutex<BTreeMap<u64, Pending>>,
    active: Mutex<BTreeMap<u64, watch::Sender<bool>>>,
    received: Mutex<BTreeMap<(u64, Direction), u64>>,
    batches: Mutex<BTreeMap<(u64, Direction), (u64, BatchDecision)>>,
    pub activity: AtomicU64,
}

impl Hub {
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }
    pub fn set_enabled(&self, enabled: bool) {
        let mut queue = self.pending.lock().unwrap();
        self.enabled.store(enabled, Ordering::SeqCst);
        if !enabled {
            for (_, pending) in std::mem::take(&mut *queue) {
                let _ = pending
                    .reply
                    .send(Decision::Forward(pending.item.payload.to_vec()));
            }
        }
    }
    pub fn pending(&self) -> Vec<Intercepted> {
        self.pending
            .lock()
            .unwrap()
            .values()
            .map(|p| p.item.clone())
            .collect()
    }
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
    pub fn decide(&self, id: u64, decision: Decision, limit: usize) -> Result<()> {
        let mut queue = self.pending.lock().unwrap();
        let pending = queue
            .get(&id)
            .context("WebSocket message is no longer pending")?;
        if let Decision::Forward(payload) = &decision {
            ensure!(
                payload.len() <= limit,
                "Edited WebSocket message exceeds message limit"
            );
            if pending.item.kind == Kind::Text {
                std::str::from_utf8(payload).context("Text WebSocket messages must be UTF-8")?;
            }
        }
        let pending = queue.remove(&id).unwrap();
        pending
            .reply
            .send(decision)
            .map_err(|_| anyhow::anyhow!("WebSocket session disconnected"))
    }
    pub fn forward_all(&self, edited: Option<(u64, Vec<u8>)>, limit: usize) -> Result<()> {
        if let Some((id, payload)) = edited {
            self.decide(id, Decision::Forward(payload), limit)?;
        }
        self.batch(BatchDecision::Forward);
        let queue = std::mem::take(&mut *self.pending.lock().unwrap());
        for (_, p) in queue {
            let _ = p.reply.send(Decision::Forward(p.item.payload.to_vec()));
        }
        Ok(())
    }
    pub fn drop_all(&self) {
        self.batch(BatchDecision::Drop);
        for (_, p) in std::mem::take(&mut *self.pending.lock().unwrap()) {
            let _ = p.reply.send(Decision::Drop);
        }
    }
    fn batch(&self, decision: BatchDecision) {
        let received = self.received.lock().unwrap().clone();
        let mut batches = self.batches.lock().unwrap();
        for (key, sequence) in received {
            batches.insert(key, (sequence, decision));
        }
    }
    pub fn release_exempt(&self, settings: &crate::model::Settings) {
        let mut queue = self.pending.lock().unwrap();
        let ids: Vec<_> = queue
            .iter()
            .filter(|(_, p)| {
                settings.intercept_in_scope_only && !settings.scope.contains(&p.item.url)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            let p = queue.remove(&id).unwrap();
            let _ = p.reply.send(Decision::Forward(p.item.payload.to_vec()));
        }
    }
    pub fn close(&self, id: u64) -> Result<()> {
        self.active
            .lock()
            .unwrap()
            .get(&id)
            .context("WebSocket session is no longer open")?
            .send(true)?;
        Ok(())
    }
    pub fn is_active(&self, id: u64) -> bool {
        self.active.lock().unwrap().contains_key(&id)
    }
}

pub fn is_websocket(request: &Message) -> bool {
    request
        .header("Upgrade")
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

pub fn validate_request(request: &Message) -> Result<()> {
    ensure!(
        request.method() == "GET",
        "WebSocket handshake requires GET"
    );
    ensure!(
        request.header("Sec-WebSocket-Version") == Some("13"),
        "Unsupported WebSocket version"
    );
    let key = request
        .header("Sec-WebSocket-Key")
        .context("Missing Sec-WebSocket-Key")?;
    ensure!(
        base64::engine::general_purpose::STANDARD.decode(key)?.len() == 16,
        "Invalid WebSocket key"
    );
    Ok(())
}

pub fn validate_response(request: &Message, response: &Message) -> Result<()> {
    validate_request(request)?;
    ensure!(
        response.status() == 101 && is_websocket(response),
        "Invalid WebSocket upgrade response"
    );
    ensure!(
        response.header("Connection").is_some_and(|v| v
            .split(',')
            .any(|s| s.trim().eq_ignore_ascii_case("upgrade"))),
        "Missing Connection: Upgrade"
    );
    let key = request.header("Sec-WebSocket-Key").unwrap();
    let expected = base64::engine::general_purpose::STANDARD.encode(Sha1::digest(format!(
        "{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    )));
    ensure!(
        response.header("Sec-WebSocket-Accept") == Some(expected.as_str()),
        "Invalid Sec-WebSocket-Accept"
    );
    ensure!(
        response.header("Sec-WebSocket-Extensions").is_none(),
        "Server negotiated an unoffered WebSocket extension"
    );
    if let Some(protocol) = response.header("Sec-WebSocket-Protocol") {
        ensure!(
            request
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("Sec-WebSocket-Protocol"))
                .flat_map(|(_, value)| value.split(','))
                .any(|s| s.trim() == protocol),
            "Server selected an unoffered WebSocket subprotocol"
        );
    }
    Ok(())
}

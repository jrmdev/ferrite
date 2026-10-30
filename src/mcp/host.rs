//! Shared state for executing MCP tools against the live engine.
use super::{AuditEntry, McpSettings, Outcome, Permission, now_ms};
use crate::engine::Engine;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_PENDING_APPROVALS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostMode {
    /// Tools run inside the Ferrite window; approvals are interactive.
    Gui,
    /// Tools run in `ferrite mcp --headless`; there is nobody to ask.
    Headless,
}

/// Capabilities that produce network traffic and need authorisation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    SendRequests,
    ActiveScans,
}
impl Capability {
    pub fn label(self) -> &'static str {
        match self {
            Self::SendRequests => "Send HTTP requests",
            Self::ActiveScans => "Active scanning",
        }
    }
}

/// A pending request for the Ferrite user's approval.
#[derive(Clone, Debug)]
pub struct Approval {
    pub id: u64,
    pub capability: Capability,
    pub client: String,
    pub summary: String,
    /// Request head or scan targets, bounded, for the user to review.
    pub detail: String,
    pub requested: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    AllowOnce,
    /// Allow this capability until MCP is disabled or Ferrite exits.
    AllowSession,
    Deny,
}

/// An MCP client connected to this host.
#[derive(Clone, Debug)]
pub struct Client {
    pub id: u64,
    pub name: String,
    pub version: String,
    pub transport: &'static str,
    pub connected_ms: u64,
    pub calls: u64,
    pub last_call_ms: Option<u64>,
}

pub struct Host {
    engine: RwLock<Arc<Engine>>,
    settings: RwLock<McpSettings>,
    mode: HostMode,
    approvals: Mutex<BTreeMap<u64, (Approval, oneshot::Sender<Decision>)>>,
    next_id: AtomicU64,
    session_allowed: Mutex<BTreeSet<Capability>>,
    clients: Mutex<BTreeMap<u64, Client>>,
    sends: Mutex<VecDeque<Instant>>,
    network: Mutex<Arc<Semaphore>>,
    /// Incremented when approvals, clients or audit entries change.
    pub activity: AtomicU64,
}

impl Host {
    pub fn new(engine: Arc<Engine>, settings: McpSettings, mode: HostMode) -> Arc<Self> {
        let network = Arc::new(Semaphore::new(settings.max_concurrent_requests));
        Arc::new(Self {
            engine: RwLock::new(engine),
            settings: RwLock::new(settings),
            mode,
            approvals: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            session_allowed: Mutex::new(BTreeSet::new()),
            clients: Mutex::new(BTreeMap::new()),
            sends: Mutex::new(VecDeque::new()),
            network: Mutex::new(network),
            activity: AtomicU64::new(0),
        })
    }
    pub fn mode(&self) -> HostMode {
        self.mode
    }
    /// The engine of the currently open project.
    pub fn engine(&self) -> Arc<Engine> {
        self.engine.read().unwrap().clone()
    }
    /// Follow a project switch. Pending approvals belong to the old project.
    pub fn set_engine(&self, engine: Arc<Engine>) {
        *self.engine.write().unwrap() = engine;
        self.deny_all();
    }
    pub fn settings(&self) -> McpSettings {
        self.settings.read().unwrap().clone()
    }
    pub fn set_settings(&self, settings: McpSettings) {
        let previous = std::mem::replace(&mut *self.settings.write().unwrap(), settings.clone());
        if previous.max_concurrent_requests != settings.max_concurrent_requests {
            *self.network.lock().unwrap() =
                Arc::new(Semaphore::new(settings.max_concurrent_requests));
        }
        if !settings.enabled {
            self.session_allowed.lock().unwrap().clear();
            self.deny_all();
        }
        self.touch();
    }
    fn touch(&self) {
        self.activity.fetch_add(1, Ordering::SeqCst);
    }

    pub fn pending_approvals(&self) -> Vec<Approval> {
        self.approvals
            .lock()
            .unwrap()
            .values()
            .map(|(approval, _)| approval.clone())
            .collect()
    }
    pub fn decide(&self, id: u64, decision: Decision) {
        if let Some((approval, reply)) = self.approvals.lock().unwrap().remove(&id) {
            if decision == Decision::AllowSession {
                self.session_allowed
                    .lock()
                    .unwrap()
                    .insert(approval.capability);
            }
            let _ = reply.send(decision);
        }
        self.touch();
    }
    pub fn deny_all(&self) {
        for (_, (_, reply)) in std::mem::take(&mut *self.approvals.lock().unwrap()) {
            let _ = reply.send(Decision::Deny);
        }
        self.touch();
    }
    pub fn revoke_session(&self) {
        self.session_allowed.lock().unwrap().clear();
        self.touch();
    }
    pub fn session_allowed(&self) -> Vec<Capability> {
        self.session_allowed
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect()
    }

    /// Wait for permission to use a capability. Returns the denial reason.
    pub async fn authorise(
        &self,
        capability: Capability,
        client: &str,
        summary: String,
        detail: String,
    ) -> Result<(), String> {
        let settings = self.settings();
        let permission = match capability {
            Capability::SendRequests => settings.send_requests,
            Capability::ActiveScans => settings.active_scans,
        };
        let setting = match capability {
            Capability::SendRequests => "Send HTTP requests",
            Capability::ActiveScans => "Active scans",
        };
        match permission {
            Permission::Allow => return Ok(()),
            Permission::Deny => {
                return Err(format!(
                    "{} is disabled for MCP clients. The Ferrite user can change '{setting}' under MCP in Ferrite.",
                    capability.label()
                ));
            }
            Permission::Ask => {}
        }
        if self.session_allowed.lock().unwrap().contains(&capability) {
            return Ok(());
        }
        if self.mode == HostMode::Headless {
            return Err(format!(
                "{} requires approval, but headless MCP has no window to ask in. Restart it with --allow-requests or --allow-active-scans to pre-authorise.",
                capability.label()
            ));
        }
        let (tx, rx) = oneshot::channel();
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        {
            let mut approvals = self.approvals.lock().unwrap();
            if approvals.len() >= MAX_PENDING_APPROVALS {
                return Err("Too many MCP actions are already awaiting approval".into());
            }
            approvals.insert(
                id,
                (
                    Approval {
                        id,
                        capability,
                        client: client.into(),
                        summary,
                        detail,
                        requested: Instant::now(),
                    },
                    tx,
                ),
            );
        }
        self.touch();
        // Removing the entry on every exit path keeps cancelled calls out of the UI.
        struct Cleanup<'a>(&'a Host, u64);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                if self.0.approvals.lock().unwrap().remove(&self.1).is_some() {
                    self.0.touch();
                }
            }
        }
        let _cleanup = Cleanup(self, id);
        match tokio::time::timeout(APPROVAL_TIMEOUT, rx).await {
            Ok(Ok(Decision::AllowOnce | Decision::AllowSession)) => Ok(()),
            Ok(Ok(Decision::Deny)) | Ok(Err(_)) => {
                Err("The Ferrite user denied this action. Do not retry it unless asked.".into())
            }
            Err(_) => Err(
                "No decision was made in Ferrite within two minutes; the action was not performed."
                    .into(),
            ),
        }
    }

    /// Reserve capacity for one outbound request under the rate and
    /// concurrency limits.
    pub fn admit_request(&self) -> Result<OwnedSemaphorePermit, String> {
        let settings = self.settings();
        let permit = self
            .network
            .lock()
            .unwrap()
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                format!(
                    "{} MCP requests are already in flight; wait for them to finish",
                    settings.max_concurrent_requests
                )
            })?;
        let mut sends = self.sends.lock().unwrap();
        let window = Duration::from_secs(60);
        while sends.front().is_some_and(|at| at.elapsed() > window) {
            sends.pop_front();
        }
        if sends.len() >= settings.requests_per_minute as usize {
            let wait = sends
                .front()
                .map(|at| window.saturating_sub(at.elapsed()).as_secs() + 1)
                .unwrap_or(1);
            return Err(format!(
                "MCP rate limit of {} requests per minute reached; retry in {wait} s",
                settings.requests_per_minute
            ));
        }
        sends.push_back(Instant::now());
        Ok(permit)
    }

    pub fn connect(&self, name: &str, version: &str, transport: &'static str) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let clip = |value: &str| value.chars().take(80).collect::<String>();
        self.clients.lock().unwrap().insert(
            id,
            Client {
                id,
                name: clip(name),
                version: clip(version),
                transport,
                connected_ms: now_ms(),
                calls: 0,
                last_call_ms: None,
            },
        );
        self.touch();
        id
    }
    pub fn disconnect(&self, id: u64) {
        self.clients.lock().unwrap().remove(&id);
        self.touch();
    }
    pub fn clients(&self) -> Vec<Client> {
        self.clients.lock().unwrap().values().cloned().collect()
    }
    pub(super) fn record_call(&self, client: u64) {
        if let Some(client) = self.clients.lock().unwrap().get_mut(&client) {
            client.calls += 1;
            client.last_call_ms = Some(now_ms());
        }
    }

    /// Append to the current project's audit trail.
    pub(super) fn audit(&self, entry: AuditEntry) {
        let engine = self.engine();
        let result = engine.project.lock().unwrap().append_audit(entry);
        if let Err(error) = result {
            engine.log_error(format!("MCP audit: {error:#}"));
        }
        self.touch();
    }
    pub fn recent_audit(&self) -> Vec<AuditEntry> {
        self.engine()
            .project
            .lock()
            .unwrap()
            .audit_entries()
            .to_vec()
    }
}

pub(super) fn outcome_entry(
    client: &str,
    tool: &str,
    summary: String,
    outcome: Outcome,
    detail: String,
    started: Instant,
    exchange_ids: Vec<u64>,
) -> AuditEntry {
    AuditEntry {
        id: 0,
        timestamp_ms: now_ms(),
        client: client.into(),
        tool: tool.into(),
        summary,
        outcome,
        detail: detail.chars().take(500).collect(),
        duration_ms: started.elapsed().as_millis() as u64,
        exchange_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::Project;

    fn host(settings: McpSettings, mode: HostMode) -> Arc<Host> {
        Host::new(Engine::new(Project::temporary()).unwrap(), settings, mode)
    }

    #[tokio::test]
    async fn permissions_and_approvals() {
        let denied = host(
            McpSettings {
                send_requests: Permission::Deny,
                ..Default::default()
            },
            HostMode::Gui,
        );
        assert!(
            denied
                .authorise(Capability::SendRequests, "c", "GET /".into(), String::new())
                .await
                .unwrap_err()
                .contains("disabled")
        );
        let headless = host(McpSettings::default(), HostMode::Headless);
        assert!(
            headless
                .authorise(Capability::SendRequests, "c", "GET /".into(), String::new())
                .await
                .unwrap_err()
                .contains("--allow-requests")
        );
        let gui = host(McpSettings::default(), HostMode::Gui);
        let waiting = {
            let gui = gui.clone();
            tokio::spawn(async move {
                gui.authorise(Capability::SendRequests, "c", "GET /".into(), "x".into())
                    .await
            })
        };
        while gui.pending_approvals().is_empty() {
            tokio::task::yield_now().await;
        }
        let pending = gui.pending_approvals();
        assert_eq!(pending[0].summary, "GET /");
        gui.decide(pending[0].id, Decision::AllowSession);
        assert!(waiting.await.unwrap().is_ok());
        assert!(gui.pending_approvals().is_empty());
        // The session grant skips the prompt for the same capability only.
        gui.authorise(
            Capability::SendRequests,
            "c",
            "GET /2".into(),
            String::new(),
        )
        .await
        .unwrap();
        assert!(
            gui.authorise(Capability::ActiveScans, "c", "scan".into(), String::new())
                .await
                .is_err()
        );
        let waiting = {
            let gui = gui.clone();
            tokio::spawn(async move {
                gui.authorise(Capability::SendRequests, "c", "x".into(), String::new())
                    .await
            })
        };
        tokio::task::yield_now().await;
        // Disabling MCP revokes session grants and denies anything pending.
        gui.set_settings(McpSettings {
            enabled: false,
            ..Default::default()
        });
        let _ = waiting.await.unwrap();
        assert!(gui.session_allowed().is_empty());
    }

    #[test]
    fn rate_and_concurrency_limits() {
        let host = host(
            McpSettings {
                requests_per_minute: 3,
                max_concurrent_requests: 2,
                ..Default::default()
            },
            HostMode::Gui,
        );
        let first = host.admit_request().unwrap();
        let second = host.admit_request().unwrap();
        assert!(host.admit_request().unwrap_err().contains("in flight"));
        drop(first);
        drop(second);
        let _third = host.admit_request().unwrap();
        assert!(host.admit_request().unwrap_err().contains("rate limit"));
    }
}

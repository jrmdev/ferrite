//! Model Context Protocol (MCP) support.
//!
//! Ferrite exposes its live engine to MCP clients through
//! tools defined in [`tools`]. The protocol layer ([`server`]) uses the
//! official `rmcp` SDK over stdio and talks to a [`server::Backend`]:
//!
//! - **Relay** (`ferrite mcp`): forwards tool calls over an authenticated
//!   loopback connection ([`ipc`]) to a running Ferrite GUI, which executes
//!   them against its in-memory engine and project. The relay never opens the
//!   project database, so there is a single writer.
//! - **Headless** (`ferrite mcp --headless`): owns the project exclusively and
//!   executes tools in-process.
//!
//! MCP is opt-in. Network-producing tools are confined to the target scope,
//! rate- and concurrency-limited, and gated by per-capability permissions
//! that default to asking (requests) or denying (active scans). Every call is
//! recorded in the project's audit trail.
pub mod host;
pub mod ipc;
mod redact;
pub mod server;
pub mod tools;

use serde::{Deserialize, Serialize};

/// How a capability that produces network traffic is authorised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    /// Always refused.
    #[default]
    Deny,
    /// Each call waits for approval in the Ferrite window.
    Ask,
    /// Allowed without prompting (still scope-limited and rate-limited).
    Allow,
}
impl Permission {
    pub const ALL: [Self; 3] = [Self::Deny, Self::Ask, Self::Allow];
    pub fn label(self) -> &'static str {
        match self {
            Self::Deny => "Deny",
            Self::Ask => "Ask each time",
            Self::Allow => "Allow",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct McpSettings {
    /// Serve MCP clients from the running Ferrite window.
    pub enabled: bool,
    /// Sending HTTP requests through Ferrite's engine (`send_http_request`).
    pub send_requests: Permission,
    /// Starting and cancelling active scans.
    pub active_scans: Permission,
    /// Return credential headers (Cookie, Authorization, ...) unredacted.
    pub include_credentials: bool,
    pub requests_per_minute: u32,
    pub max_concurrent_requests: usize,
}
impl Default for McpSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            send_requests: Permission::Ask,
            active_scans: Permission::Deny,
            include_credentials: false,
            requests_per_minute: 60,
            max_concurrent_requests: 4,
        }
    }
}
impl McpSettings {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=6000).contains(&self.requests_per_minute),
            "MCP request rate must be 1..6000 per minute"
        );
        anyhow::ensure!(
            (1..=32).contains(&self.max_concurrent_requests),
            "MCP request concurrency must be 1..32"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Ok,
    Error,
    Denied,
}
impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Error => "Error",
            Self::Denied => "Denied",
        }
    }
}

/// One MCP tool call, persisted in the project's `mcp_audit` table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp_ms: u64,
    pub client: String,
    pub tool: String,
    /// Arguments in brief; request bodies are summarised, never stored.
    pub summary: String,
    pub outcome: Outcome,
    pub detail: String,
    pub duration_ms: u64,
    /// History exchanges created by the call.
    pub exchange_ids: Vec<u64>,
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

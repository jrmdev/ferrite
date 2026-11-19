//! Project-scoped HTTP auditing. Passive checks never receive a transport.
pub mod checks;
mod engine;
pub mod report;
pub mod runner;
mod tls_checks;

/// Bump whenever probe generation/order or confirmation semantics change.
pub const CHECK_VERSION: u32 = 7;

use crate::model::Exchange;
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, atomic::AtomicU64};

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Information,
    Low,
    #[default]
    Medium,
    High,
}
impl Severity {
    pub const ALL: [Self; 4] = [Self::High, Self::Medium, Self::Low, Self::Information];
    pub fn label(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Information => "Information",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    #[default]
    Tentative,
    Firm,
    Certain,
}
impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::Certain => "Certain",
            Self::Firm => "Firm",
            Self::Tentative => "Tentative",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    Passive,
    Active,
}
impl ScanMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Passive => "Passive",
            Self::Active => "Active",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewState {
    #[default]
    New,
    Reviewed,
    FalsePositive,
}
impl ReviewState {
    pub const ALL: [Self; 3] = [Self::New, Self::Reviewed, Self::FalsePositive];
    pub fn label(self) -> &'static str {
        match self {
            Self::New => "New",
            Self::Reviewed => "Reviewed",
            Self::FalsePositive => "False positive",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelayMode {
    #[default]
    Fixed,
    Random,
    Increasing,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureAction {
    #[default]
    Pause,
    Stop,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ScanSettings {
    pub concurrency: usize,
    pub delay_ms: u64,
    pub delay_mode: DelayMode,
    pub jitter_ms: u64,
    pub delay_increment_ms: u64,
    pub auto_throttle: bool,
    pub throttle_503: bool,
    pub throttle_codes: Vec<u16>,
    pub backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub timeout_secs: u64,
    pub stop_after_failures: usize,
    pub failure_action: FailureAction,
    pub check_failure_limit: usize,
    pub insertion_failure_limit: usize,
    pub failed_item_limit: usize,
    pub failed_item_percent: u8,
    pub retry_passes: usize,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub max_insertion_points: usize,
    pub max_probes_per_request: usize,
    /// Empty selects all applicable checks. disabled_checks can override this default.
    pub enabled_checks: Vec<String>,
    pub disabled_checks: Vec<String>,
    pub intrusive: bool,
    pub static_javascript: bool,
    pub scan_query_values: bool,
    pub scan_form_values: bool,
    pub scan_json_values: bool,
    pub scan_json_body: bool,
    pub scan_xml_elements: bool,
    pub scan_xml_attributes: bool,
    pub scan_multipart_values: bool,
    pub scan_multipart_filenames: bool,
    pub scan_headers: bool,
    pub scan_cookies: bool,
    pub scan_path: bool,
    pub scan_parameter_names: bool,
    pub nested: bool,
    pub excluded_parameters: Vec<String>,
}
impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            concurrency: 10,
            delay_ms: 0,
            delay_mode: DelayMode::Fixed,
            jitter_ms: 100,
            delay_increment_ms: 100,
            auto_throttle: true,
            throttle_503: false,
            throttle_codes: vec![],
            backoff_ms: 1000,
            max_backoff_ms: 60000,
            timeout_secs: 30,
            stop_after_failures: 10,
            failure_action: FailureAction::Pause,
            check_failure_limit: 2,
            insertion_failure_limit: 2,
            failed_item_limit: 60,
            failed_item_percent: 0,
            retry_passes: 1,
            follow_redirects: true,
            max_redirects: 5,
            max_insertion_points: 30,
            max_probes_per_request: 20000,
            enabled_checks: vec![],
            disabled_checks: vec![],
            intrusive: false,
            static_javascript: true,
            scan_query_values: true,
            scan_form_values: true,
            scan_json_values: true,
            scan_json_body: false,
            scan_xml_elements: true,
            scan_xml_attributes: true,
            scan_multipart_values: true,
            scan_multipart_filenames: true,
            scan_headers: false,
            scan_cookies: false,
            scan_path: false,
            scan_parameter_names: false,
            nested: true,
            excluded_parameters: vec![
                "PHPSESSID".into(),
                "JSESSIONID".into(),
                "session_id".into(),
                "ASP.NET_SessionId".into(),
                "ASPSESSIONID*".into(),
                "CFID".into(),
                "CFTOKEN".into(),
                "__VIEWSTATE".into(),
                "__VIEWSTATEGENERATOR".into(),
                "__EVENTVALIDATION".into(),
                "__EVENTTARGET".into(),
                "__EVENTARGUMENT".into(),
                "_ga".into(),
                "_gid".into(),
                "_gat".into(),
                "_ga_*".into(),
                "_gac_*".into(),
                "AWSALB*".into(),
                "AWSALBCORS".into(),
                "csrf_token".into(),
                "csrftoken".into(),
                "XSRF-TOKEN".into(),
                "_csrf".into(),
                "authenticity_token".into(),
            ],
        }
    }
}
impl ScanSettings {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=128).contains(&self.concurrency),
            "Scanner concurrency must be 1..128"
        );
        anyhow::ensure!(
            (1..=3600).contains(&self.timeout_secs),
            "Scanner timeout must be 1..3600 seconds"
        );
        anyhow::ensure!(
            self.delay_ms <= 600000
                && self.jitter_ms <= 600000
                && self.delay_increment_ms <= 600000,
            "Scanner delays must not exceed 600000 ms"
        );
        anyhow::ensure!(
            self.backoff_ms > 0
                && self.max_backoff_ms >= self.backoff_ms
                && self.max_backoff_ms <= 3600000,
            "Invalid scanner backoff range"
        );
        anyhow::ensure!(
            (1..=1000).contains(&self.max_insertion_points),
            "Insertion point limit must be 1..1000"
        );
        anyhow::ensure!(
            (1..=100000).contains(&self.max_probes_per_request),
            "Probe limit must be 1..100000"
        );
        anyhow::ensure!(
            self.failed_item_percent <= 100 && self.retry_passes <= 15 && self.max_redirects <= 20,
            "Invalid scanner failure, retry, or redirect limit"
        );
        anyhow::ensure!(
            self.throttle_codes.iter().all(|v| (100..=599).contains(v)),
            "Throttle status codes must be 100..599"
        );
        Ok(())
    }
    pub fn check_enabled(&self, id: &str) -> bool {
        !self.disabled_checks.iter().any(|v| v == id)
            && (self.enabled_checks.is_empty() || self.enabled_checks.iter().any(|v| v == id))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueDefinition {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub passive: bool,
    pub active: bool,
    pub intrusive: bool,
    pub description: String,
    pub remediation: String,
    pub references: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub label: String,
    pub exchange: Exchange,
}
#[derive(Clone, Debug)]
pub struct Candidate {
    pub affected: Option<(String, String)>,
    pub issue_id: String,
    pub confidence: Confidence,
    pub insertion_point: String,
    pub detail: String,
    pub evidence: Vec<Evidence>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: u64,
    pub issue_id: String,
    pub title: String,
    pub severity: Severity,
    pub original_severity: Severity,
    pub confidence: Confidence,
    pub mode: ScanMode,
    pub origins: Vec<ScanMode>,
    pub url: String,
    pub method: String,
    pub insertion_point: String,
    pub detail: String,
    pub description: String,
    pub remediation: String,
    pub evidence: Vec<Evidence>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub occurrences: usize,
    pub state: ReviewState,
    pub notes: String,
    pub scan_ids: Vec<u64>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStatus {
    #[default]
    Queued,
    Running,
    Paused,
    Completed,
    Cancelled,
    Interrupted,
    Failed,
}
impl ScanStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Running => "Running",
            Self::Paused => "Paused",
            Self::Completed => "Completed",
            Self::Cancelled => "Cancelled",
            Self::Interrupted => "Interrupted",
            Self::Failed => "Failed",
        }
    }
    pub fn unfinished(self) -> bool {
        matches!(self, Self::Queued | Self::Running | Self::Paused)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanItem {
    pub source: Exchange,
    pub status: ScanStatus,
    pub next_probe: usize,
    pub completed: usize,
    pub failures: usize,
    pub message: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: u64,
    #[serde(default)]
    pub check_version: u32,
    pub name: String,
    pub status: ScanStatus,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub settings: ScanSettings,
    pub items: Vec<ScanItem>,
    pub requests: usize,
    pub failures: usize,
    pub findings: usize,
    pub skipped: usize,
    pub message: String,
}

#[derive(Default)]
pub struct Hub {
    pub(crate) engine: std::sync::OnceLock<std::sync::Weak<crate::engine::Engine>>,
    pub runner: runner::RunnerHub,
    pub activity: AtomicU64,
    pub(crate) passive_queue: Mutex<std::collections::VecDeque<(Exchange, ScanSettings)>>,
    pub(crate) passive_running: std::sync::atomic::AtomicBool,
    pub(crate) passive_stopping: std::sync::atomic::AtomicBool,
}
impl Hub {
    pub fn is_busy(&self) -> bool {
        self.runner.active()
            || self
                .passive_running
                .load(std::sync::atomic::Ordering::SeqCst)
    }
}

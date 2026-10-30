use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}
impl Destination {
    pub fn from_url(value: &str) -> anyhow::Result<Self> {
        let u = url::Url::parse(value)?;
        anyhow::ensure!(
            matches!(u.scheme(), "http" | "https"),
            "Use http:// or https://"
        );
        anyhow::ensure!(
            u.username().is_empty() && u.password().is_none(),
            "URL credentials are not supported; use an Authorization header"
        );
        Ok(Self {
            host: u
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Missing host"))?
                .trim_matches(['[', ']'])
                .into(),
            port: u.port_or_known_default().unwrap(),
            tls: u.scheme() == "https",
        })
    }
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
    pub fn origin(&self) -> String {
        format!(
            "{}://{}",
            if self.tls { "https" } else { "http" },
            self.authority()
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum UpstreamKind {
    #[default]
    Direct,
    Http,
    Socks5,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Upstream {
    pub kind: UpstreamKind,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub remote_dns: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Scope {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}
impl Scope {
    pub fn set_url(&mut self, url: &str, included: bool) -> anyhow::Result<()> {
        Destination::from_url(url)?;
        let pattern = format!("^{}$", regex::escape(url));
        let (add, remove) = if included {
            (&mut self.include, &mut self.exclude)
        } else {
            (&mut self.exclude, &mut self.include)
        };
        remove.retain(|value| value != &pattern);
        if !add.contains(&pattern) {
            add.push(pattern);
        }
        Ok(())
    }
    pub fn set_host(&mut self, host: &str, included: bool) -> anyhow::Result<()> {
        let raw = host.trim_matches(['[', ']']);
        let authority = if raw.contains(':') {
            format!("[{raw}]")
        } else {
            raw.to_owned()
        };
        let canonical = url::Host::parse(&authority)?.to_string();
        let pattern = format!(
            r"(?i)^https?://{}(?::[0-9]+)?(?:/|$)",
            regex::escape(&canonical)
        );
        let (add, remove) = if included {
            (&mut self.include, &mut self.exclude)
        } else {
            (&mut self.exclude, &mut self.include)
        };
        remove.retain(|value| value != &pattern);
        if !add.contains(&pattern) {
            add.push(pattern);
        }
        Ok(())
    }
    pub fn contains(&self, url: &str) -> bool {
        let matches = |patterns: &[String]| {
            patterns
                .iter()
                .any(|p| regex::Regex::new(p).is_ok_and(|r| r.is_match(url)))
        };
        matches(&self.include) && !matches(&self.exclude)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        for p in self.include.iter().chain(&self.exclude) {
            regex::Regex::new(p)?;
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleTarget {
    #[default]
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplaceRule {
    pub enabled: bool,
    pub target: RuleTarget,
    pub regex: bool,
    pub pattern: String,
    pub replacement: String,
    pub comment: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub passive_scanning: bool,
    pub listen: String,
    pub transparent: bool,
    pub fallback: Option<Destination>,
    pub dns_overrides: BTreeMap<String, String>,
    pub upstream: Upstream,
    pub scope: Scope,
    pub drop_out_of_scope: bool,
    pub intercept_in_scope_only: bool,
    pub rules_in_scope_only: bool,
    pub rules: Vec<ReplaceRule>,
    pub timeout_secs: u64,
    pub max_message_bytes: usize,
    pub verify_tls: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            passive_scanning: true,
            listen: "127.0.0.1:8080".into(),
            transparent: false,
            fallback: None,
            dns_overrides: BTreeMap::new(),
            upstream: Upstream::default(),
            scope: Scope::default(),
            drop_out_of_scope: false,
            intercept_in_scope_only: false,
            rules_in_scope_only: false,
            rules: vec![],
            timeout_secs: 30,
            max_message_bytes: 32 * 1024 * 1024,
            verify_tls: true,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> anyhow::Result<()> {
        let _: std::net::SocketAddr = self.listen.parse()?;
        self.scope.validate()?;
        anyhow::ensure!(
            self.timeout_secs > 0 && self.timeout_secs <= 3600,
            "Timeout must be 1..3600 seconds"
        );
        anyhow::ensure!(
            (1024..=512 * 1024 * 1024).contains(&self.max_message_bytes),
            "Message limit must be 1 KiB..512 MiB"
        );
        if self.upstream.kind != UpstreamKind::Direct {
            anyhow::ensure!(
                !self.upstream.host.is_empty() && self.upstream.port != 0,
                "Upstream host and port are required"
            );
            anyhow::ensure!(
                self.upstream.username.len() <= 255 && self.upstream.password.len() <= 255,
                "Proxy credentials exceed 255 bytes"
            );
        }
        for r in &self.rules {
            if r.regex {
                regex::bytes::Regex::new(&r.pattern)?;
            }
        }
        for ip in self.dns_overrides.values() {
            let _: std::net::IpAddr = ip.parse()?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Exchange {
    pub id: u64,
    pub timestamp_ms: u64,
    pub tool: String,
    pub destination: Destination,
    pub url: String,
    pub method: String,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    pub status: u16,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub note: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepeaterTab {
    /// Stable identity used by the UI and MCP clients; 0 until assigned.
    #[serde(default)]
    pub id: u64,
    /// Optional collection the tab is grouped under.
    #[serde(default)]
    pub group: String,
    pub name: String,
    pub destination: String,
    #[serde(default)]
    pub request_hex: bool,
    pub request: String,
    pub history: Vec<u64>,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ColorScheme {
    #[default]
    Dark,
    Light,
    Dracula,
    Nord,
    SolarizedDark,
    PaleBlue,
    PaleGreen,
    PaleRed,
    PaleGrey,
    PalePurple,
    PaleYellow,
}

impl ColorScheme {
    pub const ALL: [Self; 11] = [
        Self::Dark,
        Self::Light,
        Self::Dracula,
        Self::Nord,
        Self::SolarizedDark,
        Self::PaleBlue,
        Self::PaleGreen,
        Self::PaleRed,
        Self::PaleGrey,
        Self::PalePurple,
        Self::PaleYellow,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Dark => "Dark",
            Self::Light => "Light",
            Self::Dracula => "Dracula",
            Self::Nord => "Nord",
            Self::SolarizedDark => "Solarized Dark",
            Self::PaleBlue => "Pale Blue",
            Self::PaleGreen => "Pale Green",
            Self::PaleRed => "Pale Red",
            Self::PaleGrey => "Pale Grey",
            Self::PalePurple => "Pale Purple",
            Self::PaleYellow => "Pale Yellow",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Workspace {
    #[serde(default)]
    pub scanner: crate::scanner::ScanSettings,
    pub schema: u32,
    pub name: String,
    #[serde(default)]
    pub color_scheme: ColorScheme,
    pub settings: Settings,
    pub repeater: Vec<RepeaterTab>,
    pub intruder: crate::intruder::Attack,
    #[serde(default)]
    pub history_filter: crate::history::HistoryFilter,
    #[serde(default = "default_enabled")]
    pub beautify_json: bool,
    #[serde(default)]
    pub websocket_state_filter: Option<crate::websocket::SessionState>,
}
impl Default for Workspace {
    fn default() -> Self {
        Self {
            scanner: crate::scanner::ScanSettings::default(),
            schema: 1,
            name: "Temporary project".into(),
            color_scheme: ColorScheme::default(),
            settings: Settings::default(),
            repeater: vec![RepeaterTab {
                id: 1,
                group: String::new(),
                name: "1".into(),
                destination: "https://example.com".into(),
                request_hex: false,
                request: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
                history: vec![],
            }],
            intruder: crate::intruder::Attack::default(),
            history_filter: crate::history::HistoryFilter::default(),
            beautify_json: true,
            websocket_state_filter: None,
        }
    }
}

impl Workspace {
    /// Give every Repeater tab a unique non-zero ID, keeping existing ones.
    pub fn assign_repeater_ids(&mut self) {
        let mut seen = std::collections::BTreeSet::new();
        let mut next = self.repeater.iter().map(|t| t.id).max().unwrap_or(0);
        for tab in &mut self.repeater {
            if tab.id == 0 || !seen.insert(tab.id) {
                next += 1;
                tab.id = next;
                seen.insert(next);
            }
        }
    }
    pub fn next_repeater_id(&self) -> u64 {
        self.repeater.iter().map(|t| t.id).max().unwrap_or(0) + 1
    }
    pub fn repeater_tab(&self, id: u64) -> Option<&RepeaterTab> {
        self.repeater.iter().find(|t| t.id == id)
    }
    pub fn repeater_tab_mut(&mut self, id: u64) -> Option<&mut RepeaterTab> {
        self.repeater.iter_mut().find(|t| t.id == id)
    }
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspaces_from_older_versions_gain_repeater_ids() {
        // A v0.1.1 workspace: Repeater tabs have no id or group.
        let mut old = serde_json::to_value(Workspace::default()).unwrap();
        let tab = serde_json::json!({
            "name": "1", "destination": "https://a.test", "request": "GET / HTTP/1.1\r\n\r\n", "history": [3]
        });
        old["repeater"] = serde_json::json!([tab.clone(), tab]);
        old["history_filter"]
            .as_object_mut()
            .unwrap()
            .remove("annotated_only");
        let mut workspace: Workspace = serde_json::from_value(old).unwrap();
        assert!(
            workspace
                .repeater
                .iter()
                .all(|t| t.id == 0 && t.group.is_empty())
        );
        workspace.assign_repeater_ids();
        assert_eq!(
            workspace.repeater.iter().map(|t| t.id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(workspace.repeater_tab(2).unwrap().history, [3]);
        assert_eq!(workspace.next_repeater_id(), 3);
        assert!(!workspace.history_filter.annotated_only);
    }
}

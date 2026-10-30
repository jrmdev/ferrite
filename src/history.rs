//! Project-persisted history display filters. These never change captured traffic.
use crate::model::{Exchange, Scope};
use serde::{Deserialize, Deserializer, Serialize};

const OLD_HIDDEN_EXTENSIONS: &str = "js,gif,jpg,jpeg,png,css,woff,woff2,ico,svg";
const DEFAULT_HIDDEN_EXTENSIONS: &str = "js,gif,jpg,jpeg,png,webp,css,woff,woff2,ttf,ico,svg";

fn deserialize_hidden_extensions<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    Ok(if value == OLD_HIDDEN_EXTENSIONS {
        DEFAULT_HIDDEN_EXTENSIONS.into()
    } else {
        value
    })
}

/// A colour mark for an exchange in History.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Highlight {
    Red,
    Orange,
    Yellow,
    Green,
    Cyan,
    Blue,
    Purple,
    Grey,
}
impl Highlight {
    pub const ALL: [Self; 8] = [
        Self::Red,
        Self::Orange,
        Self::Yellow,
        Self::Green,
        Self::Cyan,
        Self::Blue,
        Self::Purple,
        Self::Grey,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::Red => "Red",
            Self::Orange => "Orange",
            Self::Yellow => "Yellow",
            Self::Green => "Green",
            Self::Cyan => "Cyan",
            Self::Blue => "Blue",
            Self::Purple => "Purple",
            Self::Grey => "Grey",
        }
    }
    pub fn rgb(self) -> [u8; 3] {
        match self {
            Self::Red => [220, 70, 70],
            Self::Orange => [230, 140, 50],
            Self::Yellow => [220, 200, 60],
            Self::Green => [70, 180, 90],
            Self::Cyan => [60, 190, 200],
            Self::Blue => [70, 120, 220],
            Self::Purple => [160, 90, 210],
            Self::Grey => [140, 140, 140],
        }
    }
    pub fn parse(label: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|h| h.label().eq_ignore_ascii_case(label.trim()))
    }
}

/// User notes on an exchange, stored separately from captured bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annotation {
    pub comment: String,
    pub highlight: Option<Highlight>,
}
impl Annotation {
    pub fn is_empty(&self) -> bool {
        self.comment.trim().is_empty() && self.highlight.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryFilter {
    pub tool: ToolFilter,
    pub tools: Option<ToolSelection>,
    pub in_scope_only: bool,
    pub hide_without_responses: bool,
    pub parameterized_only: bool,
    pub mime: MimeFilter,
    pub status: StatusFilter,
    pub search: String,
    pub regex: bool,
    pub case_sensitive: bool,
    pub negative_search: bool,
    pub show_only_extensions: bool,
    pub only_extensions: String,
    pub hide_extensions: bool,
    #[serde(deserialize_with = "deserialize_hidden_extensions")]
    pub hidden_extensions: String,
    /// Only exchanges with a comment or highlight.
    pub annotated_only: bool,
}

impl Default for HistoryFilter {
    fn default() -> Self {
        Self {
            tool: ToolFilter::All,
            tools: None,
            in_scope_only: false,
            hide_without_responses: false,
            parameterized_only: false,
            mime: MimeFilter::default(),
            status: StatusFilter::default(),
            search: String::new(),
            regex: false,
            case_sensitive: false,
            negative_search: false,
            show_only_extensions: false,
            only_extensions: "asp,aspx,jsp,php".into(),
            hide_extensions: false,
            hidden_extensions: DEFAULT_HIDDEN_EXTENSIONS.into(),
            annotated_only: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolFilter {
    #[default]
    All,
    Proxy,
    Repeater,
    Intruder,
    Scanner,
}

impl ToolFilter {
    pub const ALL: [Self; 5] = [
        Self::All,
        Self::Proxy,
        Self::Repeater,
        Self::Intruder,
        Self::Scanner,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Proxy => "Proxy",
            Self::Repeater => "Repeater",
            Self::Intruder => "Intruder",
            Self::Scanner => "Scanner",
        }
    }
    fn matches(self, tool: &str) -> bool {
        match self {
            Self::All => true,
            Self::Proxy => tool == "Proxy",
            Self::Repeater => tool == "Repeater",
            Self::Intruder => tool == "Intruder" || tool.starts_with("Intruder #"),
            Self::Scanner => tool == "Scanner",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolSelection {
    pub proxy: bool,
    pub repeater: bool,
    pub intruder: bool,
    pub scanner: bool,
}
impl Default for ToolSelection {
    fn default() -> Self {
        Self {
            proxy: true,
            repeater: true,
            intruder: true,
            scanner: true,
        }
    }
}
impl ToolSelection {
    pub fn from_legacy(tool: ToolFilter) -> Self {
        Self {
            proxy: tool == ToolFilter::All || tool == ToolFilter::Proxy,
            repeater: tool == ToolFilter::All || tool == ToolFilter::Repeater,
            intruder: tool == ToolFilter::All || tool == ToolFilter::Intruder,
            scanner: tool == ToolFilter::All || tool == ToolFilter::Scanner,
        }
    }
    fn matches(&self, tool: &str) -> bool {
        (self.proxy && ToolFilter::Proxy.matches(tool))
            || (self.repeater && ToolFilter::Repeater.matches(tool))
            || (self.intruder && ToolFilter::Intruder.matches(tool))
            || (self.scanner && ToolFilter::Scanner.matches(tool))
            || (self.proxy
                && self.repeater
                && self.intruder
                && self.scanner
                && ![
                    ToolFilter::Proxy,
                    ToolFilter::Repeater,
                    ToolFilter::Intruder,
                    ToolFilter::Scanner,
                ]
                .iter()
                .any(|kind| kind.matches(tool)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MimeFilter {
    pub html: bool,
    pub script: bool,
    pub xml: bool,
    pub css: bool,
    pub other_text: bool,
    pub images: bool,
    pub json: bool,
    pub other_binary: bool,
}
impl Default for MimeFilter {
    fn default() -> Self {
        Self {
            html: true,
            script: true,
            xml: true,
            css: true,
            other_text: true,
            images: false,
            json: true,
            other_binary: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusFilter {
    pub success: bool,
    pub redirection: bool,
    pub request_error: bool,
    pub server_error: bool,
}
impl Default for StatusFilter {
    fn default() -> Self {
        Self {
            success: true,
            redirection: true,
            request_error: true,
            server_error: true,
        }
    }
}

pub struct CompiledFilter<'a> {
    filter: &'a HistoryFilter,
    search: Option<regex::bytes::Regex>,
    only_extensions: Vec<String>,
    hidden_extensions: Vec<String>,
}

impl HistoryFilter {
    pub fn compile(&self) -> anyhow::Result<CompiledFilter<'_>> {
        let search = if self.search.is_empty() {
            None
        } else {
            let pattern = if self.regex {
                self.search.clone()
            } else {
                regex::escape(&self.search)
            };
            Some(
                regex::bytes::RegexBuilder::new(&pattern)
                    .case_insensitive(!self.case_sensitive)
                    .build()?,
            )
        };
        let extensions = |list: &str| {
            list.split(|c: char| c == ',' || c.is_whitespace())
                .map(|ext| ext.trim_start_matches(['*', '.']).to_ascii_lowercase())
                .filter(|ext| !ext.is_empty())
                .collect()
        };
        Ok(CompiledFilter {
            filter: self,
            search,
            only_extensions: extensions(&self.only_extensions),
            hidden_extensions: extensions(&self.hidden_extensions),
        })
    }
}

impl CompiledFilter<'_> {
    /// Whether an exchange passes the filter. Searches also match the
    /// exchange's comment.
    pub fn matches(&self, flow: &Exchange, scope: &Scope, annotation: Option<&Annotation>) -> bool {
        let f = self.filter;
        if f.annotated_only && annotation.is_none_or(Annotation::is_empty) {
            return false;
        }
        if !f.tools.as_ref().map_or_else(
            || f.tool.matches(&flow.tool),
            |tools| tools.matches(&flow.tool),
        ) || (f.in_scope_only && !scope.contains(&flow.url))
            || (f.hide_without_responses && flow.response.is_empty())
            || (f.parameterized_only && !has_parameters(flow))
        {
            return false;
        }
        let status = match flow.status / 100 {
            2 => f.status.success,
            3 => f.status.redirection,
            4 => f.status.request_error,
            5 => f.status.server_error,
            _ => true, // Missing responses remain visible unless explicitly hidden.
        };
        if !status
            || (flow.status != 101
                && !flow.response.is_empty()
                && !mime_matches(&f.mime, &content_type(&flow.response))
                && !has_upgrade_header(&flow.request))
        {
            return false;
        }
        if f.show_only_extensions || f.hide_extensions {
            let extension = url::Url::parse(&flow.url).ok().and_then(|url| {
                url.path()
                    .rsplit('/')
                    .next()?
                    .rsplit_once('.')
                    .map(|(_, ext)| ext.to_ascii_lowercase())
            });
            if f.show_only_extensions
                && !extension
                    .as_ref()
                    .is_some_and(|ext| self.only_extensions.contains(ext))
            {
                return false;
            }
            if f.hide_extensions
                && extension
                    .as_ref()
                    .is_some_and(|ext| self.hidden_extensions.contains(ext))
            {
                return false;
            }
        }
        if let Some(search) = &self.search {
            let found = [
                flow.url.as_bytes(),
                flow.tool.as_bytes(),
                &flow.request,
                &flow.response,
                annotation.map_or(&[][..], |a| a.comment.as_bytes()),
            ]
            .iter()
            .any(|bytes| search.is_match(bytes));
            if found == f.negative_search {
                return false;
            }
        }
        true
    }
}

fn content_type(bytes: &[u8]) -> String {
    let end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .ok()
        .and_then(|head| {
            head.split("\r\n")
                .skip(1)
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| {
                    value
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase()
                })
        })
        .unwrap_or_default()
}

/// Return the response MIME subtype (for example, `json`), or empty if unknown.
pub fn short_content_type(response: &[u8]) -> String {
    content_type(response)
        .split_once('/')
        .filter(|(kind, subtype)| !kind.is_empty() && !subtype.is_empty())
        .map(|(_, subtype)| subtype.to_owned())
        .unwrap_or_default()
}

fn has_upgrade_header(bytes: &[u8]) -> bool {
    let end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).is_ok_and(|head| {
        head.split("\r\n")
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .any(|(name, value)| name.eq_ignore_ascii_case("Upgrade") && !value.trim().is_empty())
    })
}

fn mime_matches(filter: &MimeFilter, mime: &str) -> bool {
    match mime {
        "text/html" | "application/xhtml+xml" => filter.html,
        "text/javascript"
        | "application/javascript"
        | "application/x-javascript"
        | "text/ecmascript"
        | "application/ecmascript" => filter.script,
        "application/xml" | "text/xml" => filter.xml,
        "text/css" => filter.css,
        mime if mime == "application/json" || mime == "text/json" || mime.ends_with("+json") => {
            filter.json
        }
        mime if mime.starts_with("image/") => filter.images,
        mime if mime.ends_with("+xml") => filter.xml,
        mime if mime.starts_with("text/") || mime == "application/x-www-form-urlencoded" => {
            filter.other_text
        }
        _ => filter.other_binary,
    }
}

fn has_parameters(flow: &Exchange) -> bool {
    if url::Url::parse(&flow.url).is_ok_and(|url| url.query_pairs().any(|(key, _)| !key.is_empty()))
    {
        return true;
    }
    let Some(end) = flow.request.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let body = &flow.request[end + 4..];
    let mime = content_type(&flow.request);
    match mime.as_str() {
        "application/x-www-form-urlencoded" => {
            url::form_urlencoded::parse(body).any(|(key, _)| !key.is_empty())
        }
        "multipart/form-data" => body.split(|byte| *byte == b'\n').any(|line| {
            std::str::from_utf8(line).is_ok_and(|line| {
                let line = line.to_ascii_lowercase();
                line.starts_with("content-disposition:")
                    && line.contains("form-data")
                    && line.contains("name=")
            })
        }),
        mime if mime == "application/json" || mime.ends_with("+json") => {
            serde_json::from_slice::<serde_json::Value>(body)
                .is_ok_and(|value| value.as_object().is_some_and(|object| !object.is_empty()))
        }
        _ => false,
    }
}

//! Specialized checks use repeated controls and retain their complete evidence.
//! Raw and cache-changing probes are always opt-in.
use super::*;

#[derive(Clone, Debug)]
pub(super) enum Matcher {
    Error {
        pattern: String,
    },
    Cors {
        origin: String,
    },
    GraphqlSuggestions,
    GraphqlContentType,
    GraphqlBatching,
    GraphqlInterface,
    GraphqlAliasOverload,
    Series {
        family: String,
        phase: usize,
        pair: usize,
        marker: String,
    },
}
impl Matcher {
    pub(super) fn serial(&self) -> bool {
        matches!(self, Self::Series { family, .. }
            if matches!(family.as_str(), "cache-poison" | "cache-deception" | "cl-te" | "te-cl" | "put"))
    }

    /// Only repeated metadata probes need their exchanges retained for series
    /// evaluation. Single-response checks are decided immediately.
    pub(super) fn series_result(&self) -> bool {
        matches!(self, Self::Series { .. })
    }
}

pub(super) fn definitions() -> Vec<IssueDefinition> {
    use Severity::*;
    [
        ("csp-style", "CSP permits unsafe style execution", Information,true,false,false,"An enforced style policy permits unrestricted inline CSS or broad style sources.","Use nonces or hashes for inline styles and restrict style sources."),
        ("csp-script-sources", "CSP permits broad script sources", Information,true,false,false,"A script policy trusts arbitrary network sources without a nonce-based strict-dynamic policy.","Restrict script sources and use unpredictable nonces or content hashes."),
        ("csp-form", "CSP does not restrict form destinations", Information,true,false,false,"A page with forms has a content security policy that does not constrain form submissions.","Set an explicit form-action policy appropriate to the application."),
        ("csp-report-only", "Content security policy is report-only", Information,true,false,false,"The response supplies a reporting policy without an enforced CSP header.","Deploy an enforced policy after reviewing violation reports."),
        ("csp-not-enforced", "Content security policy not enforced", Information,true,false,false,"An HTML response has no enforced Content-Security-Policy header.","Deploy an appropriate enforced policy and review its directives."),
        ("csp-malformed", "Malformed content security policy", Information,true,false,false,"A CSP directive contains invalid syntax or an unterminated source expression.","Correct the policy syntax and validate its browser interpretation."),
        ("csp-script-library", "CSP trusts a script-hosting service", Information,true,false,false,"An enforced script allowlist includes a service that hosts user-selectable libraries or content.","Prefer nonces/hashes and review each trusted script host."),
        ("flash-policy", "Permissive Flash cross-domain policy", High,true,false,false,"A captured Flash cross-domain policy grants access to arbitrary domains.","Remove obsolete policies or allow only specific trusted origins."),
        ("silverlight-policy", "Permissive Silverlight cross-domain policy", High,true,false,false,"A captured Silverlight policy grants access to arbitrary domains.","Remove obsolete policies or allow only specific trusted origins."),
        ("database-connection", "Database connection string disclosed", Medium,true,false,false,"The response contains a database connection URI with embedded nonempty credentials.","Remove connection credentials from responses and rotate exposed secrets."),
        ("ssn-disclosure", "Possible social security number disclosed", Information,true,false,false,"A response labels a syntactically plausible US social security number.","Review whether the data is real and restrict or redact sensitive identifiers."),
        ("base64-parameter", "Base64-encoded structured input", Information,true,false,false,"A request parameter contains decodable JSON or XML wrapped in Base64.","Treat encoded data as untrusted; encoding provides no integrity protection."),
        ("graphql-endpoint", "GraphQL endpoint found", Information,true,false,false,"Captured request and response structures identify a GraphQL operation.","Apply authorization, query limits, and appropriate error handling to GraphQL."),
        ("unencrypted-http", "Unencrypted HTTP communication", Low,true,false,false,"The captured HTTP exchange uses plaintext transport.","Use HTTPS when integrity or confidentiality is required."),
        ("cors-wildcard", "CORS allows arbitrary noncredentialed origins", Information,true,false,false,"The response permits cross-origin reads from any origin without browser credentials.","Confirm that the response is intended to be public."),
        ("html-comment-secret", "Sensitive-looking data in HTML comment", Low,true,false,false,"An HTML comment contains an explicitly labeled password or secret.","Remove secrets from delivered source and rotate exposed credentials."),
        ("graphql-suggestions", "GraphQL field suggestions enabled", Low,false,true,false,"An invalid field query returns schema field suggestions.","Disable unnecessary field suggestions on production endpoints."),
        ("graphql-content-type", "GraphQL accepts simple cross-site content type", Low,false,true,false,"The endpoint executes a GraphQL operation submitted as text/plain.","Enforce the intended JSON media type and implement CSRF defenses."),
        ("graphql-batching", "GraphQL query batching enabled", Low,false,true,false,"The endpoint accepts an array of operations in one request.","Disable batching unless required, and enforce per-request operation and cost limits."),
        ("graphql-interface", "GraphQL IDE interface exposed", Medium,false,true,false,"A GraphQL development interface is reachable and returns an interactive HTML application.","Disable development interfaces in production or restrict them to trusted operators."),
        ("graphql-alias-overload", "GraphQL alias overloading accepted", Low,false,true,false,"A single operation accepts many aliases of the same field without an apparent complexity limit.","Apply query cost or alias limits and reject operations that exceed them."),
        ("ldap-injection", "Possible LDAP injection", High,false,true,false,"A delimiter probe introduces an LDAP filter parser diagnostic absent from the baseline.","Use safe LDAP filter construction and context-specific escaping."),
        ("xpath-injection", "Possible XPath injection", High,false,true,false,"A delimiter probe introduces an XPath parser diagnostic absent from the baseline.","Use parameterized XPath expressions or strict context-specific escaping."),
        ("xml-injection", "Possible XML injection", Medium,false,true,false,"An input delimiter introduces an XML parser diagnostic absent from the baseline.","Build XML with a structured serializer and validate user-controlled values."),
        ("cors-null", "Credentialed CORS trusts the null origin", Medium,false,true,false,"An authenticated response authorizes the null origin and remains readable with credentials.","Do not trust the null origin for credentialed resources."),
        ("cors-subdomain", "Credentialed CORS trusts arbitrary subdomains", Low,false,true,false,"An authenticated response authorizes an attacker-controlled subdomain of the target domain.","Do not derive allowed CORS origins from a suffix or wildcard domain."),
        ("cors-insecure-origin", "Credentialed CORS trusts an insecure origin", Low,false,true,false,"An HTTPS resource authorizes an HTTP origin with credentials.","Only allow required authenticated HTTPS origins."),
        ("referer-dependent", "Referer-dependent response", Information,false,true,false,"Repeated requests change consistently when only Referer is changed.","Do not use Referer as the sole authentication or authorization control."),
        ("user-agent-dependent", "User-Agent-dependent response", Information,false,true,false,"Repeated requests change consistently when only User-Agent is changed.","Review whether client-dependent behavior exposes additional functionality."),
        ("spoofable-ip", "Spoofable client IP trust", Medium,false,true,false,"A denied resource becomes accessible only when a client IP forwarding header is supplied.","Trust forwarding headers only from explicitly trusted reverse proxies."),
        ("request-url-override", "Request URL override header accepted", Low,false,true,false,"A URL override header makes an otherwise nonexistent path return the selected resource.","Strip untrusted URL override headers at the trusted edge."),
        ("cache-poisoning", "Web cache poisoning", High,false,true,true,"A unique forwarded-host marker persists into a clean request served from cache.","Include relevant inputs in cache keys and remove untrusted routing metadata."),
        ("cache-deception", "Web cache deception", Medium,false,true,true,"An authenticated response is cached under a static-looking path and retrieved without credentials.","Align cache rules with application routing and prevent caching of personalized responses."),
        ("request-smuggling", "Possible HTTP request smuggling", High,false,true,true,"Repeated ambiguous-framing requests time out while matched unambiguous controls complete.","Reject ambiguous framing consistently at every intermediary and origin."),
        ("put-write", "HTTP PUT permits file creation", High,false,true,true,"A unique benign file written with PUT is retrievable by a separate GET request.","Disable unauthenticated write methods or enforce appropriate authorization."),
    ].into_iter().map(|(id,name,severity,passive,active,intrusive,description,remediation)|IssueDefinition{id:id.into(),name:name.into(),severity,passive,active,intrusive,description:description.into(),remediation:remediation.into(),references:vec![]}).collect()
}

fn sources(policy: &str, directive: &str) -> Option<Vec<String>> {
    policy.split(';').find_map(|part| {
        let mut words = part.split_whitespace();
        (words.next()?.eq_ignore_ascii_case(directive))
            .then(|| words.map(|s| s.to_ascii_lowercase()).collect())
    })
}
fn broad(values: &[String]) -> bool {
    values
        .iter()
        .any(|s| matches!(s.as_str(), "*" | "http:" | "https:" | "data:"))
}
fn strict_script(values: &[String]) -> bool {
    values.iter().any(|s| s == "'strict-dynamic'")
        && values
            .iter()
            .any(|s| s.starts_with("'nonce-") || s.starts_with("'sha"))
}

/// Passive checks on the parsed response and shared finding budget.
pub(super) fn passive_parsed(
    flow: &Exchange,
    request: &Message,
    response: &Message,
    body: &str,
    policies: Option<&[String]>,
    json: Option<&serde_json::Value>,
    findings: &mut super::PassiveFindings<'_>,
) {
    let mut add = |id: &str, confidence: Confidence, point: &str, detail: &str| {
        findings.add(id, confidence, point, detail);
    };
    if !flow.destination.tls {
        add(
            "unencrypted-http",
            Confidence::Certain,
            "transport",
            "The selected service uses plaintext HTTP.",
        );
    }
    if response.header("Access-Control-Allow-Origin") == Some("*") {
        add(
            "cors-wildcard",
            Confidence::Certain,
            "Access-Control-Allow-Origin",
            "Wildcard CORS grants noncredentialed cross-origin access; verify intended public exposure.",
        );
    }
    if let Some(policies) = policies {
        if policies.is_empty() {
            if response
                .header("Content-Security-Policy-Report-Only")
                .is_some()
            {
                add(
                    "csp-report-only",
                    Confidence::Certain,
                    "Content-Security-Policy-Report-Only",
                    "A report-only policy is present without an enforced policy header.",
                );
            } else {
                add(
                    "csp-not-enforced",
                    Confidence::Certain,
                    "Content-Security-Policy",
                    "No enforced Content-Security-Policy header is present on an HTML response.",
                );
            }
        }
        if !policies.is_empty() {
            let scripts: Vec<_> = policies
                .iter()
                .filter_map(|p| {
                    sources(p, "script-src-elem")
                        .or_else(|| sources(p, "script-src"))
                        .or_else(|| sources(p, "default-src"))
                })
                .collect();
            if !scripts.is_empty() && scripts.iter().all(|s| broad(s) && !strict_script(s)) {
                add(
                    "csp-script-sources",
                    Confidence::Firm,
                    "Content-Security-Policy",
                    "Every applicable script policy permits broad script sources without nonce/hash strict-dynamic.",
                );
            }
            let style_capabilities = |policy: &str| {
                let elem = sources(policy, "style-src-elem")
                    .or_else(|| sources(policy, "style-src"))
                    .or_else(|| sources(policy, "default-src"));
                let attr = sources(policy, "style-src-attr")
                    .or_else(|| sources(policy, "style-src"))
                    .or_else(|| sources(policy, "default-src"));
                let inline = |values: &[String]| {
                    values.iter().any(|v| v == "'unsafe-inline'")
                        && !values.iter().any(|v| {
                            v.starts_with("'nonce-")
                                || v.starts_with("'sha256-")
                                || v.starts_with("'sha384-")
                                || v.starts_with("'sha512-")
                        })
                };
                [
                    elem.as_deref().is_none_or(inline),
                    attr.as_deref().is_none_or(inline),
                    elem.as_deref().is_none_or(broad),
                ]
            };
            let mut shared_style = [true; 3];
            for policy in policies {
                for (shared, allowed) in shared_style.iter_mut().zip(style_capabilities(policy)) {
                    *shared &= allowed;
                }
                if !shared_style.contains(&true) {
                    break;
                }
            }
            if shared_style.contains(&true) {
                add(
                    "csp-style",
                    Confidence::Tentative,
                    "Content-Security-Policy",
                    "Every applicable style policy permits inline styles or arbitrary network styles.",
                );
            }
            if re(r"(?i)<form\b", body)
                && policies
                    .iter()
                    .all(|p| sources(p, "form-action").is_none_or(|s| broad(&s)))
            {
                add(
                    "csp-form",
                    Confidence::Firm,
                    "Content-Security-Policy",
                    "Forms are present, but no policy restricts form submissions to trusted destinations.",
                );
            }
            if !scripts.is_empty()
                && scripts.iter().all(|s| {
                    !strict_script(s)
                        && s.iter().any(|v| {
                            [
                                "cdnjs.cloudflare.com",
                                "unpkg.com",
                                "cdn.jsdelivr.net",
                                "ajax.googleapis.com",
                                "code.jquery.com",
                                "cdn.skypack.dev",
                                "esm.sh",
                                "cdn.staticfile.org",
                                "cdn.bootcdn.net",
                            ]
                            .iter()
                            .any(|host| {
                                let source = if v.contains("://") {
                                    v.clone()
                                } else {
                                    format!("https://{v}")
                                };
                                url::Url::parse(&source).ok().is_some_and(|url| {
                                    url.host_str().is_some_and(|value| {
                                        value == *host || value.ends_with(&format!(".{host}"))
                                    })
                                })
                            })
                        })
                })
            {
                add(
                    "csp-script-library",
                    Confidence::Tentative,
                    "Content-Security-Policy",
                    "The script allowlist includes a general-purpose script/library hosting service; review exploitable endpoints.",
                );
            }
            if policies.iter().any(|p| {
                p.matches('\'').count() % 2 == 1
                    || p.split(';').any(|part| {
                        part.split_whitespace().next().is_some_and(|name| {
                            !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        })
                    })
            }) {
                add(
                    "csp-malformed",
                    Confidence::Firm,
                    "Content-Security-Policy",
                    "A directive name is malformed or a quoted source expression is unterminated.",
                );
            }
        }
        let secret_comment = {
            static COMMENTS: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"(?s)<!--(.*?)-->").unwrap());
            COMMENTS.captures_iter(body).any(|c| {
                re(
                    r#"(?i)\b(?:password|secret|api[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9/+_=-]{8,}"#,
                    &c[1].chars().take(1024).collect::<String>(),
                )
            })
        };
        if secret_comment {
            add(
                "html-comment-secret",
                Confidence::Tentative,
                "HTML comment",
                "A delivered HTML comment includes a secret-like assignment. Verify whether the value is sensitive.",
            );
        }
    }
    if re(
        r#"(?is)<cross-domain-policy\b.*<allow-access-from\b[^>]*\bdomain\s*=\s*["']\*["']"#,
        body,
    ) {
        add(
            "flash-policy",
            Confidence::Certain,
            "cross-domain-policy",
            "The captured policy grants allow-access-from to domain=*. This is a policy observation, not evidence of a working Flash client.",
        );
    }
    if re(
        r#"(?is)<access-policy\b.*<grant-to\b.*<domain\b[^>]*\buri\s*=\s*["']\*["']"#,
        body,
    ) {
        add(
            "silverlight-policy",
            Confidence::Certain,
            "access-policy",
            "The captured Silverlight policy grants access to an unrestricted domain.",
        );
    }
    if re(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^\s:/<>]+:[^\s@<>]+@[^\s<>]+",
        body,
    ) {
        add(
            "database-connection",
            Confidence::Firm,
            "response body",
            "A database connection URI contains a username and nonempty password.",
        );
    }
    if re(
        r"(?i)\b(?:SSN|social security number)\s*[:=#-]?\s*(?:00[1-9]|0[1-9][0-9]|[1-5][0-9]{2}|6[0-57-9][0-9]|[78][0-9]{2})-(?:0[1-9]|[1-9][0-9])-(?:[0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]|[0-9][1-9][0-9]{2}|[1-9][0-9]{3})\b",
        body,
    ) {
        add(
            "ssn-disclosure",
            Confidence::Tentative,
            "response body",
            "A labeled value has a plausible SSN structure; confirm whether it is real personal information.",
        );
    }
    if url::Url::parse(&flow.url).ok().is_some_and(|u| {
        u.query_pairs().any(|(_, value)| {
            [
                STANDARD.decode(value.as_bytes()),
                URL_SAFE_NO_PAD.decode(value.as_bytes()),
            ]
            .into_iter()
            .flatten()
            .any(|v| {
                std::str::from_utf8(&v).is_ok_and(|s| {
                    serde_json::from_str::<serde_json::Value>(s).is_ok()
                        || s.trim_start().starts_with('<')
                })
            })
        })
    }) {
        add(
            "base64-parameter",
            Confidence::Certain,
            "request parameters",
            "A query value decodes from Base64 to JSON or XML.",
        );
    }
    let graphql_request = serde_json::from_slice::<serde_json::Value>(&request.body)
        .ok()
        .is_some_and(|v| v["query"].is_string())
        || url::Url::parse(&flow.url)
            .ok()
            .is_some_and(|u| u.query_pairs().any(|(k, v)| k == "query" && !v.is_empty()));
    if graphql_request && json.is_some_and(|v| v.get("data").is_some() || v.get("errors").is_some())
    {
        add(
            "graphql-endpoint",
            Confidence::Certain,
            "GraphQL operation",
            "The request contains a GraphQL query and the response uses its data/errors envelope.",
        );
    }
}

// One admission point applies the byte and count limits to every specialized probe.
#[allow(clippy::too_many_arguments)]
fn push(
    out: &mut Vec<Probe>,
    base: &Exchange,
    settings: &ScanSettings,
    id: &str,
    point: &str,
    request: Vec<u8>,
    raw: bool,
    matcher: Matcher,
) {
    if enabled(settings, id)
        && (matches!(&matcher, Matcher::Series { .. })
            || !out.iter().any(|p| p.issue_id == id && p.request == request))
        && out.len() < settings.max_probes_per_request
        && out
            .iter()
            .map(|p| p.request.len())
            .sum::<usize>()
            .saturating_add(request.len())
            <= 64 * 1024 * 1024
    {
        out.push(Probe {
            issue_id: id.into(),
            insertion_point: point.into(),
            request,
            destination: base.destination.clone(),
            raw,
            matcher: super::Matcher::Advanced(matcher),
        });
    }
}
fn header_probe(base: &Message, name: &str, value: &str) -> Vec<u8> {
    let mut m = base.clone();
    m.set(name, value.into());
    m.encode()
}
fn with_cache_key(base: &Message, dest: &Destination, key: &str) -> anyhow::Result<Message> {
    let mut m = base.clone();
    let target = origin_target(base, dest)?;
    let sep = if target.contains('?') { '&' } else { '?' };
    replace_target(&mut m, &format!("{target}{sep}__ferrite_audit={key}"));
    Ok(m)
}

pub(super) fn active_plan(base: &Exchange, settings: &ScanSettings) -> anyhow::Result<Vec<Probe>> {
    let request = Message::parse(&base.request)?;
    let token = marker(base);
    let mut out = vec![];
    for point in points(&request, &base.destination, settings)? {
        for (id, payload, pattern) in [
            (
                "ldap-injection",
                format!("{}')(ferrite=*)", point.original),
                r"(?i)(InvalidSearchFilterException|LDAP: error code 87|Bad search filter|LDAPException.{0,80}(?:filter|syntax)|BadFilterException)",
            ),
            (
                "xpath-injection",
                format!("{}'\"]ferrite[", point.original),
                r"(?i)(XPathException|XPathExpressionException|Invalid XPath|XPath evaluation|XPath syntax|javax\.xml\.xpath|xmlXPathEval:)",
            ),
            (
                "xml-injection",
                format!("{}<ferrite-{token}>&", point.original),
                r"(?i)(SAXParseException|XMLSyntaxError|XML parsing error|not well-formed \(invalid token\)|System\.Xml\.XmlException|Premature end of data in tag)",
            ),
        ] {
            push(
                &mut out,
                base,
                settings,
                id,
                &point.label,
                point_request(&request, &base.destination, &point, &payload)?,
                false,
                Matcher::Error {
                    pattern: pattern.into(),
                },
            );
        }
    }
    for (id, origin) in [
        ("cors-null", "null".into()),
        (
            "cors-insecure-origin",
            format!("http://{}", base.destination.authority()),
        ),
    ] {
        push(
            &mut out,
            base,
            settings,
            id,
            "Origin header",
            header_probe(&request, "Origin", &origin),
            false,
            Matcher::Cors { origin },
        );
    }
    if base.destination.host.parse::<std::net::IpAddr>().is_err() {
        let scheme = if base.destination.tls {
            "https"
        } else {
            "http"
        };
        let port = base.destination.port;
        let default_port = if base.destination.tls { 443 } else { 80 };
        let suffix = if port == default_port {
            String::new()
        } else {
            format!(":{port}")
        };
        let mut parents = vec![base.destination.host.clone()];
        if let Some((_, parent)) = base.destination.host.split_once('.')
            && parent.contains('.')
        {
            parents.push(parent.to_owned());
        }
        for parent in parents {
            let origin = format!("{scheme}://ferrite-{token}.{parent}{suffix}");
            push(
                &mut out,
                base,
                settings,
                "cors-subdomain",
                "Origin header",
                header_probe(&request, "Origin", &origin),
                false,
                Matcher::Cors { origin },
            );
        }
    }
    let graphql = serde_json::from_slice::<serde_json::Value>(&request.body)
        .ok()
        .is_some_and(|v| v["query"].is_string())
        || url::Url::parse(&base.url)
            .is_ok_and(|u| u.path().to_ascii_lowercase().contains("graphql"));
    if graphql {
        let graphql_post = |body: String, content_type: &str| -> anyhow::Result<Vec<u8>> {
            let mut message = request.clone();
            message.start = format!(
                "POST {} HTTP/1.1",
                origin_target(&request, &base.destination)?
            );
            message.set("Content-Type", content_type.into());
            message.body = body.into_bytes();
            message.normalize_length();
            Ok(message.encode())
        };
        for field in ["__typenam", "user", "users", "system", "node"] {
            let body = serde_json::json!({ "query": format!("query {{ {field} }}") }).to_string();
            push(
                &mut out,
                base,
                settings,
                "graphql-suggestions",
                "GraphQL query",
                graphql_post(body, "application/json")?,
                false,
                Matcher::GraphqlSuggestions,
            );
        }
        push(
            &mut out,
            base,
            settings,
            "graphql-content-type",
            "GraphQL query",
            graphql_post(r#"{"query":"query { __typename }"}"#.into(), "text/plain")?,
            false,
            Matcher::GraphqlContentType,
        );
        push(
            &mut out,
            base,
            settings,
            "graphql-batching",
            "GraphQL query",
            graphql_post(
                serde_json::json!([
                    { "query": "query { __typename }" },
                    { "query": "query { __typename }" }
                ])
                .to_string(),
                "application/json",
            )?,
            false,
            Matcher::GraphqlBatching,
        );
        let aliases = (0..20)
            .map(|index| format!("a{index}: __typename"))
            .collect::<Vec<_>>()
            .join(" ");
        push(
            &mut out,
            base,
            settings,
            "graphql-alias-overload",
            "GraphQL query",
            graphql_post(
                serde_json::json!({ "query": format!("query {{ {aliases} }}") }).to_string(),
                "application/json",
            )?,
            false,
            Matcher::GraphqlAliasOverload,
        );
        let parent = url::Url::parse(&base.url)
            .ok()
            .and_then(|url| {
                url.path()
                    .rsplit_once('/')
                    .map(|(parent, _)| parent.to_owned())
            })
            .unwrap_or_default();
        for path in [format!("{parent}/graphiql"), format!("{parent}/playground")] {
            let mut message = request.clone();
            message.start = format!("GET {path} HTTP/1.1");
            message.body.clear();
            message.remove("Content-Type");
            message.remove("Content-Length");
            message.set("Accept", "text/html".into());
            message.normalize_length();
            push(
                &mut out,
                base,
                settings,
                "graphql-interface",
                "GraphQL IDE path",
                message.encode(),
                false,
                Matcher::GraphqlInterface,
            );
        }
    }
    for (id, header, value) in [
        (
            "referer-dependent",
            "Referer",
            format!("https://{token}.invalid/"),
        ),
        (
            "user-agent-dependent",
            "User-Agent",
            format!("Ferrite-Audit/{token}"),
        ),
        ("spoofable-ip", "X-Forwarded-For", "127.0.0.1".into()),
        ("spoofable-ip", "X-Real-IP", "127.0.0.1".into()),
        ("spoofable-ip", "X-Client-IP", "127.0.0.1".into()),
        ("spoofable-ip", "True-Client-IP", "127.0.0.1".into()),
        ("spoofable-ip", "Forwarded", "for=127.0.0.1".into()),
    ] {
        let family = if id == "spoofable-ip" {
            format!("spoofable-ip-{header}")
        } else {
            id.into()
        };
        for pair in 0..2 {
            for phase in [0, 1] {
                let bytes = if phase == 0 {
                    request.encode()
                } else {
                    header_probe(&request, header, &value)
                };
                push(
                    &mut out,
                    base,
                    settings,
                    id,
                    header,
                    bytes,
                    false,
                    Matcher::Series {
                        family: family.clone(),
                        phase,
                        pair,
                        marker: token.clone(),
                    },
                );
            }
        }
    }
    if matches!(request.method(), "GET" | "HEAD") {
        let mut wrong = request.clone();
        let original = origin_target(&request, &base.destination)?;
        replace_target(&mut wrong, &format!("/ferrite-nonexistent-{token}"));
        for header in ["X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix"] {
            for phase in 0..2 {
                let mut m = wrong.clone();
                if phase == 1 {
                    m.set(header, original.clone());
                }
                push(
                    &mut out,
                    base,
                    settings,
                    "request-url-override",
                    header,
                    m.encode(),
                    false,
                    Matcher::Series {
                        family: format!("override-{header}"),
                        phase,
                        pair: 0,
                        marker: token.clone(),
                    },
                );
            }
        }
    }
    if settings.intrusive {
        if request.method() == "GET" {
            let poisoned = format!("poison-{token}.invalid");
            for phase in 0..3 {
                let mut m = with_cache_key(
                    &request,
                    &base.destination,
                    &format!("{token}-{}", usize::from(phase == 2)),
                )?;
                if phase == 0 {
                    m.set("X-Forwarded-Host", poisoned.clone());
                    m.set("Forwarded", format!("host={poisoned}"));
                    m.set("X-Host", poisoned.clone());
                    m.set("X-Forwarded-Server", poisoned.clone());
                }
                push(
                    &mut out,
                    base,
                    settings,
                    "cache-poisoning",
                    "cache key / forwarding headers",
                    m.encode(),
                    false,
                    Matcher::Series {
                        family: "cache-poison".into(),
                        phase,
                        pair: 0,
                        marker: poisoned.clone(),
                    },
                );
            }
            if request.header("Authorization").is_some() || request.header("Cookie").is_some() {
                for phase in 0..3 {
                    let mut m = request.clone();
                    let target = origin_target(&m, &base.destination)?;
                    let (path, query) = target
                        .split_once('?')
                        .map_or((target.as_str(), None), |(p, q)| (p, Some(q)));
                    replace_target(
                        &mut m,
                        &format!(
                            "{}/ferrite-{token}-{}.css{}",
                            path.trim_end_matches('/'),
                            usize::from(phase == 2),
                            query.map(|q| format!("?{q}")).unwrap_or_default()
                        ),
                    );
                    if phase > 0 {
                        m.remove("Authorization");
                        m.remove("Cookie");
                    }
                    push(
                        &mut out,
                        base,
                        settings,
                        "cache-deception",
                        "static-looking resource path",
                        m.encode(),
                        false,
                        Matcher::Series {
                            family: "cache-deception".into(),
                            phase,
                            pair: 0,
                            marker: token.clone(),
                        },
                    );
                }
            }
        }
        if request.header("Upgrade").is_none() {
            for family in ["cl-te", "te-cl"] {
                for pair in 0..3 {
                    for phase in [0, 1] {
                        let mut m = request.clone();
                        m.start = format!(
                            "{} {} HTTP/1.1",
                            request.method(),
                            origin_target(&request, &base.destination)?
                        );
                        m.remove("Content-Length");
                        m.remove("Transfer-Encoding");
                        m.set("Connection", "close".into());
                        if phase == 0 {
                            // The control must be unambiguous. CL.TE uses a
                            // valid chunked terminator with no Content-Length;
                            // TE.CL uses a valid fixed-length body with no
                            // Transfer-Encoding. The paired positive then adds
                            // the conflicting framing header.
                            if family == "cl-te" {
                                m.set("Transfer-Encoding", "chunked".into());
                                m.body = b"0\r\n\r\n".to_vec();
                            } else {
                                m.set("Content-Length", "6".into());
                                m.body = b"0\r\n\r\nX".to_vec();
                            }
                        } else if family == "te-cl" {
                            m.set("Transfer-Encoding", "chunked".into());
                            m.set("Content-Length", "6".into());
                            m.body = b"0\r\n\r\nX".to_vec();
                        } else {
                            m.set("Transfer-Encoding", "chunked".into());
                            m.set("Content-Length", "4".into());
                            m.body = b"1\r\nA\r\n0\r\n\r\n".to_vec();
                        }
                        push(
                            &mut out,
                            base,
                            settings,
                            "request-smuggling",
                            family,
                            m.encode(),
                            true,
                            Matcher::Series {
                                family: family.into(),
                                phase,
                                pair,
                                marker: token.clone(),
                            },
                        );
                    }
                }
            }
        }
        // PUT is a separate opt-in check and always uses a unique, benign resource.
        if settings.check_enabled("put-write") {
            let path = format!("/ferrite-audit-{token}.txt");
            let value = format!("Ferrite benign write verification {token}");
            for phase in 0..3 {
                let mut m = request.clone();
                m.start = format!("{} {path} HTTP/1.1", ["PUT", "GET", "DELETE"][phase]);
                m.body = if phase == 0 {
                    value.as_bytes().to_vec()
                } else {
                    vec![]
                };
                m.set("Content-Type", "text/plain".into());
                m.normalize_length();
                push(
                    &mut out,
                    base,
                    settings,
                    "put-write",
                    "HTTP method / unique resource",
                    m.encode(),
                    false,
                    Matcher::Series {
                        family: "put".into(),
                        phase,
                        pair: 0,
                        marker: value.clone(),
                    },
                );
            }
        }
    }
    Ok(out)
}

fn message(flow: &Exchange) -> Option<(Message, String)> {
    let m = Message::parse(&flow.response).ok()?;
    let b = text_body(&m, 4 * 1024 * 1024)?;
    Some((m, b))
}
fn content(flow: &Exchange) -> Option<Vec<u8>> {
    if flow.error.is_some() {
        return None;
    }
    let (m, b) = message(flow)?;
    ((200..300).contains(&m.status()) && !b.is_empty()).then(|| Sha256::digest(b).to_vec())
}
fn cached(flow: &Exchange) -> bool {
    Message::parse(&flow.response).ok().is_some_and(|m| {
        m.header("Age")
            .is_some_and(|s| s.parse::<u64>().is_ok_and(|n| n > 0))
            || ["X-Cache", "CF-Cache-Status", "Cache-Status"]
                .iter()
                .any(|h| {
                    m.header(h).is_some_and(|v| {
                        let l = v.to_ascii_lowercase();
                        l.contains("hit") && !l.contains("miss")
                    })
                })
    })
}
fn marker_in_response(flow: &Exchange, marker: &str) -> bool {
    message(flow).is_some_and(|(m, b)| {
        b.contains(marker) || m.header("Location").is_some_and(|v| v.contains(marker))
    })
}

pub(super) fn evaluate_cached(
    probe: &Probe,
    baseline: &CachedBaseline<'_>,
    response: &Exchange,
) -> Vec<Candidate> {
    let super::Matcher::Advanced(matcher) = &probe.matcher else {
        return vec![];
    };
    let Some((m, body)) = message(response) else {
        return vec![];
    };
    let old = baseline.body.as_str();
    if response.error.is_some() {
        return vec![];
    }
    let (matched, confidence) = match matcher {
        Matcher::Error { pattern } => (
            re(pattern, &body) && !re(pattern, old),
            Confidence::Tentative,
        ),
        Matcher::Cors { origin } => {
            let auth = Message::parse(&baseline.exchange.request)
                .is_ok_and(|r| r.header("Cookie").is_some() || r.header("Authorization").is_some());
            let same = baseline.message.as_ref().is_some_and(|b| {
                (200..300).contains(&b.status()) && !b.body.is_empty() && similar_content(b, &m)
            });
            (
                auth && baseline.exchange.destination.tls
                    && same
                    && m.header("Access-Control-Allow-Origin") == Some(origin)
                    && m.header("Access-Control-Allow-Credentials")
                        .is_some_and(|v| v.eq_ignore_ascii_case("true")),
                Confidence::Firm,
            )
        }
        Matcher::GraphqlSuggestions => (
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .is_some_and(|v| {
                    v["errors"].as_array().is_some_and(|errors| {
                        errors.iter().any(|error| {
                            error["message"].as_str().is_some_and(|message| {
                                message.to_ascii_lowercase().contains("did you mean")
                            })
                        })
                    })
                }),
            Confidence::Certain,
        ),
        Matcher::GraphqlBatching => (
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| value.as_array().map(Vec::len))
                .is_some_and(|length| length >= 2)
                && serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|value| value.as_array().cloned())
                    .is_some_and(|responses| {
                        responses.len() >= 2
                            && responses.iter().all(|response| {
                                response
                                    .pointer("/data/__typename")
                                    .is_some_and(|value| value.is_string())
                            })
                    }),
            Confidence::Certain,
        ),
        Matcher::GraphqlInterface => (
            m.status() == 200
                && m.header("Content-Type")
                    .is_some_and(|value| value.to_ascii_lowercase().contains("html"))
                && {
                    let body = body.to_ascii_lowercase();
                    body.contains("graphiql")
                        || body.contains("graphql playground")
                        || body.contains("altair")
                },
            Confidence::Firm,
        ),
        Matcher::GraphqlAliasOverload => (
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .is_some_and(|value| {
                    value["data"].as_object().is_some_and(|data| {
                        (0..20).all(|index| {
                            data.get(&format!("a{index}"))
                                .is_some_and(|value| value.is_string())
                        })
                    })
                }),
            Confidence::Certain,
        ),
        Matcher::GraphqlContentType => (
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .is_some_and(|v| v.pointer("/data/__typename").is_some_and(|v| v.is_string()))
                && m.status() == 200,
            Confidence::Tentative,
        ),
        Matcher::Series { .. } => (false, Confidence::Tentative),
    };
    if !matched {
        return vec![];
    }
    let mut c = candidate(
        &probe.issue_id,
        response,
        confidence,
        &probe.insertion_point,
        "The probe produced check-specific evidence absent from the baseline. Review the attached request and response.",
    );
    c.evidence.insert(
        0,
        Evidence {
            label: "Baseline".into(),
            exchange: baseline.exchange.clone(),
        },
    );
    vec![c]
}

type SeriesEntry<'a> = (&'a Probe, &'a Exchange, usize, usize, &'a str);

pub(super) fn evaluate_series(
    baseline: &Exchange,
    results: &[(Probe, Exchange)],
) -> Vec<Candidate> {
    let mut groups: std::collections::BTreeMap<(String, String), Vec<SeriesEntry<'_>>> =
        std::collections::BTreeMap::new();
    for (p, r) in results {
        if let super::Matcher::Advanced(Matcher::Series {
            family,
            phase,
            pair,
            marker,
        }) = &p.matcher
        {
            groups
                .entry((family.clone(), p.insertion_point.clone()))
                .or_default()
                .push((p, r, *phase, *pair, marker));
        }
    }
    let mut findings = vec![];
    for ((family, point), entries) in groups {
        let get = |phase: usize, pair: usize| {
            entries
                .iter()
                .find(|e| e.2 == phase && e.3 == pair)
                .copied()
        };
        let marker = entries[0].4;
        let (detected, confidence, detail) = if matches!(family.as_str(), "cl-te" | "te-cl") {
            let valid = (0..3).all(|pair| {
                get(0, pair).zip(get(1, pair)).is_some_and(|(a, b)| {
                    a.1.error.is_none()
                        && a.1.status == baseline.status
                        && !a.1.response.is_empty()
                        && b.1.response.is_empty()
                        && b.1
                            .error
                            .as_deref()
                            .is_some_and(|s| s.contains("timed out"))
                        && b.1.duration_ms >= a.1.duration_ms.saturating_add(1500)
                })
            });
            (
                valid,
                Confidence::Firm,
                "Three ambiguous-framing probes timed out before any response, while each matched unambiguous framing control completed. This is a repeatable desynchronization signal; verify the intermediary/origin interpretation.",
            )
        } else if family == "cache-poison" {
            let valid =
                get(0, 0)
                    .zip(get(1, 0))
                    .zip(get(2, 0))
                    .is_some_and(|((seed, clean), fresh)| {
                        [seed.1, clean.1, fresh.1].iter().all(|f| f.error.is_none())
                            && marker_in_response(seed.1, marker)
                            && marker_in_response(clean.1, marker)
                            && !marker_in_response(fresh.1, marker)
                            && cached(clean.1)
                            && !marker_in_response(baseline, marker)
                    });
            (
                valid,
                Confidence::Firm,
                "An attacker-controlled forwarding-host marker was retained in a subsequent clean cache hit, while an independent clean key did not contain it.",
            )
        } else if family == "cache-deception" {
            let valid = get(0, 0).zip(get(1, 0)).zip(get(2, 0)).is_some_and(
                |((seed, anonymous), fresh)| {
                    content(seed.1).is_some()
                        && content(seed.1) == content(baseline)
                        && content(seed.1) == content(anonymous.1)
                        && cached(anonymous.1)
                        && matches!(fresh.1.status, 401 | 403)
                        && [seed.1, anonymous.1, fresh.1]
                            .iter()
                            .all(|f| f.error.is_none())
                },
            );
            (
                valid,
                Confidence::Firm,
                "A static-looking cache path returned the selected authenticated content to a request without credentials. An independent anonymous cache key was denied.",
            )
        } else if family == "put" {
            let valid = get(0, 0).zip(get(1, 0)).is_some_and(|(put, read)| {
                put.1.error.is_none()
                    && matches!(put.1.status, 200 | 201 | 204)
                    && read.1.error.is_none()
                    && read.1.status == 200
                    && message(read.1).is_some_and(|(_, b)| b == marker)
            });
            let cleanup = get(2, 0).is_some_and(|entry| {
                entry.1.error.is_none() && matches!(entry.1.status, 200 | 202 | 204)
            });
            (
                valid,
                Confidence::Certain,
                if cleanup {
                    "A unique benign text resource was created using PUT and retrieved independently using GET. The DELETE cleanup request also completed successfully."
                } else {
                    "A unique benign text resource was created using PUT and retrieved independently using GET. The DELETE cleanup request did not complete successfully; review the evidence and remove the resource if it remains."
                },
            )
        } else if family.starts_with("override") {
            let valid = get(0, 0).zip(get(1, 0)).is_some_and(|(control, changed)| {
                control.1.error.is_none()
                    && matches!(control.1.status, 400 | 404)
                    && content(changed.1).is_some()
                    && content(changed.1) == content(baseline)
            });
            (
                valid,
                Confidence::Firm,
                "A nonexistent request path returned the selected baseline content only after X-Original-URL was added.",
            )
        } else {
            let pairs: Vec<_> = (0..2)
                .filter_map(|pair| get(0, pair).zip(get(1, pair)))
                .collect();
            let stable = pairs.len() == 2
                && pairs
                    .iter()
                    .all(|(a, b)| a.1.error.is_none() && b.1.error.is_none())
                && pairs[0].0.1.status == pairs[1].0.1.status
                && pairs[0].1.1.status == pairs[1].1.1.status
                && message(pairs[0].0.1).map(|(_, b)| b) == message(pairs[1].0.1).map(|(_, b)| b)
                && message(pairs[0].1.1).map(|(_, b)| b) == message(pairs[1].1.1).map(|(_, b)| b);
            let different = stable
                && (pairs[0].0.1.status != pairs[0].1.1.status
                    || message(pairs[0].0.1).map(|(_, b)| b)
                        != message(pairs[0].1.1).map(|(_, b)| b));
            let valid = if family.starts_with("spoofable-ip") {
                different
                    && matches!(pairs[0].0.1.status, 401 | 403)
                    && content(pairs[0].1.1).is_some()
            } else {
                different
            };
            (
                valid,
                if family.starts_with("spoofable-ip") {
                    Confidence::Firm
                } else {
                    Confidence::Certain
                },
                "Two repeated control/modified-header pairs produced stable, different responses. This describes observed header-dependent behavior; review the evidence before assigning a security impact.",
            )
        };
        if detected {
            let mut c = candidate(
                &entries[0].0.issue_id,
                entries[0].1,
                confidence,
                &point,
                detail,
            );
            c.evidence = vec![Evidence {
                label: "Selected baseline".into(),
                exchange: baseline.clone(),
            }];
            for (p, r, phase, pair, _) in entries {
                c.evidence.push(Evidence {
                    label: format!("{} phase {phase}, pair {pair}", p.issue_id),
                    exchange: r.clone(),
                });
            }
            findings.push(c);
        }
    }
    findings
}

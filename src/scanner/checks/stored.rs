//! Cross-request checks only replay readbacks explicitly selected by the user.
//! A complete control / mutation / readback sequence is required to report.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Xss,
    Redirect,
    Sql,
    Input,
    Transformation,
}

#[derive(Clone, Debug)]
pub(super) struct Matcher {
    group: String,
    phase: usize,
    kind: Kind,
    token: String,
    payload: String,
    seed_url: String,
    readback_url: String,
    readback_destination: Destination,
}

impl Matcher {
    pub(super) fn serial(&self) -> bool {
        true
    }
}

pub(super) fn definitions() -> Vec<IssueDefinition> {
    [
        (
            "stored-xss",
            "Stored cross-site scripting (HTTP evidence)",
            Severity::High,
            "A unique injected HTML event handler appears in an executable HTML context when a separately selected request is replayed. Browser execution is not performed.",
            "Apply context-specific output encoding to stored input, sanitize permitted HTML, and deploy a restrictive content security policy.",
        ),
        (
            "stored-redirect",
            "Stored external redirection",
            Severity::Medium,
            "After an input is submitted, a selected readback request starts redirecting to the unique injected destination. The destination is never contacted by this check.",
            "Validate stored redirect destinations against an explicit allowlist or store application-controlled route identifiers.",
        ),
        (
            "sql-second-order",
            "Possible second-order SQL injection",
            Severity::High,
            "A selected readback request starts returning a SQL parser diagnostic after a separate input submission. The finding is tentative because a parser diagnostic does not demonstrate exploitability.",
            "Use parameterized database queries when consuming stored data as well as when accepting the initial input.",
        ),
        (
            "input-stored",
            "Input returned in response (stored)",
            Severity::Information,
            "A unique submitted marker appears when an unchanged selected readback request is replayed.",
            "Review who can retrieve the stored input and apply context-appropriate encoding wherever it is returned.",
        ),
        (
            "input-transformed-stored",
            "Suspicious input transformation (stored)",
            Severity::Information,
            "Percent escapes, JavaScript escapes, or numeric character references in input are returned decoded in a subsequent readback.",
            "Apply validation after canonicalization and apply output encoding where the stored value is returned.",
        ),
    ]
    .into_iter()
    .map(|(id, name, severity, description, remediation)| IssueDefinition {
        id: id.into(),
        name: name.into(),
        severity,
        passive: false,
        active: true,
        intrusive: true,
        description: description.into(),
        remediation: remediation.into(),
        references: vec![],
    })
    .collect()
}

fn same_origin(left: &Destination, right: &Destination) -> bool {
    left.tls == right.tls && left.port == right.port && left.host.eq_ignore_ascii_case(&right.host)
}

fn nonce(base: &Exchange, point: &str, readback: &Exchange, id: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(marker(base));
    // The runner supplies a persisted scan/item identity in this planning copy.
    // Unlike randomness, this survives plan regeneration after an interruption.
    hash.update(base.note.as_bytes());
    hash.update(point.as_bytes());
    hash.update(&readback.request);
    hash.update(id.as_bytes());
    format!("{:x}", hash.finalize())[..24].into()
}

pub(super) fn plan(
    base: &Exchange,
    readbacks: &[Exchange],
    settings: &ScanSettings,
) -> anyhow::Result<Vec<Probe>> {
    settings.validate()?;
    let checks = [
        ("stored-xss", Kind::Xss),
        ("stored-redirect", Kind::Redirect),
        ("sql-second-order", Kind::Sql),
        ("input-stored", Kind::Input),
        ("input-transformed-stored", Kind::Transformation),
    ];
    if !settings.intrusive || !checks.iter().any(|(id, _)| enabled(settings, id)) {
        return Ok(vec![]);
    }
    let source = Message::parse(&base.request)?;
    let insertion_points = points(&source, &base.destination, settings)?;
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();
    for readback in readbacks {
        if !same_origin(&base.destination, &readback.destination) {
            continue;
        }
        let Ok(request) = Message::parse(&readback.request) else {
            continue;
        };
        if !matches!(request.method(), "GET" | "HEAD") || request.header("Upgrade").is_some() {
            continue;
        }
        let digest: [u8; 32] = Sha256::digest(&readback.request).into();
        if seen.insert(digest) {
            candidates.push((readback, request.method() == "GET"));
        }
    }
    let mut probes = Vec::new();
    let mut bytes = 0usize;
    'points: for point in insertion_points {
        for &(readback, readback_is_get) in &candidates {
            for (id, kind) in checks {
                if !enabled(settings, id) {
                    continue;
                }
                let token = format!("ferrite-stored-{}", nonce(base, &point.label, readback, id));
                let variants = match kind {
                    Kind::Input | Kind::Transformation => {
                        if !reflection::supports_point(&point)
                            || !matches!(source.method(), "POST" | "PUT" | "PATCH")
                            || !readback_is_get
                        {
                            continue;
                        }
                        if kind == Kind::Input {
                            vec![(token.clone(), token)]
                        } else {
                            reflection::transformed_payloads(&token).collect()
                        }
                    }
                    Kind::Xss => xss_payloads(&token),
                    Kind::Redirect => {
                        vec![(token.clone(), format!("https://{token}.invalid/ferrite"))]
                    }
                    Kind::Sql => vec![(token.clone(), format!("{}'\"`{token}", point.original))],
                };
                for (token, payload) in variants {
                    if probes.len().saturating_add(3) > settings.max_probes_per_request {
                        break 'points;
                    }
                    if readback
                        .request
                        .windows(token.len())
                        .any(|window| window == token.as_bytes())
                    {
                        continue;
                    }
                    let mutation = point_request(&source, &base.destination, &point, &payload)?;
                    let group_bytes = readback
                        .request
                        .len()
                        .saturating_mul(2)
                        .saturating_add(mutation.len());
                    if group_bytes > (64usize * 1024 * 1024).saturating_sub(bytes) {
                        break 'points;
                    }
                    bytes += group_bytes;
                    let group = format!("{id}:{token}");
                    for (phase, request) in
                        [readback.request.clone(), mutation, readback.request.clone()]
                            .into_iter()
                            .enumerate()
                    {
                        probes.push(Probe {
                            issue_id: id.into(),
                            insertion_point: point.label.clone(),
                            request,
                            destination: if phase == 1 {
                                base.destination.clone()
                            } else {
                                readback.destination.clone()
                            },
                            raw: false,
                            matcher: super::Matcher::Stored(Matcher {
                                group: group.clone(),
                                phase,
                                kind,
                                token: token.clone(),
                                payload: payload.clone(),
                                seed_url: base.url.clone(),
                                readback_url: readback.url.clone(),
                                readback_destination: readback.destination.clone(),
                            }),
                        });
                    }
                }
            }
        }
    }
    Ok(probes)
}

struct Observation<'a> {
    probe: &'a Probe,
    response: &'a Exchange,
    matcher: &'a Matcher,
}
#[derive(Default)]
struct Group<'a> {
    phases: [Option<Observation<'a>>; 3],
    duplicate: bool,
}

fn body(flow: &Exchange) -> Option<(Message, String)> {
    let message = Message::parse(&flow.response).ok()?;
    let body = text_body(&message, 4 * 1024 * 1024)?;
    Some((message, body))
}

fn marker_seen(flow: &Exchange, token: &str) -> bool {
    String::from_utf8_lossy(&flow.response).contains(token)
        || body(flow).is_some_and(|(_, body)| body.contains(token))
}

fn executable_markup(body: &str, markup: &str) -> bool {
    html_execution_context(body, markup)
}

fn redirected_to(flow: &Exchange, injected: &str) -> bool {
    if !(300..400).contains(&flow.status) {
        return false;
    }
    Message::parse(&flow.response).ok().is_some_and(|message| {
        message.header("Location").is_some_and(|location| {
            url::Url::parse(location)
                .ok()
                .zip(url::Url::parse(injected).ok())
                .is_some_and(|(actual, expected)| {
                    matches!(actual.scheme(), "http" | "https")
                        && actual.host_str() == expected.host_str()
                        && actual.path() == expected.path()
                        && actual.username().is_empty()
                        && actual.password().is_none()
                })
        })
    })
}

pub(super) fn evaluate_series(
    baseline: &Exchange,
    results: &[(Probe, Exchange)],
) -> Vec<Candidate> {
    let mut groups: BTreeMap<&str, Group<'_>> = BTreeMap::new();
    for (probe, response) in results {
        if let super::Matcher::Stored(matcher) = &probe.matcher {
            let group = groups.entry(&matcher.group).or_default();
            if let Some(phase) = group.phases.get_mut(matcher.phase) {
                if phase.is_some() {
                    group.duplicate = true;
                } else {
                    *phase = Some(Observation {
                        probe,
                        response,
                        matcher,
                    });
                }
            }
        }
    }
    let mut findings = Vec::new();
    for group in groups.into_values() {
        if group.duplicate {
            continue;
        }
        let [Some(control), Some(seed), Some(after)] = group.phases else {
            continue;
        };
        let marker = after.matcher;
        if [control.response, seed.response, after.response]
            .iter()
            .any(|response| response.error.is_some())
            || !(200..400).contains(&seed.response.status)
            || control.probe.request != after.probe.request
            || control.response.request != after.response.request
            || !same_origin(&after.response.destination, &marker.readback_destination)
            || !same_origin(&control.response.destination, &marker.readback_destination)
            || marker_seen(control.response, &marker.token)
            || marker_seen(baseline, &marker.token)
        {
            continue;
        }
        let confidence = match marker.kind {
            Kind::Input | Kind::Transformation => {
                let Some((before, response)) = reflection::response(control.response)
                    .zip(reflection::response(after.response))
                else {
                    continue;
                };
                if !reflection::same_request(
                    &after.probe.request,
                    &after.response.request,
                    &after.response.destination,
                ) || !reflection::same_request(
                    &seed.probe.request,
                    &seed.response.request,
                    &seed.response.destination,
                ) || seed.response.destination != seed.probe.destination
                    || control.response.url != after.response.url
                    || !(200..400).contains(&before.status())
                    || !(200..400).contains(&response.status())
                    || reflection::marker_location(&before, &marker.token).is_some()
                    || reflection::marker_location(&response, &marker.token).is_none()
                {
                    continue;
                }
                Confidence::Certain
            }
            Kind::Xss => {
                let Some((message, contents)) = body(after.response) else {
                    continue;
                };
                let markup = xss_markup(&marker.payload);
                if !xss_html_response(&message) || !executable_markup(&contents, markup) {
                    continue;
                }
                Confidence::Firm
            }
            Kind::Redirect => {
                if !redirected_to(after.response, &marker.payload)
                    || redirected_to(control.response, &marker.payload)
                {
                    continue;
                }
                Confidence::Firm
            }
            Kind::Sql => {
                let Some((_, old)) = body(control.response) else {
                    continue;
                };
                let Some((_, changed)) = body(after.response) else {
                    continue;
                };
                let source_error = body(baseline).is_some_and(|(_, body)| sql_error(&body));
                let seed_error = body(seed.response).is_some_and(|(_, body)| sql_error(&body));
                if !sql_error(&changed) || sql_error(&old) || source_error || seed_error {
                    continue;
                }
                Confidence::Tentative
            }
        };
        let mut finding = candidate(
            &after.probe.issue_id,
            after.response,
            confidence,
            &after.probe.insertion_point,
            format!(
                "A complete selected-request control → input submission → readback sequence changed {} after input at {} was submitted through {}. {}",
                marker.readback_url,
                after.probe.insertion_point,
                marker.seed_url,
                match marker.kind {
                    Kind::Xss =>
                        "The unique HTML event-handler payload was absent before submission and present in an executable HTML context on readback. Browser execution and CSP bypass are not confirmed.",
                    Kind::Redirect =>
                        "The original readback request redirected to the unique injected .invalid destination after submission; the destination was not contacted.",
                    Kind::Sql =>
                        "The readback introduced a SQL parser diagnostic absent from its control and from both seed responses. This temporal differential needs manual verification and does not establish exploitable SQL injection.",
                    Kind::Input =>
                        "The unique marker appeared in the readback response and was absent from its control. Review who can retrieve this value and how it is used.",
                    Kind::Transformation =>
                        "The encoded probe marker appeared decoded in the readback response and was absent from its control.",
                },
            ),
        );
        finding.affected = Some((after.response.url.clone(), after.response.method.clone()));
        finding.evidence = vec![
            Evidence {
                label: "Selected seed baseline".into(),
                exchange: baseline.clone(),
            },
            Evidence {
                label: "Readback before input submission".into(),
                exchange: control.response.clone(),
            },
            Evidence {
                label: "Input submission".into(),
                exchange: seed.response.clone(),
            },
            Evidence {
                label: "Readback after input submission".into(),
                exchange: after.response.clone(),
            },
        ];
        findings.push(finding);
    }
    findings
}

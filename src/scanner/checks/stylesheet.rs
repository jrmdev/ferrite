use super::*;
use url::Url;

const ID: &str = "path-relative-stylesheet";
const LIMIT: usize = 512 * 1024;

#[derive(Clone, Debug)]
pub(super) struct ProbePart {
    group: usize,
    phase: usize,
    token: String,
    link: String,
    baseline_target: String,
}

fn mime(message: &Message) -> &str {
    message
        .header("Content-Type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
}

fn links(body: &str) -> Vec<String> {
    let mut links = Vec::new();
    for (name, tag) in charset::html_tags(body.as_bytes()) {
        // Any explicit base makes URL resolution depend on more than the
        // address bar. Suppress the check in this case.
        if name.eq_ignore_ascii_case(b"base") {
            return vec![];
        }
        if !name.eq_ignore_ascii_case(b"link") {
            continue;
        }
        let attrs: Vec<_> = charset::attributes(tag).collect();
        let attribute = |name: &[u8]| {
            attrs
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .and_then(|(_, value)| std::str::from_utf8(value).ok())
        };
        if attribute(b"rel").is_some_and(|rel| {
            rel.split_ascii_whitespace()
                .any(|v| v.eq_ignore_ascii_case("stylesheet"))
                && !rel
                    .split_ascii_whitespace()
                    .any(|v| v.eq_ignore_ascii_case("alternate"))
        }) && attribute(b"disabled").is_none()
            && attribute(b"integrity").is_none_or(str::is_empty)
            && let Some(href) = attribute(b"href").map(str::trim)
            && !href.is_empty()
            && !href.starts_with(['/', '\\', '?', '#'])
            && !href.contains(['&', '\\'])
            && Url::parse(href).is_err()
            && !links.iter().any(|v| v == href)
        {
            links.push(href.into());
        }
    }
    links
}

fn ok_html(message: &Message) -> bool {
    message.status() == 200
        && mime(message).eq_ignore_ascii_case("text/html")
        && !message.header("Content-Disposition").is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("attachment"))
        })
}

fn denies_style_load(message: &Message, body: &str, url: &str, stylesheet: &str) -> bool {
    let Ok(page) = Url::parse(url) else {
        return true;
    };
    let Ok(stylesheet) = Url::parse(stylesheet) else {
        return true;
    };
    csp_policies(message, body).iter().any(|policy| {
        csp_sources(policy, &["style-src-elem", "style-src", "default-src"]).is_some_and(
            |sources| {
                !sources.iter().any(|source| {
                    source == "'self'" && page.origin() == stylesheet.origin()
                        || source == "*"
                        || source == &format!("{}:", stylesheet.scheme())
                        || source.trim_end_matches('/') == stylesheet.origin().ascii_serialization()
                })
            },
        )
    })
}

pub(super) fn plan(base: &Exchange, request: &Message, settings: &ScanSettings) -> Vec<Probe> {
    if !enabled(settings, ID) || request.method() != "GET" || request.header("Upgrade").is_some() {
        return vec![];
    }
    let Some(message) = reflection::response(base).filter(ok_html) else {
        return vec![];
    };
    let Some(body) = text_body(&message, LIMIT) else {
        return vec![];
    };
    let Ok(baseline_target) = origin_target(request, &base.destination) else {
        return vec![];
    };
    let Ok(url) = Url::parse(&format!("{}{baseline_target}", base.destination.origin())) else {
        return vec![];
    };
    let mut digest = Sha256::new();
    digest.update(marker(base));
    digest.update(base.note.as_bytes());
    let digest = format!("{:x}", digest.finalize());
    let token = format!("ferrite-style-{}", &digest[..24]);
    let mut changed = url.clone();
    changed.set_path(&format!("{}/{token}/", url.path().trim_end_matches('/')));
    let mut probes = Vec::new();
    for (group, link) in links(&body).into_iter().take(6).enumerate() {
        let Ok((original_css, shifted_css)) = url
            .join(&link)
            .and_then(|old| changed.join(&link).map(|new| (old, new)))
        else {
            continue;
        };
        if original_css.origin() != url.origin()
            || shifted_css.origin() != url.origin()
            || original_css == shifted_css
            || !shifted_css.path().contains(&token)
        {
            continue;
        }
        for (phase, url) in [&changed, &original_css, &shifted_css]
            .into_iter()
            .enumerate()
        {
            let mut probe = request.clone();
            let mut target = url.path().to_owned();
            if let Some(query) = url.query() {
                target.push('?');
                target.push_str(query);
            }
            replace_target(&mut probe, &target);
            probe.body.clear();
            probe.normalize_length();
            probes.push(Probe {
                issue_id: ID.into(),
                insertion_point: format!("Stylesheet {link}"),
                request: probe.encode(),
                destination: base.destination.clone(),
                raw: false,
                matcher: Matcher::Stylesheet(ProbePart {
                    group,
                    phase,
                    token: token.clone(),
                    link: link.clone(),
                    baseline_target: baseline_target.clone(),
                }),
            });
        }
    }
    probes
}

pub(super) fn evaluate_series(
    baseline: &Exchange,
    results: &[(Probe, Exchange)],
) -> Vec<Candidate> {
    let Some(before) = reflection::response(baseline).filter(ok_html) else {
        return vec![];
    };
    let Some(old) = text_body(&before, LIMIT) else {
        return vec![];
    };
    let Ok(request) = Message::parse(&baseline.request) else {
        return vec![];
    };
    let Ok(baseline_target) = origin_target(&request, &baseline.destination) else {
        return vec![];
    };
    let original_links = links(&old);
    let mut groups = std::collections::BTreeMap::<_, [_; 3]>::new();
    for (probe, flow) in results {
        if let Matcher::Stylesheet(part) = &probe.matcher
            && probe.destination == flow.destination
            && reflection::same_request(&probe.request, &flow.request, &flow.destination)
        {
            groups.entry(part.group).or_default()[part.phase] = Some((probe, flow, part));
        }
    }
    let mut findings = Vec::new();
    for phases in groups.into_values() {
        let [
            Some((probe, changed, part)),
            Some((_, css, _)),
            Some((_, shifted, _)),
        ] = phases
        else {
            continue;
        };
        let Some(page) = reflection::response(changed).filter(ok_html) else {
            continue;
        };
        let Some(css_response) = reflection::response(css).filter(|m| {
            m.status() == 200 && mime(m).eq_ignore_ascii_case("text/css") && !m.body.is_empty()
        }) else {
            continue;
        };
        let Some(wrong) = reflection::response(shifted).filter(ok_html) else {
            continue;
        };
        let Some((page_body, wrong_body)) = text_body(&page, LIMIT).zip(text_body(&wrong, LIMIT))
        else {
            continue;
        };
        if baseline.destination != probe.destination || baseline_target != part.baseline_target
            || !original_links.contains(&part.link) || !links(&page_body).contains(&part.link)
            || !links(&wrong_body).contains(&part.link)
            || denies_style_load(&page, &page_body, &changed.url, &shifted.url)
            || old.contains(&part.token) || !wrong_body.contains(&part.token)
            || reflection::marker_location(&css_response, &part.token).is_some()
            || [&page, &wrong].into_iter().any(|message| message.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("X-Content-Type-Options")
                    && value.split(',').any(|v| v.trim().eq_ignore_ascii_case("nosniff"))
            }))
            // Limit findings to documents that can enter quirks mode on their own.
            || [&page_body, &wrong_body].into_iter().any(|body| {
                re(r"(?is)<!doctype\b", &body[..body.floor_char_boundary(body.len().min(4096))])
            })
        {
            continue;
        }
        let mut finding = candidate(
            ID,
            shifted,
            Confidence::Firm,
            &probe.insertion_point,
            "The original stylesheet returned CSS. A path suffix preserved the relative stylesheet link, but the shifted stylesheet URL returned HTML containing the unique path marker. Review whether a browser will interpret the HTML as CSS.",
        );
        finding.affected = Some((baseline.url.clone(), baseline.method.clone()));
        finding.evidence = [
            ("Original page", baseline),
            ("Page with appended path", changed),
            ("Original stylesheet", css),
            ("Shifted stylesheet", shifted),
        ]
        .into_iter()
        .map(|(label, exchange)| Evidence {
            label: label.into(),
            exchange: exchange.clone(),
        })
        .collect();
        findings.push(finding);
    }
    findings
}

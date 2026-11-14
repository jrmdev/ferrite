use super::*;

pub(super) fn supports_point(point: &Point) -> bool {
    // Use individual JSON values instead of replacing the entire document.
    !matches!(point.location, Location::Body { raw: true, .. })
}

pub(super) fn canary(base: &Exchange, point: &Point, family: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(marker(base));
    hash.update(base.note.as_bytes());
    hash.update(family.as_bytes());
    hash.update(point.label.as_bytes());
    let digest = format!("{:x}", hash.finalize());
    format!("ferrite-input-{}", &digest[..24])
}

const ENCODERS: [fn(&str) -> String; 6] = [
    |token| token.bytes().map(|byte| format!("%{byte:02X}")).collect(),
    |token| {
        token
            .bytes()
            .map(|byte| format!("%25{byte:02X}"))
            .collect()
    },
    |token| token.bytes().map(|byte| format!("\\u{byte:04x}")).collect(),
    |token| token.bytes().map(|byte| format!("\\x{byte:02x}")).collect(),
    |token| token.bytes().map(|byte| format!("&#{byte};")).collect(),
    |token| token.bytes().map(|byte| format!("&#x{byte:02x};")).collect(),
];

pub(super) fn transformed_payloads(token: &str) -> impl Iterator<Item = (String, String)> + '_ {
    ENCODERS.iter().enumerate().map(move |(index, encode)| {
        let marker = format!("{token}-{index}");
        let payload = encode(&marker);
        (marker, payload)
    })
}

pub(super) fn response(flow: &Exchange) -> Option<Message> {
    if flow.error.is_some() {
        return None;
    }
    let message = Message::parse(&flow.response).ok()?;
    (message.status() == flow.status).then_some(message)
}

pub(super) fn same_request(planned: &[u8], observed: &[u8], destination: &Destination) -> bool {
    if planned == observed {
        return true;
    }
    Message::parse(planned).is_ok_and(|mut request| {
        request.prepare_request(destination).is_ok() && request.encode() == observed
    })
}

pub(super) fn marker_location(message: &Message, token: &str) -> Option<String> {
    let body = text_body(message, 4 * 1024 * 1024)?;
    marker_location_body(message, &body, token)
}

/// Use an already decoded body so callers that cache the baseline text do not
/// decompress and decode the same response once per probe.
pub(super) fn marker_location_body(
    message: &Message,
    body: &str,
    token: &str,
) -> Option<String> {
    let media_type = message
        .header("Content-Type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if matches!(media_type.as_str(), "message/http" | "application/http") {
        return None;
    }
    if let Some((name, _)) = message
        .headers
        .iter()
        .find(|(_, value)| contains(value, token))
    {
        return Some(format!("response header {name}"));
    }
    if (media_type.is_empty()
        || media_type.starts_with("text/")
        || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
        || matches!(
            media_type.as_str(),
            "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/x-javascript"
                | "application/x-www-form-urlencoded"
        ))
        && !body.contains('\0')
        && contains(body, token)
    {
        return Some("response body".into());
    }
    None
}

fn contains(value: &str, token: &str) -> bool {
    value.contains(token)
        || value
            .as_bytes()
            .windows(token.len())
            .any(|window| window.eq_ignore_ascii_case(token.as_bytes()))
}

pub(super) fn evaluate_cached(
    probe: &Probe,
    baseline: &CachedBaseline<'_>,
    flow: &Exchange,
    token: &str,
) -> Vec<Candidate> {
    let Some(before) = baseline.message.as_ref() else {
        return vec![];
    };
    let Some(after) = response(flow) else {
        return vec![];
    };
    let status = after.status();
    // A response that changed the status is acceptable evidence only when it
    // stayed inside the same class of success, or kept the baseline status.
    // A reflected marker on a new error page is still a reflection.
    let comparable = (200..400).contains(&status) || status == before.status();
    if flow.destination != probe.destination
        || !same_request(&probe.request, &flow.request, &flow.destination)
        || !comparable
        || marker_location_body(before, &baseline.body, token).is_some()
    {
        return vec![];
    }
    let Some(location) = marker_location(&after, token) else {
        return vec![];
    };
    let observation = if probe.issue_id == "input-transformed" {
        "An encoded probe marker appeared decoded"
    } else {
        "The unique input marker appeared"
    };
    let mut finding = candidate(
        &probe.issue_id,
        flow,
        Confidence::Certain,
        &probe.insertion_point,
        format!(
            "{observation} in the {location} and was absent from the baseline. Review how the application uses the returned input."
        ),
    );
    finding.evidence.insert(
        0,
        Evidence {
            label: "Selected baseline".into(),
            exchange: baseline.exchange.clone(),
        },
    );
    vec![finding]
}

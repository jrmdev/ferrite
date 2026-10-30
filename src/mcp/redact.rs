//! Credential header redaction for MCP results.
//!
//! Values of credential-bearing headers are replaced with [`MARKER`]. A client
//! can send a request containing the marker together with a base exchange or
//! Repeater tab, and Ferrite substitutes the original value locally, so the
//! credential itself never leaves Ferrite. Bodies are not redacted.
use crate::http::Message;
use anyhow::{Result, bail};

pub const MARKER: &str = "[REDACTED]";

const SENSITIVE: [&str; 16] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-amz-security-token",
    "x-goog-api-key",
    "private-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-session-token",
    "authentication",
];

pub fn sensitive(name: &str) -> bool {
    SENSITIVE
        .iter()
        .any(|s| s.eq_ignore_ascii_case(name.trim()))
}

/// Redact parsed headers in place, returning the names that were redacted.
pub fn headers(headers: &mut [(String, String)]) -> Vec<String> {
    let mut names = vec![];
    for (name, value) in headers.iter_mut() {
        if sensitive(name) && !value.is_empty() {
            *value = MARKER.into();
            if !names.iter().any(|n: &String| n.eq_ignore_ascii_case(name)) {
                names.push(name.clone());
            }
        }
    }
    names
}

/// Redact header values in raw message bytes, preserving every other byte.
pub fn raw(bytes: &[u8]) -> (Vec<u8>, Vec<String>) {
    let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return (bytes.to_vec(), vec![]);
    };
    let mut out = Vec::with_capacity(bytes.len());
    let mut names = vec![];
    for (index, line) in bytes[..end].split(|b| *b == b'\n').enumerate() {
        if index > 0 {
            out.push(b'\n');
        }
        let name = line
            .iter()
            .position(|b| *b == b':')
            .and_then(|colon| std::str::from_utf8(&line[..colon]).ok().map(|n| (colon, n)));
        match name {
            Some((colon, name)) if index > 0 && sensitive(name) => {
                out.extend_from_slice(&line[..=colon]);
                out.push(b' ');
                out.extend_from_slice(MARKER.as_bytes());
                if line.ends_with(b"\r") {
                    out.push(b'\r');
                }
                if !names.iter().any(|n: &String| n.eq_ignore_ascii_case(name)) {
                    names.push(name.trim().to_string());
                }
            }
            _ => out.extend_from_slice(line),
        }
    }
    out.extend_from_slice(&bytes[end..]);
    (out, names)
}

/// Replace marker values with the same-named header from `base`, matching
/// repeated headers by occurrence.
pub fn restore(message: &mut Message, base: Option<&Message>) -> Result<()> {
    let mut seen: Vec<(String, usize)> = vec![];
    for (name, value) in message.headers.iter_mut() {
        let lower = name.to_ascii_lowercase();
        let occurrence = match seen.iter_mut().find(|(n, _)| *n == lower) {
            Some((_, count)) => {
                *count += 1;
                *count - 1
            }
            None => {
                seen.push((lower.clone(), 1));
                0
            }
        };
        if value.trim() != MARKER {
            continue;
        }
        let Some(base) = base else {
            bail!(
                "{name} contains {MARKER}; pass base_exchange_id or tab_id so Ferrite can restore the original value"
            );
        };
        let original = base
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .nth(occurrence)
            .map(|(_, v)| v.clone());
        match original {
            Some(original) => *value = original,
            None => bail!("Cannot restore {name}: the base request has no matching header"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_redaction_preserves_other_bytes() {
        let message = b"GET / HTTP/1.1\r\nHost: a\r\nCookie:  s=1; t=2\r\nAuthorization: Bearer x\r\nX-Other: keep\r\n\r\nbody Cookie: no";
        let (out, names) = raw(message);
        assert_eq!(
            out,
            b"GET / HTTP/1.1\r\nHost: a\r\nCookie: [REDACTED]\r\nAuthorization: [REDACTED]\r\nX-Other: keep\r\n\r\nbody Cookie: no"
        );
        assert_eq!(names, ["Cookie", "Authorization"]);
        assert_eq!(raw(b"no head").0, b"no head");
    }

    #[test]
    fn restore_uses_base_values_by_occurrence() {
        let base = Message::parse(
            b"GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\nAuthorization: Bearer t\r\n\r\n",
        )
        .unwrap();
        let mut view = base.clone();
        assert_eq!(headers(&mut view.headers), ["Cookie", "Authorization"]);
        assert!(view.headers.iter().all(|(n, v)| n == "Host" || v == MARKER));
        let mut edited = Message::parse(
            b"POST /x HTTP/1.1\r\nCookie: [REDACTED]\r\nCookie: [REDACTED]\r\nAuthorization: Bearer mine\r\n\r\n",
        )
        .unwrap();
        restore(&mut edited, Some(&base)).unwrap();
        assert_eq!(
            edited.headers,
            [
                ("Cookie".to_string(), "a=1".to_string()),
                ("Cookie".into(), "b=2".into()),
                ("Authorization".into(), "Bearer mine".into())
            ]
        );
        let mut orphan =
            Message::parse(b"GET / HTTP/1.1\r\nX-Api-Key: [REDACTED]\r\n\r\n").unwrap();
        assert!(restore(&mut orphan.clone(), None).is_err());
        assert!(restore(&mut orphan, Some(&base)).is_err());
    }
}

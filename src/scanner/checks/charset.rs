use crate::http::Message;
use encoding_rs::Encoding;
use regex::bytes::Regex;
use std::sync::LazyLock;

// Consume quoted parameter values as a unit so a semicolon within another
// parameter cannot be mistaken for the start of a charset declaration.
static PARAMETERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i-u);\s*([^\s;=]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([^;"'\s]*))"#)
        .unwrap()
});

fn charset_parameter(content_type: &[u8]) -> Option<&[u8]> {
    PARAMETERS.captures_iter(content_type).find_map(|parts| {
        parts[1].eq_ignore_ascii_case(b"charset").then(|| {
            parts
                .get(2)
                .or_else(|| parts.get(3))
                .or_else(|| parts.get(4))
                .map_or(&[][..], |value| value.as_bytes())
        })
    })
}

static TAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is-u)<!--(?:.*?(?:--!?>|$))|<![^>]*(?:>|$)|<(/?)([a-z][^\s/>]*)([\s/](?:[^>"']|"[^"]*"|'[^']*')*)?>"#)
        .unwrap()
});
static ATTRIBUTES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i-u)([^\s/="'<>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?"#).unwrap()
});

pub(super) fn html_tags(bytes: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    let mut raw_text: Option<&[u8]> = None;
    let mut templates = 0usize;
    TAGS.captures_iter(bytes).filter_map(move |tag| {
        let name = tag.get(2)?.as_bytes();
        let closing = !tag[1].is_empty();
        if let Some(raw) = raw_text {
            if closing && name.eq_ignore_ascii_case(raw) && !raw.eq_ignore_ascii_case(b"plaintext")
            {
                raw_text = None;
            }
            return None;
        }
        if name.eq_ignore_ascii_case(b"template") {
            templates = if closing {
                templates.saturating_sub(1)
            } else {
                templates + 1
            };
        }
        if !closing
            && [
                b"script".as_slice(),
                b"style",
                b"title",
                b"textarea",
                b"xmp",
                b"iframe",
                b"noembed",
                b"noframes",
                b"noscript",
                b"plaintext",
            ]
            .iter()
            .any(|raw| name.eq_ignore_ascii_case(raw))
        {
            raw_text = Some(name);
        }
        if closing || templates > 0 {
            return None;
        }
        Some((name, tag.get(3).map_or(&[][..], |value| value.as_bytes())))
    })
}

pub(super) fn attributes(tag: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    ATTRIBUTES.captures_iter(tag).map(|attr| {
        let value = attr
            .get(2)
            .or_else(|| attr.get(3))
            .or_else(|| attr.get(4))
            .map_or(&[][..], |value| value.as_bytes());
        (attr.get(1).unwrap().as_bytes(), value)
    })
}

fn meta_charsets(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    html_tags(bytes).filter_map(|(name, tag)| {
        if !name.eq_ignore_ascii_case(b"meta") {
            return None;
        }
        let mut charset = None;
        let mut pragma = None;
        let mut content = None;
        for (name, value) in attributes(tag) {
            if name.eq_ignore_ascii_case(b"charset") {
                charset.get_or_insert(value);
            } else if name.eq_ignore_ascii_case(b"http-equiv") {
                pragma.get_or_insert(value);
            } else if name.eq_ignore_ascii_case(b"content") {
                content.get_or_insert(value);
            }
        }
        charset.or_else(|| {
            pragma.filter(|v| v.eq_ignore_ascii_case(b"content-type"))?;
            charset_parameter(content?)
        })
    })
}

pub(super) fn finding(
    response: &Message,
    bytes: &[u8],
) -> Option<(&'static str, &'static str, String)> {
    let mut content_types = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Type"));
    let (_, content_type) = content_types.next()?;
    if bytes.is_empty()
        || content_types.next().is_some()
        || !content_type
            .split(';')
            .next()?
            .trim()
            .eq_ignore_ascii_case("text/html")
        || Encoding::for_bom(bytes).is_some()
    {
        return None;
    }
    let recognized = |label: &[u8]| Encoding::for_label_no_replacement(label).is_some();
    let header = charset_parameter(content_type.as_bytes());
    if header.is_some_and(recognized) {
        return None;
    }
    let mut unknown = header.map(|label| ("Content-Type", label));
    // Browsers are encouraged to prescan the first 1024 bytes for meta charset.
    for label in meta_charsets(&bytes[..bytes.len().min(1024)]) {
        if recognized(label) {
            return None;
        }
        unknown.get_or_insert(("meta charset", label));
    }
    if let Some((point, label)) = unknown {
        let label: String = String::from_utf8_lossy(label).chars().take(80).collect();
        return Some((
            "charset-unrecognized",
            point,
            format!(
                "The declared HTML charset {label:?} is not a recognized browser encoding. No recognized fallback was found."
            ),
        ));
    }
    (!bytes.is_ascii()).then(|| {
        (
            "charset",
            "HTML encoding",
            "Non-ASCII HTML has no HTTP or early meta charset declaration.".into(),
        )
    })
}

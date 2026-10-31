//! Whitespace-only JSON previews; never replace an editable message buffer.
use eframe::egui;
use serde::Deserialize as _;
use std::{collections::VecDeque, sync::Arc};

#[derive(Clone, Copy, Default)]
struct Config {
    enabled: bool,
    project: usize,
    epoch: u64,
}

#[derive(Clone, Default)]
struct Cache {
    entries: VecDeque<(egui::Id, Arc<str>, Option<Arc<str>>)>,
}

pub(super) fn configure(ctx: &egui::Context, enabled: bool, project: usize) {
    ctx.data_mut(|data| {
        let config = data.get_temp_mut_or_default::<Config>(egui::Id::new("json-preview-config"));
        if config.enabled != enabled || config.project != project {
            config.epoch = config.epoch.wrapping_add(1);
            config.enabled = enabled;
            config.project = project;
            data.remove::<Cache>(egui::Id::new("json-preview-cache"));
        }
    });
}

pub(super) fn preview(
    ctx: &egui::Context,
    id: egui::Id,
    text: &str,
) -> Option<(egui::Id, Arc<str>)> {
    cached_preview(ctx, id, text, false)
}

pub(super) fn preview_payload(
    ctx: &egui::Context,
    id: egui::Id,
    text: &str,
) -> Option<(egui::Id, Arc<str>)> {
    cached_preview(ctx, id, text, true)
}

fn cached_preview(
    ctx: &egui::Context,
    id: egui::Id,
    text: &str,
    payload: bool,
) -> Option<(egui::Id, Arc<str>)> {
    let config = ctx
        .data(|data| data.get_temp::<Config>(egui::Id::new("json-preview-config")))
        .unwrap_or_default();
    if !config.enabled || text.len() > super::response_content::DISPLAY_LIMIT {
        return None;
    }
    let key = id.with(("json-preview", config.epoch, payload));
    let cache_id = egui::Id::new("json-preview-cache");
    let cached = ctx
        .data(|data| data.get_temp::<Cache>(cache_id))
        .unwrap_or_default();
    if let Some((_, _, rendered)) = cached
        .entries
        .iter()
        .find(|(entry, source, _)| *entry == key && source.as_ref() == text)
    {
        return rendered.clone().map(|text| (key, text));
    }
    let rendered = if payload {
        format_json("", text)
    } else {
        format_message(text)
    }
    .map(Arc::<str>::from);
    ctx.data_mut(|data| {
        let cache = data.get_temp_mut_or_default::<Cache>(cache_id);
        cache.entries.retain(|(entry, _, _)| *entry != key);
        cache
            .entries
            .push_back((key, Arc::from(text), rendered.clone()));
        let mut bytes: usize = cache
            .entries
            .iter()
            .map(|(_, source, rendered)| {
                source.len() + rendered.as_ref().map_or(0, |text| text.len())
            })
            .sum();
        while cache.entries.len() > 8 || bytes > 4 * super::response_content::DISPLAY_LIMIT {
            if let Some((_, source, rendered)) = cache.entries.pop_front() {
                bytes -= source.len() + rendered.as_ref().map_or(0, |text| text.len());
            }
        }
    });
    rendered.map(|text| (key, text))
}

fn format_message(text: &str) -> Option<String> {
    let end = text
        .find("\r\n\r\n")
        .map(|n| n + 4)
        .or_else(|| text.find("\n\n").map(|n| n + 2))?;
    let (headers, body) = text.split_at(end);
    let content_type = headers
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))?
        .1
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase();
    if content_type != "application/json"
        && content_type != "text/json"
        && !content_type.ends_with("+json")
    {
        return None;
    }
    format_json(headers, body)
}

fn format_json(headers: &str, body: &str) -> Option<String> {
    let mut deserializer = serde_json::Deserializer::from_str(body);
    serde::de::IgnoredAny::deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    // Validate with serde, then preserve the original tokens, including duplicate
    // keys, ordering, escape sequences, and exact numeric representations.
    let tokens: Vec<u8> = body
        .bytes()
        .scan((false, false), |(string, escaped), byte| {
            let in_string = *string;
            if *escaped {
                *escaped = false;
            } else if *string && byte == b'\\' {
                *escaped = true;
            } else if byte == b'"' {
                *string = !*string;
            }
            Some((byte, in_string))
        })
        .filter_map(|(byte, in_string)| (in_string || !byte.is_ascii_whitespace()).then_some(byte))
        .collect();
    let mut out = headers.as_bytes().to_vec();
    let mut depth = 0usize;
    let mut string = false;
    let mut escaped = false;
    for (index, &byte) in tokens.iter().enumerate() {
        if string {
            out.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string = false;
            }
        } else {
            match byte {
                b'"' => {
                    string = true;
                    out.push(byte);
                }
                b'{' | b'[' => {
                    out.push(byte);
                    depth += 1;
                    if tokens
                        .get(index + 1)
                        .is_some_and(|b| !matches!(b, b'}' | b']'))
                    {
                        out.push(b'\n');
                        out.extend(std::iter::repeat_n(b' ', depth * 2));
                    }
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1)?;
                    if index > 0 && !matches!(tokens[index - 1], b'{' | b'[') {
                        out.push(b'\n');
                        out.extend(std::iter::repeat_n(b' ', depth * 2));
                    }
                    out.push(byte);
                }
                b',' => {
                    out.extend_from_slice(b",\n");
                    out.extend(std::iter::repeat_n(b' ', depth * 2));
                }
                b':' => out.extend_from_slice(b": "),
                _ => out.push(byte),
            }
        }
        if out.len() > super::response_content::DISPLAY_LIMIT {
            return None;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_bounds_retained_bytes_and_releases_previous_project() {
        let ctx = egui::Context::default();
        let cache_id = egui::Id::new("json-preview-cache");
        configure(&ctx, true, 1);
        let payload = format!(
            "{{\"x\":\"{}\"}}",
            "x".repeat(super::super::response_content::DISPLAY_LIMIT / 2)
        );
        for id in 0..12 {
            assert!(preview_payload(&ctx, egui::Id::new(id), &payload).is_some());
        }
        let cache = ctx.data(|data| data.get_temp::<Cache>(cache_id)).unwrap();
        let bytes: usize = cache
            .entries
            .iter()
            .map(|(_, source, rendered)| source.len() + rendered.as_ref().map_or(0, |s| s.len()))
            .sum();
        assert!(bytes <= 4 * super::super::response_content::DISPLAY_LIMIT);
        assert!(cache.entries.len() < 8);
        configure(&ctx, true, 2);
        assert!(ctx.data(|data| data.get_temp::<Cache>(cache_id)).is_none());
        preview_payload(&ctx, egui::Id::new("new"), "{}");
        configure(&ctx, false, 2);
        assert!(ctx.data(|data| data.get_temp::<Cache>(cache_id)).is_none());
    }

    #[test]
    fn websocket_json_is_detected_without_headers_and_respects_the_project_setting() {
        let ctx = egui::Context::default();
        let id = egui::Id::new("ws-json");
        let payload = "{\"value\":1e+02,\"value\":2}";
        configure(&ctx, true, 1);
        assert!(preview(&ctx, id, payload).is_none());
        let (_, rendered) = preview_payload(&ctx, id, payload).unwrap();
        assert_eq!(&*rendered, "{\n  \"value\": 1e+02,\n  \"value\": 2\n}");
        assert!(preview_payload(&ctx, id, "non-JSON payload").is_none());
        configure(&ctx, false, 1);
        assert!(preview_payload(&ctx, id, payload).is_none());
    }

    #[test]
    fn formatting_preserves_duplicate_keys_numbers_escapes_and_headers() {
        let text = "POST / HTTP/1.1\r\nContent-Type: application/problem+json; charset=UTF-8\r\nContent-Length: 42\r\n\r\n{\"x\":1e+02,\"x\":2,\"s\":\"a,\\\"[]\",\"empty\":{}}";
        let formatted = format_message(text).unwrap();
        assert!(formatted.starts_with(text.split_once("\r\n\r\n").unwrap().0));
        assert!(formatted.contains("\n  \"x\": 1e+02,\n  \"x\": 2,"));
        assert!(formatted.contains("\"s\": \"a,\\\"[]\""));
        assert!(formatted.ends_with("\"empty\": {}\n}"));
    }

    #[test]
    fn non_json_invalid_json_and_oversized_previews_are_left_alone() {
        for text in [
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n{\"x\":1}",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{invalid}",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[Body too large to be displayed]",
            "7b 22 78 22 3a 31 7d",
        ] {
            assert!(format_message(text).is_none());
        }
        let text = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[{}0]",
            "0,".repeat(700_000)
        );
        assert!(format_message(&text).is_none());
    }
}

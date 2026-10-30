//! Syntax highlighting and find matches for message editors. Highlighting
//! only changes how text is drawn; the text itself is never modified.
use eframe::egui::{self, Color32, text::LayoutJob};
use std::{hash::Hasher, sync::Arc};

/// Text beyond this many bytes is drawn without syntax colours.
const HIGHLIGHT_LIMIT: usize = 512 * 1024;
const FIND_ID: &str = "ferrite-editor-find";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Kind {
    Http,
    Json,
    Plain,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Body {
    Json,
    Markup,
    Form,
    Plain,
}

struct Palette {
    text: Color32,
    weak: Color32,
    accent: Color32,
    name: Color32,
    key: Color32,
    string: Color32,
    number: Color32,
    literal: Color32,
    found: Color32,
}
impl Palette {
    fn new(visuals: &egui::Visuals) -> Self {
        let rgb = |dark: [u8; 3], light: [u8; 3]| {
            let [r, g, b] = if visuals.dark_mode { dark } else { light };
            Color32::from_rgb(r, g, b)
        };
        Self {
            text: visuals.text_color(),
            weak: visuals.weak_text_color(),
            accent: rgb([110, 180, 255], [20, 90, 170]),
            name: rgb([230, 170, 90], [150, 80, 0]),
            key: rgb([150, 200, 255], [30, 80, 160]),
            string: rgb([160, 210, 140], [40, 120, 40]),
            number: rgb([230, 160, 110], [170, 80, 20]),
            literal: rgb([200, 150, 230], [130, 50, 160]),
            found: if visuals.dark_mode {
                Color32::from_rgba_unmultiplied(230, 200, 60, 110)
            } else {
                Color32::from_rgba_unmultiplied(250, 220, 60, 170)
            },
        }
    }
}

/// The find term shared by the visible message editors.
pub(super) fn find_term(ctx: &egui::Context) -> String {
    ctx.data(|d| d.get_temp::<String>(egui::Id::new(FIND_ID)))
        .unwrap_or_default()
}
pub(super) fn set_find_term(ctx: &egui::Context, term: &str) {
    ctx.data_mut(|d| d.insert_temp(egui::Id::new(FIND_ID), term.to_owned()));
}

/// A find field that highlights matches in the visible message editors.
pub(super) fn find_bar(ui: &mut egui::Ui, parts: &[(&str, &str)]) {
    let mut term = find_term(ui.ctx());
    ui.horizontal(|ui| {
        ui.label("Find");
        if ui
            .add(
                egui::TextEdit::singleline(&mut term)
                    .hint_text("Highlight text in both messages")
                    .desired_width(240.0),
            )
            .changed()
        {
            set_find_term(ui.ctx(), &term);
        }
        if !term.is_empty() {
            let counts: Vec<String> = parts
                .iter()
                .map(|(label, text)| format!("{} in {label}", matches(text, &term).len()))
                .collect();
            ui.weak(counts.join(" · "));
            if ui.small_button("Clear").clicked() {
                set_find_term(ui.ctx(), "");
            }
        }
    });
}

/// Byte ranges of case-insensitive (ASCII) matches.
pub(super) fn matches(text: &str, term: &str) -> Vec<(usize, usize)> {
    if term.is_empty() || term.len() > text.len() {
        return vec![];
    }
    let haystack = text.as_bytes();
    let needle: Vec<u8> = term.bytes().map(|b| b.to_ascii_lowercase()).collect();
    let mut found = vec![];
    let mut index = 0;
    while index + needle.len() <= haystack.len() {
        if haystack[index..index + needle.len()]
            .iter()
            .zip(&needle)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
        {
            found.push((index, index + needle.len()));
            index += needle.len();
        } else {
            index += 1;
        }
    }
    found
}

fn body_kind(head: &str, body: &str) -> Body {
    let content_type = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default();
    let trimmed = body.trim_start();
    if content_type.contains("json") {
        Body::Json
    } else if content_type.contains("xml") || content_type.contains("html") {
        Body::Markup
    } else if content_type.contains("x-www-form-urlencoded") {
        Body::Form
    } else if trimmed.starts_with('{') || trimmed.starts_with('[') {
        Body::Json
    } else if trimmed.starts_with('<') {
        Body::Markup
    } else {
        Body::Plain
    }
}

type Spans = Vec<(usize, usize, Color32)>;

fn push(spans: &mut Spans, start: usize, end: usize, color: Color32) {
    if end > start {
        spans.push((start, end, color));
    }
}

fn http_head(text: &str, offset: usize, p: &Palette, spans: &mut Spans, visuals: &egui::Visuals) {
    let mut position = offset;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let start = position;
        position += line.len();
        let content = line.trim_end_matches(['\r', '\n']);
        if index == 0 {
            let mut words = content.split(' ');
            let first = words.next().unwrap_or("");
            if first.starts_with("HTTP/") {
                push(spans, start, start + first.len(), p.weak);
                let status = words.next().unwrap_or("");
                let color = super::theme::status_color(visuals, status.parse().unwrap_or(0));
                push(
                    spans,
                    start + first.len(),
                    start + first.len() + 1 + status.len(),
                    color,
                );
                push(
                    spans,
                    start + first.len() + 1 + status.len(),
                    position,
                    p.text,
                );
            } else {
                push(spans, start, start + first.len(), p.accent);
                let version = content.rfind(" HTTP/").unwrap_or(content.len());
                push(spans, start + first.len(), start + version, p.text);
                push(spans, start + version, position, p.weak);
            }
        } else if let Some(colon) = content.find(':') {
            push(spans, start, start + colon, p.name);
            push(spans, start + colon, start + colon + 1, p.weak);
            push(spans, start + colon + 1, position, p.text);
        } else {
            push(spans, start, position, p.text);
        }
    }
}

fn json(text: &str, offset: usize, p: &Palette, spans: &mut Spans) {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut plain = 0;
    let flush =
        |spans: &mut Spans, from: usize, to: usize| push(spans, offset + from, offset + to, p.text);
    while index < bytes.len() {
        let start = index;
        let color = match bytes[index] {
            b'"' => {
                index += 1;
                while index < bytes.len() && bytes[index] != b'"' {
                    index += if bytes[index] == b'\\' { 2 } else { 1 };
                }
                index = (index + 1).min(bytes.len());
                let next = bytes[index..].iter().find(|b| !b.is_ascii_whitespace());
                if next == Some(&b':') { p.key } else { p.string }
            }
            b'-' | b'0'..=b'9' => {
                while index < bytes.len()
                    && matches!(bytes[index], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                {
                    index += 1;
                }
                p.number
            }
            b't' | b'f' | b'n'
                if ["true", "false", "null"]
                    .iter()
                    .any(|w| bytes[index..].starts_with(w.as_bytes())) =>
            {
                index += ["true", "false", "null"]
                    .iter()
                    .find(|w| bytes[index..].starts_with(w.as_bytes()))
                    .unwrap()
                    .len();
                p.literal
            }
            b'{' | b'}' | b'[' | b']' | b':' | b',' => {
                index += 1;
                p.weak
            }
            _ => {
                index += 1;
                continue;
            }
        };
        flush(spans, plain, start);
        push(spans, offset + start, offset + index, color);
        plain = index;
    }
    flush(spans, plain, bytes.len());
}

fn markup(text: &str, offset: usize, p: &Palette, spans: &mut Spans) {
    let mut index = 0;
    while index < text.len() {
        let Some(open) = text[index..].find('<').map(|o| index + o) else {
            push(spans, offset + index, offset + text.len(), p.text);
            break;
        };
        push(spans, offset + index, offset + open, p.text);
        if text[open..].starts_with("<!--") {
            let end = text[open..]
                .find("-->")
                .map_or(text.len(), |e| open + e + 3);
            push(spans, offset + open, offset + end, p.weak);
            index = end;
            continue;
        }
        let end = text[open..].find('>').map_or(text.len(), |e| open + e + 1);
        let tag = &text[open..end];
        let name_end = tag
            .find(|c: char| c.is_whitespace() || c == '>' || (c == '/' && tag.len() > 2))
            .unwrap_or(tag.len())
            .max(1);
        push(spans, offset + open, offset + open + name_end, p.accent);
        let mut cursor = name_end;
        let mut quote: Option<char> = None;
        let mut segment = cursor;
        for (i, c) in tag[name_end..].char_indices() {
            let at = name_end + i;
            match (quote, c) {
                (None, '"' | '\'') => {
                    push(spans, offset + open + segment, offset + open + at, p.name);
                    quote = Some(c);
                    segment = at;
                }
                (Some(q), c) if c == q => {
                    push(
                        spans,
                        offset + open + segment,
                        offset + open + at + 1,
                        p.string,
                    );
                    quote = None;
                    segment = at + 1;
                }
                _ => {}
            }
            cursor = at + c.len_utf8();
        }
        let tail = if quote.is_some() { p.string } else { p.name };
        let close = if tag.ends_with('>') && quote.is_none() {
            cursor.saturating_sub(1).max(segment)
        } else {
            cursor
        };
        push(spans, offset + open + segment, offset + open + close, tail);
        push(spans, offset + open + close, offset + end, p.accent);
        index = end;
    }
}

fn form(text: &str, offset: usize, p: &Palette, spans: &mut Spans) {
    let mut position = 0;
    for pair in text.split_inclusive('&') {
        let content = pair.trim_end_matches('&');
        match content.find('=') {
            Some(eq) => {
                push(spans, offset + position, offset + position + eq, p.key);
                push(
                    spans,
                    offset + position + eq,
                    offset + position + eq + 1,
                    p.weak,
                );
                push(
                    spans,
                    offset + position + eq + 1,
                    offset + position + content.len(),
                    p.text,
                );
            }
            None => push(
                spans,
                offset + position,
                offset + position + content.len(),
                p.key,
            ),
        }
        push(
            spans,
            offset + position + content.len(),
            offset + position + pair.len(),
            p.weak,
        );
        position += pair.len();
    }
}

/// Colour spans covering the start of `text` (up to the highlight limit).
fn spans(text: &str, kind: Kind, p: &Palette, visuals: &egui::Visuals) -> Spans {
    let mut limit = text.len().min(HIGHLIGHT_LIMIT);
    while !text.is_char_boundary(limit) {
        limit -= 1;
    }
    let text = &text[..limit];
    let mut spans = vec![];
    match kind {
        Kind::Plain => push(&mut spans, 0, text.len(), p.text),
        Kind::Json => json(text, 0, p, &mut spans),
        Kind::Http => {
            let split = text
                .find("\r\n\r\n")
                .map(|i| (i, i + 4))
                .or_else(|| text.find("\n\n").map(|i| (i, i + 2)));
            let Some((head_end, body_start)) = split else {
                http_head(text, 0, p, &mut spans, visuals);
                return spans;
            };
            http_head(&text[..body_start], 0, p, &mut spans, visuals);
            let _ = head_end;
            let body = &text[body_start..];
            match body_kind(&text[..head_end], body) {
                Body::Json => json(body, body_start, p, &mut spans),
                Body::Markup => markup(body, body_start, p, &mut spans),
                Body::Form => form(body, body_start, p, &mut spans),
                Body::Plain => push(&mut spans, body_start, text.len(), p.text),
            }
        }
    }
    spans
}

/// Build the layout for an editor: syntax colours plus find highlights.
pub(super) fn layout(
    text: &str,
    kind: Kind,
    find: &str,
    font: egui::FontId,
    wrap_width: f32,
    visuals: &egui::Visuals,
) -> LayoutJob {
    let p = Palette::new(visuals);
    // Normalise to ordered, contiguous, in-range spans on char boundaries so
    // the laid-out text is exactly the editor text.
    let mut colored: Spans = vec![];
    let mut covered = 0;
    for (start, end, color) in spans(text, kind, &p, visuals) {
        let (start, end) = (start.max(covered), end.min(text.len()));
        if end <= start || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            continue;
        }
        push(&mut colored, covered, start, p.text);
        colored.push((start, end, color));
        covered = end;
    }
    push(&mut colored, covered, text.len(), p.text);
    let found = matches(text, find);
    let mut job = LayoutJob::default();
    job.wrap.max_width = wrap_width;
    let mut next_match = 0;
    for (start, end, color) in colored {
        let mut at = start;
        while at < end {
            while next_match < found.len() && found[next_match].1 <= at {
                next_match += 1;
            }
            let (piece_end, highlighted) = match found.get(next_match) {
                Some(&(m_start, m_end)) if m_start <= at => (m_end.min(end), true),
                Some(&(m_start, _)) if m_start < end => (m_start, false),
                _ => (end, false),
            };
            let mut format = egui::TextFormat::simple(font.clone(), color);
            if highlighted {
                format.background = p.found;
            }
            job.append(&text[at..piece_end], 0.0, format);
            at = piece_end;
        }
    }
    job
}

/// A layouter for `TextEdit` that caches the galley by content.
pub(super) fn layouter(
    kind: Kind,
    id: egui::Id,
) -> impl FnMut(&egui::Ui, &dyn egui::TextBuffer, f32) -> Arc<egui::Galley> {
    move |ui, buffer, wrap_width| {
        let text = buffer.as_str();
        let find = find_term(ui.ctx());
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(
            &(
                text,
                &find,
                kind,
                wrap_width.to_bits(),
                ui.visuals().dark_mode,
            ),
            &mut hasher,
        );
        let key = hasher.finish();
        let cache = id.with("highlight-cache");
        if let Some((cached, galley)) = ui.data(|d| d.get_temp::<(u64, Arc<egui::Galley>)>(cache))
            && cached == key
        {
            return galley;
        }
        let font = egui::TextStyle::Monospace.resolve(ui.style());
        let job = layout(text, kind, &find, font, wrap_width, ui.visuals());
        let galley = ui.fonts_mut(|f| f.layout_job(job));
        ui.data_mut(|d| d.insert_temp(cache, (key, galley.clone())));
        galley
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn colours(text: &str, kind: Kind, find: &str) -> Vec<(String, Color32, bool)> {
        let visuals = egui::Visuals::dark();
        let job = layout(
            text,
            kind,
            find,
            egui::FontId::monospace(12.0),
            400.0,
            &visuals,
        );
        assert_eq!(job.text, text, "highlighting must not change the text");
        job.sections
            .iter()
            .map(|s| {
                (
                    text[s.byte_range.clone()].to_string(),
                    s.format.color,
                    s.format.background != Color32::TRANSPARENT,
                )
            })
            .collect()
    }

    #[test]
    fn http_json_markup_and_form_are_coloured_without_changing_text() {
        let p = Palette::new(&egui::Visuals::dark());
        let request = "POST /api?x=1 HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"id\": 5, \"ok\": true, \"name\": \"a\\\"b\"}";
        let sections = colours(request, Kind::Http, "");
        assert!(sections.contains(&("POST".into(), p.accent, false)));
        assert!(sections.contains(&("Content-Type".into(), p.name, false)));
        assert!(sections.contains(&("\"id\"".into(), p.key, false)));
        assert!(sections.contains(&("5".into(), p.number, false)));
        assert!(sections.contains(&("true".into(), p.literal, false)));
        assert!(sections.contains(&("\"a\\\"b\"".into(), p.string, false)));
        let html = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<a href=\"/x\">hi<!-- c --></a>";
        let sections = colours(html, Kind::Http, "");
        assert!(sections.iter().any(|(t, c, _)| t == "<a" && *c == p.accent));
        assert!(
            sections
                .iter()
                .any(|(t, c, _)| t == "\"/x\"" && *c == p.string)
        );
        assert!(
            sections
                .iter()
                .any(|(t, c, _)| t == "<!-- c -->" && *c == p.weak)
        );
        let form =
            "POST / HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nuser=al&pw=x";
        let sections = colours(form, Kind::Http, "");
        assert!(sections.contains(&("user".into(), p.key, false)));
        assert!(sections.contains(&("&".into(), p.weak, false)));
        // Unterminated and binary-looking input must not panic or lose text.
        colours("GET / HTTP/1.1\n\n{\"open", Kind::Http, "");
        colours("<a href='x", Kind::Plain, "a");
        colours("é\u{0}ü", Kind::Json, "ü");
        colours("HTTP/1.1", Kind::Http, "");
        colours("HTTP/1.1 200", Kind::Http, "1");
        colours("{\"a\\é", Kind::Json, "");
    }

    #[test]
    fn find_highlights_case_insensitive_matches_across_tokens() {
        assert_eq!(matches("Token token TOKEN", "token").len(), 3);
        assert!(matches("abc", "").is_empty());
        let sections = colours(
            "GET /search?q=Secret HTTP/1.1\r\nX-Secret: 1\r\n\r\n",
            Kind::Http,
            "secret",
        );
        let highlighted: Vec<_> = sections
            .iter()
            .filter(|s| s.2)
            .map(|s| s.0.as_str())
            .collect();
        assert_eq!(highlighted, ["Secret", "Secret"]);
    }
}

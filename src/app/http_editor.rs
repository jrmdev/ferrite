use eframe::egui;

pub(super) fn message_view(bytes: &[u8], all_hex: bool) -> String {
    if all_hex {
        return super::hex(bytes);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// The scroll viewport stays bounded; text grows downwards and wraps at its width.
pub(super) fn http_editor(
    ui: &mut egui::Ui,
    text: &mut dyn egui::TextBuffer,
    document: impl std::hash::Hash,
) -> egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput> {
    editor(ui, text, document, Content::Http)
}

pub(super) fn websocket_editor(
    ui: &mut egui::Ui,
    text: &mut dyn egui::TextBuffer,
    document: impl std::hash::Hash,
    hex: bool,
) -> egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput> {
    editor(
        ui,
        text,
        document,
        if hex { Content::Raw } else { Content::Json },
    )
}

/// Pending messages must always edit the original payload directly.
pub(super) fn websocket_intercept_editor(
    ui: &mut egui::Ui,
    text: &mut dyn egui::TextBuffer,
    document: impl std::hash::Hash,
    hex: bool,
) -> egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput> {
    let id = ui.make_persistent_id(("http-editor", document));
    let kind = if hex {
        super::highlight::Kind::Plain
    } else {
        super::highlight::Kind::Json
    };
    render(ui, text, id, kind)
}

enum Content {
    Http,
    Json,
    Raw,
}

fn editor(
    ui: &mut egui::Ui,
    text: &mut dyn egui::TextBuffer,
    document: impl std::hash::Hash,
    content: Content,
) -> egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput> {
    let id = ui.make_persistent_id(("http-editor", document));
    let kind = match content {
        Content::Http => super::highlight::Kind::Http,
        Content::Json => super::highlight::Kind::Json,
        Content::Raw => super::highlight::Kind::Plain,
    };
    let preview = match content {
        Content::Http => super::json_preview::preview(ui.ctx(), id, text.as_str()),
        Content::Json => super::json_preview::preview_payload(ui.ctx(), id, text.as_str()),
        Content::Raw => None,
    };
    if let Some((key, preview)) = preview {
        let mut edit = ui
            .data(|data| data.get_temp::<bool>(key.with("edit")))
            .unwrap_or(false);
        if text.is_mutable() && ui.button(if edit { "Preview" } else { "Edit" }).clicked() {
            edit = !edit;
        }
        ui.data_mut(|data| data.insert_temp(key.with("edit"), edit));
        if !text.is_mutable() || !edit {
            return render(ui, &mut preview.as_ref(), key, kind);
        }
    }
    render(ui, text, id, kind)
}

fn render(
    ui: &mut egui::Ui,
    text: &mut dyn egui::TextBuffer,
    id: egui::Id,
    kind: super::highlight::Kind,
) -> egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput> {
    let mut layouter = super::highlight::layouter(kind, id);
    let viewport = ui.available_rect_before_wrap().intersect(ui.clip_rect());
    let available = viewport.size();
    let height = available.y.max(1.0);
    let background = super::theme::message_background(ui.visuals());
    // TextEdit only fills editable buffers; paint the viewport for read-only
    // messages too, including the space below short messages and the scroll bar.
    ui.painter().rect_filled(
        viewport,
        ui.visuals().widgets.inactive.corner_radius,
        background,
    );
    egui::ScrollArea::vertical()
        .id_salt(id.with("scroll"))
        .auto_shrink([false, false])
        .min_scrolled_height(0.0)
        .max_height(height)
        .max_width(available.x.max(1.0))
        .show(ui, |ui| {
            // add_sized centers oversized widgets, which can move long HTTP messages
            // outside the viewport. A minimum height fills the pane without that layout.
            egui::TextEdit::multiline(text)
                .id(id.with("text"))
                .background_color(background)
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .desired_rows(1)
                .min_size(egui::vec2(0.0, height))
                .horizontal_align(egui::Align::Min)
                .vertical_align(egui::Align::Min)
                .cursor_at_end(false)
                .code_editor()
                .layouter(&mut layouter)
                .show(ui)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_preview_changes_the_view_without_modifying_editable_or_read_only_messages() {
        let ctx = egui::Context::default();
        let original = "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"x\":1,\"x\":2}";
        let mut draft = original.to_owned();
        super::super::json_preview::configure(&ctx, true, 1);
        let viewed = render(&ctx, &mut draft, 600.0, 1);
        assert!(
            viewed
                .inner
                .galley
                .job
                .text
                .contains("\n  \"x\": 1,\n  \"x\": 2\n")
        );
        assert_eq!(draft, original);
        assert!(!viewed.inner.response.changed());
        let mut read_only = original;
        let viewed = render(&ctx, &mut read_only, 600.0, 2);
        assert!(viewed.inner.galley.job.text.contains("\n  \"x\": 1,"));
        assert_eq!(read_only, original);
        super::super::json_preview::configure(&ctx, false, 1);
        assert_eq!(
            render(&ctx, &mut draft, 600.0, 1).inner.galley.job.text,
            original
        );
        assert_eq!(draft, original);
    }

    #[test]
    fn websocket_preview_preserves_pending_payload_and_hex_view() {
        let ctx = egui::Context::default();
        super::super::json_preview::configure(&ctx, true, 1);
        let original = "{\"value\":1,\"value\":2}";
        let mut payload = original.to_owned();
        let mut viewed = None;
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                viewed = Some(websocket_editor(ui, &mut payload, "ws-json", false));
            });
        });
        assert_eq!(payload, original);
        assert!(
            viewed
                .as_ref()
                .unwrap()
                .inner
                .galley
                .job
                .text
                .contains("\n  \"value\": 1,\n")
        );
        let mut hex = super::super::hex(original.as_bytes());
        let expected = hex.clone();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                viewed = Some(websocket_editor(ui, &mut hex, "ws-hex", true));
            });
        });
        assert_eq!(viewed.unwrap().inner.galley.job.text, expected);
        assert_eq!(hex, expected);
    }

    #[test]
    fn websocket_intercept_edits_original_json_even_when_beautify_is_enabled() {
        let ctx = egui::Context::default();
        super::super::json_preview::configure(&ctx, true, 1);
        let mut payload = "{\"value\":1}".to_owned();
        let mut viewed = None;
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                viewed = Some(websocket_intercept_editor(
                    ui,
                    &mut payload,
                    "ws-pending",
                    false,
                ));
            });
        });
        let editor = viewed.unwrap().inner;
        assert_eq!(editor.galley.job.text, "{\"value\":1}");
        editor.response.request_focus();
        let _ = ctx.run(
            egui::RawInput {
                events: vec![egui::Event::Text("x".into())],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    websocket_intercept_editor(ui, &mut payload, "ws-pending", false);
                });
            },
        );
        assert!(payload.contains('x'));
    }

    #[test]
    fn binary_messages_display_directly_and_hex_is_explicit() {
        let head = b"HTTP/2 200\r\nContent-Type: application/octet-stream\r\n\r\n";
        let body: Vec<_> = (0..=255).collect();
        let bytes = [head.as_slice(), &body].concat();
        let view = message_view(&bytes, false);
        assert_eq!(view, String::from_utf8_lossy(&bytes));
        assert!(view.starts_with(std::str::from_utf8(head).unwrap()));
        assert_eq!(
            super::super::unhex(&message_view(&bytes, true)).unwrap(),
            bytes
        );
        assert_eq!(
            message_view(b"HTTP/1.1 200 OK\r\n\r\n\0a\0", false),
            "HTTP/1.1 200 OK\r\n\r\n\0a\0"
        );
        let output = render(&egui::Context::default(), &mut view.as_str(), 350.0, 1);
        assert_visible_at_start(&output);
        assert_eq!(output.inner.galley.job.text, view);
    }

    #[test]
    fn text_empty_and_header_only_messages_are_unchanged() {
        for bytes in [
            b"".as_slice(),
            b"HTTP/2 204\r\nX-Test: 1\r\n\r\n",
            "HTTP/2 200\r\n\r\nHello π\n".as_bytes(),
        ] {
            assert_eq!(message_view(bytes, false).as_bytes(), bytes);
        }
    }

    fn render(
        ctx: &egui::Context,
        text: &mut dyn egui::TextBuffer,
        width: f32,
        document: u64,
    ) -> egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput> {
        let mut editor = None;
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 260.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    editor = Some(http_editor(ui, text, document));
                });
            },
        );
        editor.unwrap()
    }

    fn assert_visible_at_start(
        output: &egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput>,
    ) {
        let editor = &output.inner;
        assert!(editor.galley_pos.x >= output.inner_rect.left());
        assert!(editor.galley_pos.x < output.inner_rect.left() + 10.0);
        assert!(editor.galley_pos.y >= output.inner_rect.top());
        assert!(editor.galley_pos.y < output.inner_rect.top() + 10.0);
        assert!(editor.response.rect.width() <= output.inner_rect.width() + 0.5);
        assert!(output.state.offset.x.abs() < 0.5);
        for row in &editor.galley.rows {
            assert!(
                row.size.x <= editor.text_clip_rect.width() + 0.5,
                "Row exceeds editor width"
            );
        }
    }

    #[test]
    fn long_headers_and_unbroken_body_wrap_without_hiding_message_start() {
        let ctx = egui::Context::default();
        let mut text = format!(
            "HTTP/1.1 200 OK\r\nX-Long: {}\r\n\r\n{}",
            "header ".repeat(120),
            "x".repeat(5000)
        );
        let original = text.clone();
        let wide = render(&ctx, &mut text, 720.0, 1);
        assert_visible_at_start(&wide);
        let narrow = render(&ctx, &mut text, 250.0, 1);
        assert_visible_at_start(&narrow);
        assert!(narrow.inner.galley.rows.len() > wide.inner.galley.rows.len());
        let wide_again = render(&ctx, &mut text, 720.0, 1);
        assert_visible_at_start(&wide_again);
        assert_eq!(text, original);
    }

    #[test]
    fn read_only_responses_remain_visible_after_empty_and_long_messages() {
        let ctx = egui::Context::default();
        let mut empty = "";
        render(&ctx, &mut empty, 350.0, 1);
        let long = format!(
            "HTTP/2 200\r\nContent-Type: text/html\r\n\r\n{}",
            "body ".repeat(1000)
        );
        let mut borrowed = long.as_str();
        let output = render(&ctx, &mut borrowed, 350.0, 2);
        assert_visible_at_start(&output);
        assert_eq!(output.inner.galley.job.text, long);
        let mut state = output.state;
        state.offset.y = 500.0;
        state.store(&ctx, output.id);
        let scrolled = render(&ctx, &mut borrowed, 350.0, 2);
        assert!(scrolled.state.offset.y > 0.0);
        let mut next = "HTTP/2 204\r\nX-Next: visible\r\n\r\n";
        let next_output = render(&ctx, &mut next, 350.0, 3);
        assert_visible_at_start(&next_output);
        assert_eq!(next_output.inner.galley.job.text, next);
    }
}

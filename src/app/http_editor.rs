use super::highlight;
use crate::engine::Stage;
use eframe::egui::{
    self,
    text::{CCursor, CCursorRange},
};
use std::borrow::Cow;

pub(super) fn message_view(bytes: &[u8], all_hex: bool) -> Cow<'_, str> {
    if all_hex {
        return Cow::Owned(super::hex(bytes));
    }
    String::from_utf8_lossy(bytes)
}

pub(super) enum Find<'a> {
    Text(Stage),
    WithHex(Stage, &'a mut bool),
}

/// The scroll viewport stays bounded; text grows downwards and wraps at its width.
pub(super) fn http_editor(
    ui: &mut egui::Ui,
    text: &mut dyn egui::TextBuffer,
    document: impl std::hash::Hash,
    find: Option<Find<'_>>,
) -> egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput> {
    editor(ui, text, document, Content::Http, find)
}

/// Keep the request draft editable even when its body can be previewed as JSON.
pub(super) fn editable_http_editor(
    ui: &mut egui::Ui,
    text: &mut String,
    document: impl std::hash::Hash,
    find: Find<'_>,
) -> egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput> {
    let id = ui.make_persistent_id(("http-editor", document));
    render(ui, text, id, highlight::Kind::Http, Some(find))
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
        None,
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
        highlight::Kind::Plain
    } else {
        highlight::Kind::Json
    };
    render(ui, text, id, kind, None)
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
    find: Option<Find<'_>>,
) -> egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput> {
    let id = ui.make_persistent_id(("http-editor", document));
    let kind = match content {
        Content::Http => highlight::Kind::Http,
        Content::Json => highlight::Kind::Json,
        Content::Raw => highlight::Kind::Plain,
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
            return render(ui, &mut preview.as_ref(), key, kind, find);
        }
    }
    render(ui, text, id, kind, find)
}

#[derive(Clone, Default)]
struct FindState {
    term: String,
    document: Option<egui::Id>,
    current: Option<usize>,
}

impl FindState {
    fn show(&mut self, ui: &mut egui::Ui, text: &str, find: Find<'_>) -> Option<CCursorRange> {
        let (stage, hex) = match find {
            Find::Text(stage) => (stage, None),
            Find::WithHex(stage, hex) => (stage, Some(hex)),
        };
        let hint = match stage {
            Stage::Request => "Find text in request",
            Stage::Response => "Find text in response",
        };
        ui.horizontal_wrapped(|ui| {
            if let Some(hex) = hex {
                if ui.checkbox(hex, "Hex").changed() {
                    // The caller uses the new mode when preparing the message for the next frame.
                    ui.ctx().request_repaint();
                }
                if ui.available_size_before_wrap().x < 170.0 {
                    ui.end_row();
                }
            }
            let width = ui.available_size_before_wrap().x;
            let search_width = (width * 0.65).min(width - 52.0).clamp(24.0, 260.0);
            if ui
                .add(
                    egui::TextEdit::singleline(&mut self.term)
                        .hint_text(hint)
                        .desired_width(search_width),
                )
                .changed()
            {
                self.current = None;
            }

            let count = highlight::matches(text, &self.term).count();
            self.current = self.current.filter(|&index| index < count);
            let previous = ui
                .add_enabled(count > 0, egui::Button::new("<"))
                .on_hover_text("Previous match")
                .clicked();
            let next = ui
                .add_enabled(count > 0, egui::Button::new(">"))
                .on_hover_text("Next match")
                .clicked();
            let selection = if previous || next {
                let index = match (previous, self.current) {
                    (true, Some(index)) if index > 0 => index - 1,
                    (true, _) => count - 1,
                    (false, Some(index)) => (index + 1) % count,
                    (false, None) => 0,
                };
                self.current = Some(index);
                let (start, end) = highlight::matches(text, &self.term).nth(index).unwrap();
                let first = text[..start].chars().count();
                let last = first + text[start..end].chars().count();
                Some(CCursorRange::two(CCursor::new(first), CCursor::new(last)))
            } else {
                None
            };

            if !self.term.is_empty() {
                let width = ui.available_size_before_wrap().x;
                if width >= 44.0 && ui.small_button("Clear").clicked() {
                    self.term.clear();
                    self.current = None;
                } else if ui.available_size_before_wrap().x > 0.0 {
                    let status = match self.current {
                        Some(index) => format!("{} / {count}", index + 1),
                        None if count == 1 => "1 match".into(),
                        None => format!("{count} matches"),
                    };
                    ui.add(egui::Label::new(egui::RichText::new(status).weak()).truncate());
                }
            }
            selection
        })
        .inner
    }
}

fn render(
    ui: &mut egui::Ui,
    text: &mut dyn egui::TextBuffer,
    id: egui::Id,
    kind: highlight::Kind,
    find: Option<Find<'_>>,
) -> egui::scroll_area::ScrollAreaOutput<egui::text_edit::TextEditOutput> {
    let mut search = FindState::default();
    let mut selection = None;
    let search_id = ui.make_persistent_id("message-find");
    let has_find = find.is_some();
    if let Some(find) = find {
        search = ui.data(|data| data.get_temp(search_id)).unwrap_or_default();
        if search.document != Some(id) {
            search.document = Some(id);
            search.current = None;
        }
        selection = egui::TopBottomPanel::bottom(search_id)
            .resizable(false)
            .frame(egui::Frame::NONE)
            .show_inside(ui, |ui| search.show(ui, text.as_str(), find))
            .inner;
    }

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
    let output = egui::ScrollArea::vertical()
        .id_salt(id.with("scroll"))
        .auto_shrink([false, false])
        .min_scrolled_height(0.0)
        .max_height(height)
        .max_width(available.x.max(1.0))
        .show(ui, |ui| {
            let mut layouter = highlight::layouter(kind, id, &search.term);
            // add_sized centers oversized widgets, which can move long HTTP messages
            // outside the viewport. A minimum height fills the pane without that layout.
            let edit = egui::TextEdit::multiline(text)
                .background_color(background)
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .desired_rows(1)
                .min_size(egui::vec2(0.0, height))
                .horizontal_align(egui::Align::Min)
                .vertical_align(egui::Align::Min)
                .cursor_at_end(false)
                .code_editor()
                .layouter(&mut layouter);
            let mut output = super::editor_context::show(ui, id.with("text"), edit);
            if let Some(range) = selection {
                output.state.cursor.set_char_range(Some(range));
                output.state.clone().store(ui.ctx(), output.response.id);
                // The arrow click can clear focus while TextEdit is drawing.
                output.response.request_focus();
                ui.ctx().request_repaint();
                let start = output.galley.pos_from_cursor(range.secondary);
                let end = output.galley.pos_from_cursor(range.primary);
                ui.scroll_to_rect(
                    start.union(end).translate(output.galley_pos.to_vec2()),
                    None,
                );
            }
            output
        });
    if has_find {
        if output.inner.response.changed() {
            search.current = None;
        }
        ui.data_mut(|data| data.insert_temp(search_id, search));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn right_click_preserves_and_copies_the_message_editor_selection() {
        let ctx = egui::Context::default();
        let mut text = "GET / HTTP/1.1\r\n\r\nπ and café".to_owned();
        let mut frame = |events| {
            let mut editor = None;
            let output = ctx.run(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let output = http_editor(ui, &mut text, "right-click", None).inner;
                        super::super::editor_menu(&output, false, None);
                        editor = Some(output);
                    });
                },
            );
            (editor.unwrap(), output)
        };
        let (editor, _) = frame(vec![]);
        let range = CCursorRange::two(CCursor::new(18), CCursor::new(28));
        let mut state = editor.state;
        state.cursor.set_char_range(Some(range));
        state.store(&ctx, editor.response.id);
        editor.response.request_focus();

        let pos = editor.response.rect.left_top() + egui::vec2(120.0, 7.0);
        let click = |pos, button, pressed| egui::Event::PointerButton {
            pos,
            button,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        frame(vec![egui::Event::PointerMoved(pos)]);
        for pressed in [true, false] {
            let (editor, _) = frame(vec![click(pos, egui::PointerButton::Secondary, pressed)]);
            assert_eq!(editor.state.cursor.char_range(), Some(range));
            assert_eq!(editor.cursor_range, Some(range));
        }
        let (_, menu) = frame(vec![]);
        let position = |output: &egui::FullOutput, label| {
            output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::Shape::Text(text) if text.galley.text() == label => {
                        Some(text.visual_bounding_rect().center())
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("Missing menu item {label}"))
        };
        let copy = position(&menu, "Copy");
        frame(vec![egui::Event::PointerMoved(copy)]);
        frame(vec![click(copy, egui::PointerButton::Primary, true)]);
        frame(vec![click(copy, egui::PointerButton::Primary, false)]);
        let (_, submenu) = frame(vec![]);
        let selection = position(&submenu, "Selection");
        frame(vec![egui::Event::PointerMoved(selection)]);
        frame(vec![click(selection, egui::PointerButton::Primary, true)]);
        let (_, output) = frame(vec![click(selection, egui::PointerButton::Primary, false)]);
        assert!(output.platform_output.commands.iter().any(|command| {
            matches!(command, egui::OutputCommand::CopyText(text) if text == "π and café")
        }));
        assert_eq!(frame(vec![]).0.cursor_range, Some(range));
    }

    #[test]
    fn message_find_navigates_and_scrolls_only_its_own_pane() {
        let ctx = egui::Context::default();
        ctx.style_mut(|style| style.scroll_animation = egui::style::ScrollAnimation::none());
        let mut request = "GET /needle HTTP/1.1\r\n\r\n".to_owned();
        let response = format!(
            "HTTP/1.1 200 OK\r\n\r\nπ needle\n{}needle\n{}",
            "filler\n".repeat(100),
            "filler\n".repeat(30),
        );
        let mut request_hex = false;
        let mut response_hex = false;
        let mut frame = |events| {
            let mut editors = None;
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(840.0, 260.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let [mut left, mut right] =
                            super::super::split_panes(ui, "test-messages", false, 0.5);
                        editors = Some([
                            http_editor(
                                &mut left,
                                &mut request,
                                1,
                                Some(Find::WithHex(Stage::Request, &mut request_hex)),
                            ),
                            http_editor(
                                &mut right,
                                &mut response.as_str(),
                                2,
                                Some(Find::WithHex(Stage::Response, &mut response_hex)),
                            ),
                        ]);
                    });
                },
            );
            (output.shapes, editors.unwrap())
        };
        let position = |shapes: &[egui::epaint::ClippedShape], label: &str| {
            shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::Shape::Text(text)
                        if text.galley.job.text == label && text.pos.x > 420.0 =>
                    {
                        Some(text.visual_bounding_rect().center())
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("Missing response find control {label:?}"))
        };
        let click = |pos| {
            let button = |pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            vec![egui::Event::PointerMoved(pos), button(true), button(false)]
        };

        let (shapes, [_, pane]) = frame(vec![]);
        let query = position(&shapes, "Find text in response");
        assert!(query.y > pane.inner_rect.bottom());
        frame(click(query));
        let (shapes, [request, pane]) = frame(vec![egui::Event::Text("needle".into())]);
        let has_highlights = |galley: &egui::Galley| {
            galley
                .job
                .sections
                .iter()
                .any(|s| s.format.background != egui::Color32::TRANSPARENT)
        };
        assert!(!has_highlights(&request.inner.galley));
        assert!(has_highlights(&pane.inner.galley));

        frame(click(position(&shapes, ">")));
        let (shapes, [_, pane]) = frame(vec![]);
        let first = pane.inner.cursor_range.unwrap();
        assert_eq!(first.slice_str(&response), "needle");
        assert_eq!(pane.state.offset.y, 0.0);

        frame(click(position(&shapes, "<")));
        let (shapes, [_, pane]) = frame(vec![]);
        let last = pane.inner.cursor_range.unwrap();
        assert_eq!(last.slice_str(&response), "needle");
        assert!(last.primary.index > first.primary.index);
        assert!(pane.state.offset.y > 0.0);
        let (_, [_, pane]) = frame(vec![]);
        let match_pos = pane
            .inner
            .galley
            .pos_from_cursor(last.primary)
            .translate(pane.inner.galley_pos.to_vec2());
        assert!(
            pane.inner_rect.contains_rect(match_pos),
            "Match at {match_pos:?} is outside {:?}",
            pane.inner_rect,
        );
        let scrolled_offset = pane.state.offset.y;

        frame(click(position(&shapes, ">")));
        let (shapes, [_, pane]) = frame(vec![]);
        assert_eq!(pane.inner.cursor_range, Some(first));
        assert!(pane.state.offset.y < scrolled_offset);

        let hex_checkbox = position(&shapes, "Hex");
        assert!(hex_checkbox.y > pane.inner_rect.bottom());
        assert!((hex_checkbox.y - position(&shapes, "needle").y).abs() < 4.0);
        frame(click(hex_checkbox));
        assert!(response_hex);
        assert!(!request_hex);
    }

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
        let output = render(&egui::Context::default(), &mut view.as_ref(), 350.0, 1);
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
            let view = message_view(bytes, false);
            assert!(matches!(view, Cow::Borrowed(_)));
            assert_eq!(view.as_bytes(), bytes);
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
                    editor = Some(http_editor(
                        ui,
                        text,
                        document,
                        Some(Find::Text(Stage::Response)),
                    ));
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

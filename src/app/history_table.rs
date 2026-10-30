use super::history_viewport::HistoryViewport;
use super::{EntryAction, entry_menu, history_selection::HistorySelection, timestamp};
use crate::display_timezone::DisplayTimezone;
use crate::history::{Annotation, short_content_type};
use crate::model::Exchange;
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::cmp::Ordering;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum SortColumn {
    #[default]
    Id,
    Timestamp,
    Status,
    Type,
    Bytes,
    Duration,
    Tool,
    Method,
    Comment,
    Url,
}

const COLUMNS: [(SortColumn, &str, f32); 10] = [
    (SortColumn::Id, "#", 50.0),
    (SortColumn::Timestamp, "Timestamp", 200.0),
    (SortColumn::Status, "Status", 70.0),
    (SortColumn::Type, "Type", 100.0),
    (SortColumn::Bytes, "Bytes", 80.0),
    (SortColumn::Duration, "Duration (ms)", 100.0),
    (SortColumn::Tool, "Tool", 80.0),
    (SortColumn::Method, "Method", 70.0),
    (SortColumn::Comment, "Comment", 140.0),
    (SortColumn::Url, "URL", 240.0),
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct HistorySort {
    column: SortColumn,
    descending: bool,
}

impl Default for HistorySort {
    fn default() -> Self {
        Self {
            column: SortColumn::Id,
            descending: true,
        }
    }
}

impl HistorySort {
    fn select(&mut self, column: SortColumn) {
        if self.column == column {
            self.descending = !self.descending;
        } else {
            self.column = column;
            self.descending = false;
        }
    }

    #[cfg(test)]
    fn compare(&self, a: &Exchange, b: &Exchange) -> Ordering {
        self.compare_with(a, b, &BTreeMap::new())
    }

    fn compare_with(
        &self,
        a: &Exchange,
        b: &Exchange,
        annotations: &BTreeMap<u64, Annotation>,
    ) -> Ordering {
        let comment = |id| {
            annotations
                .get(&id)
                .map_or("", |a: &Annotation| a.comment.as_str())
        };
        let order = match self.column {
            SortColumn::Id => a.id.cmp(&b.id),
            SortColumn::Timestamp => a.timestamp_ms.cmp(&b.timestamp_ms),
            SortColumn::Status => a.status.cmp(&b.status),
            SortColumn::Type => {
                short_content_type(&a.response).cmp(&short_content_type(&b.response))
            }
            SortColumn::Bytes => a.response.len().cmp(&b.response.len()),
            SortColumn::Duration => a.duration_ms.cmp(&b.duration_ms),
            SortColumn::Tool => a.tool.cmp(&b.tool),
            SortColumn::Method => a.method.cmp(&b.method),
            SortColumn::Comment => comment(a.id).cmp(comment(b.id)),
            SortColumn::Url => a.url.cmp(&b.url),
        }
        .then_with(|| a.id.cmp(&b.id));
        if self.descending {
            order.reverse()
        } else {
            order
        }
    }
}

/// How the table is presented: which history it shows and with what notes.
pub(super) struct TableView<'a> {
    pub intruder: bool,
    pub timezone: DisplayTimezone,
    pub annotations: &'a BTreeMap<u64, Annotation>,
}

pub(super) fn show(
    ui: &mut egui::Ui,
    rows: &mut [&Exchange],
    selection: &mut HistorySelection,
    sort: &mut HistorySort,
    viewport: &mut HistoryViewport,
    view: TableView<'_>,
) -> Option<(Vec<u64>, EntryAction)> {
    let TableView {
        intruder,
        timezone,
        annotations,
    } = view;
    let mut action = None;
    let original_sort = *sort;
    rows.sort_unstable_by(|a, b| sort.compare_with(a, b, annotations));
    let initial_ids: Vec<_> = rows.iter().map(|flow| flow.id).collect();
    let offset = viewport.offset_for(&initial_ids, *sort);
    let invert_stripes = viewport.invert_stripes_for(&initial_ids, *sort);
    let height = ui.available_height();
    let entry_id = ui.id().with(("history-entry", intruder));
    let focus_id = ui.id().with(("history-keyboard", intruder));
    selection.retain_visible(&initial_ids);
    let target = super::table_arrow_navigation(
        ui,
        focus_id,
        selection
            .focused
            .and_then(|id| initial_ids.iter().position(|row| *row == id)),
        initial_ids.len(),
    );
    if let Some(index) = target {
        selection.click(initial_ids[index], &initial_ids, false, false, false);
    }
    egui::ScrollArea::horizontal()
        .id_salt(("history-horizontal", intruder))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            super::compact_rows(ui);
            let mut table = TableBuilder::new(ui)
                .id_salt(("history-table", intruder))
                .striped(false)
                .resizable(true)
                .vertical_scroll_offset(offset)
                .animate_scrolling(false)
                .stick_to_bottom(false)
                // Rows have exchange IDs below; the table's index-based cell IDs must
                // not own hover/click state when captures change their row indexes.
                .sense(egui::Sense::hover())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .min_scrolled_height(0.0)
                .max_scroll_height((height - 26.0).max(0.0))
                .auto_shrink([false, false]);
            if let Some(index) = target { table = table.scroll_to_row(index, None); }
            for (column, _, width) in COLUMNS {
                table = table.column(if column == SortColumn::Url {
                    Column::remainder().at_least(400.0).clip(true)
                } else { Column::initial(width).at_least(40.0).clip(true) });
            }
            let output = table.header(24.0, |mut header| {
                for (column, title, _) in COLUMNS {
                    header.col(|ui| {
                        let response = ui.add_sized(ui.available_size(), egui::Button::new(title).frame(false))
                            .on_hover_text("Click to sort; click again to reverse. Drag column borders to resize.");
                        let response = if column == SortColumn::Timestamp {
                            response.on_hover_text(format!("Display timezone: {}", timezone.label()))
                        } else { response };
                        if response.clicked() { sort.select(column); }
                        if sort.column == column {
                            let center = egui::pos2(response.rect.right() - 7.0, response.rect.center().y);
                            let direction = if sort.descending { 1.0 } else { -1.0 };
                            let points = vec![center + egui::vec2(-3.0, -2.0 * direction),
                                center + egui::vec2(3.0, -2.0 * direction),
                                center + egui::vec2(0.0, 3.0 * direction)];
                            ui.painter().add(egui::Shape::convex_polygon(points,
                                ui.visuals().text_color(), egui::Stroke::NONE));
                        }
                    });
                }
            }).body(|mut body| {
                // Sort after rendering headers so a click updates rows in the same frame.
                rows.sort_unstable_by(|a, b| sort.compare_with(a, b, annotations));
                let visible: Vec<_> = rows.iter().map(|flow| flow.id).collect();
                selection.retain_visible(&visible);
                // Insert the stripes behind the cells so selection/hover fills still take precedence.
                let painter = body.ui_mut().painter().clone();
                let background = painter.add(egui::Shape::Noop);
                let stripe_color = body.ui_mut().visuals().faint_bg_color;
                let hover_color = body.ui_mut().visuals().widgets.hovered.bg_fill;
                let dark = body.ui_mut().visuals().dark_mode;
                let spacing = body.ui_mut().spacing().item_spacing;
                let row_width = body.widths().iter().sum::<f32>()
                    + spacing.x * (body.widths().len() - 1) as f32;
                let interactions = body.ui_mut().new_child(egui::UiBuilder::new().id_salt("row-interactions"));
                let mut stripes = Vec::new();
                body.rows(20.0, rows.len(), |mut row| {
                    let striped = row.index().is_multiple_of(2) != invert_stripes;
                    let flow = rows[row.index()];
                    let row_id = entry_id.with(flow.id);
                    let selected = selection.ids.contains(&flow.id);
                    row.set_selected(selected);
                    row.set_hovered(false);
                    let values = [flow.id.to_string(), timestamp(flow.timestamp_ms, timezone),
                        if flow.error.is_some() { format!("{} (error)", flow.status) } else { flow.status.to_string() },
                        short_content_type(&flow.response),
                        flow.response.len().to_string(), flow.duration_ms.to_string(),
                        flow.tool.clone(), flow.method.clone(),
                        annotations.get(&flow.id).map(|a| a.comment.lines().next().unwrap_or("").to_string()).unwrap_or_default(),
                        flow.url.clone()];
                    let mut rect = egui::Rect::NOTHING;
                    let mut response = None;
                    for (column, value) in values.into_iter().enumerate() {
                        row.col(|ui| {
                            // Ui::response() can contain last frame's geometry. Capture
                            // this frame's cell bounds for both stripes and hit testing.
                            rect = rect.union(ui.max_rect());
                            if column == 0 {
                                // Register the row before its labels, so their hover
                                // tooltips stay above the row's click target.
                                let hit_rect = egui::Rect::from_min_size(ui.max_rect().min,
                                    egui::vec2(row_width, ui.max_rect().height()));
                                response = Some(interactions.interact(hit_rect, row_id, egui::Sense::click()));
                            }
                            ui.scope_builder(egui::UiBuilder::new().id(row_id.with(column)), |ui| {
                                let text: egui::WidgetText = match COLUMNS[column].0 {
                                    SortColumn::Timestamp => super::theme::timestamp_text(ui, &value,
                                        egui::TextStyle::Body.resolve(ui.style()), ui.visuals().text_color()).into(),
                                    SortColumn::Status => egui::RichText::new(&value)
                                        .color(super::theme::status_color(ui.visuals(), flow.status)).into(),
                                    SortColumn::Url => url_text(ui, &value).into(),
                                    _ => value.into(),
                                };
                                ui.add(egui::Label::new(text).truncate().selectable(false));
                            });
                        });
                    }
                    let response = response.unwrap();
                    let highlight = annotations.get(&flow.id).and_then(|a| a.highlight).map(|h| {
                        let [r, g, b] = h.rgb();
                        egui::Color32::from_rgba_unmultiplied(r, g, b, if dark { 70 } else { 90 })
                    });
                    let fill = if response.hovered() && !selected { Some(hover_color) }
                        else if highlight.is_some() { highlight }
                        else if striped { Some(stripe_color) } else { None };
                    if let Some(fill) = fill {
                        stripes.push(egui::Shape::rect_filled(rect.expand2(spacing * 0.5),
                            egui::CornerRadius::ZERO, fill));
                    }
                    if response.clicked() || response.secondary_clicked() {
                        response.ctx.memory_mut(|memory| memory.request_focus(focus_id));
                        let modifiers = response.ctx.input(|input| input.modifiers);
                        selection.click(flow.id, &visible, modifiers.command || modifiers.ctrl,
                            modifiers.shift, response.secondary_clicked());
                    }
                    if let Some(value) = entry_menu(&response, true) {
                        let ids = if matches!(value, EntryAction::Intruder | EntryAction::CopyUrl
                            | EntryAction::CopyCurl | EntryAction::CopyPython | EntryAction::CopyMessage(_)
                            | EntryAction::Comparer(..) | EntryAction::Decoder(_)) { vec![flow.id] }
                            else { visible.iter().filter(|id| selection.ids.contains(id)).copied().collect() };
                        action = Some((ids, value));
                    }
                    let comment = annotations.get(&flow.id).map(|a| a.comment.as_str()).filter(|c| !c.is_empty());
                    match (&flow.error, comment) {
                        (Some(error), Some(comment)) => { response.on_hover_text(format!("{comment}\n{error}")); }
                        (Some(error), None) => { response.on_hover_text(error); }
                        (None, Some(comment)) => { response.on_hover_text(comment); }
                        (None, None) => {}
                    }
                });
                painter.set(background, egui::Shape::Vec(stripes));
            });
            let ids: Vec<_> = rows.iter().map(|flow| flow.id).collect();
            viewport.record(&ids, output.state.offset.y, original_sort, invert_stripes);
        });
    action
}

fn url_text(ui: &egui::Ui, url: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let query_start = url.find('?').unwrap_or(url.len());
    let font_id = egui::TextStyle::Body.resolve(ui.style());
    job.append(
        &url[..query_start],
        0.0,
        egui::TextFormat::simple(font_id.clone(), ui.visuals().text_color()),
    );
    if query_start < url.len() {
        let grey = if ui.visuals().dark_mode { 160 } else { 104 };
        job.append(
            &url[query_start..],
            0.0,
            egui::TextFormat::simple(font_id, egui::Color32::from_gray(grey)),
        );
    }
    job
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Destination;

    #[derive(Debug, PartialEq)]
    enum RowPaint {
        Fill(egui::Rect, egui::Color32),
        Text(egui::Rect, egui::Pos2, String),
    }

    fn painted_rows(output: &egui::FullOutput) -> Vec<RowPaint> {
        fn collect(shape: &egui::Shape, clip: egui::Rect, out: &mut Vec<RowPaint>) {
            match shape {
                egui::Shape::Vec(shapes) => {
                    for shape in shapes {
                        collect(shape, clip, out);
                    }
                }
                egui::Shape::Rect(shape) if shape.fill != egui::Color32::TRANSPARENT => {
                    let rect = shape.rect.intersect(clip);
                    if rect.is_positive() {
                        out.push(RowPaint::Fill(rect, shape.fill));
                    }
                }
                egui::Shape::Text(text)
                    if shape.visual_bounding_rect().intersect(clip).is_positive() =>
                {
                    out.push(RowPaint::Text(clip, text.pos, text.galley.job.text.clone()));
                }
                _ => {}
            }
        }
        let mut paint = Vec::new();
        // Exclude headers and scroll bars, whose counts/ranges legitimately change.
        let region = egui::Rect::from_min_max(egui::pos2(20.0, 60.0), egui::pos2(430.0, 350.0));
        for clipped in &output.shapes {
            collect(
                &clipped.shape,
                clipped.clip_rect.intersect(region),
                &mut paint,
            );
        }
        paint
    }

    #[test]
    fn arrow_keys_move_clicked_selection_and_scroll_to_it() {
        let ctx = egui::Context::default();
        let mut selection = HistorySelection::default();
        let mut sort = HistorySort::default();
        let mut viewport = HistoryViewport::default();
        let flows: Vec<_> = (1..=30).map(|id| flow(id, id, 200, 1, 1, "/")).collect();
        let mut frame = |events| {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 140.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let mut rows: Vec<_> = flows.iter().collect();
                        show(
                            ui,
                            &mut rows,
                            &mut selection,
                            &mut sort,
                            &mut viewport,
                            TableView {
                                intruder: false,
                                timezone: DisplayTimezone::Utc,
                                annotations: &BTreeMap::new(),
                            },
                        );
                    });
                },
            );
        };
        frame(vec![]);
        let pos = egui::pos2(100.0, 43.0);
        frame(vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            },
        ]);
        frame(vec![egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        }]);
        for _ in 0..8 {
            frame(vec![egui::Event::Key {
                key: egui::Key::ArrowDown,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }]);
        }
        assert_eq!(selection.focused, Some(22));
        let ids: Vec<_> = (1..=30).rev().collect();
        assert!(viewport.offset_for(&ids, sort) > 0.0);
    }

    #[test]
    fn incoming_capture_does_not_change_the_view_on_any_frame() {
        let ctx = egui::Context::default();
        let mut selection = HistorySelection::default();
        selection.ids.extend([86, 80]);
        let mut sort = HistorySort::default();
        let mut viewport = HistoryViewport::default();
        let mut flows: Vec<_> = (1..=100)
            .rev()
            .map(|id| flow(id, id, 200, 100, 10, "/same"))
            .collect();
        let mut time = 0.0;
        let mut render =
            |flows: &[Exchange], viewport: &mut HistoryViewport, pointer: egui::Pos2| {
                time += 0.1;
                ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(900.0, 420.0),
                        )),
                        time: Some(time),
                        events: vec![egui::Event::PointerMoved(pointer)],
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            let mut rows: Vec<_> = flows.iter().collect();
                            show(
                                ui,
                                &mut rows,
                                &mut selection,
                                &mut sort,
                                viewport,
                                TableView {
                                    intruder: false,
                                    timezone: DisplayTimezone::Utc,
                                    annotations: &BTreeMap::new(),
                                },
                            );
                        });
                    },
                )
            };
        let over_row = egui::pos2(200.0, 155.0);
        render(&flows, &mut viewport, over_row);
        let ids: Vec<_> = flows.iter().map(|flow| flow.id).collect();
        viewport.record(&ids, 22.0 * 12.0 + 7.25, HistorySort::default(), false);
        for pointer in [over_row, egui::pos2(910.0, 430.0)] {
            for _ in 0..5 {
                render(&flows, &mut viewport, pointer);
            }
            let before = painted_rows(&render(&flows, &mut viewport, pointer));
            assert!(
                before
                    .iter()
                    .any(|paint| matches!(paint, RowPaint::Fill(_, color)
                if *color == ctx.style().visuals.selection.bg_fill))
            );
            if pointer == over_row {
                assert!(
                    before
                        .iter()
                        .any(|paint| matches!(paint, RowPaint::Fill(_, color)
                    if *color == ctx.style().visuals.widgets.hovered.bg_fill))
                );
            }
            for _ in 0..7 {
                let id = flows.len() as u64 + 1;
                flows.push(flow(id, id, 200, 100, 10, "/new"));
                for frame in 0..3 {
                    let next = painted_rows(&render(&flows, &mut viewport, pointer));
                    assert_eq!(
                        before, next,
                        "History flickered on capture {id}, frame {frame}"
                    );
                }
            }
        }
    }

    fn flow(
        id: u64,
        timestamp_ms: u64,
        status: u16,
        size: usize,
        duration_ms: u64,
        url: &str,
    ) -> Exchange {
        Exchange {
            id,
            timestamp_ms,
            status,
            duration_ms,
            url: url.into(),
            response: vec![0; size],
            destination: Destination::from_url("http://example.test").unwrap(),
            tool: "Proxy".into(),
            method: "GET".into(),
            request: vec![],
            error: None,
            note: String::new(),
        }
    }

    #[test]
    fn sorts_mime_subtypes_with_unknown_types_and_deterministic_ties() {
        let flows: Vec<_> = [
            None,
            Some("text/plain"),
            Some("application/json"),
            Some("text/json"),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, mime)| {
            let mut flow = flow(index as u64 + 1, 0, 200, 0, 0, "/");
            if let Some(mime) = mime {
                flow.response =
                    format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\n\r\n").into_bytes();
            }
            flow
        })
        .collect();
        let mut rows: Vec<_> = flows.iter().collect();
        let mut sort = HistorySort::default();
        sort.select(SortColumn::Type);
        rows.sort_unstable_by(|a, b| sort.compare(a, b));
        assert_eq!(
            rows.iter().map(|flow| flow.id).collect::<Vec<_>>(),
            [1, 3, 4, 2]
        );
        sort.select(SortColumn::Type);
        rows.sort_unstable_by(|a, b| sort.compare(a, b));
        assert_eq!(
            rows.iter().map(|flow| flow.id).collect::<Vec<_>>(),
            [2, 4, 3, 1]
        );
    }

    #[test]
    fn sorts_numeric_columns_by_value_and_toggles_direction() {
        let flows = [
            flow(1, 100, 404, 100, 100, "/z"),
            flow(2, 9, 200, 9, 9, "/a"),
        ];
        for column in [
            SortColumn::Timestamp,
            SortColumn::Status,
            SortColumn::Bytes,
            SortColumn::Duration,
        ] {
            let mut sort = HistorySort::default();
            sort.select(column);
            assert_eq!(sort.compare(&flows[0], &flows[1]), Ordering::Greater);
            sort.select(column);
            assert_eq!(sort.compare(&flows[0], &flows[1]), Ordering::Less);
        }
    }

    #[test]
    fn defaults_to_newest_first_and_sorts_text_with_deterministic_ties() {
        let flows = [flow(1, 1, 200, 9, 0, "/z"), flow(2, 2, 200, 9, 0, "/a")];
        let mut rows = flows.iter().collect::<Vec<_>>();
        let mut sort = HistorySort::default();
        rows.sort_unstable_by(|a, b| sort.compare(a, b));
        assert_eq!(rows.iter().map(|flow| flow.id).collect::<Vec<_>>(), [2, 1]);
        sort.select(SortColumn::Id);
        rows.sort_unstable_by(|a, b| sort.compare(a, b));
        assert_eq!(rows[0].id, 1);
        sort.select(SortColumn::Url);
        rows.sort_unstable_by(|a, b| sort.compare(a, b));
        assert_eq!(rows[0].id, 2);
        // Equal values have a deterministic order.
        sort.select(SortColumn::Bytes);
        rows.sort_unstable_by(|a, b| sort.compare(a, b));
        assert_eq!(rows[0].id, 1);
    }
}

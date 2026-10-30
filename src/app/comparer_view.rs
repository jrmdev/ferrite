//! Comparer: side-by-side differences between two requests or responses.
use super::{Workbench, subsection_heading};
use crate::{
    comparer::{self, Comparison, Granularity, RowKind, Segment},
    http,
};
use eframe::egui::{self, Color32, RichText, text::LayoutJob};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Slot {
    A,
    B,
}

#[derive(Default)]
pub(super) struct State {
    labels: [String; 2],
    texts: [String; 2],
    granularity: Granularity,
    hex: bool,
    only_changes: bool,
    cache: Option<(u64, Comparison)>,
}

/// One display line: a wrapped chunk of a diff row.
struct DisplayRow {
    kind: RowKind,
    left: Option<(Option<usize>, Vec<Segment>)>,
    right: Option<(Option<usize>, Vec<Segment>)>,
}

impl State {
    pub(super) fn set(&mut self, slot: Slot, label: String, bytes: &[u8]) {
        let index = slot as usize;
        self.labels[index] = label;
        self.texts[index] = String::from_utf8_lossy(bytes).into_owned();
        if !http::is_display_text(bytes) {
            self.hex = true;
            self.texts[index] = http::hex_dump(bytes);
        }
        self.cache = None;
    }
    fn comparison(&mut self) -> &Comparison {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (
            &self.texts,
            self.hex,
            self.granularity == Granularity::Words,
        )
            .hash(&mut hasher);
        let key = hasher.finish();
        if self.cache.as_ref().is_none_or(|(k, _)| *k != key) {
            let prepare = |text: &str| {
                if self.hex && http::parse_hex(text).is_err() {
                    // Hex view of text input: one byte row per line.
                    http::hex_dump(text.as_bytes())
                } else {
                    text.to_string()
                }
            };
            let (a, b) = (prepare(&self.texts[0]), prepare(&self.texts[1]));
            self.cache = Some((key, comparer::compare(&a, &b, self.granularity)));
        }
        &self.cache.as_ref().unwrap().1
    }
}

fn display_rows(comparison: &Comparison, width: usize, only_changes: bool) -> Vec<DisplayRow> {
    let mut rows = vec![];
    for row in &comparison.rows {
        if only_changes && row.kind == RowKind::Equal {
            continue;
        }
        let left = row
            .left
            .as_ref()
            .map(|l| (l.number, comparer::wrap(&l.segments, width)));
        let right = row
            .right
            .as_ref()
            .map(|l| (l.number, comparer::wrap(&l.segments, width)));
        let height = left
            .as_ref()
            .map_or(0, |(_, c)| c.len())
            .max(right.as_ref().map_or(0, |(_, c)| c.len()));
        for chunk in 0..height {
            let side = |side: &Option<(usize, Vec<Vec<Segment>>)>| {
                side.as_ref().and_then(|(number, chunks)| {
                    chunks
                        .get(chunk)
                        .map(|segments| ((chunk == 0).then_some(*number), segments.clone()))
                })
            };
            rows.push(DisplayRow {
                kind: row.kind,
                left: side(&left),
                right: side(&right),
            });
        }
    }
    rows
}

fn tint(dark: bool, kind: RowKind, left: bool) -> Option<Color32> {
    let (r, g, b) = match (kind, left) {
        (RowKind::Equal, _) => return None,
        (RowKind::Deleted, _) | (RowKind::Changed, true) => (200, 70, 70),
        (RowKind::Inserted, _) | (RowKind::Changed, false) => (60, 170, 90),
    };
    let alpha = if dark { 40 } else { 32 };
    Some(Color32::from_rgba_unmultiplied(r, g, b, alpha))
}

fn strong_tint(dark: bool, left: bool) -> Color32 {
    let alpha = if dark { 120 } else { 90 };
    if left {
        Color32::from_rgba_unmultiplied(220, 60, 60, alpha)
    } else {
        Color32::from_rgba_unmultiplied(50, 180, 80, alpha)
    }
}

fn cell(
    ui: &mut egui::Ui,
    side: Option<&(Option<usize>, Vec<Segment>)>,
    kind: RowKind,
    left: bool,
    width: f32,
    height: f32,
) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let dark = ui.visuals().dark_mode;
    if let Some(fill) = tint(dark, kind, left).filter(|_| side.is_some()) {
        ui.painter().rect_filled(rect, 0.0, fill);
    }
    let Some((number, segments)) = side else {
        return;
    };
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let text = ui.visuals().text_color();
    let weak = ui.visuals().weak_text_color();
    let mut job = LayoutJob::default();
    job.append(
        &number
            .map(|n| format!("{n:>5} "))
            .unwrap_or_else(|| "      ".into()),
        0.0,
        egui::TextFormat::simple(font.clone(), weak),
    );
    for segment in segments {
        let mut format = egui::TextFormat::simple(font.clone(), text);
        if segment.changed && kind == RowKind::Changed {
            format.background = strong_tint(dark, left);
        }
        // Make line endings and tabs visible but compact.
        job.append(&segment.text.replace('\t', "→   "), 0.0, format);
    }
    let galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
    ui.painter()
        .with_clip_rect(rect)
        .galley(rect.min + egui::vec2(2.0, 0.0), galley, text);
}

impl Workbench {
    pub(super) fn send_to_comparer(&mut self, slot: Slot, label: String, bytes: &[u8]) {
        self.comparer.set(slot, label, bytes);
        self.page = super::Page::Comparer;
    }

    pub(super) fn comparer_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Comparer");
        let state = &mut self.comparer;
        ui.horizontal_wrapped(|ui| {
            for (index, name) in ["A", "B"].iter().enumerate() {
                let label = if state.labels[index].is_empty() {
                    "empty".to_string()
                } else {
                    state.labels[index].clone()
                };
                ui.label(RichText::new(format!("{name}:")).strong());
                ui.label(format!("{label} ({} bytes)", state.texts[index].len()));
                if ui.small_button("Clear").clicked() {
                    state.texts[index].clear();
                    state.labels[index].clear();
                }
                ui.separator();
            }
            if ui.button("Swap").clicked() {
                state.texts.swap(0, 1);
                state.labels.swap(0, 1);
            }
            ui.separator();
            ui.label("Highlight");
            ui.radio_value(&mut state.granularity, Granularity::Words, "Words");
            ui.radio_value(
                &mut state.granularity,
                Granularity::Characters,
                "Characters",
            );
            ui.checkbox(&mut state.hex, "Hex");
            ui.checkbox(&mut state.only_changes, "Only differences");
        });
        egui::CollapsingHeader::new("Edit or paste inputs")
            .id_salt("comparer-inputs")
            .default_open(state.texts.iter().all(String::is_empty))
            .show(ui, |ui| {
                ui.columns(2, |columns| {
                    for (index, column) in columns.iter_mut().enumerate() {
                        egui::ScrollArea::vertical()
                            .id_salt(("comparer-input", index))
                            .max_height(140.0)
                            .show(column, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut state.texts[index])
                                        .font(egui::TextStyle::Monospace)
                                        .desired_rows(5)
                                        .desired_width(f32::INFINITY)
                                        .hint_text(if index == 0 {
                                            "A: paste text, or use Send to Comparer"
                                        } else {
                                            "B"
                                        }),
                                );
                            });
                    }
                });
            });
        if state.texts.iter().all(String::is_empty) {
            ui.weak("Right-click an exchange in History, Target or Repeater and choose Send To → Comparer, or use Compare in Repeater.");
            return;
        }
        let only_changes = state.only_changes;
        let comparison = state.comparison();
        let stats = comparison.stats.clone();
        if comparison.identical() {
            ui.label(RichText::new("The inputs are identical.").strong());
        } else {
            ui.label(format!(
                "{} changed, {} only in A, {} only in B, {} unchanged lines",
                stats.changed, stats.deleted, stats.inserted, stats.equal
            ));
        }
        subsection_heading(ui, "Differences");
        let font = egui::TextStyle::Monospace.resolve(ui.style());
        let char_width = ui.fonts_mut(|f| f.glyph_width(&font, '0')).max(1.0);
        let row_height = ui.fonts_mut(|f| f.row_height(&font)) + 2.0;
        let column = ((ui.available_width() - 24.0) / 2.0).max(120.0);
        let chars = (((column - 4.0) / char_width) as usize)
            .saturating_sub(6)
            .max(16);
        let rows = display_rows(comparison, chars, only_changes);
        egui::ScrollArea::vertical()
            .id_salt("comparer-rows")
            .auto_shrink([false, false])
            .show_rows(ui, row_height, rows.len(), |ui, range| {
                ui.spacing_mut().item_spacing = egui::vec2(8.0, 0.0);
                for row in &rows[range] {
                    ui.horizontal(|ui| {
                        cell(ui, row.left.as_ref(), row.kind, true, column, row_height);
                        cell(ui, row.right.as_ref(), row.kind, false, column, row_height);
                    });
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_rows_wrap_and_filter() {
        let comparison =
            comparer::compare("same\nold value\n", "same\nnew value\n", Granularity::Words);
        let all = display_rows(&comparison, 4, false);
        // "same" fits one chunk; "old value"/"new value" need three.
        assert_eq!(all.len(), 1 + 3);
        assert_eq!(all[1].left.as_ref().unwrap().0, Some(2));
        assert_eq!(all[2].left.as_ref().unwrap().0, None);
        let changes = display_rows(&comparison, 80, true);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, RowKind::Changed);
        let mut state = State::default();
        state.set(Slot::B, "binary".into(), &[0, 1, 2]);
        assert!(state.hex);
        assert_eq!(state.texts[1], "00 01 02");
    }
}

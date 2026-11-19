use crate::{history_export::export_items, model::Exchange};
use eframe::egui;
use std::{path::Path, sync::Arc};

pub(super) struct HistoryExport {
    items: Vec<Arc<Exchange>>,
    path: String,
    error: Option<String>,
}

pub(super) enum ExportOutcome {
    Open,
    Cancelled,
    Saved(String),
    Failed(String),
}

impl HistoryExport {
    pub fn new(items: Vec<Arc<Exchange>>) -> Self {
        Self {
            items,
            path: "selected-history.json".into(),
            error: None,
        }
    }

    pub fn show(&mut self, ctx: &egui::Context) -> ExportOutcome {
        let mut result = ExportOutcome::Open;
        let modal = egui::Modal::new(egui::Id::new("export-history-items")).show(ctx, |ui| {
            ui.set_width(480.0);
            ui.heading("Export selected items");
            ui.label(format!(
                "{} selected request/response pairs",
                self.items.len()
            ));
            ui.label("JSON filename");
            ui.add(egui::TextEdit::singleline(&mut self.path).desired_width(f32::INFINITY));
            if let Some(error) = &self.error {
                ui.colored_label(ui.visuals().error_fg_color, error);
            }
            ui.horizontal(|ui| {
                if ui.button("Export JSON").clicked() {
                    match export_items(Path::new(&self.path), &self.items) {
                        Ok(()) => {
                            result = ExportOutcome::Saved(format!(
                                "Exported {} items to {}",
                                self.items.len(),
                                self.path
                            ))
                        }
                        Err(error) => {
                            let message = format!("{error:#}");
                            self.error = Some(message.clone());
                            result = ExportOutcome::Failed(message);
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    result = ExportOutcome::Cancelled;
                }
            });
            ui.weak("Choose a new filename. Existing files are preserved.");
        });
        if modal.should_close() && matches!(result, ExportOutcome::Open) {
            result = ExportOutcome::Cancelled;
        }
        result
    }
}

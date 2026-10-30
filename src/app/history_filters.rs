use crate::history::{HistoryFilter, ToolSelection};
use eframe::egui;

pub(super) fn show(ui: &mut egui::Ui, filter: &mut HistoryFilter) {
    egui::CollapsingHeader::new("Filters").show(ui, |ui| {
        super::compact_rows(ui);
        ui.horizontal_wrapped(|ui| {
            ui.label("Search");
            ui.add(
                egui::TextEdit::singleline(&mut filter.search)
                    .hint_text("URL, request, response or comment")
                    .desired_width(280.0),
            );
            ui.checkbox(&mut filter.regex, "Regex");
            ui.checkbox(&mut filter.case_sensitive, "Case sensitive");
            ui.checkbox(&mut filter.negative_search, "Negative search");
            ui.checkbox(&mut filter.annotated_only, "Only commented or highlighted");
            if ui.button("Reset filters").clicked() {
                *filter = HistoryFilter::default();
            }
        });
        let line_height = ui
            .spacing()
            .interact_size
            .y
            .max(ui.text_style_height(&egui::TextStyle::Body));
        let group_height = ui.text_style_height(&egui::TextStyle::Body)
            + 4.0 * (line_height + ui.spacing().item_spacing.y);
        let checkbox_width = |ui: &egui::Ui, label: &str| {
            let font = egui::TextStyle::Body.resolve(ui.style());
            let text_width = ui.fonts_mut(|fonts| {
                fonts
                    .layout_no_wrap(label.into(), font, egui::Color32::WHITE)
                    .size()
                    .x
            });
            text_width + ui.spacing().icon_width + ui.spacing().icon_spacing + 4.0
        };
        let tool_width = checkbox_width(ui, "Filter by tool").max(checkbox_width(ui, "Intruder"));
        let request_width = checkbox_width(ui, "Hide items without responses")
            .max(checkbox_width(ui, "Show only parameterized requests"));
        let mime_left = checkbox_width(ui, "Script");
        let mime_right = checkbox_width(ui, "Other binary");
        let status_width =
            checkbox_width(ui, "4xx (request error)").max(checkbox_width(ui, "5xx (server error)"));
        let extension_width =
            checkbox_width(ui, "Show only:") + 220.0 + ui.spacing().item_spacing.x;
        egui::ScrollArea::horizontal()
            .id_salt("history-filter-groups")
            .show(ui, |ui| {
                ui.horizontal_top(|ui| {
                    filter_group(ui, tool_width, group_height, |ui| {
                        ui.strong("Filter by tool");
                        let tools = filter
                            .tools
                            .get_or_insert_with(|| ToolSelection::from_legacy(filter.tool));
                        ui.checkbox(&mut tools.proxy, "Proxy");
                        ui.checkbox(&mut tools.repeater, "Repeater");
                        ui.checkbox(&mut tools.intruder, "Intruder");
                        ui.checkbox(&mut tools.scanner, "Scanner");
                    });
                    filter_group(ui, request_width, group_height, |ui| {
                        ui.strong("Filter by request type");
                        ui.checkbox(&mut filter.in_scope_only, "Show only in-scope items");
                        ui.checkbox(
                            &mut filter.hide_without_responses,
                            "Hide items without responses",
                        );
                        ui.checkbox(
                            &mut filter.parameterized_only,
                            "Show only parameterized requests",
                        );
                    });
                    filter_group(
                        ui,
                        mime_left + mime_right + ui.spacing().item_spacing.x,
                        group_height,
                        |ui| {
                            ui.strong("Filter by MIME type");
                            ui.horizontal_top(|ui| {
                                ui.vertical(|ui| {
                                    ui.set_width(mime_left);
                                    ui.checkbox(&mut filter.mime.html, "HTML");
                                    ui.checkbox(&mut filter.mime.script, "Script");
                                    ui.checkbox(&mut filter.mime.xml, "XML");
                                    ui.checkbox(&mut filter.mime.css, "CSS");
                                });
                                ui.vertical(|ui| {
                                    ui.set_width(mime_right);
                                    ui.checkbox(&mut filter.mime.other_text, "Other text");
                                    ui.checkbox(&mut filter.mime.images, "Images");
                                    ui.checkbox(&mut filter.mime.json, "JSON");
                                    ui.checkbox(&mut filter.mime.other_binary, "Other binary");
                                });
                            });
                        },
                    );
                    filter_group(ui, status_width, group_height, |ui| {
                        ui.strong("Filter by status code");
                        ui.checkbox(&mut filter.status.success, "2xx (success)");
                        ui.checkbox(&mut filter.status.redirection, "3xx (redirection)");
                        ui.checkbox(&mut filter.status.request_error, "4xx (request error)");
                        ui.checkbox(&mut filter.status.server_error, "5xx (server error)");
                    });
                    filter_group(ui, extension_width, group_height, |ui| {
                        ui.strong("Filter by file extension");
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut filter.show_only_extensions, "Show only:");
                            ui.add_enabled(
                                filter.show_only_extensions,
                                egui::TextEdit::singleline(&mut filter.only_extensions)
                                    .desired_width(220.0)
                                    .hint_text("asp,aspx,jsp,php"),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut filter.hide_extensions, "Hide:");
                            ui.add_enabled(
                                filter.hide_extensions,
                                egui::TextEdit::singleline(&mut filter.hidden_extensions)
                                    .desired_width(220.0)
                                    .hint_text("js,gif,jpg,png,css,woff"),
                            );
                        });
                        ui.weak("Comma-separated; hide takes precedence.")
                            .on_hover_text("Matching ignores case and URL queries.");
                    });
                });
            });
    });
}

fn filter_group(ui: &mut egui::Ui, width: f32, height: f32, add: impl FnOnce(&mut egui::Ui)) {
    ui.group(|ui| {
        ui.vertical(|ui| {
            ui.set_width(width);
            ui.set_min_height(height);
            add(ui);
        });
    });
}

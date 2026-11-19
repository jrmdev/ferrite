use super::history_table::{HistorySort, TableRows};
use crate::{
    history::{Annotation, HistoryFilter, ToolSelection},
    model::{Exchange, Scope},
};
use eframe::egui;
use std::{collections::BTreeMap, sync::Arc};

pub(super) struct FilterKey {
    pub revision: Option<u64>,
    pub filter: HistoryFilter,
    pub scope: Option<Scope>,
    pub reveal: Option<u64>,
    pub annotations: Arc<BTreeMap<u64, Annotation>>,
}

impl PartialEq for FilterKey {
    fn eq(&self, other: &Self) -> bool {
        self.revision == other.revision
            && self.filter == other.filter
            && self.scope == other.scope
            && self.reveal == other.reveal
            && Arc::ptr_eq(&self.annotations, &other.annotations)
    }
}

#[derive(Default)]
pub(super) struct HistoryMatches {
    key: Option<FilterKey>,
    rows: TableRows,
    error: Option<String>,
}

impl HistoryMatches {
    pub fn invalidate(&mut self) {
        self.key = None;
    }

    pub fn update(
        &mut self,
        exchanges: &[Arc<Exchange>],
        key: FilterKey,
        sort: HistorySort,
    ) -> (&mut TableRows, Option<&str>) {
        if self.key.as_ref() != Some(&key) {
            let compiled = key.filter.compile();
            let in_scope = key
                .scope
                .as_ref()
                .map(|scope| super::scope_matcher(scope, true));
            self.rows
                .rebuild(exchanges, sort, &key.annotations, |flow| {
                    key.reveal == Some(flow.id)
                        || compiled.as_ref().is_ok_and(|filter| {
                            filter.matches_using(flow, key.annotations.get(&flow.id), |url| {
                                in_scope.as_ref().is_some_and(|matches| matches(url))
                            })
                        })
                });
            self.error = compiled
                .err()
                .map(|error| format!("Invalid search pattern: {error}"));
            self.key = Some(key);
        }
        (&mut self.rows, self.error.as_deref())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::Destination, project::Project};

    #[test]
    fn cached_history_tracks_changes_in_data_annotations_scope_and_reveal() {
        let mut project = Project::temporary();
        let mut exchange = Exchange {
            id: 1,
            timestamp_ms: 0,
            tool: "Proxy".into(),
            destination: Destination::from_url("http://example.test").unwrap(),
            url: "http://example.test/".into(),
            method: "GET".into(),
            request: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            response: b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nold body".to_vec(),
            status: 200,
            duration_ms: 0,
            error: None,
            omitted_response_body_bytes: None,
            streamed_response: None,
            note: String::new(),
        };
        project.insert(exchange.clone()).unwrap();
        let mut cache = HistoryMatches::default();
        let mut rows = Vec::new();
        let mut revision = None;
        let mut filter = HistoryFilter {
            search: "needle".into(),
            ..Default::default()
        };
        let mut visible = |project: &Project, filter: &HistoryFilter, scope, reveal| {
            project.sync_history(&mut rows, &mut revision).unwrap();
            let (rows, error) = cache.update(
                &rows,
                FilterKey {
                    revision,
                    filter: filter.clone(),
                    scope,
                    reveal,
                    annotations: project.annotation_snapshot(),
                },
                HistorySort::default(),
            );
            (rows.len(), error.is_some())
        };
        assert_eq!(visible(&project, &filter, None, None), (0, false));
        exchange.response.extend_from_slice(b" needle");
        project.insert(exchange).unwrap();
        assert_eq!(visible(&project, &filter, None, None), (1, false));
        filter.annotated_only = true;
        assert_eq!(visible(&project, &filter, None, None), (0, false));
        project
            .set_annotations(&[(
                1,
                Annotation {
                    comment: "note".into(),
                    highlight: None,
                },
            )])
            .unwrap();
        assert_eq!(visible(&project, &filter, None, None), (1, false));
        filter.in_scope_only = true;
        assert_eq!(
            visible(&project, &filter, Some(Scope::default()), None),
            (0, false)
        );
        let scope = Scope {
            include: vec!["example\\.test".into()],
            ..Default::default()
        };
        assert_eq!(visible(&project, &filter, Some(scope), None), (1, false));
        filter.in_scope_only = false;
        filter.regex = true;
        filter.search = "[".into();
        assert_eq!(visible(&project, &filter, None, None), (0, true));
        assert_eq!(visible(&project, &filter, None, Some(1)), (1, true));
        project.delete(&[1]).unwrap();
        assert_eq!(visible(&project, &filter, None, Some(1)), (0, true));
    }
}

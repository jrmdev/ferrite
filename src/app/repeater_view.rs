//! Repeater tabs, grouped into collections, with an ID-based merge so tabs
//! created or sent by MCP clients are never overwritten by the UI.
use super::comparer_view::Slot;
use super::{
    Event, Workbench, decode_editor, editable, editor_context, entry_menu, hex_headers,
    http_editor, item_menu, split_panes, subsection_heading,
};
use crate::model::{Exchange, RepeaterTab};
use eframe::egui::{self, RichText};

/// Apply the UI's edits (`edited`, made from the `original` snapshot) to the
/// project's `current` tabs, keeping concurrent additions and sends.
pub(super) fn merge_tabs(
    original: &[RepeaterTab],
    edited: &[RepeaterTab],
    current: &[RepeaterTab],
) -> Vec<RepeaterTab> {
    // Tabs the UI closed disappear; tabs added elsewhere stay.
    let mut merged: Vec<RepeaterTab> = current
        .iter()
        .filter(|tab| {
            !original.iter().any(|o| o.id == tab.id) || edited.iter().any(|e| e.id == tab.id)
        })
        .cloned()
        .collect();
    for (index, tab) in edited.iter().enumerate() {
        if original.iter().any(|o| o == tab) {
            continue;
        }
        if let Some(slot) = merged.iter_mut().find(|m| m.id == tab.id) {
            // Send history is appended outside the editor; keep the latest.
            let history = std::mem::take(&mut slot.history);
            *slot = tab.clone();
            slot.history = history;
        } else {
            let position = index
                .checked_sub(1)
                .and_then(|previous| merged.iter().position(|m| m.id == edited[previous].id))
                .map_or(merged.len(), |p| p + 1);
            merged.insert(position, tab.clone());
        }
    }
    merged
}

fn next_id(tabs: &[RepeaterTab], project: u64) -> u64 {
    tabs.iter()
        .map(|t| t.id + 1)
        .max()
        .unwrap_or(1)
        .max(project)
}

enum TabAction {
    Duplicate(u64),
    Close(u64),
    MoveTo(u64, String),
}

impl Workbench {
    pub(super) fn select_repeater_tab(&mut self, tab: &RepeaterTab) {
        self.repeater_tab = tab.id;
        self.repeater_flow = tab.history.last().copied();
        self.repeater_cursor = tab.history.len().saturating_sub(1);
    }

    pub(super) fn send_to_repeater(&mut self, flow: &Exchange) {
        let (request, request_hex) = editable(&flow.request);
        let mut project = self.engine.project.lock().unwrap();
        let id = project.workspace.next_repeater_id();
        project.workspace.repeater.push(RepeaterTab {
            id,
            group: String::new(),
            name: id.to_string(),
            destination: flow.destination.origin(),
            request,
            request_hex,
            history: vec![],
        });
        drop(project);
        self.repeater_tab = id;
        self.repeater_flow = None;
        self.page = super::Page::Repeater;
        self.persist();
    }

    pub(super) fn repeater_sent(&mut self, tab_id: u64, result: anyhow::Result<Exchange>) {
        self.repeater_busy.retain(|id| *id != tab_id);
        if let Some(flow) = self.report(result) {
            let mut project = self.engine.project.lock().unwrap();
            if let Some(tab) = project.workspace.repeater_tab_mut(tab_id) {
                tab.history.push(flow.id);
                if self.repeater_tab == tab_id {
                    self.repeater_flow = Some(flow.id);
                    self.repeater_cursor = tab.history.len().saturating_sub(1);
                }
            }
            drop(project);
            self.persist();
        }
    }

    fn repeater_tab_bar(&mut self, ui: &mut egui::Ui, tabs: &mut Vec<RepeaterTab>) {
        let mut action = None;
        let groups: Vec<String> = tabs.iter().fold(vec![], |mut groups, tab| {
            if !groups.contains(&tab.group) {
                groups.push(tab.group.clone());
            }
            groups
        });
        for group in &groups {
            ui.horizontal_wrapped(|ui| {
                if !group.is_empty() || groups.len() > 1 {
                    ui.label(
                        RichText::new(format!(
                            "{}:",
                            if group.is_empty() { "Ungrouped" } else { group }
                        ))
                        .weak(),
                    );
                }
                for tab in tabs.iter().filter(|t| &t.group == group) {
                    let mut label = RichText::new(&tab.name);
                    if self.repeater_busy.contains(&tab.id) {
                        label = label.italics();
                    }
                    let response = ui.selectable_label(self.repeater_tab == tab.id, label);
                    if response.clicked() {
                        self.select_repeater_tab(tab);
                    }
                    response.context_menu(|ui| {
                        if ui.button("Duplicate").clicked() {
                            action = Some(TabAction::Duplicate(tab.id));
                            ui.close();
                        }
                        ui.menu_button("Move to collection", |ui| {
                            for other in &groups {
                                let name = if other.is_empty() { "Ungrouped" } else { other };
                                if other != &tab.group && ui.button(name).clicked() {
                                    action = Some(TabAction::MoveTo(tab.id, other.clone()));
                                    ui.close();
                                }
                            }
                            ui.separator();
                            ui.label("Or type a new collection in the tab's Collection field.");
                        });
                        ui.separator();
                        if ui.button("Close tab").clicked() {
                            action = Some(TabAction::Close(tab.id));
                            ui.close();
                        }
                    });
                }
                if group == groups.last().unwrap()
                    && ui.button("+").on_hover_text("New tab").clicked()
                {
                    let project_next = self
                        .engine
                        .project
                        .lock()
                        .unwrap()
                        .workspace
                        .next_repeater_id();
                    let id = next_id(tabs, project_next);
                    let group = tabs
                        .iter()
                        .find(|t| t.id == self.repeater_tab)
                        .map(|t| t.group.clone())
                        .unwrap_or_default();
                    tabs.push(RepeaterTab {
                        id,
                        group,
                        name: id.to_string(),
                        destination: "https://example.com".into(),
                        request: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
                        ..Default::default()
                    });
                    self.repeater_tab = id;
                    self.repeater_flow = None;
                }
            });
        }
        if tabs.is_empty() && ui.button("New tab").clicked() {
            let id = next_id(
                tabs,
                self.engine
                    .project
                    .lock()
                    .unwrap()
                    .workspace
                    .next_repeater_id(),
            );
            tabs.push(RepeaterTab {
                id,
                name: id.to_string(),
                destination: "https://example.com".into(),
                request: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
                ..Default::default()
            });
            self.repeater_tab = id;
        }
        match action {
            Some(TabAction::Duplicate(id)) => {
                let project_next = self
                    .engine
                    .project
                    .lock()
                    .unwrap()
                    .workspace
                    .next_repeater_id();
                if let Some(index) = tabs.iter().position(|t| t.id == id) {
                    let mut copy = tabs[index].clone();
                    copy.id = next_id(tabs, project_next);
                    copy.name = format!("{} (copy)", copy.name);
                    copy.history.clear();
                    self.repeater_tab = copy.id;
                    self.repeater_flow = None;
                    tabs.insert(index + 1, copy);
                }
            }
            Some(TabAction::Close(id)) => {
                if let Some(index) = tabs.iter().position(|t| t.id == id) {
                    tabs.remove(index);
                    if self.repeater_tab == id
                        && let Some(next) =
                            tabs.get(index.min(tabs.len().saturating_sub(1))).cloned()
                    {
                        self.select_repeater_tab(&next);
                    }
                }
            }
            Some(TabAction::MoveTo(id, group)) => {
                if let Some(tab) = tabs.iter_mut().find(|t| t.id == id) {
                    tab.group = group;
                }
            }
            None => {}
        }
    }

    pub(super) fn repeater(&mut self, ui: &mut egui::Ui) {
        ui.heading("Repeater");
        let mut editor_action = None;
        let original = self
            .engine
            .project
            .lock()
            .unwrap()
            .workspace
            .repeater
            .clone();
        let mut tabs = original.clone();
        self.repeater_tab_bar(ui, &mut tabs);
        if !tabs.iter().any(|t| t.id == self.repeater_tab)
            && let Some(first) = tabs.first().cloned()
        {
            self.select_repeater_tab(&first);
        }
        let selected = self.repeater_tab;
        if let Some(tab) = tabs.iter_mut().find(|t| t.id == selected) {
            ui.horizontal_wrapped(|ui| {
                ui.label("Name");
                ui.add(egui::TextEdit::singleline(&mut tab.name).desired_width(120.0));
                ui.label("Collection");
                ui.add(
                    egui::TextEdit::singleline(&mut tab.group)
                        .hint_text("none")
                        .desired_width(110.0),
                );
                ui.label("Target");
                ui.text_edit_singleline(&mut tab.destination);
                let busy = self.repeater_busy.contains(&tab.id);
                if ui.add_enabled(!busy, egui::Button::new("Send")).clicked() {
                    let parsed = decode_editor(&tab.request, tab.request_hex).and_then(|r| {
                        Ok((r, crate::model::Destination::from_url(&tab.destination)?))
                    });
                    if let Some((request, dest)) = self.report(parsed) {
                        let tx = self.tx.clone();
                        let engine = self.engine.clone();
                        let id = tab.id;
                        self.repeater_busy.push(id);
                        self.runtime.spawn(async move {
                            let result = engine.execute(request, dest, "Repeater", false).await;
                            let _ = tx.send(Event::Repeater(id, result));
                        });
                    }
                }
                ui.label(if busy { "Sending…" } else { "" });
            });
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut tab.request_hex, "Request is hex");
                ui.checkbox(&mut self.response_hex, "Response as hex");
                if ui
                    .add_enabled(
                        !tab.history.is_empty()
                            && (self.repeater_flow.is_none() || self.repeater_cursor > 0),
                        egui::Button::new("Previous"),
                    )
                    .clicked()
                {
                    self.repeater_cursor = self.repeater_cursor.saturating_sub(1);
                    self.repeater_cursor = self.repeater_cursor.min(tab.history.len() - 1);
                    self.repeater_flow = Some(tab.history[self.repeater_cursor]);
                }
                if ui
                    .add_enabled(
                        !tab.history.is_empty()
                            && (self.repeater_flow.is_none()
                                || self.repeater_cursor.saturating_add(1) < tab.history.len()),
                        egui::Button::new("Next"),
                    )
                    .clicked()
                {
                    self.repeater_cursor = (self.repeater_cursor + 1).min(tab.history.len() - 1);
                    self.repeater_flow = Some(tab.history[self.repeater_cursor]);
                }
                ui.label(format!("{} saved sends", tab.history.len()));
                if tab.history.len() >= 2
                    && ui
                        .button("Compare with previous")
                        .on_hover_text("Open this response and the send before it in Comparer")
                        .clicked()
                {
                    let current = self.repeater_cursor.clamp(1, tab.history.len() - 1);
                    let ids = [tab.history[current - 1], tab.history[current]];
                    let found: Vec<_> = ids
                        .iter()
                        .filter_map(|id| self.rows.iter().find(|r| r.id == *id).cloned())
                        .collect();
                    if let [previous, shown] = found.as_slice() {
                        self.comparer.set(
                            Slot::A,
                            format!("#{} response", previous.id),
                            &previous.response,
                        );
                        self.send_to_comparer(
                            Slot::B,
                            format!("#{} response", shown.id),
                            &shown.response,
                        );
                    }
                }
            });
            let flow = self
                .repeater_flow
                .and_then(|id| self.rows.iter().find(|r| r.id == id))
                .cloned();
            if let Some(flow) = &flow {
                ui.label(format!(
                    "Status {} · {} bytes · {} ms",
                    flow.status,
                    flow.response.len(),
                    flow.duration_ms
                ));
                if let Some(e) = &flow.error {
                    ui.colored_label(ui.visuals().error_fg_color, e);
                }
                if ui.button("Restore this request").clicked() {
                    let (text, h) = editable(&flow.request);
                    tab.request = text;
                    tab.request_hex = h;
                }
            }
            let response = flow
                .as_ref()
                .map(|f| {
                    self.response_cache.get(
                        f.id,
                        &f.response,
                        self.response_hex,
                        self.engine.settings().max_message_bytes,
                    )
                })
                .unwrap_or_default();
            super::highlight::find_bar(ui, &[("request", &tab.request), ("response", &response)]);
            ui.separator();
            let [mut request_ui, mut response_ui] = split_panes(ui, "repeater-editors", false, 0.5);
            subsection_heading(&mut request_ui, "Request");
            subsection_heading(&mut response_ui, "Response");
            let headers = hex_headers(
                &mut request_ui,
                &tab.request,
                tab.request_hex,
                ("repeater-headers", tab.id),
            );
            let request_output = http_editor(
                &mut request_ui,
                &mut tab.request,
                ("repeater-request", tab.id, tab.request_hex),
            );
            let action = item_menu(&request_output.inner.response, false, None).or_else(|| {
                headers
                    .as_ref()
                    .and_then(|response| item_menu(response, false, None))
            });
            if let Some(action) = action {
                editor_action = Some((action, editor_context::repeater(tab)));
            }
            let response_output = http_editor(
                &mut response_ui,
                &mut response.as_ref(),
                (
                    "repeater-response",
                    tab.id,
                    self.repeater_flow,
                    self.response_hex,
                ),
            );
            if let Some(saved) = &flow {
                if let Some(action) = entry_menu(&response_output.inner.response, true) {
                    editor_action = Some((action, Ok((**saved).clone())));
                }
            } else if let Some(action) = item_menu(&response_output.inner.response, false, None) {
                editor_action = Some((action, editor_context::repeater(tab)));
            }
        }
        if tabs != original {
            let mut project = self.engine.project.lock().unwrap();
            let merged = merge_tabs(&original, &tabs, &project.workspace.repeater);
            if merged != project.workspace.repeater {
                project.workspace.repeater = merged;
                let result = project.save_workspace();
                drop(project);
                self.report(result);
            }
        }
        if let Some((action, snapshot)) = editor_action {
            self.editor_action(ui.ctx(), action, snapshot, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab(id: u64, name: &str) -> RepeaterTab {
        RepeaterTab {
            id,
            name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn merge_keeps_concurrent_additions_and_history() {
        let original = vec![tab(1, "a"), tab(2, "b")];
        // The UI renamed tab 1, closed tab 2 and duplicated tab 1 as tab 4.
        let mut edited = original.clone();
        edited[0].name = "renamed".into();
        edited.remove(1);
        edited.insert(1, tab(4, "a (copy)"));
        // Meanwhile an MCP client added tab 3 and sent from tab 1.
        let mut current = original.clone();
        current[0].history.push(99);
        current.push(tab(3, "MCP 3"));
        let merged = merge_tabs(&original, &edited, &current);
        let names: Vec<_> = merged.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["renamed", "a (copy)", "MCP 3"]);
        assert_eq!(merged[0].history, [99]);
        // An unchanged UI snapshot never overwrites the project.
        assert_eq!(merge_tabs(&original, &original, &current), current);
    }
}

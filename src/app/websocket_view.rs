use super::http_editor::websocket_editor;
use super::{editable, hex, split_panes, timestamp, unhex};
use crate::{
    display_timezone::DisplayTimezone,
    engine::Engine,
    websocket::{self, CapturedMessage, MessageSummary, Session, SessionState},
};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::sync::{Arc, atomic::Ordering};

pub(super) struct State {
    pub show_history: bool,
    pub reveal_handshake: Option<u64>,
    session: Option<u64>,
    selected: Option<u64>,
    seen: u64,
    sessions: Vec<Session>,
    state_filter: Option<SessionState>,
    messages: Vec<MessageSummary>,
    loaded_session: Option<u64>,
    payload: Option<CapturedMessage>,
    detail: Arc<str>,
    hex: bool,
    forwarded: bool,
    pending_id: Option<u64>,
    edit: String,
    edit_hex: bool,
    hidden: bool,
    error: String,
}

impl Default for State {
    fn default() -> Self {
        Self {
            show_history: false,
            reveal_handshake: None,
            session: None,
            selected: None,
            seen: u64::MAX,
            sessions: vec![],
            state_filter: None,
            messages: vec![],
            loaded_session: None,
            payload: None,
            detail: Arc::from(""),
            hex: false,
            forwarded: false,
            pending_id: None,
            edit: String::new(),
            edit_hex: false,
            hidden: false,
            error: String::new(),
        }
    }
}

impl State {
    fn refresh(&mut self, engine: &Engine) -> anyhow::Result<()> {
        let activity = engine.websockets.activity.load(Ordering::SeqCst);
        let project = engine.project.lock().unwrap();
        let state_filter = project.workspace.websocket_state_filter;
        if activity == self.seen && state_filter == self.state_filter {
            return Ok(());
        }
        self.state_filter = state_filter;
        self.sessions = project
            .ws_sessions()
            .into_iter()
            .filter(|session| self.state_filter.is_none_or(|state| session.state == state))
            .collect();
        if self.session.is_none() || !self.sessions.iter().any(|s| Some(s.id) == self.session) {
            self.session = self.sessions.first().map(|s| s.id);
            self.selected = None;
            self.payload = None;
            self.detail = Arc::from("");
        }
        if self.loaded_session != self.session {
            self.messages.clear();
            self.loaded_session = self.session;
        }
        if let Some(id) = self.session {
            for message in self
                .messages
                .iter_mut()
                .filter(|m| m.disposition == websocket::Disposition::Pending)
            {
                if let Some(updated) = project.ws_summary(id, message.sequence) {
                    *message = updated;
                }
            }
            self.messages.extend(
                project.ws_summaries_after(id, self.messages.last().map_or(0, |m| m.sequence)),
            );
        }
        if let Some(seq) = self.selected {
            let changed = self
                .messages
                .iter()
                .find(|m| m.sequence == seq)
                .is_some_and(|summary| {
                    self.payload.as_ref().is_none_or(|m| {
                        m.summary.disposition != summary.disposition
                            || m.summary.session_id != summary.session_id
                    })
                });
            if changed {
                self.payload = self
                    .session
                    .map(|id| project.ws_message(id, seq))
                    .transpose()?
                    .flatten();
                self.render_payload();
            }
        }
        self.seen = activity;
        Ok(())
    }
    fn render_payload(&mut self) {
        self.detail = if let Some(message) = &self.payload {
            if self.forwarded
                && !matches!(
                    message.summary.disposition,
                    websocket::Disposition::Forwarded | websocket::Disposition::Modified
                )
            {
                self.detail = format!(
                    "[No forwarded payload: {}]",
                    message.summary.disposition.label()
                )
                .into();
                return;
            }
            let bytes = if self.forwarded {
                message.forwarded.as_ref().unwrap_or(&message.original)
            } else {
                &message.original
            };
            if bytes.len() > super::response_content::DISPLAY_LIMIT {
                format!(
                    "[Payload too large to be displayed ({} bytes)]",
                    bytes.len()
                )
                .into()
            } else if self.hex {
                hex(bytes).into()
            } else {
                String::from_utf8_lossy(bytes).into_owned().into()
            }
        } else {
            Arc::from("")
        };
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        engine: &Engine,
        timezone: DisplayTimezone,
    ) -> anyhow::Result<Option<u64>> {
        self.refresh(engine)?;
        let previous = self.state_filter;
        egui::ComboBox::from_label("State")
            .selected_text(self.state_filter.map_or("All", |state| state.label()))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.state_filter, None, "All");
                for state in [
                    SessionState::Open,
                    SessionState::Closed,
                    SessionState::Interrupted,
                    SessionState::Error,
                ] {
                    ui.selectable_value(&mut self.state_filter, Some(state), state.label());
                }
            });
        if previous != self.state_filter {
            {
                let mut project = engine.project.lock().unwrap();
                project.workspace.websocket_state_filter = self.state_filter;
                if let Err(error) = project.save_workspace() {
                    project.workspace.websocket_state_filter = previous;
                    self.state_filter = previous;
                    return Err(error);
                }
            }
            self.seen = u64::MAX;
            self.refresh(engine)?;
        }
        if self.sessions.is_empty() {
            ui.label(if self.state_filter.is_some() {
                "No WebSocket sessions match the selected state."
            } else {
                "WebSocket sessions will appear here after a successful upgrade through the proxy."
            });
            return Ok(None);
        }
        let mut handshake = None;
        let mut close = None;
        ui.horizontal(|ui| {
            if let Some(session) = self.sessions.iter().find(|s| Some(s.id) == self.session) {
                ui.label(format!(
                    "Session #{} · {} · {} messages",
                    session.id,
                    session.state.label(),
                    session.message_count
                ));
                if ui.button("View HTTP handshake").clicked() {
                    handshake = Some(session.id);
                }
                if ui
                    .add_enabled(
                        session.state == SessionState::Open
                            && engine.websockets.is_active(session.id),
                        egui::Button::new("Close session"),
                    )
                    .clicked()
                {
                    close = Some(session.id);
                }
            }
        });
        if let Some(id) = close {
            engine.websockets.close(id)?;
        }
        if let Some(session) = self.sessions.iter().find(|s| Some(s.id) == self.session) {
            if let Some(error) = &session.error {
                ui.colored_label(ui.visuals().error_fg_color, error);
            }
            if let Some(code) = session.close_code {
                ui.label(format!("Close {code}: {}", session.close_reason));
            }
        }
        let [mut sessions_ui, mut messages_ui] = split_panes(ui, "websocket-sessions", true, 0.28);
        let mut selected_session = self.session;
        let session_height = sessions_ui.available_height();
        let session_focus = sessions_ui.id().with("ws-session-rows-focus");
        let session_target = super::table_arrow_navigation(
            &mut sessions_ui,
            session_focus,
            self.sessions
                .iter()
                .position(|session| Some(session.id) == selected_session),
            self.sessions.len(),
            ((session_height - 25.0).max(0.0) / 24.0) as usize,
        );
        if let Some(index) = session_target {
            selected_session = Some(self.sessions[index].id);
        }

        egui::ScrollArea::horizontal()
            .id_salt("ws-sessions-horizontal")
            .show(&mut sessions_ui, |ui| {
                super::compact_rows(ui);
                let mut table = TableBuilder::new(ui)
                    .id_salt("ws-sessions")
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(55.0))
                    .column(Column::initial(360.0).at_least(100.0).clip(true))
                    .column(Column::initial(185.0))
                    .column(Column::initial(85.0))
                    .column(Column::initial(75.0))
                    .column(Column::remainder().at_least(100.0))
                    .max_scroll_height((session_height - 25.0).max(1.0))
                    .min_scrolled_height(0.0);
                if let Some(index) = session_target {
                    table = table.scroll_to_row(index, None);
                }
                table
                    .header(22.0, |mut row| {
                        for title in ["ID", "URL", "Opened", "State", "Messages", "Subprotocol"] {
                            row.col(|ui| {
                                let response = ui.strong(title);
                                if title == "Opened" {
                                    response.on_hover_text(format!(
                                        "Display timezone: {}",
                                        timezone.label()
                                    ));
                                }
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(22.0, self.sessions.len(), |mut row| {
                            let session = &self.sessions[row.index()];
                            row.set_selected(Some(session.id) == self.session);
                            for (column, text) in [
                                session.id.to_string(),
                                session.url.clone(),
                                timestamp(session.opened_ms, timezone),
                                session.state.label().into(),
                                session.message_count.to_string(),
                                session.subprotocol.clone(),
                            ]
                            .into_iter()
                            .enumerate()
                            {
                                row.col(|ui| {
                                    let text: egui::WidgetText = if column == 2 {
                                        super::theme::timestamp_text(
                                            ui,
                                            &text,
                                            egui::TextStyle::Body.resolve(ui.style()),
                                            ui.visuals().text_color(),
                                        )
                                        .into()
                                    } else {
                                        text.into()
                                    };
                                    ui.add(egui::Label::new(text).truncate().selectable(false));
                                });
                            }
                            if row.response().clicked() {
                                row.response()
                                    .ctx
                                    .memory_mut(|memory| memory.request_focus(session_focus));
                                selected_session = Some(session.id);
                            }
                        })
                    });
            });
        if selected_session != self.session {
            self.session = selected_session;
            self.selected = None;
            self.payload = None;
            self.detail = Arc::from("");
            self.seen = u64::MAX;
            self.refresh(engine)?;
        }
        let [mut table_ui, mut detail_ui] =
            split_panes(&mut messages_ui, "websocket-message-detail", true, 0.6);
        let table_height = table_ui.available_height();
        let mut selected = self.selected;
        let message_focus = table_ui.id().with("ws-message-rows-focus");
        let message_target = super::table_arrow_navigation(
            &mut table_ui,
            message_focus,
            self.messages
                .iter()
                .position(|message| Some(message.sequence) == selected),
            self.messages.len(),
            ((table_height - 25.0).max(0.0) / 24.0) as usize,
        );
        if let Some(index) = message_target {
            selected = Some(self.messages[index].sequence);
        }

        egui::ScrollArea::horizontal()
            .id_salt("ws-messages-horizontal")
            .show(&mut table_ui, |ui| {
                super::compact_rows(ui);
                let mut table = TableBuilder::new(ui)
                    .id_salt(("ws-messages", self.session))
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(55.0))
                    .column(Column::initial(145.0))
                    .column(Column::initial(185.0))
                    .column(Column::initial(65.0))
                    .column(Column::initial(85.0))
                    .column(Column::initial(90.0))
                    .column(Column::remainder().at_least(200.0).clip(true))
                    .stick_to_bottom(true)
                    .max_scroll_height((table_height - 25.0).max(1.0))
                    .min_scrolled_height(0.0);
                if let Some(index) = message_target {
                    table = table.scroll_to_row(index, None);
                }
                table
                    .header(22.0, |mut row| {
                        for title in [
                            "#",
                            "Direction",
                            "Timestamp",
                            "Type",
                            "Length",
                            "Status",
                            "Data",
                        ] {
                            row.col(|ui| {
                                let response = ui.strong(title);
                                if title == "Timestamp" {
                                    response.on_hover_text(format!(
                                        "Display timezone: {}",
                                        timezone.label()
                                    ));
                                }
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(22.0, self.messages.len(), |mut row| {
                            let message = &self.messages[row.index()];
                            let row_selected = Some(message.sequence) == self.selected;
                            row.set_selected(row_selected);
                            for (column, text) in [
                                message.sequence.to_string(),
                                message.direction.label().into(),
                                timestamp(message.timestamp_ms, timezone),
                                message.kind.label().into(),
                                message.length.to_string(),
                                message.disposition.label().into(),
                                message.preview.clone(),
                            ]
                            .into_iter()
                            .enumerate()
                            {
                                row.col(|ui| {
                                    let visuals = ui.visuals();
                                    let color = if !row_selected {
                                        let incoming = message.direction
                                            == websocket::Direction::ServerToClient;
                                        // Keep incoming rows lighter in both light and dark themes.
                                        match (visuals.dark_mode, incoming) {
                                            (false, true) => visuals
                                                .text_color()
                                                .lerp_to_gamma(egui::Color32::WHITE, 0.2),
                                            (true, false) => visuals
                                                .text_color()
                                                .lerp_to_gamma(visuals.panel_fill, 0.12),
                                            _ => visuals.text_color(),
                                        }
                                    } else {
                                        visuals.text_color()
                                    };
                                    let text: egui::WidgetText = if column == 2 {
                                        super::theme::timestamp_text(
                                            ui,
                                            &text,
                                            egui::TextStyle::Body.resolve(ui.style()),
                                            color,
                                        )
                                        .into()
                                    } else {
                                        egui::RichText::new(text).color(color).into()
                                    };
                                    ui.add(egui::Label::new(text).truncate().selectable(false));
                                });
                            }
                            if row.response().clicked() {
                                row.response()
                                    .ctx
                                    .memory_mut(|memory| memory.request_focus(message_focus));
                                selected = Some(message.sequence);
                            }
                        })
                    });
            });
        if selected != self.selected {
            self.selected = selected;
            self.payload = if let (Some(id), Some(seq)) = (self.session, selected) {
                engine.project.lock().unwrap().ws_message(id, seq)?
            } else {
                None
            };
            self.render_payload();
        }
        let mut changed = false;
        detail_ui.horizontal(|ui| {
            changed |= ui.checkbox(&mut self.hex, "Hex").changed();
            changed |= ui
                .selectable_value(&mut self.forwarded, false, "Original")
                .changed();
            changed |= ui
                .selectable_value(&mut self.forwarded, true, "Forwarded")
                .changed();
            if let Some(message) = &self.payload {
                ui.label(format!(
                    "{} · {} received bytes",
                    message.summary.disposition.label(),
                    message.original.len()
                ));
                if let Some(sent) = &message.forwarded {
                    ui.label(format!("{} forwarded bytes", sent.len()));
                }
            }
        });
        if changed {
            self.render_payload();
        }
        if let Some(error) = self.payload.as_ref().and_then(|m| m.error.as_ref()) {
            detail_ui.colored_label(detail_ui.visuals().error_fg_color, error);
        }
        if self.payload.is_none() {
            detail_ui.label("Select a message to inspect its payload.");
        } else {
            websocket_editor(
                &mut detail_ui,
                &mut self.detail.as_ref(),
                (
                    "ws-payload",
                    self.session,
                    self.selected,
                    self.hex,
                    self.forwarded,
                ),
                self.hex,
            );
        }
        Ok(handshake)
    }

    pub fn pending_edit(&self, engine: &Engine) -> anyhow::Result<Option<(u64, Vec<u8>)>> {
        let Some(item) = engine
            .websockets
            .pending()
            .into_iter()
            .find(|p| Some(p.id) == self.pending_id)
        else {
            return Ok(None);
        };
        let bytes = if self.hidden {
            item.payload.to_vec()
        } else if self.edit_hex {
            unhex(&self.edit)?
        } else {
            self.edit.as_bytes().to_vec()
        };
        anyhow::ensure!(
            bytes.len() <= engine.settings().max_message_bytes,
            "Edited WebSocket message exceeds message limit"
        );
        if item.kind == websocket::Kind::Text {
            std::str::from_utf8(&bytes)?;
        }
        Ok(Some((item.id, bytes)))
    }
    fn load(&mut self, item: &websocket::Intercepted) {
        self.pending_id = Some(item.id);
        self.hidden = item.payload.len() > super::response_content::DISPLAY_LIMIT;
        if self.hidden {
            self.edit.clear();
            self.edit_hex = false;
        } else {
            (self.edit, self.edit_hex) = editable(&item.payload);
        }
        self.error.clear();
    }
    pub fn intercept(&mut self, ui: &mut egui::Ui, engine: &Engine) {
        let pending = engine.websockets.pending();
        if !pending.iter().any(|p| Some(p.id) == self.pending_id) {
            self.pending_id = None;
            if let Some(item) = pending.first() {
                self.load(item);
            }
        }
        ui.horizontal_wrapped(|ui| {
            for item in &pending {
                if ui
                    .selectable_label(
                        Some(item.id) == self.pending_id,
                        format!(
                            "WS #{} / {} · {} · {}",
                            item.session_id,
                            item.sequence,
                            item.direction.label(),
                            item.kind.label()
                        ),
                    )
                    .clicked()
                {
                    self.load(item);
                }
            }
        });
        let Some(item) = pending.iter().find(|p| Some(p.id) == self.pending_id) else {
            ui.label("Enable Intercept WebSockets to pause text and binary messages in both directions. Ping, pong, and close continue automatically.");
            return;
        };
        ui.label(format!("{} · {} bytes", item.url, item.payload.len()));
        ui.horizontal(|ui| {
            if ui.button("Forward").clicked() {
                let result = self.pending_edit(engine).and_then(|edited| {
                    let (id, bytes) = edited.context("Message is no longer pending")?;
                    engine.websockets.decide(
                        id,
                        websocket::Decision::Forward(bytes),
                        engine.settings().max_message_bytes,
                    )
                });
                match result {
                    Ok(()) => self.pending_id = None,
                    Err(e) => self.error = e.to_string(),
                }
            }
            if ui.button("Drop").clicked() {
                match engine.websockets.decide(
                    item.id,
                    websocket::Decision::Drop,
                    engine.settings().max_message_bytes,
                ) {
                    Ok(()) => self.pending_id = None,
                    Err(e) => self.error = e.to_string(),
                }
            }
            if !self.hidden
                && ui
                    .button(if self.edit_hex {
                        "Switch to text"
                    } else {
                        "Switch to hex"
                    })
                    .clicked()
            {
                let result = if self.edit_hex {
                    unhex(&self.edit).and_then(|bytes| Ok(String::from_utf8(bytes)?))
                } else {
                    Ok(hex(self.edit.as_bytes()))
                };
                match result {
                    Ok(text) => {
                        self.edit = text;
                        self.edit_hex = !self.edit_hex;
                    }
                    Err(e) => self.error = e.to_string(),
                }
            }
        });
        if !self.error.is_empty() {
            ui.colored_label(ui.visuals().error_fg_color, &self.error);
        }
        if self.hidden {
            ui.label(format!(
                "[Payload too large to be displayed ({} bytes)]",
                item.payload.len()
            ));
            ui.label("Forward preserves the complete original payload.");
        } else {
            websocket_editor(
                ui,
                &mut self.edit,
                ("ws-intercept", item.id, self.edit_hex),
                self.edit_hex,
            );
        }
    }
}

use anyhow::Context as _;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        project::Project,
        websocket::{Direction, Disposition, Kind},
    };

    fn message(sequence: u64) -> CapturedMessage {
        CapturedMessage {
            summary: MessageSummary {
                session_id: 1,
                sequence,
                direction: Direction::ServerToClient,
                timestamp_ms: 1,
                kind: Kind::Text,
                length: 7,
                disposition: Disposition::Forwarded,
                preview: "payload".into(),
            },
            original: b"payload".to_vec(),
            forwarded: None,
            error: None,
        }
    }

    #[test]
    fn incoming_messages_preserve_session_selection_and_cached_payload() {
        let mut project = Project::temporary();
        project
            .put_ws_session(Session {
                id: 1,
                url: "ws://example.test/socket".into(),
                opened_ms: 1,
                closed_ms: Some(2),
                state: SessionState::Closed,
                subprotocol: "chat".into(),
                message_count: 1,
                close_code: Some(1000),
                close_reason: String::new(),
                error: None,
            })
            .unwrap();
        project.put_ws_message(message(1)).unwrap();
        let engine = Engine::new(project).unwrap();
        let ctx = egui::Context::default();
        let mut state = State {
            session: Some(1),
            selected: Some(1),
            ..Default::default()
        };
        for width in [1150.0, 800.0] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 700.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        state.show(ui, &engine, DisplayTimezone::Utc).unwrap();
                    });
                },
            );
        }
        assert_eq!(&*state.detail, "payload");
        let first = state.detail.clone();
        for sequence in 2..10 {
            engine
                .project
                .lock()
                .unwrap()
                .put_ws_message(message(sequence))
                .unwrap();
            engine.websockets.activity.fetch_add(1, Ordering::SeqCst);
            state.refresh(&engine).unwrap();
            assert_eq!(state.session, Some(1));
            assert_eq!(state.selected, Some(1));
            assert!(Arc::ptr_eq(&first, &state.detail));
        }
        state.payload.as_mut().unwrap().summary.disposition = Disposition::Dropped;
        state.forwarded = true;
        state.render_payload();
        assert_eq!(&*state.detail, "[No forwarded payload: Dropped]");
    }

    #[test]
    fn oversized_pending_payload_is_not_copied_into_the_text_editor() {
        let item = websocket::Intercepted {
            id: 1,
            session_id: 1,
            sequence: 1,
            url: "http://example.test/socket".into(),
            direction: Direction::ClientToServer,
            kind: Kind::Binary,
            payload: vec![255; super::super::response_content::DISPLAY_LIMIT + 1].into(),
        };
        let mut state = State::default();
        state.load(&item);
        assert!(state.hidden);
        assert!(state.edit.is_empty());
    }

    #[test]
    fn session_state_filter_only_changes_visible_rows_and_clears_hidden_selection() {
        let mut project = Project::temporary();
        for (id, status) in [
            (1, SessionState::Closed),
            (2, SessionState::Open),
            (3, SessionState::Error),
        ] {
            project
                .put_ws_session(Session {
                    id,
                    url: "ws://example.test/".into(),
                    opened_ms: 1,
                    closed_ms: None,
                    state: status,
                    subprotocol: String::new(),
                    message_count: 0,
                    close_code: None,
                    close_reason: String::new(),
                    error: None,
                })
                .unwrap();
        }
        project.put_ws_message(message(1)).unwrap();
        let engine = Engine::new(project).unwrap();
        let mut state = State {
            session: Some(1),
            selected: Some(1),
            ..Default::default()
        };
        state.refresh(&engine).unwrap();
        assert_eq!(state.sessions.len(), 3);
        engine
            .project
            .lock()
            .unwrap()
            .workspace
            .websocket_state_filter = Some(SessionState::Open);
        state.refresh(&engine).unwrap();
        assert_eq!(state.sessions.iter().map(|s| s.id).collect::<Vec<_>>(), [2]);
        assert_eq!(state.session, Some(2));
        assert!(state.selected.is_none());
        assert!(state.messages.is_empty());
        engine
            .project
            .lock()
            .unwrap()
            .workspace
            .websocket_state_filter = Some(SessionState::Interrupted);
        state.refresh(&engine).unwrap();
        assert!(state.sessions.is_empty());
        assert!(state.session.is_none());
        assert_eq!(engine.project.lock().unwrap().ws_sessions().len(), 3);
        engine
            .project
            .lock()
            .unwrap()
            .workspace
            .websocket_state_filter = None;
        state.refresh(&engine).unwrap();
        assert_eq!(state.sessions.len(), 3);
    }
}

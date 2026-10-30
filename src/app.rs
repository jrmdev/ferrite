use crate::{
    display_timezone::DisplayTimezone,
    engine::{Decision, Engine, Listener, Stage},
    http::{self, Message},
    intruder::{AttackType, Plan},
    model::{ColorScheme, Exchange, RuleTarget, UpstreamKind},
    preferences::Preferences,
    project::Project,
};
use eframe::egui::{self, Color32, RichText};
mod alerts;
mod browser_view;
mod comparer_view;
mod decoder_view;
mod editor_context;
mod highlight;
mod history_export;
mod history_filters;
mod history_selection;
mod history_table;
mod history_viewport;
mod http_editor;
mod json_preview;
mod mcp_view;
mod repeater_view;
mod request_copy;
mod response_content;
mod scanner_view;
mod theme;
mod websocket_view;
use alerts::{Alerts, Level};
use history_export::{ExportOutcome, HistoryExport};
use history_selection::HistorySelection;
use history_table::HistorySort;
use history_viewport::HistoryViewport;
use http_editor::{http_editor, message_view};
use response_content::ResponseCache;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, atomic::Ordering, mpsc},
    time::Duration,
};
type Result<T> = anyhow::Result<T>;
#[derive(Clone, Copy, PartialEq)]
enum Page {
    AppSettings,
    Target,
    Intercept,
    History,
    Repeater,
    Intruder,
    Scanner,
    Decoder,
    Comparer,
    Proxy,
    Browser,
    Mcp,
    Alerts,
    Plugins,
}
#[derive(Clone, Copy)]
enum FileAction {
    OpenProject,
    NewProject,
    SaveProject,
    ExportCertificate,
    LoadPayloadSet(usize),
    BrowserExecutable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwitchAction {
    NewTemporary,
    NewDisk,
    Open,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwitchState {
    Confirm(SwitchAction),
    Saving(SwitchAction),
    Stopping(SwitchAction),
}
#[derive(Clone, Copy)]
enum SwitchChoice {
    Save,
    Discard,
    Cancel,
}
enum Event {
    FileDialog(FileAction, Option<PathBuf>),
    Started(Result<Listener>),
    Repeater(u64, Result<Exchange>),
    AttackDone(Result<usize>),
    Browser(browser_view::BrowserEvent),
    Mcp(Result<crate::mcp::ipc::IpcServer>),
}
pub struct Workbench {
    engine: Arc<Engine>,
    runtime: Arc<tokio::runtime::Runtime>,
    tx: mpsc::Sender<Event>,
    rx: mpsc::Receiver<Event>,
    page: Page,
    listener: Option<Listener>,
    starting: bool,
    listener_was_running: bool,
    alerts: Alerts,
    project_path: Option<PathBuf>,
    file_dialog_open: bool,
    switch_state: Option<SwitchState>,
    settings_json: String,
    fallback_text: String,
    fallback_dirty: bool,
    scope_include: String,
    scope_exclude: String,
    rows: Vec<Exchange>,
    history_sort: [HistorySort; 2],
    history_selection: [HistorySelection; 2],
    history_viewport: [HistoryViewport; 2],
    history_export: Option<HistoryExport>,
    seen: u64,
    selected: Option<u64>,
    search: String,
    search_regex: bool,
    case_sensitive: bool,
    scope_only: bool,
    response_hex: bool,
    response_cache: ResponseCache,
    message: String,
    intercept_id: Option<u64>,
    intercept_edit: String,
    intercept_hex: bool,
    intercept_omission: Option<response_content::BodyOmitted>,
    /// Selected Repeater tab ID.
    repeater_tab: u64,
    /// Tab IDs with a send in flight.
    repeater_busy: Vec<u64>,
    repeater_flow: Option<u64>,
    repeater_cursor: usize,
    attack_cancel: Option<tokio::sync::watch::Sender<bool>>,
    attack_running: bool,
    attack_payloads: Vec<String>,
    attack_generation: u64,
    preferences: Preferences,
    websocket_view: websocket_view::State,
    websocket_intercept: bool,
    timezone_search: String,
    scanner_view: scanner_view::State,
    browser: browser_view::State,
    mcp: Arc<crate::mcp::host::Host>,
    mcp_view: mcp_view::State,
    decoder: decoder_view::State,
    comparer: comparer_view::State,
    /// Exchanges whose comment is being edited, with the draft text.
    comment_edit: Option<(Vec<u64>, String)>,
}
fn hex(bytes: &[u8]) -> String {
    http::hex_dump(bytes)
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    http::parse_hex(text)
}
fn editable(bytes: &[u8]) -> (String, bool) {
    http::editor_text(bytes)
}
fn subsection_heading(ui: &mut egui::Ui, title: &str) {
    ui.label(RichText::new(title).size(15.0).strong());
}
fn decode_editor(text: &str, is_hex: bool) -> Result<Message> {
    http::from_editor_buffer(text, is_hex)
}
// Keep binary messages byte-editable while also exposing their HTTP headers as text.
fn hex_headers(
    ui: &mut egui::Ui,
    text: &str,
    is_hex: bool,
    document: impl std::hash::Hash,
) -> Option<egui::Response> {
    if !is_hex {
        return None;
    }
    let bytes = unhex(text).ok()?;
    let end = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&bytes[..end]);
    ui.label("HTTP headers · raw message below in hex");
    let height = (ui.available_height() * 0.3).min(110.0);
    let output = ui.allocate_ui(egui::vec2(ui.available_width(), height), |ui| {
        http_editor(ui, &mut head.as_ref(), document)
    });
    ui.separator();
    Some(output.inner.inner.response)
}
fn editor(ui: &mut egui::Ui, text: &mut String, rows: usize, id: impl std::hash::Hash) {
    egui::ScrollArea::both()
        .id_salt(id)
        .max_height((rows as f32) * 18.0)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(rows)
                    .code_editor(),
            );
        });
}

fn compact_rows(ui: &mut egui::Ui) {
    let spacing = ui.spacing_mut();
    spacing.item_spacing.y = 2.0;
    spacing.button_padding.y = 1.0;
    spacing.interact_size.y = 20.0;
}

fn table_arrow_navigation(
    ui: &mut egui::Ui,
    id: egui::Id,
    selected: Option<usize>,
    len: usize,
) -> Option<usize> {
    ui.interact(
        egui::Rect::NOTHING,
        id,
        egui::Sense::focusable_noninteractive(),
    );
    if !ui.memory(|memory| memory.has_focus(id)) {
        return None;
    }
    let direction = ui.input_mut(|input| {
        if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
            -1
        } else if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
            1
        } else {
            0
        }
    });
    let current = selected.filter(|index| *index < len)?;
    match direction {
        -1 if current > 0 => Some(current - 1),
        1 if current + 1 < len => Some(current + 1),
        _ => None,
    }
}

fn focus_table(ui: &egui::Ui, id: egui::Id) {
    ui.memory_mut(|memory| memory.request_focus(id));
}

fn split_panes(ui: &mut egui::Ui, id: &str, vertical: bool, initial: f32) -> [egui::Ui; 2] {
    let (rect, _) = ui.allocate_exact_size(
        ui.available_rect_before_wrap()
            .intersect(ui.clip_rect())
            .size()
            .max(egui::vec2(1.0, 1.0)),
        egui::Sense::hover(),
    );
    let key = ui.id().with(id);
    let mut ratio = ui.data_mut(|data| *data.get_temp_mut_or_insert_with(key, || initial));
    let length = if vertical {
        rect.height()
    } else {
        rect.width()
    };
    let usable = (length - 8.0).max(0.0);
    let mut offset = usable * ratio;
    let bar = if vertical {
        egui::Rect::from_min_size(
            rect.min + egui::vec2(0.0, offset),
            egui::vec2(rect.width(), 8.0),
        )
    } else {
        egui::Rect::from_min_size(
            rect.min + egui::vec2(offset, 0.0),
            egui::vec2(8.0, rect.height()),
        )
    };
    let response = ui
        .interact(bar, key, egui::Sense::drag())
        .on_hover_cursor(if vertical {
            egui::CursorIcon::ResizeVertical
        } else {
            egui::CursorIcon::ResizeHorizontal
        });
    if response.dragged()
        && let Some(pointer) = response.interact_pointer_pos()
    {
        offset = if vertical {
            pointer.y - rect.top()
        } else {
            pointer.x - rect.left()
        };
        ratio = (offset / usable.max(1.0)).clamp(0.15, 0.85);
        ui.data_mut(|data| data.insert_temp(key, ratio));
        offset = usable * ratio;
    }
    let color = if response.hovered() || response.dragged() {
        ui.visuals().selection.bg_fill
    } else {
        ui.visuals().widgets.noninteractive.bg_stroke.color
    };
    // Draw at the new position during a drag as well.
    let (first, second) = if vertical {
        let y = rect.top() + offset;
        ui.painter()
            .hline(rect.x_range(), y + 4.0, egui::Stroke::new(2.0_f32, color));
        (
            egui::Rect::from_min_max(rect.min, egui::pos2(rect.right(), y)),
            egui::Rect::from_min_max(egui::pos2(rect.left(), y + 8.0), rect.max),
        )
    } else {
        let x = rect.left() + offset;
        ui.painter()
            .vline(x + 4.0, rect.y_range(), egui::Stroke::new(2.0_f32, color));
        (
            egui::Rect::from_min_max(rect.min, egui::pos2(x, rect.bottom())),
            egui::Rect::from_min_max(egui::pos2(x + 8.0, rect.top()), rect.max),
        )
    };
    let mut index = 0;
    [first, second].map(|rect| {
        index += 1;
        let mut child = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(rect)
                .id_salt((id, index))
                .layout(egui::Layout::top_down(egui::Align::Min)),
        );
        child.set_clip_rect(rect.intersect(ui.clip_rect()));
        child
    })
}

#[derive(Clone, Copy)]
enum EntryAction {
    CopyUrl,
    CopyCurl,
    CopyPython,
    /// Copy the request (false) or response (true) as text.
    CopyMessage(bool),
    /// Send the request (false) or response (true) to a Comparer slot.
    Comparer(bool, comparer_view::Slot),
    /// Send the request (false) or response (true) to Decoder.
    Decoder(bool),
    /// Set or clear the highlight colour of stored exchanges.
    Highlight(Option<crate::history::Highlight>),
    /// Edit the comment of stored exchanges.
    Comment,
    Repeater,
    Intruder,
    Scanner,
    Delete,
    AddScope,
    RemoveScope,
    AddUrlScope,
    ExcludeUrlScope,
    Export,
}
fn entry_menu(response: &egui::Response, export: bool) -> Option<EntryAction> {
    item_menu(response, export, Some("Delete"))
}
fn item_menu(response: &egui::Response, export: bool, delete: Option<&str>) -> Option<EntryAction> {
    let mut action = None;
    response.context_menu(|ui| {
        ui.menu_button("Copy", |ui| {
            for (label, value) in [
                ("URL", EntryAction::CopyUrl),
                ("Request", EntryAction::CopyMessage(false)),
                ("Response", EntryAction::CopyMessage(true)),
                ("as curl", EntryAction::CopyCurl),
                ("as Python requests", EntryAction::CopyPython),
            ] {
                if ui.button(label).clicked() {
                    action = Some(value);
                    ui.close();
                }
            }
        });
        ui.menu_button("Send To", |ui| {
            for (label, value) in [
                ("Repeater", EntryAction::Repeater),
                ("Intruder", EntryAction::Intruder),
                ("Scanner", EntryAction::Scanner),
            ] {
                if ui.button(label).clicked() {
                    action = Some(value);
                    ui.close();
                }
            }
            ui.menu_button("Comparer", |ui| {
                for (label, value) in [
                    (
                        "Request as A",
                        EntryAction::Comparer(false, comparer_view::Slot::A),
                    ),
                    (
                        "Request as B",
                        EntryAction::Comparer(false, comparer_view::Slot::B),
                    ),
                    (
                        "Response as A",
                        EntryAction::Comparer(true, comparer_view::Slot::A),
                    ),
                    (
                        "Response as B",
                        EntryAction::Comparer(true, comparer_view::Slot::B),
                    ),
                ] {
                    if ui.button(label).clicked() {
                        action = Some(value);
                        ui.close();
                    }
                }
            });
            ui.menu_button("Decoder", |ui| {
                for (label, value) in [
                    ("Request", EntryAction::Decoder(false)),
                    ("Response", EntryAction::Decoder(true)),
                ] {
                    if ui.button(label).clicked() {
                        action = Some(value);
                        ui.close();
                    }
                }
            });
        });
        ui.separator();
        if let Some(label) = delete
            && ui.button(label).clicked()
        {
            action = Some(EntryAction::Delete);
            ui.close();
        }
        for (label, entries) in [
            (
                "Add to scope",
                [
                    ("Host", EntryAction::AddScope),
                    ("URL", EntryAction::AddUrlScope),
                ],
            ),
            (
                "Exclude from scope",
                [
                    ("Host", EntryAction::RemoveScope),
                    ("URL", EntryAction::ExcludeUrlScope),
                ],
            ),
        ] {
            ui.menu_button(label, |ui| {
                for (label, value) in entries {
                    if ui.button(label).clicked() {
                        action = Some(value);
                        ui.close();
                    }
                }
            });
        }
        if export {
            ui.separator();
            ui.menu_button("Highlight", |ui| {
                for colour in crate::history::Highlight::ALL {
                    let [r, g, b] = colour.rgb();
                    if ui
                        .button(
                            RichText::new(format!("■ {}", colour.label()))
                                .color(Color32::from_rgb(r, g, b)),
                        )
                        .clicked()
                    {
                        action = Some(EntryAction::Highlight(Some(colour)));
                        ui.close();
                    }
                }
                if ui.button("None").clicked() {
                    action = Some(EntryAction::Highlight(None));
                    ui.close();
                }
            });
            if ui.button("Comment…").clicked() {
                action = Some(EntryAction::Comment);
                ui.close();
            }
            if ui.button("Export selected items").clicked() {
                action = Some(EntryAction::Export);
                ui.close();
            }
        }
    });
    action
}
impl Workbench {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        engine: Arc<Engine>,
        runtime: Arc<tokio::runtime::Runtime>,
        path: Option<PathBuf>,
        preferences: Preferences,
    ) -> Self {
        Self::with_context(&cc.egui_ctx, engine, runtime, path, preferences)
    }
    fn with_context(
        ctx: &egui::Context,
        engine: Arc<Engine>,
        runtime: Arc<tokio::runtime::Runtime>,
        path: Option<PathBuf>,
        preferences: Preferences,
    ) -> Self {
        theme::apply(ctx, preferences.scheme());
        json_preview::configure(
            ctx,
            engine.project.lock().unwrap().workspace.beautify_json,
            Arc::as_ptr(&engine) as usize,
        );
        let (tx, rx) = mpsc::channel();
        let s = engine.settings();
        let mcp = crate::mcp::host::Host::new(
            engine.clone(),
            preferences.mcp().clone(),
            crate::mcp::host::HostMode::Gui,
        );
        let start_mcp = preferences.mcp().enabled;
        let attack_payloads = engine
            .project
            .lock()
            .unwrap()
            .workspace
            .intruder
            .payload_sets
            .iter()
            .map(|s| s.join("\n"))
            .collect();
        let (initial_repeater_tab, initial_repeater_flow, initial_repeater_cursor) = engine
            .project
            .lock()
            .unwrap()
            .workspace
            .repeater
            .first()
            .map(|tab| {
                (
                    tab.id,
                    tab.history.last().copied(),
                    tab.history.len().saturating_sub(1),
                )
            })
            .unwrap_or_default();
        Self {
            engine,
            runtime,
            tx,
            rx,
            page: Page::Proxy,
            listener: None,
            starting: false,
            listener_was_running: false,
            alerts: Alerts::default(),
            project_path: path,
            file_dialog_open: false,
            switch_state: None,
            fallback_text: s.fallback.as_ref().map(|d| d.origin()).unwrap_or_default(),
            fallback_dirty: false,
            settings_json: serde_json::to_string_pretty(&s).unwrap(),
            scope_include: s.scope.include.join("\n"),
            scope_exclude: s.scope.exclude.join("\n"),
            rows: vec![],
            history_sort: [HistorySort::default(); 2],
            history_selection: Default::default(),
            history_viewport: Default::default(),
            history_export: None,
            seen: u64::MAX,
            selected: None,
            search: String::new(),
            search_regex: false,
            case_sensitive: false,
            scope_only: false,
            response_hex: false,
            response_cache: ResponseCache::default(),
            message: String::new(),
            intercept_id: None,
            intercept_edit: String::new(),
            intercept_hex: false,
            intercept_omission: None,
            repeater_tab: initial_repeater_tab,
            repeater_busy: vec![],
            repeater_flow: initial_repeater_flow,
            repeater_cursor: initial_repeater_cursor,
            attack_cancel: None,
            attack_running: false,
            attack_payloads,
            attack_generation: 0,
            preferences,
            websocket_view: websocket_view::State::default(),
            websocket_intercept: false,
            timezone_search: String::new(),
            scanner_view: scanner_view::State::default(),
            browser: browser_view::State::default(),
            mcp,
            mcp_view: mcp_view::State::default(),
            decoder: decoder_view::State::default(),
            comparer: comparer_view::State::default(),
            comment_edit: None,
        }
        .started(start_mcp)
    }
    fn started(mut self, start_mcp: bool) -> Self {
        if start_mcp {
            self.start_mcp();
        }
        self
    }
    fn report<T>(&mut self, result: Result<T>) -> Option<T> {
        match result {
            Ok(v) => Some(v),
            Err(e) => {
                let message = format!("{e:#}");
                self.alerts
                    .push(Level::Error, "Application", message.clone());
                self.message = message;
                None
            }
        }
    }
    fn notify(&mut self, source: &str, message: impl Into<String>) {
        self.message = message.into();
        self.alerts.push(Level::Info, source, self.message.clone());
    }
    fn refresh(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::FileDialog(action, path) => {
                    self.file_dialog_open = false;
                    if let Some(path) = path {
                        self.complete_file_action(action, path);
                    } else if matches!(action, FileAction::SaveProject)
                        && matches!(self.switch_state, Some(SwitchState::Saving(_)))
                    {
                        self.switch_state = None;
                    }
                }
                Event::Started(result) => {
                    self.starting = false;
                    if let Some(listener) = self.report(result) {
                        self.notify("Proxy", format!("Listening on {}", listener.address));
                        self.listener = Some(listener);
                    }
                    if self.browser.launch_after_start {
                        if self.listener.is_some() {
                            self.launch_browser();
                        } else {
                            self.browser.launch_after_start = false;
                        }
                    }
                }
                Event::Browser(event) => self.browser_event(event),
                Event::Mcp(result) => self.mcp_started(result),
                Event::Repeater(tab, result) => self.repeater_sent(tab, result),
                Event::AttackDone(result) => {
                    self.attack_running = false;
                    self.attack_cancel = None;
                    if let Some(n) = self.report(result) {
                        self.notify(
                            "Intruder",
                            format!("Intruder finished: {n} requests completed"),
                        );
                    }
                }
            }
        }
        let current = self.engine.activity.load(Ordering::SeqCst);
        if current != self.seen {
            let list = self.engine.project.lock().unwrap().list();
            if let Some(rows) = self.report(list) {
                let previous_ids: std::collections::BTreeSet<_> =
                    self.rows.iter().map(|flow| flow.id).collect();
                for flow in &rows {
                    if !previous_ids.contains(&flow.id)
                        && let Some(error) = &flow.error
                    {
                        self.alerts.push_at(
                            flow.timestamp_ms,
                            Level::Error,
                            &flow.tool,
                            format!("#{} {} {}: {error}", flow.id, flow.method, flow.url),
                        );
                    }
                }
                self.rows = rows;
                self.seen = current;
            }
        }
        let errors: Vec<_> = self.engine.errors.lock().unwrap().drain(..).collect();
        for error in errors {
            self.alerts.push(Level::Error, "Connection", error);
        }
        let running = self.engine.is_running();
        if self.listener_was_running && !running {
            self.notify("Proxy", "Listener stopped");
        }
        self.listener_was_running = running;
        if self.listener.is_some() && !self.engine.is_running() {
            self.listener = None;
        }
    }
    fn persist(&mut self) {
        let result = self.engine.project.lock().unwrap().save_workspace();
        self.report(result);
    }
    fn apply_settings(&mut self) -> bool {
        let result = (|| -> Result<()> {
            let mut settings: crate::model::Settings = serde_json::from_str(&self.settings_json)?;
            if self.fallback_dirty {
                settings.fallback = if self.fallback_text.is_empty() {
                    None
                } else {
                    Some(crate::model::Destination::from_url(&self.fallback_text)?)
                };
            }
            self.engine.configure(settings)
        })();
        if self.report(result).is_some() {
            let s = self.engine.settings();
            self.fallback_text = s.fallback.as_ref().map(|d| d.origin()).unwrap_or_default();
            self.fallback_dirty = false;
            self.settings_json = serde_json::to_string_pretty(&s).unwrap();
            self.scope_include = s.scope.include.join("\n");
            self.scope_exclude = s.scope.exclude.join("\n");
            self.notify(
                "Settings",
                "Settings saved. Restart the listener after changing bind or invisible mode.",
            );
            true
        } else {
            false
        }
    }
    fn start(&mut self) {
        if self.starting || self.engine.is_running() {
            return;
        }
        self.starting = true;
        let tx = self.tx.clone();
        let engine = self.engine.clone();
        self.runtime.spawn(async move {
            let _ = tx.send(Event::Started(engine.start().await));
        });
    }
    fn stop(&mut self) {
        if let Some(listener) = self.listener.take() {
            self.runtime.spawn(async move {
                listener.stop().await;
            });
        }
        self.engine.drop_pending();
    }
    fn busy(&self) -> bool {
        self.starting
            || self.engine.is_running()
            || self.attack_running
            || !self.repeater_busy.is_empty()
            || self.engine.scanner.is_busy()
    }
    fn switch_project(&mut self, project: Project, path: Option<PathBuf>) -> bool {
        let project = Engine::new_with_key(project, self.preferences.ca_key());
        if let Some(engine) = self.report(project) {
            self.engine = engine;
            self.mcp.set_engine(self.engine.clone());
            self.alerts.clear();
            self.listener_was_running = false;
            self.project_path = path;
            self.rows.clear();
            self.seen = u64::MAX;
            self.websocket_view = websocket_view::State::default();
            self.scanner_view = scanner_view::State::default();
            self.selected = None;
            self.history_selection = Default::default();
            self.history_viewport = Default::default();
            self.history_export = None;
            self.response_cache = ResponseCache::default();
            let first = self
                .engine
                .project
                .lock()
                .unwrap()
                .workspace
                .repeater
                .first()
                .cloned();
            match first {
                Some(tab) => self.select_repeater_tab(&tab),
                None => {
                    (self.repeater_tab, self.repeater_flow, self.repeater_cursor) = (0, None, 0);
                }
            }
            self.intercept_id = None;
            let s = self.engine.settings();
            self.settings_json = serde_json::to_string_pretty(&s).unwrap();
            self.fallback_text = s.fallback.as_ref().map(|d| d.origin()).unwrap_or_default();
            self.fallback_dirty = false;
            self.settings_json = serde_json::to_string_pretty(&s).unwrap();
            self.scope_include = s.scope.include.join("\n");
            self.scope_exclude = s.scope.exclude.join("\n");
            self.attack_payloads = self
                .engine
                .project
                .lock()
                .unwrap()
                .workspace
                .intruder
                .payload_sets
                .iter()
                .map(|s| s.join("\n"))
                .collect();
            self.notify("Project", "Project opened; proxy stopped.");
            true
        } else {
            false
        }
    }
    fn choose_file(&mut self, ctx: &egui::Context, action: FileAction) {
        if self.file_dialog_open {
            return;
        }
        self.file_dialog_open = true;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let path = match action {
                FileAction::OpenProject => rfd::FileDialog::new()
                    .set_title("Open project")
                    .add_filter("Ferrite project", &["ferrite"])
                    .pick_file(),
                FileAction::NewProject | FileAction::SaveProject => rfd::FileDialog::new()
                    .set_title(if matches!(action, FileAction::NewProject) {
                        "New on-disk project"
                    } else {
                        "Save project"
                    })
                    .add_filter("Ferrite project", &["ferrite"])
                    .set_file_name("project.ferrite")
                    .save_file(),
                FileAction::ExportCertificate => rfd::FileDialog::new()
                    .set_title("Export public CA certificate")
                    .add_filter("PEM certificate", &["pem"])
                    .set_file_name("ferrite-ca.pem")
                    .save_file(),
                FileAction::LoadPayloadSet(index) => rfd::FileDialog::new()
                    .set_title(format!("Load payload set {}", index + 1))
                    .add_filter("Payload list", &["txt", "lst", "csv"])
                    .pick_file(),
                FileAction::BrowserExecutable => rfd::FileDialog::new()
                    .set_title("Choose a Chromium-family browser executable")
                    .pick_file(),
            };
            let _ = tx.send(Event::FileDialog(action, path));
            ctx.request_repaint();
        });
    }
    fn complete_file_action(&mut self, action: FileAction, path: PathBuf) {
        if matches!(action, FileAction::OpenProject | FileAction::NewProject) && self.busy() {
            self.notify(
                "Project",
                "Stop the proxy and finish or cancel active sends before switching projects.",
            );
            return;
        }
        match action {
            FileAction::OpenProject => {
                let current = self
                    .project_path
                    .as_ref()
                    .and_then(|p| p.canonicalize().ok());
                if current.is_some() && current == path.canonicalize().ok() {
                    self.notify("Project", "This project is already open.");
                } else if let Some(project) = self.report(Project::open_existing(&path)) {
                    self.switch_project(project, Some(path));
                }
            }
            FileAction::NewProject => {
                if let Some(project) = self.report(Project::create(&path)) {
                    self.switch_project(project, Some(path));
                }
            }
            FileAction::SaveProject => {
                let result = self.engine.project.lock().unwrap().save_to_disk(&path);
                if self.report(result).is_some() {
                    self.project_path = Some(path.clone());
                    self.notify("Project", format!("Project saved to {}", path.display()));
                    if let Some(SwitchState::Saving(action)) = self.switch_state {
                        self.switch_state = Some(SwitchState::Stopping(action));
                    }
                } else if matches!(self.switch_state, Some(SwitchState::Saving(_))) {
                    self.switch_state = None;
                }
            }
            FileAction::BrowserExecutable => self.complete_browser_pick(path),
            FileAction::ExportCertificate => {
                let result =
                    std::fs::write(&path, self.engine.authority.pem()).map_err(anyhow::Error::from);
                if self.report(result).is_some() {
                    self.notify("Proxy", format!("CA exported to {}", path.display()));
                }
            }
            FileAction::LoadPayloadSet(index) => {
                let result = std::fs::read_to_string(&path).map_err(anyhow::Error::from);
                if let Some(contents) = self.report(result)
                    && index < self.attack_payloads.len()
                {
                    let contents = contents.strip_prefix('\u{feff}').unwrap_or(&contents);
                    self.attack_payloads[index] = contents.to_owned();
                    let payload_sets = self
                        .attack_payloads
                        .iter()
                        .map(|set| set.lines().map(str::to_string).collect())
                        .collect();
                    let save = {
                        let mut project = self.engine.project.lock().unwrap();
                        project.workspace.intruder.payload_sets = payload_sets;
                        project.save_workspace()
                    };
                    if self.report(save).is_some() {
                        self.notify(
                            "Intruder",
                            format!(
                                "Loaded {} payloads into set {} from {}",
                                contents.lines().count(),
                                index + 1,
                                path.display()
                            ),
                        );
                    }
                }
            }
        }
    }
    fn choose_switch(&mut self, choice: SwitchChoice, ctx: &egui::Context) {
        let Some(SwitchState::Confirm(action)) = self.switch_state else {
            return;
        };
        match choice {
            SwitchChoice::Cancel => self.switch_state = None,
            SwitchChoice::Discard => self.switch_state = Some(SwitchState::Stopping(action)),
            SwitchChoice::Save if self.project_path.is_none() => {
                self.switch_state = Some(SwitchState::Saving(action));
                self.choose_file(ctx, FileAction::SaveProject);
            }
            SwitchChoice::Save => {
                let result = self.engine.project.lock().unwrap().save_workspace();
                if self.report(result).is_some() {
                    self.switch_state = Some(SwitchState::Stopping(action));
                } else {
                    self.switch_state = None;
                }
            }
        }
    }
    fn advance_switch(&mut self, ctx: &egui::Context) {
        let Some(SwitchState::Stopping(action)) = self.switch_state else {
            return;
        };
        if self.listener.is_some() {
            self.stop();
        }
        if let Some(cancel) = &self.attack_cancel {
            let _ = cancel.send(true);
        }
        {
            let _entered = self.runtime.enter();
            let _ = crate::scanner::runner::shutdown(self.engine.clone());
        }
        if self.busy() {
            return;
        }
        self.switch_state = None;
        match action {
            SwitchAction::NewTemporary => {
                self.switch_project(Project::temporary(), None);
            }
            SwitchAction::NewDisk => self.choose_file(ctx, FileAction::NewProject),
            SwitchAction::Open => self.choose_file(ctx, FileAction::OpenProject),
        }
    }
    fn switch_dialog(&mut self, ctx: &egui::Context) {
        match self.switch_state {
            Some(SwitchState::Confirm(_)) => {
                egui::Modal::new(egui::Id::new("confirm-project-switch")).show(ctx, |ui| {
                    ui.heading("Save current project?");
                    ui.label("Would you like to save the current project before switching?");
                    if self.project_path.is_some() {
                        ui.label("Disk projects save changes automatically.");
                    }
                    if self.busy() {
                        ui.label("Switching stops the proxy, drops pending interceptions, cancels Intruder and Scanner work, and waits for Repeater sends to finish.");
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() { self.choose_switch(SwitchChoice::Save, ctx); }
                        if ui.button("Don't save").clicked() { self.choose_switch(SwitchChoice::Discard, ctx); }
                        if ui.button("Cancel").clicked() { self.choose_switch(SwitchChoice::Cancel, ctx); }
                    });
                });
            }
            Some(SwitchState::Stopping(_)) if self.busy() => {
                egui::Modal::new(egui::Id::new("stopping-project-work")).show(ctx, |ui| {
                    ui.label("Stopping the proxy and waiting for active sends to finish…");
                });
            }
            _ => {}
        }
    }
    fn projects(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.add_space(8.0);
        ui.heading("Global settings");
        subsection_heading(ui, "Color scheme");
        let mut scheme = self.preferences.scheme();
        let previous = scheme;
        egui::ComboBox::from_label("Theme")
            .selected_text(scheme.label())
            .show_ui(ui, |ui| {
                for option in ColorScheme::ALL {
                    ui.selectable_value(&mut scheme, option, option.label());
                }
            });
        if scheme != previous {
            let result = self.preferences.set_scheme(scheme);
            if self.report(result).is_some() {
                theme::apply(ui.ctx(), scheme);
            }
        }
        ui.label("The color scheme applies to all projects.");
        ui.add_space(12.0);
        subsection_heading(ui, "Timezone");
        let mut timezone = self.preferences.timezone();
        let previous = timezone;
        egui::ComboBox::from_label("Display timezone")
            .selected_text(timezone.label())
            .width(280.0)
            .height(300.0)
            .show_ui(ui, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.timezone_search)
                        .hint_text("Search timezones"),
                );
                let query = self.timezone_search.to_lowercase();
                for option in [DisplayTimezone::Utc, DisplayTimezone::Local] {
                    if option.label().to_lowercase().contains(&query) {
                        ui.selectable_value(&mut timezone, option, option.label());
                    }
                }
                for zone in chrono_tz::TZ_VARIANTS {
                    if zone != chrono_tz::UTC && zone.name().to_lowercase().contains(&query) {
                        ui.selectable_value(
                            &mut timezone,
                            DisplayTimezone::Named(zone),
                            zone.name(),
                        );
                    }
                }
            });
        if timezone != previous {
            let result = self.preferences.set_timezone(timezone);
            self.report(result);
        }
        ui.weak("Display only, across all projects. Stored timestamps and exports stay unchanged.");
        ui.add_space(12.0);
        ui.separator();
        ui.heading("Project settings");
        let mut beautify = self.engine.project.lock().unwrap().workspace.beautify_json;
        let previous = beautify;
        if ui.checkbox(&mut beautify, "Beautify JSON").changed() {
            let result = {
                let mut project = self.engine.project.lock().unwrap();
                project.workspace.beautify_json = beautify;
                let result = project.save_workspace();
                if result.is_err() {
                    project.workspace.beautify_json = previous;
                }
                result
            };
            if self.report(result).is_some() {
                json_preview::configure(ui.ctx(), beautify, Arc::as_ptr(&self.engine) as usize);
            }
        }
        ui.add(egui::Label::new(RichText::new("Visually formats JSON requests and responses with a JSON Content-Type, and valid JSON WebSocket payloads throughout this project. Display only; stored and sent bytes are unchanged.").weak()).wrap());
        ui.add_space(12.0);
        let mut settings = self.engine.settings();
        if ui
            .checkbox(&mut settings.passive_scanning, "Enable passive scanning")
            .changed()
            && self.report(self.engine.configure(settings)).is_some()
        {
            self.settings_json = serde_json::to_string_pretty(&self.engine.settings()).unwrap();
        }
        ui.add(egui::Label::new(RichText::new("Analyze new in-scope HTTP exchanges without sending additional requests. Existing history is not scanned.").weak()).wrap());
        ui.add_space(12.0);
        subsection_heading(ui, "Project file");
        let name = self.engine.project.lock().unwrap().workspace.name.clone();
        ui.label(format!("Current: {name}"));
        ui.label(
            self.project_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "Temporary project in memory".into()),
        );
        ui.add_space(12.0);
        let busy = self.busy();
        ui.horizontal_wrapped(|ui| {
            ui.add_enabled_ui(
                !self.file_dialog_open && self.switch_state.is_none(),
                |ui| {
                    if ui.button("New temporary").clicked() {
                        self.switch_state = Some(SwitchState::Confirm(SwitchAction::NewTemporary));
                    }
                    if ui.button("New on-disk").clicked() {
                        self.switch_state = Some(SwitchState::Confirm(SwitchAction::NewDisk));
                    }
                    if ui.button("Open").clicked() {
                        self.switch_state = Some(SwitchState::Confirm(SwitchAction::Open));
                    }
                },
            );
            let can_save = !self.file_dialog_open && self.switch_state.is_none();
            if ui
                .add_enabled(can_save, egui::Button::new("Save"))
                .clicked()
            {
                if self.project_path.is_some() {
                    let result = self.engine.project.lock().unwrap().save_workspace();
                    if self.report(result).is_some() {
                        self.notify("Project", "Project saved.");
                    }
                } else {
                    self.choose_file(ui.ctx(), FileAction::SaveProject);
                }
            }
        });
        if busy {
            ui.label("Switching projects will stop the proxy and settle active work.");
        }
        ui.add_space(12.0);
        ui.add(egui::Label::new("Disk projects automatically save settings, HTTP history, Repeater tabs and sends, and Intruder configuration and results. Save a temporary project to keep it on disk.").wrap());
    }
    fn public_ca(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.file_dialog_open, egui::Button::new("Export CA"))
                .clicked()
            {
                self.choose_file(ui.ctx(), FileAction::ExportCertificate);
            }
            if ui
                .add_enabled(
                    !self.busy() && !self.file_dialog_open,
                    egui::Button::new("Regenerate CA"),
                )
                .clicked()
            {
                let result = self.preferences.regenerate_ca();
                if let Some(authority) = self.report(result) {
                    self.engine.authority.replace(authority);
                    self.notify(
                        "Proxy",
                        "CA regenerated. Export and trust the new certificate in your browser.",
                    );
                }
            }
        });
        ui.label("The built-in browser (Open browser) trusts this CA automatically, only inside its isolated profile. For other browsers or devices, import this public certificate as a certificate authority to intercept HTTPS.");
        ui.label(format!(
            "Current CA SHA-256 fingerprint: {}",
            self.engine.authority.fingerprint()
        ));
        ui.label("The CA is shared across projects and persists across restarts. After regenerating, export and trust the new certificate in your browser.");
        if self.busy() {
            ui.label("Stop the proxy and finish or cancel active sends to regenerate the CA.");
        }
    }

    fn search_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Search");
            ui.text_edit_singleline(&mut self.search);
            ui.checkbox(&mut self.search_regex, "Regex");
            ui.checkbox(&mut self.case_sensitive, "Case sensitive");
            ui.checkbox(&mut self.scope_only, "In scope");
        });
    }
    fn filtered(&self, flow: &Exchange, pattern: Option<&regex::bytes::Regex>) -> bool {
        if self.scope_only && !self.engine.settings().scope.contains(&flow.url) {
            return false;
        }
        if self.search.is_empty() {
            return true;
        }
        let mut bytes = flow.url.as_bytes().to_vec();
        bytes.extend_from_slice(flow.tool.as_bytes());
        bytes.extend_from_slice(&flow.request);
        bytes.extend_from_slice(&flow.response);
        if let Some(pattern) = pattern {
            pattern.is_match(&bytes)
        } else {
            false
        }
    }
    fn search_pattern(&self) -> Result<regex::bytes::Regex> {
        regex::bytes::RegexBuilder::new(&if self.search_regex {
            self.search.clone()
        } else {
            regex::escape(&self.search)
        })
        .case_insensitive(!self.case_sensitive)
        .build()
        .map_err(Into::into)
    }
    fn history(&mut self, ui: &mut egui::Ui, intruder_only: bool) {
        if !intruder_only && let Some(id) = self.websocket_view.reveal_handshake {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "Showing WebSocket handshake #{id} alongside the filtered history."
                ));
                if ui.button("Use current filters").clicked() {
                    self.websocket_view.reveal_handshake = None;
                }
            });
        }
        let mut filter = self
            .engine
            .project
            .lock()
            .unwrap()
            .workspace
            .history_filter
            .clone();
        if intruder_only {
            self.search_bar(ui);
        } else {
            history_filters::show(ui, &mut filter);
            let mut project = self.engine.project.lock().unwrap();
            if project.workspace.history_filter != filter {
                project.workspace.history_filter = filter.clone();
                let result = project.save_workspace();
                drop(project);
                self.report(result);
            }
        }
        let pattern = match if intruder_only {
            self.search_pattern().map(Some)
        } else {
            Ok(None)
        } {
            Ok(r) => r,
            Err(e) => {
                ui.colored_label(ui.visuals().error_fg_color, e.to_string());
                None
            }
        };
        let compiled = match filter.compile() {
            Ok(r) => Some(r),
            Err(e) => {
                if !intruder_only {
                    ui.colored_label(
                        ui.visuals().error_fg_color,
                        format!("Invalid search pattern: {e}"),
                    );
                }
                None
            }
        };
        let scope = self.engine.settings().scope;
        let annotations = self.engine.project.lock().unwrap().annotations().clone();
        let mut rows: Vec<_> = self
            .rows
            .iter()
            .filter(|r| {
                if intruder_only {
                    r.tool.starts_with("Intruder") && self.filtered(r, pattern.as_ref())
                } else {
                    self.websocket_view.reveal_handshake == Some(r.id)
                        || compiled
                            .as_ref()
                            .is_some_and(|filter| filter.matches(r, &scope, annotations.get(&r.id)))
                }
            })
            .collect();
        ui.label(format!(
            "{} matching / {} stored exchanges · {} selected",
            rows.len(),
            self.rows.len(),
            self.history_selection[usize::from(intruder_only)].ids.len()
        )).on_hover_text("Ctrl/Cmd-click to toggle rows; Shift-click to select a range. Right-click to export the selection.");
        let [mut list, mut detail] = split_panes(ui, "history-detail", true, 0.38);
        let action = history_table::show(
            &mut list,
            &mut rows,
            &mut self.history_selection[usize::from(intruder_only)],
            &mut self.history_sort[usize::from(intruder_only)],
            &mut self.history_viewport[usize::from(intruder_only)],
            history_table::TableView {
                intruder: intruder_only,
                timezone: self.preferences.timezone(),
                annotations: &annotations,
            },
        );
        if let Some((ids, action)) = action {
            self.entry_action(ui.ctx(), &ids, action);
        }
        if let Some(flow) = self.history_selection[usize::from(intruder_only)]
            .focused
            .and_then(|id| self.rows.iter().find(|r| r.id == id))
            .cloned()
        {
            self.flow_view(&mut detail, &flow);
        } else {
            detail.label("Select an exchange to inspect its request and response.");
        }
    }
    fn entry_action(&mut self, ctx: &egui::Context, ids: &[u64], action: EntryAction) {
        if matches!(action, EntryAction::Delete) {
            let result = self.engine.project.lock().unwrap().delete(ids);
            if self.report(result).is_some() {
                self.rows.retain(|flow| !ids.contains(&flow.id));
                if self.selected.is_some_and(|id| ids.contains(&id)) {
                    self.selected = None;
                }
                if self.repeater_flow.is_some_and(|id| ids.contains(&id)) {
                    self.repeater_flow = None;
                }
                self.engine.activity.fetch_add(1, Ordering::SeqCst);
                self.engine
                    .websockets
                    .activity
                    .fetch_add(1, Ordering::SeqCst);
            }
            return;
        }
        let by_id: BTreeMap<_, _> = self.rows.iter().map(|flow| (flow.id, flow)).collect();
        let flows = ids
            .iter()
            .filter_map(|id| by_id.get(id).map(|flow| (*flow).clone()))
            .collect();
        self.exchange_action(ctx, flows, action);
    }
    fn exchange_action(&mut self, ctx: &egui::Context, flows: Vec<Exchange>, action: EntryAction) {
        match action {
            EntryAction::CopyUrl | EntryAction::CopyCurl | EntryAction::CopyPython => {
                if let Some(flow) = flows.iter().max_by_key(|flow| flow.id) {
                    let text = match action {
                        EntryAction::CopyUrl => Ok(flow.url.clone()),
                        EntryAction::CopyCurl => request_copy::curl(flow),
                        EntryAction::CopyPython => request_copy::python(flow),
                        _ => unreachable!(),
                    };
                    if let Some(text) = self.report(text) {
                        ctx.copy_text(text);
                    }
                }
            }
            EntryAction::CopyMessage(response) => {
                if let Some(flow) = flows.iter().max_by_key(|flow| flow.id) {
                    let bytes = if response {
                        &flow.response
                    } else {
                        &flow.request
                    };
                    ctx.copy_text(String::from_utf8_lossy(bytes).into_owned());
                }
            }
            EntryAction::Comparer(response, slot) => {
                if let Some(flow) = flows.iter().max_by_key(|flow| flow.id) {
                    let part = if response { "response" } else { "request" };
                    let label = if flow.id == 0 {
                        format!("Repeater {part}")
                    } else {
                        format!("#{} {part}", flow.id)
                    };
                    let bytes = if response {
                        &flow.response
                    } else {
                        &flow.request
                    };
                    self.send_to_comparer(slot, label, &bytes.clone());
                }
            }
            EntryAction::Decoder(response) => {
                if let Some(flow) = flows.iter().max_by_key(|flow| flow.id) {
                    self.decoder.set_input(if response {
                        &flow.response
                    } else {
                        &flow.request
                    });
                    self.page = Page::Decoder;
                }
            }
            EntryAction::Highlight(colour) => {
                let result = {
                    let mut project = self.engine.project.lock().unwrap();
                    let changes: Vec<_> = flows
                        .iter()
                        .filter(|flow| flow.id != 0)
                        .map(|flow| {
                            let mut annotation =
                                project.annotation(flow.id).cloned().unwrap_or_default();
                            annotation.highlight = colour;
                            (flow.id, annotation)
                        })
                        .collect();
                    project.set_annotations(&changes)
                };
                self.report(result);
            }
            EntryAction::Comment => {
                let ids: Vec<u64> = flows.iter().map(|f| f.id).filter(|id| *id != 0).collect();
                let current = ids
                    .first()
                    .and_then(|id| self.engine.project.lock().unwrap().annotation(*id).cloned())
                    .map(|a| a.comment)
                    .unwrap_or_default();
                if !ids.is_empty() {
                    self.comment_edit = Some((ids, current));
                }
            }
            EntryAction::Repeater => {
                for flow in &flows {
                    self.send_to_repeater(flow);
                }
            }
            EntryAction::Intruder => {
                if let Some(flow) = flows.iter().max_by_key(|flow| flow.id) {
                    self.send_to_intruder(flow);
                }
            }
            EntryAction::Scanner => self.send_to_scanner(flows),
            EntryAction::Export => self.history_export = Some(HistoryExport::new(flows)),
            EntryAction::Delete => self.entry_action(
                ctx,
                &flows.iter().map(|flow| flow.id).collect::<Vec<_>>(),
                action,
            ),
            EntryAction::AddScope
            | EntryAction::RemoveScope
            | EntryAction::AddUrlScope
            | EntryAction::ExcludeUrlScope => {
                let mut settings = self.engine.settings();
                let host_action =
                    matches!(action, EntryAction::AddScope | EntryAction::RemoveScope);
                let included = matches!(action, EntryAction::AddScope | EntryAction::AddUrlScope);
                let values: std::collections::BTreeSet<_> = flows
                    .iter()
                    .map(|flow| {
                        if host_action {
                            url::Url::parse(&flow.url)
                                .ok()
                                .and_then(|url| url.host_str().map(str::to_owned))
                                .unwrap_or_else(|| flow.destination.host.clone())
                        } else {
                            flow.url.clone()
                        }
                    })
                    .collect();
                for value in values {
                    let result = if host_action {
                        settings.scope.set_host(&value, included)
                    } else {
                        settings.scope.set_url(&value, included)
                    };
                    if self.report(result).is_none() {
                        return;
                    }
                }
                if self.report(self.engine.configure(settings)).is_some() {
                    let settings = self.engine.settings();
                    self.scope_include = settings.scope.include.join("\n");
                    self.scope_exclude = settings.scope.exclude.join("\n");
                    self.settings_json = serde_json::to_string_pretty(&settings).unwrap();
                    self.notify("Scope", "Scope updated. Exclusions take precedence.");
                }
            }
        }
    }
    fn comment_dialog(&mut self, ctx: &egui::Context) {
        let Some((ids, draft)) = &mut self.comment_edit else {
            return;
        };
        let mut save = None;
        let mut close = false;
        egui::Modal::new(egui::Id::new("history-comment")).show(ctx, |ui| {
            ui.heading(if ids.len() == 1 {
                format!("Comment on #{}", ids[0])
            } else {
                format!("Comment on {} exchanges", ids.len())
            });
            ui.add(
                egui::TextEdit::multiline(draft)
                    .desired_rows(4)
                    .desired_width(420.0)
                    .hint_text("Notes are stored in the project and searchable in History"),
            );
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    save = Some((ids.clone(), draft.clone()));
                }
                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        });
        if let Some((ids, comment)) = save {
            let result = {
                let mut project = self.engine.project.lock().unwrap();
                let changes: Vec<_> = ids
                    .iter()
                    .map(|id| {
                        let mut annotation = project.annotation(*id).cloned().unwrap_or_default();
                        annotation.comment = comment.trim().to_string();
                        (*id, annotation)
                    })
                    .collect();
                project.set_annotations(&changes)
            };
            self.report(result);
            close = true;
        }
        if close {
            self.comment_edit = None;
        }
    }
    fn editor_action(
        &mut self,
        ctx: &egui::Context,
        action: EntryAction,
        snapshot: Result<Exchange>,
        pending: Option<u64>,
    ) {
        if matches!(action, EntryAction::Delete)
            && let Some(id) = pending
        {
            let result = self.engine.decide(id, Decision::Drop);
            self.report(result);
            self.intercept_id = None;
        } else if let Some(flow) = self.report(snapshot) {
            self.exchange_action(ctx, vec![flow], action);
        }
    }
    fn flow_view(&mut self, ui: &mut egui::Ui, flow: &Exchange) {
        ui.horizontal(|ui| {
            if ui.button("Send to Repeater").clicked() {
                self.send_to_repeater(flow);
            }
            if ui.button("Send to Intruder").clicked() {
                self.send_to_intruder(flow);
            }
            ui.checkbox(&mut self.response_hex, "Hex");
            if ui.button("Send to Scanner").clicked() {
                self.send_to_scanner(vec![flow.clone()]);
            }
            let title = format!("{} {}", flow.method, flow.url);
            ui.add(
                egui::Label::new(RichText::new(&title).strong())
                    .truncate()
                    .show_tooltip_when_elided(false),
            )
            .on_hover_text(&title);
        });
        if let Some(e) = &flow.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        let request = message_view(&flow.request, self.response_hex);
        let response = self.response_cache.get(
            flow.id,
            &flow.response,
            self.response_hex,
            self.engine.settings().max_message_bytes,
        );
        highlight::find_bar(ui, &[("request", &request), ("response", &response)]);
        ui.separator();
        let [mut request_ui, mut response_ui] = split_panes(ui, "flow-editors", false, 0.5);
        subsection_heading(&mut request_ui, "Request");
        subsection_heading(&mut response_ui, "Response");
        let request_output = http_editor(
            &mut request_ui,
            &mut request.as_str(),
            ("request-view", flow.id, self.response_hex),
        );
        let response_output = http_editor(
            &mut response_ui,
            &mut response.as_ref(),
            ("response-view", flow.id, self.response_hex),
        );
        let action = entry_menu(&request_output.inner.response, true)
            .or_else(|| entry_menu(&response_output.inner.response, true));
        if let Some(action) = action {
            self.exchange_action(ui.ctx(), vec![flow.clone()], action);
        }
    }
    fn send_to_scanner(&mut self, flows: Vec<Exchange>) {
        let result = {
            let _entered = self.runtime.enter();
            crate::scanner::runner::start(self.engine.clone(), flows)
        };
        if let Some(id) = self.report(result) {
            self.scanner_view.select_scan(id);
            self.page = Page::Scanner;
            self.notify("Scanner", format!("Scan #{id} started"));
        }
    }
    fn scanner(&mut self, ui: &mut egui::Ui) {
        let result = {
            let _entered = self.runtime.enter();
            self.scanner_view
                .show(ui, &self.engine, self.preferences.timezone())
        };
        if let Some(Some(message)) = self.report(result) {
            self.notify("Scanner", message);
        }
        if let Some((action, flow)) = self.scanner_view.take_action() {
            self.exchange_action(ui.ctx(), vec![flow], action);
        }
    }
    fn send_to_intruder(&mut self, flow: &Exchange) {
        if let Ok(text) = std::str::from_utf8(&flow.request) {
            let mut p = self.engine.project.lock().unwrap();
            p.workspace.intruder.destination = flow.destination.origin();
            p.workspace.intruder.template = text.into();
            drop(p);
            self.page = Page::Intruder;
            self.persist();
        } else {
            self.notify(
                "Intruder",
                "Intruder templates currently require UTF-8. Repeater supports hex requests.",
            );
        }
    }
    fn intercept(&mut self, ui: &mut egui::Ui) {
        ui.heading("Intercept");
        ui.horizontal_wrapped(|ui| {
            for (stage, label) in [
                (Stage::Request, "Intercept requests"),
                (Stage::Response, "Intercept responses"),
            ] {
                let mut enabled = self.engine.intercept_enabled(stage);
                if ui.checkbox(&mut enabled, label).changed() {
                    self.engine.set_intercept(stage, enabled);
                }
            }
            let mut intercept_ws = self.engine.websockets.enabled();
            if ui.checkbox(&mut intercept_ws, "Intercept WebSockets").changed() {
                self.engine.websockets.set_enabled(intercept_ws);
                if intercept_ws { self.websocket_intercept = true; }
            }
            let mut settings = self.engine.settings();
            if ui.checkbox(&mut settings.intercept_in_scope_only, "Limit to scope")
                .on_hover_text("Only pause in-scope requests and responses. Other traffic is forwarded normally.")
                .changed()
                && self.report(self.engine.configure(settings)).is_some()
            {
                self.settings_json = serde_json::to_string_pretty(&self.engine.settings()).unwrap();
            }
            let pending = self.engine.pending();
            if !pending.is_empty() || self.engine.websockets.pending_count() > 0 {
                if ui.button("Drop all pending").clicked() {
                    self.engine.drop_pending();
                    self.engine.websockets.drop_all();
                    self.intercept_id = None;
                }
                if ui.button("Forward all pending")
                    .on_hover_text("Forward all queued messages, including edits to the selected message.")
                    .clicked() {
                    let selected = (!self.websocket_intercept).then_some(self.intercept_id).flatten().and_then(|id| pending.iter().find(|item| item.id == id));
                    let edited = selected.map(|item| {
                        editor_context::intercept_forward(
                            item,
                            &self.intercept_edit,
                            self.intercept_hex,
                            self.engine.settings().max_message_bytes,
                        ).map(|message| (item.id, message))
                    }).transpose();
                    if let Some(edited) = self.report(edited) {
                        let ws_edit = if self.websocket_intercept { self.websocket_view.pending_edit(&self.engine) } else { Ok(None) };
                        let Some(ws_edit) = self.report(ws_edit) else { return; };
                        let ws_forward = self.engine.websockets.forward_all(ws_edit, self.engine.settings().max_message_bytes);
                        if self.report(ws_forward).is_none() { return; }
                        let result = self.engine.forward_pending(edited);
                        if self.report(result).is_some() {
                            self.intercept_id = None;
                        }
                    }
                }
            }
        });
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.websocket_intercept,
                false,
                format!("HTTP ({})", self.engine.pending_count()),
            );
            ui.selectable_value(
                &mut self.websocket_intercept,
                true,
                format!("WebSockets ({})", self.engine.websockets.pending_count()),
            );
        });
        if self.websocket_intercept {
            self.websocket_view.intercept(ui, &self.engine);
            return;
        }
        let pending = self.engine.pending();
        ui.label(format!("{} pending messages", pending.len()));
        ui.horizontal_wrapped(|ui| {
            for item in &pending {
                if ui
                    .selectable_label(
                        self.intercept_id == Some(item.id),
                        format!(
                            "#{} {:?} {}",
                            item.id,
                            item.stage,
                            item.destination.authority()
                        ),
                    )
                    .clicked()
                {
                    self.intercept_id = None;
                    self.load_intercept(item);
                }
            }
        });
        if !pending.iter().any(|p| Some(p.id) == self.intercept_id) {
            self.intercept_id = None;
            if let Some(item) = pending.first() {
                self.load_intercept(item);
            }
        }
        if let Some(id) = self.intercept_id {
            ui.horizontal(|ui| {
                if ui.button("Forward").clicked() {
                    let message = pending
                        .iter()
                        .find(|item| item.id == id)
                        .ok_or_else(|| anyhow::anyhow!("Message is no longer pending"))
                        .and_then(|item| {
                            editor_context::intercept_forward(
                                item,
                                &self.intercept_edit,
                                self.intercept_hex,
                                self.engine.settings().max_message_bytes,
                            )
                        });
                    if let Some(message) = self.report(message) {
                        let result = self.engine.decide(id, Decision::Forward(message));
                        self.report(result);
                        self.intercept_id = None;
                    }
                }
                if ui.button("Drop").clicked() {
                    let result = self.engine.decide(id, Decision::Drop);
                    self.report(result);
                    self.intercept_id = None;
                }
                let label = if self.intercept_hex {
                    "Switch to text"
                } else {
                    "Switch to hex"
                };
                if ui.button(label).clicked()
                    && let Some(message) =
                        self.report(decode_editor(&self.intercept_edit, self.intercept_hex))
                {
                    let bytes = message.encode();
                    if self.intercept_hex {
                        match String::from_utf8(bytes) {
                            Ok(s) => {
                                self.intercept_edit = s;
                                self.intercept_hex = false;
                            }
                            Err(_) => self.notify(
                                "Intercept",
                                "This message contains binary bytes; keep hex mode.",
                            ),
                        }
                    } else {
                        self.intercept_edit = hex(&bytes);
                        self.intercept_hex = true;
                    }
                }
            });
            ui.separator();
            let headers = hex_headers(
                ui,
                &self.intercept_edit,
                self.intercept_hex,
                ("intercept-headers", id),
            );
            let output = if let Some(omitted) = &self.intercept_omission {
                let output = ui
                    .allocate_ui(
                        egui::vec2(
                            ui.available_width(),
                            (ui.available_height() - 48.0).max(40.0),
                        ),
                        |ui| {
                            http_editor(
                                ui,
                                &mut self.intercept_edit,
                                ("intercept-editor", id, self.intercept_hex),
                            )
                        },
                    )
                    .inner;
                ui.label(omitted.notice());
                ui.weak("The full body is preserved. Only HTTP headers can be edited here.");
                output
            } else {
                http_editor(
                    ui,
                    &mut self.intercept_edit,
                    ("intercept-editor", id, self.intercept_hex),
                )
            };
            let action = item_menu(&output.inner.response, false, Some("Drop")).or_else(|| {
                headers
                    .as_ref()
                    .and_then(|response| item_menu(response, false, Some("Drop")))
            });
            if let Some(action) = action {
                let snapshot = pending
                    .iter()
                    .find(|item| item.id == id)
                    .ok_or_else(|| anyhow::anyhow!("Message is no longer pending"))
                    .and_then(|item| {
                        editor_context::intercept(item, &self.intercept_edit, self.intercept_hex)
                    });
                self.editor_action(ui.ctx(), action, snapshot, Some(id));
            }
        } else {
            ui.label("Enable interception and send browser traffic through the listener. Messages will appear here.");
        }
    }
    fn load_intercept(&mut self, item: &crate::engine::Intercepted) {
        self.intercept_id = Some(item.id);
        self.intercept_omission = if item.stage == Stage::Response {
            response_content::body_preview(&item.message, self.engine.settings().max_message_bytes)
                .omitted
        } else {
            None
        };
        if self.intercept_omission.is_some() {
            let headers = Message {
                start: item.message.start.clone(),
                headers: item.message.headers.clone(),
                body: vec![],
            };
            self.intercept_edit =
                String::from_utf8(headers.encode()).expect("HTTP headers are UTF-8");
            self.intercept_hex = false;
            return;
        }
        let preview = if item.stage == Stage::Response {
            response_content::decoded(&item.message, self.engine.settings().max_message_bytes)
        } else {
            None
        };
        let (text, is_hex) = editable(&preview.as_ref().unwrap_or(&item.message).encode());
        self.intercept_edit = text;
        self.intercept_hex = is_hex;
    }
    fn target(&mut self, ui: &mut egui::Ui) {
        ui.heading("Target");
        ui.columns(2, |cols| {
            cols[0].strong("Include URL regex (one per line)");
            cols[1].strong("Exclude URL regex (one per line)");
            editor(&mut cols[0], &mut self.scope_include, 4, "include");
            editor(&mut cols[1], &mut self.scope_exclude, 4, "exclude");
        });
        if ui.button("Apply scope").clicked() {
            let mut s = self.engine.settings();
            s.scope.include = self
                .scope_include
                .lines()
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            s.scope.exclude = self
                .scope_exclude
                .lines()
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            if self.report(self.engine.configure(s)).is_some() {
                self.settings_json = serde_json::to_string_pretty(&self.engine.settings()).unwrap();
                self.notify("Scope", "Scope saved. Exclusions take precedence; an empty include list matches nothing.");
            }
        }
        self.search_bar(ui);
        let pattern = self.search_pattern().ok();
        let mut sites: BTreeMap<String, SiteNode> = BTreeMap::new();
        for flow in &self.rows {
            if !self.filtered(flow, pattern.as_ref()) {
                continue;
            }
            let origin = flow.destination.origin();
            let node = sites.entry(origin).or_default();
            if let Ok(url) = url::Url::parse(&flow.url) {
                let mut current = node;
                for part in url.path().split('/').filter(|s| !s.is_empty()) {
                    current = current.children.entry(part.to_string()).or_default();
                }
                current.ids.push(flow.id);
            }
        }
        let [mut list, mut detail] = split_panes(ui, "target-detail", true, 0.35);
        let mut action = None;
        egui::ScrollArea::vertical()
            .id_salt("sitemap")
            .auto_shrink([false, false])
            .show(&mut list, |ui| {
                compact_rows(ui);
                for (host, node) in sites {
                    let header = egui::CollapsingHeader::new(host)
                        .default_open(false)
                        .show(ui, |ui| {
                            site_node(ui, &node, &mut self.selected, &mut action)
                        });
                    if let Some(value) = entry_menu(&header.header_response, false) {
                        action = Some((node.all_ids(), value));
                    }
                }
            });
        if let Some((ids, value)) = action {
            self.entry_action(ui.ctx(), &ids, value);
        }
        if let Some(flow) = self
            .selected
            .and_then(|id| self.rows.iter().find(|r| r.id == id))
            .cloned()
        {
            self.flow_view(&mut detail, &flow);
        } else {
            detail.label("Select an exchange to inspect its request and response.");
        }
    }

    fn intruder(&mut self, ui: &mut egui::Ui) {
        ui.heading("Intruder");
        let mut attack = self
            .engine
            .project
            .lock()
            .unwrap()
            .workspace
            .intruder
            .clone();
        ui.add_enabled_ui(!self.attack_running, |ui| {
            ui.horizontal(|ui| {
                ui.label("Target");
                ui.text_edit_singleline(&mut attack.destination);
                egui::ComboBox::from_id_salt("attack-kind")
                    .selected_text(format!("{:?}", attack.kind))
                    .show_ui(ui, |ui| {
                        for kind in [
                            AttackType::Sniper,
                            AttackType::BatteringRam,
                            AttackType::Pitchfork,
                            AttackType::ClusterBomb,
                        ] {
                            ui.selectable_value(&mut attack.kind, kind, format!("{kind:?}"));
                        }
                    });
                ui.label("Concurrency");
                ui.add(egui::DragValue::new(&mut attack.concurrency).range(1..=128));
                ui.label("Delay ms");
                ui.add(egui::DragValue::new(&mut attack.delay_ms).range(0..=60000));
            });
            ui.label("Place paired § markers around payload positions, for example ?q=§test§.");
            ui.allocate_ui(egui::vec2(ui.available_width(), 120.0), |ui| {
                http_editor(ui, &mut attack.template, "attack-template");
            });
            ui.horizontal(|ui| {
                subsection_heading(ui, "Payload sets");
                if ui.button("Add set").clicked() {
                    self.attack_payloads.push(String::new());
                }
                if self.attack_payloads.len() > 1 && ui.button("Remove last set").clicked() {
                    self.attack_payloads.pop();
                }
            });
            let mut load_payload_set = None;
            ui.horizontal_wrapped(|ui| {
                for (i, text) in self.attack_payloads.iter_mut().enumerate() {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(format!("Set {} (one payload per line)", i + 1));
                            if ui.small_button("Load file…").clicked() {
                                load_payload_set = Some(i);
                            }
                        });
                        ui.add(
                            egui::TextEdit::multiline(text)
                                .font(egui::TextStyle::Monospace)
                                .desired_rows(4)
                                .desired_width(210.0),
                        );
                    });
                }
            });
            if let Some(index) = load_payload_set {
                self.choose_file(ui.ctx(), FileAction::LoadPayloadSet(index));
            }
            attack.payload_sets = self
                .attack_payloads
                .iter()
                .map(|s| s.lines().map(str::to_string).collect())
                .collect();
        });
        let plan = Plan::new(attack.clone());
        ui.horizontal(|ui| {
            match &plan {
                Ok(p) => {
                    ui.label(format!("{} requests", p.count));
                }
                Err(e) => {
                    ui.label(e.to_string());
                }
            }
            if ui
                .add_enabled(
                    !self.attack_running && plan.is_ok(),
                    egui::Button::new("Start attack"),
                )
                .clicked()
            {
                let dest = crate::model::Destination::from_url(&attack.destination);
                if self.report(dest).is_some() {
                    let (cancel, rx) = tokio::sync::watch::channel(false);
                    self.attack_cancel = Some(cancel);
                    self.attack_running = true;
                    self.attack_generation += 1;
                    let engine = self.engine.clone();
                    let tx = self.tx.clone();
                    let a = attack.clone();
                    self.runtime.spawn(async move {
                        let _ =
                            tx.send(Event::AttackDone(crate::intruder::run(engine, a, rx).await));
                    });
                }
            }
            if ui
                .add_enabled(self.attack_running, egui::Button::new("Cancel"))
                .clicked()
                && let Some(cancel) = &self.attack_cancel
            {
                let _ = cancel.send(true);
            }
        });
        let mut p = self.engine.project.lock().unwrap();
        if serde_json::to_string(&p.workspace.intruder).unwrap()
            != serde_json::to_string(&attack).unwrap()
        {
            p.workspace.intruder = attack;
            let result = p.save_workspace();
            drop(p);
            self.report(result);
        } else {
            drop(p);
        }
        ui.separator();
        self.history(ui, true);
    }
    fn settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Proxy");
        ui.horizontal(|ui| {
            if self.engine.is_running() {
                if ui
                    .add_enabled(self.listener.is_some(), egui::Button::new("Stop listener"))
                    .clicked()
                {
                    self.stop();
                }
            } else if ui
                .add_enabled(
                    !self.starting,
                    egui::Button::new(if self.starting {
                        "Starting…"
                    } else {
                        "Start listener"
                    }),
                )
                .clicked()
                && self.apply_settings()
            {
                self.start();
            }
            ui.label(
                self.listener
                    .as_ref()
                    .map(|listener| listener.address.to_string())
                    .unwrap_or_else(|| self.engine.settings().listen),
            );
            ui.separator();
            self.browser_controls(ui);
        });
        ui.separator();
        let parsed = serde_json::from_str::<crate::model::Settings>(&self.settings_json);
        if let Ok(mut s) = parsed {
            let rules_before = s.rules.clone();
            ui.horizontal(|ui| {
                ui.label("Listen");
                ui.text_edit_singleline(&mut s.listen);
                ui.checkbox(&mut s.transparent, "Invisible / transparent HTTP + TLS");
            });
            if s.transparent {
                ui.horizontal(|ui| {
                    ui.label("Fallback target");
                    if ui.text_edit_singleline(&mut self.fallback_text).changed() {
                        self.fallback_dirty = true;
                    }
                });
            }
            ui.horizontal(|ui| {
                ui.label("Upstream");
                egui::ComboBox::from_id_salt("upstream-kind")
                    .selected_text(format!("{:?}", s.upstream.kind))
                    .show_ui(ui, |ui| {
                        for kind in [
                            UpstreamKind::Direct,
                            UpstreamKind::Http,
                            UpstreamKind::Socks5,
                        ] {
                            ui.selectable_value(
                                &mut s.upstream.kind,
                                kind.clone(),
                                format!("{kind:?}"),
                            );
                        }
                    });
                if s.upstream.kind != UpstreamKind::Direct {
                    ui.label("Host");
                    ui.text_edit_singleline(&mut s.upstream.host);
                    ui.label("Port");
                    ui.add(egui::DragValue::new(&mut s.upstream.port));
                }
            });
            if s.upstream.kind != UpstreamKind::Direct {
                ui.horizontal(|ui| {
                    ui.label("Username");
                    ui.text_edit_singleline(&mut s.upstream.username);
                    ui.label("Password");
                    ui.add(egui::TextEdit::singleline(&mut s.upstream.password).password(true));
                    if s.upstream.kind == UpstreamKind::Socks5 {
                        ui.checkbox(&mut s.upstream.remote_dns, "SOCKS remote DNS");
                    }
                });
            }
            ui.horizontal(|ui| {
                ui.checkbox(&mut s.verify_tls, "Verify upstream TLS certificates");
                ui.label("Timeout seconds");
                ui.add(egui::DragValue::new(&mut s.timeout_secs).range(1..=3600));
            });
            ui.horizontal(|ui| {
                ui.checkbox(&mut s.drop_out_of_scope, "Drop out of scope");
                ui.checkbox(&mut s.intercept_in_scope_only, "Intercept in scope only");
                ui.checkbox(&mut s.rules_in_scope_only, "Rules in scope only");
            });
            ui.separator();
            subsection_heading(ui, "CA certificate");
            self.public_ca(ui);
            ui.separator();
            subsection_heading(ui, "Match and replace");
            let mut remove = None;
            for (i, rule) in s.rules.iter_mut().enumerate() {
                ui.push_id(i, |ui| {
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut rule.enabled, "On");
                        egui::ComboBox::from_id_salt("rule-target")
                            .selected_text(format!("{:?}", rule.target))
                            .show_ui(ui, |ui| {
                                for t in [
                                    RuleTarget::RequestHeader,
                                    RuleTarget::RequestBody,
                                    RuleTarget::ResponseHeader,
                                    RuleTarget::ResponseBody,
                                ] {
                                    ui.selectable_value(&mut rule.target, t, format!("{t:?}"));
                                }
                            });
                        ui.checkbox(&mut rule.regex, "Regex");
                        ui.add(
                            egui::TextEdit::singleline(&mut rule.pattern)
                                .hint_text("Match")
                                .desired_width(200.0),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut rule.replacement)
                                .hint_text("Replace")
                                .desired_width(200.0),
                        );
                        if ui.button("Remove").clicked() {
                            remove = Some(i);
                        }
                    });
                });
            }
            if let Some(i) = remove {
                s.rules.remove(i);
            }
            if ui.button("Add rule").clicked() {
                s.rules.push(crate::model::ReplaceRule {
                    enabled: true,
                    ..Default::default()
                });
            }
            self.settings_json = serde_json::to_string_pretty(&s).unwrap();
            if s.rules != rules_before {
                let mut configured = self.engine.settings();
                configured.rules = s.rules;
                let result = self.engine.configure(configured);
                self.report(result);
            }
        }
        egui::CollapsingHeader::new("Advanced JSON: DNS overrides, message limits, rule ordering")
            .show(ui, |ui| {
                editor(ui, &mut self.settings_json, 18, "settings-json");
            });
        ui.label("Invisible mode accepts origin-form HTTP and direct TLS with SNI. DNS overrides route redirected hosts back to the real server. When invisible mode is enabled, a fallback target can handle clients without Host/SNI.");
    }
}
#[derive(Default)]
struct SiteNode {
    children: BTreeMap<String, SiteNode>,
    ids: Vec<u64>,
}
impl SiteNode {
    fn all_ids(&self) -> Vec<u64> {
        self.ids
            .iter()
            .copied()
            .chain(self.children.values().flat_map(Self::all_ids))
            .collect()
    }
}
fn site_node(
    ui: &mut egui::Ui,
    node: &SiteNode,
    selected: &mut Option<u64>,
    action: &mut Option<(Vec<u64>, EntryAction)>,
) {
    for id in &node.ids {
        let response = ui.selectable_label(*selected == Some(*id), format!("Exchange #{id}"));
        if response.clicked() {
            *selected = Some(*id);
        }
        if let Some(value) = entry_menu(&response, false) {
            *action = Some((vec![*id], value));
        }
    }
    for (path, child) in &node.children {
        let header = egui::CollapsingHeader::new(path)
            .id_salt((path, child.all_ids().first()))
            .show(ui, |ui| site_node(ui, child, selected, action));
        if let Some(value) = entry_menu(&header.header_response, false) {
            *action = Some((child.all_ids(), value));
        }
    }
}
fn timestamp(milliseconds: u64, timezone: DisplayTimezone) -> String {
    timezone.format(milliseconds)
}
impl eframe::App for Workbench {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.refresh();
        self.poll_browser(ctx);
        self.advance_switch(ctx);
        json_preview::configure(
            ctx,
            self.engine.project.lock().unwrap().workspace.beautify_json,
            Arc::as_ptr(&self.engine) as usize,
        );
        ctx.request_repaint_after(Duration::from_millis(100));
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("FERRITE")
                        .size(22.0)
                        .color(if ui.visuals().dark_mode {
                            Color32::from_rgb(85, 205, 190)
                        } else {
                            Color32::from_rgb(0, 105, 96)
                        })
                        .strong(),
                );
                ui.label("HTTP testing workbench");
                ui.separator();
                ui.label(self.engine.project.lock().unwrap().workspace.name.clone());
                ui.separator();
                ui.label(if self.engine.is_running() {
                    "⏺ Proxy running"
                } else {
                    "○ Proxy stopped"
                });
                if self.browser.process.is_some() {
                    ui.separator();
                    ui.label("⏺ Browser open");
                }
                if let Some(status) = self.mcp_status() {
                    ui.separator();
                    if ui.selectable_label(false, status).clicked() {
                        self.page = Page::Mcp;
                    }
                }
            });
        });
        egui::SidePanel::left("nav")
            .exact_width(145.0)
            .show(ctx, |ui| {
                ui.add_space(16.0);
                for (page, name) in [
                    (Page::AppSettings, "Settings"),
                    (Page::Proxy, "Proxy"),
                    (Page::Browser, "Browser"),
                    (Page::Mcp, "MCP"),
                    (Page::Target, "Target"),
                    (Page::Intercept, "Intercept"),
                    (Page::History, "History"),
                    (Page::Repeater, "Repeater"),
                    (Page::Intruder, "Intruder"),
                    (Page::Scanner, "Scanner"),
                    (Page::Decoder, "Decoder"),
                    (Page::Comparer, "Comparer"),
                    (Page::Alerts, &self.alerts.label()),
                    (Page::Plugins, "Plugins"),
                ] {
                    ui.add_space(7.0);
                    ui.selectable_value(&mut self.page, page, name);
                }
            });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.small_button(self.alerts.label()).clicked() {
                    self.page = Page::Alerts;
                }
                if !self.message.is_empty() && ui.small_button("Clear").clicked() {
                    self.message.clear();
                }
                ui.add(egui::Label::new(self.message.lines().next().unwrap_or("")).truncate())
                    .on_hover_text(&self.message);
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            let scroll_page = matches!(
                self.page,
                Page::AppSettings
                    | Page::Proxy
                    | Page::Browser
                    | Page::Mcp
                    | Page::Decoder
                    | Page::Plugins
            );
            let show_page = |ui: &mut egui::Ui| match self.page {
                Page::AppSettings => self.projects(ui),
                Page::Target => self.target(ui),
                Page::Intercept => self.intercept(ui),
                Page::History => {
                    ui.heading("History");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.websocket_view.show_history, false, "HTTP");
                        ui.selectable_value(
                            &mut self.websocket_view.show_history,
                            true,
                            "WebSockets",
                        );
                    });
                    if self.websocket_view.show_history {
                        let result =
                            self.websocket_view
                                .show(ui, &self.engine, self.preferences.timezone());
                        if let Some(Some(id)) = self.report(result) {
                            self.websocket_view.show_history = false;
                            self.websocket_view.reveal_handshake = Some(id);
                            self.history_selection[0].focused = Some(id);
                            self.history_selection[0].ids.clear();
                            self.history_selection[0].ids.insert(id);
                        }
                    } else {
                        self.history(ui, false);
                    }
                }
                Page::Repeater => self.repeater(ui),
                Page::Intruder => self.intruder(ui),
                Page::Scanner => self.scanner(ui),
                Page::Decoder => self.decoder(ui),
                Page::Comparer => self.comparer_page(ui),
                Page::Proxy => self.settings(ui),
                Page::Browser => self.browser_page(ui),
                Page::Mcp => self.mcp_page(ui),
                Page::Alerts => self.alerts.show(ui, self.preferences.timezone()),
                Page::Plugins => {
                    ui.heading("Plugins");
                    ui.label("Ferrite does not load third-party code yet.");
                    ui.add_space(6.0);
                    ui.label("To automate Ferrite or connect AI assistants today, use the MCP server: it exposes history, Repeater, scanner and WebSocket data and in-scope request sending, with permissions, scope enforcement and an audit trail.");
                    if ui.button("Open MCP settings").clicked() {
                        self.page = Page::Mcp;
                    }
                    ui.add_space(6.0);
                    ui.weak("A sandboxed WebAssembly plugin system (capability-based, resource-limited, with scope-enforced network access) is proposed in docs/PLUGINS.md.");
                }
            };
            if scroll_page {
                egui::ScrollArea::vertical()
                    .id_salt("page")
                    .show(ui, show_page);
            } else {
                let mut show_page = show_page;
                show_page(ui);
            }
        });
        self.switch_dialog(ctx);
        self.browser_dialogs(ctx);
        self.mcp_dialogs(ctx);
        self.comment_dialog(ctx);
        if let Some(mut export) = self.history_export.take() {
            match export.show(ctx) {
                ExportOutcome::Saved(message) => self.notify("History", message),
                ExportOutcome::Cancelled => {}
                ExportOutcome::Failed(message) => {
                    self.report::<()>(Err(anyhow::anyhow!(message)));
                    self.history_export = Some(export);
                }
                ExportOutcome::Open => self.history_export = Some(export),
            }
        }
    }
    fn on_exit(&mut self) {
        {
            let _entered = self.runtime.enter();
            let _ = crate::scanner::runner::shutdown(self.engine.clone());
        }
        if let Some(cancel) = &self.attack_cancel {
            let _ = cancel.send(true);
        }
        self.shutdown_browser();
        self.mcp.deny_all();
        // Dropping the bridge disconnects clients and removes the endpoint file.
        self.mcp_view.server.take();
        self.stop();
        self.persist();
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use crate::model::RepeaterTab;

    #[test]
    fn selected_save_file_becomes_active_project() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("assessment.ferrite");
        let project = Project::temporary();
        let preferences =
            Preferences::load_at(&dir.path().join("settings.json"), &project).unwrap();
        let engine = Engine::new_with_key(project, preferences.ca_key()).unwrap();
        let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let mut app = Workbench::with_context(
            &egui::Context::default(),
            engine,
            runtime,
            None,
            preferences,
        );
        app.file_dialog_open = true;
        app.tx
            .send(Event::FileDialog(
                FileAction::SaveProject,
                Some(path.clone()),
            ))
            .unwrap();
        app.refresh();
        assert!(!app.file_dialog_open);
        assert_eq!(app.project_path.as_ref(), Some(&path));
        assert_eq!(
            app.engine.project.lock().unwrap().workspace.name,
            "assessment"
        );
        app.engine.project.lock().unwrap().workspace.name = "Updated".into();
        app.engine.project.lock().unwrap().save_workspace().unwrap();
        drop(app);
        assert_eq!(
            Project::open_existing(&path).unwrap().workspace.name,
            "Updated"
        );
    }

    #[test]
    fn save_dialog_can_replace_an_existing_project() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.ferrite");
        drop(Project::create(&path).unwrap());
        let mut project = Project::temporary();
        project.workspace.name = "Replacement".into();
        project.save_to_disk(&path).unwrap();
        assert_eq!(project.workspace.name, "Replacement");
        drop(project);
        assert_eq!(
            Project::open_existing(&path).unwrap().workspace.name,
            "Replacement"
        );
    }

    fn test_workbench(dir: &std::path::Path) -> Workbench {
        let project = Project::temporary();
        let preferences = Preferences::load_at(&dir.join("settings.json"), &project).unwrap();
        let engine = Engine::new_with_key(project, preferences.ca_key()).unwrap();
        let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
        Workbench::with_context(
            &egui::Context::default(),
            engine,
            runtime,
            None,
            preferences,
        )
    }

    #[test]
    fn copy_actions_emit_clipboard_text_from_current_request_edits() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_workbench(dir.path());
        let ctx = egui::Context::default();
        let tab = RepeaterTab {
            destination: "https://example.test:8443".into(),
            request: "POST /edited?q=1 HTTP/1.1\nHost: virtual.test\nCookie: id=secret\n\nnew body"
                .into(),
            ..Default::default()
        };
        for action in [
            EntryAction::CopyUrl,
            EntryAction::CopyCurl,
            EntryAction::CopyPython,
        ] {
            let output = ctx.run(egui::RawInput::default(), |ctx| {
                app.editor_action(ctx, action, editor_context::repeater(&tab), None);
            });
            let copied = output
                .platform_output
                .commands
                .iter()
                .find_map(|command| {
                    if let egui::OutputCommand::CopyText(text) = command {
                        Some(text)
                    } else {
                        None
                    }
                })
                .expect("copy action must emit a clipboard command");
            assert!(copied.contains("https://example.test:8443/edited?q=1"));
            if !matches!(action, EntryAction::CopyUrl) {
                assert!(copied.contains("POST"));
                assert!(copied.contains("id=secret"));
                assert!(copied.contains("new body"));
            }
        }
        assert!(app.rows.is_empty());
    }

    #[test]
    fn switch_confirmation_cancel_and_save_temporary_project() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("saved.ferrite");
        let ctx = egui::Context::default();
        let mut app = test_workbench(dir.path());
        app.engine.project.lock().unwrap().workspace.name = "Original".into();
        app.switch_state = Some(SwitchState::Confirm(SwitchAction::NewTemporary));
        app.choose_switch(SwitchChoice::Cancel, &ctx);
        assert!(app.switch_state.is_none());
        assert_eq!(
            app.engine.project.lock().unwrap().workspace.name,
            "Original"
        );

        // Simulate the native picker returning the chosen path after Save.
        app.switch_state = Some(SwitchState::Saving(SwitchAction::NewTemporary));
        app.file_dialog_open = true;
        app.tx
            .send(Event::FileDialog(
                FileAction::SaveProject,
                Some(path.clone()),
            ))
            .unwrap();
        app.refresh();
        assert_eq!(
            app.switch_state,
            Some(SwitchState::Stopping(SwitchAction::NewTemporary))
        );
        app.advance_switch(&ctx);
        assert!(app.switch_state.is_none());
        assert!(app.project_path.is_none());
        assert_eq!(
            Project::open_existing(&path).unwrap().workspace.name,
            "Original"
        );

        // Cancelling the save picker must abandon the requested switch.
        app.switch_state = Some(SwitchState::Saving(SwitchAction::NewTemporary));
        app.file_dialog_open = true;
        app.tx
            .send(Event::FileDialog(FileAction::SaveProject, None))
            .unwrap();
        app.refresh();
        assert!(app.switch_state.is_none());
        assert!(app.project_path.is_none());
    }

    #[test]
    fn save_choice_on_disk_saves_and_switches_projects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("active.ferrite");
        let ctx = egui::Context::default();
        let mut app = test_workbench(dir.path());
        app.complete_file_action(FileAction::SaveProject, path.clone());
        app.engine.project.lock().unwrap().workspace.name = "Updated before switching".into();
        app.switch_state = Some(SwitchState::Confirm(SwitchAction::NewTemporary));
        app.choose_switch(SwitchChoice::Save, &ctx);
        assert_eq!(
            app.switch_state,
            Some(SwitchState::Stopping(SwitchAction::NewTemporary))
        );
        app.advance_switch(&ctx);
        assert!(app.project_path.is_none());
        assert_eq!(
            Project::open_existing(&path).unwrap().workspace.name,
            "Updated before switching"
        );
    }

    #[test]
    fn switch_waits_for_running_proxy_to_stop() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = egui::Context::default();
        let mut app = test_workbench(dir.path());
        let mut settings = app.engine.settings();
        settings.listen = "127.0.0.1:0".into();
        app.engine.configure(settings).unwrap();
        app.listener = Some(app.runtime.block_on(app.engine.start()).unwrap());
        app.switch_state = Some(SwitchState::Confirm(SwitchAction::NewTemporary));
        app.choose_switch(SwitchChoice::Discard, &ctx);
        app.advance_switch(&ctx);
        for _ in 0..300 {
            app.refresh();
            app.advance_switch(&ctx);
            if app.switch_state.is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(app.switch_state.is_none());
        assert!(!app.engine.is_running());
    }

    #[test]
    fn payload_file_replaces_and_persists_the_selected_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payloads.txt");
        std::fs::write(&path, "\u{feff}alpha\nbeta\n").unwrap();
        let mut app = test_workbench(dir.path());
        app.attack_payloads = vec!["old".into(), "untouched".into()];

        app.complete_file_action(FileAction::LoadPayloadSet(0), path);

        assert_eq!(app.attack_payloads, ["alpha\nbeta\n", "untouched"]);
        assert_eq!(
            app.engine
                .project
                .lock()
                .unwrap()
                .workspace
                .intruder
                .payload_sets,
            [
                vec!["alpha".to_owned(), "beta".to_owned()],
                vec!["untouched".to_owned()]
            ]
        );
    }

    #[test]
    fn oversized_metadata_cannot_push_response_pane_offscreen() {
        let ctx = egui::Context::default();
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 600.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    // Reproduce a URL label expanding the parent before the split.
                    ui.add(egui::Label::new("https://example.test/".repeat(400)).extend());
                    let [request, response] = split_panes(ui, "regression", false, 0.5);
                    assert!(request.max_rect().width() > 200.0);
                    assert!(response.max_rect().width() > 200.0);
                    assert!(response.max_rect().right() <= ui.clip_rect().right());
                    assert!(response.max_rect().bottom() <= ui.clip_rect().bottom());
                });
            },
        );
    }
}

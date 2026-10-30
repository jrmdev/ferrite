//! MCP server controls: status, clients, permissions, approvals, setup and audit.
use super::{Event, Workbench, subsection_heading, timestamp};
use crate::mcp::{
    McpSettings, Outcome, Permission,
    host::{Capability, Decision},
    ipc::{self, IpcServer},
};
use eframe::egui::{self, RichText};

#[derive(Default)]
pub(super) struct State {
    pub(super) server: Option<IpcServer>,
    pub(super) starting: bool,
    draft: Option<McpSettings>,
    audit_search: String,
    last_error: Option<String>,
}

impl Workbench {
    pub(super) fn start_mcp(&mut self) {
        if self.mcp_view.server.is_some() || self.mcp_view.starting {
            return;
        }
        let path = match ipc::default_endpoint_path() {
            Ok(path) => path,
            Err(error) => {
                self.mcp_view.last_error = Some(format!("{error:#}"));
                self.report::<()>(Err(error));
                return;
            }
        };
        self.mcp_view.starting = true;
        let host = self.mcp.clone();
        let tx = self.tx.clone();
        self.runtime.spawn(async move {
            let _ = tx.send(Event::Mcp(IpcServer::start(host, path).await));
        });
    }

    pub(super) fn stop_mcp(&mut self) {
        self.mcp.deny_all();
        if let Some(server) = self.mcp_view.server.take() {
            self.runtime.spawn(server.stop());
        }
    }

    pub(super) fn mcp_started(&mut self, result: anyhow::Result<IpcServer>) {
        self.mcp_view.starting = false;
        match result {
            Ok(server) if self.preferences.mcp().enabled => {
                self.mcp_view.last_error = None;
                self.notify(
                    "MCP",
                    format!("MCP server ready on {} for local clients", server.address()),
                );
                self.mcp_view.server = Some(server);
            }
            // Disabled while starting: discard.
            Ok(server) => drop(server),
            Err(error) => {
                self.mcp_view.last_error = Some(format!("{error:#}"));
                self.report::<()>(Err(error));
            }
        }
    }

    fn apply_mcp(&mut self, settings: McpSettings) {
        let was_enabled = self.preferences.mcp().enabled;
        let result = self.preferences.set_mcp(settings.clone());
        if self.report(result).is_none() {
            return;
        }
        self.mcp.set_settings(settings.clone());
        self.mcp_view.draft = None;
        match (was_enabled, settings.enabled) {
            (false, true) => self.start_mcp(),
            (true, false) => {
                self.stop_mcp();
                self.notify("MCP", "MCP server disabled; clients were disconnected");
            }
            _ => self.notify("MCP", "MCP settings saved"),
        }
    }

    /// Top bar indicator.
    pub(super) fn mcp_status(&self) -> Option<String> {
        self.mcp_view.server.as_ref()?;
        let clients = self.mcp.clients().len();
        let pending = self.mcp.pending_approvals().len();
        Some(match (clients, pending) {
            (_, p) if p > 0 => format!("⚠ MCP approval needed ({p})"),
            (0, _) => "⏺ MCP ready".into(),
            (1, _) => "⏺ MCP · 1 client".into(),
            (n, _) => format!("⏺ MCP · {n} clients"),
        })
    }

    pub(super) fn mcp_dialogs(&mut self, ctx: &egui::Context) {
        let Some(approval) = self.mcp.pending_approvals().into_iter().next() else {
            return;
        };
        let remaining = self.mcp.pending_approvals().len();
        egui::Modal::new(egui::Id::new(("mcp-approval", approval.id))).show(ctx, |ui| {
            ui.set_max_width(640.0);
            ui.heading(match approval.capability {
                Capability::SendRequests => "Allow an MCP client to send this request?",
                Capability::ActiveScans => "Allow an MCP client to run this scan action?",
            });
            ui.label(format!(
                "The MCP client \"{}\" wants to: {}",
                approval.client, approval.summary
            ));
            if !approval.detail.is_empty() {
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(&approval.detail).monospace().small())
                                .wrap(),
                        );
                    });
            }
            ui.weak(match approval.capability {
                Capability::SendRequests => "The request is in scope and goes through Ferrite's engine; it will appear in History as MCP.",
                Capability::ActiveScans => "Active scans send many probes to in-scope targets using the project's scanner settings.",
            });
            if remaining > 1 {
                ui.weak(format!("{} more waiting", remaining - 1));
            }
            ui.weak(format!(
                "Waiting {} s; requests not answered within two minutes are denied.",
                approval.requested.elapsed().as_secs()
            ));
            ui.horizontal(|ui| {
                if ui.button("Allow once").clicked() {
                    self.mcp.decide(approval.id, Decision::AllowOnce);
                }
                if ui
                    .button("Allow for this session")
                    .on_hover_text("Allow this capability without asking until MCP is disabled or Ferrite exits")
                    .clicked()
                {
                    self.mcp.decide(approval.id, Decision::AllowSession);
                }
                if ui.button("Deny").clicked() {
                    self.mcp.decide(approval.id, Decision::Deny);
                }
            });
        });
    }

    pub(super) fn mcp_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("MCP server");
        ui.add(
            egui::Label::new(RichText::new("Lets local MCP clients, agents and harnesses read this project and send in-scope requests through Ferrite. Captured traffic is returned to the client, which may forward it to a model provider.").weak())
                .wrap(),
        );
        ui.add_space(6.0);
        let saved = self.preferences.mcp().clone();
        let mut enabled = saved.enabled;
        ui.horizontal(|ui| {
            if ui.checkbox(&mut enabled, "Enable MCP server").changed() {
                let settings = McpSettings {
                    enabled,
                    ..saved.clone()
                };
                self.apply_mcp(settings);
            }
            match (&self.mcp_view.server, self.mcp_view.starting) {
                (Some(server), _) => {
                    ui.label(format!(
                        "⏺ Listening on {} (loopback only, token required)",
                        server.address()
                    ))
                    .on_hover_text(format!(
                        "Endpoint file: {}",
                        server.endpoint_path().display()
                    ));
                }
                (None, true) => {
                    ui.label("Starting…");
                }
                (None, false) if saved.enabled => {
                    ui.colored_label(ui.visuals().error_fg_color, "Not running");
                    if ui.button("Retry").clicked() {
                        self.start_mcp();
                    }
                }
                (None, false) => {
                    ui.label("○ Disabled");
                }
            }
        });
        if let Some(error) = &self.mcp_view.last_error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        ui.add_space(8.0);
        subsection_heading(ui, "Connected clients");
        let clients = self.mcp.clients();
        if clients.is_empty() {
            ui.weak(if self.mcp_view.server.is_some() {
                "No clients connected. Clients connect when your MCP client starts its Ferrite server."
            } else {
                "Enable the MCP server to accept clients."
            });
        } else {
            let timezone = self.preferences.timezone();
            egui::Grid::new("mcp-clients")
                .striped(true)
                .num_columns(5)
                .show(ui, |ui| {
                    for header in ["Client", "Transport", "Connected", "Calls", "Last call"] {
                        ui.strong(header);
                    }
                    ui.end_row();
                    for client in &clients {
                        ui.label(format!("{} {}", client.name, client.version));
                        ui.label(client.transport);
                        ui.label(timestamp(client.connected_ms, timezone));
                        ui.label(client.calls.to_string());
                        ui.label(
                            client
                                .last_call_ms
                                .map(|ms| timestamp(ms, timezone))
                                .unwrap_or_default(),
                        );
                        ui.end_row();
                    }
                });
        }
        ui.add_space(8.0);
        subsection_heading(ui, "Permissions");
        let draft = self.mcp_view.draft.get_or_insert_with(|| saved.clone());
        egui::Grid::new("mcp-permissions").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            for (label, value, hint) in [
                ("Send HTTP requests", &mut draft.send_requests, "send_http_request: in-scope requests through Ferrite's engine"),
                ("Active scans", &mut draft.active_scans, "start_active_scan and cancel_scan, using the project's scanner settings"),
            ] {
                ui.label(label).on_hover_text(hint);
                egui::ComboBox::from_id_salt(label)
                    .selected_text(value.label())
                    .show_ui(ui, |ui| {
                        for option in Permission::ALL {
                            ui.selectable_value(value, option, option.label());
                        }
                    });
                ui.end_row();
            }
            ui.label("Requests per minute");
            ui.add(egui::DragValue::new(&mut draft.requests_per_minute).range(1..=6000));
            ui.end_row();
            ui.label("Concurrent requests");
            ui.add(egui::DragValue::new(&mut draft.max_concurrent_requests).range(1..=32));
            ui.end_row();
            ui.label("Credentials");
            ui.checkbox(&mut draft.include_credentials, "Return Cookie, Authorization and similar header values")
                .on_hover_text("When off, values appear as [REDACTED]; clients can still resend requests and Ferrite restores the originals locally.");
            ui.end_row();
        });
        let draft = draft.clone();
        let changed = McpSettings {
            enabled: saved.enabled,
            ..draft.clone()
        } != saved;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(changed, egui::Button::new("Save permissions"))
                .clicked()
            {
                self.apply_mcp(McpSettings {
                    enabled: saved.enabled,
                    ..draft
                });
            }
            if ui
                .add_enabled(changed, egui::Button::new("Revert"))
                .clicked()
            {
                self.mcp_view.draft = None;
            }
            let session = self.mcp.session_allowed();
            if !session.is_empty() {
                ui.label(format!(
                    "Allowed for this session: {}",
                    session
                        .iter()
                        .map(|c| c.label())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                if ui.button("Revoke").clicked() {
                    self.mcp.revoke_session();
                }
            }
        });
        ui.weak("Requests and scans are always limited to the target scope (Target page). Read-only tools need no permission.");
        ui.add_space(8.0);
        self.mcp_setup(ui);
        ui.add_space(8.0);
        self.mcp_audit(ui);
    }

    fn mcp_setup(&mut self, ui: &mut egui::Ui) {
        subsection_heading(ui, "Connect an MCP client");
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "ferrite".into());
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {"ferrite": {"command": exe, "args": ["mcp"]}}
        }))
        .unwrap_or_default();
        ui.label("1. Keep this window open with the MCP server enabled.");
        ui.label("2. Add a stdio MCP server to your client using this example configuration:");
        ui.horizontal(|ui| {
            ui.add(egui::Label::new(RichText::new(&json).monospace()));
            if ui.small_button("Copy").clicked() {
                ui.ctx().copy_text(json.clone());
            }
        });
        ui.weak("Configuration formats and file locations vary by client. Use the executable as the command and mcp as its argument.");
        ui.label(
            "3. Start or reconnect your client and use its MCP tools to interact with Ferrite.",
        );
        ui.weak("Without this window, `ferrite mcp --headless --project FILE` serves a project directly (see ferrite mcp --help).");
    }

    fn mcp_audit(&mut self, ui: &mut egui::Ui) {
        subsection_heading(ui, "Audit trail");
        let entries = self.mcp.recent_audit();
        ui.horizontal(|ui| {
            ui.label("Search");
            ui.text_edit_singleline(&mut self.mcp_view.audit_search);
            ui.weak(format!(
                "{} recent calls (stored in the project)",
                entries.len()
            ));
        });
        let query = self.mcp_view.audit_search.to_lowercase();
        let timezone = self.preferences.timezone();
        // The page already scrolls; show the newest entries directly.
        egui::Grid::new("mcp-audit-grid")
            .striped(true)
            .num_columns(6)
            .show(ui, |ui| {
                for header in ["Time", "Client", "Tool", "Result", "Details", "ms"] {
                    ui.strong(header);
                }
                ui.end_row();
                let details_width = (ui.available_width() - 620.0).clamp(240.0, 900.0);
                for entry in entries
                    .iter()
                    .rev()
                    .filter(|e| {
                        query.is_empty()
                            || format!("{} {} {} {}", e.client, e.tool, e.summary, e.detail)
                                .to_lowercase()
                                .contains(&query)
                    })
                    .take(200)
                {
                    ui.label(timestamp(entry.timestamp_ms, timezone));
                    ui.label(&entry.client);
                    ui.label(&entry.tool);
                    let color = match entry.outcome {
                        Outcome::Ok => ui.visuals().text_color(),
                        Outcome::Denied => ui.visuals().warn_fg_color,
                        Outcome::Error => ui.visuals().error_fg_color,
                    };
                    ui.colored_label(color, entry.outcome.label());
                    let mut details = entry.summary.clone();
                    if !entry.exchange_ids.is_empty() {
                        details.push_str(&format!(
                            " → #{}",
                            entry
                                .exchange_ids
                                .iter()
                                .map(u64::to_string)
                                .collect::<Vec<_>>()
                                .join(", #")
                        ));
                    }
                    let hover = if entry.detail.is_empty() {
                        details.clone()
                    } else {
                        format!("{details}\n{}", entry.detail)
                    };
                    ui.allocate_ui_with_layout(
                        egui::vec2(details_width, 18.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            ui.set_min_width(details_width);
                            ui.add(egui::Label::new(details).truncate())
                                .on_hover_text(hover);
                        },
                    );
                    ui.label(entry.duration_ms.to_string());
                    ui.end_row();
                }
            });
    }
}

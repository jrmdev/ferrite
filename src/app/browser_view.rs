//! Managed browser controls: launch, lifecycle, tab navigation and settings.
use super::{Event, FileAction, Level, Workbench, subsection_heading};
use crate::browser::{self, Browser, BrowserSettings, ProfileMode, cdp};
use eframe::egui::{self, RichText};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

const TAB_REFRESH: Duration = Duration::from_millis(1500);

#[derive(Default)]
pub(super) struct State {
    pub(super) process: Option<Browser>,
    draft: Option<BrowserSettings>,
    extra_args: String,
    detected: Option<Vec<PathBuf>>,
    url: String,
    pub(super) tabs: Vec<cdp::Target>,
    selected_tab: Option<String>,
    tabs_requested: Option<Instant>,
    tabs_pending: bool,
    /// Launch once the listener started on the user's request reports back.
    pub(super) launch_after_start: bool,
    confirm_start: bool,
    confirm_reset: bool,
    relaunch: bool,
    last_exit: Option<String>,
}

pub(super) enum BrowserEvent {
    Tabs(anyhow::Result<Vec<cdp::Target>>),
    Done(&'static str, anyhow::Result<()>),
    Closing(anyhow::Result<()>),
}

fn normalise_url(input: &str) -> String {
    let input = input.trim();
    if input.is_empty() || input.contains("://") || input.starts_with("about:") {
        input.into()
    } else {
        format!("https://{input}")
    }
}

impl Workbench {
    fn browser_proxy(&self) -> anyhow::Result<String> {
        browser::resolve_proxy(
            self.preferences.browser(),
            self.listener.as_ref().map(|listener| listener.address),
        )
    }

    /// Open the managed browser, offering to start the listener first.
    pub(super) fn open_browser(&mut self) {
        if let Some(process) = &self.browser.process {
            if let (Some(url), Some(tab)) = (
                process.devtools_url(),
                self.browser.tabs.first().map(|t| t.target_id.clone()),
            ) {
                self.browser_task("Bring browser to front", async move {
                    cdp::activate(&url, &tab).await
                });
            }
            self.notify("Browser", "The browser is already open.");
            return;
        }
        if self.preferences.browser().custom_proxy.trim().is_empty() && self.listener.is_none() {
            if self.starting {
                self.browser.launch_after_start = true;
            } else {
                self.browser.confirm_start = true;
            }
            return;
        }
        self.launch_browser();
    }

    pub(super) fn launch_browser(&mut self) {
        self.browser.launch_after_start = false;
        let result = self.browser_proxy().and_then(|proxy| {
            let pin = self.engine.authority.spki_sha256_base64()?;
            Browser::launch(self.preferences.browser(), &proxy, &pin)
        });
        if let Some(process) = self.report(result) {
            self.notify(
                "Browser",
                format!(
                    "Browser opened (process {}) through {}",
                    process.pid(),
                    process.proxy()
                ),
            );
            self.browser.last_exit = None;
            self.browser.tabs.clear();
            self.browser.selected_tab = None;
            self.browser.tabs_requested = None;
            self.browser.process = Some(process);
        }
    }

    pub(super) fn close_browser(&mut self) {
        let Some(process) = &mut self.browser.process else {
            return;
        };
        if process.closing() {
            return;
        }
        process.begin_close();
        if let Some(url) = process.devtools_url() {
            let tx = self.tx.clone();
            self.runtime.spawn(async move {
                let result = cdp::close_browser(&url).await;
                let _ = tx.send(Event::Browser(BrowserEvent::Closing(result)));
            });
        } else {
            process.terminate();
        }
    }

    /// Graceful, bounded shutdown used when Ferrite exits.
    pub(super) fn shutdown_browser(&mut self) {
        // Dropping the process terminates anything still running and deletes
        // temporary profiles; a DevTools close first lets Chromium flush state.
        if let Some(mut process) = self.browser.process.take()
            && let Some(url) = process.devtools_url()
        {
            let _ = self.runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(2), cdp::close_browser(&url)).await
            });
            process.begin_close();
            process.wait_timeout(Duration::from_secs(3));
        }
    }

    fn browser_task(
        &self,
        label: &'static str,
        task: impl std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
    ) {
        let tx = self.tx.clone();
        self.runtime.spawn(async move {
            let result = task.await;
            let _ = tx.send(Event::Browser(BrowserEvent::Done(label, result)));
        });
    }

    pub(super) fn browser_event(&mut self, event: BrowserEvent) {
        match event {
            BrowserEvent::Tabs(result) => {
                self.browser.tabs_pending = false;
                // Tab listing fails briefly during start-up and shutdown.
                if let Ok(tabs) = result {
                    if self
                        .browser
                        .selected_tab
                        .as_ref()
                        .is_none_or(|id| !tabs.iter().any(|t| &t.target_id == id))
                    {
                        self.browser.selected_tab = tabs.first().map(|t| t.target_id.clone());
                    }
                    self.browser.tabs = tabs;
                }
            }
            BrowserEvent::Done(label, result) => {
                if let Err(error) = result {
                    self.report::<()>(Err(error.context(label)));
                }
                self.browser.tabs_requested = None;
            }
            BrowserEvent::Closing(result) => {
                if result.is_err()
                    && let Some(process) = &mut self.browser.process
                {
                    process.terminate();
                }
            }
        }
    }

    /// Per-frame lifecycle: exit detection, relaunch and tab refresh.
    pub(super) fn poll_browser(&mut self, ctx: &egui::Context) {
        let Some(process) = &mut self.browser.process else {
            return;
        };
        if let Some(status) = process.poll() {
            let closing = process.closing();
            let handed_off = process.handed_off();
            let output = process.recent_output();
            self.browser.process = None;
            self.browser.tabs.clear();
            self.browser.selected_tab = None;
            if closing {
                self.notify("Browser", "Browser closed");
            } else if handed_off {
                let message = "Chromium passed the launch to another running instance that uses the same profile, so it may not use Ferrite's proxy. Close that browser or use a temporary profile.";
                self.alerts.push(Level::Error, "Browser", message.into());
                self.browser.last_exit = Some(message.into());
                self.message = message.into();
            } else {
                let tail: Vec<_> = output.iter().rev().take(6).rev().cloned().collect();
                let message = format!("Browser exited unexpectedly ({status})");
                self.alerts.push(
                    Level::Error,
                    "Browser",
                    format!("{message}\n{}", tail.join("\n")),
                );
                self.message = message.clone();
                self.browser.last_exit = Some(format!("{message}\n{}", tail.join("\n")));
            }
            if std::mem::take(&mut self.browser.relaunch) {
                self.launch_browser();
            }
            return;
        }
        let Some(url) = process.devtools_url() else {
            return;
        };
        if self.page == super::Page::Browser
            && !self.browser.tabs_pending
            && self
                .browser
                .tabs_requested
                .is_none_or(|at| at.elapsed() > TAB_REFRESH)
        {
            self.browser.tabs_pending = true;
            self.browser.tabs_requested = Some(Instant::now());
            let tx = self.tx.clone();
            let ctx = ctx.clone();
            self.runtime.spawn(async move {
                let result = cdp::pages(&url).await;
                let _ = tx.send(Event::Browser(BrowserEvent::Tabs(result)));
                ctx.request_repaint();
            });
        }
    }

    /// Warnings for a browser whose proxy or CA no longer matches Ferrite.
    fn browser_warnings(&self) -> Vec<String> {
        let Some(process) = &self.browser.process else {
            return vec![];
        };
        let mut warnings = vec![];
        match self.browser_proxy() {
            Ok(proxy) if proxy != process.proxy() => warnings.push(format!(
                "The browser uses {} but the listener is now {proxy}. Restart the browser to apply it.",
                process.proxy()
            )),
            Err(_) => warnings.push(
                "The proxy listener is stopped, so browser requests will fail until it is started."
                    .into(),
            ),
            Ok(_) => {}
        }
        if self
            .engine
            .authority
            .spki_sha256_base64()
            .is_ok_and(|pin| pin != process.ca_pin())
        {
            warnings.push(
                "The CA was regenerated after the browser started. Restart the browser to trust the new CA.".into(),
            );
        }
        warnings
    }

    /// Compact status and controls for the Proxy page.
    pub(super) fn browser_controls(&mut self, ui: &mut egui::Ui) {
        let running = self.browser.process.is_some();
        if ui
            .button(if running {
                "Show browser"
            } else {
                "Open browser"
            })
            .on_hover_text(
                "Launch a dedicated Chromium window that routes through this listener and trusts Ferrite's CA",
            )
            .clicked()
        {
            self.open_browser();
        }
        if running && ui.button("Close browser").clicked() {
            self.close_browser();
        }
        if !self.browser_warnings().is_empty() {
            ui.colored_label(ui.visuals().warn_fg_color, "⚠ browser needs restart")
                .on_hover_text(self.browser_warnings().join("\n"));
        }
    }

    pub(super) fn browser_dialogs(&mut self, ctx: &egui::Context) {
        if self.browser.confirm_start {
            let address = self.engine.settings().listen;
            egui::Modal::new(egui::Id::new("browser-start-listener")).show(ctx, |ui| {
                ui.heading("Start the proxy listener?");
                ui.label(format!(
                    "The browser routes its traffic through Ferrite. Start the listener on {address} and open the browser?"
                ));
                ui.horizontal(|ui| {
                    if ui.button("Start listener and open browser").clicked() {
                        self.browser.confirm_start = false;
                        if self.apply_settings() {
                            self.browser.launch_after_start = true;
                            self.start();
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.browser.confirm_start = false;
                    }
                });
            });
        }
        if self.browser.confirm_reset {
            egui::Modal::new(egui::Id::new("browser-reset-profile")).show(ctx, |ui| {
                ui.heading("Reset the persistent browser profile?");
                ui.label("This deletes the profile's cookies, sessions, history, saved data and extensions.");
                ui.horizontal(|ui| {
                    if ui.button("Delete profile").clicked() {
                        self.browser.confirm_reset = false;
                        let result = browser::persistent_profile_dir(self.preferences.browser())
                            .and_then(|path| browser::reset_profile(&path).map(|_| path));
                        if let Some(path) = self.report(result) {
                            self.notify("Browser", format!("Deleted browser profile {}", path.display()));
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.browser.confirm_reset = false;
                    }
                });
            });
        }
    }

    pub(super) fn browser_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Browser");
        ui.add(
            egui::Label::new(
                RichText::new("A dedicated Chromium-family browser with an isolated profile. Its HTTP and HTTPS traffic, including loopback targets, passes through the Ferrite listener into History, Intercept and Target.")
                    .weak(),
            )
            .wrap(),
        );
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| match &self.browser.process {
            Some(process) if process.closing() => {
                ui.label("○ Closing…");
            }
            Some(process) => {
                ui.label(format!(
                    "⏺ Running · process {} · proxy {} · {} profile · {} s",
                    process.pid(),
                    process.proxy(),
                    if process.temporary_profile() {
                        "temporary"
                    } else {
                        "persistent"
                    },
                    process.uptime().as_secs()
                ))
                .on_hover_text(format!(
                    "{}\nProfile: {}",
                    process.executable().display(),
                    process.profile_path().display()
                ));
            }
            None => {
                ui.label("○ Not running");
            }
        });
        ui.horizontal(|ui| {
            let running = self.browser.process.is_some();
            if !running {
                if ui
                    .add_enabled(!self.starting, egui::Button::new("Open browser"))
                    .clicked()
                {
                    self.open_browser();
                }
            } else {
                if ui.button("Close browser").clicked() {
                    self.close_browser();
                }
                if ui
                    .button("Restart")
                    .on_hover_text("Close and relaunch with the current listener, CA and settings. Temporary profiles start empty.")
                    .clicked()
                {
                    self.browser.relaunch = true;
                    self.close_browser();
                }
            }
        });
        for warning in self.browser_warnings() {
            ui.colored_label(ui.visuals().warn_fg_color, format!("⚠ {warning}"));
        }
        if let Some(exit) = &self.browser.last_exit {
            egui::CollapsingHeader::new(
                RichText::new(exit.lines().next().unwrap_or("Browser exited"))
                    .color(ui.visuals().error_fg_color),
            )
            .id_salt("browser-exit")
            .show(ui, |ui| {
                ui.monospace(exit);
                ui.weak("If Chromium reports that it cannot run as root, add --no-sandbox to the launch arguments only inside a disposable container.");
            });
        }
        ui.separator();
        self.browser_navigation(ui);
        ui.separator();
        self.browser_settings(ui);
    }

    fn browser_navigation(&mut self, ui: &mut egui::Ui) {
        subsection_heading(ui, "Tabs");
        let devtools = self
            .browser
            .process
            .as_ref()
            .and_then(|process| process.devtools_url());
        let Some(devtools) = devtools else {
            ui.weak(if self.browser.process.is_some() {
                if self.preferences.browser().devtools {
                    "Waiting for the browser's DevTools endpoint…"
                } else {
                    "Enable DevTools controls in Browser settings to navigate from Ferrite. Use the browser window directly meanwhile."
                }
            } else {
                "Open the browser to list and navigate its tabs here."
            });
            return;
        };
        let selected = self.browser.selected_tab.clone();
        ui.horizontal(|ui| {
            let back = ui
                .add_enabled(selected.is_some(), egui::Button::new("◀"))
                .on_hover_text("Back");
            let forward = ui
                .add_enabled(selected.is_some(), egui::Button::new("▶"))
                .on_hover_text("Forward");
            let reload = ui
                .add_enabled(selected.is_some(), egui::Button::new("⟳"))
                .on_hover_text("Reload");
            let field = ui.add(
                egui::TextEdit::singleline(&mut self.browser.url)
                    .hint_text("URL to open")
                    .desired_width((ui.available_width() - 150.0).max(120.0)),
            );
            let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let go = ui.button("Go").clicked() || enter;
            let new_tab = ui.button("New tab").clicked();
            let url = normalise_url(&self.browser.url);
            if new_tab || (go && selected.is_none()) {
                let devtools = devtools.clone();
                let url = if url.is_empty() {
                    "about:blank".into()
                } else {
                    url.clone()
                };
                self.browser_task("Open tab", async move {
                    cdp::open(&devtools, &url).await.map(|_| ())
                });
            } else if go
                && !url.is_empty()
                && let Some(tab) = selected.clone()
            {
                let devtools = devtools.clone();
                self.browser_task("Navigate", async move {
                    cdp::navigate(&devtools, &tab, &url).await
                });
            }
            if let Some(tab) = selected.clone() {
                for (clicked, delta) in [(back.clicked(), -1), (forward.clicked(), 1)] {
                    if clicked {
                        let devtools = devtools.clone();
                        let tab = tab.clone();
                        self.browser_task("Navigate history", async move {
                            cdp::go(&devtools, &tab, delta).await
                        });
                    }
                }
                if reload.clicked() {
                    let devtools = devtools.clone();
                    self.browser_task("Reload", async move { cdp::reload(&devtools, &tab).await });
                }
            }
        });
        let tabs = self.browser.tabs.clone();
        if tabs.is_empty() {
            ui.weak("No open tabs.");
        }
        for tab in &tabs {
            ui.horizontal(|ui| {
                let title = if tab.title.is_empty() {
                    &tab.url
                } else {
                    &tab.title
                };
                let chosen = self.browser.selected_tab.as_deref() == Some(tab.target_id.as_str());
                let width = ui.available_width();
                if ui
                    .add_sized(
                        [(width * 0.35).clamp(120.0, 360.0), 20.0],
                        egui::Button::selectable(chosen, title.as_str()).truncate(),
                    )
                    .on_hover_text(&tab.url)
                    .clicked()
                {
                    self.browser.selected_tab = Some(tab.target_id.clone());
                    self.browser.url = tab.url.clone();
                }
                ui.add_sized(
                    [(ui.available_width() - 110.0).max(60.0), 20.0],
                    egui::Label::new(RichText::new(&tab.url).weak()).truncate(),
                );
                if ui.small_button("Focus").clicked() {
                    let devtools = devtools.clone();
                    let id = tab.target_id.clone();
                    self.browser_task(
                        "Focus tab",
                        async move { cdp::activate(&devtools, &id).await },
                    );
                }
                if ui.small_button("Close").clicked() {
                    let devtools = devtools.clone();
                    let id = tab.target_id.clone();
                    self.browser_task(
                        "Close tab",
                        async move { cdp::close_tab(&devtools, &id).await },
                    );
                }
            });
        }
    }

    fn browser_settings(&mut self, ui: &mut egui::Ui) {
        subsection_heading(ui, "Browser settings");
        let saved = self.preferences.browser().clone();
        let mut browse = false;
        let draft = self.browser.draft.get_or_insert_with(|| {
            self.browser.extra_args = saved.extra_args.join("\n");
            saved.clone()
        });
        egui::Grid::new("browser-settings")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Executable");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut draft.executable)
                            .hint_text("Detect automatically")
                            .desired_width(360.0),
                    );
                    if ui.button("Browse…").clicked() {
                        browse = true;
                    }
                    let detected = self
                        .browser
                        .detected
                        .get_or_insert_with(browser::candidates);
                    egui::ComboBox::from_id_salt("browser-detected")
                        .selected_text("Detected")
                        .show_ui(ui, |ui| {
                            if detected.is_empty() {
                                ui.label("No Chromium-family browser found");
                            }
                            for path in detected.iter() {
                                if ui
                                    .selectable_label(false, path.display().to_string())
                                    .clicked()
                                {
                                    draft.executable = path.display().to_string();
                                }
                            }
                        });
                });
                ui.end_row();
                ui.label("Profile");
                ui.horizontal(|ui| {
                    for mode in [ProfileMode::Temporary, ProfileMode::Persistent] {
                        ui.radio_value(&mut draft.profile, mode, mode.label());
                    }
                });
                ui.end_row();
                if draft.profile == ProfileMode::Persistent {
                    ui.label("Profile directory");
                    ui.horizontal(|ui| {
                        let default = browser::default_profile_dir()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default();
                        ui.add(
                            egui::TextEdit::singleline(&mut draft.profile_dir)
                                .hint_text(default)
                                .desired_width(360.0),
                        );
                        if ui
                            .add_enabled(
                                self.browser.process.is_none(),
                                egui::Button::new("Reset profile…"),
                            )
                            .on_disabled_hover_text("Close the browser first")
                            .clicked()
                        {
                            self.browser.confirm_reset = true;
                        }
                    });
                    ui.end_row();
                }
                ui.label("Proxy");
                ui.add(
                    egui::TextEdit::singleline(&mut draft.custom_proxy)
                        .hint_text("Active Ferrite listener")
                        .desired_width(220.0),
                )
                .on_hover_text("Leave empty to follow the running listener, or enter host:port");
                ui.end_row();
                ui.label("Start URL");
                ui.add(egui::TextEdit::singleline(&mut draft.start_url).desired_width(360.0));
                ui.end_row();
                ui.label("Extra arguments");
                ui.add(
                    egui::TextEdit::multiline(&mut self.browser.extra_args)
                        .hint_text("One --switch per line, e.g. --lang=en-AU")
                        .desired_rows(3)
                        .desired_width(360.0)
                        .font(egui::TextStyle::Monospace),
                );
                ui.end_row();
                ui.label("");
                ui.vertical(|ui| {
                    ui.checkbox(
                        &mut draft.devtools,
                        "DevTools controls from Ferrite (random loopback port)",
                    );
                    ui.checkbox(
                        &mut draft.quiet,
                        "Suppress Chromium background traffic (sync, updates, telemetry)",
                    );
                });
                ui.end_row();
            });
        draft.extra_args = self
            .browser
            .extra_args
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(String::from)
            .collect();
        let validation = draft.validate();
        if let Err(error) = &validation {
            ui.colored_label(ui.visuals().error_fg_color, format!("{error:#}"));
        }
        let changed = *draft != saved;
        let draft = draft.clone();
        if browse {
            self.choose_file(ui.ctx(), FileAction::BrowserExecutable);
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    changed && validation.is_ok(),
                    egui::Button::new("Save browser settings"),
                )
                .clicked()
            {
                let result = self.preferences.set_browser(draft);
                if self.report(result).is_some() {
                    self.browser.draft = None;
                    self.notify(
                        "Browser",
                        if self.browser.process.is_some() {
                            "Browser settings saved. Restart the browser to apply them."
                        } else {
                            "Browser settings saved."
                        },
                    );
                }
            }
            if ui
                .add_enabled(changed, egui::Button::new("Revert"))
                .clicked()
            {
                self.browser.draft = None;
            }
            if changed {
                ui.weak("Unsaved changes apply to the next launch");
            }
        });
        ui.add_space(6.0);
        let pin = self
            .engine
            .authority
            .spki_sha256_base64()
            .unwrap_or_default();
        ui.add(
            egui::Label::new(RichText::new(format!(
                "HTTPS trust: the browser accepts only certificates issued by Ferrite's current CA (public key pin {pin}), using Chromium's --ignore-certificate-errors-spki-list with the isolated profile. The operating system trust store is not changed and other browsers are unaffected."
            )).weak())
            .wrap(),
        );
    }

    pub(super) fn complete_browser_pick(&mut self, path: PathBuf) {
        let draft = self
            .browser
            .draft
            .get_or_insert_with(|| self.preferences.browser().clone());
        draft.executable = path.display().to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_addresses_default_to_https() {
        assert_eq!(normalise_url("example.com/a"), "https://example.com/a");
        assert_eq!(normalise_url(" http://x.test "), "http://x.test");
        assert_eq!(normalise_url("about:blank"), "about:blank");
        assert_eq!(normalise_url(""), "");
    }
}

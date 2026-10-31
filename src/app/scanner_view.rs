use super::{
    EntryAction, http_editor, item_menu, message_view, response_content::ResponseCache,
    split_panes, subsection_heading, timestamp,
};
use crate::{
    display_timezone::DisplayTimezone,
    engine::Engine,
    model::Exchange,
    scanner::{
        self, DelayMode, FailureAction, Finding, ReviewState, ScanJob, ScanMode, ScanSettings,
        ScanStatus, Severity,
    },
};
use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    path::Path,
    sync::{Arc, atomic::Ordering},
};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Tab {
    #[default]
    Scans,
    Findings,
    Issues,
    Settings,
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum DetailTab {
    #[default]
    Issue,
    Evidence,
    Triage,
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Sort {
    #[default]
    Severity,
    Title,
    Source,
    Url,
    Confidence,
    State,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LibrarySort {
    Enabled,
    Severity,
    Issue,
    Detection,
    Intrusive,
}

fn sort_header(ui: &mut egui::Ui, title: &str, active: bool, descending: bool) -> bool {
    let response = ui
        .add_sized(ui.available_size(), egui::Button::new(title).frame(false))
        .on_hover_text("Click to sort; click again to reverse. Drag column borders to resize.");
    if active {
        let center = egui::pos2(response.rect.right() - 7.0, response.rect.center().y);
        let direction = if descending { 1.0 } else { -1.0 };
        ui.painter().add(egui::Shape::convex_polygon(
            vec![
                center + egui::vec2(-3.0, -2.0 * direction),
                center + egui::vec2(3.0, -2.0 * direction),
                center + egui::vec2(0.0, 3.0 * direction),
            ],
            ui.visuals().text_color(),
            egui::Stroke::NONE,
        ));
    }
    response.clicked()
}
fn detection(definition: &scanner::IssueDefinition) -> &'static str {
    match (definition.passive, definition.active) {
        (true, true) => "Passive + Active",
        (true, false) => "Passive",
        _ => "Active",
    }
}

struct FindingRow {
    id: u64,
    severity: Severity,
    title: String,
    source: String,
    url: String,
    confidence: scanner::Confidence,
    state: ReviewState,
}

pub(super) struct State {
    tab: Tab,
    detail_tab: DetailTab,
    jobs: Vec<ScanJob>,
    findings: Vec<Finding>,
    finding_members: std::collections::BTreeMap<u64, Vec<u64>>,
    selected_scan: Option<u64>,
    selected_finding: Option<u64>,
    finding_detail: Option<Finding>,
    selected_issue: Option<String>,
    search: String,
    issue_search: String,
    severity: Option<Severity>,
    source: Option<ScanMode>,
    review: Option<ReviewState>,
    sort: Sort,
    descending: bool,
    library_sort: LibrarySort,
    library_descending: bool,
    evidence_index: usize,
    hex: bool,
    response_cache: ResponseCache,
    seen: (u64, u64),
    action: Option<(EntryAction, Exchange)>,
    export_open: bool,
    export_html: bool,
    export_path: String,
    export_findings: Vec<Finding>,
    error: String,
    throttle_codes_text: Option<String>,
    excluded_parameters_text: Option<String>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            tab: Tab::Scans,
            detail_tab: DetailTab::Issue,
            jobs: vec![],
            findings: vec![],
            finding_members: Default::default(),
            selected_scan: None,
            selected_finding: None,
            finding_detail: None,
            selected_issue: None,
            search: String::new(),
            issue_search: String::new(),
            severity: None,
            source: None,
            review: None,
            sort: Sort::Severity,
            descending: true,
            library_sort: LibrarySort::Severity,
            library_descending: true,
            evidence_index: 0,
            hex: false,
            response_cache: ResponseCache::default(),
            seen: (u64::MAX, u64::MAX),
            action: None,
            export_open: false,
            export_html: false,
            export_path: "scanner-findings.json".into(),
            export_findings: vec![],
            error: String::new(),
            throttle_codes_text: None,
            excluded_parameters_text: None,
        }
    }
}
fn severity_color(ui: &egui::Ui, severity: Severity) -> Color32 {
    match (ui.visuals().dark_mode, severity) {
        (true, Severity::High) => Color32::from_rgb(255, 110, 110),
        (false, Severity::High) => Color32::from_rgb(174, 20, 35),
        (true, Severity::Medium) => Color32::from_rgb(255, 177, 92),
        (false, Severity::Medium) => Color32::from_rgb(150, 75, 0),
        (true, Severity::Low) => Color32::from_rgb(230, 211, 106),
        (false, Severity::Low) => Color32::from_rgb(119, 96, 0),
        (true, Severity::Information) => Color32::from_rgb(116, 186, 245),
        (false, Severity::Information) => Color32::from_rgb(0, 89, 152),
    }
}
fn severity_label(ui: &mut egui::Ui, severity: Severity) {
    ui.add(
        egui::Label::new(
            RichText::new(severity.label())
                .color(severity_color(ui, severity))
                .strong(),
        )
        .selectable(false),
    );
}
fn source_label(finding: &Finding) -> String {
    if finding.origins.contains(&ScanMode::Passive) && finding.origins.contains(&ScanMode::Active) {
        "Passive + Active".into()
    } else {
        finding.mode.label().into()
    }
}

fn finding_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned())
}

fn group_findings(
    findings: Vec<Finding>,
) -> (Vec<Finding>, std::collections::BTreeMap<u64, Vec<u64>>) {
    let mut groups: std::collections::BTreeMap<(String, String), Vec<Finding>> = Default::default();
    for finding in findings {
        groups
            .entry((finding.issue_id.clone(), finding_host(&finding.url)))
            .or_default()
            .push(finding);
    }
    let mut members = std::collections::BTreeMap::new();
    let mut grouped = Vec::new();
    for (_, mut group) in groups {
        group.sort_by_key(|finding| finding.id);
        let mut iter = group.into_iter();
        let mut combined = iter.next().unwrap();
        let mut ids = vec![combined.id];
        for finding in iter {
            ids.push(finding.id);
            combined.severity = combined.severity.max(finding.severity);
            combined.confidence = combined.confidence.max(finding.confidence);
            combined.first_seen_ms = combined.first_seen_ms.min(finding.first_seen_ms);
            combined.last_seen_ms = combined.last_seen_ms.max(finding.last_seen_ms);
            combined.occurrences = combined.occurrences.saturating_add(finding.occurrences);
            for origin in finding.origins {
                if !combined.origins.contains(&origin) {
                    combined.origins.push(origin);
                }
            }
            for id in finding.scan_ids {
                if !combined.scan_ids.contains(&id) {
                    combined.scan_ids.push(id);
                }
            }
            combined.evidence.extend(finding.evidence);
        }
        members.insert(combined.id, ids);
        grouped.push(combined);
    }
    (grouped, members)
}

impl State {
    pub fn select_scan(&mut self, id: u64) {
        self.selected_scan = Some(id);
        self.tab = Tab::Scans;
        self.seen = (u64::MAX, u64::MAX);
    }
    pub fn take_action(&mut self) -> Option<(EntryAction, Exchange)> {
        self.action.take()
    }
    fn refresh(&mut self, engine: &Engine) {
        let activity = (
            engine.scanner.activity.load(Ordering::SeqCst),
            engine.scanner.runner.activity.load(Ordering::SeqCst),
        );
        if activity != self.seen {
            let project = engine.project.lock().unwrap();
            self.jobs = project.scan_jobs();
            self.jobs.sort_by_key(|j| std::cmp::Reverse(j.id));
            (self.findings, self.finding_members) = group_findings(project.findings());
            self.finding_detail = None;
            self.seen = activity;
            if self.selected_scan.is_none() {
                self.selected_scan = self.jobs.first().map(|j| j.id);
            }
        }
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        engine: &Arc<Engine>,
        timezone: DisplayTimezone,
    ) -> anyhow::Result<Option<String>> {
        self.refresh(engine);
        ui.heading("Scanner");
        ui.horizontal_wrapped(|ui| {
            for (tab, label) in [
                (Tab::Scans, "Scans"),
                (Tab::Findings, "Findings"),
                (Tab::Issues, "Library"),
                (Tab::Settings, "Settings"),
            ] {
                ui.selectable_value(&mut self.tab, tab, label);
            }
            ui.separator();
            ui.weak(format!(
                "{} findings · {} scans",
                self.findings.len(),
                self.jobs.len()
            ));
        });
        ui.separator();
        if !self.error.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(ui.visuals().error_fg_color, &self.error);
                if ui.small_button("Dismiss").clicked() {
                    self.error.clear();
                }
            });
        }
        let result = match self.tab {
            Tab::Scans => self.scans(ui, engine, timezone),
            Tab::Findings => self.findings(ui, engine, timezone),
            Tab::Issues => self.issues(ui, engine),
            Tab::Settings => self.settings(ui, engine),
        };
        let message = match result {
            Ok(message) => message,
            Err(error) => {
                self.error = format!("{error:#}");
                None
            }
        };
        let export_message = self.export(ui.ctx())?;
        Ok(export_message.or(message))
    }
    fn scans(
        &mut self,
        ui: &mut egui::Ui,
        engine: &Arc<Engine>,
        timezone: DisplayTimezone,
    ) -> anyhow::Result<Option<String>> {
        ui.weak(scanner::runner::resource_status(engine));
        let selected = self
            .jobs
            .iter()
            .find(|job| Some(job.id) == self.selected_scan)
            .cloned();
        let mut action = None;
        ui.horizontal_wrapped(|ui| {
            if let Some(job)=&selected {
                ui.strong(format!("Scan #{}",job.id));
                let running=matches!(job.status,ScanStatus::Queued|ScanStatus::Running);
                if ui.add_enabled(running,egui::Button::new("Pause")).clicked(){action=Some("pause");}
                if ui.add_enabled(matches!(job.status,ScanStatus::Paused|ScanStatus::Interrupted),egui::Button::new("Resume")).clicked(){action=Some("resume");}
                if ui.add_enabled(job.status.unfinished()||job.status==ScanStatus::Interrupted,egui::Button::new("Cancel")).clicked(){action=Some("cancel");}
                if ui.add_enabled(!running,egui::Button::new("Retry failed")).clicked(){action=Some("retry");}
            } else {ui.weak("Select requests in History, Target, Intercept, or Repeater and choose Send to > Scanner.");}
        });
        if let (Some(action), Some(job)) = (action, &selected) {
            match action {
                "pause" => scanner::runner::pause(engine.clone(), job.id)?,
                "resume" => scanner::runner::resume(engine.clone(), job.id)?,
                "cancel" => scanner::runner::cancel(engine.clone(), job.id)?,
                _ => scanner::runner::retry(engine.clone(), job.id)?,
            }
            self.seen = (u64::MAX, u64::MAX);
        }
        let [mut table_ui, mut detail_ui] = split_panes(ui, "scanner-scans-split", true, 0.48);
        let table_height = table_ui.available_height().max(40.0);
        let page_rows =
            ((table_height - 24.0).max(0.0) / (24.0 + table_ui.spacing().item_spacing.y)) as usize;
        let focus_id = table_ui.id().with("scan-rows-focus");
        let target = super::table_arrow_navigation(
            &mut table_ui,
            focus_id,
            self.jobs
                .iter()
                .position(|job| Some(job.id) == self.selected_scan),
            self.jobs.len(),
            page_rows,
        );
        if let Some(index) = target {
            self.selected_scan = Some(self.jobs[index].id);
        }

        let mut table = TableBuilder::new(&mut table_ui)
            .sense(egui::Sense::click())
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(65.0))
            .column(Column::initial(210.0))
            .column(Column::initial(95.0))
            .column(Column::initial(90.0))
            .column(Column::initial(80.0))
            .column(Column::initial(70.0))
            .column(Column::remainder().at_least(100.0))
            .max_scroll_height(table_height);
        if let Some(index) = target {
            table = table.scroll_to_row(index, None);
        }
        table
            .header(24.0, |mut header| {
                for label in [
                    "Scan", "Name", "State", "Items", "Requests", "Errors", "Findings",
                ] {
                    header.col(|ui| {
                        ui.strong(label);
                    });
                }
            })
            .body(|mut body| {
                for job in &self.jobs {
                    body.row(24.0, |mut row| {
                        row.set_selected(Some(job.id) == self.selected_scan);
                        row.col(|ui| {
                            if ui
                                .selectable_label(
                                    Some(job.id) == self.selected_scan,
                                    format!("#{}", job.id),
                                )
                                .clicked()
                            {
                                super::focus_table(ui, focus_id);
                                self.selected_scan = Some(job.id);
                            }
                        });
                        row.col(|ui| {
                            ui.add(egui::Label::new(&job.name).truncate());
                        });
                        row.col(|ui| {
                            ui.label(job.status.label());
                        });
                        let complete = job
                            .items
                            .iter()
                            .filter(|item| item.status == ScanStatus::Completed)
                            .count();
                        row.col(|ui| {
                            ui.label(format!("{complete}/{}", job.items.len()));
                        });
                        row.col(|ui| {
                            ui.label(job.requests.to_string());
                        });
                        row.col(|ui| {
                            ui.label(job.failures.to_string());
                        });
                        row.col(|ui| {
                            ui.label(job.findings.to_string());
                        });
                        if row.response().clicked() {
                            row.response()
                                .ctx
                                .memory_mut(|memory| memory.request_focus(focus_id));
                            self.selected_scan = Some(job.id);
                        }
                    });
                }
            });
        let selected = self
            .jobs
            .iter()
            .find(|job| Some(job.id) == self.selected_scan)
            .cloned();
        if let Some(job) = selected {
            detail_ui.horizontal_wrapped(|ui| {
                ui.strong(format!("Scan #{} · {}", job.id, job.status.label()));
                ui.weak(timestamp(job.created_ms, timezone));
            });
            detail_ui.label(&job.message);
            detail_ui.weak(format!(
                "{} requests · {} failures · {} skipped checks · {} findings",
                job.requests, job.failures, job.skipped, job.findings
            ));
            egui::ScrollArea::vertical()
                .id_salt("scanner-scan-items")
                .show(&mut detail_ui, |ui| {
                    for (index, item) in job.items.iter().enumerate() {
                        egui::CollapsingHeader::new(format!(
                            "{} {} {} · {}",
                            index + 1,
                            item.source.method,
                            item.source.url,
                            item.status.label()
                        ))
                        .id_salt((job.id, index))
                        .show(ui, |ui| {
                            ui.label(format!(
                                "{} completed probes · {} failures",
                                item.completed, item.failures
                            ));
                            ui.label(&item.message);
                            if ui.button("Send source to Repeater").clicked() {
                                self.action = Some((EntryAction::Repeater, item.source.clone()));
                            }
                        });
                    }
                });
        }
        Ok(None)
    }
    fn filtered_findings(&self) -> Vec<FindingRow> {
        let search = self.search.to_lowercase();
        let mut findings: Vec<_> = self
            .findings
            .iter()
            .filter(|finding| {
                self.severity
                    .is_none_or(|severity| finding.severity == severity)
                    && self.source.is_none_or(|source| {
                        finding.mode == source || finding.origins.contains(&source)
                    })
                    && self.review.is_none_or(|review| finding.state == review)
                    && (search.is_empty()
                        || finding
                            .evidence
                            .iter()
                            .any(|e| e.exchange.url.to_lowercase().contains(&search))
                        || format!(
                            "{} {} {} {}",
                            finding.title, finding.url, finding.insertion_point, finding.detail
                        )
                        .to_lowercase()
                        .contains(&search))
            })
            .map(|finding| FindingRow {
                id: finding.id,
                severity: finding.severity,
                title: finding.title.clone(),
                source: source_label(finding),
                url: finding_host(&finding.url),
                confidence: finding.confidence,
                state: finding.state,
            })
            .collect();
        findings.sort_by(|left, right| {
            let order = match self.sort {
                Sort::Severity => left.severity.cmp(&right.severity),
                Sort::Title => left.title.cmp(&right.title),
                Sort::Source => left.source.cmp(&right.source),
                Sort::Url => left.url.cmp(&right.url),
                Sort::Confidence => left.confidence.cmp(&right.confidence),
                Sort::State => left.state.label().cmp(right.state.label()),
            }
            .then(left.id.cmp(&right.id));
            if self.descending {
                order.reverse()
            } else {
                order
            }
        });
        findings
    }
    fn findings(
        &mut self,
        ui: &mut egui::Ui,
        engine: &Arc<Engine>,
        timezone: DisplayTimezone,
    ) -> anyhow::Result<Option<String>> {
        ui.horizontal_wrapped(|ui| {
            ui.label("Search");
            ui.add(egui::TextEdit::singleline(&mut self.search).desired_width(220.0));
            egui::ComboBox::from_id_salt("scanner-severity-filter")
                .selected_text(self.severity.map_or("All severities", Severity::label))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.severity, None, "All severities");
                    for severity in Severity::ALL {
                        ui.selectable_value(&mut self.severity, Some(severity), severity.label());
                    }
                });
            egui::ComboBox::from_id_salt("scanner-source-filter")
                .selected_text(self.source.map_or("All sources", ScanMode::label))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.source, None, "All sources");
                    for mode in [ScanMode::Passive, ScanMode::Active] {
                        ui.selectable_value(&mut self.source, Some(mode), mode.label());
                    }
                });
            egui::ComboBox::from_id_salt("scanner-review-filter")
                .selected_text(self.review.map_or("All review states", ReviewState::label))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.review, None, "All review states");
                    for review in ReviewState::ALL {
                        ui.selectable_value(&mut self.review, Some(review), review.label());
                    }
                });
            if ui.button("Export filtered findings").clicked() {
                let ids: std::collections::BTreeSet<_> =
                    self.filtered_findings().iter().map(|row| row.id).collect();
                self.export_findings = self
                    .findings
                    .iter()
                    .filter(|finding| ids.contains(&finding.id))
                    .cloned()
                    .collect();
                self.export_open = true;
            }
        });
        let findings = self.filtered_findings();
        if !findings
            .iter()
            .any(|finding| Some(finding.id) == self.selected_finding)
        {
            self.selected_finding = findings.first().map(|finding| finding.id);
            self.evidence_index = 0;
            self.response_cache = ResponseCache::default();
        }
        let [mut table_ui, mut detail_ui] = split_panes(ui, "scanner-findings-split", true, 0.45);
        let height = table_ui.available_height().max(40.0);
        super::compact_rows(&mut table_ui);
        let focus_id = table_ui.id().with("finding-rows-focus");
        let target = super::table_arrow_navigation(
            &mut table_ui,
            focus_id,
            findings
                .iter()
                .position(|finding| Some(finding.id) == self.selected_finding),
            findings.len(),
            ((height - 24.0).max(0.0) / 22.0) as usize,
        );
        if let Some(index) = target {
            self.selected_finding = Some(findings[index].id);
            self.evidence_index = 0;
            self.response_cache = ResponseCache::default();
        }

        let mut table = TableBuilder::new(&mut table_ui)
            .sense(egui::Sense::click())
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(90.0))
            .column(Column::initial(250.0))
            .column(Column::initial(120.0))
            .column(Column::remainder().at_least(150.0))
            .column(Column::initial(90.0))
            .column(Column::initial(95.0))
            .max_scroll_height(height);
        if let Some(index) = target {
            table = table.scroll_to_row(index, None);
        }
        table
            .header(24.0, |mut header| {
                for (sort, label) in [
                    (Sort::Severity, "Severity"),
                    (Sort::Title, "Title"),
                    (Sort::Source, "Source"),
                    (Sort::Url, "URL"),
                    (Sort::Confidence, "Confidence"),
                    (Sort::State, "Review"),
                ] {
                    header.col(|ui| {
                        if sort_header(ui, label, self.sort == sort, self.descending) {
                            if self.sort == sort {
                                self.descending = !self.descending;
                            } else {
                                self.sort = sort;
                                self.descending = sort == Sort::Severity;
                            }
                        }
                    });
                }
            })
            .body(|mut body| {
                for finding in &findings {
                    body.row(20.0, |mut row| {
                        row.set_selected(self.selected_finding == Some(finding.id));
                        row.col(|ui| severity_label(ui, finding.severity));
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(&finding.title)
                                    .truncate()
                                    .selectable(false),
                            );
                        });
                        row.col(|ui| {
                            ui.add(egui::Label::new(&finding.source).selectable(false));
                        });
                        row.col(|ui| {
                            ui.add(egui::Label::new(&finding.url).truncate().selectable(false));
                        });
                        row.col(|ui| {
                            ui.add(egui::Label::new(finding.confidence.label()).selectable(false));
                        });
                        row.col(|ui| {
                            ui.add(egui::Label::new(finding.state.label()).selectable(false));
                        });
                        if row.response().clicked() {
                            row.response()
                                .ctx
                                .memory_mut(|memory| memory.request_focus(focus_id));
                            if self.selected_finding != Some(finding.id) {
                                self.selected_finding = Some(finding.id);
                                self.evidence_index = 0;
                                self.response_cache = ResponseCache::default();
                            }
                        }
                    });
                }
            });
        let selected = self
            .finding_detail
            .take()
            .filter(|finding| Some(finding.id) == self.selected_finding)
            .or_else(|| {
                self.findings
                    .iter()
                    .find(|finding| Some(finding.id) == self.selected_finding)
                    .cloned()
            });
        if let Some(mut finding) = selected {
            detail_ui.horizontal_wrapped(|ui| {
                severity_label(ui, finding.severity);
                ui.strong(&finding.title);
                ui.weak(format!(
                    "{} · {} · {} occurrences",
                    finding.confidence.label(),
                    source_label(&finding),
                    finding.occurrences
                ));
            });
            detail_ui.add(egui::Label::new(&finding.url).truncate().selectable(false));
            detail_ui.horizontal(|ui| {
                for (tab, label) in [
                    (DetailTab::Issue, "Issue details"),
                    (DetailTab::Evidence, "Requests / responses"),
                    (DetailTab::Triage, "Review / notes"),
                ] {
                    ui.selectable_value(&mut self.detail_tab, tab, label);
                }
            });
            detail_ui.separator();
            match self.detail_tab {
                DetailTab::Issue => {
                    egui::ScrollArea::vertical()
                        .id_salt("scanner-issue-detail")
                        .show(&mut detail_ui, |ui| {
                            if !finding.insertion_point.is_empty() {
                                ui.strong(format!("Insertion point: {}", finding.insertion_point));
                            }
                            ui.label(&finding.detail);
                            ui.add_space(8.0);
                            subsection_heading(ui, "Description");
                            ui.label(&finding.description);
                            ui.add_space(8.0);
                            subsection_heading(ui, "Remediation");
                            ui.label(&finding.remediation);
                            ui.add_space(8.0);
                            ui.weak(format!(
                                "First seen {} · Last seen {}",
                                timestamp(finding.first_seen_ms, timezone),
                                timestamp(finding.last_seen_ms, timezone)
                            ));
                            if let Some(definition) = scanner::checks::definitions()
                                .iter()
                                .find(|definition| definition.id == finding.issue_id)
                            {
                                for reference in &definition.references {
                                    ui.hyperlink(reference);
                                }
                            }
                        });
                }
                DetailTab::Evidence => self.evidence(&mut detail_ui, engine, &finding),
                DetailTab::Triage => {
                    let before = (finding.state, finding.severity, finding.notes.clone());
                    egui::ScrollArea::vertical().id_salt("scanner-triage").show(
                        &mut detail_ui,
                        |ui| {
                            ui.horizontal_wrapped(|ui| {
                                egui::ComboBox::from_label("Review state")
                                    .selected_text(finding.state.label())
                                    .show_ui(ui, |ui| {
                                        for state in ReviewState::ALL {
                                            ui.selectable_value(
                                                &mut finding.state,
                                                state,
                                                state.label(),
                                            );
                                        }
                                    });
                                egui::ComboBox::from_label("Severity override")
                                    .selected_text(finding.severity.label())
                                    .show_ui(ui, |ui| {
                                        for severity in Severity::ALL {
                                            ui.selectable_value(
                                                &mut finding.severity,
                                                severity,
                                                severity.label(),
                                            );
                                        }
                                    });
                                if ui.button("Reset severity").clicked() {
                                    finding.severity = finding.original_severity;
                                }
                            });
                            ui.label("Notes");
                            ui.add(
                                egui::TextEdit::multiline(&mut finding.notes)
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(5),
                            );
                            if let Some(ids) = self.finding_members.get(&finding.id) {
                                let project = engine.project.lock().unwrap();
                                for id in ids.iter().filter(|id| **id != finding.id) {
                                    if let Some(other) = project.finding(*id) && !other.notes.is_empty() {
                                        ui.label(format!("Notes from finding #{}: {}", other.id, other.notes));
                                    }
                                }
                            }
                            ui.weak("Review state and severity apply to the group. Notes are saved on the first finding; earlier notes on other findings are shown above.");
                        },
                    );
                    if before != (finding.state, finding.severity, finding.notes.clone()) {
                        {
                            let mut project = engine.project.lock().unwrap();
                            let ids = self
                                .finding_members
                                .get(&finding.id)
                                .cloned()
                                .unwrap_or_else(|| vec![finding.id]);
                            for id in ids {
                                if let Some(mut latest) = project.finding(id) {
                                    if before.0 != finding.state {
                                        latest.state = finding.state;
                                    }
                                    if before.1 != finding.severity {
                                        latest.severity = finding.severity;
                                    }
                                    if before.2 != finding.notes && id == finding.id {
                                        latest.notes = finding.notes.clone();
                                    }
                                    project.put_finding(latest)?;
                                }
                            }
                        }
                        engine.scanner.activity.fetch_add(1, Ordering::SeqCst);
                        self.seen = (u64::MAX, u64::MAX);
                    }
                }
            }
            self.finding_detail = Some(finding);
        } else {
            detail_ui.weak("Select a finding to inspect its description and captured evidence.");
        }
        Ok(None)
    }
    fn evidence(&mut self, ui: &mut egui::Ui, engine: &Engine, finding: &Finding) {
        if finding.evidence.is_empty() {
            ui.weak("No request/response evidence is available.");
            return;
        }
        self.evidence_index = self.evidence_index.min(finding.evidence.len() - 1);
        ui.horizontal_wrapped(|ui| {
            let selected = &finding.evidence[self.evidence_index];
            egui::ComboBox::from_id_salt("scanner-evidence-select")
                .selected_text(format!("{}: {}", self.evidence_index + 1, selected.label))
                .show_ui(ui, |ui| {
                    for (index, evidence) in finding.evidence.iter().enumerate() {
                        if ui
                            .selectable_value(
                                &mut self.evidence_index,
                                index,
                                format!(
                                    "{}: {} · {} {}",
                                    index + 1,
                                    evidence.label,
                                    evidence.exchange.method,
                                    evidence.exchange.url
                                ),
                            )
                            .changed()
                        {
                            self.response_cache = ResponseCache::default();
                        }
                    }
                });
            ui.checkbox(&mut self.hex, "Hex");
            if ui.button("Send to Repeater").clicked() {
                self.action = Some((
                    EntryAction::Repeater,
                    finding.evidence[self.evidence_index].exchange.clone(),
                ));
            }
        });
        let exchange = &finding.evidence[self.evidence_index].exchange;
        ui.weak(format!(
            "{} {} · HTTP {} · {} ms",
            exchange.method, exchange.url, exchange.status, exchange.duration_ms
        ));
        if let Some(error) = &exchange.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        let [mut request_ui, mut response_ui] =
            split_panes(ui, "scanner-evidence-editors", false, 0.5);
        subsection_heading(&mut request_ui, "Request");
        subsection_heading(&mut response_ui, "Response");
        let request = message_view(&exchange.request, self.hex);
        let response = self.response_cache.get(
            exchange.id,
            &exchange.response,
            self.hex,
            engine.settings().max_message_bytes,
        );
        let request_out = http_editor(
            &mut request_ui,
            &mut request.as_str(),
            ("scanner-request", finding.id, self.evidence_index, self.hex),
        );
        let response_out = http_editor(
            &mut response_ui,
            &mut response.as_ref(),
            (
                "scanner-response",
                finding.id,
                self.evidence_index,
                self.hex,
            ),
        );
        if let Some(action) = item_menu(&request_out.inner.response, false, None)
            .or_else(|| item_menu(&response_out.inner.response, false, None))
        {
            self.action = Some((action, exchange.clone()));
        }
    }
    fn issues(&mut self, ui: &mut egui::Ui, engine: &Engine) -> anyhow::Result<Option<String>> {
        ui.horizontal(|ui| {
            ui.label("Search checks");
            ui.add(egui::TextEdit::singleline(&mut self.issue_search).desired_width(300.0));
        });
        let mut settings = engine.project.lock().unwrap().workspace.scanner.clone();
        let before = settings.clone();
        let definitions = scanner::checks::definitions();
        let mut sorted: Vec<_> = definitions.iter().collect();
        let query = self.issue_search.to_lowercase();
        sorted.sort_by(|a, b| {
            let order = match self.library_sort {
                LibrarySort::Enabled => settings
                    .check_enabled(&a.id)
                    .cmp(&settings.check_enabled(&b.id)),
                LibrarySort::Severity => a.severity.cmp(&b.severity),
                LibrarySort::Issue => a.name.cmp(&b.name),
                LibrarySort::Detection => detection(a).cmp(detection(b)),
                LibrarySort::Intrusive => a.intrusive.cmp(&b.intrusive),
            }
            .then_with(|| a.id.cmp(&b.id));
            if self.library_descending {
                order.reverse()
            } else {
                order
            }
        });
        sorted.retain(|definition| {
            query.is_empty()
                || format!("{} {}", definition.name, definition.id)
                    .to_lowercase()
                    .contains(&query)
        });
        let [mut table_ui, mut detail_ui] = split_panes(ui, "scanner-issues-split", true, 0.6);
        let height = table_ui.available_height().max(40.0);
        super::compact_rows(&mut table_ui);
        let focus_id = table_ui.id().with("library-rows-focus");
        let target = super::table_arrow_navigation(
            &mut table_ui,
            focus_id,
            sorted.iter().position(|definition| {
                self.selected_issue.as_deref() == Some(definition.id.as_str())
            }),
            sorted.len(),
            ((height - 24.0).max(0.0) / 22.0) as usize,
        );
        if let Some(index) = target {
            self.selected_issue = Some(sorted[index].id.clone());
        }

        let mut table = TableBuilder::new(&mut table_ui)
            .sense(egui::Sense::click())
            .striped(true)
            .resizable(true)
            .column(Column::exact(65.0))
            .column(Column::initial(95.0))
            .column(Column::remainder().at_least(200.0))
            .column(Column::initial(130.0))
            .column(Column::initial(90.0))
            .max_scroll_height(height)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
        if let Some(index) = target {
            table = table.scroll_to_row(index, None);
        }
        table
            .header(24.0, |mut header| {
                for (column, label) in [
                    (LibrarySort::Enabled, "Enabled"),
                    (LibrarySort::Severity, "Severity"),
                    (LibrarySort::Issue, "Issue"),
                    (LibrarySort::Detection, "Detection"),
                    (LibrarySort::Intrusive, "Intrusive"),
                ] {
                    header.col(|ui| {
                        if sort_header(
                            ui,
                            label,
                            self.library_sort == column,
                            self.library_descending,
                        ) {
                            if self.library_sort == column {
                                self.library_descending = !self.library_descending;
                            } else {
                                self.library_sort = column;
                                self.library_descending = column == LibrarySort::Severity;
                            }
                        }
                    });
                }
            })
            .body(|mut body| {
                for definition in &sorted {
                    body.row(20.0, |mut row| {
                        row.set_selected(
                            self.selected_issue.as_deref() == Some(definition.id.as_str()),
                        );
                        row.col(|ui| {
                            let mut enabled = settings.check_enabled(&definition.id);
                            if ui.checkbox(&mut enabled, "").changed() {
                                settings.disabled_checks.retain(|id| id != &definition.id);
                                if !enabled {
                                    settings.disabled_checks.push(definition.id.clone());
                                } else if !settings.enabled_checks.is_empty()
                                    && !settings.enabled_checks.contains(&definition.id)
                                {
                                    settings.enabled_checks.push(definition.id.clone());
                                }
                            }
                        });
                        row.col(|ui| severity_label(ui, definition.severity));
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(&definition.name)
                                    .truncate()
                                    .selectable(false),
                            );
                        });
                        row.col(|ui| {
                            ui.add(egui::Label::new(detection(definition)).selectable(false));
                        });
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(if definition.intrusive {
                                    "Opt-in"
                                } else {
                                    "No"
                                })
                                .selectable(false),
                            );
                        });
                        if row.response().clicked() {
                            row.response()
                                .ctx
                                .memory_mut(|memory| memory.request_focus(focus_id));
                            self.selected_issue = Some(definition.id.clone());
                        }
                    });
                }
            });
        if settings != before {
            save_settings(engine, settings)?;
        }
        if let Some(definition) = definitions
            .iter()
            .find(|definition| Some(&definition.id) == self.selected_issue.as_ref())
        {
            egui::ScrollArea::vertical()
                .id_salt("scanner-definition-detail")
                .show(&mut detail_ui, |ui| {
                    ui.strong(&definition.name);
                    ui.label(&definition.description);
                    ui.add_space(8.0);
                    subsection_heading(ui, "Remediation");
                    ui.label(&definition.remediation);
                    if definition.intrusive {
                        ui.weak("Enable intrusive checks in Scanner Settings to run this check.");
                    }
                    for reference in &definition.references {
                        ui.hyperlink(reference);
                    }
                });
        } else {
            detail_ui.weak(
                "Select an issue to read its description, remediation, and detection options.",
            );
        }
        Ok(None)
    }
    fn settings(&mut self, ui: &mut egui::Ui, engine: &Engine) -> anyhow::Result<Option<String>> {
        let mut settings = engine.project.lock().unwrap().workspace.scanner.clone();
        let previous = settings.clone();
        egui::ScrollArea::vertical().id_salt("scanner-settings").show(ui, |ui| {
            ui.weak("Settings apply to this project. New scans capture the selected checks and audit options. Resource limits apply to all running scans.");
            resource_settings(ui, &mut settings);
            ui.add_space(8.0);
            subsection_heading(ui, "Automatic throttling");
            ui.checkbox(&mut settings.auto_throttle, "Enable automatic throttling (HTTP 429)");
            ui.checkbox(&mut settings.throttle_503, "Throttle on HTTP 503 (Service Unavailable)");
            ui.horizontal_wrapped(|ui| {
                ui.label("Additional status codes");
                let codes = self.throttle_codes_text.get_or_insert_with(|| {
                    settings.throttle_codes.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
                });
                if ui.text_edit_singleline(codes).changed()
                    && let Some(parsed) = parse_codes(codes) {
                    settings.throttle_codes = parsed;
                }
                if parse_codes(codes).is_none() {
                    ui.colored_label(ui.visuals().error_fg_color, "Use codes from 100 to 599 separated by commas");
                }
            });
            egui::Grid::new("scanner-backoff-settings").num_columns(2).spacing([20.0, 7.0]).show(ui, |ui| {
                number(ui, "Initial backoff (ms)", &mut settings.backoff_ms, 1..=3600000);
                number(ui, "Maximum backoff (ms)", &mut settings.max_backoff_ms, 1..=3600000);
            });
            failure_settings(ui, &mut settings);
            coverage_settings(ui, &mut settings);
            ui.label("Excluded parameter names (one per line)");
            let excluded = self.excluded_parameters_text.get_or_insert_with(|| settings.excluded_parameters.join("\n"));
            if ui.add(egui::TextEdit::multiline(excluded).desired_width(400.0).desired_rows(5)).changed() {
                settings.excluded_parameters = excluded.lines().map(str::trim).filter(|name| !name.is_empty()).map(str::to_owned).collect();
            }
            ui.weak("Captured cookies, tokens, and Authorization headers are reused. Scans do not log in or refresh authentication automatically.");
            ui.add_space(8.0);
            if ui.button("Restore default scanner settings").clicked() {
                settings = ScanSettings::default();
                self.throttle_codes_text = None;
                self.excluded_parameters_text = None;
            }
        });
        if settings != previous {
            save_settings(engine, settings)?;
            return Ok(Some("Scanner settings saved".into()));
        }
        Ok(None)
    }
    fn export(&mut self, ctx: &egui::Context) -> anyhow::Result<Option<String>> {
        if !self.export_open {
            return Ok(None);
        }
        let findings = &self.export_findings;
        let mut result = None;
        let mut close = false;
        let response = egui::Modal::new(egui::Id::new("scanner-export-findings")).show(ctx, |ui| {
            ui.set_width(500.0);
            ui.heading("Export findings");
            ui.label(format!(
                "{} findings match the current filters",
                findings.len()
            ));
            ui.horizontal(|ui| {
                if ui
                    .selectable_value(&mut self.export_html, false, "JSON")
                    .changed()
                {
                    self.export_path = "scanner-findings.json".into();
                }
                if ui
                    .selectable_value(&mut self.export_html, true, "HTML report")
                    .changed()
                {
                    self.export_path = "scanner-findings.html".into();
                }
            });
            ui.label("Filename");
            ui.add(egui::TextEdit::singleline(&mut self.export_path).desired_width(f32::INFINITY));
            ui.horizontal(|ui| {
                if ui.button("Export").clicked() {
                    match scanner::report::write(
                        Path::new(&self.export_path),
                        findings,
                        self.export_html,
                    ) {
                        Ok(()) => {
                            result = Some(format!(
                                "Exported {} findings to {}",
                                findings.len(),
                                self.export_path
                            ));
                            close = true;
                        }
                        Err(error) => self.error = format!("{error:#}"),
                    }
                }
                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
            ui.weak("Exports include captured request/response evidence. Choose a new filename.");
            if !self.error.is_empty() {
                ui.colored_label(ui.visuals().error_fg_color, &self.error);
            }
        });
        if close || response.should_close() {
            self.export_open = false;
            self.export_findings.clear();
        }
        Ok(result)
    }
}
fn resource_settings(ui: &mut egui::Ui, settings: &mut ScanSettings) {
    ui.add_space(8.0);
    subsection_heading(ui, "Resource limits");
    egui::Grid::new("scanner-resource-settings")
        .num_columns(2)
        .spacing([20.0, 7.0])
        .show(ui, |ui| {
            number(
                ui,
                "Concurrent requests",
                &mut settings.concurrency,
                1..=128,
            );
            number(ui, "Request delay (ms)", &mut settings.delay_ms, 0..=600000);
            ui.label("Delay type");
            egui::ComboBox::from_id_salt("scanner-delay-mode")
                .selected_text(delay_label(settings.delay_mode))
                .show_ui(ui, |ui| {
                    for mode in [DelayMode::Fixed, DelayMode::Random, DelayMode::Increasing] {
                        ui.selectable_value(&mut settings.delay_mode, mode, delay_label(mode));
                    }
                });
            ui.end_row();
            if settings.delay_mode == DelayMode::Random {
                number(
                    ui,
                    "Random variation (ms)",
                    &mut settings.jitter_ms,
                    0..=600000,
                );
            }
            if settings.delay_mode == DelayMode::Increasing {
                number(
                    ui,
                    "Delay increment (ms)",
                    &mut settings.delay_increment_ms,
                    0..=600000,
                );
            }
            number(
                ui,
                "Request timeout (seconds)",
                &mut settings.timeout_secs,
                1..=3600,
            );
        });
}
fn failure_settings(ui: &mut egui::Ui, settings: &mut ScanSettings) {
    ui.add_space(8.0);
    subsection_heading(ui, "Failures and retries");
    ui.weak("Zero disables an error threshold. HTTP response status codes are separate from transport failures.");
    egui::Grid::new("scanner-failure-settings")
        .num_columns(2)
        .spacing([20.0, 7.0])
        .show(ui, |ui| {
            number(
                ui,
                "Consecutive request failures",
                &mut settings.stop_after_failures,
                0..=10000,
            );
            ui.label("At the failure threshold");
            egui::ComboBox::from_id_salt("scanner-failure-action")
                .selected_text(if settings.failure_action == FailureAction::Pause {
                    "Pause"
                } else {
                    "Stop"
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut settings.failure_action,
                        FailureAction::Pause,
                        "Pause",
                    );
                    ui.selectable_value(&mut settings.failure_action, FailureAction::Stop, "Stop");
                });
            ui.end_row();
            number(
                ui,
                "Failed checks before skipping an insertion point",
                &mut settings.check_failure_limit,
                0..=10000,
            );
            number(
                ui,
                "Failed insertion points before failing a request",
                &mut settings.insertion_failure_limit,
                0..=10000,
            );
            number(
                ui,
                "Failed requests before pausing a scan",
                &mut settings.failed_item_limit,
                0..=10000,
            );
            number(
                ui,
                "Failed request percentage before pausing",
                &mut settings.failed_item_percent,
                0..=100,
            );
            number(
                ui,
                "Timeout retry passes",
                &mut settings.retry_passes,
                0..=15,
            );
        });
}
fn coverage_settings(ui: &mut egui::Ui, settings: &mut ScanSettings) {
    ui.add_space(8.0);
    subsection_heading(ui, "Audit coverage");
    ui.checkbox(
        &mut settings.intrusive,
        "Enable intrusive HTTP checks (raw framing, persistent input, cache changes)",
    );
    ui.checkbox(
        &mut settings.static_javascript,
        "Analyze captured HTML / JavaScript without browser execution",
    );
    ui.checkbox(
        &mut settings.follow_redirects,
        "Follow in-scope redirects when required by checks",
    );
    egui::Grid::new("scanner-audit-limits")
        .num_columns(2)
        .spacing([20.0, 7.0])
        .show(ui, |ui| {
            number(ui, "Maximum redirects", &mut settings.max_redirects, 0..=20);
            number(
                ui,
                "Insertion points per request",
                &mut settings.max_insertion_points,
                1..=1000,
            );
            number(
                ui,
                "Maximum probes per request",
                &mut settings.max_probes_per_request,
                1..=100000,
            );
        });
    ui.add_space(8.0);
    subsection_heading(ui, "Insertion points");
    ui.checkbox(
        &mut settings.scan_query_values,
        "URL query parameter values",
    );
    ui.checkbox(&mut settings.scan_form_values, "Form body parameter values");
    ui.checkbox(&mut settings.scan_json_values, "JSON values");
    ui.checkbox(&mut settings.scan_json_body, "Entire JSON body");
    ui.checkbox(&mut settings.scan_xml_elements, "XML element text");
    ui.checkbox(&mut settings.scan_xml_attributes, "XML attributes");
    ui.checkbox(&mut settings.scan_multipart_values, "Multipart form values");
    ui.checkbox(
        &mut settings.scan_multipart_filenames,
        "Multipart filenames",
    );
    ui.checkbox(&mut settings.scan_cookies, "Cookies");
    ui.checkbox(&mut settings.scan_headers, "HTTP headers");
    ui.checkbox(&mut settings.scan_path, "URL path segments");
    ui.checkbox(&mut settings.scan_parameter_names, "Parameter names");
    ui.checkbox(&mut settings.nested, "Nested encoded parameters");
    ui.weak("Nested values are scanned only within enabled insertion points. Dedicated checks may use their own request locations; configure those in Library.");
}
fn save_settings(engine: &Engine, settings: ScanSettings) -> anyhow::Result<()> {
    settings.validate()?;
    let mut project = engine.project.lock().unwrap();
    let previous = std::mem::replace(&mut project.workspace.scanner, settings);
    if let Err(error) = project.save_workspace() {
        project.workspace.scanner = previous;
        return Err(error);
    }
    engine.scanner.activity.fetch_add(1, Ordering::SeqCst);
    Ok(())
}
fn delay_label(mode: DelayMode) -> &'static str {
    match mode {
        DelayMode::Fixed => "Fixed",
        DelayMode::Random => "Random variation",
        DelayMode::Increasing => "Increasing",
    }
}
fn number<T: egui::emath::Numeric>(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut T,
    range: std::ops::RangeInclusive<T>,
) {
    ui.label(label);
    ui.add(egui::DragValue::new(value).range(range));
    ui.end_row();
}
fn parse_codes(text: &str) -> Option<Vec<u16>> {
    text.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<u16>()
                .ok()
                .filter(|code| (100..=599).contains(code))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Confidence;
    #[test]
    fn throttle_codes_are_validated_as_http_statuses() {
        assert_eq!(parse_codes("429, 503, 504"), Some(vec![429, 503, 504]));
        assert_eq!(parse_codes(""), Some(vec![]));
        assert_eq!(parse_codes("99"), None);
        assert_eq!(parse_codes("600"), None);
        assert_eq!(parse_codes("503, invalid"), None);
    }
    fn finding(id: u64, severity: Severity) -> Finding {
        Finding {
            id,
            issue_id: "test-check".into(),
            title: format!("Finding {id}"),
            severity,
            original_severity: severity,
            confidence: Confidence::Firm,
            mode: ScanMode::Passive,
            origins: vec![ScanMode::Passive],
            url: "https://example.test/search?q=original".into(),
            method: "GET".into(),
            insertion_point: "query:q".into(),
            detail: "Evidence detail".into(),
            description: "Issue background".into(),
            remediation: "Validate the input".into(),
            evidence: vec![scanner::Evidence {
                label: "Observed response".into(),
                exchange: Exchange {
                    id,
                    timestamp_ms: 1,
                    tool: "Proxy".into(),
                    destination: crate::model::Destination::from_url("https://example.test")
                        .unwrap(),
                    url: "https://example.test/search?q=original".into(),
                    method: "GET".into(),
                    request: b"GET /search?q=original HTTP/1.1\r\nHost: example.test\r\n\r\n"
                        .to_vec(),
                    response: b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\noriginal"
                        .to_vec(),
                    status: 200,
                    duration_ms: 1,
                    error: None,
                    note: String::new(),
                },
            }],
            first_seen_ms: 1,
            last_seen_ms: 1,
            occurrences: 1,
            state: ReviewState::New,
            notes: String::new(),
            scan_ids: vec![],
        }
    }
    #[test]
    fn groups_findings_by_issue_and_host_and_keeps_all_evidence() {
        let first = finding(1, Severity::Low);
        let mut second = finding(2, Severity::High);
        second.url = "https://example.test/other?q=changed".into();
        second.method = "POST".into();
        second.insertion_point = "body:x".into();
        second.origins.push(ScanMode::Active);
        second.evidence[0].exchange.url = second.url.clone();
        let mut other_host = finding(3, Severity::Low);
        other_host.url = "https://sub.example.test/".into();
        let mut other_issue = finding(4, Severity::Low);
        other_issue.issue_id = "other-check".into();
        let (grouped, members) = group_findings(vec![second, other_host, other_issue, first]);
        assert_eq!(grouped.len(), 3);
        let group = grouped.iter().find(|f| f.id == 1).unwrap();
        assert_eq!(members[&1], vec![1, 2]);
        assert_eq!(group.occurrences, 2);
        assert_eq!(group.evidence.len(), 2);
        assert_eq!(group.severity, Severity::High);
        assert_eq!(source_label(group), "Passive + Active");
        let view = State {
            findings: grouped,
            search: "q=changed".into(),
            ..Default::default()
        };
        assert_eq!(
            view.filtered_findings()
                .iter()
                .map(|f| f.id)
                .collect::<Vec<_>>(),
            vec![1]
        );
    }
    #[test]
    fn filtering_uses_all_provenance_and_severity_sort() {
        let low = finding(1, Severity::Low);
        let mut high = finding(2, Severity::High);
        high.origins.push(ScanMode::Active);
        let mut view = State {
            findings: vec![low, high],
            ..Default::default()
        };
        assert_eq!(
            view.filtered_findings()
                .iter()
                .map(|f| f.id)
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        view.source = Some(ScanMode::Active);
        assert_eq!(
            view.filtered_findings()
                .iter()
                .map(|f| f.id)
                .collect::<Vec<_>>(),
            vec![2]
        );
        view.search = "not-present".into();
        assert!(view.filtered_findings().is_empty());
        view.search.clear();
        view.review = Some(ReviewState::FalsePositive);
        assert!(view.filtered_findings().is_empty());
    }
    #[test]
    fn every_scanner_page_and_evidence_renders_in_a_narrow_viewport() {
        let engine = Engine::new(crate::project::Project::temporary()).unwrap();
        let original = finding(1, Severity::High);
        engine
            .project
            .lock()
            .unwrap()
            .put_finding(original.clone())
            .unwrap();
        let context = egui::Context::default();
        let mut view = State {
            selected_finding: Some(original.id),
            ..Default::default()
        };
        for dark in [false, true] {
            context.set_visuals(if dark {
                egui::Visuals::dark()
            } else {
                egui::Visuals::light()
            });
            for tab in [Tab::Scans, Tab::Findings, Tab::Issues, Tab::Settings] {
                view.tab = tab;
                for detail in [DetailTab::Issue, DetailTab::Evidence, DetailTab::Triage] {
                    view.detail_tab = detail;
                    for _ in 0..2 {
                        let input = egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::Pos2::ZERO,
                                egui::vec2(760.0, 620.0),
                            )),
                            ..Default::default()
                        };
                        let output = context.run(input, |context| {
                            egui::CentralPanel::default().show(context, |ui| {
                                view.show(ui, &engine, DisplayTimezone::Utc).unwrap();
                            });
                        });
                        assert!(!output.shapes.is_empty());
                        assert!(view.error.is_empty(), "{}", view.error);
                    }
                }
            }
        }
        let saved = engine.project.lock().unwrap().finding(original.id).unwrap();
        assert_eq!(
            saved.evidence[0].exchange.request,
            original.evidence[0].exchange.request
        );
        assert_eq!(
            saved.evidence[0].exchange.response,
            original.evidence[0].exchange.response
        );
    }
}

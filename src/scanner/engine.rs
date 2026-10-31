use super::*;
use crate::{
    engine::Engine,
    http::Message,
    model::{Destination, Exchange},
    transport,
};
use anyhow::{Context, Result, ensure};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Capture<'a> {
    engine: &'a Engine,
    flow: Option<Exchange>,
    started: Instant,
}

fn routed_url(request: &Message, destination: &Destination) -> Result<String> {
    let target = request.target();
    if target.starts_with("http://") || target.starts_with("https://") {
        let url = url::Url::parse(target)?;
        let declared = Destination::from_url(target)?;
        ensure!(
            declared.host.eq_ignore_ascii_case(&destination.host)
                && declared.port == destination.port
                && declared.tls == destination.tls,
            "Absolute request target does not match scanner destination"
        );
        Ok(format!(
            "{}{}{}",
            destination.origin(),
            url.path(),
            url.query().map(|q| format!("?{q}")).unwrap_or_default()
        ))
    } else {
        ensure!(
            target.starts_with('/'),
            "Scanner requires an HTTP origin-form or absolute-form target"
        );
        Ok(format!("{}{target}", destination.origin()))
    }
}
impl Drop for Capture<'_> {
    fn drop(&mut self) {
        if let Some(mut flow) = self.flow.take() {
            flow.duration_ms = self.started.elapsed().as_millis() as u64;
            flow.error = Some("Scanner request interrupted".into());
            match self.engine.project.lock().unwrap().insert(flow) {
                Ok(()) => {
                    self.engine.activity.fetch_add(1, Ordering::SeqCst);
                }
                Err(error) => self
                    .engine
                    .errors
                    .lock()
                    .unwrap()
                    .push(format!("Save interrupted scanner exchange: {error:#}")),
            }
        }
    }
}

impl Engine {
    pub fn record_scan_candidates(
        &self,
        candidates: Vec<Candidate>,
        mode: ScanMode,
        scan_id: Option<u64>,
        base: &Exchange,
    ) -> Result<usize> {
        let definitions = checks::definitions();
        let mut project = self.project.lock().unwrap();
        let previous_count = project.finding_count(scan_id);
        let settings = scan_id
            .and_then(|id| project.scan_job(id).map(|j| j.settings))
            .unwrap_or_else(|| project.workspace.scanner.clone());
        let mut count = 0;
        for candidate in candidates {
            if !settings.check_enabled(&candidate.issue_id) {
                continue;
            }
            let Some(definition) = definitions.iter().find(|d| d.id == candidate.issue_id) else {
                continue;
            };
            if mode == ScanMode::Passive
                && !settings.static_javascript
                && (candidate.issue_id.contains("javascript") || candidate.issue_id == "static-dom")
            {
                continue;
            }
            let timestamp = now();
            let (affected_url, affected_method) = candidate
                .affected
                .unwrap_or_else(|| (base.url.clone(), base.method.clone()));
            let evidence = if candidate.evidence.is_empty() {
                vec![Evidence {
                    label: "Observed exchange".into(),
                    exchange: base.clone(),
                }]
            } else {
                candidate.evidence
            };
            let finding = Finding {
                id: 0,
                issue_id: definition.id.clone(),
                title: definition.name.clone(),
                severity: definition.severity,
                original_severity: definition.severity,
                confidence: candidate.confidence,
                mode,
                origins: vec![mode],
                url: affected_url,
                method: affected_method,
                insertion_point: candidate.insertion_point,
                detail: candidate.detail,
                description: definition.description.clone(),
                remediation: definition.remediation.clone(),
                evidence,
                first_seen_ms: timestamp,
                last_seen_ms: timestamp,
                occurrences: 1,
                state: ReviewState::New,
                notes: String::new(),
                scan_ids: scan_id.into_iter().collect(),
            };
            project.upsert_finding(finding)?;
            count += 1;
        }
        if count > 0 {
            self.scanner.activity.fetch_add(1, Ordering::SeqCst);
        }
        Ok(project
            .finding_count(scan_id)
            .saturating_sub(previous_count))
    }

    pub(crate) fn enqueue_passive(&self, flow: &Exchange) {
        let settings = self.settings();
        if self.scanner.passive_stopping.load(Ordering::SeqCst)
            || !settings.passive_scanning
            || !settings.scope.contains(&flow.url)
        {
            return;
        }
        let config = self.project.lock().unwrap().workspace.scanner.clone();
        {
            let mut queue = self.scanner.passive_queue.lock().unwrap();
            if self.scanner.passive_stopping.load(Ordering::SeqCst) {
                return;
            }
            let queued_bytes: usize = queue
                .iter()
                .map(|(flow, _)| flow.request.len() + flow.response.len())
                .sum();
            if queue.len() >= 128
                || queued_bytes
                    .saturating_add(flow.request.len())
                    .saturating_add(flow.response.len())
                    > 64 * 1024 * 1024
            {
                self.errors
                    .lock()
                    .unwrap()
                    .push("Passive scanner queue is full; this exchange was not analyzed".into());
                return;
            }
            queue.push_back((flow.clone(), config));
            if self.scanner.passive_running.swap(true, Ordering::SeqCst) {
                return;
            }
        }
        let Some(engine) = self
            .scanner
            .engine
            .get()
            .and_then(|engine| engine.upgrade())
        else {
            return;
        };
        tokio::task::spawn_blocking(move || {
            loop {
                let next = {
                    let mut queue = engine.scanner.passive_queue.lock().unwrap();
                    match queue.pop_front() {
                        Some(next) => Some(next),
                        None => {
                            engine
                                .scanner
                                .passive_running
                                .store(false, Ordering::SeqCst);
                            None
                        }
                    }
                };
                let Some((flow, config)) = next else {
                    break;
                };
                if !engine.settings().scope.contains(&flow.url) {
                    continue;
                }
                let mut candidates = checks::passive(
                    &flow,
                    engine.settings().max_message_bytes.min(8 * 1024 * 1024),
                );
                candidates.retain(|c| {
                    config.check_enabled(&c.issue_id)
                        && (config.static_javascript
                            || !(c.issue_id.contains("javascript") || c.issue_id == "static-dom"))
                });
                let budget = (64 * 1024 * 1024usize
                    / (flow.request.len() + flow.response.len()).max(1))
                .clamp(1, 64);
                if candidates.len() >= budget {
                    candidates.truncate(budget);
                    engine.errors.lock().unwrap().push(format!("Passive analysis of exchange #{} reached its finding/evidence budget; additional results may be omitted",flow.id));
                }
                if let Err(error) =
                    engine.record_scan_candidates(candidates, ScanMode::Passive, None, &flow)
                {
                    engine
                        .errors
                        .lock()
                        .unwrap()
                        .push(format!("Passive scanner: {error:#}"));
                }
            }
        });
    }

    pub fn stop_passive(&self) {
        let mut queue = self.scanner.passive_queue.lock().unwrap();
        self.scanner.passive_stopping.store(true, Ordering::SeqCst);
        queue.clear();
    }

    pub async fn scanner_execute(
        &self,
        bytes: Vec<u8>,
        destination: Destination,
        raw: bool,
        timeout_secs: u64,
        association: &str,
    ) -> Result<Exchange> {
        let request = Message::parse(&bytes)?;
        let mut settings = self.settings();
        let route = routed_url(&request, &destination);
        let url = route
            .as_ref()
            .cloned()
            .unwrap_or_else(|_| format!("{}{}", destination.origin(), request.target()));
        let id = self.project.lock().unwrap().allocate_id();
        let flow = Exchange {
            id,
            timestamp_ms: now(),
            tool: "Scanner".into(),
            destination: destination.clone(),
            url: url.clone(),
            method: request.method().into(),
            request: bytes,
            response: vec![],
            status: 0,
            duration_ms: 0,
            error: None,
            note: association.into(),
        };
        let mut capture = Capture {
            engine: self,
            flow: Some(flow),
            started: Instant::now(),
        };
        let result: Result<()> = async {
            route?;
            ensure!(
                settings.scope.contains(&url),
                "Scanner request is outside target scope"
            );
            if let Some(address) = self.scanner_listener_address() {
                settings.listen = address.to_string();
            }
            let flow = capture.flow.as_mut().unwrap();
            ensure!(
                flow.request.len() <= settings.max_message_bytes,
                "Scanner request exceeds message limit"
            );
            tokio::time::timeout(Duration::from_secs(timeout_secs.clamp(1, 3600)), async {
                // The current scope is authoritative even if a job was queued earlier.
                ensure!(
                    self.settings().scope.contains(&url),
                    "Scanner request is outside current target scope"
                );
                if raw {
                    let mut stream = transport::connect_raw(&destination, &settings).await?;
                    ensure!(
                        self.settings().scope.contains(&url),
                        "Scanner request is outside current target scope"
                    );
                    stream.write_all(&flow.request).await?;
                    stream.flush().await?;
                    let mut buffer = [0u8; 8192];
                    loop {
                        let n = if flow.response.is_empty() {
                            stream.read(&mut buffer).await?
                        } else {
                            match tokio::time::timeout(
                                Duration::from_millis(300),
                                stream.read(&mut buffer),
                            )
                            .await
                            {
                                Ok(n) => n?,
                                Err(_) => break,
                            }
                        };
                        if n == 0 {
                            break;
                        }
                        ensure!(
                            flow.response.len() + n <= settings.max_message_bytes,
                            "Raw scanner response exceeds message limit"
                        );
                        flow.response.extend_from_slice(&buffer[..n]);
                    }
                    ensure!(
                        !flow.response.is_empty(),
                        "Target closed without a response"
                    );
                    flow.status = Message::parse(&flow.response).map_or(0, |m| m.status());
                } else {
                    let mut request = request;
                    request.prepare_request(&destination)?;
                    flow.request = request.encode();
                    let response =
                        transport::send_scanner(&destination, &request, &settings, &|| {
                            self.settings().scope.contains(&url)
                        })
                        .await?;
                    flow.status = response.status();
                    flow.response = response.encode();
                }
                Ok(())
            })
            .await
            .context("Scanner request timed out")?
        }
        .await;
        let mut flow = capture.flow.take().unwrap();
        flow.duration_ms = capture.started.elapsed().as_millis() as u64;
        if let Err(error) = result {
            flow.error = Some(format!("{error:#}"));
        }
        self.project.lock().unwrap().record(&flow)?;
        self.activity.fetch_add(1, Ordering::SeqCst);
        self.enqueue_passive(&flow);
        Ok(flow)
    }
}

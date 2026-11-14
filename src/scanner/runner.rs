//! Bounded, project-scoped scanner scheduling. No network work resumes on load.
use super::{
    DelayMode, FailureAction, ScanItem, ScanJob, ScanMode, ScanSettings, ScanStatus, checks,
};
use crate::{
    engine::Engine,
    http::Message,
    model::{Destination, Exchange},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, watch},
    task::JoinSet,
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Run,
    Pause,
    Cancel,
    Interrupt,
    Failure,
}

struct PoolState {
    in_flight: usize,
    exclusive: bool,
    last_start: Option<Instant>,
    blocked_until: Instant,
    starts: u64,
    backoff_ms: u64,
}
impl Default for PoolState {
    fn default() -> Self {
        Self {
            in_flight: 0,
            exclusive: false,
            last_start: None,
            blocked_until: Instant::now(),
            starts: 0,
            backoff_ms: 0,
        }
    }
}
#[derive(Default)]
struct SharedPool {
    state: Mutex<PoolState>,
    changed: Notify,
}

#[derive(Default)]
pub struct RunnerHub {
    controls: Mutex<BTreeMap<u64, watch::Sender<Command>>>,
    pool: Arc<SharedPool>,
    pub activity: AtomicU64,
}
impl RunnerHub {
    pub fn active(&self) -> bool {
        !self.controls.lock().unwrap().is_empty()
    }
    pub fn stop_all(&self) {
        for control in self.controls.lock().unwrap().values() {
            control.send_replace(Command::Interrupt);
        }
        self.pool.changed.notify_waiters();
    }
}
struct Lease {
    pool: Arc<SharedPool>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.pool.state.lock().unwrap();
        state.in_flight = state.in_flight.saturating_sub(1);
        if state.in_flight == 0 {
            state.exclusive = false;
        }
        drop(state);
        self.pool.changed.notify_waiters();
    }
}
fn notify(engine: &Engine) {
    engine
        .scanner
        .runner
        .activity
        .fetch_add(1, Ordering::SeqCst);
    engine.scanner.activity.fetch_add(1, Ordering::SeqCst);
}
fn persist(engine: &Engine, job: &mut ScanJob) -> Result<()> {
    job.updated_ms = super::now();
    engine.project.lock().unwrap().put_scan_job(job.clone())?;
    notify(engine);
    Ok(())
}
/// Bound note writes and job snapshots. Progress is durable within a quarter
/// second, while a large scan no longer serializes the complete job (including
/// every selected request) once per probe response.
fn persist_due(
    engine: &Engine,
    job: &mut ScanJob,
    last: &mut Option<Instant>,
    notes: &mut Vec<(String, u64, bool)>,
    force: bool,
) -> Result<()> {
    let due = force
        || notes.len() >= 4096
        || last.is_none_or(|instant| instant.elapsed() >= Duration::from_millis(250));
    if !due {
        return Ok(());
    }
    if !notes.is_empty() {
        let pending = std::mem::take(notes);
        engine.project.lock().unwrap().put_scan_notes(&pending)?;
    }
    persist(engine, job)?;
    *last = Some(Instant::now());
    Ok(())
}
fn command_status(command: Command) -> ScanStatus {
    match command {
        Command::Run => ScanStatus::Running,
        Command::Pause => ScanStatus::Paused,
        Command::Cancel => ScanStatus::Cancelled,
        Command::Interrupt => ScanStatus::Interrupted,
        Command::Failure => ScanStatus::Failed,
    }
}
/// Live resource-pool state for scan progress views.
pub fn resource_status(engine: &Engine) -> String {
    let settings = live_settings(engine);
    let state = engine.scanner.runner.pool.state.lock().unwrap();
    let mut status = format!(
        "{} / {} requests active",
        state.in_flight, settings.concurrency
    );
    if state.exclusive {
        status.push_str(" · isolated timing or state-changing check");
    }
    if settings.auto_throttle && state.blocked_until > Instant::now() {
        status.push_str(&format!(
            " · throttled for {:.1}s",
            state
                .blocked_until
                .saturating_duration_since(Instant::now())
                .as_secs_f32()
        ));
    }
    status
}
fn live_settings(engine: &Engine) -> ScanSettings {
    engine.project.lock().unwrap().workspace.scanner.clone()
}

/// Creates and immediately dispatches a batch using a frozen check configuration.
pub fn start(engine: Arc<Engine>, sources: Vec<Exchange>) -> Result<u64> {
    let _runtime = tokio::runtime::Handle::try_current()
        .context("Scanner requires an entered Tokio runtime")?;
    ensure!(!sources.is_empty(), "Select at least one request to scan");
    let settings = live_settings(&engine);
    settings.validate()?;
    let timestamp = super::now();
    let mut project = engine.project.lock().unwrap();
    let id = project.allocate_scan_id();
    let job = ScanJob {
        id,
        name: format!("Scan {id}"),
        check_version: super::CHECK_VERSION,
        status: ScanStatus::Queued,
        created_ms: timestamp,
        updated_ms: timestamp,
        settings,
        items: sources
            .into_iter()
            .map(|source| ScanItem {
                source,
                status: ScanStatus::Queued,
                next_probe: 0,
                completed: 0,
                failures: 0,
                message: String::new(),
            })
            .collect(),
        requests: 0,
        failures: 0,
        findings: 0,
        skipped: 0,
        message: String::new(),
    };
    project.put_scan_job(job.clone())?;
    drop(project);
    spawn(engine, job, false)?;
    Ok(id)
}
fn spawn(engine: Arc<Engine>, job: ScanJob, retry_failed: bool) -> Result<()> {
    let runtime = tokio::runtime::Handle::try_current()
        .context("Scanner requires an entered Tokio runtime")?;
    let (tx, rx) = watch::channel(Command::Run);
    let mut controls = engine.scanner.runner.controls.lock().unwrap();
    ensure!(
        !controls.contains_key(&job.id),
        "This scan is already running or settling"
    );
    controls.insert(job.id, tx);
    drop(controls);
    notify(&engine);
    runtime.spawn(async move {
        let id = job.id;
        if let Err(error) = run(engine.clone(), job, rx, retry_failed).await {
            let saved = engine.project.lock().unwrap().scan_job(id);
            if let Some(mut failed) = saved {
                failed.status = ScanStatus::Failed;
                failed.message = format!("{error:#}");
                let _ = persist(&engine, &mut failed);
            }
            engine.log_error(format!("Scanner {id}: {error:#}"));
        }
        engine.scanner.runner.controls.lock().unwrap().remove(&id);
        notify(&engine);
    });
    Ok(())
}
fn signal(engine: &Arc<Engine>, id: u64, command: Command) -> Result<bool> {
    let controls = engine.scanner.runner.controls.lock().unwrap();
    if let Some(control) = controls.get(&id) {
        ensure!(
            !matches!(
                *control.borrow(),
                Command::Cancel | Command::Interrupt | Command::Failure
            ),
            "Scan is settling; wait for current work to stop"
        );
        control.send_replace(command);
        drop(controls);
        engine.scanner.runner.pool.changed.notify_waiters();
        Ok(true)
    } else {
        Ok(false)
    }
}
pub fn pause(engine: Arc<Engine>, id: u64) -> Result<()> {
    let saved = engine
        .project
        .lock()
        .unwrap()
        .scan_job(id)
        .context("Scan does not exist")?;
    ensure!(
        matches!(
            saved.status,
            ScanStatus::Queued | ScanStatus::Running | ScanStatus::Paused
        ),
        "Scan cannot be paused"
    );
    signal(&engine, id, Command::Pause)?;
    let mut job = engine
        .project
        .lock()
        .unwrap()
        .scan_job(id)
        .context("Scan does not exist")?;
    job.status = ScanStatus::Paused;
    job.message = "Paused; current requests are allowed to finish".into();
    persist(&engine, &mut job)
}
pub fn resume(engine: Arc<Engine>, id: u64) -> Result<()> {
    let job = engine
        .project
        .lock()
        .unwrap()
        .scan_job(id)
        .context("Scan does not exist")?;
    ensure!(
        job.check_version == super::CHECK_VERSION,
        "This scan uses an older check version; create a new scan from its requests"
    );
    ensure!(
        matches!(
            job.status,
            ScanStatus::Paused | ScanStatus::Interrupted | ScanStatus::Queued
        ),
        "Only paused or interrupted scans can resume"
    );
    if signal(&engine, id, Command::Run)? {
        return Ok(());
    }
    spawn(engine, job, false)
}
pub fn cancel(engine: Arc<Engine>, id: u64) -> Result<()> {
    let mut job = engine
        .project
        .lock()
        .unwrap()
        .scan_job(id)
        .context("Scan does not exist")?;
    if signal(&engine, id, Command::Cancel)? {
        return Ok(());
    }
    ensure!(
        job.status.unfinished() || job.status == ScanStatus::Interrupted,
        "Scan has already finished"
    );
    job.status = ScanStatus::Cancelled;
    job.message = "Cancelled".into();
    persist(&engine, &mut job)
}
pub fn retry(engine: Arc<Engine>, id: u64) -> Result<()> {
    ensure!(
        !engine
            .scanner
            .runner
            .controls
            .lock()
            .unwrap()
            .contains_key(&id),
        "Stop or finish the scan before retrying"
    );
    let mut job = engine
        .project
        .lock()
        .unwrap()
        .scan_job(id)
        .context("Scan does not exist")?;
    ensure!(
        job.check_version == super::CHECK_VERSION,
        "This scan uses an older check version; create a new scan from its requests"
    );
    ensure!(
        job.failures > 0
            || matches!(
                job.status,
                ScanStatus::Failed | ScanStatus::Cancelled | ScanStatus::Interrupted
            ),
        "There is no failed work to retry"
    );
    for item in &mut job.items {
        if item.failures > 0 || item.status != ScanStatus::Completed {
            item.status = ScanStatus::Queued;
            item.next_probe = 0;
            item.completed = 0;
            item.message.clear();
        }
    }
    job.status = ScanStatus::Queued;
    job.message = "Retrying failed work; successful probes are retained".into();
    persist(&engine, &mut job)?;
    spawn(engine, job, true)
}
pub fn shutdown(engine: Arc<Engine>) -> Result<()> {
    engine.stop_passive();
    engine.scanner.runner.stop_all();
    Ok(())
}

fn spacing(settings: &ScanSettings, sequence: u64) -> Duration {
    let extra = match settings.delay_mode {
        DelayMode::Fixed => 0,
        DelayMode::Increasing => settings
            .delay_increment_ms
            .saturating_mul(sequence)
            .min(600_000),
        DelayMode::Random => {
            // Deterministic jitter needs no RNG state and remains independent across request starts.
            let mut x = sequence.wrapping_add(0x9e3779b97f4a7c15);
            x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
            (x ^ (x >> 31)) % settings.jitter_ms.saturating_add(1)
        }
    };
    Duration::from_millis(settings.delay_ms.saturating_add(extra).min(600_000))
}
async fn acquire(
    engine: &Arc<Engine>,
    serial: bool,
    control: &mut watch::Receiver<Command>,
) -> Result<Lease> {
    loop {
        match *control.borrow() {
            Command::Cancel | Command::Interrupt | Command::Failure => {
                anyhow::bail!("Scan interrupted")
            }
            Command::Pause => {}
            Command::Run => {}
        }
        if *control.borrow() == Command::Pause {
            control.changed().await.context("Scanner control closed")?;
            continue;
        }
        let shared = engine.scanner.runner.pool.clone();
        let notified = shared.changed.notified();
        let settings = live_settings(engine);
        let delay = {
            let mut state = shared.state.lock().unwrap();
            let now = Instant::now();
            let paced = state.last_start.map_or(now, |last| {
                last + spacing(&settings, state.starts.saturating_sub(1))
            });
            let deadline = if settings.auto_throttle {
                paced.max(state.blocked_until)
            } else {
                paced
            };
            let capacity = if serial {
                state.in_flight == 0
            } else {
                !state.exclusive && state.in_flight < settings.concurrency
            };
            if capacity && deadline <= now {
                state.in_flight += 1;
                state.exclusive = serial;
                state.last_start = Some(now);
                state.starts = state.starts.wrapping_add(1);
                drop(state);
                return Ok(Lease {
                    pool: shared.clone(),
                });
            }
            if capacity {
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(250))
            } else {
                Duration::from_millis(250)
            }
        };
        tokio::select! { _=notified=>{}, _=tokio::time::sleep(delay)=>{}, result=control.changed()=>{result.context("Scanner control closed")?;} }
    }
}
fn retry_after(response: &Exchange) -> Option<Duration> {
    let message = Message::parse(&response.response).ok()?;
    let value = message.header("Retry-After")?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds.min(365 * 24 * 3600)));
    }
    let date = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    Some(Duration::from_millis(
        (date.timestamp_millis() as i128 - super::now() as i128)
            .max(0)
            .min(u64::MAX as i128) as u64,
    ))
}
fn throttle(engine: &Engine, response: &Exchange) {
    let settings = live_settings(engine);
    if !settings.auto_throttle {
        return;
    }
    let trigger = response.status == 429
        || (settings.throttle_503 && response.status == 503)
        || settings.throttle_codes.contains(&response.status);
    let mut state = engine.scanner.runner.pool.state.lock().unwrap();
    if trigger {
        state.backoff_ms = if state.backoff_ms == 0 {
            settings.backoff_ms
        } else {
            state
                .backoff_ms
                .saturating_mul(2)
                .min(settings.max_backoff_ms)
        };
        let delay =
            Duration::from_millis(state.backoff_ms).max(retry_after(response).unwrap_or_default());
        state.blocked_until = state.blocked_until.max(Instant::now() + delay);
    } else if response.error.is_none() && Instant::now() >= state.blocked_until {
        state.backoff_ms = 0;
    }
    drop(state);
    engine.scanner.runner.pool.changed.notify_waiters();
}
#[allow(clippy::too_many_arguments)]
async fn send_once(
    engine: &Arc<Engine>,
    request: Vec<u8>,
    destination: Destination,
    raw: bool,
    serial: bool,
    settings: &ScanSettings,
    association: &str,
    control: &mut watch::Receiver<Command>,
) -> Result<Exchange> {
    let _lease = acquire(engine, serial, control).await?;
    let future = engine.scanner_execute(
        request,
        destination,
        raw,
        settings.timeout_secs,
        association,
    );
    tokio::pin!(future);
    let response = loop {
        tokio::select! {
            result=&mut future=>break result?,
            changed=control.changed()=>{
                if changed.is_err()||matches!(*control.borrow(),Command::Cancel|Command::Interrupt) {anyhow::bail!("Scan interrupted");}
                // Pause does not interrupt an already-started request.
            }
        }
    };
    throttle(engine, &response);
    Ok(response)
}
fn redirect(response: &Exchange, request: &[u8]) -> Option<(Vec<u8>, Destination)> {
    if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let response_message = Message::parse(&response.response).ok()?;
    let location = response_message.header("Location")?;
    let previous = url::Url::parse(&response.url).ok()?;
    let next = previous.join(location).ok()?;
    let destination = Destination::from_url(next.as_str()).ok()?;
    let mut message = Message::parse(request).ok()?;
    if previous.origin() != next.origin() {
        message.remove("Authorization");
        message.remove("Cookie");
        message.remove("Proxy-Authorization");
    }
    let old_method = message.method().to_owned();
    let method = if response.status == 303 && old_method != "HEAD"
        || matches!(response.status, 301 | 302) && old_method == "POST"
    {
        "GET".to_owned()
    } else {
        old_method
    };
    if method == "GET" && message.method() != "GET" {
        message.body.clear();
        message.remove("Content-Type");
        message.remove("Content-Length");
        message.remove("Transfer-Encoding");
    }
    let version = message
        .start
        .split_whitespace()
        .nth(2)
        .unwrap_or("HTTP/1.1")
        .to_owned();
    let mut target = next.path().to_owned();
    if let Some(query) = next.query() {
        target.push('?');
        target.push_str(query);
    }
    message.start = format!("{method} {target} {version}");
    message.set("Host", destination.authority());
    message.normalize_length();
    Some((message.encode(), destination))
}
#[allow(clippy::too_many_arguments)]
async fn send_chain(
    engine: &Arc<Engine>,
    request: Vec<u8>,
    destination: Destination,
    raw: bool,
    serial: bool,
    settings: &ScanSettings,
    association: &str,
    control: &mut watch::Receiver<Command>,
) -> Result<Vec<Exchange>> {
    let mut exchanges = vec![];
    let mut request = request;
    let mut destination = destination;
    let mut visited = BTreeSet::new();
    for hop in 0..=settings.max_redirects {
        let note = if hop == 0 {
            association.to_owned()
        } else {
            format!("{association};redirect:{hop}")
        };
        let response = send_once(
            engine,
            request.clone(),
            destination.clone(),
            raw,
            serial,
            settings,
            &note,
            control,
        )
        .await?;
        let follow = if !raw && settings.follow_redirects && response.error.is_none() {
            redirect(&response, &request)
        } else {
            None
        };
        let ended = response.error.is_some();
        exchanges.push(response);
        let Some((next_request, next_destination)) = follow else {
            break;
        };
        let next_message = Message::parse(&next_request)?;
        let next_url = next_message.url(&next_destination);
        if ended || !engine.settings().scope.contains(&next_url) || !visited.insert(next_url) {
            break;
        }
        request = next_request;
        destination = next_destination;
    }
    Ok(exchanges)
}
struct Outcome {
    index: usize,
    probe: checks::Probe,
    exchanges: Vec<Exchange>,
}
fn safe_to_retry(probe: &checks::Probe) -> bool {
    static INTRUSIVE: OnceLock<BTreeSet<String>> = OnceLock::new();
    let intrusive = INTRUSIVE.get_or_init(|| {
        checks::definitions()
            .into_iter()
            .filter(|check| check.intrusive)
            .map(|check| check.id)
            .collect()
    });
    !probe.raw
        && !intrusive.contains(&probe.issue_id)
        && Message::parse(&probe.request)
            .is_ok_and(|m| matches!(m.method(), "GET" | "HEAD" | "OPTIONS"))
}
async fn execute_probe(
    engine: Arc<Engine>,
    job_id: u64,
    item: usize,
    index: usize,
    probe: checks::Probe,
    mut settings: ScanSettings,
    mut control: watch::Receiver<Command>,
) -> Result<Outcome> {
    settings.follow_redirects &= probe.follow_redirects();
    let mut exchanges = vec![];
    let association = format!("scan:{job_id};item:{item};probe:{index}");
    let attempts = if safe_to_retry(&probe) {
        settings.retry_passes + 1
    } else {
        1
    };
    for attempt in 0..attempts {
        let note = if attempt == 0 {
            association.clone()
        } else {
            format!("{association};retry:{attempt}")
        };
        let mut responses = send_chain(
            &engine,
            probe.request.clone(),
            probe.destination.clone(),
            probe.raw,
            probe.serial(),
            &settings,
            &note,
            &mut control,
        )
        .await?;
        let failed = responses.last().is_some_and(|flow| flow.error.is_some());
        exchanges.append(&mut responses);
        if !failed {
            break;
        }
    }
    Ok(Outcome {
        index,
        probe,
        exchanges,
    })
}
/// Completed probe indices plus the exchanges retained for combined checks.
type SavedProbeState = (BTreeSet<usize>, Vec<(checks::Probe, Exchange)>);

/// Saved probe state for one item. Completed indices are kept even when the
/// matching exchange is dropped, so a resumed scan never needs to deserialize
/// the full capture history. Exchanges are fetched only for checks that need a
/// completed series.
fn saved_pairs(
    engine: &Engine,
    job: u64,
    item: usize,
    probes: &[checks::Probe],
    retry_failed: bool,
) -> Result<SavedProbeState> {
    let prefix = format!("scan:{job};item:{item};probe:");
    let rows = engine.project.lock().unwrap().scan_notes(&prefix)?;
    let mut completed = BTreeSet::new();
    let mut series = Vec::new();
    for (note, id, ok) in rows {
        let Some(rest) = note.strip_prefix(&prefix) else {
            continue;
        };
        let Ok(index) = rest.parse::<usize>() else {
            continue;
        };
        if index >= probes.len() {
            continue;
        }
        if retry_failed && !ok {
            continue;
        }
        completed.insert(index);
        if ok && probes[index].needs_series() {
            let flow = engine.project.lock().unwrap().get(id)?;
            if let Some(flow) = flow {
                series.push((probes[index].clone(), flow));
            }
        }
    }
    Ok((completed, series))
}
async fn wait_running(
    engine: &Engine,
    job: &mut ScanJob,
    control: &mut watch::Receiver<Command>,
) -> Result<bool> {
    loop {
        let command = *control.borrow();
        job.status = command_status(command);
        if matches!(
            command,
            Command::Cancel | Command::Interrupt | Command::Failure
        ) {
            return Ok(false);
        }
        if command == Command::Run {
            return Ok(true);
        }
        persist(engine, job)?;
        control.changed().await.context("Scanner control closed")?;
    }
}
fn threshold_reached(job: &ScanJob) -> bool {
    let failed = job
        .items
        .iter()
        .filter(|v| v.status == ScanStatus::Failed)
        .count();
    let finished = job
        .items
        .iter()
        .filter(|v| matches!(v.status, ScanStatus::Completed | ScanStatus::Failed))
        .count();
    (job.settings.failed_item_limit > 0 && failed >= job.settings.failed_item_limit)
        || (job.settings.failed_item_percent > 0
            && finished > 0
            && failed * 100 >= finished * usize::from(job.settings.failed_item_percent))
}
fn set_failure_action(engine: &Engine, id: u64, action: FailureAction) {
    if let Some(sender) = engine.scanner.runner.controls.lock().unwrap().get(&id) {
        sender.send_replace(if action == FailureAction::Pause {
            Command::Pause
        } else {
            Command::Failure
        });
    }
}
async fn run(
    engine: Arc<Engine>,
    mut job: ScanJob,
    mut control: watch::Receiver<Command>,
    retry_failed: bool,
) -> Result<()> {
    job.status = ScanStatus::Running;
    job.message.clear();
    persist(&engine, &mut job)?;
    let readbacks: Vec<_> = if job.settings.intrusive {
        job.items
            .iter()
            .filter(|item| matches!(item.source.method.as_str(), "GET" | "HEAD"))
            .map(|item| {
                let mut request = item.source.clone();
                request.response.clear();
                request
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut consecutive_failures = 0usize;
    let mut audited_tls = BTreeSet::new();
    let mut pending_notes: Vec<(String, u64, bool)> = Vec::new();
    let mut last_persist: Option<Instant> = None;
    'items: for item_index in 0..job.items.len() {
        if job.items[item_index].status == ScanStatus::Completed {
            continue;
        }
        if !wait_running(&engine, &mut job, &mut control).await? {
            break;
        }
        let source = job.items[item_index].source.clone();
        if !engine.settings().scope.contains(&source.url) {
            job.items[item_index].status = ScanStatus::Failed;
            job.items[item_index].message = "Outside project scope; no requests sent".into();
            job.skipped += 1;
            persist(&engine, &mut job)?;
            continue;
        }
        let audited_this_item = source.destination.tls
            && super::tls_checks::enabled(&job.settings)
            && audited_tls.insert(source.destination.authority());
        if audited_this_item {
            let candidates = {
                let audit = async {
                    let _lease = acquire(&engine, false, &mut control.clone()).await?;
                    Ok::<_, anyhow::Error>(
                        super::tls_checks::audit(&engine, &job.settings, &source).await,
                    )
                };
                tokio::pin!(audit);
                let mut audit_control = control.clone();
                loop {
                    tokio::select! {
                        findings = &mut audit => break findings?,
                        change = audit_control.changed() => {
                            if change.is_err() || matches!(*audit_control.borrow(), Command::Cancel | Command::Interrupt | Command::Failure) {
                                break 'items;
                            }
                        }
                    }
                }
            };
            job.findings += engine.record_scan_candidates(
                candidates,
                ScanMode::Active,
                Some(job.id),
                &source,
            )?;
            persist(&engine, &mut job)?;
        }
        let plan = (|| -> Result<(Vec<checks::Probe>, usize)> {
            let mut seed = source.clone();
            seed.note = format!("scan:{};item:{item_index}", job.id);
            let plan = checks::active_plan_with_stats(&seed, &job.settings)?;
            let mut probes = plan.probes;
            let mut skipped = plan.skipped;
            if job.settings.intrusive {
                let stored = checks::stored_plan(&seed, &readbacks, &job.settings)?;
                let mut bytes: usize = probes.iter().map(|probe| probe.request.len()).sum();
                for group in stored.chunks(3) {
                    let group_bytes: usize = group.iter().map(|probe| probe.request.len()).sum();
                    if group.len() != 3
                        || probes.len().saturating_add(group.len())
                            > job.settings.max_probes_per_request
                        || bytes.saturating_add(group_bytes) > 64 * 1024 * 1024
                    {
                        skipped += group.len();
                        continue;
                    }
                    bytes += group_bytes;
                    probes.extend_from_slice(group);
                }
            }
            Ok((probes, skipped))
        })();
        let probes = match plan {
            Ok((probes, skipped)) => {
                job.skipped += skipped;
                probes
            }
            Err(error) => {
                job.items[item_index].status = ScanStatus::Failed;
                job.items[item_index].message = format!("Cannot build audit plan: {error:#}");
                job.skipped += 1;
                persist(&engine, &mut job)?;
                continue;
            }
        };
        if probes.is_empty() {
            job.items[item_index].status = ScanStatus::Completed;
            job.items[item_index].message = if audited_this_item {
                "TLS audit finished".into()
            } else {
                "No applicable enabled active checks".into()
            };
            persist(&engine, &mut job)?;
            continue;
        }
        job.items[item_index].status = ScanStatus::Running;
        let baseline_note = format!("scan:{};item:{item_index};baseline", job.id);
        let saved_baseline = {
            let project = engine.project.lock().unwrap();
            project
                .scan_notes(&baseline_note)?
                .into_iter()
                .find(|(note, _, ok)| note == &baseline_note && *ok)
                .map(|(_, id, _)| project.get(id))
                .transpose()?
                .flatten()
                .filter(|flow| flow.error.is_none())
        };
        let baseline = if let Some(baseline) = saved_baseline {
            baseline
        } else {
            let baseline_chain = send_chain(
                &engine,
                source.request.clone(),
                source.destination.clone(),
                false,
                false,
                &job.settings,
                &baseline_note,
                &mut control,
            )
            .await;
            let responses = match baseline_chain {
                Ok(v) => v,
                Err(error) => {
                    if matches!(
                        *control.borrow(),
                        Command::Cancel | Command::Interrupt | Command::Failure
                    ) {
                        break 'items;
                    }
                    return Err(error);
                }
            };
            job.requests += responses.len();
            job.failures += responses.iter().filter(|v| v.error.is_some()).count();
            let Some(baseline) = responses.last().cloned() else {
                continue;
            };
            if baseline.error.is_some() {
                job.items[item_index].status = ScanStatus::Failed;
                job.items[item_index].failures += 1;
                consecutive_failures += 1;
                if job.settings.stop_after_failures > 0
                    && consecutive_failures >= job.settings.stop_after_failures
                {
                    job.message = format!("{consecutive_failures} consecutive transport failures");
                    set_failure_action(&engine, job.id, job.settings.failure_action);
                    consecutive_failures = 0;
                }
                job.items[item_index].message =
                    "Baseline request failed; retry after checking target availability".into();
                persist(&engine, &mut job)?;
                if threshold_reached(&job) {
                    set_failure_action(&engine, job.id, job.settings.failure_action);
                }
                continue;
            }
            consecutive_failures = 0;
            baseline
        };
        let baseline_denied = matches!(baseline.status, 401 | 403);
        let evaluation = checks::CachedBaseline::new(&baseline);
        pending_notes.push((baseline_note.clone(), baseline.id, true));
        let (mut completed, mut series_results) =
            saved_pairs(&engine, job.id, item_index, &probes, retry_failed)?;
        let mut series_bytes: usize = series_results
            .iter()
            .map(|(_, flow)| flow.response.len())
            .sum();
        let mut series_dropped = false;
        let mut cursor = job.items[item_index].next_probe.min(probes.len());
        let mut tasks = JoinSet::new();
        let mut serial_pending = false;
        let mut blocked_points = BTreeSet::<String>::new();
        let mut point_failures = BTreeMap::<String, usize>::new();
        let mut failed_points = 0usize;
        let mut item_failed = false;
        loop {
            let command = *control.borrow();
            if matches!(
                command,
                Command::Cancel | Command::Interrupt | Command::Failure
            ) {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break 'items;
            }
            job.status = command_status(command);
            if command == Command::Run && !serial_pending {
                while cursor < probes.len() && tasks.len() < job.settings.concurrency {
                    if probes[cursor].serial() && !tasks.is_empty() {
                        break;
                    }
                    let index = cursor;
                    cursor += 1;
                    if completed.contains(&index) {
                        continue;
                    }
                    if blocked_points.contains(&probes[index].insertion_point) || item_failed {
                        job.skipped += 1;
                        continue;
                    }
                    serial_pending = probes[index].serial();
                    tasks.spawn(execute_probe(
                        engine.clone(),
                        job.id,
                        item_index,
                        index,
                        probes[index].clone(),
                        job.settings.clone(),
                        control.clone(),
                    ));
                    if serial_pending {
                        break;
                    }
                }
            }
            if cursor >= probes.len() && tasks.is_empty() {
                break;
            }
            if tasks.is_empty() && command == Command::Pause {
                persist_due(
                    &engine,
                    &mut job,
                    &mut last_persist,
                    &mut pending_notes,
                    true,
                )?;
                control.changed().await.context("Scanner control closed")?;
                continue;
            }
            tokio::select! {
                changed=control.changed()=>{changed.context("Scanner control closed")?;persist(&engine,&mut job)?;}
                outcome=tasks.join_next(),if !tasks.is_empty()=>{
                    let Some(outcome)=outcome else {continue;};
                    let outcome=match outcome.context("Scanner worker panicked")? {
                        Ok(outcome)=>outcome,
                        Err(error)=>{
                            if matches!(*control.borrow(),Command::Cancel|Command::Interrupt){tasks.abort_all();while tasks.join_next().await.is_some(){}break 'items;}
                            return Err(error);
                        }
                    };
                    if outcome.probe.serial(){serial_pending=false;}
                    job.requests+=outcome.exchanges.len();
                    let mut candidates=vec![];
                    for response in &outcome.exchanges {
                        if response.error.is_some(){job.failures+=1;job.items[item_index].failures+=1;consecutive_failures+=1;}else{consecutive_failures=0;candidates.extend(checks::evaluate_cached(&evaluation,&outcome.probe,response));}
                    }
                    job.findings+=engine.record_scan_candidates(candidates,ScanMode::Active,Some(job.id),&source)?;
                    if let Some(response)=outcome.exchanges.last() {
                        let failures=point_failures.entry(outcome.probe.insertion_point.clone()).or_default();
                        if response.error.is_some(){*failures+=1;}else{*failures=0;}
                        if job.settings.check_failure_limit>0&&*failures>=job.settings.check_failure_limit&&blocked_points.insert(outcome.probe.insertion_point.clone()) {
                            failed_points+=1;job.items[item_index].message=format!("Skipped insertion point {} after repeated transport failures",outcome.probe.insertion_point);
                            if job.settings.insertion_failure_limit>0&&failed_points>=job.settings.insertion_failure_limit{item_failed=true;}
                        }
                        completed.insert(outcome.index);
                        pending_notes.push((
                            format!("scan:{};item:{item_index};probe:{}", job.id, outcome.index),
                            response.id,
                            response.error.is_none(),
                        ));
                        if outcome.probe.needs_series() && response.error.is_none() {
                            series_bytes = series_bytes.saturating_add(response.response.len());
                            if series_bytes <= 64 * 1024 * 1024 {
                                series_results.push((outcome.probe.clone(), response.clone()));
                            } else {
                                series_dropped = true;
                            }
                        }
                    }
                    job.items[item_index].completed=completed.len();
                    // Advance the resume cursor monotonically instead of
                    // rescanning every prior index after each probe.
                    let mut next = job.items[item_index].next_probe.min(cursor);
                    while next < cursor && completed.contains(&next) {
                        next += 1;
                    }
                    job.items[item_index].next_probe = next;
                    if job.settings.stop_after_failures>0&&consecutive_failures>=job.settings.stop_after_failures {
                        job.message=format!("{} consecutive transport failures",consecutive_failures);set_failure_action(&engine,job.id,job.settings.failure_action);consecutive_failures=0;
                    }
                    persist_due(&engine,&mut job,&mut last_persist,&mut pending_notes,false)?;
                }
            }
        }
        if series_dropped {
            engine.log_error(format!(
                "Scanner {} item {}: series evidence exceeded 64 MiB; some combined checks were not evaluated",
                job.id, item_index
            ));
        }
        job.findings += engine.record_scan_candidates(
            checks::evaluate_series(&baseline, &series_results),
            ScanMode::Active,
            Some(job.id),
            &source,
        )?;
        job.items[item_index].next_probe = probes.len();
        job.items[item_index].status = if item_failed {
            ScanStatus::Failed
        } else {
            ScanStatus::Completed
        };
        if !item_failed {
            job.items[item_index].message = if baseline_denied {
                format!(
                    "{} probes completed; baseline returned {}. Captured credentials were not accepted for this request.",
                    job.items[item_index].completed, baseline.status
                )
            } else {
                format!("{} probes completed", job.items[item_index].completed)
            };
        }
        if threshold_reached(&job) {
            job.message = "Failed audit item threshold reached".into();
            set_failure_action(&engine, job.id, job.settings.failure_action);
        }
        persist_due(
            &engine,
            &mut job,
            &mut last_persist,
            &mut pending_notes,
            true,
        )?;
    }
    let command = *control.borrow();
    if matches!(
        command,
        Command::Cancel | Command::Interrupt | Command::Failure
    ) {
        job.status = command_status(command);
        job.message = match command {
            Command::Cancel => "Cancelled".into(),
            Command::Failure => format!("Stopped after failure threshold: {}", job.message),
            _ => "Interrupted; resume explicitly to continue".into(),
        };
        for item in &mut job.items {
            if item.status.unfinished() {
                item.status = job.status;
            }
        }
        // In-flight requests are aborted; their recorder guards may add a few
        // exchanges that are not yet reflected in the counters. Counts remain a
        // close lower bound without deserializing the complete capture history.
    } else {
        job.status = if job.items.iter().any(|v| v.status == ScanStatus::Failed) {
            ScanStatus::Failed
        } else {
            ScanStatus::Completed
        };
        job.message = format!(
            "{} requests, {} transport failures, {} skipped probes",
            job.requests, job.failures, job.skipped
        );
    }
    persist_due(
        &engine,
        &mut job,
        &mut last_persist,
        &mut pending_notes,
        true,
    )?;
    // Completed scans cannot resume. Failed and cancelled scans may be retried,
    // so their note index is retained and pruned when the project is reopened.
    if job.status == ScanStatus::Completed {
        engine.project.lock().unwrap().clear_scan_notes(job.id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pacing_modes_have_bounded_repeatable_spacing() {
        let mut s = ScanSettings {
            delay_ms: 20,
            ..ScanSettings::default()
        };
        assert_eq!(spacing(&s, 4), Duration::from_millis(20));
        s.delay_mode = DelayMode::Increasing;
        s.delay_increment_ms = 5;
        assert_eq!(spacing(&s, 4), Duration::from_millis(40));
        s.delay_mode = DelayMode::Random;
        s.jitter_ms = 7;
        let values: Vec<_> = (0..30).map(|i| spacing(&s, i)).collect();
        assert!(
            values
                .iter()
                .all(|d| *d >= Duration::from_millis(20) && *d <= Duration::from_millis(27))
        );
        assert!(values.windows(2).any(|v| v[0] != v[1]));
        assert_eq!(spacing(&s, 11), spacing(&s, 11));
    }
    fn response(url: &str, headers: &str) -> Exchange {
        let destination = Destination::from_url(url).unwrap();
        Exchange {
            id: 1,
            timestamp_ms: 0,
            tool: "Scanner".into(),
            destination,
            url: url.into(),
            method: "POST".into(),
            request: vec![],
            response: format!("HTTP/1.1 302 Found\r\n{headers}\r\n").into_bytes(),
            status: 302,
            duration_ms: 0,
            error: None,
            omitted_response_body_bytes: None,
            streamed_response: None,
            note: String::new(),
        }
    }
    #[test]
    fn cross_origin_redirect_drops_credentials_and_post_body() {
        let flow = response(
            "https://first.example:443/start",
            "Location: https://other.example/next?x=1\r\n",
        );
        let request=b"POST /start HTTP/1.1\r\nHost: first.example\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let (bytes, destination) = redirect(&flow, request).unwrap();
        let next = Message::parse(&bytes).unwrap();
        assert_eq!(destination.host, "other.example");
        assert_eq!(next.method(), "GET");
        assert_eq!(next.target(), "/next?x=1");
        assert!(next.body.is_empty());
        assert!(next.header("Authorization").is_none());
        assert!(next.header("Cookie").is_none());
    }
    #[test]
    fn retry_after_handles_seconds_and_http_date() {
        let mut flow = response("https://first.example:443/", "Retry-After: 7\r\n");
        assert_eq!(retry_after(&flow), Some(Duration::from_secs(7)));
        flow.response =
            b"HTTP/1.1 429 Slow\r\nRetry-After: Wed, 21 Oct 2015 07:28:00 GMT\r\n\r\n".to_vec();
        assert_eq!(retry_after(&flow), Some(Duration::ZERO));
    }
}

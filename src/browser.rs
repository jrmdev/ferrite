//! Managed Chromium-family browser routed through the Ferrite listener.
//!
//! The browser is a separate process with an isolated profile, so Ferrite's
//! idle footprint is unchanged while it is closed. HTTPS trust is confined to
//! that process: Chromium's `--ignore-certificate-errors-spki-list` switch
//! accepts only certificate chains that contain Ferrite's CA public key, and
//! Chromium honours it only together with a dedicated `--user-data-dir`. The
//! operating system trust store is never modified, certificate validation is
//! not disabled, and the CA private key never leaves Ferrite.
pub mod cdp;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    io::BufRead,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Marker written into profiles created by Ferrite. Reset refuses to delete
/// directories without it, so a mistyped path cannot remove unrelated data.
const PROFILE_MARKER: &str = ".ferrite-browser-profile";
const OUTPUT_LINES: usize = 200;
const OUTPUT_LINE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileMode {
    /// A fresh profile per launch, deleted when the browser exits.
    #[default]
    Temporary,
    /// A dedicated profile that keeps cookies and sessions across launches.
    Persistent,
}
impl ProfileMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Temporary => "Temporary (deleted on exit)",
            Self::Persistent => "Persistent",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BrowserSettings {
    /// Empty selects the first detected Chromium-family executable.
    pub executable: String,
    pub profile: ProfileMode,
    /// Empty uses [`default_profile_dir`] for persistent profiles.
    pub profile_dir: String,
    /// Empty routes through the active Ferrite listener; otherwise `host:port`.
    pub custom_proxy: String,
    /// Additional `--switch[=value]` arguments, one per entry.
    pub extra_args: Vec<String>,
    pub start_url: String,
    /// Expose the DevTools protocol on a random loopback port so Ferrite can
    /// list, open, navigate and close tabs and close the browser gracefully.
    pub devtools: bool,
    /// Disable Chromium's background services (updates, sync, telemetry) so
    /// they do not clutter the HTTP history.
    pub quiet: bool,
}
impl Default for BrowserSettings {
    fn default() -> Self {
        Self {
            executable: String::new(),
            profile: ProfileMode::Temporary,
            profile_dir: String::new(),
            custom_proxy: String::new(),
            extra_args: vec![],
            start_url: "about:blank".into(),
            devtools: true,
            quiet: true,
        }
    }
}

/// Switches Ferrite sets itself. Overriding them could route traffic around
/// the proxy, reuse a personal profile, or disable certificate validation.
const RESERVED: [&str; 13] = [
    "--user-data-dir",
    "--proxy-server",
    "--proxy-pac-url",
    "--proxy-auto-detect",
    "--no-proxy-server",
    "--proxy-bypass-list",
    "--ignore-certificate-errors-spki-list",
    "--ignore-certificate-errors",
    "--remote-debugging-port",
    "--remote-debugging-pipe",
    "--remote-debugging-address",
    "--remote-allow-origins",
    "--disable-web-security",
];

impl BrowserSettings {
    pub fn validate(&self) -> Result<()> {
        for arg in self.extra_args.iter().map(|a| a.trim()) {
            if arg.is_empty() {
                continue;
            }
            ensure!(
                arg.starts_with("--"),
                "Browser arguments must be --switches; set the start URL separately: {arg}"
            );
            let name = arg.split('=').next().unwrap_or(arg);
            ensure!(
                !RESERVED.contains(&name),
                "{name} is managed by Ferrite and cannot be overridden"
            );
        }
        if !self.custom_proxy.trim().is_empty() {
            parse_proxy(&self.custom_proxy)?;
        }
        if !self.start_url.trim().is_empty() && self.start_url.trim() != "about:blank" {
            let url = url::Url::parse(self.start_url.trim()).context("Invalid start URL")?;
            ensure!(
                matches!(url.scheme(), "http" | "https"),
                "Start URL must use http, https or about:blank"
            );
        }
        Ok(())
    }
}

fn parse_proxy(value: &str) -> Result<String> {
    let value = value.trim();
    let value = value.strip_prefix("http://").unwrap_or(value);
    let url = url::Url::parse(&format!("http://{value}")).context("Invalid proxy address")?;
    ensure!(
        url.path() == "/" && url.query().is_none() && url.username().is_empty(),
        "Proxy must be host:port"
    );
    let host = url.host_str().context("Proxy needs a host")?;
    let port = url.port().context("Proxy needs a port")?;
    Ok(format!("{host}:{port}"))
}

/// The address a local browser should use to reach a listener. Wildcard binds
/// are reached through the matching loopback address.
pub fn proxy_for_listener(address: SocketAddr) -> String {
    let ip = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, address.port()).to_string()
}

/// Resolve the proxy for a launch from the settings and the active listener.
pub fn resolve_proxy(settings: &BrowserSettings, listener: Option<SocketAddr>) -> Result<String> {
    if settings.custom_proxy.trim().is_empty() {
        Ok(proxy_for_listener(listener.context(
            "Start the proxy listener before opening the browser",
        )?))
    } else {
        parse_proxy(&settings.custom_proxy)
    }
}

fn executable_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &["chrome.exe", "msedge.exe", "brave.exe", "chromium.exe"]
    } else {
        &[
            "chromium",
            "chromium-browser",
            "google-chrome",
            "google-chrome-stable",
            "chrome",
            "microsoft-edge",
            "microsoft-edge-stable",
            "brave-browser",
        ]
    }
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// macOS users often choose the `.app` bundle; launch its main executable.
fn resolve_bundle(path: &Path) -> PathBuf {
    if path.extension().is_some_and(|e| e == "app") && path.is_dir() {
        let directory = path.join("Contents").join("MacOS");
        if let Some(stem) = path.file_stem() {
            let named = directory.join(stem);
            if is_executable(&named) {
                return named;
            }
        }
        if let Ok(entries) = std::fs::read_dir(&directory) {
            let files: Vec<_> = entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| is_executable(p))
                .collect();
            if files.len() == 1 {
                return files[0].clone();
            }
        }
    }
    path.to_owned()
}

/// Installed Chromium-family browsers in preference order.
pub fn candidates() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = vec![];
    let mut push = |path: PathBuf| {
        let path = resolve_bundle(&path);
        if is_executable(&path) {
            let key = path.canonicalize().unwrap_or_else(|_| path.clone());
            if !found
                .iter()
                .any(|p| p.canonicalize().unwrap_or_else(|_| p.clone()) == key)
            {
                found.push(path);
            }
        }
    };
    if let Some(path) = std::env::var_os("FERRITE_BROWSER") {
        push(PathBuf::from(path));
    }
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir();
        for app in [
            "Google Chrome",
            "Chromium",
            "Google Chrome for Testing",
            "Microsoft Edge",
            "Brave Browser",
            "Google Chrome Canary",
        ] {
            let bundle = format!("{app}.app/Contents/MacOS/{app}");
            push(Path::new("/Applications").join(&bundle));
            if let Some(home) = &home {
                push(home.join("Applications").join(&bundle));
            }
        }
    }
    #[cfg(windows)]
    {
        for base in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            let Some(base) = std::env::var_os(base) else {
                continue;
            };
            for relative in [
                r"Google\Chrome\Application\chrome.exe",
                r"Chromium\Application\chrome.exe",
                r"Microsoft\Edge\Application\msedge.exe",
                r"BraveSoftware\Brave-Browser\Application\brave.exe",
            ] {
                push(Path::new(&base).join(relative));
            }
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for name in executable_names() {
            for directory in std::env::split_paths(&paths) {
                push(directory.join(name));
            }
        }
    }
    #[cfg(target_os = "linux")]
    for path in ["/opt/google/chrome/chrome", "/snap/bin/chromium"] {
        push(PathBuf::from(path));
    }
    found
}

/// The configured executable, or the first detected browser.
pub fn locate(settings: &BrowserSettings) -> Result<PathBuf> {
    let configured = settings.executable.trim();
    if !configured.is_empty() {
        let path = resolve_bundle(Path::new(configured));
        ensure!(
            is_executable(&path),
            "Browser executable {} does not exist or is not executable",
            path.display()
        );
        return Ok(path);
    }
    candidates().into_iter().next().context(
        "No Chromium, Google Chrome, Edge or Brave executable was found. Install one or choose its executable in Browser settings.",
    )
}

pub fn default_profile_dir() -> Result<PathBuf> {
    Ok(dirs::data_local_dir()
        .context("Cannot locate the local application data directory")?
        .join("ferrite")
        .join("browser-profile"))
}

pub fn persistent_profile_dir(settings: &BrowserSettings) -> Result<PathBuf> {
    if settings.profile_dir.trim().is_empty() {
        default_profile_dir()
    } else {
        Ok(PathBuf::from(settings.profile_dir.trim()))
    }
}

fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("Create browser profile {}", path.display()))
}

/// Prepare a persistent profile, refusing directories Ferrite did not create.
fn prepare_persistent(path: &Path) -> Result<()> {
    if path.exists() {
        ensure!(path.is_dir(), "{} is not a directory", path.display());
        let marked = path.join(PROFILE_MARKER).is_file();
        let empty = std::fs::read_dir(path)?.next().is_none();
        ensure!(
            marked || empty,
            "{} is not a Ferrite browser profile. Choose an empty directory so a personal browser profile is never reused.",
            path.display()
        );
    } else {
        create_private_dir(path)?;
    }
    std::fs::write(
        path.join(PROFILE_MARKER),
        b"Managed by Ferrite Workbench. Profile reset deletes this directory.\n",
    )?;
    Ok(())
}

/// The live process holding a profile's singleton lock, if any.
pub fn profile_owner(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        // Chromium's SingletonLock is a symlink to "<hostname>-<pid>".
        let target = std::fs::read_link(path.join("SingletonLock")).ok()?;
        let pid: i32 = target.to_str()?.rsplit('-').next()?.parse().ok()?;
        let pid = rustix::process::Pid::from_raw(pid)?;
        rustix::process::test_kill_process(pid).ok()?;
        Some(pid.as_raw_nonzero().get() as u32)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Remove temporary profiles left behind when Ferrite was killed before it
/// could clean up. Only marked directories without a live owner are removed.
fn sweep_stale_profiles(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let stale = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("ferrite-browser-"))
            && path.join(PROFILE_MARKER).is_file()
            && entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| t.elapsed().unwrap_or_default() > Duration::from_secs(60))
            && profile_owner(&path).is_none()
            // Windows keeps "lockfile" open while Chromium runs.
            && match std::fs::remove_file(path.join("lockfile")) {
                Ok(()) => true,
                Err(error) => error.kind() == std::io::ErrorKind::NotFound,
            };
        if stale {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// Delete a Ferrite-created persistent profile while no browser uses it.
pub fn reset_profile(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    ensure!(
        path.join(PROFILE_MARKER).is_file(),
        "{} was not created by Ferrite; delete it manually if intended",
        path.display()
    );
    if let Some(pid) = profile_owner(path) {
        bail!("The profile is in use by browser process {pid}; close it first");
    }
    std::fs::remove_dir_all(path).with_context(|| format!("Delete {}", path.display()))
}

/// Complete Chromium command line for an isolated, proxied launch.
pub fn arguments(
    settings: &BrowserSettings,
    profile: &Path,
    proxy: &str,
    spki: &str,
) -> Result<Vec<String>> {
    settings.validate()?;
    ensure!(
        !spki.is_empty() && !spki.contains([',', ' ']),
        "Invalid CA public key pin"
    );
    let mut args = vec![
        format!("--user-data-dir={}", profile.display()),
        format!("--proxy-server=http://{proxy}"),
        // Chromium bypasses loopback by default; route local targets through Ferrite too.
        "--proxy-bypass-list=<-loopback>".into(),
        format!("--ignore-certificate-errors-spki-list={spki}"),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        // QUIC cannot traverse an HTTP proxy; keep every request on TCP.
        "--disable-quic".into(),
    ];
    // Chromium honours only the last --disable-features switch, so merge any
    // user-supplied list with Ferrite's instead of letting one replace the other.
    let mut disabled: Vec<String> = vec![];
    if settings.quiet {
        args.extend(QUIET_SWITCHES.map(String::from));
        disabled.extend(QUIET_FEATURES.map(String::from));
    }
    let mut extra = vec![];
    for arg in settings
        .extra_args
        .iter()
        .map(|a| a.trim())
        .filter(|a| !a.is_empty())
    {
        match arg.strip_prefix("--disable-features=") {
            Some(list) => disabled.extend(
                list.split(',')
                    .map(str::trim)
                    .filter(|f| !f.is_empty())
                    .map(String::from),
            ),
            None => extra.push(arg.to_string()),
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    disabled.retain(|feature| seen.insert(feature.clone()));
    if !disabled.is_empty() {
        args.push(format!("--disable-features={}", disabled.join(",")));
    }
    if settings.devtools {
        // Bound to loopback on a random port and announced on stderr. Clients
        // that send an Origin header are rejected unless explicitly allowed.
        args.push("--remote-debugging-port=0".into());
    }
    args.extend(extra);
    let start = settings.start_url.trim();
    args.push(
        if start.is_empty() {
            "about:blank"
        } else {
            start
        }
        .into(),
    );
    Ok(args)
}

/// Background services that would otherwise add Chromium's own requests to
/// the history. Some Google endpoints (account and GCM check-ins, component
/// updates) cannot be disabled by switches; filter History by scope instead.
const QUIET_SWITCHES: [&str; 9] = [
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-component-extensions-with-background-pages",
    "--disable-sync",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--no-pings",
    "--metrics-recording-only",
];
const QUIET_FEATURES: [&str; 6] = [
    "OptimizationHints",
    "MediaRouter",
    "Translate",
    "AutofillServerCommunication",
    "InterestFeedContentSuggestions",
    "NetworkTimeServiceQuerying",
];

enum Profile {
    Temporary(tempfile::TempDir),
    Persistent(PathBuf),
}
impl Profile {
    fn path(&self) -> &Path {
        match self {
            Self::Temporary(dir) => dir.path(),
            Self::Persistent(path) => path,
        }
    }
}

#[derive(Default)]
struct Output {
    lines: VecDeque<String>,
    devtools: Option<String>,
}

/// A running browser. Dropping it terminates the process tree.
pub struct Browser {
    child: Child,
    profile: Profile,
    proxy: String,
    ca_pin: String,
    executable: PathBuf,
    started: Instant,
    output: Arc<Mutex<Output>>,
    exit: Option<ExitStatus>,
    closing: Option<Instant>,
}

impl Browser {
    /// Launch a browser. Call from a long-lived thread: on Linux the browser is
    /// asked to exit when the launching thread's process goes away.
    pub fn launch(settings: &BrowserSettings, proxy: &str, spki: &str) -> Result<Self> {
        settings.validate()?;
        let executable = locate(settings)?;
        let profile = match settings.profile {
            ProfileMode::Temporary => {
                sweep_stale_profiles(&std::env::temp_dir());
                let dir = tempfile::Builder::new()
                    .prefix("ferrite-browser-")
                    .tempdir()
                    .context("Create temporary browser profile")?;
                std::fs::write(
                    dir.path().join(PROFILE_MARKER),
                    b"Temporary Ferrite profile\n",
                )?;
                Profile::Temporary(dir)
            }
            ProfileMode::Persistent => {
                let path = persistent_profile_dir(settings)?;
                prepare_persistent(&path)?;
                if let Some(pid) = profile_owner(&path) {
                    bail!(
                        "The persistent browser profile is already in use by process {pid}. Close that browser or use a temporary profile."
                    );
                }
                Profile::Persistent(path)
            }
        };
        let args = arguments(settings, profile.path(), proxy, spki)?;
        let mut command = Command::new(&executable);
        command
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            let parent = rustix::process::getpid();
            // SAFETY: the hook runs in the forked child before exec and only
            // performs the async-signal-safe prctl and getppid system calls.
            unsafe {
                command.pre_exec(move || {
                    rustix::process::set_parent_process_death_signal(Some(
                        rustix::process::Signal::TERM,
                    ))?;
                    if rustix::process::getppid() != Some(parent) {
                        return Err(std::io::Error::other("Ferrite exited during launch"));
                    }
                    Ok(())
                });
            }
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("Launch {}", executable.display()))?;
        let output = Arc::new(Mutex::new(Output::default()));
        if let Some(stderr) = child.stderr.take() {
            let output = output.clone();
            std::thread::Builder::new()
                .name("ferrite-browser-log".into())
                .spawn(move || read_output(stderr, &output))
                .context("Start browser log reader")?;
        }
        Ok(Self {
            child,
            profile,
            proxy: proxy.into(),
            ca_pin: spki.into(),
            executable,
            started: Instant::now(),
            output,
            exit: None,
            closing: None,
        })
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn proxy(&self) -> &str {
        &self.proxy
    }
    /// The CA public key pin the browser trusts.
    pub fn ca_pin(&self) -> &str {
        &self.ca_pin
    }
    pub fn executable(&self) -> &Path {
        &self.executable
    }
    pub fn profile_path(&self) -> &Path {
        self.profile.path()
    }
    pub fn temporary_profile(&self) -> bool {
        matches!(self.profile, Profile::Temporary(_))
    }
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }
    pub fn closing(&self) -> bool {
        self.closing.is_some()
    }
    /// The browser-level DevTools WebSocket URL, once announced.
    pub fn devtools_url(&self) -> Option<String> {
        self.output.lock().unwrap().devtools.clone()
    }
    /// The loopback DevTools HTTP endpoint, once announced.
    pub fn devtools_address(&self) -> Option<SocketAddr> {
        cdp::endpoint(&self.devtools_url()?).ok()
    }
    pub fn recent_output(&self) -> Vec<String> {
        self.output.lock().unwrap().lines.iter().cloned().collect()
    }
    /// Non-blocking exit check. Escalates to a kill when a graceful close stalls.
    pub fn poll(&mut self) -> Option<ExitStatus> {
        if self.exit.is_none() {
            self.exit = self.child.try_wait().ok().flatten();
        }
        if self.exit.is_none()
            && self
                .closing
                .is_some_and(|since| since.elapsed() > Duration::from_secs(5))
        {
            let _ = self.child.kill();
            self.exit = self.child.wait().ok();
        }
        self.exit
    }
    /// True when the process exited soon after launch without an error, which
    /// is how Chromium reports handing its command line to another instance.
    pub fn handed_off(&self) -> bool {
        self.exit.is_some_and(|s| s.success()) && self.closing.is_none() && {
            self.started.elapsed() < Duration::from_secs(5)
        }
    }
    /// Mark a graceful close in progress (for example after a DevTools
    /// `Browser.close`); [`Self::poll`] kills the process if it lingers.
    pub fn begin_close(&mut self) {
        self.closing.get_or_insert_with(Instant::now);
    }
    /// Ask the browser to exit: SIGTERM on Unix, termination on Windows.
    pub fn terminate(&mut self) {
        self.begin_close();
        if self.exit.is_some() {
            return;
        }
        #[cfg(unix)]
        {
            if let Some(pid) = rustix::process::Pid::from_raw(self.child.id() as i32)
                && rustix::process::kill_process(pid, rustix::process::Signal::TERM).is_ok()
            {
                return;
            }
        }
        let _ = self.child.kill();
    }
    /// Block until the process exits or the timeout elapses.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.poll() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        self.poll()
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        if self.poll().is_none() {
            self.terminate();
            if self.wait_timeout(Duration::from_secs(3)).is_none() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
        // Temporary profiles are removed by TempDir after the process exits.
    }
}

fn read_output(stderr: std::process::ChildStderr, output: &Mutex<Output>) {
    let mut reader = std::io::BufReader::new(stderr);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        line.truncate(OUTPUT_LINE_BYTES);
        let text = String::from_utf8_lossy(&line).trim_end().to_string();
        let mut output = output.lock().unwrap();
        if let Some(url) = text.strip_prefix("DevTools listening on ") {
            output.devtools = Some(url.trim().to_string());
        }
        if output.lines.len() >= OUTPUT_LINES {
            output.lines.pop_front();
        }
        output.lines.push_back(text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_arguments_isolate_profile_proxy_and_trust() {
        let settings = BrowserSettings {
            extra_args: vec![
                "--window-size=1200,800".into(),
                " ".into(),
                "--disable-features=Translate,HttpsUpgrades".into(),
            ],
            ..Default::default()
        };
        let args = arguments(&settings, Path::new("/tmp/p"), "127.0.0.1:8080", "abc=").unwrap();
        assert!(args.contains(&"--user-data-dir=/tmp/p".to_string()));
        assert!(args.contains(&"--proxy-server=http://127.0.0.1:8080".to_string()));
        assert!(args.contains(&"--proxy-bypass-list=<-loopback>".to_string()));
        assert!(args.contains(&"--ignore-certificate-errors-spki-list=abc=".to_string()));
        assert!(args.contains(&"--remote-debugging-port=0".to_string()));
        assert!(args.contains(&"--window-size=1200,800".to_string()));
        assert!(!args.iter().any(|a| a == "--ignore-certificate-errors"));
        assert_eq!(args.last().unwrap(), "about:blank");
        let features: Vec<_> = args
            .iter()
            .filter(|a| a.starts_with("--disable-features="))
            .collect();
        assert_eq!(features.len(), 1, "Chromium honours only the last list");
        assert!(features[0].contains("NetworkTimeServiceQuerying"));
        assert!(features[0].ends_with(",HttpsUpgrades"));
        assert_eq!(features[0].matches("Translate").count(), 1);
        let quiet = args.len();
        let loud = arguments(
            &BrowserSettings {
                quiet: false,
                devtools: false,
                ..settings
            },
            Path::new("/tmp/p"),
            "127.0.0.1:8080",
            "abc=",
        )
        .unwrap();
        assert!(loud.len() < quiet);
        assert!(!loud.iter().any(|a| a.starts_with("--remote-debugging")));
    }

    #[test]
    fn managed_switches_cannot_be_overridden() {
        for arg in [
            "--proxy-server=socks5://x:1",
            "--user-data-dir=/home/me/.config/google-chrome",
            "--ignore-certificate-errors",
            "--remote-debugging-port=9222",
            "https://example.com",
        ] {
            let settings = BrowserSettings {
                extra_args: vec![arg.into()],
                ..Default::default()
            };
            assert!(settings.validate().is_err(), "{arg} must be rejected");
        }
        assert!(
            BrowserSettings {
                start_url: "file:///etc/passwd".into(),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            arguments(
                &BrowserSettings::default(),
                Path::new("/p"),
                "127.0.0.1:1",
                "a,--x"
            )
            .is_err()
        );
    }

    #[test]
    fn proxy_resolution_maps_wildcards_to_loopback() {
        assert_eq!(
            proxy_for_listener("0.0.0.0:8080".parse().unwrap()),
            "127.0.0.1:8080"
        );
        assert_eq!(
            proxy_for_listener("[::]:8081".parse().unwrap()),
            "[::1]:8081"
        );
        assert_eq!(
            proxy_for_listener("192.0.2.5:9000".parse().unwrap()),
            "192.0.2.5:9000"
        );
        let settings = BrowserSettings::default();
        assert!(resolve_proxy(&settings, None).is_err());
        let custom = BrowserSettings {
            custom_proxy: "http://localhost:8888".into(),
            ..Default::default()
        };
        assert_eq!(resolve_proxy(&custom, None).unwrap(), "localhost:8888");
        assert!(
            BrowserSettings {
                custom_proxy: "localhost".into(),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn persistent_profiles_never_adopt_or_delete_foreign_directories() {
        let dir = tempfile::tempdir().unwrap();
        let foreign = dir.path().join("Chrome");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join("Preferences"), b"{}").unwrap();
        assert!(prepare_persistent(&foreign).is_err());
        assert!(reset_profile(&foreign).is_err());
        assert!(foreign.join("Preferences").exists());

        let managed = dir.path().join("managed");
        prepare_persistent(&managed).unwrap();
        std::fs::write(managed.join("Cookies"), b"x").unwrap();
        prepare_persistent(&managed).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&managed).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        reset_profile(&managed).unwrap();
        assert!(!managed.exists());
        reset_profile(&managed).unwrap();
    }

    #[test]
    fn stale_temporary_profiles_are_swept_but_others_are_kept() {
        let root = tempfile::tempdir().unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(600);
        let make = |name: &str, marked: bool| {
            let path = root.path().join(name);
            std::fs::create_dir(&path).unwrap();
            if marked {
                std::fs::write(path.join(PROFILE_MARKER), b"x").unwrap();
            }
            std::fs::File::open(&path)
                .unwrap()
                .set_modified(old)
                .unwrap();
            path
        };
        let stale = make("ferrite-browser-stale", true);
        let foreign = make("ferrite-browser-unmarked", false);
        let other = make("other-app", true);
        let fresh = root.path().join("ferrite-browser-fresh");
        std::fs::create_dir(&fresh).unwrap();
        std::fs::write(fresh.join(PROFILE_MARKER), b"x").unwrap();
        sweep_stale_profiles(root.path());
        assert!(!stale.exists());
        assert!(foreign.exists() && other.exists() && fresh.exists());
    }

    #[cfg(unix)]
    #[test]
    fn launch_failure_and_lifecycle_are_observable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // A stand-in executable that announces DevTools like Chromium, then waits.
        let script = dir.path().join("fake-chromium");
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'DevTools listening on ws://127.0.0.1:9/devtools/browser/x' >&2\nfor a in \"$@\"; do echo \"$a\" >&2; done\nexec sleep 30\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let settings = BrowserSettings {
            executable: script.display().to_string(),
            ..Default::default()
        };
        let mut browser = Browser::launch(&settings, "127.0.0.1:8080", "pin=").unwrap();
        let profile = browser.profile_path().to_owned();
        assert!(profile.exists());
        assert!(browser.temporary_profile());
        for _ in 0..200 {
            if browser.devtools_url().is_some() && browser.recent_output().len() > 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            browser.devtools_address(),
            Some("127.0.0.1:9".parse().unwrap())
        );
        assert!(
            browser
                .recent_output()
                .contains(&"--proxy-server=http://127.0.0.1:8080".to_string())
        );
        assert!(browser.poll().is_none());
        browser.terminate();
        assert!(browser.wait_timeout(Duration::from_secs(5)).is_some());
        assert!(!browser.handed_off());
        drop(browser);
        assert!(!profile.exists(), "temporary profile must be removed");

        let missing = BrowserSettings {
            executable: dir.path().join("missing").display().to_string(),
            ..Default::default()
        };
        assert!(Browser::launch(&missing, "127.0.0.1:8080", "pin=").is_err());
    }
}

#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use ferrite::{engine::Engine, model::Destination, preferences::Preferences, project::Project};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
struct Args {
    headless: bool,
    project: Option<PathBuf>,
    listen: Option<String>,
    transparent: bool,
    fallback: Option<String>,
    ca: Option<PathBuf>,
}
fn args() -> Result<Args> {
    let mut a = Args {
        headless: false,
        project: None,
        listen: None,
        transparent: false,
        fallback: None,
        ca: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--headless" => a.headless = true,
            "--project" => a.project = Some(it.next().context("--project requires a path")?.into()),
            "--listen" => a.listen = Some(it.next().context("--listen requires IP:port")?),
            "--transparent" => a.transparent = true,
            "--fallback" => {
                a.fallback = Some(it.next().context("--fallback requires an HTTP(S) URL")?)
            }
            "--export-ca" => a.ca = Some(it.next().context("--export-ca requires a path")?.into()),
            "--help" | "-h" => {
                println!(
                    "Ferrite Workbench 0.1\n\nUsage: ferrite [--project FILE] [--listen IP:PORT] [--headless]\n               [--transparent] [--fallback URL] [--export-ca FILE]\n       ferrite mcp [--headless ...]   (MCP server; see ferrite mcp --help)\n\nWithout --project, uses a temporary in-memory project.\nHeadless proxy starts with interception disabled. Ctrl-C stops it.\n--export-ca writes only the public CA certificate (PEM).\nBuild without the GUI: cargo build --no-default-features"
                );
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("Ferrite Workbench {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => anyhow::bail!("Unknown argument {flag}; use --help"),
        }
    }
    Ok(a)
}
fn export_ca(engine: &Engine, path: &Path) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "Create CA export {}; choose a new filename if it exists",
                path.display()
            )
        })?;
    f.write_all(engine.authority.pem().as_bytes())?;
    Ok(())
}
const MCP_HELP: &str = "Ferrite Workbench MCP server (Model Context Protocol over stdio)

Usage: ferrite mcp [--endpoint-file FILE]
       ferrite mcp --headless [--project FILE] [--listen IP:PORT] [--start-proxy]
                   [--allow-requests] [--allow-active-scans] [--include-credentials]

Without --headless, relays an MCP client (for example Claude Code) to the
running Ferrite window. Enable MCP in Ferrite's MCP page first.

--headless runs Ferrite without a window and owns the project exclusively.
Requests and active scans are denied unless pre-authorised with
--allow-requests / --allow-active-scans; they stay limited to the project's
target scope. --start-proxy also starts the proxy listener.

Standard output carries only MCP messages; diagnostics go to standard error.";

fn mcp_main(mut it: impl Iterator<Item = String>) -> Result<()> {
    use ferrite::mcp::{
        McpSettings, Permission,
        host::{Host, HostMode},
        ipc, server,
    };
    let mut headless = false;
    let mut project = None;
    let mut listen = None;
    let mut start_proxy = false;
    let mut endpoint = None;
    let mut settings = McpSettings {
        enabled: true,
        send_requests: Permission::Deny,
        active_scans: Permission::Deny,
        ..Default::default()
    };
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--headless" => headless = true,
            "--project" => {
                project = Some(PathBuf::from(
                    it.next().context("--project requires a path")?,
                ))
            }
            "--listen" => listen = Some(it.next().context("--listen requires IP:port")?),
            "--start-proxy" => start_proxy = true,
            "--allow-requests" => settings.send_requests = Permission::Allow,
            "--allow-active-scans" => settings.active_scans = Permission::Allow,
            "--include-credentials" => settings.include_credentials = true,
            "--endpoint-file" => {
                endpoint = Some(PathBuf::from(
                    it.next().context("--endpoint-file requires a path")?,
                ))
            }
            "--help" | "-h" => {
                eprintln!("{MCP_HELP}");
                return Ok(());
            }
            _ => anyhow::bail!("Unknown argument {flag}; use ferrite mcp --help"),
        }
    }
    let runtime = tokio::runtime::Runtime::new()?;
    if !headless {
        anyhow::ensure!(
            project.is_none() && listen.is_none() && !start_proxy,
            "--project, --listen and --start-proxy require --headless"
        );
        let endpoint = match endpoint {
            Some(path) => path,
            None => ipc::default_endpoint_path()?,
        };
        return runtime.block_on(server::run_relay(endpoint));
    }
    // redb locks the file, so a project open in the GUI cannot be opened here.
    let project = match &project {
        Some(path) => Project::open(path)
            .with_context(|| format!("Open {} (close it in Ferrite first)", path.display()))?,
        None => Project::temporary(),
    };
    let preferences = Preferences::load(&project)?;
    let engine = Engine::new_with_key(project, preferences.ca_key())?;
    if let Some(listen) = listen {
        let mut proxy = engine.settings();
        proxy.listen = listen;
        engine.configure(proxy)?;
    }
    let host = Host::new(engine.clone(), settings, HostMode::Headless);
    runtime.block_on(async {
        let listener = if start_proxy {
            let listener = engine.start().await?;
            eprintln!("Ferrite proxy listening on {}", listener.address);
            Some(listener)
        } else {
            None
        };
        let result = server::run_headless(host).await;
        let _ = ferrite::scanner::runner::shutdown(engine.clone());
        if let Some(listener) = listener {
            listener.stop().await;
        }
        result
    })
}

fn main() -> Result<()> {
    let mut raw = std::env::args().skip(1).peekable();
    if raw.peek().map(String::as_str) == Some("mcp") {
        raw.next();
        return mcp_main(raw);
    }
    let args = args()?;
    let project = if let Some(path) = &args.project {
        Project::open(path)?
    } else {
        Project::temporary()
    };
    let preferences = Preferences::load(&project)?;
    let engine = Engine::new_with_key(project, preferences.ca_key())?;
    let mut settings = engine.settings();
    if let Some(listen) = args.listen {
        settings.listen = listen;
    }
    if args.transparent {
        settings.transparent = true;
    }
    if let Some(fallback) = args.fallback {
        settings.fallback = Some(Destination::from_url(&fallback)?);
    }
    engine.configure(settings)?;
    if let Some(path) = args.ca {
        export_ca(&engine, &path)?;
        println!("Public CA exported to {}", path.display());
    }
    let runtime = Arc::new(tokio::runtime::Runtime::new()?);
    if args.headless {
        runtime.block_on(async {
            let listener = engine.start().await?;
            println!(
                "Ferrite proxy listening on {}. Interception disabled. Ctrl-C to stop.",
                listener.address
            );
            tokio::signal::ctrl_c().await?;
            listener.stop().await;
            Ok::<_, anyhow::Error>(())
        })?;
    } else {
        #[cfg(feature = "gui")]
        {
            let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/ferrite.png"))
                .context("Decode application icon")?;
            let options = eframe::NativeOptions {
                viewport: eframe::egui::ViewportBuilder::default()
                    .with_inner_size([1320.0, 880.0])
                    .with_min_inner_size([950.0, 650.0])
                    .with_icon(icon),
                ..Default::default()
            };
            eframe::run_native(
                "Ferrite Workbench",
                options,
                Box::new(move |cc| {
                    Ok(Box::new(ferrite::app::Workbench::new(
                        cc,
                        engine,
                        runtime,
                        args.project,
                        preferences,
                    )))
                }),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        #[cfg(not(feature = "gui"))]
        anyhow::bail!("Built without GUI support. Use --headless.");
    }
    Ok(())
}

# Ferrite Workbench

Ferrite is a free, native desktop workbench for HTTP security testing. Inspired by Burp Proxy, it is an independent implementation written from scratch in Rust, with its own interface and project format.

Built for speed, Ferrite uses a native UI and asynchronous networking.

## Screenshots

**Settings**

![Settings](screenshots/image1.png)

**Proxy**

![Proxy](screenshots/image2.png)

**Target**

![Target](screenshots/image3.png)

**Intercept**

![Intercept](screenshots/image4.png)

**HTTP history**

![HTTP history](screenshots/image5.png)

**Scanner findings**

![Scanner findings](screenshots/image6.png)

**WebSocket history**

![WebSocket history](screenshots/image7.png)

## Tools

- **Proxy** — Capture HTTP and HTTPS traffic through a local listener. Configure upstream HTTP or SOCKS5 proxies, TLS verification, match-and-replace rules, and the proxy CA certificate.
- **Browser** — Open a dedicated Chromium, Chrome, Edge or Brave window that is already routed through the listener and trusts Ferrite's CA, with an isolated profile. Navigate, list and close tabs from Ferrite. See [built-in browser](docs/BROWSER.md).
- **MCP** — Let MCP clients, agents and harnesses inspect history, the site map, Repeater, scanner findings and WebSockets, and send in-scope requests through Ferrite, with approvals, rate limits, credential redaction and an audit trail. See [MCP server](docs/MCP.md).
- **Target** — Browse captured hosts and paths in a site map and manage which URLs are in scope.
- **Intercept** — Pause, inspect, edit, forward, or drop HTTP requests and responses and WebSocket messages.
- **History** — Search, filter, sort, inspect, and export captured exchanges. A WebSockets view lists sessions and their messages.
- **Repeater** — Edit and resend requests in named tabs grouped into collections; duplicate, close and move tabs, navigate previous sends, and compare a response with the previous send.
- **Intruder** — Run payload-based attacks using Sniper, Battering Ram, Pitchfork, and Cluster Bomb modes, with configurable concurrency and pacing.
- **Scanner** — Run passive checks on new in-scope traffic and active checks on selected requests. Review findings and evidence, manage checks in the Library, and export reports.
- **Decoder** — Chain Base64, Base64URL, URL, HTML entity, hex, Unicode escape and gzip transforms, inspect JWTs (without treating them as valid), and hash with MD5, SHA-1 and SHA-2.
- **Comparer** — Compare two requests or responses side by side with line, word or character highlights. Send items from any context menu or from Repeater.
- **Alerts** — Review connection errors, failed exchanges, and application activity.
- **Settings** — Manage projects, appearance, display timezone, and JSON formatting.
- **Plugins** — Not yet available; automation uses MCP. A sandboxed WebAssembly design is proposed in [extensibility](docs/PLUGINS.md).

Message editors highlight HTTP syntax and JSON, XML/HTML and form bodies, and offer a find bar. History rows can carry comments and colour highlights, which are searchable and filterable.

## Getting started

Install Rust 1.96 or newer, then start Ferrite:

```sh
cargo run --release -- --project assessment.ferrite
```

1. Open **Proxy** and select **Open browser** (Ferrite offers to start the listener). Browse your target in the window that opens; HTTPS works without installing the CA.
2. Alternatively, select **Start listener**, set `127.0.0.1:8080` as the HTTP and HTTPS proxy of another browser or device, and trust the public CA certificate exported from **Proxy**.
3. Add your target to scope, then inspect traffic in **History** or send requests to **Repeater**, **Intruder**, **Scanner**, **Decoder** or **Comparer**.

Passive scanning is enabled by default for new projects and analyzes new in-scope exchanges without sending additional requests. Active scans reuse captured credentials; intrusive checks require explicit enablement. Scanner does not automatically crawl, log in, or execute a browser.

Ferrite also supports headless proxying:

```sh
cargo run --release --no-default-features -- --headless --project assessment.ferrite --listen 127.0.0.1:8080 --export-ca assessment-ca.pem
```

Press Ctrl-C to stop the listener. Run `ferrite --help` for more options.

## MCP clients and agents

1. Open **MCP** in Ferrite and select **Enable MCP server**.
2. Add a stdio MCP server in your client or harness. Use the full path to the Ferrite executable as the command and `mcp` as its argument. The MCP page provides a copyable JSON example; configuration formats and locations vary by client.
3. Start or reconnect your client, then use Ferrite's tools. For example, ask an agent: "Using Ferrite, list the in-scope endpoints that take parameters and resend the last login request as another user."

Sending requests asks for your approval by default and is always limited to the target scope; active scans are disabled until you allow them. Credential headers are shown to the client as `[REDACTED]` and restored by Ferrite when requests are resent. Every call is recorded in the project's audit trail. Without the window, `ferrite mcp --headless --project assessment.ferrite` serves a project directly. See [MCP server](docs/MCP.md) for the tool reference and security model.

## Projects and traffic

Projects store captured traffic, tool configuration, findings, and results in a `.ferrite` file. Temporary projects can be saved to disk from **Settings**. Project files can contain credentials and other sensitive traffic.

Scope uses URL regular expressions; an empty include list matches nothing. Captured traffic is not blocked by scope unless **Drop out of scope** is enabled. History filters change the displayed rows without deleting captured traffic.

Ferrite supports HTTP/1.1, HTTP/2, HTTPS interception, and WebSocket capture. Response previews decode supported content encodings, while JSON beautification formats the display without changing the stored or transmitted bytes.

## Build and test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --no-default-features --all-targets
cargo build --release --locked
```

MCP and managed browser unit tests run as part of the test suite.

The project uses egui for the desktop UI, Tokio for networking, redb for project storage, and Rustls with RustCrypto for TLS. The RustCrypto TLS provider is experimental. See [architecture](docs/ARCHITECTURE.md) for implementation details.

## Platform support

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Proxy, tools, projects | Verified | CI build and tests | CI build and tests |
| Managed browser | Verified with Chrome for Testing 153 | Detection of Chrome, Chromium, Edge and Brave; untested against a real browser | Detection of Chrome, Chromium, Edge and Brave; untested against a real browser |
| Orphan prevention | Browser exits with Ferrite, even if Ferrite is killed | Closed on normal exit only | Closed on normal exit only |
| MCP relay and headless | Verified end to end | CI tests | CI tests |

## Known limitations

- The browser is a separate managed window, not embedded in Ferrite.
- Some Chromium background requests to Google services cannot be disabled by switches; filter History by scope to hide them.
- MCP supports the stdio transport; the authenticated Streamable HTTP transport is structured for but not yet implemented. Response bodies returned to MCP clients are not redacted.
- Ferrite does not load third-party plugins yet.
- History retains complete exchanges for display, so memory still grows with captured traffic. Incremental refreshes reuse unchanged exchanges, and temporary projects share their stored exchanges with the UI; MCP reads use a separate lock-free reader.

## Configuration

Application settings (theme, timezone, CA, browser and MCP settings) live in `settings.json` in Ferrite's configuration directory (for example `~/.config/ferrite` on Linux). Set `FERRITE_CONFIG_DIR` to use another directory, for example for a portable installation.

## License

MIT. See [LICENSE](LICENSE).

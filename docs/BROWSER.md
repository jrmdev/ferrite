# Built-in browser

Ferrite can launch a dedicated Chromium-family browser (Chromium, Google Chrome, Microsoft Edge or Brave) that is already routed through the Ferrite listener and already trusts Ferrite's CA. Its traffic appears in **History**, **Intercept** and **Target** like any other proxied client.

The browser is a separate, Ferrite-managed process. It is not embedded in the Ferrite window, so it adds nothing to Ferrite's memory use while it is closed.

## Quick start

1. Install Chromium, Google Chrome, Edge or Brave.
2. In **Proxy**, select **Open browser**. If the listener is stopped, Ferrite offers to start it first.
3. Browse. Requests appear in **History**; enable interception in **Intercept** to pause them.

The **Browser** page shows the process status, offers **Close**, **Restart**, a URL bar with back/forward/reload, the list of open tabs (focus or close each), and the browser settings.

## What Ferrite configures

Every launch uses these Ferrite-managed switches. They cannot be overridden from **Extra arguments**:

| Switch | Purpose |
| --- | --- |
| `--user-data-dir=<profile>` | Isolated profile; your personal browser profile is never used |
| `--proxy-server=http://<listener>` | HTTP, HTTPS (CONNECT) and WebSocket traffic goes through Ferrite |
| `--proxy-bypass-list=<-loopback>` | Loopback targets such as `localhost` are proxied too (Chromium bypasses them by default) |
| `--ignore-certificate-errors-spki-list=<pin>` | Trust Ferrite's CA in this process only (see below) |
| `--disable-quic` | QUIC cannot traverse an HTTP proxy; keep all requests on TCP |
| `--remote-debugging-port=0` | Optional (DevTools controls): random loopback port used by the Browser page |

With **Suppress Chromium background traffic** enabled (default), Ferrite also disables sync, component updates, network-time queries, translation, domain reliability reporting and similar services. A few Google endpoints (account list, GCM check-in, component updater) cannot be disabled by switches in current Chromium builds; use the History **In scope only** filter to hide them.

`--disable-features` lists from **Extra arguments** are merged with Ferrite's, because Chromium only honours the last occurrence of that switch.

## HTTPS trust

Ferrite does not install its CA anywhere. Instead it passes the SHA-256 hash of the CA's SubjectPublicKeyInfo (RFC 7469 pin format) to Chromium's `--ignore-certificate-errors-spki-list`. Chromium then accepts certificate chains that contain that public key, and only:

- inside the launched process, and
- because a dedicated `--user-data-dir` is in use (Chromium ignores the switch otherwise).

Consequences:

- The operating system trust store, other browsers and your normal Chrome profile are unaffected.
- Certificate validation is not disabled. Certificates from any other CA still fail, which the end-to-end test checks with a deliberately mismatched pin (`ERR_CERT_AUTHORITY_INVALID`).
- Only the public key is shared with the browser. The CA private key stays in Ferrite's application settings.
- Ferrite validates origin certificates on its upstream leg as configured in **Proxy** (*Verify upstream TLS certificates*), so the browser never sees an origin's real chain.

If you **Regenerate CA** while the browser is open, the Browser page asks you to restart it so the new pin applies.

### Manual fallback

Some managed Chromium installations ignore command-line switches through enterprise policy. In that case HTTPS pages show certificate errors. Do not disable certificate checks; instead:

1. **Proxy → Export CA** to save the public certificate.
2. Import it as a trusted certificate authority in a dedicated browser profile or a disposable virtual machine (for Firefox: *Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import*, which affects only that Firefox profile).
3. Configure that browser to use the Ferrite listener as its HTTP and HTTPS proxy.

## Profiles

- **Temporary** (default): a new profile in the system temporary directory for each launch, deleted when the browser exits. If Ferrite is killed before it can clean up, the next launch removes stale Ferrite profiles that no browser is using.
- **Persistent**: keeps cookies and sessions across launches. The default location is `<local data directory>/ferrite/browser-profile` (for example `~/.local/share/ferrite/browser-profile` on Linux). Ferrite only adopts an empty directory or one it created (marked with `.ferrite-browser-profile`), so a personal browser profile can never be reused by mistake. **Reset profile…** deletes it, and is refused while a browser is using it.

## Settings

Browser settings are application-wide (stored with the theme and CA in Ferrite's settings file), not per project:

| Setting | Notes |
| --- | --- |
| Executable | Empty detects automatically. **Detected** lists installations; `FERRITE_BROWSER=/path` takes precedence for detection. On macOS the `.app` bundle can be chosen |
| Profile | Temporary or persistent, with an optional directory |
| Proxy | Empty follows the running Ferrite listener (wildcard binds use loopback). `host:port` routes elsewhere |
| Start URL | `about:blank`, or an `http(s)` URL |
| Extra arguments | One `--switch[=value]` per line, for example `--lang=en-AU` or `--window-size=1400,900` |
| DevTools controls | Lets the Browser page list, open, navigate and close tabs, and close the browser gracefully |

Changes apply to the next launch.

## Lifecycle

- Ferrite captures the browser's standard error (bounded) and reports unexpected exits with the last lines in **Alerts** and on the Browser page.
- If Chromium exits immediately with success, another instance already owned the profile and received the launch; Ferrite reports this instead of assuming the browser is proxied.
- If the listener stops or moves, or the CA changes, the Browser page and the Proxy page flag that the browser needs a restart. **Restart** relaunches with the current listener, CA and settings.
- **Close** uses the DevTools `Browser.close` command so Chromium can flush a persistent profile, escalating to termination after five seconds. Exiting Ferrite closes the browser the same way.
- On Linux the browser is also tied to Ferrite with a parent-death signal, so it exits even if Ferrite is killed. On macOS and Windows a browser can outlive a Ferrite process that is force-killed; close it manually in that case.

## DevTools security

The DevTools endpoint listens on a random loopback port. Ferrite connects without an `Origin` header and never sets `--remote-allow-origins`, so web pages cannot use the endpoint. Local processes running as your user could connect to it, as they could read the profile directory directly. Disable **DevTools controls** if that is a concern; the browser keeps working and only the in-Ferrite tab controls are unavailable.

## Why not an embedded viewport?

Embedding Chromium inside the egui window was evaluated and deferred:

- **CEF** requires shipping a ~200 MB per-platform runtime, a multi-process helper executable, off-screen rendering into textures, and manual input/IME/clipboard forwarding. There is no maintained Rust binding that integrates with egui, and it would bind Ferrite's release cadence to Chromium security updates.
- **Platform webviews** (WebView2, WKWebView, WebKitGTK via `wry`) are different engines per platform, cannot share Ferrite's proxy and CA configuration uniformly (WebKitGTK and WKWebView proxy/CA control is limited), and need a native child window that egui/wgpu does not manage.
- **Screenshot streaming** over DevTools (`Page.startScreencast`) could render a view inside Ferrite, but input fidelity (text entry, IME, drag and drop, file pickers, authentication prompts) would be poor.

A managed external process gives a fully featured browser on all three platforms with no new dependencies. The Browser page provides the in-Ferrite controls that are reliable over DevTools.

## Platform notes

| Platform | Detection | Notes |
| --- | --- | --- |
| Linux | `PATH` (`chromium`, `chromium-browser`, `google-chrome`, `google-chrome-stable`, `microsoft-edge`, `brave-browser`), `/opt/google/chrome`, `/snap/bin/chromium` | Verified end to end with Chrome for Testing 153. Snap Chromium cannot read hidden directories under your home, so persistent profiles must use a non-hidden directory. Chromium refuses to run as root without `--no-sandbox`; add it only inside disposable containers |
| macOS | `/Applications` and `~/Applications` (Chrome, Chromium, Chrome for Testing, Edge, Brave, Canary) | Compiled and unit-tested in CI; not exercised against a real browser in this change |
| Windows | `Program Files`, `Program Files (x86)` and `%LOCALAPPDATA%` (Chrome, Chromium, Edge, Brave) | Compiled and unit-tested in CI; not exercised against a real browser in this change |

## Testing

`tests/browser.rs` launches a real browser in headless mode against a live Ferrite listener and checks HTTPS interception without certificate errors, JavaScript, redirects, cookies, multiple tabs, loopback proxying, IP-literal HTTPS, history capture, graceful close, temporary profile deletion and the mismatched-pin negative control. It needs a browser, so it runs only when requested:

```sh
FERRITE_BROWSER_TESTS=1 cargo test --test browser
FERRITE_BROWSER_TESTS=1 FERRITE_BROWSER=/path/to/chrome cargo test --test browser
```

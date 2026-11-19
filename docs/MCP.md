# MCP server

Ferrite includes a native [Model Context Protocol](https://modelcontextprotocol.io) server, so compatible MCP clients, agents and harnesses can inspect Ferrite's live project and send requests through its engine. Results appear in the client; traffic, Repeater tabs and an audit trail appear in Ferrite.

The server exposes tools only. It contains no LLM integration, makes no decisions for the client, and sends nothing anywhere on its own.

## Quick start

1. Start Ferrite and open **MCP** in the sidebar.
2. Select **Enable MCP server**. **Listen interface** defaults to **Loopback only (127.0.0.1)**.
3. Select **Connect an AI agent → This machine**. Use the displayed stdio configuration. Set the command to the full path to the Ferrite executable and the arguments to `mcp`.

   For clients that use an `mcpServers` JSON object, the configuration looks like this (see [examples/mcp.json](examples/mcp.json)):

   ```json
   {
     "mcpServers": {
       "ferrite": { "command": "/path/to/ferrite", "args": ["mcp"] }
     }
   }
   ```

   Configuration formats and file locations differ between clients. On Windows, use the path to `ferrite.exe` and escape backslashes in JSON. The client launches `ferrite mcp` as a subprocess.
4. Start or reconnect the client. Connected agents appear on Ferrite's MCP page.
5. Use the client's tool interface or ask its agent, for example:
   - "Using Ferrite, summarise the in-scope endpoints and which take parameters."
   - "Show me the last POST to /login in Ferrite and resend it with the username changed to bob."
   - "Search Ferrite's history for responses that contain stack traces."

Ferrite records sent requests in History with the tool `MCP` and lists the calls in the **Audit trail**. **Send HTTP requests** defaults to **Allow** in new GUI settings. Choose **Ask each time** to require approval. Saved settings retain their selected permission.

## Connect from another machine

1. Under **Listen interface**, choose an address the agent can reach, such as the IP of a private VPN interface. **Port** defaults to `8765`. Select **Apply** to save the address and port. If MCP is already enabled, this restarts the network listener. Turn on **Enable MCP server** and keep Ferrite open. The status shows the Streamable HTTP URL ending in `/mcp`.
2. Select **Connect an AI agent → Another machine**. Copy the URL and bearer token into a Streamable HTTP server entry in your MCP client. Adapt the configuration to your client and replace `YOUR_TOKEN` with the copied token. The example address and port below stand in for the values in Ferrite.

   ```json
   {
     "mcpServers": {
       "ferrite": {
         "type": "http",
         "url": "http://192.168.1.10:8765/mcp",
         "headers": { "Authorization": "Bearer YOUR_TOKEN" }
       }
     }
   }
   ```

3. Start or reconnect the client. Network clients can inspect the live project, use Repeater, send in-scope requests and cancel active scans under the respective MCP permissions. Stdio also provides `start_active_scan`. Ferrite saves the port and issues a new bearer token each time the network listener starts. Copy the new token into your client after a restart.

The built-in HTTP listener sends the token and project data in plaintext. Use an encrypted private network or terminate HTTPS at a reverse proxy. For a reverse proxy, use the HTTPS URL in the client and forward `/mcp` and the `Authorization` header to Ferrite. Set the upstream `Host` header to the IP and port shown in Ferrite and disable response buffering for event streams. If a host firewall blocks the connection, allow the displayed TCP port from the agent's address.

On Windows, allow Ferrite on your private network if Windows displays a firewall prompt. The active profile, notification settings and existing rules determine whether Windows shows the automatic prompt. [Windows Firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)

### SSH with stdio

Select **Connect an AI agent → SSH** to run the stdio relay remotely. **Loopback only** works for SSH because the relay runs on the Ferrite machine. Install SSH on the agent's machine and configure the Ferrite host for non-interactive authentication with a trusted host key. Log in as the user running Ferrite, with access to the same Ferrite configuration directory.

For a Ferrite host using a POSIX login shell:

```json
{
  "mcpServers": {
    "ferrite": {
      "command": "ssh",
      "args": ["-T", "-o", "BatchMode=yes", "USER@FERRITE_HOST", "'/path/to/ferrite' mcp"]
    }
  }
}
```

Use the SSH username and address for the Ferrite machine and the executable path shown on the MCP page. On a Windows SSH host, quote the executable path for its configured login shell.

## Architecture

```mermaid
flowchart LR
    C[MCP client / agent / harness] -- stdio JSON-RPC --> R["ferrite mcp (relay)"]
    R -- loopback TCP + 256-bit token --> H[MCP host in the Ferrite window]
    C -- Streamable HTTP + bearer token --> H
    H --> T[Tool executor]
    T --> E[Engine: routing, upstream proxy, TLS, scope]
    T --> P[(Project: history, Repeater, findings, WebSockets, audit)]
    E --> O[In-scope origin]
    H -. approvals .-> U[Ferrite user]
```

- **Protocol**: the official Rust SDK [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk) handles JSON-RPC, protocol version negotiation (2024-11-05 through 2026-07-28), `ping` and cancellation. Ferrite implements `tools/list` and `tools/call`.
- **Relay (`ferrite mcp`)**: the process the MCP client launches. It never opens the project database. It reads the endpoint file, authenticates to the running Ferrite window and forwards tool calls. If Ferrite is not running, tools return a clear error and the relay reconnects on the next call, so Ferrite can be started after the client.
- **Bridge**: the Ferrite window listens on a random `127.0.0.1` port and writes `{address, token, pid}` to `mcp-endpoint.json` in Ferrite's configuration directory (`<config dir>/ferrite`, or `FERRITE_CONFIG_DIR`) (mode `0600` on Unix; per-user `%APPDATA%` on Windows). The relay must present the 256-bit token, compared in constant time. Messages are newline-delimited JSON with size limits. The file is removed when MCP is disabled or Ferrite exits. A second Ferrite instance refuses to take over a live endpoint.
- **Streamable HTTP** binds the selected interface address and saved port to serve `/mcp`. It uses a separate 256-bit bearer token, validates the `Host` header and rejects browser requests carrying an `Origin` header.
- **Host**: tools always target the project currently open in the window, including after you switch projects. Long reads (history scans, searches, site maps) run on blocking threads with a lock-free snapshot reader, so they never stall proxy recording or the UI.
- **Headless mode**: `ferrite mcp --headless --project FILE` runs the engine without a window and serves MCP on stdio directly. redb locks the project file, so the GUI and a headless server can never open the same project at once.

## Security model

| Control | Behaviour |
| --- | --- |
| Opt-in | Disabled until enabled on the MCP page. The setting is application-wide |
| Network exposure | The stdio bridge binds `127.0.0.1` and authenticates with the token from the user-only endpoint file. The optional Streamable HTTP endpoint binds the selected interface address and requires its own bearer token on every request |
| Scope | `send_http_request` and `start_active_scan` refuse URLs outside the target scope, regardless of **Drop out of scope messages**. The check runs inside the engine against the same settings snapshot as the send, and absolute-form request lines must match the target origin. Only the Ferrite user can change scope |
| Permissions | In new GUI settings, **Send HTTP requests** defaults to *Allow* and **Active scans** defaults to *Deny*. Each can be *Deny*, *Ask each time* or *Allow*. Approvals offer *Allow once*, *Allow for this session* (revoked when MCP is disabled or Ferrite exits) and *Deny*. Unanswered requests are denied after two minutes |
| Rate limits | 60 requests per minute and 4 concurrent requests by default (configurable). Each connection is limited to 8 concurrent tool calls; calls time out after five minutes; large reads are paged |
| Credentials | Values of `Cookie`, `Set-Cookie`, `Authorization`, `Proxy-Authorization`, API key and session/CSRF token headers are returned as `[REDACTED]` unless the user enables **Return Cookie, Authorization and similar header values**. A client can keep `[REDACTED]` in a request sent with `tab_id` or `base_exchange_id`, and Ferrite substitutes the original value locally. Bodies are not redacted |
| Secrets never exposed | Upstream proxy credentials, the CA private key and Ferrite's settings are never returned |
| Untrusted data | Server instructions, tool descriptions and a `notice` field on every result that carries captured content tell the client that captured traffic is data, not instructions |
| Audit | Every call is stored in the project's `mcp_audit` table: time, client, tool, a brief argument summary (request bodies are never stored), outcome, duration and created exchange IDs. The MCP page shows recent entries |
| Headless | No window means no approvals: *Ask* behaves as *Deny*. Use `--allow-requests` / `--allow-active-scans` to pre-authorise, still limited to scope |

Captured traffic returned to a client may be sent by that client to its model provider. Enable MCP only for projects where that is acceptable.

## Tools

All tools return JSON as text content (and as `structuredContent`). Errors are tool errors (`isError: true`) with an `error` message. Unknown arguments are rejected.

### Project and scope

| Tool | Arguments | Returns |
| --- | --- | --- |
| `get_project_info` | – | Name, path, storage, counts of exchanges/WebSocket sessions/findings/scans/Repeater tabs, CA fingerprint, version, MCP mode and permissions |
| `get_proxy_status` | – | Listener state and address, interception state, pending interceptions, invisible mode, upstream kind/host/port (no credentials), TLS verification, timeouts and limits |
| `get_scope` | – | Include/exclude regular expressions and scope options |
| `is_url_in_scope` | `url` | `in_scope` with the patterns that matched |

### HTTP history

| Tool | Arguments | Returns |
| --- | --- | --- |
| `list_http_history` | Filters: `host`, `method`, `status` (`404` or `"4xx"`), `mime`, `tool`, `url_contains`, `in_scope_only`, `has_error`; `limit` (≤200), `cursor` | Summaries newest first (ID, time, tool, method, URL, status, MIME, sizes, duration, scope, error) and `next_cursor` |
| `get_http_request` / `get_http_response` | `id`, `format` (`parsed` or `raw`), `offset`, `max_bytes` (≤1 MiB, default 64 KiB), `encoding` (`auto`, `text`, `base64`) | Start line, headers and a body chunk (or the raw message chunk) |
| `search_http_history` | `query`, `regex`, `case_sensitive`, `part` (`all`, `url`, `request`, `response`), `context_bytes`, filters, `limit`, `cursor` | Matching summaries with up to three snippets each |

**Byte fidelity.** Stored message bytes are returned unchanged except for header redaction. A chunk is `{"encoding": "utf-8" | "base64" | "utf-8-lossy", "data", "offset", "length", "total_length", "truncated"}`. With `auto`, printable UTF-8 is returned as text (a page boundary inside a multi-byte character shortens the page rather than corrupting it) and anything else as base64. Page through large bodies with `offset`. Ferrite stores responses after decoding gzip/deflate content encodings, as shown in History.

Each call examines at most 50,000 exchanges (searches also stop after 256 MiB); continue with `next_cursor`.

### Site map

| Tool | Arguments | Returns |
| --- | --- | --- |
| `get_site_map` | `host`, `in_scope_only`, `max_depth` (default 8), `max_nodes` (default 1000) | Origins with nested path segments, counts, methods and status codes |
| `list_hosts` | `in_scope_only` | Origins with counts, status classes, scope, first and last seen |
| `list_endpoints` | `host`, `in_scope_only`, `limit`, `cursor` | Method + path combinations with counts, statuses, response types, query and form/JSON body parameter names |

### Repeater

| Tool | Arguments | Returns |
| --- | --- | --- |
| `send_to_repeater` | `exchange_id`, or `request` + `target`; optional `name`, `group` (default `MCP`) | `tab_id`. The tab appears in Ferrite's Repeater immediately. No traffic is sent |
| `list_repeater_tabs` | – | Tabs with ID, name, collection, target, request line and send history |
| `get_repeater_request` | `tab_id` | The tab's current request (credential headers redacted unless allowed) |
| `send_http_request` | `request` (text, LF or CRLF) or `request_base64`; `target` (origin URL); `tab_id`; `base_exchange_id`; `max_response_bytes` | `exchange_id`, URL, status, duration, error and the parsed response |

`send_http_request` uses Ferrite's normal engine path: DNS overrides, upstream HTTP/SOCKS proxy, outbound TLS settings, HTTP/2 negotiation, message limits, timeouts, history recording and passive scanning. Content-Length is recalculated. Match-and-replace rules and interception do not apply (as for Repeater). With `tab_id`, the result is added to the tab's history, and a supplied request replaces the tab's text, so you can follow along in the Repeater page.

### Scanner

| Tool | Arguments | Returns |
| --- | --- | --- |
| `list_scanner_findings` | `min_severity`, `confidence`, `state`, `url_contains`, `offset`, `limit` | Finding summaries |
| `get_scanner_finding` | `id`, `max_evidence_bytes` (default 8 KiB) | Description, remediation, notes and up to 20 evidence exchanges |
| `get_scan_status` | `scan_id` | Jobs with progress counters and live scanner resource use |
| `start_active_scan` | `exchange_ids` (1–50, all in scope) | `scan_id`. Available over stdio with the active scan permission. Uses the project's scanner configuration, including whether intrusive checks are enabled |
| `cancel_scan` | `scan_id` | Requires the active scan permission |

### WebSockets

| Tool | Arguments | Returns |
| --- | --- | --- |
| `list_websocket_sessions` | `url_contains`, `state`, `offset`, `limit` | Sessions (the session ID is the handshake's exchange ID) |
| `get_websocket_messages` | `session_id`, `after_sequence`, `direction`, `limit`, `max_bytes` | Messages in order with original and, if edited, forwarded payloads |

## Headless mode

```sh
ferrite mcp --headless --project assessment.ferrite
ferrite mcp --headless --project assessment.ferrite --start-proxy --listen 127.0.0.1:8080 --allow-requests
```

| Flag | Effect |
| --- | --- |
| `--project FILE` | Open or create a project and own it exclusively (default: temporary in-memory project) |
| `--start-proxy`, `--listen IP:PORT` | Also run the proxy listener so traffic can be captured while the client works |
| `--allow-requests` | Allow `send_http_request` without approval (still scope-limited) |
| `--allow-active-scans` | Allow starting and cancelling active scans |
| `--include-credentials` | Return credential header values |

Example JSON configuration for a headless project (adapt it to your client's format):

```json
{
  "mcpServers": {
    "ferrite-headless": {
      "command": "/path/to/ferrite",
      "args": ["mcp", "--headless", "--project", "/path/to/assessment.ferrite"]
    }
  }
}
```

Set scope in the GUI before handing a project to a headless server: a new project's scope is empty, which matches nothing.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Tools return "Ferrite is not reachable" | Start Ferrite and enable the MCP server. The error names the endpoint file the relay looked for. Use `ferrite mcp --endpoint-file PATH` or `FERRITE_MCP_ENDPOINT` if you changed its location |
| "Another Ferrite instance is already serving MCP" | Disable MCP in the other window first |
| "Could not bind MCP to …" | Check that the interface still has the selected address. If the port is in use, choose another port and select **Apply**. Select **Retry** after the address and port are available |
| Network MCP returns HTTP 401 | Copy the current bearer token and set `Authorization: Bearer YOUR_TOKEN` in the client |
| Network MCP returns HTTP 403 | Use the exact IP and port shown in Ferrite. With a reverse proxy, set the upstream `Host` header to that IP and port |
| "outside the target scope" | Add the target in **Target** |
| "disabled for MCP clients" / "denied" | Change the permission on the MCP page, or approve the prompt |
| Headless start fails to open the project | Close the project in the Ferrite window first |

## Testing

Run the project's tests with `cargo test --all-targets`. MCP unit tests cover the server's tool definitions, permissions, redaction and local relay behavior.

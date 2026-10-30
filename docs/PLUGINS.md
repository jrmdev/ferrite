# Extensibility design

Status: investigation and proposal. Ferrite does not load third-party code yet. This document records the options considered, the recommended architecture, and the constraints any implementation must meet.

## What extensions need to do

Ranked by demand from Burp-style workflows:

1. **Passive checks**: inspect a completed exchange and report findings.
2. **Message transforms**: Decoder steps, custom encodings, request signing.
3. **Message viewers**: render a body (for example protobuf, a custom binary protocol) as text.
4. **Active checks and request rewriting**: generate probes, sign or re-sign requests before sending.
5. **Automation**: drive Ferrite from outside (scripts, CI, AI agents).

Automation (5) is already possible without loading code into Ferrite: the [MCP server](MCP.md) exposes history, Repeater, scanner and WebSocket data and in-scope request sending to any MCP client, with permissions, scope enforcement and an audit trail. External tools should use it rather than a plugin API.

## Requirements

- **Isolation**: a plugin cannot read files, open sockets, see other plugins' data, or read the CA key unless granted.
- **Capabilities, not trust**: each plugin declares what it needs (for example "read in-scope exchanges", "send in-scope requests"), the user approves, and the host enforces it. Network access, if granted, must go through the engine so scope, rate limits and history recording apply, as for MCP.
- **Stability**: a misbehaving plugin cannot crash, hang or exhaust Ferrite's memory. Execution is bounded by CPU fuel/time and memory limits, and failures disable the plugin with an alert.
- **Portability**: the same plugin binary runs on Linux, macOS and Windows with no toolchain on the user's machine.
- **Small footprint**: no cost when no plugins are installed, consistent with Ferrite's lightweight design.
- **Versioned interface**: plugins target a versioned API so Ferrite can evolve without breaking them.

## Options evaluated

| Option | Isolation | Stability | Portability | Cost | Verdict |
| --- | --- | --- | --- | --- | --- |
| Native dynamic libraries (`dlopen`, Rust ABI or C ABI) | None: full process access | A crash takes Ferrite down; Rust has no stable ABI | One build per OS and architecture | Small | Rejected |
| Embedded scripting (Rhai, Lua via `mlua`) | Good for Rhai (no I/O by default); Lua needs a careful sandbox | Needs operation limits; Lua is C code | Portable source | Small to moderate | Viable for simple transforms, weak typing for binary protocols |
| WebAssembly with **wasmtime** and the Component Model (WIT) | Strong: memory-safe sandbox, no ambient I/O, capability-based imports | Fuel or epoch interruption and memory limits per call; traps are recoverable | One `.wasm` runs everywhere; authors can use Rust, Go, C, JS, Python | Larger binary (roughly 10–20 MB) and compile time; can be an optional Cargo feature | **Recommended** |
| WebAssembly with **wasmi** (interpreter) | Strong | Fuel metering built in | Portable | Small, pure Rust | Good fallback for small transforms; too slow for heavy checks |
| Out-of-process plugins over JSON-RPC/MCP | Process boundary; OS sandboxing varies by platform | Crash-isolated | Plugin authors ship per-OS binaries | Moderate | Already covered for automation by MCP |

## Recommended architecture

1. **Internal extension points first.** Define Rust traits inside Ferrite for the hooks above and move built-in features onto them. The scanner's check registry, the Decoder's `Transform` list (`src/decoder.rs`) and the response preview pipeline are the natural seams. This gives a tested, versionable surface before any third-party code runs.
2. **WebAssembly components behind an optional `plugins` feature**, hosted with wasmtime:
   - A WIT world per capability, for example:

     ```wit
     package ferrite:plugin@0.1.0;

     interface types {
       record message { start-line: string, headers: list<tuple<string, string>>, body: list<u8> }
       record exchange { id: u64, url: string, method: string, request: message, response: option<message> }
       enum severity { information, low, medium, high }
       record finding { issue-id: string, title: string, severity: severity, detail: string }
     }

     world passive-check {
       use types.{exchange, finding};
       export analyse: func(exchange: exchange) -> list<finding>;
     }

     world transform {
       export name: func() -> string;
       export apply: func(input: list<u8>) -> result<list<u8>, string>;
     }
     ```

   - The host grants no WASI filesystem or network access. A future "send-request" import would call `Engine::execute_in_scope` with the same permission prompts, rate limits and audit trail as MCP.
   - Each call runs with fuel (or epoch) limits, a memory cap and a wall-clock timeout. Inputs are bounded by the project's message limit. A plugin that traps or times out repeatedly is disabled and reported in **Alerts**.
   - A manifest (`plugin.toml`) names the plugin, its WIT world and version, and its requested capabilities. The **Plugins** page shows them before enabling, and hashes the `.wasm` so a changed file needs re-approval.
   - Passive-check plugins run on the existing bounded passive-analysis queue, so they cannot slow the proxy.
3. **No in-process scripting of arbitrary languages** until the above exists, to avoid two plugin systems with different security properties.

## Not planned

- Loading native libraries.
- Plugins with direct socket or filesystem access.
- Plugins that bypass scope or interception.

## Today

- Use the MCP server for automation and AI-assisted workflows.
- Built-in Decoder steps and scanner checks are the internal extension points that a plugin API would generalise.

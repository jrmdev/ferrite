//! Minimal Chrome DevTools Protocol client for the managed browser.
//!
//! Only loopback endpoints announced by the managed process are contacted.
//! The handshake sends no Origin header, which Chromium requires for
//! DevTools clients unless `--remote-allow-origins` is set (Ferrite never
//! sets it), so web pages cannot drive the browser.
use crate::http::{Message, read_message};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use fastwebsockets::{FragmentCollector, Frame, OpCode, Payload, Role, WebSocket};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
};

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_MESSAGE: usize = 8 * 1024 * 1024;

/// The loopback socket address of a `ws://` DevTools URL.
pub fn endpoint(url: &str) -> Result<SocketAddr> {
    let url = url::Url::parse(url).context("Invalid DevTools URL")?;
    ensure!(url.scheme() == "ws", "DevTools URL must use ws://");
    let address: SocketAddr = format!(
        "{}:{}",
        url.host_str().context("DevTools URL has no host")?,
        url.port().context("DevTools URL has no port")?
    )
    .parse()
    .context("DevTools must listen on an IP address")?;
    ensure!(
        address.ip().is_loopback(),
        "DevTools endpoint must be loopback"
    );
    Ok(address)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub target_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub url: String,
}

fn valid_id(id: &str) -> Result<&str> {
    ensure!(
        !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric()),
        "Invalid DevTools target ID"
    );
    Ok(id)
}

/// One DevTools WebSocket connection.
pub struct Session {
    socket: FragmentCollector<TcpStream>,
    next: u64,
}

impl Session {
    pub async fn connect(url: &str) -> Result<Self> {
        let address = endpoint(url)?;
        let parsed = url::Url::parse(url)?;
        let path = parsed.path();
        ensure!(
            path.starts_with("/devtools/") && path.bytes().all(|b| b.is_ascii_graphic()),
            "Invalid DevTools path"
        );
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let key = base64::engine::general_purpose::STANDARD.encode(nonce);
        let mut tcp = tokio::time::timeout(TIMEOUT, TcpStream::connect(address))
            .await
            .context("DevTools connection timed out")??;
        tcp.set_nodelay(true)?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        tcp.write_all(request.as_bytes()).await?;
        // Single-byte buffering leaves any early frame bytes in the socket.
        let mut reader = BufReader::with_capacity(1, tcp);
        let response: Message =
            tokio::time::timeout(TIMEOUT, read_message(&mut reader, true, true, 64 * 1024))
                .await
                .context("DevTools handshake timed out")??;
        ensure!(
            response.status() == 101,
            "DevTools refused the connection: {}",
            response.start
        );
        let expected = base64::engine::general_purpose::STANDARD.encode(Sha1::digest(format!(
            "{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        )));
        ensure!(
            response.header("Sec-WebSocket-Accept") == Some(expected.as_str()),
            "Invalid DevTools handshake"
        );
        let mut socket = WebSocket::after_handshake(reader.into_inner(), Role::Client);
        socket.set_max_message_size(MAX_MESSAGE);
        socket.set_auto_pong(true);
        socket.set_auto_close(true);
        Ok(Self {
            socket: FragmentCollector::new(socket),
            next: 1,
        })
    }

    /// Send one command and wait for its reply, ignoring protocol events.
    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next;
        self.next += 1;
        let body = serde_json::to_vec(&json!({"id": id, "method": method, "params": params}))?;
        tokio::time::timeout(TIMEOUT, async {
            self.socket
                .write_frame(Frame::text(Payload::Owned(body)))
                .await?;
            loop {
                let frame = self.socket.read_frame().await?;
                match frame.opcode {
                    OpCode::Text => {
                        let message: Value = serde_json::from_slice(&frame.payload)?;
                        if message.get("id").and_then(Value::as_u64) != Some(id) {
                            continue;
                        }
                        if let Some(error) = message.get("error") {
                            bail!(
                                "{method} failed: {}",
                                error
                                    .get("message")
                                    .and_then(Value::as_str)
                                    .unwrap_or("unknown DevTools error")
                            );
                        }
                        return Ok(message.get("result").cloned().unwrap_or(Value::Null));
                    }
                    OpCode::Close => bail!("DevTools connection closed"),
                    _ => {}
                }
            }
        })
        .await
        .with_context(|| format!("{method} timed out"))?
    }
}

/// Run a single command on a fresh connection.
pub async fn call(url: &str, method: &str, params: Value) -> Result<Value> {
    Session::connect(url).await?.call(method, params).await
}

fn page_url(browser: &str, id: &str) -> Result<String> {
    let address = endpoint(browser)?;
    Ok(format!("ws://{address}/devtools/page/{}", valid_id(id)?))
}

/// Open page tabs, in the browser's order.
pub async fn pages(browser: &str) -> Result<Vec<Target>> {
    let result = call(browser, "Target.getTargets", json!({})).await?;
    let targets: Vec<Target> = serde_json::from_value(
        result
            .get("targetInfos")
            .cloned()
            .context("Missing targetInfos")?,
    )?;
    Ok(targets.into_iter().filter(|t| t.kind == "page").collect())
}

pub async fn open(browser: &str, url: &str) -> Result<String> {
    let result = call(browser, "Target.createTarget", json!({"url": url})).await?;
    Ok(result
        .get("targetId")
        .and_then(Value::as_str)
        .context("Missing targetId")?
        .to_owned())
}

pub async fn activate(browser: &str, id: &str) -> Result<()> {
    call(
        browser,
        "Target.activateTarget",
        json!({"targetId": valid_id(id)?}),
    )
    .await?;
    Ok(())
}

pub async fn close_tab(browser: &str, id: &str) -> Result<()> {
    call(
        browser,
        "Target.closeTarget",
        json!({"targetId": valid_id(id)?}),
    )
    .await?;
    Ok(())
}

pub async fn navigate(browser: &str, id: &str, url: &str) -> Result<()> {
    let result = call(
        &page_url(browser, id)?,
        "Page.navigate",
        json!({"url": url}),
    )
    .await?;
    if let Some(error) = result.get("errorText").and_then(Value::as_str) {
        bail!("Navigation failed: {error}");
    }
    Ok(())
}

pub async fn reload(browser: &str, id: &str) -> Result<()> {
    call(&page_url(browser, id)?, "Page.reload", json!({})).await?;
    Ok(())
}

/// Move through the tab's history by `delta` entries (-1 back, 1 forward).
pub async fn go(browser: &str, id: &str, delta: i64) -> Result<()> {
    let mut session = Session::connect(&page_url(browser, id)?).await?;
    let history = session.call("Page.getNavigationHistory", json!({})).await?;
    let current = history
        .get("currentIndex")
        .and_then(Value::as_i64)
        .context("Missing currentIndex")?;
    let entries = history
        .get("entries")
        .and_then(Value::as_array)
        .context("Missing entries")?;
    let index = current + delta;
    let Some(entry) = usize::try_from(index).ok().and_then(|i| entries.get(i)) else {
        return Ok(());
    };
    session
        .call(
            "Page.navigateToHistoryEntry",
            json!({"entryId": entry.get("id").cloned().unwrap_or(Value::Null)}),
        )
        .await?;
    Ok(())
}

/// Evaluate an expression in a tab and return its JSON value.
pub async fn evaluate(browser: &str, id: &str, expression: &str) -> Result<Value> {
    let result = call(
        &page_url(browser, id)?,
        "Runtime.evaluate",
        json!({"expression": expression, "returnByValue": true, "awaitPromise": true}),
    )
    .await?;
    if let Some(details) = result.get("exceptionDetails") {
        bail!("Evaluation failed: {details}");
    }
    Ok(result
        .get("result")
        .and_then(|r| r.get("value"))
        .cloned()
        .unwrap_or(Value::Null))
}

/// Ask the browser to close all windows and exit, flushing its profile.
pub async fn close_browser(browser: &str) -> Result<()> {
    let mut session = Session::connect(browser).await?;
    // The browser may close the socket before replying.
    match session.call("Browser.close", json!({})).await {
        Ok(_) => Ok(()),
        Err(error) if format!("{error:#}").contains("closed") => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_and_targets_are_restricted() {
        assert_eq!(
            endpoint("ws://127.0.0.1:9222/devtools/browser/abc").unwrap(),
            "127.0.0.1:9222".parse().unwrap()
        );
        assert!(endpoint("ws://[::1]:9222/devtools/browser/abc").is_ok());
        assert!(endpoint("ws://192.0.2.1:9222/devtools/browser/abc").is_err());
        assert!(endpoint("ws://localhost:9222/devtools/browser/abc").is_err());
        assert!(endpoint("wss://127.0.0.1:9222/devtools/browser/abc").is_err());
        assert_eq!(
            page_url("ws://127.0.0.1:9/devtools/browser/x", "AB12").unwrap(),
            "ws://127.0.0.1:9/devtools/page/AB12"
        );
        assert!(page_url("ws://127.0.0.1:9/devtools/browser/x", "../x").is_err());
    }

    #[tokio::test]
    async fn session_matches_replies_and_skips_events() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::with_capacity(1, tcp);
            let request = read_message(&mut reader, false, false, 65536)
                .await
                .unwrap();
            assert!(request.header("Origin").is_none());
            let key = request.header("Sec-WebSocket-Key").unwrap();
            let accept = base64::engine::general_purpose::STANDARD.encode(Sha1::digest(format!(
                "{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            )));
            let mut tcp = reader.into_inner();
            tcp.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await.unwrap();
            let mut ws = FragmentCollector::new(WebSocket::after_handshake(tcp, Role::Server));
            let frame = ws.read_frame().await.unwrap();
            let call: Value = serde_json::from_slice(&frame.payload).unwrap();
            assert_eq!(call["method"], "Target.getTargets");
            for reply in [
                json!({"method": "Target.targetCreated", "params": {}}),
                json!({"id": call["id"], "result": {"targetInfos": [
                    {"targetId": "A1", "type": "page", "title": "One", "url": "https://a.test/"},
                    {"targetId": "B2", "type": "service_worker", "title": "", "url": ""}
                ]}}),
            ] {
                ws.write_frame(Frame::text(Payload::Owned(
                    serde_json::to_vec(&reply).unwrap(),
                )))
                .await
                .unwrap();
            }
        });
        let pages = pages(&format!("ws://{address}/devtools/browser/test"))
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].target_id, "A1");
        assert_eq!(pages[0].url, "https://a.test/");
    }
}

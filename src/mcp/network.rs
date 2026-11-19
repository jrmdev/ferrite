//! Authenticated Streamable HTTP endpoint for remote MCP clients.
use super::{
    host::Host,
    server::{FerriteServer, LocalBackend},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    extract::Request,
    middleware::{self, Next},
    response::IntoResponse,
};
use http::{StatusCode, header};
use rand_core::RngCore;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, runtime::Handle, task::JoinHandle};
use tokio_util::sync::CancellationToken;

pub struct NetworkServer {
    address: SocketAddr,
    token: String,
    shutdown: CancellationToken,
    task: JoinHandle<()>,
}

impl NetworkServer {
    pub fn start(host: Arc<Host>, address: SocketAddr, runtime: &Handle) -> Result<Self> {
        ensure!(
            is_network_address(address.ip()),
            "Select a unicast network interface address"
        );
        Self::bind(host, address, runtime)
    }

    fn bind(host: Arc<Host>, address: SocketAddr, runtime: &Handle) -> Result<Self> {
        ensure!(address.port() != 0, "MCP listen port must be 1..65535");
        let listener = std::net::TcpListener::bind(address)
            .with_context(|| format!("Could not bind MCP to {address}"))?;
        listener.set_nonblocking(true)?;
        let listener = {
            let _entered = runtime.enter();
            TcpListener::from_std(listener)?
        };

        let mut secret = [0u8; 32];
        rand_core::OsRng.try_fill_bytes(&mut secret)?;
        let token: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
        let shutdown = CancellationToken::new();
        let router = router(host.clone(), address, &token, shutdown.clone());
        let stopped = shutdown.clone();
        let task = runtime.spawn(async move {
            if let Err(error) = axum::serve(listener, router)
                .with_graceful_shutdown(stopped.cancelled_owned())
                .await
            {
                host.engine()
                    .log_error(format!("MCP HTTP listener: {error:#}"));
            }
        });
        Ok(Self {
            address,
            token,
            shutdown,
            task,
        })
    }

    pub fn url(&self) -> String {
        format!("http://{}/mcp", self.address)
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub async fn stop(mut self) {
        self.shutdown.cancel();
        // Release the socket before the GUI tries to bind the same port again.
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for NetworkServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}

pub fn interface_addresses() -> std::io::Result<Vec<(String, IpAddr)>> {
    let mut addresses: Vec<_> = if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|interface| {
            let ip = interface.ip();
            is_network_address(ip).then_some((interface.name, ip))
        })
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    Ok(addresses)
}

fn is_network_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
                && ip.to_ipv4_mapped().is_none()
        }
    }
}

fn router(
    host: Arc<Host>,
    address: SocketAddr,
    token: &str,
    shutdown: CancellationToken,
) -> Router {
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts([address.to_string()])
        .enforce_origin_validation()
        .with_json_response(true)
        .with_cancellation_token(shutdown.clone());
    let service = StreamableHttpService::new(
        move || {
            Ok(FerriteServer::network(LocalBackend::with_transport(
                host.clone(),
                "Streamable HTTP",
            )))
        },
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let expected: Arc<str> = format!("Bearer {token}").into();
    Router::new()
        .route_service("/mcp", service)
        .route_layer(middleware::from_fn(move |request: Request, next: Next| {
            let expected = expected.clone();
            let shutdown = shutdown.clone();
            async move {
                let authenticated = request
                    .headers()
                    .get(header::AUTHORIZATION)
                    .is_some_and(|value| bool::from(value.as_bytes().ct_eq(expected.as_bytes())));
                if !authenticated {
                    return (
                        StatusCode::UNAUTHORIZED,
                        [(header::WWW_AUTHENTICATE, "Bearer")],
                    )
                        .into_response();
                }
                if shutdown.is_cancelled() {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                next.run(request).await
            }
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::Engine,
        mcp::{McpSettings, host::HostMode},
        project::Project,
    };
    use axum::body::{Body, to_bytes};
    use serde_json::{Value, json};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    const AUTHORITY: &str = "[fd00::1]:62967";
    const VERSION: &str = "2025-11-25";

    #[tokio::test]
    async fn network_listener_keeps_its_configured_port_across_restarts() {
        let mut settings: McpSettings =
            serde_json::from_str(r#"{"network_ip":"192.0.2.1"}"#).unwrap();
        assert_eq!(settings.network_port, 8765);
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        settings.network_ip = Some(address.ip());
        settings.network_port = address.port();
        let saved = serde_json::to_string(&settings).unwrap();
        let settings: McpSettings = serde_json::from_str(&saved).unwrap();
        assert_eq!(settings.network_address(), Some(address));

        let host = Host::new(
            Engine::new(Project::temporary()).unwrap(),
            settings,
            HostMode::Gui,
        );
        let runtime = Handle::current();
        let busy = NetworkServer::bind(host.clone(), address, &runtime);
        assert!(busy.is_err(), "MCP should report an occupied port");
        drop(reservation);

        let server = NetworkServer::bind(host.clone(), address, &runtime).unwrap();
        let url = format!("http://{address}/mcp");
        assert_eq!(server.url(), url);

        // Leave an HTTP connection open while replacing the listener.
        let mut connection = tokio::net::TcpStream::connect(address).await.unwrap();
        let request = format!("GET /mcp HTTP/1.1\r\nHost: {address}\r\n\r\n");
        connection.write_all(request.as_bytes()).await.unwrap();
        let mut status = [0; 12];
        tokio::time::timeout(Duration::from_secs(5), connection.read_exact(&mut status))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&status, b"HTTP/1.1 401");
        server.stop().await;

        let server = NetworkServer::bind(host, address, &runtime).unwrap();
        assert_eq!(server.url(), url);
        server.stop().await;
    }

    fn post(message: Value) -> Request {
        Request::post("/mcp")
            .header(header::HOST, AUTHORITY)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, "application/json")
            .header("mcp-protocol-version", VERSION)
            .body(Body::from(message.to_string()))
            .unwrap()
    }

    async fn rpc_response(response: axum::response::Response) -> Value {
        let status = response.status();
        let is_sse = response.headers()[header::CONTENT_TYPE]
            .as_bytes()
            .starts_with(b"text/event-stream");
        let body = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert_eq!(status, StatusCode::OK, "{text}");
        let json = if is_sse {
            text.lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .find(|data| !data.trim().is_empty())
                .expect("MCP response event")
        } else {
            text
        };
        serde_json::from_str(json).unwrap()
    }

    #[tokio::test]
    async fn network_mcp_authenticates_every_request_and_exposes_scoped_request_tools() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let origin = format!("http://{target_address}");
        let target_task = tokio::spawn(async move {
            let app = Router::new().route("/health", axum::routing::get(|| async { "ok" }));
            axum::serve(target, app).await.unwrap();
        });
        let engine = Engine::new(Project::temporary()).unwrap();
        let mut settings = engine.settings();
        settings.scope.include = vec![format!("^{}/health$", regex::escape(&origin))];
        engine.configure(settings).unwrap();
        let host = Host::new(engine, Default::default(), HostMode::Gui);
        let shutdown = CancellationToken::new();
        let app = router(
            host,
            AUTHORITY.parse().unwrap(),
            "test-token",
            shutdown.clone(),
        );
        let initialize = || {
            post(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "network-test", "version": "1"}
                }
            }))
        };
        let authenticated = |mut request: Request| {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, "Bearer test-token".parse().unwrap());
            request
        };

        for credential in [None, Some("Bearer wrong-token")] {
            let mut request = initialize();
            if let Some(credential) = credential {
                request
                    .headers_mut()
                    .insert(header::AUTHORIZATION, credential.parse().unwrap());
            }
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
        }
        for (header, value) in [
            (header::HOST, "example.com"),
            (header::ORIGIN, "https://example.com"),
        ] {
            let mut request = authenticated(initialize());
            request.headers_mut().insert(header, value.parse().unwrap());
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
        let response = app
            .clone()
            .oneshot(authenticated(initialize()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let session = response.headers()["mcp-session-id"].clone();
        let session_post = |message| {
            let mut request = post(message);
            request
                .headers_mut()
                .insert("mcp-session-id", session.clone());
            request
        };
        let response = app
            .clone()
            .oneshot(authenticated(session_post(json!({
                "jsonrpc": "2.0", "method": "notifications/initialized"
            }))))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let list = || session_post(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
        assert_eq!(
            app.clone().oneshot(list()).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let result = rpc_response(app.clone().oneshot(authenticated(list())).await.unwrap()).await;
        let tools = result["result"]["tools"].as_array().unwrap();
        for spec in crate::mcp::tools::catalogue() {
            let listed = tools.iter().any(|tool| tool["name"] == spec.name);
            assert_eq!(listed, spec.name != "start_active_scan", "{}", spec.name);
        }

        let call = |id, name, arguments| {
            authenticated(session_post(json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}
            })))
        };
        let response = app
            .clone()
            .oneshot(call(3, "start_active_scan", json!({})))
            .await
            .unwrap();
        let denied = rpc_response(response).await;
        assert!(denied["error"].is_object(), "{denied}");

        for (id, path) in [(4, "/health"), (5, "/outside-scope")] {
            let request = call(
                id,
                "send_http_request",
                json!({
                    "target": origin,
                    "request": format!("GET {path} HTTP/1.1\r\nHost: {target_address}\r\n\r\n")
                }),
            );
            let response =
                tokio::time::timeout(Duration::from_secs(5), app.clone().oneshot(request))
                    .await
                    .expect("MCP request should finish without an approval prompt")
                    .unwrap();
            let result = rpc_response(response).await;
            let content = &result["result"]["structuredContent"];
            if path == "/health" {
                assert_eq!(content["status"], 200, "{result}");
            } else {
                assert!(
                    content["error"]
                        .as_str()
                        .is_some_and(|error| error.contains("outside the target scope")),
                    "{result}"
                );
            }
        }

        target_task.abort();
        shutdown.cancel();
        assert_eq!(
            app.oneshot(authenticated(list())).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}

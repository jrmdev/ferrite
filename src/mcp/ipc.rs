//! Authenticated loopback bridge between `ferrite mcp` and a running Ferrite.
//!
//! The Ferrite window listens on a random 127.0.0.1 port and writes the
//! address with a random 256-bit token to an endpoint file readable only by
//! the current user. The relay reads that file and must present the token
//! before any tool call is accepted. Messages are newline-delimited JSON with
//! bounded sizes. The relay never touches the project database.
use super::{
    host::Host,
    tools::{self, Caller, ToolResult},
};
use anyhow::{Context, Result, bail, ensure};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};

pub const PROTOCOL: u32 = 1;
const HELLO_LIMIT: usize = 8 * 1024;
const MESSAGE_LIMIT: usize = 64 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 8;
const CALLS_PER_CONNECTION: usize = 8;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endpoint {
    pub protocol: u32,
    pub address: SocketAddr,
    pub token: String,
    pub pid: u32,
    pub version: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Hello {
        token: String,
        protocol: u32,
        client: ClientIdentity,
    },
    Call {
        id: u64,
        tool: String,
        arguments: Value,
    },
    Cancel {
        id: u64,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    Welcome { version: String, project: String },
    Error { message: String },
    Result { id: u64, result: ToolResult },
}

/// The endpoint file location: `FERRITE_MCP_ENDPOINT`, or
/// `mcp-endpoint.json` in Ferrite's configuration directory.
pub fn default_endpoint_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("FERRITE_MCP_ENDPOINT") {
        return Ok(PathBuf::from(path));
    }
    Ok(crate::preferences::config_dir()?.join("mcp-endpoint.json"))
}

pub fn read_endpoint(path: &Path) -> Result<Endpoint> {
    let endpoint: Endpoint = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("Read {}", path.display()))?,
    )
    .context("Invalid MCP endpoint file")?;
    ensure!(
        endpoint.protocol == PROTOCOL,
        "Ferrite MCP bridge protocol {} is not supported by this ferrite binary",
        endpoint.protocol
    );
    ensure!(
        endpoint.address.ip().is_loopback(),
        "MCP endpoint must be loopback"
    );
    Ok(endpoint)
}

fn write_endpoint(path: &Path, endpoint: &Endpoint) -> Result<()> {
    let directory = path.parent().context("Endpoint file has no parent")?;
    std::fs::create_dir_all(directory)?;
    // NamedTempFile is created 0600 on Unix and inherits the user-only
    // configuration directory ACL on Windows.
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(&mut file, endpoint)?;
    std::io::Write::flush(&mut file)?;
    file.persist(path)?;
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Read one newline-terminated message of at most `limit` bytes.
async fn read_line<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    limit: usize,
) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let read = (&mut *reader)
        .take(limit as u64 + 1)
        .read_until(b'\n', &mut line)
        .await?;
    if read == 0 {
        return Ok(None);
    }
    ensure!(line.len() <= limit, "Message exceeds {limit} bytes");
    ensure!(line.ends_with(b"\n"), "Connection closed mid-message");
    Ok(Some(line))
}

fn encode(message: &ServerMessage) -> Vec<u8> {
    let mut line = serde_json::to_vec(message).unwrap_or_default();
    line.push(b'\n');
    line
}

/// The loopback listener in the Ferrite process that owns the project.
pub struct IpcServer {
    address: SocketAddr,
    path: PathBuf,
    token: String,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl IpcServer {
    /// Start listening and publish the endpoint file. Refuses to replace the
    /// endpoint of another live Ferrite instance.
    pub async fn start(host: Arc<Host>, path: PathBuf) -> Result<Self> {
        if let Ok(existing) = read_endpoint(&path)
            && existing.pid != std::process::id()
            && tokio::time::timeout(
                Duration::from_millis(500),
                TcpStream::connect(existing.address),
            )
            .await
            .is_ok_and(|r| r.is_ok())
        {
            bail!(
                "Another Ferrite instance (process {}) is already serving MCP. Disable MCP there first.",
                existing.pid
            );
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut secret = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut secret);
        let token: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        write_endpoint(
            &path,
            &Endpoint {
                protocol: PROTOCOL,
                address,
                token: token.clone(),
                pid: std::process::id(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
        )?;
        let (stop, mut stopped) = watch::channel(false);
        let accepted_token = token.clone();
        let task = tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stopped.changed() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                        let host = host.clone();
                        let token = accepted_token.clone();
                        connections.spawn(async move {
                            let _permit = permit;
                            if let Err(error) = serve(host.clone(), stream, &token).await {
                                host.engine().log_error(format!("MCP connection: {error:#}"));
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            path,
            token,
            stop,
            task: Some(task),
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn endpoint_path(&self) -> &Path {
        &self.path
    }
    /// Stop accepting connections, disconnect clients and remove the
    /// endpoint file if it is still ours.
    pub async fn stop(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        self.remove_endpoint();
    }
    fn remove_endpoint(&self) {
        if read_endpoint(&self.path).is_ok_and(|e| e.token == self.token) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.remove_endpoint();
    }
}

async fn serve(host: Arc<Host>, stream: TcpStream, token: &str) -> Result<()> {
    stream.set_nodelay(true)?;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let hello = tokio::time::timeout(Duration::from_secs(5), read_line(&mut reader, HELLO_LIMIT))
        .await
        .context("MCP client did not authenticate in time")??
        .context("MCP client disconnected before authenticating")?;
    let client = match serde_json::from_slice::<ClientMessage>(&hello) {
        Ok(ClientMessage::Hello {
            token: offered,
            protocol,
            client,
        }) if constant_time_eq(offered.as_bytes(), token.as_bytes()) => {
            if protocol != PROTOCOL {
                write
                    .write_all(&encode(&ServerMessage::Error {
                        message: format!("Unsupported bridge protocol {protocol}"),
                    }))
                    .await?;
                bail!("Unsupported bridge protocol {protocol}");
            }
            client
        }
        _ => {
            // Slow down guessing; the token is 256 bits regardless.
            tokio::time::sleep(Duration::from_millis(500)).await;
            write
                .write_all(&encode(&ServerMessage::Error {
                    message: "Authentication failed".into(),
                }))
                .await?;
            bail!("Rejected an MCP connection with an invalid token");
        }
    };
    let client_id = host.connect(&client.name, &client.version, "stdio relay");
    struct Registered<'a>(&'a Host, u64);
    impl Drop for Registered<'_> {
        fn drop(&mut self) {
            self.0.disconnect(self.1);
        }
    }
    let _registered = Registered(&host, client_id);
    let project = host.engine().project.lock().unwrap().workspace.name.clone();
    write
        .write_all(&encode(&ServerMessage::Welcome {
            version: env!("CARGO_PKG_VERSION").into(),
            project,
        }))
        .await?;
    let (out, mut outgoing) = mpsc::channel::<Vec<u8>>(64);
    let writer = tokio::spawn(async move {
        while let Some(line) = outgoing.recv().await {
            if write.write_all(&line).await.is_err() {
                break;
            }
        }
    });
    let caller = Caller {
        client_id,
        name: if client.name.is_empty() {
            "MCP client".into()
        } else {
            client.name.chars().take(80).collect()
        },
    };
    let calls = Arc::new(Semaphore::new(CALLS_PER_CONNECTION));
    let running: Arc<Mutex<HashMap<u64, tokio::task::AbortHandle>>> = Default::default();
    let mut tasks = JoinSet::new();
    let result = loop {
        let line = tokio::select! {
            line = read_line(&mut reader, MESSAGE_LIMIT) => line,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let line = match line {
            Ok(Some(line)) => line,
            Ok(None) => break Ok(()),
            Err(error) => break Err(error),
        };
        match serde_json::from_slice::<ClientMessage>(&line) {
            Ok(ClientMessage::Call {
                id,
                tool,
                arguments,
            }) => {
                let Ok(permit) = calls.clone().try_acquire_owned() else {
                    let _ = out
                        .send(encode(&ServerMessage::Result {
                            id,
                            result: ToolResult::error(
                                "Too many concurrent tool calls from this client",
                            ),
                        }))
                        .await;
                    continue;
                };
                let host = host.clone();
                let caller = caller.clone();
                let out = out.clone();
                let running_map = running.clone();
                let handle = tasks.spawn(async move {
                    let _permit = permit;
                    let result = tools::call(&host, &caller, &tool, arguments).await;
                    running_map.lock().unwrap().remove(&id);
                    let _ = out
                        .send(encode(&ServerMessage::Result { id, result }))
                        .await;
                });
                running.lock().unwrap().insert(id, handle);
            }
            Ok(ClientMessage::Cancel { id }) => {
                if let Some(handle) = running.lock().unwrap().remove(&id) {
                    handle.abort();
                }
            }
            Ok(ClientMessage::Hello { .. }) | Err(_) => {
                break Err(anyhow::anyhow!("Invalid message from MCP client"));
            }
        }
    };
    // A disconnected client cancels its in-flight calls.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(out);
    let _ = writer.await;
    result
}

struct Connection {
    out: mpsc::UnboundedSender<Vec<u8>>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<ToolResult>>>>,
    alive: Arc<AtomicBool>,
}

/// The relay side: forwards tool calls to the running Ferrite.
pub struct RelayClient {
    path: PathBuf,
    client: Mutex<ClientIdentity>,
    connection: tokio::sync::Mutex<Option<Arc<Connection>>>,
    next: AtomicU64,
}

impl RelayClient {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            client: Mutex::new(ClientIdentity::default()),
            connection: tokio::sync::Mutex::new(None),
            next: AtomicU64::new(1),
        }
    }
    pub fn set_client(&self, client: ClientIdentity) {
        *self.client.lock().unwrap() = client;
    }

    fn unavailable(&self, error: &anyhow::Error) -> ToolResult {
        ToolResult::error(format!(
            "Ferrite is not reachable ({error:#}). Start Ferrite, open the MCP page and enable the MCP server, then retry. Endpoint file: {}",
            self.path.display()
        ))
    }

    async fn connect(&self) -> Result<Arc<Connection>> {
        let endpoint = read_endpoint(&self.path)?;
        let stream =
            tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(endpoint.address))
                .await
                .context("Connection timed out")??;
        stream.set_nodelay(true)?;
        let (read, mut write) = stream.into_split();
        let mut hello = serde_json::to_vec(&ClientMessage::Hello {
            token: endpoint.token,
            protocol: PROTOCOL,
            client: self.client.lock().unwrap().clone(),
        })?;
        hello.push(b'\n');
        write.write_all(&hello).await?;
        let mut reader = BufReader::new(read);
        let welcome =
            tokio::time::timeout(Duration::from_secs(5), read_line(&mut reader, HELLO_LIMIT))
                .await
                .context("Ferrite did not answer")??
                .context("Ferrite closed the connection")?;
        match serde_json::from_slice::<ServerMessage>(&welcome)? {
            ServerMessage::Welcome { .. } => {}
            ServerMessage::Error { message } => bail!("Ferrite refused the connection: {message}"),
            ServerMessage::Result { .. } => bail!("Unexpected message from Ferrite"),
        }
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<ToolResult>>>> = Default::default();
        let alive = Arc::new(AtomicBool::new(true));
        let (out, mut outgoing) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(line) = outgoing.recv().await {
                if write.write_all(&line).await.is_err() {
                    break;
                }
            }
        });
        {
            let pending = pending.clone();
            let alive = alive.clone();
            tokio::spawn(async move {
                while let Ok(Some(line)) = read_line(&mut reader, MESSAGE_LIMIT).await {
                    if let Ok(ServerMessage::Result { id, result }) = serde_json::from_slice(&line)
                        && let Some(reply) = pending.lock().unwrap().remove(&id)
                    {
                        let _ = reply.send(result);
                    }
                }
                alive.store(false, Ordering::SeqCst);
                // Dropping the senders fails every waiting call.
                pending.lock().unwrap().clear();
            });
        }
        Ok(Arc::new(Connection {
            out,
            pending,
            alive,
        }))
    }

    async fn connection(&self) -> Result<Arc<Connection>> {
        let mut slot = self.connection.lock().await;
        if let Some(connection) = slot.as_ref()
            && connection.alive.load(Ordering::SeqCst)
        {
            return Ok(connection.clone());
        }
        let connection = self.connect().await?;
        *slot = Some(connection.clone());
        Ok(connection)
    }

    /// Establish the connection early so Ferrite shows the client; failures
    /// are reported on the first tool call instead.
    pub async fn warm_up(&self) {
        let _ = self.connection().await;
    }

    pub async fn call(&self, tool: &str, arguments: Value) -> ToolResult {
        let connection = match self.connection().await {
            Ok(connection) => connection,
            Err(error) => return self.unavailable(&error),
        };
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (reply, result) = oneshot::channel();
        connection.pending.lock().unwrap().insert(id, reply);
        let mut line = match serde_json::to_vec(&ClientMessage::Call {
            id,
            tool: tool.into(),
            arguments,
        }) {
            Ok(line) => line,
            Err(error) => return ToolResult::error(error.to_string()),
        };
        line.push(b'\n');
        if connection.out.send(line).is_err() {
            connection.pending.lock().unwrap().remove(&id);
            return self.unavailable(&anyhow::anyhow!("connection closed"));
        }
        // If the MCP client cancels, this future is dropped: tell Ferrite.
        struct CancelOnDrop {
            connection: Arc<Connection>,
            id: u64,
            done: bool,
        }
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                if !self.done {
                    self.connection.pending.lock().unwrap().remove(&self.id);
                    if let Ok(mut line) = serde_json::to_vec(&ClientMessage::Cancel { id: self.id })
                    {
                        line.push(b'\n');
                        let _ = self.connection.out.send(line);
                    }
                }
            }
        }
        let mut guard = CancelOnDrop {
            connection,
            id,
            done: false,
        };
        let outcome = result.await;
        guard.done = true;
        outcome.unwrap_or_else(|_| {
            ToolResult::error("Lost the connection to Ferrite while the tool was running")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::Engine,
        mcp::{McpSettings, host::HostMode},
        project::Project,
    };

    #[tokio::test]
    async fn relay_authenticates_calls_and_reconnects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoint.json");
        let host = Host::new(
            Engine::new(Project::temporary()).unwrap(),
            McpSettings::default(),
            HostMode::Gui,
        );
        let relay = RelayClient::new(path.clone());
        let offline = relay.call("get_scope", Value::Null).await;
        assert!(offline.is_error);
        assert!(
            offline.value["error"]
                .as_str()
                .unwrap()
                .contains("not reachable")
        );

        let server = IpcServer::start(host.clone(), path.clone()).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        relay.set_client(ClientIdentity {
            name: "test-client".into(),
            version: "1".into(),
        });
        let scope = relay.call("get_scope", Value::Null).await;
        assert!(!scope.is_error, "{:?}", scope.value);
        assert_eq!(scope.value["include"], serde_json::json!([]));
        assert_eq!(host.clients()[0].name, "test-client");
        let audit = host.recent_audit();
        assert_eq!(audit.last().unwrap().tool, "get_scope");
        assert_eq!(audit.last().unwrap().client, "test-client");

        // A wrong token is refused.
        let endpoint = read_endpoint(&path).unwrap();
        let mut forged = endpoint.clone();
        forged.token = "00".repeat(32);
        let forged_path = dir.path().join("forged.json");
        write_endpoint(&forged_path, &forged).unwrap();
        let intruder = RelayClient::new(forged_path);
        let refused = intruder.call("get_scope", Value::Null).await;
        assert!(refused.value["error"].as_str().unwrap().contains("refused"));

        // Restarting Ferrite's listener is picked up on the next call.
        server.stop().await;
        assert!(!path.exists());
        assert!(relay.call("get_scope", Value::Null).await.is_error);
        let server = IpcServer::start(host.clone(), path.clone()).await.unwrap();
        assert!(!relay.call("get_scope", Value::Null).await.is_error);
        drop(server);
        assert!(!path.exists());
    }
}

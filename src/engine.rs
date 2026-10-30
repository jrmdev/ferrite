use crate::{
    http::{Message, read_request},
    model::{Destination, Exchange, Settings},
    project::Project,
    rules,
    tls::Authority,
    transport::{self, Stream},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot, watch},
    task::{JoinHandle, JoinSet},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Request,
    Response,
}
#[derive(Clone)]
pub struct Intercepted {
    pub id: u64,
    pub stage: Stage,
    pub destination: Destination,
    pub message: Message,
    pub url: String,
    /// Response interception retains the originating request for editor actions.
    pub request: Option<Arc<Message>>,
}
pub enum Decision {
    Forward(Message),
    Drop,
}
struct Pending {
    item: Intercepted,
    reply: oneshot::Sender<Decision>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
pub struct Engine {
    pub project: Mutex<Project>,
    settings: RwLock<Settings>,
    pub authority: Authority,
    pending: Mutex<BTreeMap<u64, Pending>>,
    request_intercept: AtomicBool,
    response_intercept: AtomicBool,
    next_pending: AtomicU64,
    running: AtomicBool,
    active_address: Mutex<Option<SocketAddr>>,
    pub activity: AtomicU64,
    pub errors: Mutex<Vec<String>>,
    pub websockets: crate::websocket::Hub,
    pub scanner: crate::scanner::Hub,
    pub(crate) interception_slots: Arc<Semaphore>,
}
pub struct Listener {
    pub address: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}
impl Listener {
    pub async fn stop(mut self) {
        let _ = self.stop.send(true);
        let _ = (&mut self.task).await;
    }
    pub fn shutdown(&self) {
        let _ = self.stop.send(true);
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}
struct PendingGuard<'a> {
    engine: &'a Engine,
    id: u64,
}
impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.engine.pending.lock().unwrap().remove(&self.id);
    }
}
impl Engine {
    pub fn new(mut project: Project) -> Result<Arc<Self>> {
        let authority = Authority::load(&mut project)?;
        Self::with_authority(project, authority)
    }
    pub fn new_with_key(project: Project, key: &[u8]) -> Result<Arc<Self>> {
        Self::with_authority(project, Authority::from_key(key)?)
    }
    fn with_authority(project: Project, authority: Authority) -> Result<Arc<Self>> {
        let settings = project.workspace.settings.clone();
        settings.validate()?;
        let engine = Arc::new(Self {
            project: Mutex::new(project),
            settings: RwLock::new(settings),
            authority,
            pending: Mutex::new(BTreeMap::new()),
            request_intercept: AtomicBool::new(false),
            response_intercept: AtomicBool::new(false),
            next_pending: AtomicU64::new(1),
            running: AtomicBool::new(false),
            active_address: Mutex::new(None),
            activity: AtomicU64::new(0),
            errors: Mutex::new(vec![]),
            websockets: crate::websocket::Hub::default(),
            scanner: crate::scanner::Hub::default(),
            interception_slots: Arc::new(Semaphore::new(256)),
        });
        let _ = engine.scanner.engine.set(Arc::downgrade(&engine));
        Ok(engine)
    }
    pub fn settings(&self) -> Settings {
        self.settings.read().unwrap().clone()
    }
    pub(crate) fn scanner_listener_address(&self) -> Option<SocketAddr> {
        *self.active_address.lock().unwrap()
    }
    pub fn configure(&self, settings: Settings) -> Result<()> {
        settings.validate()?;
        let mut p = self.project.lock().unwrap();
        let previous = std::mem::replace(&mut p.workspace.settings, settings.clone());
        if let Err(e) = p.save_workspace() {
            p.workspace.settings = previous;
            return Err(e);
        }
        drop(p);
        *self.settings.write().unwrap() = settings.clone();
        self.websockets.release_exempt(&settings);
        if settings.intercept_in_scope_only {
            let mut queue = self.pending.lock().unwrap();
            let ids: Vec<_> = queue
                .iter()
                .filter(|(_, p)| !settings.scope.contains(&p.item.url))
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                if let Some(p) = queue.remove(&id) {
                    let _ = p.reply.send(Decision::Forward(p.item.message));
                }
            }
        }
        Ok(())
    }
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
    pub fn intercept_enabled(&self, stage: Stage) -> bool {
        match stage {
            Stage::Request => &self.request_intercept,
            Stage::Response => &self.response_intercept,
        }
        .load(Ordering::SeqCst)
    }
    pub fn set_intercept(&self, stage: Stage, enabled: bool) {
        let mut queue = self.pending.lock().unwrap();
        match stage {
            Stage::Request => &self.request_intercept,
            Stage::Response => &self.response_intercept,
        }
        .store(enabled, Ordering::SeqCst);
        if !enabled {
            let ids: Vec<_> = queue
                .iter()
                .filter(|(_, p)| p.item.stage == stage)
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                if let Some(p) = queue.remove(&id) {
                    let _ = p.reply.send(Decision::Forward(p.item.message));
                }
            }
        }
    }
    pub fn pending(&self) -> Vec<Intercepted> {
        self.pending
            .lock()
            .unwrap()
            .values()
            .map(|p| p.item.clone())
            .collect()
    }
    /// Number of HTTP messages currently awaiting an interception decision.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
    pub fn decide(&self, id: u64, decision: Decision) -> Result<()> {
        let p = self
            .pending
            .lock()
            .unwrap()
            .remove(&id)
            .context("Message is no longer pending")?;
        p.reply
            .send(decision)
            .map_err(|_| anyhow::anyhow!("Client disconnected"))?;
        Ok(())
    }
    /// Forward the messages currently in the queue, optionally including the
    /// user's edits to the selected message. Later arrivals remain queued.
    pub fn forward_pending(&self, edited: Option<(u64, Message)>) -> Result<()> {
        let pending = {
            let mut queue = self.pending.lock().unwrap();
            if let Some((id, _)) = &edited {
                ensure!(queue.contains_key(id), "Message is no longer pending");
            }
            std::mem::take(&mut *queue)
        };
        let mut edited = edited;
        for (id, item) in pending {
            let message = if edited.as_ref().is_some_and(|(selected, _)| *selected == id) {
                edited.take().unwrap().1
            } else {
                item.item.message
            };
            let _ = item.reply.send(Decision::Forward(message));
        }
        Ok(())
    }
    pub fn drop_pending(&self) {
        let pending = std::mem::take(&mut *self.pending.lock().unwrap());
        for (_, p) in pending {
            let _ = p.reply.send(Decision::Drop);
        }
    }
    pub(crate) fn log_error(&self, error: String) {
        let mut errors = self.errors.lock().unwrap();
        if errors.len() >= 100 {
            errors.remove(0);
        }
        errors.push(error);
    }
    async fn gate(
        &self,
        msg: Message,
        dest: &Destination,
        stage: Stage,
        url: &str,
        request: Option<&Message>,
    ) -> Result<Message> {
        let (id, rx) = {
            let mut queue = self.pending.lock().unwrap();
            let settings = self.settings.read().unwrap();
            if !self.intercept_enabled(stage)
                || (settings.intercept_in_scope_only && !settings.scope.contains(url))
            {
                return Ok(msg);
            }
            let permit = self
                .interception_slots
                .clone()
                .try_acquire_owned()
                .context("Interception queue is full")?;
            let id = self.next_pending.fetch_add(1, Ordering::SeqCst);
            let (tx, rx) = oneshot::channel();
            queue.insert(
                id,
                Pending {
                    item: Intercepted {
                        id,
                        stage,
                        destination: dest.clone(),
                        message: msg,
                        url: url.into(),
                        request: request.map(|request| Arc::new(request.clone())),
                    },
                    reply: tx,
                    _permit: permit,
                },
            );
            (id, rx)
        };
        let _guard = PendingGuard { engine: self, id };
        match rx.await? {
            Decision::Forward(msg) => Ok(msg),
            Decision::Drop => anyhow::bail!("Dropped by user"),
        }
    }
    pub async fn execute(
        &self,
        request: Message,
        dest: Destination,
        tool: &str,
        intercept: bool,
    ) -> Result<Exchange> {
        Ok(self
            .execute_upgradable(request, dest, tool, intercept, false)
            .await?
            .0)
    }
    /// Send without interception, refusing any URL outside the target scope
    /// regardless of the Drop out of scope setting. The check uses the same
    /// settings snapshot as the send, so a scope change cannot race it.
    pub async fn execute_in_scope(
        &self,
        request: Message,
        dest: Destination,
        tool: &str,
    ) -> Result<Exchange> {
        Ok(self
            .execute_upgradable(request, dest, tool, false, true)
            .await?
            .0)
    }
    async fn execute_upgradable(
        &self,
        mut request: Message,
        dest: Destination,
        tool: &str,
        intercept: bool,
        require_scope: bool,
    ) -> Result<(Exchange, Option<Stream>)> {
        let mut upgrade = None;
        let started = Instant::now();
        let timestamp_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let mut settings = self.settings();
        if let Some(address) = *self.active_address.lock().unwrap() {
            settings.listen = address.to_string();
        }
        let url = request.url(&dest);
        let id = self.project.lock().unwrap().allocate_id();
        let mut flow = Exchange {
            id,
            timestamp_ms,
            tool: tool.into(),
            destination: dest.clone(),
            url: url.clone(),
            method: request.method().into(),
            request: request.encode(),
            response: vec![],
            status: 0,
            duration_ms: 0,
            error: None,
            note: String::new(),
        };
        let result: Result<Message> = async {
            let enforce_scope = settings.drop_out_of_scope || require_scope;
            ensure!(
                !enforce_scope || settings.scope.contains(&url),
                "Request is outside target scope"
            );
            let in_scope = settings.scope.contains(&url);
            let do_rules = tool == "Proxy" && (!settings.rules_in_scope_only || in_scope);
            // Captured rules run before the interactive editor; manual changes win.
            if do_rules {
                rules::apply(&mut request, &settings.rules, false)?;
            }
            if intercept {
                let request_url = request.url(&dest);
                request = self
                    .gate(request.clone(), &dest, Stage::Request, &request_url, None)
                    .await?;
            }
            request.prepare_request(&dest)?;
            if crate::websocket::is_websocket(&request) {
                crate::websocket::validate_request(&request)?;
                request.remove("Sec-WebSocket-Extensions");
            }
            // Recheck edited targets so scope policy cannot be bypassed with the editor.
            let effective_url = request.url(&dest);
            ensure!(
                !enforce_scope || settings.scope.contains(&effective_url),
                "Edited request is outside target scope"
            );
            flow.url = effective_url;
            flow.method = request.method().into();
            flow.request = request.encode();
            ensure!(
                flow.request.len() <= settings.max_message_bytes,
                "Edited request exceeds message limit"
            );
            // Downstream protocol does not dictate the cleartext origin protocol.
            // TLS negotiates independently; h2c prior knowledge is selected explicitly in tool editors.
            let mut upstream_request = request.clone();
            if tool == "Proxy" && !dest.tls {
                upstream_request.start =
                    format!("{} {} HTTP/1.1", request.method(), request.target());
            }
            let outcome = tokio::time::timeout(
                Duration::from_secs(settings.timeout_secs),
                transport::send_with_upgrade(&dest, &upstream_request, &settings),
            )
            .await
            .context("Upstream request timed out")??;
            let mut response = outcome.response;
            upgrade = outcome.upgrade;
            // Retain the actual handshake even when validation or interception fails.
            if response.status() == 101 {
                flow.status = 101;
                flow.response = response.encode();
            }
            if do_rules {
                rules::apply(&mut response, &settings.rules, true)?;
            }
            if intercept {
                response = self
                    .gate(response, &dest, Stage::Response, &flow.url, Some(&request))
                    .await?;
            }
            if response.status() == 101 {
                ensure!(
                    upgrade.is_some(),
                    "An edited 101 response requires a real upstream upgrade"
                );
                if crate::websocket::is_websocket(&request) {
                    crate::websocket::validate_response(&request, &response)?;
                } else {
                    ensure!(
                        response.header("Upgrade").is_some_and(|value| request
                            .header("Upgrade")
                            .is_some_and(|offered| offered
                                .split(',')
                                .any(|token| token.trim().eq_ignore_ascii_case(value)))),
                        "Upstream selected an unoffered upgrade protocol"
                    );
                    ensure!(
                        response.header("Connection").is_some_and(|v| v
                            .split(',')
                            .any(|s| s.trim().eq_ignore_ascii_case("upgrade"))),
                        "Invalid Connection header on upgrade"
                    );
                }
                response.body.clear();
                response.remove("Content-Length");
                response.remove("Transfer-Encoding");
                ensure!(
                    response.encode().len() <= settings.max_message_bytes,
                    "Edited response exceeds message limit"
                );
                return Ok(response);
            }
            upgrade = None;
            response.remove_hop_headers();
            response.set("Connection", "close".into());
            let status = response.status();
            if request.method() == "HEAD" || status == 304 {
                response.body.clear();
                response.remove("Transfer-Encoding");
            } else if status == 204 {
                response.body.clear();
                response.remove("Transfer-Encoding");
                response.remove("Content-Length");
            } else {
                response.normalize_length();
            }
            ensure!(
                response.encode().len() <= settings.max_message_bytes,
                "Edited response exceeds message limit"
            );
            Ok(response)
        }
        .await;
        match result {
            Ok(response) => {
                flow.status = response.status();
                flow.response = response.encode();
            }
            Err(error) => {
                upgrade = None;
                flow.error = Some(format!("{error:#}"));
            }
        }
        flow.duration_ms = started.elapsed().as_millis() as u64;
        self.project.lock().unwrap().insert(flow.clone())?;
        self.activity.fetch_add(1, Ordering::SeqCst);
        self.enqueue_passive(&flow);
        Ok((flow, upgrade))
    }
    pub async fn start(self: &Arc<Self>) -> Result<Listener> {
        ensure!(
            self.running
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok(),
            "Proxy is already running"
        );
        let settings = self.settings();
        let listener = match TcpListener::bind(&settings.listen).await {
            Ok(l) => l,
            Err(e) => {
                self.running.store(false, Ordering::SeqCst);
                return Err(e.into());
            }
        };
        let address = listener.local_addr()?;
        *self.active_address.lock().unwrap() = Some(address);
        let (stop, mut signal) = watch::channel(false);
        let engine = self.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            let semaphore = Arc::new(Semaphore::new(256));
            loop {
                tokio::select! {
                    _=signal.changed()=>break,
                    result=listener.accept()=> {
                        match result {
                            Ok((stream,_))=>{
                                if let Ok(permit)=semaphore.clone().try_acquire_owned() {
                                    let engine=engine.clone();let settings=settings.clone();
                                    tasks.spawn(async move {let _permit=permit;if let Err(e)=engine.connection(stream,&settings).await {engine.log_error(format!("{e:#}"));}});
                                }
                            },
                            Err(e)=> {engine.log_error(e.to_string());break;},
                        }
                    },
                    _=tasks.join_next(),if !tasks.is_empty()=>{},
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            engine.drop_pending();
            engine.websockets.drop_all();
            *engine.active_address.lock().unwrap() = None;
            engine.running.store(false, Ordering::SeqCst);
        });
        Ok(Listener {
            address,
            stop,
            task,
        })
    }
    async fn connection(self: &Arc<Self>, mut tcp: TcpStream, settings: &Settings) -> Result<()> {
        let deadline = Duration::from_secs(settings.timeout_secs);
        let mut first = [0u8; 1];
        let n = tokio::time::timeout(deadline, tcp.peek(&mut first)).await??;
        ensure!(n > 0, "Client disconnected");
        if first[0] == 22 {
            ensure!(
                settings.transparent,
                "Direct TLS requires invisible proxy mode"
            );
            let accept =
                tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp);
            let hello = tokio::time::timeout(deadline, accept).await??;
            let name = hello
                .client_hello()
                .server_name()
                .map(str::to_string)
                .or_else(|| settings.fallback.as_ref().map(|d| d.host.clone()))
                .context("TLS needs SNI or a fallback target")?;
            let config = self.authority.server_config(&name)?;
            let tls = tokio::time::timeout(deadline, hello.into_stream(config)).await??;
            if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                return self.serve_h2(Box::new(tls), true, None, settings).await;
            }
            return self.serve(Box::new(tls), true, None, settings).await;
        }
        let mut reader = BufReader::with_capacity(1, tcp);
        let first = tokio::time::timeout(
            deadline,
            read_request(&mut reader, settings.max_message_bytes),
        )
        .await??;
        if first.start == "PRI * HTTP/2.0" {
            // Replay the already-read preface prefix to h2 without losing buffered bytes.
            let prefix = std::io::Cursor::new(first.encode());
            let (read, write) = tokio::io::split(reader);
            let stream = tokio::io::join(prefix.chain(read), write);
            return self.serve_h2(Box::new(stream), false, None, settings).await;
        }
        if first.method() == "CONNECT" {
            let dest = Destination::from_url(&format!("https://{}", first.target()))?;
            tcp = reader.into_inner();
            tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            // Browsers also use CONNECT for unencrypted ws:// traffic. Inspect
            // without consuming bytes before choosing plain HTTP versus TLS.
            let mut first = [0u8; 1];
            ensure!(
                tokio::time::timeout(deadline, tcp.peek(&mut first)).await?? > 0,
                "Client disconnected after CONNECT"
            );
            if first[0] != 22 {
                let dest = Destination { tls: false, ..dest };
                return self.serve(Box::new(tcp), false, Some(dest), settings).await;
            }
            let config = self.authority.server_config(&dest.host)?;
            let tls = tokio::time::timeout(
                deadline,
                tokio_rustls::TlsAcceptor::from(config).accept(tcp),
            )
            .await??;
            if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                return self
                    .serve_h2(Box::new(tls), true, Some(dest), settings)
                    .await;
            }
            self.serve(Box::new(tls), true, Some(dest), settings).await
        } else {
            let dest =
                first.destination(false, settings.fallback.as_ref(), settings.transparent)?;
            let stream: Stream = Box::new(reader);
            self.respond(stream, first, dest).await
        }
    }
    async fn serve_h2(
        self: &Arc<Self>,
        stream: Stream,
        tls: bool,
        fixed: Option<Destination>,
        settings: &Settings,
    ) -> Result<()> {
        let deadline = Duration::from_secs(settings.timeout_secs);
        let mut connection = tokio::time::timeout(
            deadline,
            h2::server::Builder::new()
                .max_concurrent_streams(128)
                .max_header_list_size(settings.max_message_bytes.min(65536) as u32)
                .handshake::<_, bytes::Bytes>(stream),
        )
        .await??;
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                incoming = tokio::time::timeout(deadline, connection.accept()) => {
                    let incoming = match incoming {
                        Ok(Some(incoming)) => incoming?,
                        Ok(None) => break,
                        Err(_) if tasks.is_empty() => break,
                        Err(_) => continue,
                    };
                    let (request, mut respond) = incoming;
                    if tasks.len() >= 128 {
                        respond.send_reset(h2::Reason::REFUSED_STREAM);
                        continue;
                    }
                    let engine = self.clone();
                    let settings = settings.clone();
                    let fixed = fixed.clone();
                    tasks.spawn(async move {
                        let result: Result<()> = async {
                            let request_tls = match request.uri().scheme_str() {
                                Some("https") => true,
                                Some("http") => false,
                                _ => tls,
                            };
                            let request = tokio::time::timeout(deadline,
                                crate::http2::receive_request(request, settings.max_message_bytes)).await??;
                            let dest = if let Some(dest) = fixed { dest }
                                else { request.destination(request_tls, settings.fallback.as_ref(), true)? };
                            let flow = engine.execute(request, dest, "Proxy", true).await?;
                            let response = if flow.error.is_some() {
                                Message::parse(b"HTTP/2 502\r\nContent-Type: text/plain\r\n\r\nFerrite could not forward this request. See proxy history.\n")?
                            } else { Message::parse(&flow.response)? };
                            let head = crate::http2::response_head(&response)?;
                            let body = respond.send_response(head, response.body.is_empty())?;
                            tokio::time::timeout(deadline, crate::http2::send_body(body, &response.body)).await??;
                            Ok(())
                        }.await;
                        if let Err(error) = result {
                            respond.send_reset(h2::Reason::INTERNAL_ERROR);
                            engine.log_error(format!("{error:#}"));
                        }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {},
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
    async fn serve(
        &self,
        stream: Stream,
        tls: bool,
        fixed: Option<Destination>,
        settings: &Settings,
    ) -> Result<()> {
        let mut reader = BufReader::new(stream);
        let request = tokio::time::timeout(
            Duration::from_secs(settings.timeout_secs),
            read_request(&mut reader, settings.max_message_bytes),
        )
        .await??;
        let dest = if let Some(d) = fixed {
            d
        } else {
            request.destination(tls, settings.fallback.as_ref(), true)?
        };
        // Retain any application bytes read alongside the HTTP handshake.
        self.respond(Box::new(reader), request, dest).await
    }
    async fn respond(&self, mut stream: Stream, request: Message, dest: Destination) -> Result<()> {
        let (flow, upgrade) = self
            .execute_upgradable(request, dest, "Proxy", true, false)
            .await?;
        if let Some(mut upstream) = upgrade {
            stream.write_all(&flow.response).await?;
            stream.flush().await?;
            if crate::websocket::is_websocket(&Message::parse(&flow.request)?) {
                return crate::websocket::run(self, stream, upstream, &flow).await;
            }
            tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
            return Ok(());
        }
        let bytes = if flow.error.is_some() {
            // Detailed error stays in history, never interpolate it into an HTTP header.
            let body = b"Ferrite could not forward this request. See proxy history.\n";
            let mut bytes=format!("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
            bytes.extend_from_slice(body);
            bytes
        } else {
            let mut response = Message::parse(&flow.response)?;
            if response.start.starts_with("HTTP/2 ") {
                let status = ::http::StatusCode::from_u16(response.status())?;
                response.start = format!(
                    "HTTP/1.1 {} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("")
                );
            }
            response.encode()
        };
        tokio::time::timeout(Duration::from_secs(self.settings().timeout_secs), async {
            stream.write_all(&bytes).await?;
            stream.shutdown().await
        })
        .await??;
        Ok(())
    }
}

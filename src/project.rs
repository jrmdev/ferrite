use crate::model::{Exchange, Workspace};
use anyhow::{Context, Result, ensure};
use redb::{Database, ReadableTable, TableDefinition};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
const FLOWS: TableDefinition<u64, &[u8]> = TableDefinition::new("exchanges");

fn database_builder() -> redb::Builder {
    let mut builder = Database::builder();
    // The UI also retains message bodies; avoid redb's 1 GiB default per project.
    builder.set_cache_size(64 * 1024 * 1024);
    builder
}
mod annotations;
mod audit;
mod history_cache;
mod history_reader;
mod scanner;
mod websockets;
use crate::websocket::{CapturedMessage, MessageSummary, Session};

pub struct Project {
    db: Option<Arc<Database>>,
    path: Option<PathBuf>,
    memory: BTreeMap<u64, Arc<Exchange>>,
    pub workspace: Workspace,
    secret: Option<Vec<u8>>,
    next_id: u64,
    history_changes: history_cache::Changes,
    ws_sessions: BTreeMap<u64, Session>,
    ws_summaries: BTreeMap<(u64, u64), MessageSummary>,
    ws_memory: BTreeMap<(u64, u64), CapturedMessage>,
    scan_jobs: BTreeMap<u64, crate::scanner::ScanJob>,
    findings: BTreeMap<u64, crate::scanner::Finding>,
    audit: Vec<crate::mcp::AuditEntry>,
    annotations: BTreeMap<u64, crate::history::Annotation>,
}

pub use history_reader::HistoryReader;

impl Project {
    pub fn temporary() -> Self {
        Self {
            db: None,
            path: None,
            memory: BTreeMap::new(),
            workspace: Workspace::default(),
            secret: None,
            next_id: 1,
            history_changes: Default::default(),
            ws_sessions: BTreeMap::new(),
            ws_summaries: BTreeMap::new(),
            ws_memory: BTreeMap::new(),
            scan_jobs: BTreeMap::new(),
            findings: BTreeMap::new(),
            audit: vec![],
            annotations: BTreeMap::new(),
        }
        .normalised()
    }
    /// Assign stable identifiers to Repeater tabs saved by older versions.
    fn normalised(mut self) -> Self {
        self.workspace.assign_repeater_ids();
        self
    }
    /// The project file, or None for a temporary in-memory project.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
    /// A lock-free reader over the exchanges stored so far.
    pub fn history_reader(&self) -> HistoryReader {
        HistoryReader {
            db: self.db.clone(),
            memory: if self.db.is_some() {
                vec![]
            } else {
                self.memory.values().cloned().collect()
            },
        }
    }
    /// Open an existing project, or create one for the command-line interface.
    pub fn open(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::open_existing(path)
        } else {
            Self::create(path)
        }
    }
    pub fn open_existing(path: &Path) -> Result<Self> {
        let db = database_builder()
            .open(path)
            .with_context(|| format!("Open project {}", path.display()))?;
        Self::from_database(db, path)
    }
    pub fn create(path: &Path) -> Result<Self> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)
            .with_context(|| format!("Create {}", path.display()))?;
        let result = (|| {
            let db = database_builder()
                .create(path)
                .with_context(|| format!("Create project {}", path.display()))?;
            Self::from_database(db, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result
    }
    fn from_database(db: Database, path: &Path) -> Result<Self> {
        let tx = db.begin_write()?;
        {
            tx.open_table(META)?;
            tx.open_table(FLOWS)?;
        }
        tx.commit()?;
        let (workspace, secret, next_id) = {
            let tx = db.begin_read()?;
            let meta = tx.open_table(META)?;
            let workspace = match meta.get("workspace")? {
                Some(v) => serde_json::from_slice::<Workspace>(v.value())?,
                None => Workspace {
                    name: path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into(),
                    ..Workspace::default()
                },
            };
            ensure!(
                workspace.schema == 1,
                "Unsupported project schema {}",
                workspace.schema
            );
            workspace.settings.validate()?;
            workspace.scanner.validate()?;
            let secret = meta.get("ca-key")?.map(|v| v.value().to_vec());
            let flows = tx.open_table(FLOWS)?;
            let next_id = flows.last()?.map_or(1, |(k, _)| k.value() + 1);
            (workspace, secret, next_id)
        };
        let mut project = Self {
            db: Some(Arc::new(db)),
            path: Some(path.to_owned()),
            memory: BTreeMap::new(),
            workspace,
            secret,
            next_id,
            history_changes: Default::default(),
            ws_sessions: BTreeMap::new(),
            ws_summaries: BTreeMap::new(),
            ws_memory: BTreeMap::new(),
            scan_jobs: BTreeMap::new(),
            findings: BTreeMap::new(),
            audit: vec![],
            annotations: BTreeMap::new(),
        }
        .normalised();
        project.load_websockets()?;
        project.load_scanner()?;
        project.load_audit()?;
        project.load_annotations()?;
        project.save_workspace()?;
        Ok(project)
    }
    pub fn allocate_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
    pub fn save_workspace(&mut self) -> Result<()> {
        if let Some(db) = &self.db {
            let bytes = serde_json::to_vec(&self.workspace)?;
            let tx = db.begin_write()?;
            {
                tx.open_table(META)?.insert("workspace", bytes.as_slice())?;
            }
            tx.commit()?;
        }
        Ok(())
    }
    pub fn ca_key(&self) -> Option<Vec<u8>> {
        self.secret.clone()
    }
    pub fn set_ca_key(&mut self, bytes: Vec<u8>) -> Result<()> {
        if let Some(db) = &self.db {
            let tx = db.begin_write()?;
            {
                tx.open_table(META)?.insert("ca-key", bytes.as_slice())?;
            }
            tx.commit()?;
        }
        self.secret = Some(bytes);
        Ok(())
    }
    pub fn insert(&mut self, flow: Exchange) -> Result<()> {
        self.store_exchange(std::borrow::Cow::Owned(flow))
    }
    pub(crate) fn record(&mut self, flow: &Exchange) -> Result<()> {
        self.store_exchange(std::borrow::Cow::Borrowed(flow))
    }
    fn store_exchange(&mut self, flow: std::borrow::Cow<'_, Exchange>) -> Result<()> {
        let id = flow.id;
        let next_id = flow.id.checked_add(1).context("Exchange ID exhausted")?;
        if let Some(db) = &self.db {
            let bytes = serde_json::to_vec(flow.as_ref())?;
            let tx = db.begin_write()?;
            {
                tx.open_table(FLOWS)?.insert(flow.id, bytes.as_slice())?;
            }
            tx.commit()?;
        } else {
            self.memory.insert(flow.id, Arc::new(flow.into_owned()));
        }
        self.next_id = self.next_id.max(next_id);
        self.history_changes.record(id);
        Ok(())
    }
    pub fn delete(&mut self, ids: &[u64]) -> Result<()> {
        ensure!(
            !ids.iter().any(|id| self
                .ws_sessions
                .get(id)
                .is_some_and(|s| s.state == crate::websocket::SessionState::Open)),
            "Close the active WebSocket session before deleting its handshake"
        );
        let deleted: std::collections::HashSet<_> = ids.iter().copied().collect();
        let mut workspace = self.workspace.clone();
        for tab in &mut workspace.repeater {
            tab.history.retain(|id| !deleted.contains(id));
        }
        if let Some(db) = &self.db {
            let bytes = serde_json::to_vec(&workspace)?;
            let tx = db.begin_write()?;
            {
                let mut flows = tx.open_table(FLOWS)?;
                for id in ids {
                    flows.remove(*id)?;
                }
                tx.open_table(META)?.insert("workspace", bytes.as_slice())?;
                websockets::delete_tables(&tx, ids)?;
                annotations::delete_tables(&tx, ids)?;
            }
            tx.commit()?;
        } else {
            for id in ids {
                self.memory.remove(id);
            }
        }
        for id in ids {
            self.history_changes.record(*id);
        }
        self.workspace = workspace;
        self.ws_sessions.retain(|id, _| !deleted.contains(id));
        self.ws_summaries.retain(|(id, _), _| !deleted.contains(id));
        self.ws_memory.retain(|(id, _), _| !deleted.contains(id));
        self.annotations.retain(|id, _| !deleted.contains(id));
        Ok(())
    }
    pub fn get(&self, id: u64) -> Result<Option<Exchange>> {
        if let Some(db) = &self.db {
            let tx = db.begin_read()?;
            Ok(tx
                .open_table(FLOWS)?
                .get(id)?
                .map(|v| serde_json::from_slice(v.value()))
                .transpose()?)
        } else {
            Ok(self.memory.get(&id).map(|flow| (**flow).clone()))
        }
    }
    pub fn list(&self) -> Result<Vec<Exchange>> {
        if let Some(db) = &self.db {
            let tx = db.begin_read()?;
            tx.open_table(FLOWS)?
                .iter()?
                .map(|item| {
                    let (_, value) = item?;
                    Ok(serde_json::from_slice(value.value())?)
                })
                .collect()
        } else {
            Ok(self.memory.values().map(|flow| (**flow).clone()).collect())
        }
    }
    /// Move the current in-memory project to a new disk file without replacing
    /// the surrounding engine or losing IDs already reserved by active work.
    pub fn save_to_disk(&mut self, path: &Path) -> Result<()> {
        ensure!(self.db.is_none(), "Project is already on disk");
        let directory = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let staged = tempfile::NamedTempFile::new_in(directory)?.into_temp_path();
        {
            let db = database_builder().create(&staged)?;
            let mut disk = Self::from_database(db, path)?;
            disk.workspace = self.workspace.clone();
            if disk.workspace.name == "Temporary project"
                && let Some(name) = path.file_stem().filter(|name| !name.is_empty())
            {
                disk.workspace.name = name.to_string_lossy().into_owned();
            }
            disk.save_workspace()?;
            if let Some(secret) = &self.secret {
                disk.set_ca_key(secret.clone())?;
            }
            self.copy_history(&mut disk)?;
            self.copy_websockets(&mut disk)?;
            self.copy_scanner(&mut disk)?;
            self.copy_audit(&mut disk)?;
            self.copy_annotations(&mut disk)?;
        }
        // The native save dialog confirms replacement; only replace after the
        // complete project has been written successfully.
        staged
            .persist(path)
            .with_context(|| format!("Save project {}", path.display()))?;
        let mut disk = Self::open_existing(path)?;
        // A live temporary project retains its running scanner checkpoints.
        self.copy_scanner(&mut disk)?;
        // Moving a live temporary project to disk must not interrupt its sessions.
        for session in self.ws_sessions.values() {
            disk.put_ws_session(session.clone())?;
        }
        for summary in self.ws_summaries.values() {
            if summary.disposition == crate::websocket::Disposition::Pending
                && let Some(message) = self.ws_message(summary.session_id, summary.sequence)?
            {
                disk.put_ws_message(message)?;
            }
        }
        disk.next_id = disk.next_id.max(self.next_id);
        disk.history_changes = self.history_changes.clone();
        *self = disk;
        Ok(())
    }
    pub fn save_as(&self, path: &Path) -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(path)
            .with_context(|| format!("Create {}", path.display()))?;
        let result = (|| -> Result<()> {
            let db = database_builder()
                .create(path)
                .with_context(|| format!("Create project {}", path.display()))?;
            let mut dest = Self::from_database(db, path)?;
            dest.workspace = self.workspace.clone();
            dest.save_workspace()?;
            if let Some(secret) = &self.secret {
                dest.set_ca_key(secret.clone())?;
            }
            self.copy_history(&mut dest)?;
            self.copy_websockets(&mut dest)?;
            self.copy_scanner(&mut dest)?;
            self.copy_audit(&mut dest)?;
            self.copy_annotations(&mut dest)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result?;
        Ok(())
    }
}

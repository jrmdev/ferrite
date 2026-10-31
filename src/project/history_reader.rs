use super::{Database, Exchange, FLOWS};
use anyhow::Result;
use std::sync::Arc;

/// Read access to stored exchanges that does not hold the project lock, so
/// long scans never delay proxy recording. Disk projects read a consistent
/// redb snapshot; temporary projects read a snapshot of shared exchanges.
pub struct HistoryReader {
    pub(super) db: Option<Arc<Database>>,
    pub(super) memory: Vec<Arc<Exchange>>,
}
impl HistoryReader {
    pub fn get(&self, id: u64) -> Result<Option<Exchange>> {
        if let Some(db) = &self.db {
            let tx = db.begin_read()?;
            Ok(tx
                .open_table(FLOWS)?
                .get(id)?
                .map(|v| serde_json::from_slice(v.value()))
                .transpose()?)
        } else {
            Ok(self
                .memory
                .binary_search_by_key(&id, |flow| flow.id)
                .ok()
                .map(|index| (*self.memory[index]).clone()))
        }
    }
    pub fn len(&self) -> Result<u64> {
        if let Some(db) = &self.db {
            use redb::ReadableTableMetadata;
            Ok(db.begin_read()?.open_table(FLOWS)?.len()?)
        } else {
            Ok(self.memory.len() as u64)
        }
    }
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
    /// Visit exchanges newest first with IDs below `before`, until `visit`
    /// returns false.
    pub fn scan_desc(
        &self,
        before: Option<u64>,
        mut visit: impl FnMut(Exchange) -> Result<bool>,
    ) -> Result<()> {
        let end = before.unwrap_or(u64::MAX);
        if let Some(db) = &self.db {
            let tx = db.begin_read()?;
            let table = tx.open_table(FLOWS)?;
            for item in table.range(..end)?.rev() {
                let (_, value) = item?;
                if !visit(serde_json::from_slice(value.value())?)? {
                    break;
                }
            }
        } else {
            for flow in self.memory.iter().rev().filter(|flow| flow.id < end) {
                if !visit((**flow).clone())? {
                    break;
                }
            }
        }
        Ok(())
    }
}

impl super::Project {
    pub(super) fn copy_history(&self, dest: &mut Self) -> Result<()> {
        use redb::ReadableTable;
        if let Some(db) = &self.db {
            let tx = db.begin_read()?;
            for item in tx.open_table(FLOWS)?.iter()? {
                let (_, value) = item?;
                dest.insert(serde_json::from_slice(value.value())?)?;
            }
        } else {
            for flow in self.memory.values() {
                dest.record(flow)?;
            }
        }
        Ok(())
    }
}

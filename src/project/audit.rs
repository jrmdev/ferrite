use super::*;
use crate::mcp::AuditEntry;

const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("mcp_audit");
/// Recent entries kept in memory for display; the table keeps the full trail.
const RECENT: usize = 1000;

impl Project {
    pub(super) fn load_audit(&mut self) -> Result<()> {
        let Some(db) = &self.db else {
            return Ok(());
        };
        let tx = db.begin_write()?;
        tx.open_table(AUDIT)?;
        tx.commit()?;
        let tx = db.begin_read()?;
        let table = tx.open_table(AUDIT)?;
        let mut recent = vec![];
        for item in table.iter()?.rev().take(RECENT) {
            let (_, value) = item?;
            recent.push(serde_json::from_slice(value.value())?);
        }
        recent.reverse();
        self.audit = recent;
        Ok(())
    }
    /// Append an MCP audit entry, assigning its ID.
    pub fn append_audit(&mut self, mut entry: AuditEntry) -> Result<AuditEntry> {
        let last = if let Some(db) = &self.db {
            let tx = db.begin_read()?;
            tx.open_table(AUDIT)?.last()?.map(|(k, _)| k.value())
        } else {
            self.audit.last().map(|e| e.id)
        };
        entry.id = last.map_or(1, |id| id.saturating_add(1));
        if let Some(db) = &self.db {
            let bytes = serde_json::to_vec(&entry)?;
            let tx = db.begin_write()?;
            tx.open_table(AUDIT)?.insert(entry.id, bytes.as_slice())?;
            tx.commit()?;
        }
        if self.audit.len() >= RECENT {
            self.audit.remove(0);
        }
        self.audit.push(entry.clone());
        Ok(entry)
    }
    /// The most recent audit entries, oldest first.
    pub fn audit_entries(&self) -> &[AuditEntry] {
        &self.audit
    }
    pub(super) fn copy_audit(&self, dest: &mut Project) -> Result<()> {
        if let Some(db) = &self.db {
            let tx = db.begin_read()?;
            for item in tx.open_table(AUDIT)?.iter()? {
                let (_, value) = item?;
                dest.append_audit(serde_json::from_slice(value.value())?)?;
            }
        } else {
            for entry in &self.audit {
                dest.append_audit(entry.clone())?;
            }
        }
        Ok(())
    }
}

use super::*;
use crate::scanner::{Finding, ScanJob, ScanStatus};

const JOBS: TableDefinition<u64, &[u8]> = TableDefinition::new("scanner_jobs");
const FINDINGS: TableDefinition<u64, &[u8]> = TableDefinition::new("scanner_findings");
/// Maps a resumable scan note (`scan:{job};item:{item};probe:{n}` or
/// `...;baseline`) to the exchange that satisfied it. This avoids deserializing
/// the complete capture history for every scan item on resume.
const NOTES: TableDefinition<&str, &[u8]> = TableDefinition::new("scanner_notes");
// Retained findings and exchanges still refer to deleted scans by id.
const LAST_DELETED_SCAN_ID: &str = "last-deleted-scan-id";
/// Retained evidence per finding. Repeated passive observations must not grow a
/// finding without bound.
const EVIDENCE_LIMIT: usize = 8;

impl Project {
    pub(super) fn load_scanner(&mut self) -> Result<()> {
        let Some(db) = &self.db else {
            return Ok(());
        };
        let tx = db.begin_write()?;
        tx.open_table(JOBS)?;
        tx.open_table(FINDINGS)?;
        tx.open_table(NOTES)?;
        tx.commit()?;
        {
            let tx = db.begin_read()?;
            if let Some(id) = tx.open_table(META)?.get(LAST_DELETED_SCAN_ID)? {
                self.last_deleted_scan_id = serde_json::from_slice(id.value())?;
            }
            for item in tx.open_table(JOBS)?.iter()? {
                let (key, value) = item?;
                let job: ScanJob = serde_json::from_slice(value.value())?;
                job.settings.validate()?;
                self.scan_jobs.insert(key.value(), job);
            }
            for item in tx.open_table(FINDINGS)?.iter()? {
                let (key, value) = item?;
                self.findings
                    .insert(key.value(), serde_json::from_slice(value.value())?);
            }
        }
        let interrupted: Vec<_> = self
            .scan_jobs
            .values()
            .filter(|j| j.status.unfinished())
            .cloned()
            .collect();
        for mut job in interrupted {
            job.status = ScanStatus::Interrupted;
            job.message =
                "Scan interrupted when the project was closed; resume explicitly to continue"
                    .into();
            job.updated_ms = crate::scanner::now();
            for item in &mut job.items {
                if item.status.unfinished() {
                    item.status = ScanStatus::Interrupted;
                }
            }
            self.put_scan_job(job)?;
        }
        // A finished job cannot resume, so its note index is dead weight.
        let finished: Vec<u64> = self
            .scan_jobs
            .values()
            .filter(|job| !matches!(job.status, ScanStatus::Interrupted))
            .map(|job| job.id)
            .collect();
        for id in finished {
            self.clear_scan_notes(id)?;
        }
        if let Some(db) = &self.db {
            let tx = db.begin_read()?;
            for item in tx.open_table(NOTES)?.iter()? {
                let (key, value) = item?;
                let Ok(text) = std::str::from_utf8(value.value()) else {
                    continue;
                };
                let Some((id, ok)) = text.split_once(':') else {
                    continue;
                };
                if let Ok(id) = id.parse::<u64>() {
                    self.scan_index
                        .insert(key.value().to_owned(), (id, ok == "1"));
                }
            }
        }
        Ok(())
    }
    pub fn allocate_scan_id(&self) -> u64 {
        self.scan_jobs
            .last_key_value()
            .map_or(0, |(id, _)| *id)
            .max(self.last_deleted_scan_id)
            .saturating_add(1)
    }
    pub fn scan_jobs(&self) -> Vec<ScanJob> {
        self.scan_jobs.values().rev().cloned().collect()
    }
    pub fn scan_job(&self, id: u64) -> Option<ScanJob> {
        self.scan_jobs.get(&id).cloned()
    }
    pub(crate) fn contains_scan_job(&self, id: u64) -> bool {
        self.scan_jobs.contains_key(&id)
    }
    pub fn put_scan_job(&mut self, job: ScanJob) -> Result<()> {
        job.settings.validate()?;
        if let Some(db) = &self.db {
            let bytes = serde_json::to_vec(&job)?;
            let tx = db.begin_write()?;
            tx.open_table(JOBS)?.insert(job.id, bytes.as_slice())?;
            tx.commit()?;
        }
        self.scan_jobs.insert(job.id, job);
        Ok(())
    }
    /// Batch note writes into one transaction.
    pub(crate) fn put_scan_notes(&mut self, notes: &[(String, u64, bool)]) -> Result<()> {
        if notes.is_empty() {
            return Ok(());
        }
        for (note, exchange, ok) in notes {
            self.scan_index.insert(note.clone(), (*exchange, *ok));
        }
        if let Some(db) = &self.db {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(NOTES)?;
                for (note, exchange, ok) in notes {
                    let value = format!("{exchange}:{}", u8::from(*ok));
                    table.insert(note.as_str(), value.as_bytes())?;
                }
            }
            tx.commit()?;
        }
        Ok(())
    }
    /// Note entries for one prefix, ordered by note. Reads the in-memory index
    /// rather than the capture history.
    pub(crate) fn scan_notes(&self, prefix: &str) -> Result<Vec<(String, u64, bool)>> {
        Ok(self
            .scan_index
            .range(prefix.to_owned()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, (id, ok))| (key.clone(), *id, *ok))
            .collect())
    }
    pub(crate) fn clear_scan_notes(&mut self, job: u64) -> Result<()> {
        let prefix = format!("scan:{job};");
        if let Some(db) = &self.db {
            let tx = db.begin_write()?;
            remove_scan_notes(&tx, &prefix)?;
            tx.commit()?;
        }
        self.scan_index.retain(|key, _| !key.starts_with(&prefix));
        Ok(())
    }
    pub(crate) fn delete_scan_job(&mut self, id: u64) -> Result<()> {
        ensure!(self.contains_scan_job(id), "Scan does not exist");
        let last_deleted = self.last_deleted_scan_id.max(id);
        let prefix = format!("scan:{id};");
        if let Some(db) = &self.db {
            let tx = db.begin_write()?;
            tx.open_table(JOBS)?.remove(id)?;
            remove_scan_notes(&tx, &prefix)?;
            write_last_deleted_scan_id(&tx, last_deleted)?;
            tx.commit()?;
        }
        self.scan_index.retain(|key, _| !key.starts_with(&prefix));
        self.scan_jobs.remove(&id);
        self.last_deleted_scan_id = last_deleted;
        Ok(())
    }
    pub fn findings(&self) -> Vec<Finding> {
        self.findings.values().rev().cloned().collect()
    }
    pub fn finding_count(&self, scan_id: Option<u64>) -> usize {
        self.findings
            .values()
            .filter(|f| scan_id.is_none_or(|id| f.scan_ids.contains(&id)))
            .count()
    }
    pub fn finding(&self, id: u64) -> Option<Finding> {
        self.findings.get(&id).cloned()
    }
    pub fn put_finding(&mut self, finding: Finding) -> Result<()> {
        if let Some(db) = &self.db {
            let bytes = serde_json::to_vec(&finding)?;
            let tx = db.begin_write()?;
            tx.open_table(FINDINGS)?
                .insert(finding.id, bytes.as_slice())?;
            tx.commit()?;
        }
        self.findings.insert(finding.id, finding);
        Ok(())
    }
    /// Merge a candidate into the finding set.
    pub fn upsert_finding(&mut self, incoming: Finding) -> Result<Finding> {
        Ok(self.upsert_finding_tracked(incoming)?.0)
    }
    /// Merge a candidate and report whether it was created or newly associated
    /// with one of its scan ids, so callers do not need to rescan every finding
    /// to compute a delta.
    pub fn upsert_finding_tracked(&mut self, mut incoming: Finding) -> Result<(Finding, bool)> {
        fn location(f: &Finding) -> String {
            url::Url::parse(&f.url)
                .map(|mut u| {
                    u.set_query(None);
                    u.set_fragment(None);
                    u.to_string()
                })
                .unwrap_or_else(|_| f.url.clone())
        }
        fn push_evidence(finding: &mut Finding, evidence: crate::scanner::Evidence) {
            let duplicate = finding.evidence.iter().any(|existing| {
                existing.label == evidence.label
                    && existing.exchange.request == evidence.exchange.request
                    && existing.exchange.response == evidence.exchange.response
            });
            if duplicate {
                return;
            }
            finding.evidence.push(evidence);
            if finding.evidence.len() > EVIDENCE_LIMIT {
                // Keep the earliest context (usually the control/baseline) and
                // the newest observations instead of letting the list grow.
                let tail = EVIDENCE_LIMIT / 2;
                let head = EVIDENCE_LIMIT - tail;
                let split = finding.evidence.len() - tail;
                let newest = finding.evidence.split_off(split);
                finding.evidence.truncate(head);
                finding.evidence.extend(newest);
            }
        }
        let existing = self
            .findings
            .values()
            .find(|f| {
                f.issue_id == incoming.issue_id
                    && f.method == incoming.method
                    && f.insertion_point == incoming.insertion_point
                    && location(f) == location(&incoming)
            })
            .cloned();
        if let Some(mut finding) = existing {
            let attached = incoming
                .scan_ids
                .iter()
                .any(|id| !finding.scan_ids.contains(id));
            finding.last_seen_ms = incoming.last_seen_ms;
            finding.occurrences = finding.occurrences.saturating_add(1);
            finding.confidence = finding.confidence.max(incoming.confidence);
            for origin in incoming.origins {
                if !finding.origins.contains(&origin) {
                    finding.origins.push(origin);
                }
            }
            for id in incoming.scan_ids {
                if !finding.scan_ids.contains(&id) {
                    finding.scan_ids.push(id);
                }
            }
            for evidence in incoming.evidence {
                push_evidence(&mut finding, evidence);
            }
            self.put_finding(finding.clone())?;
            Ok((finding, attached))
        } else {
            let attached = true;
            incoming.id = self
                .findings
                .last_key_value()
                .map_or(1, |(id, _)| id.saturating_add(1));
            if incoming.evidence.len() > EVIDENCE_LIMIT {
                let tail = EVIDENCE_LIMIT / 2;
                let split = incoming.evidence.len() - tail;
                let newest = incoming.evidence.split_off(split);
                incoming.evidence.truncate(EVIDENCE_LIMIT - tail);
                incoming.evidence.extend(newest);
            }
            self.put_finding(incoming.clone())?;
            Ok((incoming, attached))
        }
    }
    pub(super) fn copy_scanner(&self, dest: &mut Project) -> Result<()> {
        if self.last_deleted_scan_id > dest.last_deleted_scan_id {
            if let Some(db) = &dest.db {
                let tx = db.begin_write()?;
                write_last_deleted_scan_id(&tx, self.last_deleted_scan_id)?;
                tx.commit()?;
            }
            dest.last_deleted_scan_id = self.last_deleted_scan_id;
        }
        for job in self.scan_jobs.values() {
            dest.put_scan_job(job.clone())?;
        }
        for finding in self.findings.values() {
            dest.put_finding(finding.clone())?;
        }
        let notes: Vec<_> = self
            .scan_index
            .iter()
            .map(|(note, (id, ok))| (note.clone(), *id, *ok))
            .collect();
        dest.put_scan_notes(&notes)?;
        Ok(())
    }
}

fn remove_scan_notes(tx: &redb::WriteTransaction, prefix: &str) -> Result<()> {
    let mut table = tx.open_table(NOTES)?;
    let mut keys = Vec::new();
    for entry in table.range(prefix..)? {
        let (key, _) = entry?;
        if !key.value().starts_with(prefix) {
            break;
        }
        keys.push(key.value().to_owned());
    }
    for key in keys {
        table.remove(key.as_str())?;
    }
    Ok(())
}

fn write_last_deleted_scan_id(tx: &redb::WriteTransaction, id: u64) -> Result<()> {
    let bytes = serde_json::to_vec(&id)?;
    tx.open_table(META)?
        .insert(LAST_DELETED_SCAN_ID, bytes.as_slice())?;
    Ok(())
}

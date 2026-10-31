use std::collections::VecDeque;

const CHANGE_LIMIT: usize = 4096;

/// A bounded journal of committed IDs, including out-of-order completions.
#[derive(Clone, Default)]
pub(super) struct Changes {
    revision: u64,
    ids: VecDeque<u64>,
}

impl Changes {
    pub fn record(&mut self, id: u64) {
        self.revision += 1;
        self.ids.push_back(id);
        if self.ids.len() > CHANGE_LIMIT {
            self.ids.pop_front();
        }
    }
}

#[cfg(any(feature = "gui", test))]
impl super::Project {
    /// Update the GUI snapshot without decoding or copying unchanged bodies.
    /// Read failures leave both the snapshot and its revision untouched.
    pub(crate) fn sync_history(
        &self,
        rows: &mut Vec<std::sync::Arc<crate::model::Exchange>>,
        revision: &mut Option<u64>,
    ) -> anyhow::Result<Vec<std::sync::Arc<crate::model::Exchange>>> {
        use redb::ReadableTable;
        use std::{collections::BTreeSet, sync::Arc};

        let changes = &self.history_changes;
        if *revision == Some(changes.revision) {
            return Ok(vec![]);
        }
        let pending = revision
            .and_then(|r| changes.revision.checked_sub(r))
            .filter(|count| *count <= changes.ids.len() as u64);
        let mut added = Vec::new();
        if let Some(count) = pending {
            let ids: BTreeSet<_> = changes
                .ids
                .iter()
                .rev()
                .take(count as usize)
                .copied()
                .collect();
            let updates: Vec<_> = if let Some(db) = &self.db {
                let tx = db.begin_read()?;
                let table = tx.open_table(super::FLOWS)?;
                ids.iter()
                    .map(|id| {
                        table
                            .get(*id)?
                            .map(|value| {
                                serde_json::from_slice(value.value())
                                    .map(Arc::new)
                                    .map_err(Into::into)
                            })
                            .transpose()
                    })
                    .collect::<anyhow::Result<_>>()?
            } else {
                ids.iter().map(|id| self.memory.get(id).cloned()).collect()
            };
            if rows
                .last()
                .is_none_or(|last| ids.first().is_some_and(|id| *id > last.id))
            {
                added.extend(updates.into_iter().flatten());
                rows.extend(added.iter().cloned());
                *revision = Some(changes.revision);
                return Ok(added);
            }
            for flow in updates.iter().flatten() {
                if rows.binary_search_by_key(&flow.id, |row| row.id).is_err() {
                    added.push(flow.clone());
                }
            }
            rows.retain(|row| !ids.contains(&row.id));
            rows.extend(updates.into_iter().flatten());
            rows.sort_unstable_by_key(|row| row.id);
        } else {
            let snapshot: Vec<_> = if let Some(db) = &self.db {
                let tx = db.begin_read()?;
                tx.open_table(super::FLOWS)?
                    .iter()?
                    .map(|item| {
                        let (_, value) = item?;
                        Ok(Arc::new(serde_json::from_slice(value.value())?))
                    })
                    .collect::<anyhow::Result<_>>()?
            } else {
                self.memory.values().cloned().collect()
            };
            for flow in &snapshot {
                if rows.binary_search_by_key(&flow.id, |row| row.id).is_err() {
                    added.push(flow.clone());
                }
            }
            *rows = snapshot;
        }
        *revision = Some(changes.revision);
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{Destination, Exchange},
        project::Project,
    };
    use std::sync::Arc;

    fn flow(id: u64) -> Exchange {
        Exchange {
            id,
            timestamp_ms: 0,
            tool: "Proxy".into(),
            destination: Destination::from_url("http://example.com").unwrap(),
            method: "GET".into(),
            url: "http://example.com/".into(),
            request: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            response: vec![b'x'; 1024],
            status: 200,
            duration_ms: 0,
            error: None,
            note: String::new(),
        }
    }

    #[test]
    fn incremental_history_handles_replacements_deletions_and_late_completions() {
        let dir = tempfile::tempdir().unwrap();
        for mut project in [
            Project::temporary(),
            Project::create(&dir.path().join("history.ferrite")).unwrap(),
        ] {
            project.insert(flow(3)).unwrap();
            let (mut rows, mut revision) = (vec![], None);
            assert_eq!(
                project
                    .sync_history(&mut rows, &mut revision)
                    .unwrap()
                    .len(),
                1
            );
            let original = rows[0].clone();
            if project.db.is_none() {
                assert!(Arc::ptr_eq(&original, &project.memory[&3]));
            }
            project.insert(flow(1)).unwrap();
            project.insert(flow(5)).unwrap();
            let added = project.sync_history(&mut rows, &mut revision).unwrap();
            assert_eq!(added.iter().map(|f| f.id).collect::<Vec<_>>(), [1, 5]);
            assert!(Arc::ptr_eq(&original, &rows[1]));
            assert!(
                project
                    .sync_history(&mut rows, &mut revision)
                    .unwrap()
                    .is_empty()
            );
            let mut replaced = flow(3);
            replaced.response = b"updated".to_vec();
            project.insert(replaced).unwrap();
            project.delete(&[1, 5]).unwrap();
            assert!(
                project
                    .sync_history(&mut rows, &mut revision)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].response, b"updated");
            assert!(!Arc::ptr_eq(&original, &rows[0]));
        }
    }

    #[test]
    fn failed_snapshot_read_can_be_retried_without_losing_updates() {
        let dir = tempfile::tempdir().unwrap();
        let mut project = Project::create(&dir.path().join("history.ferrite")).unwrap();
        project.insert(flow(1)).unwrap();
        let (mut rows, mut revision) = (vec![], None);
        project.sync_history(&mut rows, &mut revision).unwrap();
        let original = rows[0].clone();
        let previous_revision = revision;
        project.insert(flow(2)).unwrap();
        let tx = project.db.as_ref().unwrap().begin_write().unwrap();
        tx.open_table(super::super::FLOWS)
            .unwrap()
            .insert(2, b"invalid".as_slice())
            .unwrap();
        tx.commit().unwrap();
        assert!(project.sync_history(&mut rows, &mut revision).is_err());
        assert_eq!(revision, previous_revision);
        assert_eq!(rows.len(), 1);
        assert!(Arc::ptr_eq(&original, &rows[0]));
        project.insert(flow(2)).unwrap();
        project.sync_history(&mut rows, &mut revision).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(Arc::ptr_eq(&original, &rows[0]));
    }

    #[test]
    fn journal_is_bounded_and_slow_consumers_resynchronize() {
        let mut project = Project::temporary();
        let (mut rows, mut revision) = (vec![], None);
        project.sync_history(&mut rows, &mut revision).unwrap();
        for id in 1..=CHANGE_LIMIT as u64 + 1 {
            project.insert(flow(id)).unwrap();
        }
        assert_eq!(project.history_changes.ids.len(), CHANGE_LIMIT);
        project.sync_history(&mut rows, &mut revision).unwrap();
        assert_eq!(rows.len(), CHANGE_LIMIT + 1);
        assert_eq!(rows.first().unwrap().id, 1);
    }

    #[test]
    fn saving_live_project_preserves_the_history_revision() {
        let dir = tempfile::tempdir().unwrap();
        let mut project = Project::temporary();
        project.insert(flow(2)).unwrap();
        let (mut rows, mut revision) = (vec![], None);
        project.sync_history(&mut rows, &mut revision).unwrap();
        let original = rows[0].clone();
        project
            .save_to_disk(&dir.path().join("saved.ferrite"))
            .unwrap();
        project.insert(flow(1)).unwrap();
        project.sync_history(&mut rows, &mut revision).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(Arc::ptr_eq(&original, &rows[1]));
    }
}

use super::*;
use crate::history::Annotation;

const ANNOTATIONS: TableDefinition<u64, &[u8]> = TableDefinition::new("exchange_annotations");

pub(super) fn delete_tables(tx: &redb::WriteTransaction, ids: &[u64]) -> Result<()> {
    let mut table = tx.open_table(ANNOTATIONS)?;
    for id in ids {
        table.remove(*id)?;
    }
    Ok(())
}

impl Project {
    pub(super) fn load_annotations(&mut self) -> Result<()> {
        let Some(db) = &self.db else {
            return Ok(());
        };
        let tx = db.begin_write()?;
        tx.open_table(ANNOTATIONS)?;
        tx.commit()?;
        let tx = db.begin_read()?;
        for item in tx.open_table(ANNOTATIONS)?.iter()? {
            let (key, value) = item?;
            self.annotations
                .insert(key.value(), serde_json::from_slice(value.value())?);
        }
        Ok(())
    }
    pub fn annotation(&self, id: u64) -> Option<&Annotation> {
        self.annotations.get(&id)
    }
    pub fn annotations(&self) -> &BTreeMap<u64, Annotation> {
        &self.annotations
    }
    /// Set or clear (when empty) the annotations of several exchanges at once.
    pub fn set_annotations(&mut self, changes: &[(u64, Annotation)]) -> Result<()> {
        if let Some(db) = &self.db {
            let tx = db.begin_write()?;
            {
                let mut table = tx.open_table(ANNOTATIONS)?;
                for (id, annotation) in changes {
                    if annotation.is_empty() {
                        table.remove(*id)?;
                    } else {
                        table.insert(*id, serde_json::to_vec(annotation)?.as_slice())?;
                    }
                }
            }
            tx.commit()?;
        }
        for (id, annotation) in changes {
            if annotation.is_empty() {
                self.annotations.remove(id);
            } else {
                self.annotations.insert(*id, annotation.clone());
            }
        }
        Ok(())
    }
    pub(super) fn copy_annotations(&self, dest: &mut Project) -> Result<()> {
        let all: Vec<_> = self
            .annotations
            .iter()
            .map(|(id, a)| (*id, a.clone()))
            .collect();
        dest.set_annotations(&all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{history::Highlight, model::Destination};

    fn flow(id: u64) -> Exchange {
        Exchange {
            id,
            timestamp_ms: 0,
            tool: "Proxy".into(),
            destination: Destination::from_url("http://a.test").unwrap(),
            url: "http://a.test/".into(),
            method: "GET".into(),
            request: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            response: vec![],
            status: 200,
            duration_ms: 0,
            error: None,
            note: String::new(),
        }
    }

    #[test]
    fn annotations_persist_follow_deletes_and_copy_with_save_as() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.ferrite");
        let mut project = Project::create(&path).unwrap();
        project.insert(flow(1)).unwrap();
        project.insert(flow(2)).unwrap();
        let note = Annotation {
            comment: "check auth".into(),
            highlight: Some(Highlight::Red),
        };
        project
            .set_annotations(&[(1, note.clone()), (2, note.clone())])
            .unwrap();
        drop(project);
        let mut project = Project::open_existing(&path).unwrap();
        assert_eq!(project.annotation(1), Some(&note));
        project.delete(&[2]).unwrap();
        assert!(project.annotation(2).is_none());
        project
            .set_annotations(&[(1, Annotation::default())])
            .unwrap();
        assert!(project.annotations().is_empty());
        project.set_annotations(&[(1, note.clone())]).unwrap();
        let copy = dir.path().join("b.ferrite");
        project.save_as(&copy).unwrap();
        drop(project);
        assert_eq!(
            Project::open_existing(&path).unwrap().annotations().len(),
            1
        );
        assert_eq!(
            Project::open_existing(&copy).unwrap().annotation(1),
            Some(&note)
        );
        // Temporary projects keep annotations in memory.
        let mut temporary = Project::temporary();
        temporary.set_annotations(&[(7, note.clone())]).unwrap();
        assert_eq!(temporary.annotation(7), Some(&note));
    }
}

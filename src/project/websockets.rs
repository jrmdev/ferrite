use super::*;
use crate::websocket::{Disposition, SessionState, now};

const SESSIONS: TableDefinition<u64, &[u8]> = TableDefinition::new("websocket_sessions");
const MESSAGES: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("websocket_messages");
const SUMMARIES: TableDefinition<(u64, u64), &[u8]> =
    TableDefinition::new("websocket_message_summaries");

pub(super) fn delete_tables(tx: &redb::WriteTransaction, ids: &[u64]) -> Result<()> {
    let mut sessions = tx.open_table(SESSIONS)?;
    let mut messages = tx.open_table(MESSAGES)?;
    let mut summaries = tx.open_table(SUMMARIES)?;
    for id in ids {
        sessions.remove(*id)?;
        let keys: Vec<_> = summaries
            .range((*id, 0)..=(*id, u64::MAX))?
            .map(|item| item.map(|(key, _)| key.value()))
            .collect::<std::result::Result<_, _>>()?;
        for key in keys {
            messages.remove(key)?;
            summaries.remove(key)?;
        }
    }
    Ok(())
}

impl Project {
    pub(super) fn load_websockets(&mut self) -> Result<()> {
        let Some(db) = &self.db else {
            return Ok(());
        };
        let tx = db.begin_write()?;
        tx.open_table(SESSIONS)?;
        tx.open_table(MESSAGES)?;
        tx.open_table(SUMMARIES)?;
        tx.commit()?;
        {
            let tx = db.begin_read()?;
            for item in tx.open_table(SESSIONS)?.iter()? {
                let (key, value) = item?;
                self.ws_sessions
                    .insert(key.value(), serde_json::from_slice(value.value())?);
            }
            for item in tx.open_table(SUMMARIES)?.iter()? {
                let (key, value) = item?;
                self.ws_summaries
                    .insert(key.value(), serde_json::from_slice(value.value())?);
            }
        }
        let unfinished: Vec<_> = self
            .ws_sessions
            .values()
            .filter(|s| s.state == SessionState::Open)
            .cloned()
            .collect();
        for mut session in unfinished {
            session.state = SessionState::Interrupted;
            session.closed_ms = Some(now());
            session.error = Some("Session interrupted when the project was closed".into());
            self.put_ws_session(session)?;
        }
        let pending: Vec<_> = self
            .ws_summaries
            .values()
            .filter(|m| m.disposition == Disposition::Pending)
            .map(|m| (m.session_id, m.sequence))
            .collect();
        for (id, seq) in pending {
            if let Some(mut message) = self.ws_message(id, seq)? {
                message.summary.disposition = Disposition::Interrupted;
                message.error = Some("Message was not forwarded before the session ended".into());
                self.put_ws_message(message)?;
            }
        }
        Ok(())
    }
    pub fn ws_sessions(&self) -> Vec<Session> {
        self.ws_sessions.values().rev().cloned().collect()
    }
    pub fn ws_session(&self, id: u64) -> Option<Session> {
        self.ws_sessions.get(&id).cloned()
    }
    pub fn ws_summaries(&self, id: u64) -> Vec<MessageSummary> {
        self.ws_summaries
            .range((id, 0)..=(id, u64::MAX))
            .map(|(_, summary)| summary.clone())
            .collect()
    }
    pub fn ws_summaries_after(&self, id: u64, sequence: u64) -> Vec<MessageSummary> {
        self.ws_summaries
            .range((
                std::ops::Bound::Excluded((id, sequence)),
                std::ops::Bound::Included((id, u64::MAX)),
            ))
            .map(|(_, summary)| summary.clone())
            .collect()
    }
    pub fn ws_summary(&self, id: u64, sequence: u64) -> Option<MessageSummary> {
        self.ws_summaries.get(&(id, sequence)).cloned()
    }
    pub fn ws_message(&self, id: u64, sequence: u64) -> Result<Option<CapturedMessage>> {
        let key = (id, sequence);
        if let Some(db) = &self.db {
            let tx = db.begin_read()?;
            Ok(tx
                .open_table(MESSAGES)?
                .get(key)?
                .map(|v| serde_json::from_slice(v.value()))
                .transpose()?)
        } else {
            Ok(self.ws_memory.get(&key).cloned())
        }
    }
    pub fn delete_ws_session(&mut self, id: u64) -> Result<()> {
        let session = self
            .ws_sessions
            .get(&id)
            .context("WebSocket session does not exist")?;
        ensure!(
            session.state != SessionState::Open,
            "Close the active WebSocket session before deleting it"
        );
        if let Some(db) = &self.db {
            let tx = db.begin_write()?;
            delete_tables(&tx, &[id])?;
            tx.commit()?;
        }
        self.ws_sessions.remove(&id);
        self.ws_summaries.retain(|(session, _), _| *session != id);
        self.ws_memory.retain(|(session, _), _| *session != id);
        Ok(())
    }
    pub fn export_ws_session(&self, id: u64) -> Result<Vec<u8>> {
        let session = self
            .ws_session(id)
            .context("WebSocket session does not exist")?;
        let messages: Vec<_> = self
            .ws_summaries(id)
            .iter()
            .map(|summary| {
                self.ws_message(id, summary.sequence)?
                    .context("WebSocket message is missing")
            })
            .collect::<Result<_>>()?;
        Ok(serde_json::to_vec_pretty(
            &serde_json::json!({"session": session, "messages": messages}),
        )?)
    }
    pub fn put_ws_session(&mut self, session: Session) -> Result<()> {
        if let Some(db) = &self.db {
            let tx = db.begin_write()?;
            tx.open_table(SESSIONS)?
                .insert(session.id, serde_json::to_vec(&session)?.as_slice())?;
            tx.commit()?;
        }
        self.ws_sessions.insert(session.id, session);
        Ok(())
    }
    pub fn put_ws_message(&mut self, message: CapturedMessage) -> Result<()> {
        let summary = message.summary.clone();
        let key = (summary.session_id, summary.sequence);
        ensure!(
            self.ws_sessions.contains_key(&summary.session_id),
            "WebSocket session does not exist"
        );
        if let Some(db) = &self.db {
            let tx = db.begin_write()?;
            tx.open_table(MESSAGES)?
                .insert(key, serde_json::to_vec(&message)?.as_slice())?;
            tx.open_table(SUMMARIES)?
                .insert(key, serde_json::to_vec(&summary)?.as_slice())?;
            tx.commit()?;
        } else {
            self.ws_memory.insert(key, message);
        }
        self.ws_summaries.insert(key, summary);
        Ok(())
    }
    pub(super) fn copy_websockets(&self, dest: &mut Project) -> Result<()> {
        for session in self.ws_sessions.values() {
            dest.put_ws_session(session.clone())?;
        }
        for &(id, seq) in self.ws_summaries.keys() {
            if let Some(message) = self.ws_message(id, seq)? {
                dest.put_ws_message(message)?;
            }
        }
        Ok(())
    }
}

//! Selected exchanges, with binary-safe messages and no project configuration or CA keys.
use crate::model::{Destination, Exchange};
use base64::{display::Base64Display, engine::general_purpose::STANDARD};
use serde::{Serialize, Serializer};
use std::{
    borrow::Borrow,
    io::{BufWriter, Write},
    path::Path,
};

#[derive(Serialize)]
struct Export<T> {
    format: &'static str,
    version: u32,
    items: T,
}

struct Items<'a, T>(&'a [T]);

#[derive(Serialize)]
struct Item<'a> {
    id: u64,
    timestamp_ms: u64,
    tool: &'a str,
    destination: &'a Destination,
    url: &'a str,
    method: &'a str,
    response_code: u16,
    duration_ms: u64,
    request_bytes: usize,
    response_bytes: usize,
    error: Option<&'a str>,
    note: &'a str,
    #[serde(serialize_with = "base64_bytes")]
    request_base64: &'a [u8],
    #[serde(serialize_with = "base64_bytes")]
    response_base64: &'a [u8],
}

fn base64_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&Base64Display::new(bytes, &STANDARD))
}

impl<T: Borrow<Exchange>> Serialize for Items<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|flow| {
            let flow = flow.borrow();
            Item {
                id: flow.id,
                timestamp_ms: flow.timestamp_ms,
                tool: &flow.tool,
                destination: &flow.destination,
                url: &flow.url,
                method: &flow.method,
                response_code: flow.status,
                duration_ms: flow.duration_ms,
                request_bytes: flow.request.len(),
                response_bytes: flow.response.len(),
                error: flow.error.as_deref(),
                note: &flow.note,
                request_base64: &flow.request,
                response_base64: &flow.response,
            }
        }))
    }
}

pub fn export_selected(path: &Path, exchanges: &[Exchange]) -> anyhow::Result<()> {
    export_items(path, exchanges)
}

pub(crate) fn export_items<T: Borrow<Exchange>>(
    path: &Path,
    exchanges: &[T],
) -> anyhow::Result<()> {
    anyhow::ensure!(!exchanges.is_empty(), "Select at least one history item");
    let export = Export {
        format: "ferrite-history",
        version: 1,
        items: Items(exchanges),
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = BufWriter::new(options.open(path)?);
    let result = (|| -> anyhow::Result<()> {
        serde_json::to_writer_pretty(&mut file, &export)?;
        file.flush()?;
        file.get_ref().sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    result
}

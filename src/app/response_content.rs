use crate::{
    http::Message,
    model::{StreamCapture, StreamReason},
};
use anyhow::{Result, bail, ensure};
use std::{borrow::Cow, io::Read, sync::Arc};

pub(super) const DISPLAY_LIMIT: usize = 3 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BodyOmitted {
    pub bytes: usize,
    pub at_least: bool,
}

impl BodyOmitted {
    pub fn notice(&self) -> String {
        format!(
            "[Body too large to be displayed ({}{} bytes)]",
            if self.at_least { "at least " } else { "" },
            self.bytes
        )
    }
}

pub(super) fn intercept_omission(
    item: &crate::engine::Intercepted,
    limit: usize,
) -> Option<BodyOmitted> {
    if item.stage != crate::engine::Stage::Response {
        return None;
    }
    body_preview(&item.message, limit).omitted
}

pub(super) struct BodyPreview {
    pub body: Vec<u8>,
    pub omitted: Option<BodyOmitted>,
    pub decoded: bool,
}

type Reader<'a> = Box<dyn Read + 'a>;

// A streaming adapter is needed because zstd permits concatenated frames and
// skippable metadata, including when nested inside another content encoding.
struct ZstdReader<'a> {
    source: Option<Reader<'a>>,
    decoder: Option<ruzstd::decoding::StreamingDecoder<Reader<'a>, ruzstd::decoding::FrameDecoder>>,
    limit: usize,
}

impl Read for ZstdReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(decoder) = &mut self.decoder {
                let n = decoder.read(out)?;
                if n > 0 {
                    return Ok(n);
                }
                self.source = Some(self.decoder.take().unwrap().into_inner());
            }
            let mut source = self.source.take().unwrap();
            let mut magic = [0u8; 4];
            if source.read(&mut magic[..1])? == 0 {
                self.source = Some(source);
                return Ok(0);
            }
            source.read_exact(&mut magic[1..])?;
            if (0x184d2a50..=0x184d2a5f).contains(&u32::from_le_bytes(magic)) {
                let mut size = [0; 4];
                source.read_exact(&mut size)?;
                let size = u32::from_le_bytes(size) as u64;
                let copied = std::io::copy(&mut source.by_ref().take(size), &mut std::io::sink())?;
                if copied != size {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                self.source = Some(source);
                continue;
            }
            let source: Reader<'_> = Box::new(std::io::Cursor::new(magic).chain(source));
            self.decoder = Some(
                ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
                    source,
                    self.limit.max(8 * 1024 * 1024) as u64,
                )
                .map_err(std::io::Error::other)?,
            );
        }
    }
}

/// Count decoded bytes while retaining at most the display budget. The original
/// Message remains the source of truth for forwarding and export.
pub(super) fn body_preview(message: &Message, limit: usize) -> BodyPreview {
    body_preview_bytes(message, &message.body, limit)
}

fn body_preview_bytes(message: &Message, raw_body: &[u8], limit: usize) -> BodyPreview {
    let raw = || BodyPreview {
        body: if raw_body.len() <= DISPLAY_LIMIT {
            raw_body.to_vec()
        } else {
            vec![]
        },
        omitted: (raw_body.len() > DISPLAY_LIMIT).then_some(BodyOmitted {
            bytes: raw_body.len(),
            at_least: false,
        }),
        decoded: false,
    };
    let encodings: Vec<_> = message
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Encoding"))
        .flat_map(|(_, value)| value.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    if encodings.is_empty() || encodings.len() > 16 || encodings.iter().all(|s| s == "identity") {
        return raw();
    }
    let mut reader: Reader<'_> = Box::new(raw_body);
    for encoding in encodings.iter().rev() {
        reader = match encoding.as_str() {
            "identity" => reader,
            "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(reader)),
            "br" => Box::new(brotli::Decompressor::new(reader, 4096)),
            "zstd" => Box::new(ZstdReader {
                source: Some(reader),
                decoder: None,
                limit,
            }),
            "deflate" => {
                use std::io::BufRead;
                let mut buffered = std::io::BufReader::new(reader);
                let Ok(header) = buffered.fill_buf() else {
                    return raw();
                };
                if header.len() >= 2
                    && header[0] & 15 == 8
                    && (u16::from_be_bytes([header[0], header[1]]) % 31 == 0)
                {
                    Box::new(flate2::read::ZlibDecoder::new(buffered))
                } else {
                    Box::new(flate2::read::DeflateDecoder::new(buffered))
                }
            }
            _ => return raw(),
        };
        // Bound intermediate expansion as well as the final decoded output.
        reader = Box::new(reader.take(limit.saturating_add(1) as u64));
    }
    let mut body = Vec::new();
    let mut count = 0;
    let mut chunk = [0; 8192];
    loop {
        let n = match reader.read(&mut chunk) {
            Ok(n) => n,
            Err(_) => return raw(),
        };
        if n == 0 {
            break;
        }
        count += n;
        if count <= DISPLAY_LIMIT {
            body.extend_from_slice(&chunk[..n]);
        } else if !body.is_empty() {
            // An omitted preview must not pin the display-sized allocation.
            body = Vec::new();
        }
        if count > limit {
            // A small caller budget still retains the legacy raw fallback.
            if limit < DISPLAY_LIMIT {
                return raw();
            }
            return BodyPreview {
                body: vec![],
                omitted: Some(BodyOmitted {
                    bytes: count,
                    at_least: true,
                }),
                decoded: true,
            };
        }
    }
    BodyPreview {
        body,
        omitted: (count > DISPLAY_LIMIT).then_some(BodyOmitted {
            bytes: count,
            at_least: false,
        }),
        decoded: true,
    }
}

fn bounded_read(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut out)?;
    ensure!(out.len() <= limit, "Decoded response exceeds display limit");
    Ok(out)
}

fn zstd(mut bytes: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        // Zstandard permits concatenated frames and skippable metadata frames.
        if bytes.len() >= 8 {
            let magic = u32::from_le_bytes(bytes[..4].try_into()?);
            if (0x184d2a50..=0x184d2a5f).contains(&magic) {
                let length = u32::from_le_bytes(bytes[4..8].try_into()?) as usize;
                bytes = bytes
                    .get(8..)
                    .and_then(|rest| rest.get(length..))
                    .ok_or_else(|| anyhow::anyhow!("Truncated Zstandard metadata"))?;
                continue;
            }
        }
        let mut decoder = ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
            bytes,
            limit.max(8 * 1024 * 1024) as u64,
        )?;
        out.extend(bounded_read(&mut decoder, limit - out.len())?);
        let rest = decoder.into_inner();
        ensure!(
            rest.len() < bytes.len(),
            "Zstandard decoder made no progress"
        );
        bytes = rest;
    }
    Ok(out)
}

/// Decode a preview copy. Failure always leaves the original message available.
pub(super) fn decoded(message: &Message, limit: usize) -> Option<Message> {
    if !message.start.starts_with("HTTP/") || message.body.is_empty() {
        return None;
    }
    let encodings: Vec<_> = message
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Encoding"))
        .flat_map(|(_, value)| value.split(','))
        .map(|encoding| encoding.trim().to_ascii_lowercase())
        .collect();
    if encodings.is_empty()
        || encodings.len() > 16
        || encodings.iter().all(|encoding| encoding == "identity")
    {
        return None;
    }
    let decode = || -> Result<Vec<u8>> {
        let mut body = Cow::Borrowed(message.body.as_slice());
        for encoding in encodings.iter().rev() {
            let bytes = body.as_ref();
            body = Cow::Owned(match encoding.as_str() {
                "identity" => continue,
                "gzip" | "x-gzip" => bounded_read(flate2::read::MultiGzDecoder::new(bytes), limit)?,
                "deflate" => bounded_read(flate2::read::ZlibDecoder::new(bytes), limit)
                    .or_else(|_| bounded_read(flate2::read::DeflateDecoder::new(bytes), limit))?,
                "br" => bounded_read(brotli::Decompressor::new(bytes, 4096), limit)?,
                "zstd" => zstd(bytes, limit)?,
                _ => bail!("Unsupported content encoding"),
            });
        }
        Ok(body.into_owned())
    };
    let mut preview = Message {
        start: message.start.clone(),
        headers: message.headers.clone(),
        body: decode().ok()?,
    };
    preview.remove("Content-Encoding");
    preview.normalize_length();
    Some(preview)
}

fn display(bytes: &[u8], hex: bool, limit: usize) -> String {
    if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
        let raw_body = &bytes[end + 4..];
        // Hex displays stored bytes, which can be larger than decoded content
        // (for example, zstd skippable metadata). Bound that view independently.
        if hex && raw_body.len() > DISPLAY_LIMIT {
            return format!(
                "{}{}",
                String::from_utf8_lossy(&bytes[..end + 4]),
                BodyOmitted {
                    bytes: raw_body.len(),
                    at_least: false
                }
                .notice()
            );
        }
        // Parse only the headers, avoiding Message::parse's large body copy.
        if let Ok(message) = Message::parse(&bytes[..end + 4]) {
            let preview = if message.header("Content-Encoding").is_some() {
                body_preview_bytes(&message, raw_body, limit)
            } else {
                BodyPreview {
                    body: vec![],
                    decoded: false,
                    omitted: (raw_body.len() > DISPLAY_LIMIT).then_some(BodyOmitted {
                        bytes: raw_body.len(),
                        at_least: false,
                    }),
                }
            };
            if let Some(omitted) = preview.omitted {
                return format!(
                    "{}{}",
                    String::from_utf8_lossy(&bytes[..end + 4]),
                    omitted.notice()
                );
            }
            if !hex && preview.decoded {
                return format!(
                    "{}{}",
                    String::from_utf8_lossy(&bytes[..end + 4]),
                    String::from_utf8_lossy(&preview.body)
                );
            }
        }
    }
    super::http_editor::message_view(bytes, hex)
}

/// Keep one rendered response and refresh it when streaming metadata changes.
#[derive(Default)]
pub(super) struct ResponseCache {
    entry: Option<(ResponseKey, Arc<str>)>,
}

#[derive(PartialEq, Eq)]
struct ResponseKey {
    id: u64,
    hex: bool,
    limit: usize,
    streamed: Option<StreamCapture>,
}

impl ResponseCache {
    pub fn get(
        &mut self,
        id: u64,
        bytes: &[u8],
        omitted: Option<usize>,
        streamed: Option<StreamCapture>,
        hex: bool,
        limit: usize,
    ) -> Arc<str> {
        let key = ResponseKey {
            id,
            hex,
            limit,
            streamed,
        };
        if let Some((cached, text)) = &self.entry
            && *cached == key
        {
            return text.clone();
        }
        let text: Arc<str> = match (streamed.map(|stream| stream.reason), omitted) {
            (Some(StreamReason::CaptureLimit), _) => "[Body too large to be displayed]".into(),
            (Some(StreamReason::Policy), _) => "[Streaming response body omitted]".into(),
            (None, Some(size)) => format!(
                "{}{}",
                String::from_utf8_lossy(bytes),
                BodyOmitted {
                    bytes: size,
                    at_least: false
                }
                .notice(),
            ),
            (None, None) => display(bytes, hex, limit),
        }
        .into();
        self.entry = Some((key, text.clone()));
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn live_response_shows_only_the_notice_and_refreshes_on_completion() {
        let mut cache = ResponseCache::default();
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n";
        let active = StreamCapture {
            reason: StreamReason::Policy,
            declared_bytes: None,
            body_bytes: None,
        };
        let first = cache.get(1, head, None, Some(active), false, 1024);
        assert_eq!(&*first, "[Streaming response body omitted]");
        let complete = StreamCapture {
            body_bytes: Some(128),
            ..active
        };
        let last = cache.get(1, head, None, Some(complete), false, 1024);
        assert_eq!(&*last, &*first);
        assert!(!Arc::ptr_eq(&first, &last));
        let oversized = StreamCapture {
            reason: StreamReason::CaptureLimit,
            ..complete
        };
        assert_eq!(
            &*cache.get(1, head, None, Some(oversized), true, 1024),
            "[Body too large to be displayed]"
        );
    }

    #[test]
    fn captured_oversized_response_displays_headers_and_omission_in_both_modes() {
        let mut cache = ResponseCache::default();
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 9000\r\nX-Test: visible\r\n\r\n";
        for hex in [false, true] {
            assert_eq!(
                &*cache.get(1, headers, Some(9000), None, hex, 1024),
                "HTTP/1.1 200 OK\r\nContent-Length: 9000\r\nX-Test: visible\r\n\r\n[Body too large to be displayed (9000 bytes)]"
            );
        }
    }

    #[test]
    fn display_guard_keeps_headers_and_only_omits_bodies_above_three_mib() {
        for length in [DISPLAY_LIMIT - 1, DISPLAY_LIMIT, DISPLAY_LIMIT + 1] {
            let mut message = Message::parse(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Test: visible\r\n\r\n",
            )
            .unwrap();
            message.body = vec![b'x'; length];
            let bytes = message.encode();
            for hex in [false, true] {
                let rendered = display(&bytes, hex, 32 * 1024 * 1024);
                if length > DISPLAY_LIMIT {
                    assert_eq!(
                        rendered,
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Test: visible\r\n\r\n[Body too large to be displayed ({length} bytes)]"
                        )
                    );
                } else {
                    assert!(!rendered.contains("Body too large"));
                    if !hex {
                        assert_eq!(rendered.as_bytes(), bytes);
                    }
                }
            }
            assert_eq!(message.body.len(), length);
        }
    }

    #[test]
    fn compressed_display_counts_decoded_bytes_without_retaining_large_output() {
        let body = vec![b'a'; DISPLAY_LIMIT + 19001];
        for encoding in ["gzip", "deflate", "br", "zstd"] {
            let message = message(encoding, compress(encoding, &body));
            let preview = body_preview(&message, 32 * 1024 * 1024);
            assert!(preview.body.is_empty());
            assert_eq!(preview.body.capacity(), 0);
            assert_eq!(
                preview.omitted,
                Some(BodyOmitted {
                    bytes: body.len(),
                    at_least: false
                })
            );
            let encoded = message.encode();
            for hex in [false, true] {
                let text = display(&encoded, hex, 32 * 1024 * 1024);
                assert!(text.contains(&format!("Content-Encoding: {encoding}")));
                assert!(text.ends_with(&format!(
                    "[Body too large to be displayed ({} bytes)]",
                    body.len()
                )));
            }
            let limited = body_preview(&message, DISPLAY_LIMIT + 10);
            assert_eq!(
                limited.omitted,
                Some(BodyOmitted {
                    bytes: DISPLAY_LIMIT + 11,
                    at_least: true
                })
            );
        }
    }

    #[test]
    fn large_zstd_metadata_cannot_bypass_the_hex_display_guard() {
        let mut body = 0x184d2a50u32.to_le_bytes().to_vec();
        body.extend_from_slice(&((DISPLAY_LIMIT + 1) as u32).to_le_bytes());
        body.extend(vec![0; DISPLAY_LIMIT + 1]);
        body.extend(compress("zstd", b"small decoded body"));
        let encoded = message("zstd", body).encode();
        assert!(display(&encoded, false, 32 * 1024 * 1024).ends_with("small decoded body"));
        let rendered = display(&encoded, true, 32 * 1024 * 1024);
        assert!(rendered.starts_with("HTTP/2 200\r\nContent-Encoding: zstd\r\n"));
        assert!(rendered.contains("Body too large to be displayed"));
        assert!(rendered.len() < 300);
    }

    fn compress(encoding: &str, body: &[u8]) -> Vec<u8> {
        match encoding {
            "gzip" => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(body).unwrap();
                encoder.finish().unwrap()
            }
            "deflate" => {
                let mut encoder =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(body).unwrap();
                encoder.finish().unwrap()
            }
            "raw-deflate" => {
                let mut encoder =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(body).unwrap();
                encoder.finish().unwrap()
            }
            "br" => {
                let mut out = Vec::new();
                let mut input = body;
                brotli::BrotliCompress(&mut input, &mut out, &Default::default()).unwrap();
                out
            }
            "zstd" => {
                ruzstd::encoding::compress_to_vec(body, ruzstd::encoding::CompressionLevel::Fastest)
            }
            _ => unreachable!(),
        }
    }

    fn message(encoding: &str, body: Vec<u8>) -> Message {
        let mut message = Message::parse(
            format!(
                "HTTP/2 200\r\nContent-Encoding: {encoding}\r\nContent-Type: text/plain\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        message.body = body;
        message
    }

    #[test]
    fn previews_all_supported_encodings_and_preserves_original_headers_and_bytes() {
        let body = "Decoded response: π\n".repeat(100);
        for encoding in ["gzip", "deflate", "raw-deflate", "br", "zstd"] {
            let header = if encoding == "raw-deflate" {
                "deflate"
            } else {
                encoding
            };
            let message = message(header, compress(encoding, body.as_bytes()));
            let original = message.encode();
            let view = display(&original, false, 1024 * 1024);
            assert_eq!(view.split_once("\r\n\r\n").unwrap().1, body, "{encoding}");
            assert!(view.contains(&format!("Content-Encoding: {header}\r\n")));
            assert_eq!(
                super::super::unhex(&display(&original, true, 1024 * 1024)).unwrap(),
                original
            );
            assert_eq!(message.encode(), original);
        }
    }

    #[test]
    fn decodes_stacked_duplicate_headers_and_concatenated_frames() {
        let body = b"stacked body\0\xff";
        let mut stacked = message("GZip, identity", compress("br", &compress("gzip", body)));
        stacked
            .headers
            .push(("content-encoding".into(), " bR ".into()));
        assert_eq!(decoded(&stacked, 4096).unwrap().body, body);
        assert_eq!(body_preview(&stacked, 4096).body, body);
        for encoding in ["gzip", "zstd"] {
            let frames = [compress(encoding, b"one"), compress(encoding, b"two")].concat();
            assert_eq!(
                decoded(&message(encoding, frames), 4096).unwrap().body,
                b"onetwo"
            );
            let frames = [compress(encoding, b"one"), compress(encoding, b"two")].concat();
            assert_eq!(
                body_preview(&message(encoding, frames), 4096).body,
                b"onetwo"
            );
        }
        let mut frames = b"\x50\x2a\x4d\x18\x03\0\0\0abc".to_vec();
        frames.extend(compress("zstd", b"after metadata"));
        assert_eq!(
            decoded(&message("zstd", frames), 4096).unwrap().body,
            b"after metadata"
        );
    }

    #[test]
    fn corrupt_unknown_empty_and_oversized_content_falls_back_to_raw() {
        for encoding in ["gzip", "deflate", "br", "zstd", "unknown", "gzip, unknown"] {
            let broken = message(encoding, b"invalid compressed body".to_vec()).encode();
            assert_eq!(
                display(&broken, false, 4096),
                String::from_utf8_lossy(&broken)
            );
        }
        for encoding in ["gzip", "deflate", "br", "zstd"] {
            let compressed = message(encoding, compress(encoding, &vec![b'a'; 10000]));
            let bytes = compressed.encode();
            assert_eq!(display(&bytes, false, 100), String::from_utf8_lossy(&bytes));
            let mut truncated = compressed.clone();
            truncated.body.truncate(2);
            assert!(decoded(&truncated, 1024 * 1024).is_none());
        }
        let no_body = message("br", vec![]).encode();
        assert_eq!(display(&no_body, false, 4096).as_bytes(), no_body);
    }

    #[test]
    fn cached_response_is_reused_and_hex_or_limit_changes_refresh_it() {
        let bytes = message("br", compress("br", b"cached response")).encode();
        let mut cache = ResponseCache::default();
        let first = cache.get(1, &bytes, None, None, false, 4096);
        assert!(Arc::ptr_eq(
            &first,
            &cache.get(1, &bytes, None, None, false, 4096)
        ));
        assert!(first.ends_with("cached response"));
        assert_eq!(
            super::super::unhex(&cache.get(1, &bytes, None, None, true, 4096)).unwrap(),
            bytes
        );
        assert_eq!(
            &*cache.get(1, &bytes, None, None, false, 1),
            String::from_utf8_lossy(&bytes)
        );
    }
}

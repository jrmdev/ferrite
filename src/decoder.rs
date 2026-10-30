//! Byte transformations for the Decoder tool. Every step is pure and works
//! on bytes, so binary data survives chains such as Base64 → Hex.
use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Output larger than this is refused, so a hostile input cannot exhaust memory.
const MAX_OUTPUT: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Transform {
    Base64Encode,
    Base64Decode,
    Base64UrlEncode,
    Base64UrlDecode,
    UrlEncode,
    UrlEncodeAll,
    UrlDecode,
    HtmlEncode,
    HtmlDecode,
    HexEncode,
    HexDecode,
    UnicodeEscape,
    UnicodeUnescape,
    GzipDecompress,
    JwtDecode,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Transform {
    pub const ALL: [Self; 20] = [
        Self::Base64Decode,
        Self::Base64Encode,
        Self::Base64UrlDecode,
        Self::Base64UrlEncode,
        Self::UrlDecode,
        Self::UrlEncode,
        Self::UrlEncodeAll,
        Self::HtmlDecode,
        Self::HtmlEncode,
        Self::HexDecode,
        Self::HexEncode,
        Self::UnicodeUnescape,
        Self::UnicodeEscape,
        Self::GzipDecompress,
        Self::JwtDecode,
        Self::Md5,
        Self::Sha1,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::Base64Encode => "Base64 encode",
            Self::Base64Decode => "Base64 decode",
            Self::Base64UrlEncode => "Base64URL encode",
            Self::Base64UrlDecode => "Base64URL decode",
            Self::UrlEncode => "URL encode (reserved)",
            Self::UrlEncodeAll => "URL encode (all bytes)",
            Self::UrlDecode => "URL decode",
            Self::HtmlEncode => "HTML entity encode",
            Self::HtmlDecode => "HTML entity decode",
            Self::HexEncode => "Hex encode",
            Self::HexDecode => "Hex decode",
            Self::UnicodeEscape => "Unicode escape (\\uXXXX)",
            Self::UnicodeUnescape => "Unicode / backslash unescape",
            Self::GzipDecompress => "Gzip / zlib decompress",
            Self::JwtDecode => "JWT inspect (no verification)",
            Self::Md5 => "MD5 hash",
            Self::Sha1 => "SHA-1 hash",
            Self::Sha256 => "SHA-256 hash",
            Self::Sha384 => "SHA-384 hash",
            Self::Sha512 => "SHA-512 hash",
        }
    }

    pub fn apply(self, input: &[u8]) -> Result<Vec<u8>> {
        let output = match self {
            Self::Base64Encode => base64::engine::general_purpose::STANDARD
                .encode(input)
                .into_bytes(),
            Self::Base64UrlEncode => base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(input)
                .into_bytes(),
            Self::Base64Decode | Self::Base64UrlDecode => base64_decode(input)?,
            Self::UrlEncode => url_encode(input, false),
            Self::UrlEncodeAll => url_encode(input, true),
            Self::UrlDecode => url_decode(input),
            Self::HtmlEncode => html_encode(&String::from_utf8_lossy(input)).into_bytes(),
            Self::HtmlDecode => html_decode(&String::from_utf8_lossy(input)).into_bytes(),
            Self::HexEncode => input
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .into_bytes(),
            Self::HexDecode => hex_decode(input)?,
            Self::UnicodeEscape => unicode_escape(&String::from_utf8_lossy(input)).into_bytes(),
            Self::UnicodeUnescape => {
                unicode_unescape(&String::from_utf8_lossy(input))?.into_bytes()
            }
            Self::GzipDecompress => decompress(input)?,
            Self::JwtDecode => jwt_inspect(&String::from_utf8_lossy(input))?.into_bytes(),
            Self::Md5 => hex_digest::<md5::Md5>(input),
            Self::Sha1 => hex_digest::<sha1::Sha1>(input),
            Self::Sha256 => hex_digest::<sha2::Sha256>(input),
            Self::Sha384 => hex_digest::<sha2::Sha384>(input),
            Self::Sha512 => hex_digest::<sha2::Sha512>(input),
        };
        ensure!(output.len() <= MAX_OUTPUT, "Output exceeds 64 MiB");
        Ok(output)
    }
}

/// The output of each step in a chain; a failed step ends the chain.
pub fn run_chain(input: &[u8], steps: &[Transform]) -> Vec<Result<Vec<u8>, String>> {
    let mut results = Vec::with_capacity(steps.len());
    let mut current = input.to_vec();
    for step in steps {
        match step.apply(&current) {
            Ok(output) => {
                current = output.clone();
                results.push(Ok(output));
            }
            Err(error) => {
                results.push(Err(format!("{error:#}")));
                break;
            }
        }
    }
    results
}

fn hex_digest<D: sha2::Digest>(input: &[u8]) -> Vec<u8> {
    D::digest(input)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .into_bytes()
}

/// Standard or URL-safe alphabet, with or without padding or whitespace.
fn base64_decode(input: &[u8]) -> Result<Vec<u8>> {
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        })
        .filter(|b| *b != b'=')
        .collect();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&cleaned)
        .context("Input is not valid Base64")
}

fn url_encode(input: &[u8], all: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3);
    for &byte in input {
        if !all && (byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)) {
            out.push(byte);
        } else {
            out.extend_from_slice(format!("%{byte:02X}").as_bytes());
        }
    }
    out
}

/// Percent-decoding with `+` as space; malformed escapes are kept literally.
fn url_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'%' if index + 2 < input.len() => {
                match std::str::from_utf8(&input[index + 1..index + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            byte => out.push(byte),
        }
        index += 1;
    }
    out
}

fn html_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

const ENTITIES: [(&str, char); 16] = [
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", '\u{a0}'),
    ("copy", '©'),
    ("reg", '®'),
    ("trade", '™'),
    ("hellip", '…'),
    ("mdash", '—'),
    ("ndash", '–'),
    ("lsquo", '‘'),
    ("rsquo", '’'),
    ("ldquo", '“'),
    ("rdquo", '”'),
];

fn html_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let decoded = rest[1..]
            .find(';')
            .filter(|end| *end <= 32)
            .and_then(|end| {
                let name = &rest[1..=end];
                let c = if let Some(number) =
                    name.strip_prefix("#x").or_else(|| name.strip_prefix("#X"))
                {
                    u32::from_str_radix(number, 16)
                        .ok()
                        .and_then(char::from_u32)
                } else if let Some(number) = name.strip_prefix('#') {
                    number.parse().ok().and_then(char::from_u32)
                } else {
                    ENTITIES.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
                }?;
                Some((c, end + 2))
            });
        match decoded {
            Some((c, length)) => {
                out.push(c);
                rest = &rest[length..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn hex_decode(input: &[u8]) -> Result<Vec<u8>> {
    let text = String::from_utf8_lossy(input);
    let cleaned: String = text
        .replace("0x", "")
        .replace("\\x", "")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != ',')
        .collect();
    ensure!(
        cleaned.len().is_multiple_of(2),
        "Hex input has an odd number of digits"
    );
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(cleaned.get(i..i + 2).context("Invalid hex")?, 16)
                .context("Input contains non-hex characters")
        })
        .collect()
}

fn unicode_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii() && !c.is_ascii_control() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

/// Decode `\uXXXX` (with surrogate pairs), `\u{...}`, `\xXX` and common
/// backslash escapes.
fn unicode_unescape(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut pending_high: Option<u16> = None;
    while let Some(c) = chars.next() {
        if c != '\\' {
            if pending_high.take().is_some() {
                out.push('\u{fffd}');
            }
            out.push(c);
            continue;
        }
        let Some(kind) = chars.next() else {
            out.push('\\');
            break;
        };
        let take_hex = |chars: &mut std::iter::Peekable<std::str::Chars>, count: usize| {
            let digits: String = (0..count).filter_map(|_| chars.next()).collect();
            u32::from_str_radix(&digits, 16)
                .ok()
                .filter(|_| digits.len() == count)
        };
        match kind {
            'u' if chars.peek() == Some(&'{') => {
                chars.next();
                let digits: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let value = u32::from_str_radix(&digits, 16).context("Invalid \\u{...} escape")?;
                out.push(char::from_u32(value).context("Invalid code point")?);
            }
            'u' => {
                let unit = take_hex(&mut chars, 4).context("Invalid \\uXXXX escape")? as u16;
                match (pending_high.take(), unit) {
                    (Some(high), 0xdc00..=0xdfff) => {
                        let value =
                            0x10000 + (((high as u32) - 0xd800) << 10) + (unit as u32 - 0xdc00);
                        out.push(char::from_u32(value).unwrap_or('\u{fffd}'));
                    }
                    (previous, 0xd800..=0xdbff) => {
                        if previous.is_some() {
                            out.push('\u{fffd}');
                        }
                        pending_high = Some(unit);
                    }
                    (previous, unit) => {
                        if previous.is_some() {
                            out.push('\u{fffd}');
                        }
                        out.push(char::from_u32(unit as u32).unwrap_or('\u{fffd}'));
                    }
                }
            }
            'x' => {
                let value = take_hex(&mut chars, 2).context("Invalid \\xXX escape")?;
                out.push(char::from_u32(value).unwrap_or('\u{fffd}'));
            }
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            '\\' | '"' | '\'' | '/' => out.push(kind),
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    if pending_high.is_some() {
        out.push('\u{fffd}');
    }
    Ok(out)
}

fn decompress(input: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let read = |reader: &mut dyn Read| -> Result<Vec<u8>> {
        let mut out = Vec::new();
        reader.take(MAX_OUTPUT as u64 + 1).read_to_end(&mut out)?;
        ensure!(out.len() <= MAX_OUTPUT, "Decompressed data exceeds 64 MiB");
        Ok(out)
    };
    if input.starts_with(&[0x1f, 0x8b]) {
        return read(&mut flate2::read::MultiGzDecoder::new(input)).context("Invalid gzip data");
    }
    read(&mut flate2::read::ZlibDecoder::new(input))
        .or_else(|_| read(&mut flate2::read::DeflateDecoder::new(input)))
        .context("Input is not gzip, zlib or raw deflate data")
}

fn describe_time(claim: &str, value: &serde_json::Value, now: i64) -> Option<String> {
    let seconds = value.as_i64()?;
    let time = chrono::DateTime::from_timestamp(seconds, 0)?;
    let relation = if seconds < now { "past" } else { "future" };
    let note = match claim {
        "exp" if seconds < now => " — EXPIRED",
        "nbf" if seconds > now => " — NOT YET VALID",
        _ => "",
    };
    Some(format!(
        "{claim}: {seconds} = {} ({relation}){note}",
        time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    ))
}

/// Decode a JWT's header and payload for inspection. The signature is never
/// verified, so nothing here implies the token is valid.
pub fn jwt_inspect(token: &str) -> Result<String> {
    let token = token
        .trim()
        .trim_start_matches("Bearer ")
        .trim_start_matches("bearer ");
    let parts: Vec<&str> = token.split('.').collect();
    match parts.len() {
        3 => {}
        5 => {
            bail!("This is an encrypted JWE (5 parts); only its header can be read without the key")
        }
        n => bail!("A JWS has 3 dot-separated parts; found {n}"),
    }
    let decode = |part: &str, name: &str| -> Result<serde_json::Value> {
        let bytes =
            base64_decode(part.as_bytes()).with_context(|| format!("{name} is not Base64URL"))?;
        serde_json::from_slice(&bytes).with_context(|| format!("{name} is not JSON"))
    };
    let header = decode(parts[0], "Header")?;
    let payload = decode(parts[1], "Payload")?;
    let signature = base64_decode(parts[2].as_bytes()).unwrap_or_default();
    let mut out = String::from("SIGNATURE NOT VERIFIED — decoded for inspection only.\n\n");
    out.push_str("Header\n");
    out.push_str(&serde_json::to_string_pretty(&header)?);
    out.push_str("\n\nPayload\n");
    out.push_str(&serde_json::to_string_pretty(&payload)?);
    out.push_str(&format!("\n\nSignature: {} bytes", signature.len()));
    let alg = header.get("alg").and_then(|a| a.as_str()).unwrap_or("");
    let mut notes = vec![];
    if alg.eq_ignore_ascii_case("none") {
        notes.push("alg is \"none\": the token is unsigned".to_string());
    } else if !alg.is_empty() {
        notes.push(format!("alg: {alg}"));
    }
    if parts[2].is_empty() {
        notes.push("Signature segment is empty".into());
    }
    let now = chrono::Utc::now().timestamp();
    for claim in ["iat", "nbf", "exp"] {
        if let Some(note) = payload
            .get(claim)
            .and_then(|v| describe_time(claim, v, now))
        {
            notes.push(note);
        }
    }
    if !notes.is_empty() {
        out.push_str("\n\n");
        out.push_str(&notes.join("\n"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(transform: Transform, input: &str) -> String {
        String::from_utf8(transform.apply(input.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn encodings_round_trip() {
        let samples: [&[u8]; 3] = [b"", b"hello world", &[0, 255, 254, 10, 13, 37]];
        for sample in samples {
            for (encode, decode) in [
                (Transform::Base64Encode, Transform::Base64Decode),
                (Transform::Base64UrlEncode, Transform::Base64UrlDecode),
                (Transform::UrlEncode, Transform::UrlDecode),
                (Transform::UrlEncodeAll, Transform::UrlDecode),
                (Transform::HexEncode, Transform::HexDecode),
            ] {
                let encoded = encode.apply(sample).unwrap();
                assert_eq!(decode.apply(&encoded).unwrap(), sample, "{encode:?}");
            }
        }
        let text_sample = "<a href=\"x\">'é' & 😀\u{7}</a>";
        assert_eq!(
            text(
                Transform::HtmlDecode,
                &text(Transform::HtmlEncode, text_sample)
            ),
            text_sample
        );
        assert_eq!(
            text(
                Transform::UnicodeUnescape,
                &text(Transform::UnicodeEscape, text_sample)
            ),
            text_sample
        );
    }

    #[test]
    fn decoders_accept_common_variants() {
        assert_eq!(text(Transform::Base64Decode, "aGk_Pz8-\n"), "hi???>");
        assert_eq!(text(Transform::Base64Decode, "aGVsbG8="), "hello");
        assert_eq!(text(Transform::UrlDecode, "a%20b+c%zz%4"), "a b c%zz%4");
        assert_eq!(text(Transform::UrlEncode, "a b/é"), "a%20b%2F%C3%A9");
        assert_eq!(text(Transform::HexDecode, "0x48 0x69\\x21"), "Hi!");
        assert!(Transform::HexDecode.apply(b"abc").is_err());
        assert_eq!(
            text(Transform::HtmlDecode, "&lt;&#60;&#x3c;&unknown;&amp"),
            "<<<&unknown;&amp"
        );
        assert_eq!(
            text(Transform::UnicodeUnescape, r"😀 \u{1F600} \x41\n\q"),
            "😀 😀 A\n\\q"
        );
        assert!(Transform::Base64Decode.apply(b"!!!").is_err());
    }

    #[test]
    fn hashes_match_known_vectors() {
        assert_eq!(
            text(Transform::Md5, "abc"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            text(Transform::Sha1, "abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            text(Transform::Sha256, "abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(text(Transform::Sha384, "abc").len(), 96);
        assert_eq!(text(Transform::Sha512, "abc").len(), 128);
    }

    #[test]
    fn jwt_inspection_never_claims_validity() {
        // {"alg":"none"}.{"sub":"alice","exp":1}.
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsImV4cCI6MX0.";
        let report = jwt_inspect(&format!("Bearer {token}")).unwrap();
        assert!(report.starts_with("SIGNATURE NOT VERIFIED"));
        assert!(report.contains("\"sub\": \"alice\""));
        assert!(report.contains("unsigned"));
        assert!(report.contains("EXPIRED"));
        assert!(jwt_inspect("a.b").is_err());
        assert!(
            jwt_inspect("a.b.c.d.e")
                .unwrap_err()
                .to_string()
                .contains("JWE")
        );
    }

    #[test]
    fn chains_stop_at_the_first_error_and_keep_binary_data() {
        let results = run_chain(
            b"\x00\xff",
            &[
                Transform::Base64Encode,
                Transform::Base64Decode,
                Transform::HexEncode,
            ],
        );
        assert_eq!(results.last().unwrap().as_deref().unwrap(), b"00ff");
        let results = run_chain(b"zz", &[Transform::HexDecode, Transform::Base64Encode]);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
        let compressed = {
            use std::io::Write;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(b"payload").unwrap();
            encoder.finish().unwrap()
        };
        assert_eq!(
            Transform::GzipDecompress.apply(&compressed).unwrap(),
            b"payload"
        );
    }
}

//! PLATFORM-PATCH 7: value-based secret redaction (see docs/PLATFORM-REDACTION-DESIGN.md).
//!
//! Pure matcher + streaming wrapper. Sinks call [`Redactor::redact`] or [`StreamRedactor`].
//! Needle values and any substring of them are never logged or returned in errors.

use aho_corasick::{AhoCorasick, MatchKind};
use std::fmt::Write as _;

/// Shortest accepted needle for filter-named env vars and the needles file (shorter => refuse).
pub const MIN_NEEDLE_LEN: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum RedactError {
    /// The needle called `name` is shorter than [`MIN_NEEDLE_LEN`]. Name only, never the value.
    NeedleTooShort { name: String },
    /// The automaton could not be built.
    Build,
}

impl std::fmt::Display for RedactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedleTooShort { name } => write!(f, "redaction needle '{name}' is too short"),
            Self::Build => write!(f, "redaction matcher build failed"),
        }
    }
}
impl std::error::Error for RedactError {}

/// Name charset for the replacement marker: only `[A-Za-z0-9_-]`, max 64 chars.
fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .take(64)
        .collect();
    if cleaned.is_empty() { "SECRET".to_string() } else { cleaned }
}

const B64_STD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode `pad` zero bytes + `v` with `bits`-bit symbols and keep only the symbols fully
/// determined by `v` (stable in any context). `pad` is the alignment offset.
fn encode_aligned(v: &[u8], pad: usize, bits: usize, alphabet: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; pad];
    data.extend_from_slice(v);
    let total_bits = data.len() * 8;
    let first = (pad * 8).div_ceil(bits);
    let last = total_bits / bits; // exclusive
    let mut out = Vec::new();
    for i in first..last {
        let mut sym = 0usize;
        for b in 0..bits {
            let bit_index = i * bits + b;
            let byte = data[bit_index / 8];
            let bit = (byte >> (7 - (bit_index % 8))) & 1;
            sym = (sym << 1) | usize::from(bit);
        }
        out.push(alphabet[sym]);
    }
    out
}

fn json_escape(v: &str, escape_slash: bool, unicode_all: bool) -> String {
    let mut out = String::new();
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' if escape_slash => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (unicode_all && !c.is_ascii()) => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{:04x}", u);
                }
            }
            c => out.push(c),
        }
    }
    out
}

fn percent_encode(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in v {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

/// Every encoded form of one needle value (deduplicated, empty forms dropped).
#[must_use]
pub fn variants(value: &str) -> Vec<Vec<u8>> {
    let v = value.as_bytes();
    let mut out: Vec<Vec<u8>> = vec![v.to_vec()];
    out.push(percent_encode(v));
    out.push(percent_encode(v).to_ascii_lowercase());
    for slash in [false, true] {
        for uni in [false, true] {
            out.push(json_escape(value, slash, uni).into_bytes());
        }
    }
    let hex_lower: String = v.iter().map(|b| format!("{b:02x}")).collect();
    out.push(hex_lower.to_ascii_uppercase().into_bytes());
    out.push(hex_lower.into_bytes());
    for pad in 0..3 {
        out.push(encode_aligned(v, pad, 6, B64_STD));
        out.push(encode_aligned(v, pad, 6, B64_URL));
    }
    for pad in 0..5 {
        out.push(encode_aligned(v, pad, 5, B32));
    }
    out.retain(|x| x.len() >= MIN_NEEDLE_LEN);
    out.sort();
    out.dedup();
    out
}

/// Immutable matcher. Swap whole `Arc<Redactor>` to rebuild atomically.
pub struct Redactor {
    ac: AhoCorasick,
    names: Vec<String>, // per pattern index
    max_len: usize,
}

impl Redactor {
    /// Build from `(name, value)` needles. `name` is an env var name or file line index.
    ///
    /// # Errors
    /// [`RedactError::NeedleTooShort`] (name only) or [`RedactError::Build`].
    pub fn new(needles: &[(String, String)]) -> Result<Self, RedactError> {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut names = Vec::new();
        for (name, value) in needles {
            if value.len() < MIN_NEEDLE_LEN {
                return Err(RedactError::NeedleTooShort { name: sanitize_name(name) });
            }
            for p in variants(value) {
                patterns.push(p);
                names.push(sanitize_name(name));
            }
        }
        let max_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .map_err(|_| RedactError::Build)?;
        Ok(Self { ac, names, max_len })
    }

    #[must_use]
    pub fn max_needle_len(&self) -> usize {
        self.max_len
    }

    /// Replace every match with `[REDACTED:<NAME>]` (leftmost-longest).
    #[must_use]
    pub fn redact(&self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        let mut last = 0;
        for m in self.ac.find_iter(input) {
            out.extend_from_slice(&input[last..m.start()]);
            out.extend_from_slice(format!("[REDACTED:{}]", self.names[m.pattern().as_usize()]).as_bytes());
            last = m.end();
        }
        out.extend_from_slice(&input[last..]);
        out
    }
}

/// Per-stream, per-sink redactor that holds back the last `max_len - 1` bytes so a secret split
/// across chunks is still matched. Held bytes are NEVER released raw: dropping the stream
/// (error, cancel, panic, signal) discards them; only [`finish`](Self::finish) flushes (redacted).
pub struct StreamRedactor<'a> {
    r: &'a Redactor,
    held: Vec<u8>,
}

impl<'a> StreamRedactor<'a> {
    #[must_use]
    pub fn new(r: &'a Redactor) -> Self {
        Self { r, held: Vec::new() }
    }

    /// Feed a chunk; returns bytes now safe to release.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(chunk);
        let keep = self.r.max_len.saturating_sub(1);
        if self.held.len() <= keep {
            return Vec::new();
        }
        // Redact the whole buffer, then keep the unredacted-safe tail by cutting at a point that
        // cannot split a match: redact everything except the last `keep` raw bytes.
        let cut = self.held.len() - keep;
        // Extend the cut to the end of any match that straddles it.
        let mut end = cut;
        for m in self.r.ac.find_iter(&self.held) {
            if m.start() < cut && m.end() > end {
                end = m.end();
            }
        }
        let released = self.r.redact(&self.held[..end]);
        self.held.drain(..end);
        released
    }

    /// End of stream: flush the held tail (redacted).
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        let out = self.r.redact(&self.held);
        self.held.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t/value+123=XYZ";

    fn red() -> Redactor {
        Redactor::new(&[("MY_API_KEY".to_string(), SECRET.to_string())]).unwrap()
    }

    fn b64(v: &[u8], pad: usize, alpha: &[u8]) -> String {
        // Independent reference encoder (standard padded base64) of pad+v, sliced the same way.
        let mut data = vec![b'#'; pad];
        data.extend_from_slice(v);
        let mut s = String::new();
        for ch in data.chunks(3) {
            let n = (u32::from(ch[0]) << 16)
                | (u32::from(*ch.get(1).unwrap_or(&0)) << 8)
                | u32::from(*ch.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= ch.len() {
                    s.push(alpha[((n >> (18 - 6 * i)) & 63) as usize] as char);
                }
            }
        }
        s
    }

    #[test]
    fn plain_hex_url_json_hits() {
        let r = red();
        let hex: String = SECRET.bytes().map(|b| format!("{b:02x}")).collect();
        for hit in [
            SECRET.to_string(),
            hex.clone(),
            hex.to_uppercase(),
            "s3cr3t%2Fvalue%2B123%3DXYZ".to_string(),
            "s3cr3t\\/value+123=XYZ".to_string(),
        ] {
            let out = r.redact(format!("a {hit} b").as_bytes());
            assert_eq!(String::from_utf8(out).unwrap(), "a [REDACTED:MY_API_KEY] b", "{hit}");
        }
    }

    #[test]
    fn base64_all_three_offsets_std_and_url() {
        let r = red();
        for pad in 0..3 {
            for alpha in [B64_STD, B64_URL] {
                let full = b64(SECRET.as_bytes(), pad, alpha);
                // Strip the chars that depend on the pad bytes (the middle is context-stable).
                let skip = (pad * 8).div_ceil(6);
                let end = (pad + SECRET.len()) * 8 / 6;
                let mid = &full[skip..end];
                let line = format!("x{mid}y");
                let out = String::from_utf8(r.redact(line.as_bytes())).unwrap();
                assert!(out.contains("[REDACTED:MY_API_KEY]"), "pad {pad}: {out}");
            }
        }
    }

    #[test]
    fn base32_offsets() {
        let r = red();
        for pad in 0..5 {
            let enc = String::from_utf8(encode_aligned(SECRET.as_bytes(), pad, 5, B32)).unwrap();
            let out = String::from_utf8(r.redact(format!("<{enc}>").as_bytes())).unwrap();
            assert_eq!(out, "<[REDACTED:MY_API_KEY]>", "pad {pad}");
        }
    }

    #[test]
    fn short_needle_is_refused_by_name_only() {
        let err = Redactor::new(&[("TOKEN_X".to_string(), "abc".to_string())]).err().unwrap();
        assert_eq!(err, RedactError::NeedleTooShort { name: "TOKEN_X".to_string() });
        assert!(!err.to_string().contains("abc"));
    }

    #[test]
    fn leftmost_longest_with_prefix_needles() {
        let r = Redactor::new(&[
            ("SHORT_KEY".to_string(), "abcd1234".to_string()),
            ("LONG_KEY".to_string(), "abcd1234efgh".to_string()),
        ])
        .unwrap();
        let out = String::from_utf8(r.redact(b"z abcd1234efgh z")).unwrap();
        assert_eq!(out, "z [REDACTED:LONG_KEY] z");
    }

    #[test]
    fn name_is_sanitized() {
        let r = Redactor::new(&[("bad name\n]".to_string(), SECRET.to_string())]).unwrap();
        let out = String::from_utf8(r.redact(SECRET.as_bytes())).unwrap();
        assert_eq!(out, "[REDACTED:bad_name__]");
    }

    #[test]
    fn stream_split_across_chunks_and_drop_never_releases_raw() {
        let r = red();
        let bytes = format!("pre {SECRET} post");
        for split in 1..bytes.len() {
            let (a, b) = bytes.as_bytes().split_at(split);
            let mut s = StreamRedactor::new(&r);
            let mut out = s.push(a);
            out.extend(s.push(b));
            out.extend(s.finish());
            assert_eq!(String::from_utf8(out).unwrap(), "pre [REDACTED:MY_API_KEY] post", "split {split}");
        }
        // Killed mid-stream: whatever was released contains no raw secret prefix beyond max_len-1.
        let mut s = StreamRedactor::new(&r);
        let released = s.push(format!("zzzzzzzzzz{}", &SECRET[..10]).as_bytes());
        drop(s);
        assert!(!String::from_utf8_lossy(&released).contains(&SECRET[..10]));
    }
}

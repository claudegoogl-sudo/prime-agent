//! PLATFORM-PATCH 7: value-based secret redaction (see docs/PLATFORM-REDACTION-DESIGN.md).
//!
//! Pure matcher + streaming wrapper. Sinks call [`Redactor::redact`] or [`StreamRedactor`].
//! Needle values and any substring of them are never logged or returned in errors.

use aho_corasick::{AhoCorasick, MatchKind};
use std::fmt::Write as _;

/// Shortest accepted needle for filter-named env vars and the needles file (shorter => refuse).
pub const MIN_NEEDLE_LEN: usize = 4;
/// Env-derived values shorter than this are skipped (name-only), and pass 2 (raw serialized
/// bytes) only uses variants at least this long so JSON structure like `true`/`null` is safe.
pub const MIN_ENV_NEEDLE_LEN: usize = 8;
pub const MIN_STRUCTURAL_VARIANT_LEN: usize = 8;

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
    /// Same patterns restricted to variants >= MIN_STRUCTURAL_VARIANT_LEN (pass 2 on JSON lines).
    ac_structural: AhoCorasick,
    names_structural: Vec<String>,
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
        let build = |pats: &[Vec<u8>]| {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(pats)
                .map_err(|_| RedactError::Build)
        };
        let ac = build(&patterns)?;
        let mut sp = Vec::new();
        let mut sn = Vec::new();
        for (p, n) in patterns.iter().zip(&names) {
            if p.len() >= MIN_STRUCTURAL_VARIANT_LEN {
                sp.push(p.clone());
                sn.push(n.clone());
            }
        }
        let ac_structural = build(&sp)?;
        Ok(Self { ac, names, ac_structural, names_structural: sn, max_len })
    }

    #[must_use]
    pub fn max_needle_len(&self) -> usize {
        self.max_len
    }

    /// Like [`redact`](Self::redact) but only variants >= MIN_STRUCTURAL_VARIANT_LEN (safe to run
    /// over serialized JSON without damaging structure).
    #[must_use]
    pub fn redact_structural(&self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        let mut last = 0;
        for m in self.ac_structural.find_iter(input) {
            out.extend_from_slice(&input[last..m.start()]);
            out.extend_from_slice(
                format!("[REDACTED:{}]", self.names_structural[m.pattern().as_usize()]).as_bytes(),
            );
            last = m.end();
        }
        out.extend_from_slice(&input[last..]);
        out
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
pub struct StreamRedactor {
    r: Arc<Redactor>,
    held: Vec<u8>,
    /// `Some(generation)` for sinks created from the process matcher: they follow reloads (R-E).
    live_gen: Option<u64>,
}

impl StreamRedactor {
    #[must_use]
    pub fn new(r: Arc<Redactor>) -> Self {
        Self { r, held: Vec::new(), live_gen: None }
    }

    /// Feed a chunk; returns bytes now safe to release.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if let Some(gen) = self.live_gen {
            let (now, cur, failed) = global()
                .read()
                .map_or((u64::MAX, None, true), |g| (g.generation, g.redactor.clone(), g.failed));
            if now != gen || failed {
                // Reload happened: follow the new matcher. Held bytes stay raw-in-memory and are
                // re-scanned with the new needles. Failed => drop held bytes, release nothing raw.
                if failed || cur.is_none() {
                    self.held.clear();
                    self.live_gen = Some(now);
                    return b"[REDACTED:ERROR]\n".to_vec();
                }
                if let Some(c) = cur {
                    self.r = c;
                }
                self.live_gen = Some(now);
            }
        }
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


// ---- needle loading (design R5, R6) ----

/// Needles file limits.
pub const NEEDLES_FILE_MAX_BYTES: u64 = 64 * 1024;
pub const NEEDLES_FILE_MAX_LINES: usize = 256;

/// Needles from env: every var whose name the shared filter blocks or that ends in a secret
/// suffix (this includes allowlisted keys such as `PAPERCLIP_API_KEY`) and has a non-empty value.
#[must_use]
pub fn needles_from_env(vars: impl IntoIterator<Item = (String, String)>) -> Vec<(String, String)> {
    const SUFFIXES: [&str; 8] = ["_SECRET", "_TOKEN", "_KEY", "_PAT", "_PASSWORD", "_PASSWD", "_CREDENTIALS", "_APIKEY"];
    vars.into_iter()
        .filter(|(k, v)| {
            let up = k.to_ascii_uppercase();
            !v.is_empty()
                && !k.starts_with("PRIME_AGENT_PLATFORM_")
                && (crate::daemon::launch_env::platform_env_blocked(k)
                    || SUFFIXES.iter().any(|s| up.ends_with(s)))
        })
        .collect()
}

/// R-H: for a value shaped like `scheme://user:pass@host/...` (URL or DSN) return the password
/// and the `user:pass` pair, so the secret is still matched when only part of the URL is logged.
#[must_use]
pub fn userinfo_parts(value: &str) -> Vec<String> {
    let Some((_, rest)) = value.split_once("://") else {
        return Vec::new();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let Some((userinfo, _)) = authority.rsplit_once('@') else {
        return Vec::new();
    };
    let mut out = vec![userinfo.to_string()];
    if let Some((_, pass)) = userinfo.split_once(':') {
        out.push(pass.to_string());
    }
    out.retain(|p| p.len() >= MIN_ENV_NEEDLE_LEN);
    out
}

fn with_userinfo(needles: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(needles.len());
    for (n, v) in needles {
        for (i, p) in userinfo_parts(&v).into_iter().enumerate() {
            out.push((format!("{n}_USERINFO{i}"), p));
        }
        out.push((n, v));
    }
    out
}

/// Read a needles file (one value per line, marker name = `FILE_LINE_<n>`, never the content).
/// Refuses symlinks (O_NOFOLLOW), anything not a regular file, group/world access, a different
/// owner, and oversize files; the checks use the open fd (no check/open race).
///
/// # Errors
/// A short, content-free reason string.
#[cfg(unix)]
pub fn read_needles_file(path: &std::path::Path) -> Result<Vec<(String, String)>, &'static str> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    // R-H: the parent directory must not be group/world-writable (rename/replace attack) and
    // must be owned by this user or root.
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let pm = std::fs::metadata(parent).map_err(|_| "needles file parent dir stat failed")?;
        // SAFETY-free: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if pm.mode() & 0o022 != 0 {
            return Err("needles file parent dir is group/world-writable");
        }
        if pm.uid() != euid && pm.uid() != 0 {
            return Err("needles file parent dir has the wrong owner");
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "needles file cannot be opened (missing or symlink)")?;
    let meta = f.metadata().map_err(|_| "needles file stat failed")?;
    if !meta.is_file() {
        return Err("needles file is not a regular file");
    }
    if meta.mode() & 0o077 != 0 {
        return Err("needles file must be mode 0600");
    }
    // SAFETY-free owner check: compare with the effective uid of this process.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err("needles file has the wrong owner");
    }
    if meta.len() > NEEDLES_FILE_MAX_BYTES {
        return Err("needles file is too large");
    }
    let mut text = String::new();
    f.take(NEEDLES_FILE_MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| "needles file is not valid UTF-8")?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i >= NEEDLES_FILE_MAX_LINES {
            return Err("needles file has too many lines");
        }
        let line = line.trim_end_matches('\r');
        if !line.is_empty() {
            out.push((format!("FILE_LINE_{}", i + 1), line.to_string()));
        }
    }
    Ok(out)
}


// ---- process-wide state + line sink (design R1, R4, fail-closed) ----

use std::sync::{Arc, OnceLock, RwLock};

struct Global {
    redactor: Option<Arc<Redactor>>,
    /// Fail-closed flag: set when the matcher could not be built. Never cleared by a failed rebuild.
    failed: bool,
    /// Bumped on every successful reload so live stream sinks can follow (R-E).
    generation: u64,
    /// Needles file of the last reload attempt, reused by the fail-closed retry.
    last_file: Option<std::path::PathBuf>,
}

fn global() -> &'static RwLock<Global> {
    static G: OnceLock<RwLock<Global>> = OnceLock::new();
    G.get_or_init(|| RwLock::new(Global { redactor: None, failed: false, generation: 0, last_file: None }))
}

/// Health flag for operators: true when redaction is fail-closed.
#[must_use]
pub fn is_failed_closed() -> bool {
    global().read().map_or(true, |g| g.failed)
}

/// (Re)build the process matcher from `vars` and the optional needles file. Atomic swap (R4):
/// on failure the OLD matcher stays and the fail-closed flag is set (never runs with none).
///
/// # Errors
/// A short content-free reason.
pub fn reload(
    vars: impl IntoIterator<Item = (String, String)>,
    needles_file: Option<&std::path::Path>,
) -> Result<(), String> {
    let result = (|| {
        // Env-derived values below the floor are skipped (name-only), never fatal (R-C).
        let mut needles: Vec<(String, String)> = needles_from_env(vars)
            .into_iter()
            .filter(|(_, v)| v.len() >= MIN_ENV_NEEDLE_LEN)
            .collect();
        #[cfg(unix)]
        if let Some(p) = needles_file {
            needles.extend(read_needles_file(p).map_err(str::to_string)?);
        }
        #[cfg(not(unix))]
        if needles_file.is_some() {
            return Err("needles file unsupported on this platform".to_string());
        }
        Redactor::new(&with_userinfo(needles)).map_err(|e| e.to_string())
    })();
    let mut g = global().write().map_err(|_| "redaction state poisoned".to_string())?;
    g.last_file = needles_file.map(std::path::Path::to_path_buf);
    match result {
        Ok(r) => {
            g.redactor = Some(Arc::new(r));
            g.failed = false;
            g.generation += 1;
            Ok(())
        }
        Err(e) => {
            g.failed = true;
            Err(e)
        }
    }
}

/// `reload` from the process env + `PRIME_AGENT_PLATFORM_NEEDLES_FILE`.
///
/// # Errors
/// See [`reload`].
pub fn reload_from_process_env() -> Result<(), String> {
    let file = std::env::var_os("PRIME_AGENT_PLATFORM_NEEDLES_FILE").map(std::path::PathBuf::from);
    reload(std::env::vars(), file.as_deref())
}

/// Sticky deny-all must not be permanent (residual note): retry the rebuild at most every
/// `RETRY_SECS` and log a content-free line. A successful retry clears the flag.
const RETRY_SECS: u64 = 5;

fn retry_failed_reload() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .max(1);
    let last = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(last) < RETRY_SECS
        || LAST.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err()
    {
        return;
    }
    let file = global().read().ok().and_then(|g| g.last_file.clone());
    let ok = reload(std::env::vars(), file.as_deref()).is_ok();
    // Content-free: reload errors never carry secret values.
    eprintln!("prime-agent: redaction is fail-closed; reload retry {}", if ok { "succeeded" } else { "failed" });
}

fn current() -> Option<Arc<Redactor>> {
    let (empty, failed) = {
        let g = global().read().ok()?;
        (g.redactor.is_none(), g.failed)
    }; // read guard dropped before any reload (R-D)
    if empty && !failed {
        let _ = reload_from_process_env();
    }
    let g = global().read().ok()?;
    // Deny-all while failed (R-B): a rotated secret must never be written raw.
    if g.failed {
        drop(g);
        retry_failed_reload();
        return None;
    }
    g.redactor.clone()
}

fn redact_value(v: &mut serde_json::Value, r: &Redactor) -> bool {
    match v {
        serde_json::Value::String(s) => {
            let out = r.redact(s.as_bytes());
            if out != s.as_bytes() {
                *s = String::from_utf8_lossy(&out).into_owned();
                true
            } else {
                false
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().fold(false, |acc, x| redact_value(x, r) | acc),
        serde_json::Value::Object(o) => {
            // R-G: keys are data too. Rebuild in order (serde_json preserve_order) only if a key hit.
            let mut changed = false;
            let old = std::mem::take(o);
            for (k, mut val) in old {
                changed |= redact_value(&mut val, r);
                let nk = r.redact(k.as_bytes());
                let key = if nk == k.as_bytes() {
                    k
                } else {
                    changed = true;
                    String::from_utf8_lossy(&nk).into_owned()
                };
                o.insert(key, val);
            }
            changed
        }
        _ => false,
    }
}

/// A stream sink on the process matcher, or `None` when redaction is unavailable (fail closed:
/// the caller must then write nothing raw).
#[must_use]
pub fn stream() -> Option<StreamRedactor> {
    let r = current()?;
    let generation = global().read().ok()?.generation;
    let mut s = StreamRedactor::new(r);
    s.live_gen = Some(generation);
    Some(s)
}

/// Sink for plain text / one JSON line without a trailing newline (stdout, stderr, logs).
/// Fail-closed: returns `[REDACTED:ERROR]` when redaction is unavailable.
#[must_use]
pub fn redact_text(text: &str) -> String {
    let Some(r) = current() else {
        return "[REDACTED:ERROR]".to_string();
    };
    String::from_utf8_lossy(&redact_json_or_text(&r, text.as_bytes())).into_owned()
}

fn redact_json_or_text(r: &Redactor, b: &[u8]) -> Vec<u8> {
    if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(b) {
        if matches!(v, serde_json::Value::Object(_) | serde_json::Value::Array(_)) {
            if redact_value(&mut v, r) {
                if let Ok(s) = serde_json::to_vec(&v) {
                    return r.redact_structural(&s);
                }
            }
            return r.redact_structural(b);
        }
    }
    // Plain text: every variant applies.
    r.redact(b)
}

/// `println!` through the redaction sink (stdout). Use instead of `println!` in output paths.
#[macro_export]
macro_rules! pa_println {
    () => {{ #[allow(clippy::disallowed_macros)] { println!() } }};
    ($($t:tt)*) => {{ #[allow(clippy::disallowed_macros)] { println!("{}", $crate::redact::redact_text(&format!($($t)*))) } }};
}

/// `eprintln!` through the redaction sink (stderr).
#[macro_export]
macro_rules! pa_eprintln {
    () => {{ #[allow(clippy::disallowed_macros)] { eprintln!() } }};
    ($($t:tt)*) => {{ #[allow(clippy::disallowed_macros)] { eprintln!("{}", $crate::redact::redact_text(&format!($($t)*))) } }};
}

/// Sink function for one serialized JSON line (R1): pass 1 on decoded string leaves, pass 2 on
/// the final bytes. Fail-closed: if redaction is unavailable the record becomes
/// `{"redacted":"[REDACTED:ERROR]"}` + newline; raw bytes are never returned.
#[must_use]
pub fn redact_json_line(line: &[u8]) -> Vec<u8> {
    let Some(r) = current() else {
        return b"{\"redacted\":\"[REDACTED:ERROR]\"}\n".to_vec();
    };
    let mut bytes = line.to_vec();
    if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(line.strip_suffix(b"\n").unwrap_or(line)) {
        if redact_value(&mut v, &r) {
            if let Ok(mut s) = serde_json::to_vec(&v) {
                if line.ends_with(b"\n") {
                    s.push(b'\n');
                }
                bytes = s;
            }
        }
    }
    r.redact_structural(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t/value+123=XYZ";

    /// R-I: tests that touch the process-wide matcher must not interleave.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static M: std::sync::Mutex<()> = std::sync::Mutex::new(());
        M.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

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
        let r = Arc::new(red());
        let bytes = format!("pre {SECRET} post");
        for split in 1..bytes.len() {
            let (a, b) = bytes.as_bytes().split_at(split);
            let mut s = StreamRedactor::new(r.clone());
            let mut out = s.push(a);
            out.extend(s.push(b));
            out.extend(s.finish());
            assert_eq!(String::from_utf8(out).unwrap(), "pre [REDACTED:MY_API_KEY] post", "split {split}");
        }
        // Killed mid-stream: whatever was released contains no raw secret prefix beyond max_len-1.
        let mut s = StreamRedactor::new(r.clone());
        let released = s.push(format!("zzzzzzzzzz{}", &SECRET[..10]).as_bytes());
        drop(s);
        assert!(!String::from_utf8_lossy(&released).contains(&SECRET[..10]));
    }

    #[test]
    fn env_needles_pick_secret_names_only() {
        let n = needles_from_env([
            ("PAPERCLIP_API_KEY".to_string(), "k-12345678".to_string()),
            ("AUTHOR".to_string(), "someone-long".to_string()),
            ("EMPTY_TOKEN".to_string(), String::new()),
            ("db_password".to_string(), "pw-87654321".to_string()),
        ]);
        let names: Vec<_> = n.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, vec!["PAPERCLIP_API_KEY", "db_password"]);
    }

    #[cfg(unix)]
    #[test]
    fn needles_file_checks_mode_symlink_size_and_lines() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("needles");
        std::fs::write(&f, "value-one-1234\n\nvalue-two-5678\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_needles_file(&f).unwrap_err(), "needles file must be mode 0600");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let ok = read_needles_file(&f).unwrap();
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[1].0, "FILE_LINE_3");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(read_needles_file(&link).is_err());
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'a'; 70_000]).unwrap();
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_needles_file(&big).unwrap_err(), "needles file is too large");
        let many = dir.path().join("many");
        std::fs::write(&many, "abcdefgh\n".repeat(300)).unwrap();
        std::fs::set_permissions(&many, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_needles_file(&many).unwrap_err(), "needles file has too many lines");
    }

    #[test]
    fn json_line_sink_redacts_leaves_and_bytes_and_fails_closed() {
        let _g = serial();
        let secret = "line-secret-VALUE-0042";
        reload([("SINK_TEST_TOKEN".to_string(), secret.to_string())], None).unwrap();
        let line = format!("{{\"a\":\"x {secret} y\",\"n\":[1,\"{secret}\"]}}\n");
        let out = String::from_utf8(redact_json_line(line.as_bytes())).unwrap();
        assert!(!out.contains(secret), "{out}");
        assert!(out.contains("[REDACTED:SINK_TEST_TOKEN]"));
        assert!(out.ends_with('\n'));
        // R-C: short env values are skipped, not fatal; structural words survive.
        reload([("SHORT_TOKEN".to_string(), "true".to_string()), ("SINK_TEST_TOKEN".to_string(), secret.to_string())], None).unwrap();
        assert!(!is_failed_closed());
        let tl = String::from_utf8(redact_json_line(b"{\"ok\":true,\"v\":null}\n")).unwrap();
        assert_eq!(tl, "{\"ok\":true,\"v\":null}\n");
        // R-B: a failed reload denies everything (no raw output with a stale matcher).
        assert!(reload([], Some(std::path::Path::new("/nonexistent/needles"))).is_err());
        assert!(is_failed_closed());
        let again = String::from_utf8(redact_json_line(line.as_bytes())).unwrap();
        assert!(again.contains("[REDACTED:ERROR]") && !again.contains(secret));
        assert_eq!(redact_text("anything"), "[REDACTED:ERROR]");
        // Recovery after a good reload.
        reload([("SINK_TEST_TOKEN".to_string(), secret.to_string())], None).unwrap();
        assert!(!is_failed_closed());
        // R-D: concurrent readers while reloading must not deadlock.
        let hs: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..200 {
                        let _ = redact_text("x");
                    }
                })
            })
            .collect();
        for _ in 0..50 {
            reload([("SINK_TEST_TOKEN".to_string(), "line-secret-VALUE-0042".to_string())], None).unwrap();
        }
        for h in hs {
            h.join().unwrap();
        }
    }

    #[test]
    fn text_sink_redacts_json_and_plain() {
        let _g = serial();
        reload([("TEXT_SINK_TOKEN".to_string(), "text-secret-VALUE-77".to_string())], None).unwrap();
        assert_eq!(redact_text("a text-secret-VALUE-77 b"), "a [REDACTED:TEXT_SINK_TOKEN] b");
        let j = redact_text("{\"k\":\"text-secret-VALUE-77\"}");
        assert!(!j.contains("text-secret-VALUE-77") && j.contains("REDACTED"));
    }

    #[test]
    fn live_stream_follows_reload_and_fails_closed() {
        let _g = serial();
        reload([("OLD_TOKEN".to_string(), "old-secret-VALUE-1111".to_string())], None).unwrap();
        let mut st = stream().unwrap();
        let _ = st.push(&[b'.'; 64]);
        reload([("NEW_TOKEN".to_string(), "new-secret-VALUE-2222".to_string())], None).unwrap();
        let mut out = st.push(b"a new-secret-VALUE-2222 b");
        out.extend(st.push(&[b'.'; 64]));
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("new-secret-VALUE-2222") && out.contains("[REDACTED:NEW_TOKEN]"), "{out}");
        assert!(reload([], Some(std::path::Path::new("/nonexistent/n"))).is_err());
        let o = String::from_utf8(st.push(b"new-secret-VALUE-2222")).unwrap();
        assert!(!o.contains("new-secret") && o.contains("REDACTED:ERROR"));
        assert!(redact_text("x") == "[REDACTED:ERROR]", "retry must reuse the bad file and stay closed");
        reload([("NEW_TOKEN".to_string(), "new-secret-VALUE-2222".to_string())], None).unwrap();
    }

    #[test]
    fn json_keys_and_userinfo_are_redacted() {
        let _g = serial();
        let dsn = "postgres://dbuser:hunter2-pass-XYZ@db.internal:5432/app";
        reload([("DB_URL_SECRET".to_string(), dsn.to_string())], None).unwrap();
        let line = b"{\"hunter2-pass-XYZ\":1,\"z\":\"p=hunter2-pass-XYZ\",\"a\":2}\n";
        let out = String::from_utf8(redact_json_line(line)).unwrap();
        assert!(!out.contains("hunter2-pass-XYZ"), "{out}");
        // key order preserved
        assert!(out.find("\"z\"").unwrap() < out.find("\"a\"").unwrap());
        assert_eq!(userinfo_parts("https://tok-abcdefgh@h/x"), vec!["tok-abcdefgh".to_string()]);
        assert!(userinfo_parts("https://host/p").is_empty());
    }

    #[test]
    fn needles_file_parent_dir_must_not_be_writable() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("needles");
        std::fs::write(&f, "value-one-1234\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(read_needles_file(&f).unwrap_err(), "needles file parent dir is group/world-writable");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read_needles_file(&f).is_ok());
    }
}

//! Per-OS daemon endpoint naming: Unix socket files under
//! `<tmpdir>/prime-agent-<uid>/`; Windows named pipes in the `\\.\\pipe\\`
//! namespace (fixed daemon pipe, hashed worker pipes) - the TS product's
//! exact split.
use std::path::{Path, PathBuf};

use crate::paths::hash_key;

/// Marker file naming the product generation that owns a socket dir.
#[cfg(unix)]
pub const GENERATION_MARKER: &str = ".pa-generation";
#[cfg(unix)]
const GENERATION: &str = "rust";

/// Refuse a socket dir that holds another product generation's sockets or
/// locks (PLA-12418): a foreign marker, or a Node-style `prime-agent-<uid>`
/// dir with `.sock`/`.lock` entries and no Rust marker. Stamps the marker
/// on first use. Never deletes anything.
#[cfg(unix)]
pub fn assert_own_generation(dir: &Path) -> anyhow::Result<()> {
    let marker = dir.join(GENERATION_MARKER);
    match std::fs::read_to_string(&marker) {
        Ok(found) if found.trim() == GENERATION => return Ok(()),
        Ok(found) => anyhow::bail!(
            "socket dir {} belongs to another product generation ({:?}); refusing to start",
            dir.display(),
            found.trim()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => anyhow::bail!("socket dir marker unreadable: {e}"),
    }
    let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let node_style = name.starts_with("prime-agent-") && !name.starts_with("prime-agent-rs-");
    if node_style {
        let foreign = std::fs::read_dir(dir)?.flatten().any(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.ends_with(".sock") || n.ends_with(".lock")
        });
        if foreign {
            anyhow::bail!(
                "socket dir {} holds sockets/locks of another product generation (Node); refusing to start. Use the Rust default dir or PRIME_AGENT_PLATFORM_SOCKET_DIR",
                dir.display()
            );
        }
    }
    std::fs::write(&marker, GENERATION)?;
    Ok(())
}

/// Default directory holding daemon socket files (Unix).
#[cfg(unix)]
pub fn socket_dir() -> PathBuf {
    // PLATFORM-PATCH 10: pinned socket dir, immune to an inherited TMPDIR.
    if let Some(pinned) = std::env::var_os("PRIME_AGENT_PLATFORM_SOCKET_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(pinned);
    }
    let uid = pa_core::platform::process::current_user_id();
    // W2 (PLA-12188): default is /tmp, never an inherited TMPDIR (binary default, not wrapper-only).
    #[cfg(target_os = "linux")]
    let tmp = PathBuf::from("/tmp");
    #[cfg(not(target_os = "linux"))]
    let tmp = std::env::var_os("TMPDIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
    socket_dir_for(&tmp, uid)
}

/// Reserve the longest generated endpoint before selecting a directory. Linux
/// can re-anchor deep paths through /proc; other Unix platforms need a short path.
#[cfg(unix)]
fn socket_dir_for(tmp: &Path, uid: u32) -> PathBuf {
    // Distinct from the TS/Node product's `prime-agent-<uid>` so the two
    // generations never share sockets or lock dirs (PLA-12418).
    let name = format!("prime-agent-rs-{uid}");
    let dir = tmp.join(&name);
    #[cfg(not(target_os = "linux"))]
    if std::os::unix::net::SocketAddr::from_pathname(
        dir.join("worker-000000000000-000000000000.sock"),
    )
    .is_err()
    {
        return Path::new("/tmp").join(name);
    }
    dir
}

/// The socket-dir half of a discovery state root on Windows: TS computes
/// `<tmpdir>/prime-agent-user` so `DaemonStateRoot` keeps one shape.
#[cfg(not(unix))]
#[must_use]
pub fn socket_dir() -> PathBuf {
    std::env::temp_dir().join("prime-agent-user")
}

/// Default supervisor endpoint: `daemon.sock` in the socket dir (Unix) or
/// the fixed daemon pipe name (Windows).
#[cfg(unix)]
#[must_use]
pub fn default_daemon_socket_path() -> PathBuf {
    socket_dir().join("daemon.sock")
}

#[cfg(not(unix))]
#[must_use]
pub fn default_daemon_socket_path() -> PathBuf {
    PathBuf::from(r"\\.\pipe\prime-agent-daemon")
}

/// Worker endpoint next to the supervisor's: hashed supervisor key plus the
/// worker id prefix (TS `workerSocketPath`).
#[cfg(unix)]
#[must_use]
pub fn worker_socket_path(supervisor_socket_path: &Path, worker_id: &str) -> PathBuf {
    let key = hash_key(&supervisor_socket_path.to_string_lossy(), 12);
    socket_dir().join(format!(
        "worker-{key}-{}.sock",
        &worker_id[..12.min(worker_id.len())]
    ))
}

#[cfg(not(unix))]
#[must_use]
pub fn worker_socket_path(supervisor_socket_path: &Path, worker_id: &str) -> PathBuf {
    let key = hash_key(&supervisor_socket_path.to_string_lossy(), 12);
    PathBuf::from(format!(
        r"\\.\pipe\prime-agent-worker-{key}-{}",
        &worker_id[..12.min(worker_id.len())]
    ))
}

// Socket-filesystem identity is the shared platform contract
// `pa_types::platform::socket_identity`: the same helper serves stale-file
// cleanup here and direct-transport ticket validation in the clients.

pub use pa_types::daemon::SocketIdentity;
pub use pa_types::platform::socket_identity;
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn default_socket_uses_the_real_uid_in_a_rust_only_dir() {
        let output = std::process::Command::new("id")
            .arg("-ru")
            .output()
            .unwrap();
        assert!(output.status.success());
        let uid = String::from_utf8(output.stdout).unwrap();
        let tmp = std::env::var_os("TMPDIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        assert_eq!(
            socket_dir(),
            socket_dir_for(&tmp, uid.trim().parse().unwrap())
        );
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn generated_endpoints_fit_even_when_tmpdir_is_deep() {
        use std::os::unix::net::SocketAddr;

        for length in [20, 65, 120] {
            let tmp = PathBuf::from(format!("/{}", "d".repeat(length - 1)));
            let dir = socket_dir_for(&tmp, 501);
            let worker = dir.join("worker-000000000000-000000000000.sock");
            assert!(SocketAddr::from_pathname(&worker).is_ok());
            if length >= 65 {
                assert_eq!(dir, Path::new("/tmp/prime-agent-rs-501"));
            } else {
                assert_eq!(dir, tmp.join("prime-agent-rs-501"));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn short_tmpdir_keeps_the_original_socket_directory() {
        assert_eq!(
            socket_dir_for(Path::new("/tmp"), 501),
            Path::new("/tmp/prime-agent-rs-501")
        );
    }

    #[test]
    fn worker_socket_names_are_deterministic() {
        let supervisor = Path::new("/tmp/prime-agent-1/daemon.sock");
        let a = worker_socket_path(supervisor, "0123456789abcdef");
        let b = worker_socket_path(supervisor, "fedcba9876543210");
        assert_ne!(a, b);
        // Only the first 12 id characters key the name.
        assert_eq!(a, worker_socket_path(supervisor, "0123456789abffff"));
        #[cfg(unix)]
        assert!(a.starts_with(socket_dir()));
    }

    /// The Windows endpoint names (TS win32 arms): the fixed daemon pipe
    /// name and the hashed worker pipe name in the `\\.\\pipe\\` namespace.
    #[test]
    #[cfg(windows)]
    fn windows_endpoints_are_the_ts_pipe_names() {
        assert_eq!(
            default_daemon_socket_path(),
            PathBuf::from(r"\\.\pipe\prime-agent-daemon")
        );
        let supervisor = Path::new(r"\\.\pipe\prime-agent-daemon");
        let a = worker_socket_path(supervisor, "0123456789abcdef");
        let rendered = a.to_string_lossy();
        assert!(
            rendered.starts_with(r"\\.\pipe\prime-agent-worker-"),
            "the worker pipe namespace: {rendered}"
        );
        assert!(
            rendered.ends_with("-0123456789ab"),
            "the 12-char id suffix: {rendered}"
        );
    }
}

#[cfg(all(test, unix))]
mod platform_patch_10_tests {
    use super::*;

    // Single test: env is process-global, so keep all cases in one fn.
    #[test]
    fn pinned_socket_dir_ignores_tmpdir() {
        std::env::set_var("TMPDIR", "/var/tmp/other-run");
        std::env::set_var("PRIME_AGENT_PLATFORM_SOCKET_DIR", "/tmp/pa-pinned-test");
        assert_eq!(socket_dir(), PathBuf::from("/tmp/pa-pinned-test"));
        std::env::remove_var("PRIME_AGENT_PLATFORM_SOCKET_DIR");
        assert!(socket_dir().starts_with("/var/tmp/other-run"));
    }
}

#[cfg(all(test, unix))]
mod generation_tests {
    use super::*;

    #[test]
    fn default_dir_is_distinct_from_node() {
        std::env::remove_var("PRIME_AGENT_PLATFORM_SOCKET_DIR");
        let n = socket_dir().file_name().unwrap().to_string_lossy().into_owned();
        assert!(n.starts_with("prime-agent-rs-"), "{n}");
    }

    #[test]
    fn refuses_node_dir_and_foreign_marker_but_stamps_empty() {
        let t = tempfile::tempdir().unwrap();
        let node = t.path().join("prime-agent-1000");
        std::fs::create_dir(&node).unwrap();
        std::fs::write(node.join("daemon.sock"), "").unwrap();
        assert!(assert_own_generation(&node).is_err());
        let foreign = t.path().join("x");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join(GENERATION_MARKER), "node").unwrap();
        assert!(assert_own_generation(&foreign).is_err());
        let own = t.path().join("prime-agent-rs-1000");
        std::fs::create_dir(&own).unwrap();
        assert!(assert_own_generation(&own).is_ok());
        assert!(assert_own_generation(&own).is_ok());
    }
}

//! R-A: full pa-daemon process e2e. Boots a real supervisor whose paths carry a
//! needle (paths land in descriptors/config), then greps EVERY file written under
//! the agent dir for every encoding of the needle.
#![cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SECRET: &str = "Zq9-needle-value-4711";

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() { walk(&p, out); } else { out.push(p); }
    }
}

#[test]
fn no_written_file_holds_any_needle_encoding() {
    let tmp = tempfile::tempdir().unwrap();
    let agent_dir = tmp.path().join(format!("agent-{SECRET}"));
    std::fs::create_dir_all(&agent_dir).unwrap();
    let socket = tmp.path().join(format!("d-{SECRET}.sock"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_pa-daemon"))
        .args(["supervisor", "--socket"]).arg(&socket)
        .arg("--agent-dir").arg(&agent_dir)
        .env("TEST_API_KEY", SECRET)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while UnixStream::connect(&socket).is_err() {
        assert!(Instant::now() < deadline, "supervisor never came up");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    let _ = child.kill();
    let _ = child.wait();
    let mut files = Vec::new();
    walk(&agent_dir, &mut files);
    assert!(!files.is_empty(), "daemon wrote no files; e2e proves nothing");
    let variants = pa_types::redact::variants(SECRET);
    for f in files {
        let bytes = std::fs::read(&f).unwrap();
        for v in &variants {
            assert!(
                !bytes.windows(v.len()).any(|w| w == v.as_slice()),
                "needle encoding found in {}", f.display()
            );
        }
    }
}

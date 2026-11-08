// Pedantic-gate dispositions as src/lib.rs (large_futures/too_many_lines/casts).
#![allow(
    clippy::large_futures,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

//! PLATFORM-PATCH 12 (PLA-12158 F4) hard-abort test; derived from the watchdog tests: spawn a real `python -m rlm.repl`
//! kernel and verify the watchdog teaches instead of killing. A cell that
//! outlives its budget still settles ok and keeps its own result, with the
//! teaching note appended to stderr; sub-budget cells, disabled budgets,
//! failed cells, and the kernel itself (namespace intact, process alive) are
//! untouched.
#![cfg(unix)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use pa_core::kernel::manager::{KernelStartOptions, ReplKernelManager};
use pa_core::kernel::shared::{
    ExecuteOptions, ExecuteStatus, HostRequestHandlers, KernelManagerOptions, KernelSnapshotConfig,
};
use pa_core::kernel::state_snapshot::{manifest_path_in, snapshot_path_in};

/// The kernel Python with prime-agent-runtime installed. Ambient product
/// state, not test input: skipped (with a note) when absent;
/// `PA_CORE_KERNEL_PYTHON` points at an explicit interpreter instead.
fn kernel_python() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("PA_CORE_KERNEL_PYTHON") {
        let explicit = PathBuf::from(explicit);
        assert!(
            explicit.exists(),
            "PA_CORE_KERNEL_PYTHON {} not found",
            explicit.display()
        );
        return Some(explicit);
    }
    let candidate = PathBuf::from(std::env::var("HOME").map_or_else(
        |_| "/home/ubuntu/.prime/agent/kernel-venv/bin/python".to_string(),
        |home| format!("{home}/.prime/agent/kernel-venv/bin/python"),
    ));
    if candidate.exists() {
        return Some(candidate);
    }
    eprintln!(
        "kernel python {} not found; skipping live kernel test",
        candidate.display()
    );
    None
}

/// A started kernel manager, or `None` when no kernel interpreter is
/// available on this machine; the caller skips the test then. The watchdog
/// needs no RLM bootstrap: a bare `rlm.repl` kernel serves sleep cells.
async fn started_manager() -> Option<ReplKernelManager> {
    let python = kernel_python()?;
    let options = KernelManagerOptions {
        python: Some(python),
        cwd: Some(std::env::temp_dir()),
        env: HashMap::new(),
        session_id: Some("cell-watchdog-test".to_string()),
        host_handlers: HostRequestHandlers::new(),
        python_skills: Vec::new(),
        on_background_work_settled: None,
        snapshot: None,
        bootstrap_code: None,
        stderr_log_path: None,
    };
    let manager = ReplKernelManager::new(options);
    manager
        .start(KernelStartOptions::default())
        .await
        .expect("kernel must start");
    Some(manager)
}

/// Execute one cell under the given watchdog budget (`None` or `0` disables).
async fn execute(
    manager: &ReplKernelManager,
    code: &str,
    cell_timeout_ms: Option<u64>,
) -> pa_core::kernel::shared::ExecuteResult {
    manager
        .execute(
            code,
            ExecuteOptions {
                cell_timeout_ms,
                ..ExecuteOptions::default()
            },
        )
        .await
        .expect("execute must not fail")
}


#[tokio::test]
async fn hard_abort_fires_with_env_budget_and_kernel_survives() {
    // Own test binary => process env is not shared with other tests.
    std::env::set_var("PRIME_AGENT_PLATFORM_HARD_CELL_ABORT", "1");
    std::env::set_var("PRIME_AGENT_PLATFORM_HARD_CELL_ABORT_MS", "2000");
    let Some(manager) = started_manager().await else {
        return;
    };
    // cell_timeout_ms None = the daemonless print path that failed in F4.
    let t = Instant::now();
    let r = manager
        .execute("import time\ntime.sleep(60)\nprint('finished-sleep')", ExecuteOptions::default())
        .await;
    let took = t.elapsed();
    assert!(took < Duration::from_secs(20), "cell must end near budget, took {took:?}");
    let aborted = match &r {
        Ok(res) => res.status != ExecuteStatus::Ok && !res.stdout.contains("finished-sleep"),
        Err(_) => true,
    };
    assert!(aborted, "cell must not finish ok: {r:?}");
    // A following cell must still work (kernel interrupted or restarted).
    let next = manager.execute("1+1", ExecuteOptions::default()).await.expect("next cell");
    assert_eq!(next.status, ExecuteStatus::Ok);
    assert_eq!(next.result.as_deref(), Some("2"));
}

# PLATFORM-PATCHES-RUST

Fork of prime-agent v0.10.2. Rules: isolation/numeric config only; no logic rewrite where avoidable.
Find every patch: `grep -rn "PLATFORM-PATCH" crates packaging`.

| id | what | where | re-apply |
|---|---|---|---|
| 1 | wrapper pins registry dir + daemon socket | packaging/platform/prime-agent-wrapper.sh | copy file; set PA_ROOT |
| 10 | socket dir pin, ignores TMPDIR | crates/pa-daemon/src/platform/paths.rs `socket_dir()` | grep `PLATFORM-PATCH 10`; env `PRIME_AGENT_PLATFORM_SOCKET_DIR` |
| 4/5 | shared secret-env filter (denylist + `*_SECRET/_TOKEN/_KEY/_PAT` minus allowlist) | crates/pa-types/src/daemon/launch_env.rs `platform_env_blocked`; used in `collect_launch_env` and crates/pa-core/.../startup.rs `kernel_spawn_env` | grep `PLATFORM-PATCH 4/5` |
| 6 | shared daemon strips run identity from its own env | crates/pa-daemon/src/main.rs supervisor arm | grep `PLATFORM-PATCH 6` |
| 2 | reqwest connect 30s + read 600s timeouts | crates/pa-ai/src/utils_inner/http.rs | grep `PLATFORM-PATCH 2` |
| 12 | opt-in hard abort of a python cell at pythonCellTimeoutMs (set env PRIME_AGENT_PLATFORM_HARD_CELL_ABORT=1 and pythonCellTimeoutMs=3000000) | crates/pa-core/src/kernel/manager/mod.rs `execute` | grep `PLATFORM-PATCH 12` |

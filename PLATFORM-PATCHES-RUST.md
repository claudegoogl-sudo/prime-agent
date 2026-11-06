# PLATFORM-PATCHES-RUST

Fork of prime-agent v0.10.2. Rules: isolation/numeric config only; no logic rewrite where avoidable.
Find every patch: `grep -rn "PLATFORM-PATCH" crates packaging`.

| id | what | where | re-apply |
|---|---|---|---|
| 1 | wrapper pins registry dir + daemon socket | packaging/platform/prime-agent-wrapper.sh | copy file; set PA_ROOT |
| 10 | socket dir pin, ignores TMPDIR | crates/pa-daemon/src/platform/paths.rs `socket_dir()` | grep `PLATFORM-PATCH 10`; env `PRIME_AGENT_PLATFORM_SOCKET_DIR` |

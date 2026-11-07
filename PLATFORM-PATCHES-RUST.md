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
| 8 | kernel-state files owner-only (0600): upstream already writes via mkstemp (0600); test pins it, no code change | prime-agent-runtime/test/test_platform_snapshot.py | run the test |
| 9 | snapshot skips secret variables: narrow name segments (api_key, *_TOKEN, password...) on str/bytes + any string containing a secret-looking env value (len>=8) | prime-agent-runtime/src/rlm/repl.py `_platform_is_secret_var` | grep `PLATFORM-PATCH 9` |
| 7 (part) | value-based redaction matcher: encodings, leftmost-longest, stream tail; design in docs/PLATFORM-REDACTION-DESIGN.md | crates/pa-types/src/redact.rs | grep `PLATFORM-PATCH 7` |

## Patch 16: claude-haiku-5-5 is missing from the bundled/remote catalog
Finding (ops smoke, PLA-11947): the model catalog has `claude-haiku-4-5`, `claude-sonnet-5-5`, `claude-opus-5-5`, but no `claude-haiku-5-5` (only a Bedrock `-v1` id exists upstream). The provider code already knows `haiku-5` ids (adaptive thinking, `crates/pa-ai/src/providers/anthropic/mod.rs`), so only the catalog entry is missing.
Smallest fix, no code change: a custom `models.json` in the agent dir (supported by `crates/pa-core/src/models/custom.rs`):
```json
{ "providers": { "anthropic": { "models": [
  { "id": "claude-haiku-5-5", "name": "Claude Haiku 5.5", "api": "anthropic-messages",
    "reasoning": true, "input": ["text", "image"],
    "contextWindow": 200000, "maxTokens": 64000,
    "cost": { "input": 1, "output": 5, "cacheRead": 0.1, "cacheWrite": 1.25 } } ] } } }
```
UNCONFIRMED values: contextWindow, maxTokens and cost are copied from the Haiku 4.5 row (the only Haiku data in the repo). Confirm the real Haiku 5.5 numbers before rollout; cost only affects usage reporting. `api` must match the other anthropic rows in the live catalog (check `prime-agent model list --json`).

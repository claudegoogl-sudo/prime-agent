# Hermetic tests and where the daemon suite may run (PLA-12418)

- Rust daemon default socket dir: `/tmp/prime-agent-rs-<uid>/` (the Node product keeps `/tmp/prime-agent-<uid>/`). Override: `PRIME_AGENT_PLATFORM_SOCKET_DIR`.
- The daemon refuses to start if the dir has a foreign `.pa-generation` marker, or is a Node-style dir holding `.sock`/`.lock` entries.
- `cargo test` runs through `scripts/hermetic-test-runner.sh`: each test binary gets its own temp HOME, agent dir, kernel venv, session dir and socket dir, and aborts (exit 98) if any resolves under the real HOME.
- The runner refuses (exit 97) to run as user `paperclip`. Run the daemon suite only as isolated user `pae2e` or on the home PC. Set `PA_TEST_ALLOW_ANY_USER=1` only there.
- Runbook note for PA-E2E.md: "The pa-daemon/pa-cli suite runs only as pae2e or on the home PC, never as paperclip."

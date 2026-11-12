# Hermetic tests and where the daemon suite may run (PLA-12418)

- Rust daemon default socket dir: `/tmp/prime-agent-rs-<uid>/` (the Node product keeps `/tmp/prime-agent-<uid>/`). Override: `PRIME_AGENT_PLATFORM_SOCKET_DIR`.
- The daemon refuses to start if the dir has a foreign `.pa-generation` marker, or is a Node-style dir holding `.sock`/`.lock` entries.
- `cargo test` runs through `scripts/hermetic-test-runner.sh`: each test binary gets its own temp HOME, agent dir, kernel venv, session dir and socket dir, and aborts (exit 98) if any resolves under the real HOME.
- The runner refuses (exit 97) to run as user `paperclip`. Run the daemon suite only as isolated user `pae2e` or on the home PC. Set `PA_TEST_ALLOW_ANY_USER=1` only there.
- Runbook note for PA-E2E.md: "The pa-daemon/pa-cli suite runs only as pae2e or on the home PC, never as paperclip."

## Upgrading a socket dir written by an older Rust build (PLA-12418)

Builds up to 882ede07 wrote sockets and locks with no `.pa-generation` marker.
The new build refuses such an unmarked dir (it cannot tell it from a Node dir).
Chosen method: explicit install step, no guessing heuristic. Before the first
start of the new build on an existing dir, either:

- stop the agents, then run `printf rust > <socket dir>/.pa-generation`, or
- stop the agents and empty the dir (sockets and locks are recreated).

Add this step to CANARY-INSTALL.md. A fresh install uses the new default dir
`/tmp/prime-agent-rs-<uid>` and needs nothing.

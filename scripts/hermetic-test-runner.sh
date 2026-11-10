#!/usr/bin/env bash
# Cargo test runner (see .cargo/config.toml). PLA-12418: every test binary runs
# with its OWN temp HOME, agent dir, kernel venv, session dir and socket dir.
# No test touches the invoking user's HOME, ~/.prime, kernel venv or sockets.
# The daemon suite is for the isolated user `pae2e` or the home PC only,
# NEVER the `paperclip` user (it killed live agents on 2026-11-10).
set -euo pipefail
bin="$1"; shift
case "$bin" in */deps/*) ;; *) exec "$bin" "$@" ;; esac   # only test binaries
real_home="${HOME:-}"
if [ "${PA_TEST_ALLOW_ANY_USER:-}" != "1" ] && [ "$(id -un)" = "paperclip" ]; then
  echo "hermetic-runner: refusing to run tests as user 'paperclip'. Use user pae2e or the home PC (docs/TESTING-HERMETIC.md)." >&2
  exit 97
fi
sandbox="$(mktemp -d /tmp/pa-test-XXXXXX)"
trap 'rm -rf "$sandbox"' EXIT
# Session dirs are NOT pinned: they derive from the sandboxed agent dir, and tests set their own.
# The e2e lanes need a kernel python. Use the invoker's (read-only) when no explicit one is given.
# Agent dir + kernel venv derive from the sandboxed HOME too (tests set HOME and expect $HOME/.prime/agent);
# an inherited override would point at the invoker, so unset them.
unset PRIME_AGENT_SESSION_DIR PRIME_AGENT_CODING_AGENT_SESSION_DIR PRIME_AGENT_CODING_AGENT_DIR PRIME_AGENT_KERNEL_VENV
if [ -z "${PA_E2E_KERNEL_PYTHON:-}" ] && [ -n "$real_home" ] && [ -x "$real_home/.prime/agent/kernel-venv/bin/python" ]; then
  export PA_E2E_KERNEL_PYTHON="$real_home/.prime/agent/kernel-venv/bin/python"
fi
export HOME="$sandbox/home" \
  PRIME_AGENT_PLATFORM_SOCKET_DIR="$sandbox/s" TMPDIR="$sandbox/t" \
  XDG_CONFIG_HOME="$sandbox/xdg-config" XDG_DATA_HOME="$sandbox/xdg-data" XDG_RUNTIME_DIR="$sandbox/xdg-run"
mkdir -p "$HOME" "$TMPDIR" "$sandbox/s"
# Guard: abort if any resolved path is under the real HOME.
for v in HOME PRIME_AGENT_PLATFORM_SOCKET_DIR TMPDIR; do
  val="${!v}"
  if [ -n "$real_home" ] && [ "$real_home" != "/" ]; then
    case "$val/" in "$real_home"/*) echo "hermetic-runner: $v=$val is under the real HOME; abort" >&2; exit 98 ;; esac
  fi
done
"$bin" "$@"

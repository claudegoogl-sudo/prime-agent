#!/usr/bin/env bash
# PLATFORM-PATCH 1: isolated prime-agent (Rust build). Usage: set PA_ROOT, or
# keep the default. Pins registry dir, daemon socket and worker-socket dir so
# a stale system daemon and an inherited TMPDIR are never used.
set -euo pipefail
PA_ROOT="${PA_ROOT:-$HOME/work/prime-agent-rust}"
mkdir -p "$PA_ROOT/supervisor" "$PA_ROOT/sock"
chmod 700 "$PA_ROOT/supervisor" "$PA_ROOT/sock"
export PRIME_AGENT_INTERNAL_DAEMON_SUPERVISOR_REGISTRY_DIR="$PA_ROOT/supervisor"
export PRIME_AGENT_PLATFORM_SOCKET_DIR="$PA_ROOT/sock"
# Subcommands (status, list, ...) reject --daemon-socket; pin it only for run/print modes.
case "${1:-}" in
  help|agents|list|sessions|attach|stop|rename|send|schedule|status|telemetry|doctor|incident|shutdown|mcp|package|update|model|session|config)
    exec "${PA_BIN:-$PA_ROOT/bin/prime-agent}" "$@" ;;
  *)
    exec "${PA_BIN:-$PA_ROOT/bin/prime-agent}" --daemon-socket "$PA_ROOT/sock/daemon.sock" "$@" ;;
esac

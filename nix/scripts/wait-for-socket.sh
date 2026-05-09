#!/usr/bin/env bash
set -euo pipefail

socket="${1:?socket path required}"
timeout="${2:-120}"
pid="${3:-}"
deadline=$((SECONDS + timeout))

while (( SECONDS < deadline )); do
  if [[ -S "$socket" ]]; then
    exit 0
  fi
  if [[ -n "$pid" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "Process $pid exited before socket $socket was created" >&2
    exit 1
  fi
  sleep 1
done

echo "Timed out waiting for socket $socket after ${timeout}s" >&2
exit 1

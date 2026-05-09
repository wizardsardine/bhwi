#!/usr/bin/env bash
set -euo pipefail

host="${1:?host required}"
port="${2:?port required}"
timeout="${3:-120}"
pid="${4:-}"
deadline=$((SECONDS + timeout))

while (( SECONDS < deadline )); do
  if nc -z "$host" "$port" >/dev/null 2>&1; then
    exit 0
  fi
  if [[ -n "$pid" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "Process $pid exited before $host:$port became reachable" >&2
    exit 1
  fi
  sleep 1
done

echo "Timed out waiting for $host:$port after ${timeout}s" >&2
exit 1

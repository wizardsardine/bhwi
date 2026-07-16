#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: stop-emulator.sh PID_FILE [tcp HOST PORT|socket PATH] [TIMEOUT_SECONDS]" >&2
  exit 2
fi

pid_file="$1"
shift
endpoint_type="${1:-}"
timeout_seconds=30

case "$endpoint_type" in
  tcp)
    host="${2:?tcp endpoint requires HOST}"
    port="${3:?tcp endpoint requires PORT}"
    timeout_seconds="${4:-30}"
    ;;
  socket)
    socket="${2:?socket endpoint requires PATH}"
    timeout_seconds="${3:-30}"
    ;;
  "")
    ;;
  *)
    echo "unknown endpoint type: $endpoint_type" >&2
    exit 2
    ;;
esac

if [[ -f "$pid_file" ]]; then
  pid="$(cat "$pid_file")"
  kill_target="$pid"
  process_group="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
  if [[ "$process_group" == "$pid" ]]; then
    kill_target="-$pid"
  fi
  if kill -0 -- "$kill_target" 2>/dev/null; then
    kill -- "$kill_target" 2>/dev/null || true
    deadline=$((SECONDS + timeout_seconds))
    while kill -0 -- "$kill_target" 2>/dev/null && ((SECONDS < deadline)); do
      sleep 1
    done
    if kill -0 -- "$kill_target" 2>/dev/null; then
      kill -KILL -- "$kill_target" 2>/dev/null || true
    fi
  fi
fi

deadline=$((SECONDS + timeout_seconds))
case "$endpoint_type" in
  tcp)
    while (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; do
      if ((SECONDS >= deadline)); then
        echo "TCP endpoint still open after stopping emulator: $host:$port" >&2
        exit 1
      fi
      sleep 1
    done
    ;;
  socket)
    while [[ -S "$socket" ]]; do
      if ((SECONDS >= deadline)); then
        rm -f "$socket"
        break
      fi
      sleep 1
    done
    ;;
esac

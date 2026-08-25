#!/usr/bin/env bash
set -euo pipefail

host="${1:?host required}"
port="${2:?port required}"
timeout="${3:-120}"
pid="${4:-}"
deadline=$((SECONDS + timeout))

# The emulators speak UDP, which has no connect to probe, so ask them to answer instead.
probe() {
  python3 - "$host" "$port" <<'PY'
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1)
try:
    sock.connect((host, port))
    sock.send(b"PINGPING")
    sys.exit(0 if sock.recv(8) == b"PONGPONG" else 1)
except OSError:
    sys.exit(1)
finally:
    sock.close()
PY
}

while ((SECONDS < deadline)); do
  if probe >/dev/null 2>&1; then
    exit 0
  fi
  if [[ -n "$pid" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "Process $pid exited before $host:$port answered" >&2
    exit 1
  fi
  sleep 1
done

echo "Timed out waiting for Trezor emulator on $host:$port after ${timeout}s" >&2
exit 1

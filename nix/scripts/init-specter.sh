#!/usr/bin/env bash
set -euo pipefail

host="${SPECTER_GUI_HOST:-127.0.0.1}"
port="${SPECTER_GUI_PORT:-8787}"
python="${SPECTER_PYTHON:?SPECTER_PYTHON must point to python3}"

# This is the upstream controller's deterministic public test vector.  It is
# synthetic and is deliberately never emitted by this script or CI.
"$python" - "$host" "$port" <<'PY'
import json
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
commands = ("", "", 1, " ".join(["abandon"] * 11 + ["about"]))

with socket.create_connection((host, port), timeout=10) as connection:
    connection.settimeout(10)
    for stage, command in enumerate(commands, start=1):
        connection.sendall(json.dumps(command).encode() + b"\r\n")
        response = b""
        while not response.endswith(b"\r\n"):
            chunk = connection.recv(1024)
            if not chunk:
                raise RuntimeError(f"Specter GUI closed during initialization stage {stage}")
            response += chunk
PY

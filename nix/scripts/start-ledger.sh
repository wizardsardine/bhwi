#!/usr/bin/env bash
set -euo pipefail

speculos="${SPECULOS_BIN:-speculos}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_script="${LEDGER_BUILD_APP_SCRIPT:-$script_dir/build-ledger-app.sh}"

elf="$(bash "$build_script")"

echo "Starting Speculos with $elf" >&2
exec "$speculos" "$elf" \
  --model nanox \
  --display headless \
  --apdu-port "${LEDGER_APDU_PORT:-9999}" \
  --api-port "${LEDGER_API_PORT:-5000}"

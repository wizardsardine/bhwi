#!/usr/bin/env bash
# Launch the BitBox02 firmware simulator for the `bhwi-e2e-bitbox` suite.
#
# The simulator listens on 127.0.0.1:15423 and speaks the same U2F-HID framing as real
# hardware. `BITBOX_SIMULATOR_BIN` is provided by the nix runner (a pinned, autopatched
# release binary); when running outside nix, point it at a simulator binary yourself.
set -euo pipefail

: "${BITBOX_SIMULATOR_BIN:?BITBOX_SIMULATOR_BIN must point to a BitBox02 simulator binary}"

# Run in a scratch directory so any simulator state does not litter the working tree.
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
cd "$workdir"

echo "Starting BitBox02 simulator on 127.0.0.1:15423"
echo "  binary: $BITBOX_SIMULATOR_BIN"
exec "$BITBOX_SIMULATOR_BIN"

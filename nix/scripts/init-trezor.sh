#!/usr/bin/env bash
set -euo pipefail

python_src="${TREZOR_PYTHON_SRC:?TREZOR_PYTHON_SRC must point to the trezorlib source}"
export PYTHONPATH="$python_src${PYTHONPATH:+:$PYTHONPATH}"

device="${TREZOR_DEVICE:-udp:127.0.0.1:21324}"
mnemonic="${TREZOR_MNEMONIC:-all all all all all all all all all all all all}"
label="${TREZOR_LABEL:-bhwi}"
pin="${TREZOR_PIN:-}"

python3 - <<PY
from trezorlib import debuglink, device
from trezorlib.debuglink import TrezorClientDebugLink
from trezorlib.transport import get_transport

client = TrezorClientDebugLink(get_transport("${device}"))
client.open()
device.wipe(client)
debuglink.load_device(
    client,
    mnemonic="${mnemonic}",
    pin="${pin}" or None,
    passphrase_protection=False,
    label="${label}",
)
client.close()
PY

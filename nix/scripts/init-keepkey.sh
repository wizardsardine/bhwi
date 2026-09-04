#!/usr/bin/env bash
set -euo pipefail

export KEEPKEY_DEVICE="${KEEPKEY_DEVICE:-udp:127.0.0.1:11044}"
export KEEPKEY_MNEMONIC="${KEEPKEY_MNEMONIC:-alcohol woman abuse must during monitor noble actual mixed trade anger aisle}"
export KEEPKEY_LABEL="${KEEPKEY_LABEL:-test}"
export KEEPKEY_PIN="${KEEPKEY_PIN:-}"
export KEEPKEY_PASSPHRASE_PROTECTION="${KEEPKEY_PASSPHRASE_PROTECTION:-false}"

python3 - <<'PY'
import os

from hwilib.devices.keepkey import (
    KeepkeyDebugLinkState,
    KeepkeyFeatures,
    KeepkeyResetDevice,
)
from hwilib.devices.trezorlib import device
from hwilib.devices.trezorlib.debuglink import TrezorClientDebugLink, load_device_by_mnemonic
from hwilib.devices.trezorlib.mapping import DEFAULT_MAPPING
from hwilib.devices.trezorlib.models import TrezorModel
from hwilib.devices.trezorlib.transport.udp import UdpTransport

value = os.environ["KEEPKEY_PASSPHRASE_PROTECTION"].lower()
if value in {"1", "true", "yes", "on"}:
    passphrase_protection = True
elif value in {"0", "false", "no", "off"}:
    passphrase_protection = False
else:
    raise SystemExit("KEEPKEY_PASSPHRASE_PROTECTION must be true or false")

mapping = DEFAULT_MAPPING
mapping.register(KeepkeyFeatures)
mapping.register(KeepkeyResetDevice)
mapping.register(KeepkeyDebugLinkState)
model = TrezorModel(
    name="K1-14M",
    internal_name="keepkey_emu",
    minimum_version=(0, 0, 0),
    vendors=("keepkey.com",),
    usb_ids=(),
    default_mapping=mapping,
)
transport = UdpTransport.find_by_path(os.environ["KEEPKEY_DEVICE"])
client = TrezorClientDebugLink(transport, model=model)
try:
    client.init_device()
    device.wipe(client)
    load_device_by_mnemonic(
        client=client,
        mnemonic=os.environ["KEEPKEY_MNEMONIC"],
        pin=os.environ["KEEPKEY_PIN"],
        passphrase_protection=passphrase_protection,
        label=os.environ["KEEPKEY_LABEL"],
        language="english",
    )
finally:
    client.close()
PY

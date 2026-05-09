#!/usr/bin/env bash
set -euo pipefail

cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/jade"
src="${JADE_FIRMWARE_SRC:?JADE_FIRMWARE_SRC must point to Jade source}"
rev="${JADE_FIRMWARE_REV:-$(basename "$src")}"
src_key="${rev//[^A-Za-z0-9_.-]/_}"
work="$cache_root/source-$src_key"
device="${JADE_DEVICE:-tcp:localhost:30121}"
pinserver_url="${JADE_PINSERVER_URL:-http://localhost:8096}"
mnemonic="${JADE_MNEMONIC:-fish inner face ginger orchard permit useful method fence kidney chuckle party favorite sunset draw limb science crane oval letter slot invite sadness banana}"

mkdir -p "$cache_root"
if [[ ! -d "$work" ]]; then
  echo "Preparing Jade source in $work" >&2
  mkdir -p "$work"
  if [[ -n "${JADE_FIRMWARE_URL:-}" && "$rev" != "locked" ]]; then
    git clone --recursive "$JADE_FIRMWARE_URL" "$work"
    git -C "$work" checkout "$rev"
    git -C "$work" submodule update --init --recursive
  else
    cp -R "$src"/. "$work"/
  fi
  chmod -R u+w "$work"
fi

cd "$work"
if [[ ! -d venv ]]; then
  python3 -m venv venv
  venv/bin/pip install --upgrade pip setuptools
  if [[ -f requirements.txt ]]; then
    venv/bin/pip install -r requirements.txt
  fi
  venv/bin/pip install click
  venv/bin/pip install -e .
fi

venv/bin/python - <<PY
from jadepy.jade import JadeAPI

jade = JadeAPI.create_serial(device="${device}")
jade.connect()
jade.set_mnemonic("${mnemonic}")
jade.disconnect()
PY

if [[ -x ./jade_cli.py ]]; then
  venv/bin/python ./jade_cli.py --device "$device" set-pinserver \
    --pubkey server_public_key.pub \
    "$pinserver_url"
else
  echo "jade_cli.py not found; mnemonic was set but pinserver was not configured" >&2
  exit 1
fi

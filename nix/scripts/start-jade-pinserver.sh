#!/usr/bin/env bash
set -euo pipefail

cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/jade"
src="${JADE_FIRMWARE_SRC:?JADE_FIRMWARE_SRC must point to Jade source}"
pinserver_src="${JADE_PINSERVER_SRC:?JADE_PINSERVER_SRC must point to the Jade pinserver source}"
pinserver_rev="${JADE_PINSERVER_REV:-$(basename "$pinserver_src")}"
pinserver_key="${pinserver_rev//[^A-Za-z0-9_.-]/_}"
package_parent="$cache_root/pinserver-source-$pinserver_key"
work="$package_parent/pinserver"
pins_dir="${JADE_PINS_DIR:-$cache_root/pins}"
port="${JADE_PINSERVER_PORT:-8096}"
runtime_dir="$cache_root/pinserver-runtime-$pinserver_key"
python="${JADE_PINSERVER_PYTHON:-python3}"
server_key="${JADE_SERVER_PRIVATE_KEY:-$src/server_private_key.key}"

mkdir -p "$cache_root" "$pins_dir"

if [[ ! -d "$work" ]]; then
  echo "Preparing Jade pinserver source in $work" >&2
  rm -rf "$package_parent"
  mkdir -p "$package_parent"
  if [[ -d "$pinserver_src" ]]; then
    mkdir -p "$work"
    cp -R "$pinserver_src"/. "$work"/
  elif [[ -n "${JADE_PINSERVER_URL:-}" && "$pinserver_rev" != "locked" ]]; then
    git clone "$JADE_PINSERVER_URL" "$work"
    git -C "$work" checkout "$pinserver_rev"
  else
    mkdir -p "$work"
    cp -R "$pinserver_src"/. "$work"/
  fi
  chmod -R u+w "$package_parent"
fi

if [[ ! -f "$work/flaskserver.py" || ! -f "$work/requirements.txt" ]]; then
  echo "Jade pinserver source is incomplete in $work" >&2
  exit 1
fi

if [[ ! -f "$server_key" ]]; then
  echo "Jade pinserver private key is missing at $server_key" >&2
  exit 1
fi

cd "$work"
if [[ ! -d venv-pinserver ]]; then
  "$python" -m venv venv-pinserver
  venv-pinserver/bin/pip install --upgrade pip setuptools wheel
  venv-pinserver/bin/pip install --require-hashes -r requirements.txt
fi

mkdir -p "$runtime_dir"
ln -sfn "$pins_dir" "$runtime_dir/pins"
ln -sf "$server_key" "$runtime_dir/server_private_key.key"

cd "$runtime_dir"
export PYTHONPATH="$package_parent"
exec "$work/venv-pinserver/bin/python" - <<PY
from pinserver.flaskserver import app

app.run(host="0.0.0.0", port=${port})
PY

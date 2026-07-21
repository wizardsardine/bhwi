#!/usr/bin/env bash
set -euo pipefail

cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/coldcard"
src="${COLDCARD_FIRMWARE_SRC:?COLDCARD_FIRMWARE_SRC must point to Coldcard firmware source}"
rev="${COLDCARD_FIRMWARE_REV:-$(basename "$src")}"
src_key="${rev//[^A-Za-z0-9_.-]/_}"
work="$cache_root/firmware-$src_key"
marker="$work/.bhwi-built"
build_key_file="$work/.bhwi-build-key"
build_key="rev=$rev simulator=unpatched-mk5-v1"
socket="${COLDCARD_SOCKET:-/tmp/ckcc-simulator.sock}"

dump_build_logs() {
  local status=$?
  local config_log="$work/external/micropython/ports/unix/build-standard/lib/libffi/config.log"
  if [[ $status -ne 0 && -f "$config_log" ]] && ! grep -q "configure: exit 0" "$config_log"; then
    echo "Coldcard libffi configure log:" >&2
    awk '
      /checking whether the C compiler works/ { show = 1 }
      show { print }
      /configure: exit/ { exit }
    ' "$config_log" >&2
  fi
  exit "$status"
}
trap dump_build_logs ERR

if [[ -S "$socket" ]]; then
  echo "Coldcard socket already exists: $socket" >&2
  echo "Stop the existing simulator or remove the stale socket before starting a new one." >&2
  exit 1
fi

mkdir -p "$cache_root"

if [[ ! -f "$marker" || ! -f "$build_key_file" || "$(cat "$build_key_file")" != "$build_key" ]]; then
  echo "Building Coldcard simulator in $work" >&2
  rm -rf "$work"
  if [[ -n "${COLDCARD_FIRMWARE_URL:-}" && "$rev" != "locked" ]]; then
    git clone "$COLDCARD_FIRMWARE_URL" "$work"
    git -C "$work" checkout "$rev"
    git -C "$work" submodule update --init \
      external/ckcc-protocol \
      external/libngu \
      external/micropython \
      external/mpy-qr
  else
    mkdir -p "$work"
    cp -R "$src"/. "$work"/
  fi
  chmod -R u+w "$work"

  cd "$work"
  # Upstream ships OS-specific micropython patches (clang vs gcc warning flags).
  if [[ "$(uname)" == "Darwin" && -f macos-mpy.patch ]]; then
    (cd external/micropython && git apply ../../macos-mpy.patch)
  elif [[ -f ubuntu24_mpy.patch ]]; then
    (cd external/micropython && git apply ../../ubuntu24_mpy.patch)
  fi
  mpy_cflags_extra="${MPY_CFLAGS_EXTRA:--Wno-error}"
  python3 -m venv ENV
  ENV/bin/pip install --upgrade pip setuptools
  grep -v \
    -e '^-r ./testing/requirements.txt$' \
    -e '^-r ./misc/gpu/requirements.txt$' \
    requirements.txt > .bhwi-simulator-requirements.txt
  ENV/bin/pip install -r .bhwi-simulator-requirements.txt
  ENV/bin/pip install pysdl2-dll
  unset CFLAGS
  unset LDFLAGS
  make -C external/micropython/mpy-cross CFLAGS_EXTRA="$mpy_cflags_extra"
  ln -sfn ../external/micropython/ports/unix unix/l-port
  ln -sfn ../external/micropython unix/l-mpy
  ln -sfn ../external/micropython/ports/unix/coldcard-mpy unix/coldcard-mpy
  git -C external/micropython submodule update --init lib/axtls lib/berkeley-db-1.xx lib/libffi
  make -C unix PWD="$work/unix" ngu-setup CFLAGS_EXTRA="$mpy_cflags_extra"
  make -C unix PWD="$work/unix" PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-}" CFLAGS_EXTRA="$mpy_cflags_extra"
  printf '%s\n' "$build_key" > "$build_key_file"
  touch "$marker"
fi

cd "$work/unix"
if [[ -n "${COLDCARD_RUNTIME_LIBRARY_PATH:-}" ]]; then
  if [[ "$(uname)" == "Darwin" ]]; then
    export DYLD_LIBRARY_PATH="$COLDCARD_RUNTIME_LIBRARY_PATH"
  else
    export LD_LIBRARY_PATH="$COLDCARD_RUNTIME_LIBRARY_PATH"
  fi
fi
exec ../ENV/bin/python3 simulator.py --headless

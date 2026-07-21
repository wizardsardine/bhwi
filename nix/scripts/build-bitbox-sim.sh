#!/usr/bin/env bash
set -euo pipefail

cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/bitbox"
rev="${BITBOX_FIRMWARE_REV:?BITBOX_FIRMWARE_REV must be set (e.g. firmware/v9.26.4)}"
url="${BITBOX_FIRMWARE_URL:-https://github.com/BitBoxSwiss/bitbox02-firmware.git}"
src_key="${rev//[^A-Za-z0-9_.-]/_}"
work="$cache_root/firmware-$src_key"
marker="$work/.bhwi-built"
build_key_file="$work/.bhwi-build-key"
build_key="rev=$rev url=$url simulator=v1"
sim="$work/build-build-noasan/bin/simulator"

mkdir -p "$cache_root"

if [[ ! -f "$marker" || ! -x "$sim" || ! -f "$build_key_file" || "$(cat "$build_key_file")" != "$build_key" ]]; then
  echo "Building BitBox02 simulator in $work" >&2
  rm -rf "$work"
  # Full clone: generate_version_headers.py resolves the version via git describe over the bootloader/* and firmware/* tags.
  git clone --recursive "$url" "$work" >&2
  git -C "$work" checkout "$rev" >&2
  git -C "$work" submodule update --init --recursive >&2
  chmod -R u+w "$work"

  # -Zbuild-std needs rust-src and the embedded targets on the firmware's pinned toolchain.
  toolchain="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$work/src/rust/rust-toolchain.toml")"
  rustup toolchain install "$toolchain" --profile minimal -c rust-src \
    -t thumbv7em-none-eabi -t thumbv8m.main-none-eabihf >&2

  make -C "$work" simulator >&2
  test -x "$sim"
  printf '%s\n' "$build_key" > "$build_key_file"
  touch "$marker"
fi

printf '%s\n' "$sim"

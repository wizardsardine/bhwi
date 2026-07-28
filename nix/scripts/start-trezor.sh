#!/usr/bin/env bash
set -euo pipefail

variant="${TREZOR_VARIANT:?TREZOR_VARIANT must be legacy or core}"
case "$variant" in
  legacy | core) ;;
  *)
    echo "unknown TREZOR_VARIANT: $variant (expected legacy or core)" >&2
    exit 2
    ;;
esac

cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/trezor"
profile="${TREZOR_PROFILE_DIR:-$cache_root/profile-$variant}"
mkdir -p "$profile"

export SDL_VIDEODRIVER="${SDL_VIDEODRIVER:-dummy}"
export TREZOR_PROFILE_DIR="$profile"

if [[ -n "${TREZOR_EMULATOR_BIN:-}" ]]; then
  exec "$TREZOR_EMULATOR_BIN" "$@"
fi

src="${TREZOR_FIRMWARE_SRC:?TREZOR_FIRMWARE_SRC must point to trezor-firmware source}"
rev="${TREZOR_FIRMWARE_REV:-$(basename "$src")}"
url="${TREZOR_FIRMWARE_URL:?TREZOR_FIRMWARE_URL must be set}"
src_key="${rev//[^A-Za-z0-9_.-]/_}"
work="$cache_root/firmware-$src_key"
build_key_file="$work/.bhwi-build-key-$variant"
build_key="rev=$rev variant=$variant debuglink=1"

if [[ "$variant" == legacy ]]; then
  emulator="$work/legacy/firmware/trezor.elf"
  run_dir="$work/legacy/firmware"
  # legacy/emulator/setup.c includes libopencm3 headers even in emulator builds.
  submodules=(vendor/nanopb vendor/QR-Code-generator vendor/secp256k1-zkp vendor/libopencm3)
  clean_paths=(legacy crypto common storage)
  build_cmd="poetry install --no-root && cd legacy && EMULATOR=1 DEBUG_LINK=1 poetry run script/cibuild"
else
  emulator="$work/core/build/unix/trezor-emu-core"
  # build_unix is unfrozen, so the binary loads its micropython sources from core/src.
  run_dir="$work/core/src"
  submodules=(vendor/nanopb vendor/QR-Code-generator vendor/secp256k1-zkp vendor/micropython)
  clean_paths=(core)
  build_cmd="poetry install --no-root && cd core && poetry run make build_unix"
fi

# The flake input is a source tarball and both emulators need submodules.
if [[ ! -d "$work/.git" ]]; then
  echo "Fetching trezor-firmware $rev into $work" >&2
  rm -rf "$work"
  mkdir -p "$work"
  git -C "$work" init -q
  git -C "$work" remote add origin "$url"
  git -C "$work" fetch -q --depth 1 origin "$rev"
  git -C "$work" checkout -q FETCH_HEAD
fi

if [[ ! -x "$emulator" ]] ||
  [[ ! -f "$build_key_file" ]] ||
  [[ "$(cat "$build_key_file")" != "$build_key" ]]; then
  git -C "$work" submodule update --init --depth 1 "${submodules[@]}"

  # Build flags are not tracked by make, so drop stale objects before rebuilding.
  rm -f "$build_key_file"
  git -C "$work" clean -qfdX "${clean_paths[@]}"

  echo "Building Trezor $variant emulator in $work" >&2
  (cd "$work" && nix-shell "$work/shell.nix" --run "$build_cmd")
  printf '%s\n' "$build_key" > "$build_key_file"
fi

cd "$run_dir"
exec "$emulator" "$@"

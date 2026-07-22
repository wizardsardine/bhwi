#!/usr/bin/env bash
set -euo pipefail

cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/jade"
src="${JADE_FIRMWARE_SRC:?JADE_FIRMWARE_SRC must point to Jade source}"
rev="${JADE_FIRMWARE_REV:-$(basename "$src")}"
src_key="${rev//[^A-Za-z0-9_.-]/_}"
work="$cache_root/source-$src_key"
flash="$cache_root/flash-image-$src_key.bin"
marker="$cache_root/.flash-built-$src_key"
prepare_hwi_dir=""
if [[ "${1:-}" == "--prepare-hwi" ]]; then
  prepare_hwi_dir="${2:?--prepare-hwi requires an output directory}"
  shift 2
fi
if [[ $# -ne 0 ]]; then
  echo "usage: start-jade.sh [--prepare-hwi OUTPUT_DIR]" >&2
  exit 2
fi

mkdir -p "$cache_root"

prepare_source() {
  rm -rf "$work"
  if [[ -n "${JADE_FIRMWARE_URL:-}" && "$rev" != "locked" ]]; then
    git clone --recursive "$JADE_FIRMWARE_URL" "$work"
    git -C "$work" checkout "$rev"
    git -C "$work" submodule update --init --recursive
  else
    mkdir -p "$work"
    cp -R "$src"/. "$work"/
  fi
  chmod -R u+w "$work"
}

if [[ ! -f "$flash" || ! -f "$marker" ]]; then
  echo "Building Jade QEMU flash image in $work" >&2
  prepare_source

  cd "$work"
  ./tools/switch_to.sh qemu --dev --ci --psram
  idf.py all
  ./tools/fwprep.py build/jade.bin build
  python_bin="${IDF_PYTHON_ENV_PATH:+$IDF_PYTHON_ENV_PATH/bin/python}"
  python_bin="${python_bin:-python3}"
  "$python_bin" -m esptool \
    --chip esp32 merge_bin \
    --fill-flash-size 4MB \
    -o "$flash" \
    --flash_mode dio \
    --flash_freq 40m \
    --flash_size 4MB \
    0x9000 build/partition_table/partition-table.bin \
    0xe000 build/ota_data_initial.bin \
    0x1000 build/bootloader/bootloader.bin \
    0x10000 build/jade.bin
  touch "$marker"
elif [[ ! -d "$work" ]]; then
  prepare_source
fi

if [[ -n "$prepare_hwi_dir" ]]; then
  mkdir -p "$prepare_hwi_dir"
  cp "$flash" "$prepare_hwi_dir/flash_image.bin"
  cp "$work/main/qemu/qemu_efuse.bin" "$prepare_hwi_dir/qemu_efuse.bin"
  ln -s "$(command -v qemu-system-xtensa)" "$prepare_hwi_dir/qemu-system-xtensa"
  qemu_dir="$(dirname "$(command -v qemu-system-xtensa)")"
  if [[ -d "$qemu_dir/../share/qemu" ]]; then
    ln -s "$qemu_dir/../share/qemu" "$prepare_hwi_dir/pc-bios"
  elif [[ -d "${QEMU_PC_BIOS_DIR:-}" ]]; then
    ln -s "$QEMU_PC_BIOS_DIR" "$prepare_hwi_dir/pc-bios"
  else
    echo "unable to locate QEMU pc-bios directory" >&2
    exit 1
  fi
  exit 0
fi

exec qemu-system-xtensa \
  -nographic \
  -machine esp32 \
  -m 4M \
  -drive "file=$flash,if=mtd,format=raw" \
  -drive "file=$work/main/qemu/qemu_efuse.bin,if=none,format=raw,id=efuse" \
  -global driver=nvram.esp32.efuse,property=drive,value=efuse \
  -nic user,model=open_eth,id=lo0,hostfwd=tcp:0.0.0.0:30122-:30122,hostfwd=tcp:0.0.0.0:30121-:30121

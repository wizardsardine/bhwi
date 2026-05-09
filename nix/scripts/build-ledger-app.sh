#!/usr/bin/env bash
set -euo pipefail

cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/ledger"
src="${APP_BITCOIN_NEW_SRC:?APP_BITCOIN_NEW_SRC must point to app-bitcoin-new source}"

if [[ -n "${LEDGER_APP_ELF:-}" ]]; then
  if [[ ! -f "$LEDGER_APP_ELF" ]]; then
    echo "LEDGER_APP_ELF does not exist: $LEDGER_APP_ELF" >&2
    exit 1
  fi
  printf '%s\n' "$LEDGER_APP_ELF"
  exit 0
fi

rev="${APP_BITCOIN_NEW_REV:-$(basename "$src")}"
src_key="${rev//[^A-Za-z0-9_.-]/_}"
work="$cache_root/app-bitcoin-new-$src_key"
elf="$work/build/nanox/bin/app.elf"
marker="$work/.bhwi-built"
image="${LEDGER_APP_BUILDER_IMAGE:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest}"

mkdir -p "$cache_root"

if [[ ! -f "$elf" || ! -f "$marker" ]]; then
  echo "Building Ledger Bitcoin app ELF in $work" >&2
  rm -rf "$work"
  if [[ -n "${APP_BITCOIN_NEW_URL:-}" && "$rev" != "locked" ]]; then
    git clone --recursive "$APP_BITCOIN_NEW_URL" "$work"
    git -C "$work" checkout "$rev"
    git -C "$work" submodule update --init --recursive
  else
    mkdir -p "$work"
    cp -R "$src"/. "$work"/
  fi
  chmod -R u+w "$work"

  if command -v docker >/dev/null 2>&1; then
    runner=(docker run --rm --user "$(id -u):$(id -g)" -v "$work:/app" -w /app "$image")
  elif command -v podman >/dev/null 2>&1; then
    runner=(podman run --rm --user "$(id -u):$(id -g)" -v "$work:/app:Z" -w /app "$image")
  else
    echo "Neither docker nor podman is available for Ledger app-builder" >&2
    exit 1
  fi

  "${runner[@]}" bash -lc 'BOLOS_SDK=$NANOX_SDK make' >&2
  test -f "$elf"
  touch "$marker"
fi

printf '%s\n' "$elf"

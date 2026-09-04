#!/usr/bin/env bash
set -euo pipefail

prepare_only=0
if [[ "${1:-}" == "--prepare-hwi" ]]; then
  prepare_only=1
  shift
fi
if [[ "$prepare_only" == 1 && $# -ne 0 ]]; then
  echo "usage: start-keepkey.sh [--prepare-hwi]" >&2
  exit 2
fi

cache_root="${XDG_CACHE_HOME:-${HOME:?HOME is required when XDG_CACHE_HOME is unset}/.cache}/bhwi/keepkey"

if [[ -n "${KEEPKEY_EMULATOR_BIN:-}" ]]; then
  if [[ ! -x "$KEEPKEY_EMULATOR_BIN" ]]; then
    echo "KEEPKEY_EMULATOR_BIN is not executable: $KEEPKEY_EMULATOR_BIN" >&2
    exit 2
  fi
  emulator="$(realpath "$KEEPKEY_EMULATOR_BIN")"
else
  firmware_src="${KEEPKEY_FIRMWARE_SRC:?KEEPKEY_FIRMWARE_SRC must point to pinned KeepKey firmware}"
  firmware_rev="${KEEPKEY_FIRMWARE_REV:?KEEPKEY_FIRMWARE_REV must be set}"
  nanopb_src="${KEEPKEY_NANOPB_SRC:?KEEPKEY_NANOPB_SRC must point to pinned nanopb}"
  nanopb_rev="${KEEPKEY_NANOPB_REV:?KEEPKEY_NANOPB_REV must be set}"
  build_patch="${KEEPKEY_BUILD_PATCH:?KEEPKEY_BUILD_PATCH must point to keepkey-build.patch}"
  googletest_patch="${KEEPKEY_GOOGLETEST_PATCH:?KEEPKEY_GOOGLETEST_PATCH must point to keepkey-googletest.patch}"
  nanopb_patch="${KEEPKEY_NANOPB_PATCH:?KEEPKEY_NANOPB_PATCH must point to nanopb-deprecated-mode.patch}"
  cmake_patch="${KEEPKEY_CMAKE_PATCH:?KEEPKEY_CMAKE_PATCH must point to the KeepKey CMake compatibility patch}"
  protoc="${KEEPKEY_PROTOC:?KEEPKEY_PROTOC must point to protoc}"
  : "${KEEPKEY_BUILD_TOOLCHAIN:?KEEPKEY_BUILD_TOOLCHAIN must be set}"

  for directory in "$firmware_src" "$nanopb_src"; do
    if [[ ! -d "$directory" ]]; then
      echo "pinned source directory does not exist: $directory" >&2
      exit 2
    fi
  done
  for file in "$build_patch" "$googletest_patch" "$nanopb_patch" "$cmake_patch"; do
    if [[ ! -f "$file" ]]; then
      echo "required KeepKey patch does not exist: $file" >&2
      exit 2
    fi
  done
  if [[ ! -x "$protoc" ]]; then
    echo "KEEPKEY_PROTOC is not executable: $protoc" >&2
    exit 2
  fi

  build_key="firmware=$firmware_rev nanopb=$nanopb_rev build_patch=$(sha256sum "$build_patch" | cut -d' ' -f1) googletest_patch=$(sha256sum "$googletest_patch" | cut -d' ' -f1) nanopb_patch=$(sha256sum "$nanopb_patch" | cut -d' ' -f1) cmake_patch=$(sha256sum "$cmake_patch" | cut -d' ' -f1) firmware_src=$KEEPKEY_FIRMWARE_SRC nanopb_src=$KEEPKEY_NANOPB_SRC toolchain=$KEEPKEY_BUILD_TOOLCHAIN recipe=9"
  work="$cache_root/build"
  key_file="$work/.bhwi-build-key"
  emulator="$work/firmware/bin/kkemu"

  mkdir -p "$cache_root"
  if [[ ! -x "$emulator" || ! -f "$key_file" || "$(cat "$key_file")" != "$build_key" ]]; then
    echo "Building pinned KeepKey emulator in $work" >&2
    rm -rf "$work"
    mkdir -p "$work/firmware" "$work/nanopb"
    cp -R "$firmware_src"/. "$work/firmware"/
    cp -R "$nanopb_src"/. "$work/nanopb"/
    chmod -R u+w "$work"

    patch -d "$work/firmware" -p1 < "$build_patch" >&2
    patch -d "$work/firmware/deps/googletest" -p1 < "$googletest_patch" >&2
    patch -d "$work/nanopb" -p1 < "$nanopb_patch" >&2
    patch -d "$work/firmware" -p1 < "$cmake_patch" >&2
    make -C "$work/nanopb/generator/proto" >&2
    python_bin="$(command -v python3)"
    mkdir -p "$work/bin"
    cat > "$work/bin/protoc-gen-nanopb" <<EOF
#!$BASH
exec "$python_bin" "$work/nanopb/generator/nanopb_generator.py" --protoc-plugin "\$@"
EOF
    cat > "$work/bin/nanopb_generator.py" <<EOF
#!$BASH
exec "$python_bin" "$work/nanopb/generator/nanopb_generator.py" "\$@"
EOF
    chmod +x "$work/bin/protoc-gen-nanopb" "$work/bin/nanopb_generator.py"
    make_bin="$(command -v make)"
    cat > "$work/make-with-shell" <<EOF
#!$BASH
exec "$make_bin" SHELL="$BASH" "\$@"
EOF
    chmod +x "$work/make-with-shell"
    (
      cd "$work/firmware"
      unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
      unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
      export PATH="$work/bin:$PATH"
      cmake \
        -C cmake/caches/emulator.cmake \
        -DNANOPB_DIR="$work/nanopb" \
        -DPROTOC_BINARY="$protoc" \
        -DCMAKE_MAKE_PROGRAM="$work/make-with-shell" \
        . >&2
      cmake --build . --parallel "$(nproc)" >&2
    )
    if [[ ! -x "$emulator" ]]; then
      echo "KeepKey build did not produce bin/kkemu" >&2
      exit 1
    fi
    printf '%s\n' "$build_key" > "$key_file"
  fi
  emulator="$(realpath "$emulator")"
fi

if [[ "$prepare_only" == 1 ]]; then
  printf '%s\n' "$emulator"
  exit 0
fi

profile="${KEEPKEY_PROFILE_DIR:-$cache_root/profile}"
export KEEPKEY_PROFILE_DIR="$profile"
umask 077
mkdir -p -- "$profile"
chmod 0700 -- "$profile"
cd -- "$profile"
exec "$emulator" "$@"

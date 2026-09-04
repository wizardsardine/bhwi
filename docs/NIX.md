# Nix

BHWI uses Nix flake outputs to run emulator-backed e2e tests for its supported
devices.

Most emulator outputs build on `x86_64-linux` and `aarch64-darwin` (Apple
Silicon). KeepKey's source-built emulator outputs are currently
`x86_64-linux` only. All are intended for GitHub Actions first, with the same
commands available locally.

## Platforms

The `nix run` and `nix develop` commands below are identical on every platform.

On macOS the device simulators have no prebuilt binaries, so they build from
source on first run under `$XDG_CACHE_HOME/bhwi`:

- Coldcard and Jade build natively.
- BitBox02 builds from source with `make simulator`. Linux keeps the prebuilt
  release binary.
- Ledger runs the `arm64` variant of the multi-arch app-builder container
  natively and publishes ports, because Docker Desktop and OrbStack on macOS do
  not support `--network host`.

Linux-only outputs:

- `bitbox02-simulator` (the prebuilt release binary).
- The HWI parity and upstream suites (`hwi-parity-*`, `hwi-upstream-*`), which
  need Linux emulator toolchains.
- `keepkey`, `keepkey-init`, `hwi-parity-keepkey`,
  `hwi-upstream-keepkey`, and the `keepkey` development shell and package
  outputs additionally require `x86_64-linux`.

The macOS emulator run is not part of PR CI and is intended for a separate
on-demand workflow.

## CI

`.github/workflows/emulators.yml` runs:

- `nix flake show --allow-import-from-derivation`
- `nix build .#checks.x86_64-linux.emulator-scripts`
- `cargo test -p bhwi-e2e-bitbox -- --test-threads=1`
- `cargo test -p bhwi-e2e-coldcard -- --test-threads=1`
- `cargo test -p bhwi-e2e-ledger -- --test-threads=1`
- `cargo test -p bhwi-e2e-jade -- --test-threads=1`
- `cargo test -p bhwi-e2e-trezor -- --test-threads=1`, once per model
- `cargo test -p bhwi-e2e-keepkey -- --test-threads=1`, its native CLI and
  differential HWI parity suites, three fresh-profile management lifecycles,
  and the 90-minute `hwi-upstream-keepkey` final gate

CI uses:

- Determinate Systems Nix installer
- `actions/cache` for mutable emulator build caches under
  `$XDG_CACHE_HOME/bhwi`. The KeepKey cache key includes runner OS and
  architecture, the exact `flake.lock` hash, and the build-input hash; its sole
  restore prefix retains the OS, architecture, and exact lock hash.

This avoids committing firmware binaries while preventing heavy emulator
artifacts from rebuilding on every PR once the cache is warm. Nix store paths
come from the public binary caches configured by the installer.

## Flake Outputs

Apps:

- `nix run .#bitbox`
- `nix run .#coldcard`
- `nix run .#ledger`
- `nix run .#ledger-build-app`
- `nix run .#hwi-upstream-suite`
- `nix run .#hwi-upstream-bitbox`
- `nix run .#hwi-upstream-coldcard`
- `nix run .#hwi-upstream-ledger`
- `nix run .#hwi-upstream-jade`
- `nix run .#hwi-upstream-keepkey`
- `nix run .#hwi-parity-keepkey`
- `nix run .#jade-pinserver`
- `nix run .#jade`
- `nix run .#jade-init`
- `nix run .#trezor-one`
- `nix run .#trezor-t`
- `nix run .#trezor-init`
- `nix run .#keepkey`
- `nix run .#keepkey-init`

Development shells:

- `nix develop .#bitbox`
- `nix develop .#coldcard`
- `nix develop .#ledger`
- `nix develop .#jade`
- `nix develop .#trezor`
- `nix develop .#keepkey`

Packages/checks:

- `nix build .#speculos`
- `nix build .#bitbox02-simulator`
- `nix build .#coldcard-simulator`
- `nix build .#hwi-reference`
- `nix build .#hwi-upstream-suite`
- `nix build .#hwi-upstream-keepkey`
- `nix build .#ledger-app`
- `nix build .#jade-qemu`
- `nix build .#checks.x86_64-linux.emulator-scripts`

## Local E2E

Run each emulator in its own terminal, then run the matching test command from
another terminal after the emulator is ready. The first run may take a while
because firmware and Python environments are built under `$XDG_CACHE_HOME/bhwi`.

BitBox02:

```sh
# Terminal 1
nix run .#bitbox

# Terminal 2
nix develop .#bitbox -c cargo test -p bhwi-e2e-bitbox -- --test-threads=1
```

Coldcard:

```sh
# Terminal 1
nix run .#coldcard

# Terminal 2
nix develop .#coldcard -c cargo test -p bhwi-e2e-coldcard -- --test-threads=1
```

Ledger:

```sh
# Terminal 1
nix run .#ledger

# Terminal 2
nix develop .#ledger -c cargo test -p bhwi-e2e-ledger -- --test-threads=1
```

Jade:

```sh
# Terminal 1
nix run .#jade-pinserver

# Terminal 2
nix run .#jade

# Terminal 3, after QEMU is listening
nix run .#jade-init

# Terminal 3
nix develop .#jade -c cargo test -p bhwi-e2e-jade -- --test-threads=1
```

Trezor. The Trezor One runs the `legacy` firmware and the Model T the `core`
firmware, so each model has its own emulator app. Both listen on UDP 21324, so
run only one at a time.

```sh
# Terminal 1
nix run .#trezor-one   # or nix run .#trezor-t

# Terminal 2, after the emulator answers
nix run .#trezor-init

# Terminal 2
nix develop .#trezor -c cargo test -p bhwi-e2e-trezor -- --test-threads=1
```

KeepKey. The main and debug UDP endpoints are 11044 and 11045.

```sh
# Terminal 1
nix run .#keepkey

# Terminal 2, after the emulator answers
nix run .#keepkey-init

# Terminal 2
nix develop .#keepkey -c cargo test -p bhwi-e2e-keepkey -- --test-threads=1
```

Useful readiness checks:

```sh
test -S /tmp/ckcc-simulator.sock
nc -z localhost 9999 && nc -z localhost 5000
nc -z localhost 8096 && nc -z localhost 30121
bash nix/scripts/wait-for-udp-emulator.sh 127.0.0.1 21324 60
bash nix/scripts/wait-for-udp-emulator.sh 127.0.0.1 11044 60
```

## Upstream HWI Suite

BHWI pins Bitcoin Core HWI 3.2.0 and exposes two kinds of parity helper:

- `hwi-reference`: runs Python HWI directly.
- `hwi-upstream-suite`: runs HWI's upstream `test/` suite in `--interface=cli`
  mode against a BHWI binary named by `HWI_BIN`.

The upstream suite is the final parity gate for every HWI-supported device that
BHWI claims to support. Each tailored app builds the BHWI `hwi` binary and
prepares its pinned simulator automatically:

```sh
nix run .#hwi-upstream-bitbox
nix run .#hwi-upstream-coldcard
nix run .#hwi-upstream-ledger
nix run .#hwi-upstream-jade
nix run .#hwi-upstream-keepkey
nix run .#hwi-upstream-trezor
nix run .#hwi-upstream-trezor-t
```

The generic dispatcher is also available:

```sh
nix run .#hwi-upstream-suite -- bitbox02
nix run .#hwi-upstream-suite -- coldcard
nix run .#hwi-upstream-suite -- ledger
nix run .#hwi-upstream-suite -- jade
nix run .#hwi-upstream-suite -- keepkey
nix run .#hwi-upstream-suite -- trezor
nix run .#hwi-upstream-suite -- trezor-t
```

The runner uses the pinned HWI Python interpreter and unmodified HWI 3.2.0
tests. It accepts `HWI_BIN` and `HWI_BITCOIND` overrides,
`HWI_LEDGER_APP_ELF` for a prebuilt Ledger app, pre-prepared
`HWI_COLDCARD_SIMULATOR` or `HWI_JADE_SIMULATOR_DIR` paths, and
`HWI_KEEPKEY_EMULATOR` for a prepared `kkemu`. A relative
`HWI_KEEPKEY_EMULATOR` path is resolved from the runner's invocation directory.
Without that override the generic and tailored KeepKey runners invoke
`HWI_KEEPKEY_PREPARE_SCRIPT` with `--prepare-hwi` and the same pinned source,
patch, compiler, and protobuf environment as `nix run .#keepkey`.

## Device Details

BitBox02:

- On Linux, downloads a pinned `BitBoxSwiss/bitbox02-firmware` multi-edition
  simulator release binary (autopatched to run on NixOS). On macOS, builds that
  same pinned firmware from source with `make simulator`.
- Starts the simulator on TCP `localhost:15423`.
- The simulator auto-confirms Noise pairing and restores a fixed mnemonic when
  the package e2e seeds it.

Coldcard:

- Uses pinned `Coldcard/firmware`.
- Builds the Unix simulator in `$XDG_CACHE_HOME/bhwi/coldcard`. On macOS applies
  the upstream `macos-mpy.patch` and links against `DYLD_LIBRARY_PATH`.
- The upstream HWI gate uses a separate `-hwi` simulator cache with HWI's own
  `coldcard-multisig.patch`; the normal Coldcard emulator remains unpatched.
- Starts `simulator.py --headless`.
- Exposes `/tmp/ckcc-simulator.sock`.

Ledger:

- Uses `LedgerHQ/app-bitcoin-new` pinned to the app version declared by the
  upstream HWI suite, currently `2.4.1`.
- Builds the Nano X Bitcoin app ELF through Ledger's app-builder container and
  caches it under `$XDG_CACHE_HOME/bhwi/ledger`.
- Starts Speculos through Ledger's app-builder container on APDU
  `localhost:9999` and API `localhost:5000`. On macOS the container runs as its
  native `arm64` variant with published ports instead of `--network host`.
- `LEDGER_APP_ELF=/path/to/app.elf` can override the cached build.

Jade:

- Uses pinned `Blockstream/Jade`.
- Uses `nixpkgs-esp-dev` for ESP-IDF and Espressif QEMU.
- Runs the Jade pinserver directly from the pinned `blind_pin_server`
  submodule with a cached Python venv.
- Builds/caches `flash_image.bin` under `$XDG_CACHE_HOME/bhwi/jade`.
- Starts QEMU TCP serial on `localhost:30121` and web display on
  `localhost:30122`.
- `jade-init` sets the e2e mnemonic and configures the local pinserver.

Trezor:

- Uses pinned `trezor/trezor-firmware`, the same revision the vendored protobuf
  bindings in `bhwi/src/trezor/proto.rs` are generated from.
- The Trezor One runs the `legacy` firmware and the Model T the `core` firmware.
  These are separate firmware codebases, so `trezor-one` and `trezor-t` are
  separate emulators rather than one binary with a model switch.
- On Linux, downloads the pinned prebuilt emulator binaries published by
  upstream (autopatched to run on NixOS). On macOS, no prebuilt is published, so
  both are built from source in `$XDG_CACHE_HOME/bhwi/trezor` through
  trezor-firmware's own `shell.nix`, which is the macOS path upstream documents.
- The `legacy` emulator is built with `DEBUG_LINK=1` so `trezor-init` can load a
  seed over the debug link.
- Both listen on UDP `127.0.0.1:21324` with the debug link on `21325`, so only
  one model can run at a time.
- `trezor-init` loads the e2e mnemonic. `TREZOR_MNEMONIC` overrides it.

KeepKey:

- Uses recursively pinned KeepKey firmware v7.10.0 commit
  `d54797ee604f12c82ac6e5e02490b62dc04bf2dd`, including device-protocol
  `323802f17dd44165a5100357df771348c8b49672`, and nanopb
  `493adf3616bee052649c63c473f8355630c2797f`.
- Copies the read-only sources to
  `${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/keepkey/build`, applies HWI 3.2.0's
  `keepkey-build.patch`, `keepkey-googletest.patch`, and
  `nanopb-deprecated-mode.patch`, then applies BHWI's source-only
  `nix/patches/keepkey/cmake-minimum.patch` for current CMake. It creates local
  Bash launchers for GNU Make and nanopb because NixOS has no `/bin/sh`, then
  builds `bin/kkemu` with Nix `protoc`. The `recipe=9` build key contains both
  revisions, the firmware and nanopb Nix store paths, all four patch checksums,
  and the exact toolchain identity
  `${pkgs.runtimeShell}:${pkgs.lib.makeBinPath [ pkgs.cmake pkgs.gcc pkgs.gnumake pkgs.patch pkgs.protobuf hwiPython ]}`.
- Runs from
  `${KEEPKEY_PROFILE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/keepkey/profile}`
  so the relative `emulator.img` is isolated. Before entering the profile, the
  launcher sets umask `077` and creates or repairs the directory to mode
  `0700`. `KEEPKEY_EMULATOR_BIN` selects a prepared executable.
- Listens on UDP `127.0.0.1:11044`, with its debug link on `11045`.
  `keepkey-init` loads the documented synthetic fixture without printing its
  mnemonic, PIN, or passphrase settings.
- The generic and tailored upstream suites symlink the binary as a temporary
  `kkemu`, let upstream create a fresh image per test, drive confirmations on
  debug port 11045, and surface `keepkey-emulator.stdout` on failure. Stop a
  shared emulator before running either upstream gate.
- Emulator outputs are `x86_64-linux` only. Physical HID/WebUSB and browser
  WebHID/WebUSB support remain available on their existing platforms. See
  [KEEPKEY](KEEPKEY.md).

## Notes

- Emulator tests must run serially. Pass `-- --test-threads=1`; this is not set
  in `.cargo/config.toml`.
- Most emulator outputs build on `x86_64-linux` and `aarch64-darwin`; KeepKey
  emulator outputs are `x86_64-linux` only. See Platforms for the other
  platform specifics.
- The first CI run for a changed emulator source may be slow. Follow-up runs
  should hit Magic Nix Cache and the `$XDG_CACHE_HOME/bhwi` artifact cache.

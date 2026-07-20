# Nix

BHWI uses Nix flake outputs to run emulator-backed e2e tests for the currently
supported devices: Coldcard, Ledger, and Jade.

The emulator outputs build on `x86_64-linux` and `aarch64-darwin` (Apple
Silicon), and are intended for GitHub Actions first, with the same commands
available locally.

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
  need the linux-amd64 prebuilt simulator and a toolchain that does not build on
  darwin.

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

CI uses:

- Determinate Systems Nix installer
- `actions/cache` for mutable emulator build caches under
  `$XDG_CACHE_HOME/bhwi`

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
- `nix run .#jade-pinserver`
- `nix run .#jade`
- `nix run .#jade-init`

Development shells:

- `nix develop .#bitbox`
- `nix develop .#coldcard`
- `nix develop .#ledger`
- `nix develop .#jade`

Packages/checks:

- `nix build .#speculos`
- `nix build .#bitbox02-simulator`
- `nix build .#coldcard-simulator`
- `nix build .#hwi-reference`
- `nix build .#hwi-upstream-suite`
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

Useful readiness checks:

```sh
test -S /tmp/ckcc-simulator.sock
nc -z localhost 9999 && nc -z localhost 5000
nc -z localhost 8096 && nc -z localhost 30121
```

## Upstream HWI Suite

BHWI pins Bitcoin Core HWI 3.2.0 and exposes two parity helpers:

- `hwi-reference`: runs Python HWI directly.
- `hwi-upstream-suite`: runs HWI's upstream `test/` suite in `--interface=cli`
  mode against a BHWI binary named by `HWI_BIN`.

The upstream suite is the final parity gate for every HWI-supported device that
BHWI claims to support. New device onboarding should enable that device's
upstream HWI suite once BHWI has the matching device support.

Ledger can use the existing pinned app-builder and Speculos wrapper:

```sh
cargo build -p bhwi-cli --bin hwi
HWI_BIN="$PWD/target/debug/hwi" nix run .#hwi-upstream-suite -- ledger
```

Coldcard and Jade need HWI-compatible simulator artifacts because upstream HWI's
tests start their own emulator processes:

```sh
cargo build -p bhwi-cli --bin hwi
HWI_BIN="$PWD/target/debug/hwi" \
HWI_COLDCARD_SIMULATOR=/path/to/firmware/unix/simulator.py \
nix run .#hwi-upstream-suite -- coldcard

HWI_BIN="$PWD/target/debug/hwi" \
HWI_JADE_SIMULATOR_DIR=/path/to/hwi-style/jade/simulator \
nix run .#hwi-upstream-suite -- jade
```

The runner also accepts `HWI_BITCOIND` to override the `bitcoind` used by the
upstream suite, and `HWI_LEDGER_APP_ELF` to use a prebuilt Ledger app.

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
- Starts `simulator.py --headless`.
- Exposes `/tmp/ckcc-simulator.sock`.

Ledger:

- Uses pinned `LedgerHQ/app-bitcoin-new`.
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

## Notes

- Emulator tests must run serially. Pass `-- --test-threads=1`; this is not set
  in `.cargo/config.toml`.
- Emulator outputs build on `x86_64-linux` and `aarch64-darwin`. See Platforms
  for the macOS specifics and the Linux-only outputs.
- The first CI run for a changed emulator source may be slow. Follow-up runs
  should hit Magic Nix Cache and the `$XDG_CACHE_HOME/bhwi` artifact cache.

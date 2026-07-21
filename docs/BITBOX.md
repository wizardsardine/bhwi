# BitBox02 Emulation

## Nix

The recommended local e2e path is the Nix runner documented in
[`docs/NIX.md`](NIX.md). It downloads the pinned BitBox02 multi-edition
simulator and exposes it over TCP on `127.0.0.1:15423`.

```sh
# Terminal 1
nix run .#bitbox

# Terminal 2
nix develop .#bitbox -c cargo test -p bhwi-e2e-bitbox -- --test-threads=1
```

The `bhwi` core interpreter is gated behind the `bitbox` cargo feature (enabled
by default). The simulator speaks the same U2F-HID framing as real hardware, so
the only difference from the USB HID path is the underlying byte channel (a TCP
stream). The simulator auto-confirms Noise pairing, so no on-device button press
is required.

## CLI e2e

The `bhwi` CLI reaches the simulator over TCP through the BitBox02 emulator path
(`tcp:127.0.0.1:15423`). Use the native global selectors for stateful commands
that must address an uninitialized device without a fingerprint:

```sh
bhwi --device-type bitbox02 --device-path tcp:127.0.0.1:15423 device setup
bhwi --device-type bitbox02 --device-path tcp:127.0.0.1:15423 device wipe
bhwi --device-type bitbox02 --device-path tcp:127.0.0.1:15423 device restore
bhwi --device-type bitbox02 --device-path tcp:127.0.0.1:15423 device toggle-passphrase
```

Successful action commands are quiet by default; add `--format json` for a
structured success response. `setup` and `restore` accept `--label`. Python-HWI
compatibility keeps its upstream command names and flags, including
`togglepassphrase`, `--interactive`, `--word_count`, and
`--backup_passphrase` validation.

The regular seeded-device CLI suite remains:

```sh
cargo build -p bhwi-cli
BHWI_BIN="$PWD/target/debug/bhwi" nix develop .#bitbox \
  -c cargo test -p bhwi-e2e-cli bitbox -- --test-threads=1
```

CI additionally runs the ignored setup/wipe and restore lifecycle tests against
fresh simulator processes. A successful wipe resets the firmware before it can
reply and leaves this simulator version in its reset loop, so the test harness
restarts it before continuing.

## Upstream references

- [BitBox02 firmware and simulator](https://github.com/BitBoxSwiss/bitbox02-firmware)
- [bitbox-api-rs](https://github.com/BitBoxSwiss/bitbox-api-rs) — the reference
  Rust client the BHWI protocol code was ported from.

The pinned simulator binary is downloaded from the firmware repository's release
assets; the version and hash are recorded in [`flake.nix`](../flake.nix).

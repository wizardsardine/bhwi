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
(`tcp:127.0.0.1:15423`). The CLI has no restore command, so seed the simulator
by running the package e2e first, then run the CLI e2e against the seeded
device:

```sh
cargo build -p bhwi-cli
BHWI_BIN="$PWD/target/debug/bhwi" nix develop .#bitbox \
  -c cargo test -p bhwi-e2e-cli bitbox -- --test-threads=1
```

## Upstream references

- [BitBox02 firmware and simulator](https://github.com/BitBoxSwiss/bitbox02-firmware)
- [bitbox-api-rs](https://github.com/BitBoxSwiss/bitbox-api-rs) — the reference
  Rust client the BHWI protocol code was ported from.

The pinned simulator binary is downloaded from the firmware repository's release
assets; the version and hash are recorded in [`flake.nix`](../flake.nix).

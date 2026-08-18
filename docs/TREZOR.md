# Trezor Emulation

## Nix

The recommended local e2e path is the Nix runner documented in
[`docs/NIX.md`](NIX.md). Trezor ships two separate firmware codebases, so there
is one emulator per model. Both expose the wire protocol over UDP on
`127.0.0.1:21324` and debuglink on `127.0.0.1:21325`.

```sh
# Terminal 1
nix run .#trezor-one   # or nix run .#trezor-t

# Terminal 2
nix run .#trezor-init

# Terminal 3
nix develop .#trezor -c cargo test -p bhwi-e2e-trezor -- --test-threads=1
```

`trezor-init` loads the deterministic test mnemonic; the emulator starts
unseeded. Set `TREZOR_MODEL` to `trezor-one` or `trezor-t` so model-specific
assertions select the right firmware version.

The `bhwi` core interpreter is gated behind the `trezor` cargo feature, which is
**not** enabled by default. Protocol-v1 framing is identical over HID, WebUSB and
the UDP emulator, so one `TrezorTransport` serves all three and the emulator
differs only in the underlying byte channel.

Unlike the BitBox02 simulator, the Trezor emulator does **not** auto-confirm.
Any command that shows a prompt needs a debuglink button press. `e2e/trezor`
drives this through `debuglink::DebugLink`; the same encoders are reused by the
parity suite and the CLI e2e crate.

If an emulator hangs on start with no UDP socket bound, delete its stale flash
image and start it again:

```sh
rm -f "${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/trezor/profile-core/trezor.flash"
rm -f "${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/trezor/profile-legacy/trezor.flash"
```

`profile-core` is the Model T, `profile-legacy` the Model One. Deleting the
image also resets the device to uninitialized, which is what the lifecycle tests
below require.

## CLI e2e

The `bhwi` CLI reaches the emulator over UDP (`udp:127.0.0.1:21324`). Use the
native global selectors for stateful commands that must address an uninitialized
device without a fingerprint:

```sh
bhwi --device-type trezor --device-path udp:127.0.0.1:21324 device setup
bhwi --device-type trezor --device-path udp:127.0.0.1:21324 device wipe
bhwi --device-type trezor --device-path udp:127.0.0.1:21324 device restore --word-count 12
bhwi --device-type trezor --device-path udp:127.0.0.1:21324 device toggle-passphrase
bhwi --device-type trezor --device-path udp:127.0.0.1:21324 device prompt-pin
bhwi --device-type trezor --device-path udp:127.0.0.1:21324 device send-pin <positions>
```

Successful action commands are quiet by default; add `--format json` for a
structured success response. `setup` and `restore` accept `--label`, and
`restore` accepts `--word-count` (12, 18 or 24). Python-HWI compatibility keeps
its upstream command names and flags, including `togglepassphrase`,
`--interactive` and `--word_count`.

Commands split by model:

| Command | Model One | Model T |
|---|---|---|
| `setup`, `restore` | unsupported — needs host PIN and word entry | supported, entered on the device screen |
| `prompt-pin`, `send-pin` | supported — host supplies scrambled keypad positions | unsupported — PIN is entered on the touchscreen |

`send-pin` takes positions on the device's scrambled keypad, not the PIN digits
themselves.

The regular seeded-device CLI suite remains:

```sh
cargo build -p bhwi-cli
BHWI_BIN="$PWD/target/debug/bhwi" nix develop .#trezor \
  -c cargo test -p bhwi-e2e-cli trezor -- --test-threads=1
```

Restore is covered by two `#[ignore]`d lifecycle tests that each require a fresh
uninitialized Model T and leave it initialized:

```sh
TREZOR_MODEL=trezor-t cargo test -p bhwi-e2e-trezor \
  can_restore_from_a_recovery_phrase -- --ignored
BHWI_BIN="$PWD/target/debug/bhwi" cargo test -p bhwi-e2e-cli \
  trezor_restore_management_lifecycle -- --ignored
```

They restore the Python HWI test mnemonic, so the device ends on fingerprint
`95d8f670` rather than the `trezor-init` seed. Re-run `trezor-init` on a wiped
emulator before the regular suites.

## Upstream references

- [trezor-firmware](https://github.com/trezor/trezor-firmware) — both the legacy
  (Model One) and core (Model T) emulators, and the protobuf definitions the
  vendored bindings in [`bhwi/src/trezor/proto.rs`](../bhwi/src/trezor/proto.rs)
  are generated from.
- `hwilib/devices/trezorlib` in Bitcoin Core HWI — the reference client the BHWI
  protocol code is checked against.

The pinned firmware revision is recorded in [`flake.nix`](../flake.nix).

# BitBox02 End-to-End Testing

These tests drive the BitBox02 integration against the official BitBox02 firmware
**simulator** over TCP. The simulator speaks the same U2F-HID framing as real hardware, so
the only thing that differs from the USB path is the byte channel (a `TcpStream` instead of
HID); everything above it — noise pairing, protobuf, signing — is exercised for real.

## Running the Tests

1. Start a simulator listening on `127.0.0.1:15423`:

   ```sh
   nix run .#bitbox
   ```

   This fetches a pinned, autopatched release binary (see `flake.nix`,
   `bitboxSimulatorVersion`) and runs it. Outside nix, run any BitBox02 simulator binary and
   point it at that port yourself.

2. In another shell:

   ```sh
   cargo test -p bhwi-e2e-bitbox
   ```

## Notes

- Each test pairs (the simulator auto-confirms) and seeds the device with its fixed BIP39
  mnemonic via `restore_from_mnemonic`, so all derived keys are deterministic. Expected
  values are computed host-side from `SIMULATOR_XPRV`.
- The tests run single-threaded (`RUST_TEST_THREADS=1` in `.cargo/config.toml`) because the
  simulator binds a single fixed port.
- The `nix run .#bitbox` simulator is a single long-lived process shared by every test in a
  run. The suite handles this (a second `restore` on an already-seeded device is treated as
  a no-op), but `can_display_address_by_descriptor` **registers a policy**, and BitBox02
  rejects duplicate registrations — so **restart the simulator between full `cargo test`
  runs** (Ctrl-C `nix run .#bitbox` and start it again).
- `can_display_address_by_descriptor` asserts only that a well-formed mainnet address is
  returned; pin the exact value once observed against the simulator.

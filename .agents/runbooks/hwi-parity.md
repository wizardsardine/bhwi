# HWI Parity Runbook

Use this when changing the Python-HWI-compatible `hwi` binary, device
enumeration, command parsing, command output, or HWI status docs.

## Contract

- Compare BHWI `hwi` output against pinned Python HWI.
- Match command names, argument names, short flags, JSON key names, JSON value
  shapes, error codes, and base64 formats where parity is claimed.
- Parse unsupported Python HWI commands and return Python-HWI-shaped unsupported
  errors instead of clap parse errors.
- Record every intentional divergence in `docs/HWI_PARITY.md`.
- Treat the unmodified upstream HWI device suite as the final acceptance gate.
  Do not patch upstream tests or add BHWI-owned skips.
- Emulator compatibility changes authored by upstream HWI, such as
  `test/data/coldcard-multisig.patch`, may be applied to an isolated emulator
  build. Keep the normal emulator build unchanged.

## Local Foundation

Build the candidate binary:

```sh
cargo build -p bhwi-cli --bin hwi
```

Run the harness directly when custom binaries are needed:

```sh
REFERENCE_HWI_BIN="$(nix build --no-link --print-out-paths .#hwi-reference-bhwi)/bin/hwi-reference-bhwi" \
HWI_BIN="$PWD/target/debug/hwi" \
nix develop -c cargo test -p bhwi-e2e-hwi-parity
```

## Device-Scoped Apps

Run only one emulator family at a time. Multiple active emulator families can
contaminate reference/candidate enumeration and cause misleading parity
failures.

```sh
nix run .#hwi-parity-coldcard
nix run .#hwi-parity-ledger
nix run .#hwi-parity-jade
nix run .#hwi-parity-bitbox
```

After focused and differential parity checks pass, stop any long-lived
simulator and run the matching final gate:

```sh
nix run .#hwi-upstream-coldcard
nix run .#hwi-upstream-ledger
nix run .#hwi-upstream-jade
nix run .#hwi-upstream-bitbox
```

## Adding A Parity Device

- Add the device to the pinned reference HWI restriction in `flake.nix`
  (`commands.all_devs`).
- Add a `mkHwiParityRunner` instance with
  `HWI_PARITY_DEVICE_TYPE=<device>`.
- Export a `hwi-parity-<device>` flake app.
- Add the device to `e2e/hwi-parity` normalization.
- Add command fixtures or device-specific assertions needed for the new device.
- Wire the parity app into `.github/workflows/emulators.yml`.
- Wire the tailored `hwi-upstream-<device>` app into the same CI job as its
  final test step, after stopping the long-lived emulator.
- Update `docs/HWI_PARITY.md` with status, known deviations, and validation
  evidence.

## Failure Triage

- If JSON differs, compare field names, optional field presence, value formats,
  and device ordering before changing protocol code.
- If reference discovery sees the wrong device, stop extra emulator families and
  rerun with only the intended device active.
- If Python HWI times out or fails before BHWI runs, inspect pinned dependency
  behavior in `flake.nix` before patching BHWI.
- If the candidate fails only after selecting a device, classify the failure as
  parser, CLI selection, async device, transport, protocol, or emulator setup.
- If the differential suite passes but the upstream gate fails, treat the
  upstream case as a missing compatibility contract. Do not normalize it away
  or add a local skip.

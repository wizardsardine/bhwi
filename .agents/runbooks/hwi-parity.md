# HWI Parity Runbook

Use this when changing the Python-HWI-compatible `hwi` binary, device
enumeration, command parsing, command output, or HWI status docs.

## Contract

- Compare BHWI `hwi` output against pinned Python HWI.
- Match command names, argument names, short flags, JSON key names, JSON value
  shapes, error codes, and base64 formats where parity is claimed.
- Parse unsupported Python HWI commands and return Python-HWI-shaped unsupported
  errors instead of clap parse errors.
- Match Python HWI's exit statuses: `0` for success, `--help`, `--version`, and
  every runtime `{"error", "code"}` JSON response; `2` for usage errors, which
  print code `-2` JSON on stdout and usage text on stderr; `1` is reserved for
  internal crashes. The harness asserts process status, not just JSON.
- Record every intentional divergence in `docs/HWI_PARITY.md`.
- Treat the unmodified upstream HWI device suite as the final acceptance gate.
  Do not patch upstream tests or add BHWI-owned skips.
- Emulator compatibility changes authored by upstream HWI, such as
  `test/data/coldcard-multisig.patch`, may be applied to an isolated emulator
  build. Keep the normal emulator build unchanged.

## Evidence Boundaries

- **Differential parity** runs each project-owned fixture through both pinned
  Python HWI and `target/debug/hwi`, then compares observable process and JSON
  behavior. It proves only the fixtures exercised by the harness.
- **Candidate lifecycle** runs an ignored, project-owned management test only
  against `target/debug/hwi` on a fresh uninitialized emulator. It covers
  management methods that upstream HWI 3.2.0 omits or cannot exercise; it is
  behavioral evidence, not reference parity.
- **Upstream gate** runs the pinned, unmodified HWI 3.2.0 device suite through
  `target/debug/hwi`. It proves compatibility only for methods upstream
  actually invokes; upstream skips are not coverage.

## Local Foundation

Build the candidate binary:

```sh
cargo build -p bhwi-cli --bin hwi
```

Run the harness directly when custom binaries are needed. The device type and
development shell must name the same family; this example targets Ledger:

```sh
REFERENCE_HWI_BIN="$(nix build --no-link --print-out-paths .#hwi-reference-bhwi)/bin/hwi-reference-bhwi" \
HWI_BIN="$PWD/target/debug/hwi" \
HWI_PARITY_DEVICE_TYPE=ledger \
nix develop .#ledger -c cargo test -p bhwi-e2e-hwi-parity -- --test-threads=1
```

The other valid type/shell pairs are `bitbox02`/`.#bitbox`,
`coldcard`/`.#coldcard`, `jade`/`.#jade`, `trezor`/`.#trezor`, and
`keepkey`/`.#keepkey`.

## Ordinary Differential Runs

An ordinary differential run requires exactly one already-running,
initialized emulator. The parity app does not start or initialize it. Stop
every other emulator family first so reference and candidate enumeration
cannot discover the wrong device.

```sh
timeout 20m nix run .#hwi-parity-bitbox -- -- --test-threads=1
timeout 20m nix run .#hwi-parity-coldcard -- -- --test-threads=1
timeout 20m nix run .#hwi-parity-ledger -- -- --test-threads=1
timeout 20m nix run .#hwi-parity-jade -- -- --test-threads=1
timeout 20m nix run .#hwi-parity-trezor -- -- --test-threads=1
timeout 20m nix run .#hwi-parity-keepkey -- -- --test-threads=1
```

The Trezor command applies to whichever one initialized Trezor model is
running.

## Candidate-Only Management Lifecycles

Do not reuse the initialized emulator from an ordinary differential run for
these ignored tests.

For BitBox02, each filter requires its own fresh, uninitialized
`nix run .#bitbox` process on TCP `127.0.0.1:15423`; do not run the BitBox
initializer. The setup filter wipes and resets the device. Stop that process,
wait 65 seconds for the fixed port to leave `TIME_WAIT`, then start a separate
fresh process for the restore filter. Stop the restore process before the
upstream gate.

```sh
timeout 20m nix run .#hwi-parity-bitbox -- tests::candidate_bitbox_setup_management_lifecycle -- --ignored --exact --test-threads=1
timeout 20m nix run .#hwi-parity-bitbox -- tests::candidate_bitbox_restore_management_lifecycle -- --ignored --exact --test-threads=1
```

For Trezor, start a fresh, uninitialized `nix run .#trezor-t` process on UDP
`127.0.0.1:21324` with its own newly cleared `TREZOR_PROFILE_DIR`; do not run
`trezor-init`. Run the filter below, then stop the process before any other
lifecycle or upstream gate.

```sh
TREZOR_MODEL=trezor-t timeout 10m nix run .#hwi-parity-trezor -- tests::candidate_trezor_restore_management_lifecycle -- --ignored --exact --test-threads=1
```

## Upstream Gates

Stop every shared emulator before an upstream gate. Each tailored app prepares
its matching emulator and runs the pinned, unmodified HWI 3.2.0 device suite
against `target/debug/hwi`. Use `hwi-upstream-trezor` for Trezor One and
`hwi-upstream-trezor-t` for Model T.

```sh
timeout 45m nix run .#hwi-upstream-bitbox
timeout 90m nix run .#hwi-upstream-coldcard
timeout 90m nix run .#hwi-upstream-ledger
timeout 120m nix run .#hwi-upstream-jade
timeout 90m nix run .#hwi-upstream-trezor
timeout 90m nix run .#hwi-upstream-trezor-t
timeout 90m nix run .#hwi-upstream-keepkey
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

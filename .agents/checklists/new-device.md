# New Device Checklist

Use this when onboarding a new hardware wallet. Do not claim device support
until core behavior, user surfaces, emulator-backed e2e coverage, and HWI parity
status are all accounted for.

## Research And Scope

- Identify upstream protocol documentation, client libraries, emulator or
  simulator support, and Python HWI support status.
- Pin upstream emulator or firmware inputs when CI or local e2e depends on
  them.
- Record the device transport model: HID, TCP, serial, WebHID, WebSerial, HTTP,
  or device-requested callback service.
- Map authentication, unlock, PIN/passphrase, network selection, and refusal
  semantics before writing code.
- Decide the initial supported BHWI commands and explicitly record unsupported
  commands or intentional parity gaps.
- Identify sensitive fields that must never appear in logs: seeds, private keys,
  xprvs, PINs, passphrases, wallet secrets, real HMACs, and raw real-device
  payloads.

## Core `bhwi`

- Add `bhwi/src/<device>/` with the sans-I/O interpreter and protocol helpers.
- Export the module from `bhwi/src/lib.rs`.
- Preserve the `Interpreter` flow: `start`, repeated `exchange`, then `end`.
- Keep device protocol state machines, request encoding, response parsing, and
  device-requested callbacks in the interpreter.
- Keep HID, TCP, serial, browser, HTTP, and emulator I/O out of core.
- Add device conversion from `common::Command`; reject unsupported command
  shapes and missing `DeviceContext` with clear errors.
- Extend `common::DeviceContext` only for device-specific command data.
- Add protocol/unit tests for request encoding, response parsing, error mapping,
  state-machine transitions, authentication callbacks, and refusal paths.
- Update `common_interpreter_is_satisfied` or equivalent compile-time coverage
  so the new common interpreter participates in the shared surface.

## Async, CLI, And WASM

- Add `bhwi-async/src/<device>.rs` and any required transport/client wiring
  outside the core interpreter.
- Export the async device type from `bhwi-async/src/lib.rs` when it is part of
  the public surface.
- Add `bhwi-cli/src/<device>.rs` with discovery/enumeration and execution
  wiring.
- Add the device to `DeviceType`, `DeviceType::enumerate`, selector matching,
  HWI parsing, and HWI label handling.
- Ensure native `bhwi` CLI output follows quiet success, `--pretty`, and
  `--json` rules.
- Ensure Python-HWI-compatible `hwi` output uses Python HWI command names, JSON
  shapes, and error codes where parity is claimed.
- Add `bhwi-wasm` support only when the existing browser surface should support
  the device; otherwise explain why it is skipped.

## E2E Crates And Emulator Infrastructure

- Add `e2e/<device>/Cargo.toml` and `e2e/<device>/src/lib.rs` for
  emulator-backed device tests.
- Cover discovery, unlock/info, master fingerprint, xpub, address display,
  signing, refusal, and error paths according to the initial support claim.
- Add `e2e/cli/src/<device>.rs` and wire it from `e2e/cli/src/lib.rs` for every
  user-facing emulator-supported CLI command.
- Add Nix inputs for pinned firmware/emulator sources in `flake.nix`.
- Add `nix/scripts/start-<device>.sh` and readiness helpers when needed.
- Add a flake app `nix run .#<device>` and shell
  `nix develop .#<device>` for local e2e.
- Add the new script to `checks.x86_64-linux.emulator-scripts`; remember that
  new scripts must be staged before flake source checks can see them.
- Add a device job to `.github/workflows/emulators.yml` with emulator startup,
  CLI e2e, package e2e, redacted failure logs, and serial test execution.
- Use `-- --test-threads=1` for emulator tests.
- Report emulator startup separately from Rust test execution.

## HWI Parity

- Confirm whether Python HWI supports the device and which command surface is
  expected to match.
- Add the device to the pinned Python-HWI reference restriction in `flake.nix`
  (`commands.all_devs`).
- Add a `hwi-parity-<device>` flake app using `HWI_PARITY_DEVICE_TYPE=<device>`.
- Add the device to `e2e/hwi-parity` normalization and any command fixtures.
- Run parity with only the intended emulator family active; do not run multiple
  emulator families at once.
- Add the device parity app to Emulator CI.
- Update `docs/HWI_PARITY.md` with support status, command matrix, known
  deviations, and validation evidence.
- If a command is intentionally unsupported, parse it and return a
  Python-HWI-shaped unsupported error instead of letting clap reject it.

## Documentation And Handoff

- Update `docs/DEVICE_ONBOARDING.md` with upstream references and local code
  entry points.
- Add or update `docs/<DEVICE>.md` with emulator setup and local e2e commands.
- Update `docs/NIX.md` for new flake apps, shells, readiness checks, and
  emulator details.
- Call out public API, CLI, dependency, security/logging, and HWI parity impact
  in the handoff.
- List every skipped surface with the reason it is not applicable.

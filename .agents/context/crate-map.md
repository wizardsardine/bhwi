# BHWI Crate Map

Use this map to find the right surface before editing.

## Core

- `bhwi`: sans-I/O protocol interpreters, shared common command surface, device
  protocol encoding/parsing, and protocol tests.
- `bhwi/src/common.rs`: common commands, responses, recipients, transmits, and
  device-specific context.
- `bhwi/src/device.rs`: device/client inventory types that do not belong in the
  common interpreter surface.
- `bhwi/src/<device>/`: device protocol modules.

## Runtime And User Surfaces

- `bhwi-async`: async execution, transports, HTTP clients, and the HWI trait/API.
- `bhwi-cli`: native `bhwi` CLI, Python-HWI-compatible `hwi` binary, discovery,
  selectors, output formatting, and device enumeration.
- `bhwi-wasm`: browser-facing transports and device support where the existing
  browser surface requires parity.
- `website`: website and demo build surface.

## E2E And Tooling

- `e2e/<device>`: emulator-backed device package tests.
- `e2e/cli`: emulator-backed user-facing CLI tests.
- `e2e/hwi-parity`: JSON parity harness comparing BHWI `hwi` with pinned
  Python HWI.
- `nix/scripts`: emulator startup, readiness, HWI upstream-suite helpers, and
  CI log helpers.
- `flake.nix`: pinned emulator inputs, flake apps, dev shells, packages, checks,
  and HWI parity runners.
- `.github/workflows/main.yml`: non-emulator Rust CI.
- `.github/workflows/emulators.yml`: emulator, CLI e2e, and HWI parity CI.
- `.github/workflows/website.yml`: website build/deploy.

## Docs

- `README.md` and `docs/VISION.md`: architecture rationale.
- `docs/DEVICE_ONBOARDING.md`: upstream references and device onboarding notes.
- `docs/NIX.md`: emulator and Nix workflow.
- `docs/HWI_PARITY.md`: Python HWI parity status and known deviations.
- `docs/<DEVICE>.md`: per-device emulator/setup notes.

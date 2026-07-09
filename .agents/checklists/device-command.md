# Device Command Checklist

Use this when adding a command to an existing device integration. If a surface
is skipped, the handoff must explain why it is not applicable.

## Design

- Identify the exact device API command and expected request/response shape.
- Decide whether the command is common across devices or device-specific.
- Record required device context explicitly; do not hide it on a device wrapper.
- Check whether Python HWI exposes equivalent behavior and whether parity tests
  should be updated.

## Core Interpreter

- Add or extend `common::Command`, `common::Response`, and
  `common::DeviceContext` only as needed.
- Convert from `common::Command` in the device module and reject missing context
  with a clear error.
- Keep protocol encoding, parsing, callbacks, and state transitions in `bhwi`.
- Keep transport, HTTP, browser, and emulator I/O outside `bhwi`.
- Add protocol/unit tests for encoding, parsing, and state-machine behavior
  before relying on e2e tests.

## Runtime And CLI Surfaces

- Add the `bhwi-async` trait method or implementation wiring when the command is
  part of the async HWI surface.
- Add `bhwi-cli` command support when user-facing.
- Preserve CLI output contracts: quiet success for action-only commands,
  Unix-friendly default output, `--pretty` tables, and `--json` for structured
  output.
- Use existing Bitcoin crate parsing/display helpers before adding encoding or
  formatting dependencies.
- Add `bhwi-wasm` support when the existing browser surface requires parity.

## Tests And Docs

- Add emulator-backed package e2e coverage for every emulator-supported command.
- Add matching `bhwi-e2e-cli` coverage for user-facing emulator-supported CLI
  commands.
- Update HWI parity tests and `docs/HWI_PARITY.md` when the command affects the
  Python-HWI-compatible `hwi` binary.
- Update device docs when setup, support status, upstream references, or user
  behavior changes.
- Run the validation required by `AGENTS.md` for the changed surfaces.

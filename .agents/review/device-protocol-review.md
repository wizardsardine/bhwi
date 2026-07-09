# Device Protocol Review Prompt

Use this prompt when reviewing protocol, interpreter, or device-command changes.

Review the change for protocol correctness, security, interpreter boundaries,
and test coverage. Prioritize findings with file/line references.

Check:

- Core `bhwi` remains sans-I/O; no HID, TCP, serial, browser, HTTP, emulator, or
  runtime code leaks into interpreters.
- The interpreter preserves `start`, repeated `exchange`, then `end`.
- Device command conversion rejects missing context and unsupported command
  shapes with clear errors.
- Protocol encoding, response parsing, callbacks, authentication, and refusal
  paths have focused unit tests.
- E2E tests do not replace protocol/unit tests for new parser, encoder, or
  state-machine behavior.
- Errors include command/context details and distinguish network mismatch,
  missing context, unsupported shape, transport failure, parser/encoding
  failure, protocol refusal, and device busy states.
- Secrets and real device payloads are not logged; logs use structured,
  truncated metadata.
- New dependencies are justified and not replacing reasonable existing crate
  APIs or caller-side handling.
- HWI parity, CLI e2e, docs, and emulator infrastructure are updated when the
  behavior is user-facing or parity-relevant.

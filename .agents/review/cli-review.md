# CLI Review Prompt

Use this prompt when reviewing native `bhwi` or Python-HWI-compatible `hwi`
changes.

Review the CLI change for behavior regressions and contract drift. Prioritize
findings with file/line references.

Check:

- Default output is Unix-friendly: no headers, easy separators, and chainable
  output.
- `--pretty` is used for tables and `--json` is used for structured output.
- Action-only success paths print nothing unless the existing contract says
  otherwise.
- Command names match user expectation: `device`, `descriptor`, and `address`
  remain scoped to their intended domains.
- Existing output shapes are preserved unless the task explicitly changes them.
- Parsing/display uses existing Bitcoin crate APIs where reasonable.
- Python-HWI-compatible `hwi` behavior matches Python HWI command names,
  argument names, JSON fields, error codes, and unsupported-command behavior.
- Device selection by type, path, fingerprint, chain, and emulator flag is
  covered where applicable.
- User-facing emulator-supported behavior has matching `bhwi-e2e-cli` coverage.
- Error messages distinguish bad arguments, no device, transport failure,
  network mismatch, unsupported command shape, protocol refusal, and parser
  failure.

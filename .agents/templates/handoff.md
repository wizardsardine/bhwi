# Handoff Template

Use this shape for final handoffs after code or docs changes.

## Summary

- Changed:
- Public API impact:
- CLI impact:
- Dependency impact:
- Security/logging impact:

## Validation

| Command | Result | Notes |
|---|---|---|
| `cargo fmt --all --check` | passed/failed/skipped | |
| `cargo clippy --all --all-features --all-targets -- -A dead_code -D warnings` | passed/failed/skipped | |
| `cargo test --verbose --no-default-features` | passed/failed/skipped | |
| `cargo test --verbose --color always -- --nocapture` | passed/failed/skipped | |
| `cargo test --all --exclude "bhwi-e2e-*" --verbose --color always -- --nocapture` | passed/failed/skipped | |
| emulator startup | passed/failed/skipped | device and command |
| emulator e2e | passed/failed/skipped | device and command |
| CLI e2e | passed/failed/skipped | device and command |
| HWI parity | passed/failed/skipped | device and command |

For docs-only changes, report:

```text
Skipped code validation because only docs changed.
```

## Notes

- Skipped surfaces and why:
- Pre-existing or environmental failures:
- Unrelated local changes left untouched:

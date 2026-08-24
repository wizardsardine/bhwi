# PR Description Format

Write for a reviewer about to read the diff. Facts only.

## Rules

- No prose narration. No restating the issue, no describing how the work went,
  no listing approaches that were tried and discarded. That belongs in PR
  comments if anywhere.
- Lead with a blocker when one exists: a one-line blockquote naming the blocking
  PR and why it blocks.
- Link the issue with `Closes #<n>` when the PR closes one.
- List changes as bullets: the file or module, then what it now does. Group by
  surface when a PR touches several.
- State behavior changes explicitly and separately: public API, CLI output,
  exit statuses, JSON shapes, dependencies. A reviewer must not have to infer
  them from the diff.
- Use a table when the content is a contract, a support matrix, or a
  before/after measurement. Do not use a table for a list of changes.
- Limit prose to at most one sentence, and only for a root cause that the
  bullets cannot carry.
- End with one line naming the checks that ran and their results, including
  emulator jobs. List what ran, not an unchecked checklist.
- Keep the whole body scannable in one screen where the change allows it.

## Shape

```markdown
> **Blocked on #<n>** — one line on why.        (only when blocked)

Closes #<n>.

<one line naming what the PR does, only if the bullets need framing>

- `path/to/file.rs` — what it now does
- `path/to/other.rs` — what it now does

Behavior changes:

- <public API / CLI / exit status / JSON / dependency change>

Checks: `fmt`, `clippy -D warnings`, <test commands>, emulator: <devices>.
```

## Notes

- Out-of-scope findings belong in follow-up issues, referenced by number.
- Do not add attribution trailers.
- Emulator-backed results are facts a reviewer needs: name the device jobs that
  ran and whether they passed.

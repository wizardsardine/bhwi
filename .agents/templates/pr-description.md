# PR Description Format

Write for a reviewer about to read the diff. Facts only.

## Rules

- No prose narration. No restating the issue, no describing how the work went,
  no listing approaches that were tried and discarded. That belongs in PR
  comments if anywhere.
- Lead with a blocker when one exists: a one-line blockquote naming it and why
  it blocks. Link the blocking PR when applicable.
- Link the issue with `Closes #<n>` when the PR closes one.
- List changes as behavior-first bullets: what now happens, with a file or
  module reference only when useful. Group by surface when a PR touches several.
- Fold actual public API, CLI output, exit status, JSON shape, dependency, and
  compatibility changes into those same bullets. Omit unchanged behavior and
  absent additions.
- Use a table when the content is a contract, a support matrix, or a
  before/after measurement. Do not use a table for a list of changes.
- Limit prose to at most one sentence, and only for a root cause that the
  bullets cannot carry.
- Omit CI mentions, CI links, passing checks, and passing test summaries.
- Mention only material gaps: blockers, unrun required checks, or missing
  requested work. State the concrete impact on review or merge readiness.
- Keep the whole body scannable in one screen where the change allows it.

## Shape

Omit the blocker, issue link, framing line, and material-gaps section when not applicable. Report each blocker once, at the top.

```markdown
> **Blocked:** <blocker and why; link a blocking PR when applicable>

Closes #<n>.

<one line naming what the PR does, only if the bullets need framing>

- <what now happens; file or module reference only when useful>
- <another actual change, including interface or compatibility changes>

Material gaps:

- <unrun required check or missing requested work and its concrete impact>
```

## Notes

- Out-of-scope findings belong in follow-up issues, referenced by number.
- Do not add attribution trailers.

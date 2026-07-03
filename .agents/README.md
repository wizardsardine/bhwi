# BHWI Agent Resources

`AGENTS.md` is the authoritative policy layer for this repository. Use this
directory for task-specific runbooks, checklists, review prompts, and templates
that are too detailed for the top-level rules.

## Start Here

- [`context/crate-map.md`](context/crate-map.md): repo surfaces and common edit
  points.
- [`checklists/device-command.md`](checklists/device-command.md): add or extend
  a command for an existing device.
- [`checklists/new-device.md`](checklists/new-device.md): onboard a new hardware
  wallet end to end.
- [`runbooks/emulator-validation.md`](runbooks/emulator-validation.md): run and
  classify emulator-backed checks.
- [`runbooks/hwi-parity.md`](runbooks/hwi-parity.md): compare the `hwi` binary
  with pinned Python HWI.
- [`review/device-protocol-review.md`](review/device-protocol-review.md):
  protocol/interpreter review prompt.
- [`review/cli-review.md`](review/cli-review.md): CLI behavior review prompt.
- [`templates/handoff.md`](templates/handoff.md): final handoff format.
- [`templates/pr-description.md`](templates/pr-description.md): PR body format.

## Use Pattern

- Pull in only the resource that matches the task.
- Keep workflow detail here instead of duplicating it in `AGENTS.md`.
- Update these files when commands, crate ownership, emulator commands, or HWI
  parity requirements change.

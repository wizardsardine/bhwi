# BHWI Agent Rules

## Purpose And Precedence

- Use this file as the working agreement for agents and developers contributing to BHWI.
- Direct user instructions override this file.
- For technical facts, prefer current code and repository docs. For workflow rules and architecture boundaries, follow this file unless a more specific tracked project doc says otherwise.
- If instructions conflict in a way that materially affects public APIs, CLI output shape, validation scope, branch history, or security-sensitive behavior, pause and ask before changing those areas.
- Preserve unrelated local changes. Do not revert, format, stage, or commit files outside the requested scope unless explicitly asked.
- Prefer root-cause fixes over cosmetic workarounds, and keep changes as small as the task allows.

## Team Workflow

- Start by checking the current branch and worktree status.
- For non-trivial or review-bound work, create or switch to a feature branch named `github_user/short_topic_name` before edits. If already on a suitable feature branch, stay there.
- Read-only investigation does not require a new branch.
- Do not commit unless asked. When asked to commit, use signed commits and keep them atomic by crate or concern.
- For broad or ambiguous work, clarify the intended behavior before implementation. For narrow bugs, inspect first and implement the smallest defensible fix.
- Handoffs must state what changed, whether public APIs or CLI behavior changed, and which validation commands passed, failed, or were skipped.

## Task Workflow Matrix

- Docs-only: update docs or instructions only; no Rust validation required.
- Core Rust/API/common interpreter: preserve sans-I/O boundaries and run all non-emulator CI checks.
- CLI behavior or output: preserve Unix-friendly output and run non-emulator CI plus focused CLI or CLI e2e tests when supported.
- Device protocol command: add protocol/unit tests, then run the matching device emulator e2e package.
- User-facing emulator-supported command: run the matching device e2e package and the matching `bhwi-e2e-cli` device test.
- WASM or website: run the existing build or test command for the touched surface when one exists.
- Nix, CI, or emulator infrastructure: pin upstream inputs when local or CI flows depend on them, and update docs when setup or references change.

## Non-Negotiable Architecture Invariants

- BHWI is a sans-I/O Bitcoin hardware wallet interface.
- Keep device protocol state machines in `bhwi`.
- Keep async runtimes, HID/TCP/Web transport, HTTP clients, browser APIs, and emulator I/O outside the core interpreters.
- Preserve the `Interpreter` model: `start`, repeated `exchange`, then `end`.
- Treat `common` as the common interpreter surface: shared commands, responses, recipients, transmits, and device-specific context.
- Keep device discovery and concrete device inventory types out of `bhwi/src/common.rs`; use device/client modules such as `device.rs` or CLI/async layers.
- Keep library APIs flexible for sync, async, FFI, WASM, and custom execution models.

## Device Commands

- For every new device command, wire the full path where relevant:
  - common command, response, and context in `bhwi`
  - device interpreter conversion and protocol encoding/parsing
  - protocol unit tests for encoding, parsing, and state-machine behavior
  - `bhwi-async` HWI trait/API
  - `bhwi-cli` command when user-facing
  - WASM support when the existing surface requires parity
  - emulator-backed e2e coverage when the command is emulator-supported
  - docs update when setup, support status, or user-visible behavior changes
- If a surface in the command path is skipped, explain in the handoff why it is not applicable.
- Do not rely only on e2e tests when protocol encoding, parsing, or state-machine behavior changed.
- If a command needs device-specific data, pass it through `Option<common::DeviceContext>` rather than storing hidden state on the device wrapper.
- Keep `DeviceContext` fields organized by device. Let `TryFrom<common::Command>` for each device reject missing required fields with a clear error.
- Do not require Ledger wallet policy data for devices that do not need it. For Ledger, keep policy name, policy, and HMAC optional at the common layer, and validate at Ledger conversion time.
- Use precise names for context fields. Prefer `policy_name` over vague `name` in transaction signing contexts.
- Device-specific commands and responses should mirror the device API as closely as possible. Let the common layer map names and shapes into a unified interface.

## Error Handling

- Unexpected device responses must include command/context details; avoid bare `unexpected result: []` errors.
- When adding an error path, include enough context to distinguish network mismatch, missing context, unsupported command shape, transport failure, protocol refusal, and parser/encoding failure.
- Do not panic in recoverable or user-facing paths for absent emulators, missing sockets, disconnected devices, empty discovery results, malformed user input, or unsupported device actions.
- Prefer typed errors that preserve useful context over string-only errors, within existing public API compatibility constraints.

## CLI UX

- CLI commands should be scoped by user expectation:
  - `device` is for listing devices, firmware/app info, and device management.
  - `descriptor` is for descriptor-related operations.
  - `address` is for address display/check/get flows.
- Prefer command names that describe actual behavior. Do not reserve broad names like `descriptor list` for narrower "common pubkey descriptor" behavior; use names like `descriptor pubkeys` when appropriate.
- Default CLI output should be Unix-friendly: no headers, easy separators, and chainable output.
- Use `--pretty` for table output.
- Use `--json` for structured output suitable for `jq`.
- Commands that only perform an action successfully should usually print nothing.
- Preserve existing output contracts unless the task explicitly changes them.
- Use existing Bitcoin crate parsing/display APIs before adding encoding dependencies. Examples: `Psbt::from_str`, `Psbt` display, and `MessageSignature` base64 helpers.
- Build `target/debug/bhwi` before running CLI e2e tests that set `BHWI_BIN="$PWD/target/debug/bhwi"`.

## Security And Logging

- Treat hardware-wallet protocol data as sensitive by default.
- Never log seeds, private keys, xprvs, PINs, passphrases, wallet secrets, or real HMACs.
- Prefer structured, truncated protocol metadata over raw APDU dumps or full PSBTs.
- Use synthetic or regtest fixtures for tests. Require explicit user approval before exposing real device payloads in logs, handoffs, CI output, or issue comments.
- Redact emulator and device logs in handoffs, CI summaries, and issue comments.
- Keep client-provided Ledger data authenticated by the device protocol.
- Avoid adding dependencies for parsing, formatting, transport, logging, or encoding unless existing crate APIs or caller-side handling are insufficient.

## Architecture Preferences From Review

- Keep trait bounds as loose as the implementation allows. Do not add `StdError + Send + Sync + Debug + 'static` unless the code truly needs them.
- Avoid new dependencies when the consumer can reasonably do the work or an existing dependency already provides the needed parsing/formatting.
- Pin emulator/upstream inputs when CI or local emulator flows depend on upstream behavior. Do not leave emulator builds exposed to unreviewed upstream breakage.
- Update docs under `docs/` when emulator setup, upstream references, support status, or device onboarding steps change.

## Device Notes

- Ledger uses APDUs, wallet policies, Merkle proofs, and device-requested client callbacks. Keep client-provided data authenticated by the device protocol.
- Ledger PSBT signing may need wallet policy context for non-standard policies; standard policies may not.
- Jade uses CBOR-RPC and may require PIN server routing via `Recipient::PinServer`.
- Coldcard commands are encrypted after the initial public-key exchange.
- Keep transport-specific code in `bhwi-async`, `bhwi-wasm`, `bhwi-cli`, or `e2e`, not in the core interpreter.

## Review Preflight

- Review changed code for public API compatibility, trait-surface impact, and downstream callers before validation.
- Check interpreter boundaries: keep transport, runtime, HTTP, browser, and emulator I/O code outside `bhwi`.
- Check error paths include enough context to distinguish missing context, unsupported command shape, network mismatch, protocol refusal, parser/encoding failure, and transport failure.
- Check CLI output shape, quiet success behavior, `--pretty`, and `--json` behavior match existing UX rules.
- Check test coverage matches the changed behavior. Do not rely on e2e tests alone when protocol encoding, parsing, or state-machine behavior changed.
- Justify every new dependency. Prefer existing crate APIs and caller-side parsing/formatting when reasonable.
- Confirm documentation is updated when behavior, setup, support status, or upstream references change.

## Verification

- Docs-only changes do not require code validation. Report: `Skipped code validation because only docs changed.`
- Code changes must pass the local non-emulator CI checks before handoff:
  - `cargo fmt --all --check`
  - `cargo clippy --all --all-features --all-targets -- -A dead_code -D warnings`
  - `cargo test --verbose --no-default-features`
  - `cargo test --verbose --color always -- --nocapture`
  - `cargo test --all --exclude "bhwi-e2e-*" --verbose --color always -- --nocapture`
- For device protocol or user-facing CLI behavior changes, run the matching emulator-backed tests:
  - Coldcard: `nix run .#coldcard`, then `nix develop .#coldcard -c cargo test -p bhwi-e2e-coldcard -- --test-threads=1`
  - Ledger: `nix run .#ledger`, then `nix develop .#ledger -c cargo test -p bhwi-e2e-ledger -- --test-threads=1`
  - Jade: `nix run .#jade-pinserver`, `nix run .#jade`, `nix run .#jade-init`, then `nix develop .#jade -c cargo test -p bhwi-e2e-jade -- --test-threads=1`
- For user-facing emulator-supported CLI commands, build the CLI binary and run the matching CLI e2e test with `BHWI_BIN` set:
  - Build: `cargo build -p bhwi-cli`
  - Coldcard: `BHWI_BIN="$PWD/target/debug/bhwi" nix develop .#coldcard -c cargo test -p bhwi-e2e-cli coldcard -- --test-threads=1`
  - Ledger: `BHWI_BIN="$PWD/target/debug/bhwi" nix develop .#ledger -c cargo test -p bhwi-e2e-cli ledger -- --test-threads=1`
  - Jade: `BHWI_BIN="$PWD/target/debug/bhwi" nix develop .#jade -c cargo test -p bhwi-e2e-cli jade -- --test-threads=1`
- Report emulator startup separately from Rust test execution when emulator-backed validation is required.
- If a broad validation command fails, inspect whether the failure was caused by the current change. Fix current-change regressions before handoff; report pre-existing or environmental failures with evidence and the exact rerun command.
- If a required check cannot run because of the local environment or emulator availability, report the exact command, the concrete blocker, and the command the user should run.
- Every code-change handoff must include a validation summary listing each required command as passed, failed, or skipped with reason.

## Commit Style

- When committing, use signed commits only.
- Use Conventional Commit style where it fits the repo history:
  - `feat(bhwi): add ...`
  - `feat(bhwi-async): add ...`
  - `feat(bhwi-cli): add ...`
  - `feat(e2e/ledger): add ...`
  - `test(e2e): add ...`
  - `fix(nix): ...`
  - `docs: ...`
  - `style: format ...`
- Keep commits atomic by crate or concern.
- Split cross-cutting command work into reviewable commits, commonly:
  - core/common interpreter support
  - one device implementation
  - async API surface
  - CLI support
  - e2e tests and automations
  - docs or Nix/CI updates
- Do not mix formatting-only churn into feature commits. Use a separate `style:` commit if needed.
- Keep commit messages brief and direct. Avoid ticket references unless asked.

## Definition Of Done

- The requested behavior or documentation change is complete and scoped to the task.
- Public API, CLI, dependency, and security-sensitive impacts are explicitly called out.
- Required tests or checks are run for the change type, or skipped with a concrete reason.
- Emulator-backed checks include whether emulator startup succeeded.
- The final handoff names unrelated local changes that were intentionally left untouched.

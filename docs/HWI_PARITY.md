# HWI Parity

BHWI ships a Python-HWI-compatible `hwi` binary. The parity suite
(`e2e/hwi-parity`) checks that its output matches Bitcoin Core HWI for the
commands and devices where parity is claimed.

## How parity is checked

- A pinned reference HWI is exposed as the `hwi-reference-bhwi` flake package,
  built with `nix build .#hwi-reference-bhwi`. Its binary imports upstream
  `hwilib` and restricts the recognized device list via `commands.all_devs`
  (see [`flake.nix`](../flake.nix)).
- Per-device flake apps run the harness with `HWI_PARITY_DEVICE_TYPE` set:
  `nix run .#hwi-parity-<device>`. Each builds `bhwi-cli --bins`, then runs
  `bhwi-e2e-hwi-parity`, comparing `REFERENCE_HWI_BIN` against the candidate
  `hwi` for the emulated device.
- The suite asserts parity for the implemented HWI command set with the
  intended emulator family active.
- `signmessage` payloads are verified cryptographically on both sides: the
  BIP-137 signature must recover the public key the reference device reports at
  the requested derivation path over `signed_msg_hash(message)`.
- `signtx` results are verified against the recomputed sighash (BIP143 for
  segwit v0, legacy otherwise) for the expected device key, and the reference
  and candidate PSBTs are then compared field for field with only the signature
  values excluded. Per-input signature key sets must still match exactly.
- Emulator CI (`.github/workflows/emulators.yml`) runs differential parity and
  a matching unmodified upstream gate for all six supported families:
  BitBox02, Coldcard, Ledger, Jade, KeepKey, and Trezor. The Trezor matrix has
  one leg per model, selecting `hwi-upstream-trezor` for Trezor One and
  `hwi-upstream-trezor-t` for Model T.

## Exit status contract

The `hwi` binary matches pinned Python HWI 3.2.0 process status
(`hwilib/_cli.py`, `HWIArgumentParser.error` and `main`).

|Status|Cases                                                                      |
|------|---------------------------------------------------------------------------|
|`0`   |Success, `--help` (which prints `{"error": "Help text requested", "code": -17}` on stdout and the help text on stderr), `--version`, every runtime `{"error", "code"}` JSON response (`-1`, `-3`, `-4`, `-5`, `-7`, `-9`, `-13`, `-14`, `-16`, `-17`, `-18`), and per-device `enumerate` failures.|
|`2`   |Usage errors: no arguments, unknown subcommand, missing required argument, invalid flag choice, or malformed numeric value. These print `{"error": "...", "code": -2}` on stdout and usage text on stderr.|
|`1`   |Internal crashes that produce no JSON on stdout. A panic hook in the `hwi` binary chains the default panic output to stderr and forces status 1 from any thread, matching upstream's exit-1-with-traceback behavior.|

Runtime errors exiting `0` is deliberate: upstream prints the error JSON and
returns normally, so a nonzero status would break callers that treat a failed
device operation as a well-formed HWI response.

The parity harness asserts process status on both sides, not just JSON. Exact
usage-error message and usage text is not compared, because the reference
reports the nix store script as its program name and lists argparse-specific
choice sets. Only status, JSON shape, code `-2`, and non-empty stderr are
compared for usage errors.

User refusals on the device stop flattening to `-3` and mirror the pinned
reference exactly: `-14` where upstream raises `ActionCanceledError` (Coldcard
signmessage/displayaddress, BitBox, Jade, and KeepKey), `-13` for Ledger
(upstream's `ledger_bitcoin` `DenyError` bypasses the `ledger_exception` cancel
mapping), and, for a refused Coldcard signtx, either `-14` (the refusal frame
answers an in-flight poll) or `-7` `Coldcard Error: No active request` (the
cleared request errors on the next poll); both occur upstream depending on poll
timing. Emulator-backed cancel parity cases cover Ledger (Speculos reject
automation, both binaries) and Coldcard (simulator refuse keypress,
candidate-only: the pinned reference presses `y` on the simulator by itself
via `sim_keypress`, so its refusal path cannot be exercised there and its codes
are pinned from upstream source). KeepKey refusal recovery is also
candidate-only because Python HWI's debug client auto-approves; the candidate
must return `-14` and the next session must succeed. Jade and BitBox refusals
are covered by protocol unit tests only.

Argument validation follows upstream's ordering: device lookup runs first, so
an invalid derivation path, PSBT, or unknown `-t` value reports `-3` when no
device matches. With a device attached an invalid path is `-7` (except BitBox
`getxpub`, whose upstream handler reports `-13`) and an invalid PSBT is `-5`;
an unknown `-t` with `-d` (and no fingerprint) is `-4` from the `get_client`
path. `enumerate` ignores an unrecognized `-t`, like upstream.

## Final acceptance gate

Parity is accepted only when the unmodified Bitcoin Core HWI 3.2.0 device
suite passes against BHWI's CLI adapter. The flake exposes a tailored app for
each supported emulator:

```sh
nix run .#hwi-upstream-bitbox
nix run .#hwi-upstream-coldcard
nix run .#hwi-upstream-ledger
nix run .#hwi-upstream-jade
nix run .#hwi-upstream-keepkey
nix run .#hwi-upstream-trezor
nix run .#hwi-upstream-trezor-t
```

Each app builds `target/debug/hwi`, prepares the pinned simulator in the layout
expected by upstream HWI, and runs `test/run_tests.py --device-only
--interface=cli`. The upstream source and tests are copied only to a temporary
writable directory; BHWI does not patch test cases or add project-owned skips.
Only skips already authored by upstream HWI are accepted. Coldcard's final
gate does apply HWI's own `test/data/coldcard-multisig.patch` to a separate
simulator build; that compatibility patch changes the emulator firmware, not
the upstream test suite.

An upstream gate proves only the methods that the unmodified upstream suite
actually invokes. It does not prove methods that upstream omits or marks
unsupported. Project-owned differential tests and the explicitly named
candidate-only fresh-image tests below provide that evidence without modifying
the pinned suite.

The generic dispatcher remains available as
`nix run .#hwi-upstream-suite -- <device>`. CI caps the upstream command at
45 minutes for BitBox02; 90 minutes for Coldcard, Ledger, KeepKey, Trezor One,
and Model T; and 120 minutes for Jade. The enclosing GitHub job timeout is the
outer bound for the whole job:
60 minutes for BitBox02, Coldcard, and Ledger; 90 minutes for Jade; and 150
minutes for each Trezor matrix leg and KeepKey. Earlier phases can therefore
leave a final gate less time than its command cap.

### Why the reference side works for the supported emulators

Both binaries run the same command — `hwi --emulators --device-type <type>
enumerate`. The load-bearing requirement is that the **reference** Python HWI's
`--emulators` enumerate finds the simulator by itself. That works only because
upstream HWI ships emulator support in each of these backends, and the flake
starts the emulator on the exact transport that backend already probes:

| Device   | Transport upstream HWI enumerates on `--emulators` | Started by |
|----------|----------------------------------------------------|------------|
| Coldcard | Unix socket `/tmp/ckcc-simulator.sock`             | `nix run .#coldcard` |
| Ledger   | Speculos APDU server over TCP `localhost:9999`     | `nix run .#ledger` |
| Jade     | QEMU serial over TCP `localhost:30121`             | `nix run .#jade` + `jade-init` |
| BitBox02 | Firmware simulator TCP `localhost:15423`           | `nix run .#bitbox` |
| Trezor   | Emulator UDP `127.0.0.1:21324`                     | `nix run .#trezor-one` or `.#trezor-t`, + `trezor-init` |
| KeepKey  | Emulator UDP `127.0.0.1:11044` (debug `11045`) | `nix run .#keepkey`, + `keepkey-init` |

The flake env blocks only supply build/runtime libraries; they do not tell HWI
where the emulator is — each upstream backend already knows its transport. The
candidate `target/debug/hwi` is a separate compatibility binary from the
native `bhwi` CLI. Its `--emulators` enumerate mirrors each upstream transport.

## Support matrix

| Device    | Differential parity | Upstream final gate |
|-----------|---------------------|---------------------|
| Ledger    | `hwi-parity-ledger` | `hwi-upstream-ledger` |
| Coldcard  | `hwi-parity-coldcard`, including file-producing `backup` | `hwi-upstream-coldcard` |
| Jade      | `hwi-parity-jade` | `hwi-upstream-jade` |
| BitBox02  | `hwi-parity-bitbox` | `hwi-upstream-bitbox` |
| Trezor    | `hwi-parity-trezor` | `hwi-upstream-trezor`, `hwi-upstream-trezor-t` |
| KeepKey   | `hwi-parity-keepkey` | `hwi-upstream-keepkey` |

Coldcard multisig display cases reset simulator state and register the same
deterministic wallet through the native `bhwi` binary before each reference
and candidate run. The harness also repeats each descriptor without
registration to preserve error-response parity. Set `BHWI_BIN` when the native
binary is not next to the candidate `HWI_BIN`.

## Ledger signing and display policy scope

Ledger `signtx` parity covers the wallet policies that Python HWI can derive
unambiguously from PSBT metadata:

- default single-key wallets using exact BIP44 `pkh`, BIP49 `sh(wpkh)`, BIP84
  `wpkh`, or BIP86 key-path `tr` derivations;
- registered `sh(sortedmulti)`, `sh(wsh(sortedmulti))`, and
  `wsh(sortedmulti)` policies with complete account-level global xpubs; and
- PSBTs containing inputs from more than one supported policy.

The adapter validates derivation paths and script commitments before asking the
device to sign. It rejects ambiguous or unsupported owned inputs, including
unsorted multisig, arbitrary witness miniscript, and taproot script paths, with
an input-indexed error directing callers to explicit descriptor and HMAC
signing.

Ledger does not persist a wallet registry. Registration authenticates a policy
and returns an HMAC, so an "already registered" wallet means the caller retained
the policy name, descriptor, and HMAC and supplies them again for later signing.
The native `register-wallet` and `sign-psbt` commands expose that reusable flow;
HWI `signtx` registers inferred non-default policies for the current invocation.

For classic multisig `displayaddress`, the candidate `hwi` accepts both
`sortedmulti` and order-preserving `multi` policies in legacy `sh(...)`,
wrapped SegWit `sh(wsh(...))`, and native SegWit `wsh(...)` descriptors. Each
invocation registers the inferred policy, uses the returned HMAC, and displays
the address immediately; it does not rely on a persistent registry.

The project-owned `tests::candidate_displayaddress_matches_reference`
differential test covers sorted 2-of-2 policies for all three wrappers and a
reverse-ordered native SegWit `multi` policy. Pinned HWI's Ledger tests mark
multisig display unsupported and skip it, so `hwi-upstream-ledger` is not
evidence for this behavior.

## BitBox02 parity notes

BitBox02 parity is wired against Python HWI's built-in simulator transport. The
pinned reference backend probes `127.0.0.1:15423`, so the BitBox emulator must be
running and initialized before `hwi-parity-bitbox` starts.

The differential harness covers the same read, sign, and display command set
as the other devices, plus BitBox02 mnemonic-export `backup`.
`tests::candidate_bitbox_management_matches_reference` runs against the shared
initialized simulator: it compares setup and restore error responses, then
toggles the passphrase setting once through each binary so the original state
is restored.

Successful candidate-`hwi` management uses two candidate-only filters on
separate fresh, uninitialized simulators.
`tests::candidate_bitbox_setup_management_lifecycle` checks the uninitialized
enumeration, setup, two passphrase toggles, and wipe;
`tests::candidate_bitbox_restore_management_lifecycle` restores another fresh
simulator and checks its initialized fingerprint. These filters exercise the
separate candidate `hwi`, not the native `bhwi` CLI, and do not invoke the
Python reference, whose BitBox02 CLI backend has no management methods.

Known divergence: BitBox02 produces nondeterministic signatures, so the
`signmessage` suite skips byte-exact JSON equality for `bitbox02` only. Both
sides must still recover the same public key from their own signature, so the
weaker comparison is limited to the signature encoding itself.

The simulator deliberately stops replying after a successful factory reset.
CI therefore treats only a read-side disconnect after the reset request as
success, stops that simulator process, waits for its fixed TCP port to become
reusable, and starts a fresh process for the restore lifecycle.

## Trezor parity notes

Trezor parity runs against the emulator's UDP transport on `127.0.0.1:21324`.
Start `trezor-one` (or `trezor-t`) and `trezor-init` before `hwi-parity-trezor`.

The differential suite covers the read, sign, and display command set.
`tests::candidate_signtx_matches_reference` covers classic multisig signing for
legacy P2SH, wrapped P2WSH-P2SH, and native P2WSH.
`tests::candidate_displayaddress_matches_reference` covers all three wrappers,
both `sortedmulti` and deliberately reverse-ordered `multi`, and both fully
derived public keys and account xpubs with concrete child suffixes. Commands
needing on-device confirmation are driven by a debuglink button presser.

Ordinary management methods are outside the differential suite. The upstream
Trezor One gate runs `TestTrezorManCommands`; upstream does not run that class
on Model T, which takes its PIN and passphrase on-device. Emulator CI runs both
unmodified model gates, `hwi-upstream-trezor` and
`hwi-upstream-trezor-t`, in separate matrix legs.

Upstream HWI 3.2.0 has no Trezor restore test. CI therefore checks restore on
three isolated, fresh Model T profiles: direct device behavior with
`tests::can_restore_from_a_recovery_phrase`, the native `bhwi` CLI with
`trezor::trezor_restore_management_lifecycle`, and the separate candidate
`hwi` with the candidate-only
`tests::candidate_trezor_restore_management_lifecycle`. The Trezor One
requires host word entry and remains unsupported.

## KeepKey parity notes

KeepKey parity runs against emulator UDP `127.0.0.1:11044`; confirmation and
state automation uses the debug link on `127.0.0.1:11045`. Start `keepkey` and
`keepkey-init` before `hwi-parity-keepkey`.

The differential suite covers enumerate, global arguments, xpubs, six
non-Taproot descriptor/keypool forms, legacy and SegWit transaction signing,
including fully derived sorted 2-of-2 KeepKey multisig across legacy P2SH,
wrapped P2WSH-P2SH, and native P2WSH, message signing, supported single- and
multisig display, validation errors, and initialized-device management
behavior. `tests::candidate_keepkey_management_matches_reference` compares
management errors, passphrase toggling, and passphrase-dependent enumeration
without leaving the shared simulator changed. Candidate refusal tests require
code `-14` and a usable following session; Python HWI's debug client
auto-approves and cannot provide the same refusal observation.

CI exercises fresh-image management independently at all three BHWI surfaces:
direct device behavior with `tests::keepkey_management_lifecycle`, the native
`bhwi` CLI with `keepkey::keepkey_management_lifecycle`, and the separate
candidate `hwi` with the candidate-only
`tests::candidate_keepkey_management_lifecycle`. Each gets its own emulator
profile. The candidate-`hwi` lifecycle covers setup, wipe, firmware
character-cipher restore, PIN handling, and passphrase behavior without
claiming a Python-reference comparison.

`hwi-upstream-keepkey` is the final gate over the 29 methods in HWI 3.2.0's
unmodified KeepKey suite. Upstream starts and initializes a new image per test,
so the shared emulator is stopped before the gate.

Restore remains partial parity (`[~]`). HWI 3.2.0 has no KeepKey restore test,
and its inherited word-request implementation does not correctly drive the
firmware's `CharacterRequest`/`CharacterAck` flow. BHWI's direct-device,
native-CLI, and candidate-`hwi` fresh-image tests cover that real flow, but
there is no working reference result to compare.

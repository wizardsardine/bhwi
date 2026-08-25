# HWI Parity

BHWI ships a Python-HWI-compatible `hwi` binary. The parity suite
(`e2e/hwi-parity`) checks that its output matches Bitcoin Core HWI for the
commands and devices where parity is claimed.

## How parity is checked

- A pinned reference HWI is exposed as the `hwi-reference-bhwi` flake app. It
  imports upstream `hwilib` and restricts the recognized device list via
  `commands.all_devs` (see [`flake.nix`](../flake.nix)).
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
- Emulator CI (`.github/workflows/emulators.yml`) runs the matching
  `hwi-parity-<device>` app inside each device job, then stops the shared
  emulator and runs the pinned upstream HWI suite as that job's final test
  gate.

## Exit status contract

The `hwi` binary matches pinned Python HWI 3.2.0 process status
(`hwilib/_cli.py`, `HWIArgumentParser.error` and `main`).

|Status|Cases                                                                      |
|------|---------------------------------------------------------------------------|
|`0`   |Success, `--help` (which prints `{"error": "Help text requested", "code": -17}` on stdout and the help text on stderr), `--version`, every runtime `{"error", "code"}` JSON response (`-1`, `-3`, `-4`, `-5`, `-7`, `-9`, `-13`, `-14`, `-16`, `-17`, `-18`), and per-device `enumerate` failures.|
|`2`   |Usage errors: no arguments, unknown subcommand, missing required argument, invalid flag choice. These print `{"error": "...", "code": -2}` on stdout and usage text on stderr.|
|`1`   |Internal crashes that produce no JSON on stdout. A panic hook in the `hwi` binary chains the default panic output to stderr and forces status 1 from any thread, matching upstream's exit-1-with-traceback behavior.|

Runtime errors exiting `0` is deliberate: upstream prints the error JSON and
returns normally, so a nonzero status would break callers that treat a failed
device operation as a well-formed HWI response.

The parity harness asserts process status on both sides, not just JSON. Exact
usage-error message and usage text is not compared, because the reference
reports the nix store script as its program name and lists argparse-specific
choice sets. Only status, JSON shape, code `-2`, and non-empty stderr are
compared for usage errors.

Known divergence: values rejected by a type or value parser rather than by
argument structure, such as `getkeypool notanum 5` or an invalid derivation
path, stay on the runtime path and exit `0` with code `-7` where upstream exits
`2` with code `-2`. That ordering difference is tracked separately.

## Final acceptance gate

Parity is accepted only when the unmodified Bitcoin Core HWI 3.2.0 device
suite passes against BHWI's CLI adapter. The flake exposes a tailored app for
each supported emulator:

```sh
nix run .#hwi-upstream-bitbox
nix run .#hwi-upstream-coldcard
nix run .#hwi-upstream-ledger
nix run .#hwi-upstream-jade
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

The generic dispatcher remains available as `nix run .#hwi-upstream-suite --
<device>`. CI gives the final gates bounded runtimes of 45 minutes for
BitBox02, 90 minutes for Coldcard and Ledger, and 120 minutes for Jade.

### Why the reference side works for the wired devices

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

The flake env blocks only supply build/runtime libraries; they do not tell HWI
where the emulator is — the backend already knows. Our candidate `bhwi hwi`
mirrors each with its own `--emulators` enumerate.

## Support matrix

| Device    | Differential parity | Upstream final gate |
|-----------|---------------------|---------------------|
| Ledger    | `hwi-parity-ledger` | `hwi-upstream-ledger` |
| Coldcard  | `hwi-parity-coldcard`, including file-producing `backup` | `hwi-upstream-coldcard` |
| Jade      | `hwi-parity-jade` | `hwi-upstream-jade` |
| BitBox02  | `hwi-parity-bitbox` | `hwi-upstream-bitbox` |
| Trezor    | `hwi-parity-trezor` | `hwi-upstream-trezor`, `hwi-upstream-trezor-t` |

Coldcard multisig display cases reset simulator state and register the same
deterministic wallet through the native `bhwi` binary before each reference
and candidate run. The harness also repeats each descriptor without
registration to preserve error-response parity. Set `BHWI_BIN` when the native
binary is not next to the candidate `HWI_BIN`.

## Ledger signing policy scope

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

## BitBox02 parity notes

BitBox02 parity is wired against Python HWI's built-in simulator transport. The
pinned reference backend probes `127.0.0.1:15423`, so the BitBox emulator must be
running and initialized before `hwi-parity-bitbox` starts.

The suite covers the same implemented read/sign/display command set as the
other wired devices, plus BitBox02 mnemonic-export `backup` and the stateful
device-management commands `setup`, `wipe`, `restore`, and
`togglepassphrase`. Differential tests cover management errors and toggle the
passphrase setting through both implementations, returning it to its original
state. Dedicated CLI lifecycle tests start fresh uninitialized simulators to
exercise successful setup, wipe, and restore flows.

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

The differential suite covers the read, sign, and display command set, including
multisig `signtx` and multisig `displayaddress`. Commands needing an on-device
confirmation are driven by a debuglink button presser.

The management commands are covered by the upstream gate rather than the
differential suite, and upstream runs `TestTrezorManCommands` on the Trezor One
only, because the Model T takes its PIN and passphrase on its own screen.

`restore` is the exception: upstream has no Trezor restore test, so it is
covered by `bhwi-e2e-trezor` and `bhwi-e2e-cli` instead. It is supported on the
Model T, which takes the recovery phrase on its own screen; the Trezor One
requires host word entry and is unsupported.

`togglepassphrase` runs but is not at parity. Python HWI's enumerate emits a
`warnings` field for a Trezor One with passphrase protection enabled and no
passphrase supplied; BHWI emits no `warnings` key for any device.

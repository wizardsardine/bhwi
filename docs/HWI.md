# HWI Compatibility

BHWI includes an `hwi` compatibility binary for users and tooling that expect
Python HWI's command-line interface. This page tracks feature parity by command
and device family.

The device-applicability entries follow Python HWI's
[support matrix](https://hwi.readthedocs.io/en/latest/devices/index.html#support-matrix):
features marked unsupported by the device firmware are shown as `n/a` here.

The end-of-life BitBox01 family is intentionally excluded from this matrix, as
recorded in [closed issue #74](https://github.com/wizardsardine/bhwi/issues/74).

## Status Key

|Status|Meaning                                   |
|------|------------------------------------------|
|`[x]` |Compatibility behavior covered for this device and command|
|`[~]` |Partial parity or a known caveat remains  |
|`[ ]` |Missing or not implemented                |
|`n/a` |Not supported by the device firmware or not a device command|

For device-management commands that are not applicable to Ledger, Jade, and
Coldcard, BHWI still tests Python HWI-compatible unsupported-action errors.

The `hwi` binary also follows Python HWI's exit-status contract: runtime JSON
errors exit `0`, and argparse-style usage errors exit `2` with
`{"error": "...", "code": -2}` on stdout and usage text on stderr. See
[HWI_PARITY.md](HWI_PARITY.md#exit-status-contract).

## Feature Parity

|Command           |Ledger|Jade |Coldcard|Trezor|KeepKey|BitBox02|Notes                                                                 |
|------------------|------|-----|--------|------|-------|--------|----------------------------------------------------------------------|
|`enumerate`       |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[x]`   |Covered for expected Python HWI fields and global selection arguments.|
|`getmasterxpub`   |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[x]`   |Covered for supported address types.                                  |
|`getxpub`         |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[x]`   |Covered for normal and expert output shape.                           |
|`getdescriptors`  |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[x]`   |Covered for account descriptors.                                      |
|`getkeypool`      |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[x]`   |Covered for receive/change ranges and address types.                  |
|`signtx`          |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[x]`   |Ledger covers default BIP44/49/84/86 wallets and classic registered sorted multisig. Trezor covers single-sig, Taproot, OP_RETURN, and all three classic multisig wrappers. KeepKey covers fully derived sorted 2-of-2 signing across all three classic wrappers.|
|`signmessage`     |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[x]`   |Covered for emulator-supported paths.                                 |
|`displayaddress`  |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[x]`   |Ledger covers inline registration and display of sorted and unsorted classic multisig. Coldcard covers registered multisig for all classic wrappers. Trezor covers sorted and unsorted multisig from derived keys and account xpubs. KeepKey covers sorted, fully derived multisig.|
|`setup`           |`n/a` |`n/a`|`n/a`   |`[x]` |`[x]`  |`[x]`   |Successful and error behavior is covered by the surface-specific management evidence below.|
|`wipe`            |`n/a` |`n/a`|`n/a`   |`[x]` |`[x]`  |`[x]`   |Successful and error behavior is covered by the surface-specific management evidence below.|
|`restore`         |`n/a` |`n/a`|`n/a`   |`[~]` |`[~]`  |`[x]`   |BitBox02 has native CLI and candidate `hwi` fresh-image coverage. Model T is covered on three surfaces; Model One host word entry is unsupported. KeepKey's character-cipher flow has no working pinned-HWI reference.|
|`backup`          |`n/a` |`n/a`|`[x]`   |`n/a` |`n/a`  |`[x]`   |Coldcard file backup and BitBox02 mnemonic-export backup are covered. |
|`promptpin`       |`n/a` |`n/a`|`n/a`   |`[x]` |`[x]`  |`n/a`   |Trezor-class host PIN behavior is covered by upstream and KeepKey lifecycle evidence.|
|`sendpin`         |`n/a` |`n/a`|`n/a`   |`[x]` |`[x]`  |`n/a`   |Trezor-class host PIN behavior is covered by upstream and KeepKey lifecycle evidence.|
|`togglepassphrase`|`n/a` |`n/a`|`n/a`   |`[x]` |`[x]`  |`[x]`   |Differential, lifecycle, and upstream evidence is detailed below.     |
|`installudevrules`|`n/a` |`n/a`|`n/a`   |`n/a` |`n/a`  |`n/a`   |Host-side Python HWI command covered by the shared udev installer. Registered on Linux only.|

The matrix summarizes compatibility behavior across several kinds of evidence;
`[x]` does not mean that every behavior is exercised by every kind:

- **Differential** tests run the same command through pinned Python HWI and the
  candidate `hwi` binary against one initialized emulator.
- **Candidate lifecycle** tests exercise the candidate `hwi` binary alone on a
  fresh emulator when pinned HWI omits or cannot drive the operation.
- **Direct** tests call the Rust device API, while **native CLI** tests use the
  separate `bhwi` binary. They prove those surfaces, not Python HWI parity.
- **Upstream gates** run the unmodified HWI 3.2.0 device suite through the
  candidate `hwi` binary and prove only the methods that suite invokes.

All six supported families run differential parity and a matching unmodified
upstream gate in Emulator CI. Trezor selects `hwi-upstream-trezor` for Model One
and `hwi-upstream-trezor-t` for Model T.

Ledger classic multisig display registers the policy and displays its address in
one candidate invocation. Project-owned differential cases cover sorted legacy
P2SH, wrapped P2WSH-P2SH, and native P2WSH plus a deliberately reverse-ordered
native `multi`; pinned HWI's Ledger suite marks multisig display unsupported and
skips it.

### Management Evidence

- **BitBox02:** differential coverage compares initialized-state management
  errors and toggles the passphrase setting through both implementations without
  changing the final state. Separate fresh simulators cover setup, two toggles,
  and wipe, plus restore, through both the native `bhwi` CLI and candidate
  `hwi`. Pinned HWI initializes BitBox02 through its Python API and has no CLI
  management methods to compare.
- **Trezor:** the two model-specific upstream gates cover the management methods
  that pinned HWI invokes. Restore is absent upstream, so three isolated,
  fresh-profile Model T checks exercise the direct device API, native `bhwi`
  CLI, and candidate `hwi`; Model One host word entry remains unsupported.
- **KeepKey:** differential coverage compares management errors, passphrase
  toggling, and PIN/passphrase behavior. Direct device, native `bhwi` CLI, and
  candidate `hwi` lifecycles each use a fresh emulator image for setup, wipe,
  and firmware character-cipher restore. The unmodified upstream gate supplies
  additional evidence, but pinned HWI has no working restore flow, so restore
  remains partial.

KeepKey wallet registration and software backup remain unsupported. Its
management input is host-interactive only when `hwi -i` is used.

## Running Parity Tests

The differential HWI tests compare the candidate `hwi` binary against pinned
Python HWI for the selected emulator. Each device-scoped Nix app builds the
candidate and supplies the binary paths and device selector; it expects exactly
one matching emulator to be already running and initialized.

```sh
nix run .#hwi-parity-ledger
nix run .#hwi-parity-jade
nix run .#hwi-parity-coldcard
nix run .#hwi-parity-bitbox
nix run .#hwi-parity-trezor
nix run .#hwi-parity-keepkey
```

To pass additional Cargo test filters or flags, append them after `--`:

```sh
nix run .#hwi-parity-ledger -- candidate_getxpub_matches_reference -- --nocapture
```

For a direct harness invocation, use the matching development shell and set all
three harness variables as described in the
[HWI parity runbook](../.agents/runbooks/hwi-parity.md). For example, after
starting and initializing only a Ledger emulator:

```sh
nix develop .#ledger -c cargo build -p bhwi-cli --bin hwi
REFERENCE_HWI_BIN="$(nix build --no-link --print-out-paths .#hwi-reference-bhwi)/bin/hwi-reference-bhwi" \
HWI_BIN="$PWD/target/debug/hwi" \
HWI_PARITY_DEVICE_TYPE=ledger \
nix develop .#ledger -c cargo test -p bhwi-e2e-hwi-parity -- --test-threads=1
```

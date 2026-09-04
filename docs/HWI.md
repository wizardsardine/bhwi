# HWI Compatibility

BHWI includes an `hwi` compatibility binary for users and tooling that expect
Python HWI's command-line interface. This page tracks feature parity by command
and device family.

The device-applicability entries follow Python HWI's
[support matrix](https://hwi.readthedocs.io/en/latest/devices/index.html#support-matrix):
features marked unsupported by the device firmware are shown as `n/a` here.

## Status Key

|Status|Meaning                                   |
|------|------------------------------------------|
|`[x]` |Parity covered for this device and command|
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

|Command           |Ledger|Jade |Coldcard|Trezor|KeepKey|BitBox01|BitBox02|Notes                                                                 |
|------------------|------|-----|--------|------|-------|--------|--------|----------------------------------------------------------------------|
|`enumerate`       |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[ ]`   |`[x]`   |Covered for expected Python HWI fields and global selection arguments.|
|`getmasterxpub`   |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[ ]`   |`[x]`   |Covered for supported address types.                                  |
|`getxpub`         |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[ ]`   |`[x]`   |Covered for normal and expert output shape.                           |
|`getdescriptors`  |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[ ]`   |`[x]`   |Covered for account descriptors.                                      |
|`getkeypool`      |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[ ]`   |`[x]`   |Covered for receive/change ranges and address types.                  |
|`signtx`          |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[ ]`   |`[x]`   |Ledger covers default BIP44/49/84/86 wallets and classic registered sorted multisig. Trezor covers single-sig, Taproot, OP_RETURN, and multisig. KeepKey multisig coverage is limited to fully derived sorted 2-of-2 signing across legacy P2SH, wrapped P2WSH-P2SH, and native P2WSH.|
|`signmessage`     |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`[ ]`   |`[x]`   |Covered for emulator-supported paths.                                 |
|`displayaddress`  |`[x]` |`[x]`|`[x]`   |`[x]` |`[x]`  |`n/a`   |`[x]`   |Registered Coldcard multisig display is covered for all script wrappers. Trezor covers descriptor and multisig display. KeepKey covers sorted, fully derived multisig.|
|`setup`           |`n/a` |`n/a`|`n/a`   |`[x]` |`[x]`  |`[ ]`   |`[x]`   |Trezor and KeepKey setup use fresh host entropy; emulator lifecycle coverage verifies setup end to end.|
|`wipe`            |`n/a` |`n/a`|`n/a`   |`[x]` |`[x]`  |`[ ]`   |`[x]`   |Stateful emulator lifecycles cover supported reset behavior.          |
|`restore`         |`n/a` |`n/a`|`n/a`   |`[~]` |`[~]`  |`n/a`   |`[x]`   |KeepKey restore implements the firmware character-cipher flow, but pinned Python HWI has no working or reference-tested flow. Trezor restore is supported on Model T; Model One host word entry remains unsupported.|
|`backup`          |`n/a` |`n/a`|`[x]`   |`n/a` |`n/a`  |`[ ]`   |`[x]`   |Coldcard file backup and BitBox02 mnemonic-export backup are covered. BitBox01 remains open.|
|`promptpin`       |`n/a` |`n/a`|`n/a`   |`[x]` |`[x]`  |`n/a`   |`n/a`   |Python HWI supports host PIN prompting for Trezor-class devices.      |
|`sendpin`         |`n/a` |`n/a`|`n/a`   |`[x]` |`[x]`  |`n/a`   |`n/a`   |Python HWI supports host PIN entry for Trezor-class devices.          |
|`togglepassphrase`|`n/a` |`n/a`|`n/a`   |`[x]` |`[x]`  |`n/a`   |`[x]`   |Python HWI supports this for Trezor, KeepKey, and BitBox02.           |
|`installudevrules`|`n/a` |`n/a`|`n/a`   |`n/a` |`n/a`  |`n/a`   |`n/a`   |Host-side Python HWI command covered by the shared udev installer. Registered on Linux only.|

KeepKey wallet registration and software backup remain unsupported. Its
management input is host-interactive only when `hwi -i` is used.

## Running Parity Tests

The HWI parity tests compare BHWI's `hwi` binary against the pinned Python HWI
reference for the selected emulator. The Nix runners build the CLI binary,
start the matching emulator environment, and run the focused parity package.

```sh
nix run .#hwi-parity-ledger
nix run .#hwi-parity-jade
nix run .#hwi-parity-coldcard
nix run .#hwi-parity-bitbox
nix run .#hwi-parity-trezor
```

To pass additional Cargo test filters or flags, append them after `--`:

```sh
nix run .#hwi-parity-ledger -- candidate_getxpub_matches_reference -- --nocapture
```

When running inside a matching Nix development shell, the lower-level command is:

```sh
cargo test -p bhwi-e2e-hwi-parity
```

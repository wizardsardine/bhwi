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

## Feature Parity

|Command           |Ledger|Jade |Coldcard|Trezor|KeepKey|BitBox01|BitBox02|Notes                                                                 |
|------------------|------|-----|--------|------|-------|--------|--------|----------------------------------------------------------------------|
|`enumerate`       |`[x]` |`[x]`|`[x]`   |`[ ]` |`[ ]`  |`[ ]`   |`[ ]`   |Covered for expected Python HWI fields and global selection arguments.|
|`getmasterxpub`   |`[x]` |`[x]`|`[x]`   |`[ ]` |`[ ]`  |`[ ]`   |`[ ]`   |Covered for supported address types.                                  |
|`getxpub`         |`[x]` |`[x]`|`[x]`   |`[ ]` |`[ ]`  |`[ ]`   |`[ ]`   |Covered for normal and expert output shape.                           |
|`getdescriptors`  |`[x]` |`[x]`|`[x]`   |`[ ]` |`[ ]`  |`[ ]`   |`[ ]`   |Covered for account descriptors.                                      |
|`getkeypool`      |`[x]` |`[x]`|`[x]`   |`[ ]` |`[ ]`  |`[ ]`   |`[ ]`   |Covered for receive/change ranges and address types.                  |
|`signtx`          |`[~]` |`[x]`|`[x]`   |`[ ]` |`[ ]`  |`[ ]`   |`[ ]`   |Ledger registered-wallet and non-default policy signing remains open. |
|`signmessage`     |`[x]` |`[x]`|`[x]`   |`[ ]` |`[ ]`  |`[ ]`   |`[ ]`   |Covered for emulator-supported paths.                                 |
|`displayaddress`  |`[x]` |`[x]`|`[~]`   |`[ ]` |`[ ]`  |`n/a`   |`[ ]`   |Coldcard registered multisig display coverage remains open.           |
|`setup`           |`n/a` |`n/a`|`n/a`   |`[ ]` |`[ ]`  |`[ ]`   |`[ ]`   |Python HWI supports software setup for the unchecked devices.         |
|`wipe`            |`n/a` |`n/a`|`n/a`   |`[ ]` |`[ ]`  |`[ ]`   |`[ ]`   |Python HWI supports software wipe for the unchecked devices.          |
|`restore`         |`n/a` |`n/a`|`n/a`   |`[ ]` |`[ ]`  |`n/a`   |`[ ]`   |Python HWI support excludes Ledger, Jade, Coldcard, and BitBox01.     |
|`backup`          |`n/a` |`n/a`|`[ ]`   |`n/a` |`n/a`  |`[ ]`   |`[ ]`   |Python HWI supports backup for Coldcard, BitBox01, and BitBox02.      |
|`promptpin`       |`n/a` |`n/a`|`n/a`   |`[ ]` |`[ ]`  |`n/a`   |`n/a`   |Python HWI supports host PIN prompting for Trezor-class devices.      |
|`sendpin`         |`n/a` |`n/a`|`n/a`   |`[ ]` |`[ ]`  |`n/a`   |`n/a`   |Python HWI supports host PIN entry for Trezor-class devices.          |
|`togglepassphrase`|`n/a` |`n/a`|`n/a`   |`[ ]` |`[ ]`  |`n/a`   |`[ ]`   |Python HWI supports this for Trezor, KeepKey, and BitBox02.           |
|`installudevrules`|`n/a` |`n/a`|`n/a`   |`n/a` |`n/a`  |`n/a`   |`n/a`   |Host-side Python HWI command not yet implemented.                     |

## Running Parity Tests

The HWI parity tests compare BHWI's `hwi` binary against the pinned Python HWI
reference for the selected emulator. The Nix runners build the CLI binary,
start the matching emulator environment, and run the focused parity package.

```sh
nix run .#hwi-parity-ledger
nix run .#hwi-parity-jade
nix run .#hwi-parity-coldcard
```

To pass additional Cargo test filters or flags, append them after `--`:

```sh
nix run .#hwi-parity-ledger -- candidate_getxpub_matches_reference -- --nocapture
```

When running inside a matching Nix development shell, the lower-level command is:

```sh
cargo test -p bhwi-e2e-hwi-parity
```

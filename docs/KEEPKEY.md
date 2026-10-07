# KeepKey

BHWI treats KeepKey as a distinct device profile while reusing the audited
Trezor protocol-v1 framing and transport. Hardware access uses HID
`2b24:0001/ff00` or WebUSB `2b24:0002`; the emulator uses UDP
`127.0.0.1:11044` and its debug link uses UDP `127.0.0.1:11045`.

## Pinned upstreams

The flake locks every source needed to build and test the emulator:

- KeepKey firmware v7.10.0 at
  `d54797ee604f12c82ac6e5e02490b62dc04bf2dd`, fetched as a flat GitHub input.
- nanopb at `493adf3616bee052649c63c473f8355630c2797f`.
- Bitcoin Core HWI 3.2.0 at
  `a4d66f8bc18fc2658704fc5875e9d3b33cf22b2a`.

One inline Nix source derivation assembles that parent and only the emulator's
required submodules, each fetched as a separate flat GitHub input at the
parent's gitlink revision (or Python KeepKey's gitlink for Ethereum lists):

| Destination in firmware tree | Repository | Revision |
| --- | --- | --- |
| `deps/device-protocol` | `keepkey/device-protocol` | `323802f17dd44165a5100357df771348c8b49672` |
| `deps/crypto/trezor-firmware` | `keepkey/trezor-firmware` | `03d8a55a832fb61bb89477ef7239a80ecb367080` |
| `deps/googletest` | `google/googletest` | `7888184f28509dba839e3683409443e0b5bb8948` |
| `deps/python-keepkey` | `keepkey/python-keepkey` | `9e4b4f0b14a6ea966fecfe31d8e2706abe7b405c` |
| `deps/qrenc/QR-Code-generator` | `keepkey/QR-Code-generator` | `6dfbfdad5d9303ed190d1c3cb7bec34b565b6ce8` |
| `deps/sca-hardening/SecAESSTM32` | `keepkey/SecAESSTM32` | `71d356a1141624994cf613bd2d2583892e8e6d5a` |
| `deps/python-keepkey/keepkeylib/eth/ethereum-lists` | `keepkey/ethereum-lists` | `89a64f717e1690bb31adb3e4c38e23640357333c` |

Recursive copies preserve upstream relative symlinks, including SecAESSTM32's
required headers; copied directories are made writable during assembly.
The Ethereum lists and tracked Uniswap data remain available to the existing
token generators: this is not a Bitcoin-only build or a replacement token
table. The full default CMake build, including unit targets, is unchanged.
Unused code-signing keys and nested Trezor dependencies such as MicroPython,
Savannah lwIP, and MicroPython's libffi are not fetched. Initial provisioning
still needs GitHub for the selected inputs; the runtime runner does not
download sources.

The build applies HWI's own `test/data/keepkey-build.patch` at the firmware
root, `keepkey-googletest.patch` under `deps/googletest`, and
`nanopb-deprecated-mode.patch` at the nanopb root. Patches are read from the
pinned HWI input; BHWI does not vendor copies. The script builds nanopb's
Python generator, configures `cmake/caches/emulator.cmake` with the absolute
nanopb tree and Nix `protoc`, and builds `bin/kkemu`. It performs no network
checkout at runtime.

BHWI also applies three local compatibility patches under
`nix/patches/keepkey/`: `cmake-minimum.patch` raises googletest's pre-3.5
minimum for current CMake, `keepkey-emulator-memcheck.patch` disables the
hardware-only stack guard on hosted builds, and
`keepkey-unpacked-structs.patch` aligns nanopb pointer descriptors for arm64
Mach-O. NixOS has no `/bin/sh`, so the build creates local Bash launchers for
GNU Make and nanopb without modifying either pinned source. All six patches
and the launcher recipe are included in the build-cache key.

## Flake commands

The emulator launcher, initializer, and development shell are available on
`x86_64-linux` and `aarch64-darwin`. The HWI parity and upstream suites below
are Linux/x86-64-only:

```sh
nix run .#keepkey
nix run .#keepkey-init
nix develop .#keepkey
nix run .#hwi-parity-keepkey -- -- --test-threads=1
nix run .#hwi-upstream-keepkey
nix run .#hwi-upstream-suite -- keepkey
```

`keepkey` starts the emulator. After UDP 11044 answers, `keepkey-init` wipes it
and loads the synthetic fixture with label `test`, an empty PIN, and
passphrase protection disabled. The fixture mnemonic is:

```text
alcohol woman abuse must during monitor noble actual mixed trade anger aisle
```

The initializer accepts `KEEPKEY_DEVICE`, `KEEPKEY_MNEMONIC`,
`KEEPKEY_LABEL`, `KEEPKEY_PIN`, and `KEEPKEY_PASSPHRASE_PROTECTION`. It does
not print those values.

The source builder also supports a prepared executable:

```sh
KEEPKEY_EMULATOR_BIN=/absolute/path/to/kkemu nix run .#keepkey
nix run .#keepkey -- --prepare-hwi
```

Prepare mode prints only the absolute emulator path. The upstream HWI runner
uses the same interface through `HWI_KEEPKEY_PREPARE_SCRIPT`; an already built
binary can instead be supplied as `HWI_KEEPKEY_EMULATOR`. Relative
`HWI_KEEPKEY_EMULATOR` paths are resolved from the runner's invocation
directory.

To check the assembled source's relative header symlink and required token
lists without compiling the emulator:

```sh
nix develop .#keepkey -c bash -c '
  test -f "$KEEPKEY_FIRMWARE_SRC/include/aes_sca/aes.h" &&
  test -n "$(find "$KEEPKEY_FIRMWARE_SRC/deps/python-keepkey/keepkeylib/eth/ethereum-lists/src/tokens/eth" -name "*.json" -print -quit)"
'
```

## Cache and profiles

The default cache root is
`${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/keepkey`. `start-keepkey.sh` copies the
assembled firmware source and the separate nanopb input into a writable
`build` tree. Its unchanged `recipe=10` build key contains both pinned
revisions, the firmware and nanopb Nix store paths, SHA-256 checksums of all
six patches, and the exact Nix toolchain identity
`${pkgs.runtimeShell}:${pkgs.lib.makeBinPath [ pkgs.cmake pkgs.gcc pkgs.gnumake pkgs.patch pkgs.protobuf hwiPython ]}`.
The assembled firmware store path changes when any selected dependency or
the assembly recipe changes, so the existing source-path key invalidates the
cache without extra revision variables or a runner recipe bump. The firmware
revision remains the parent commit, not a synthetic combined revision.
A missing binary or changed key recreates the tree before patching, so repeated
starts do not reapply patches. Actions caches this directory by runner OS and
architecture, the exact `flake.lock` hash, and the build-input hash; its sole
restore prefix retains the OS, architecture, and exact lock hash.

The emulator runs with
`${KEEPKEY_PROFILE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/keepkey/profile}`
as its working directory. Before entering it, the launcher sets umask `077`
and creates or repairs the directory to mode `0700`. Consequently its relative
`emulator.img` is private and isolated from the source/build tree. Set a
different `KEEPKEY_PROFILE_DIR` for each fresh-image management lifecycle.

## HWI final gate

`hwi-upstream-keepkey` builds the BHWI CLI and runs the unmodified HWI 3.2.0
KeepKey device suite with `--device-only --interface=cli --keepkey`. The runner
symlinks the pinned executable as a temporary `kkemu`, lets upstream create and
delete a fresh `emulator.img` for each test, confirms required actions through
debug UDP 11045, and prints `keepkey-emulator.stdout` if the suite fails. Stop
any shared KeepKey emulator before this gate. KeepKey CI bounds it to 90
minutes.

Python HWI 3.2.0 has no working reference-tested KeepKey restore flow: its
suite contains no restore test and inherits a word-request path that does not
handle KeepKey's character cipher. BHWI implements the firmware's
`CharacterRequest`/`CharacterAck` recovery flow and verifies it in direct and
CLI emulator lifecycles, so restore is marked partial (`[~]`) rather than
claimed as differential parity.

Only the HWI emulator suites are Linux/x86-64-specific. Physical KeepKey
HID/WebUSB support and browser WebHID/WebUSB support remain cross-platform on
the targets already supported by those BHWI surfaces.

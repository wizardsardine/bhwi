# KeepKey

BHWI treats KeepKey as a distinct device profile while reusing the audited
Trezor protocol-v1 framing and transport. Hardware access uses HID
`2b24:0001/ff00` or WebUSB `2b24:0002`; the emulator uses UDP
`127.0.0.1:11044` and its debug link uses UDP `127.0.0.1:11045`.

## Pinned upstreams

The flake locks every source needed to build and test the emulator:

- KeepKey firmware v7.10.0 at
  `d54797ee604f12c82ac6e5e02490b62dc04bf2dd`, fetched recursively. Its pinned
  `deps/device-protocol` revision is
  `323802f17dd44165a5100357df771348c8b49672`.
- nanopb at `493adf3616bee052649c63c473f8355630c2797f`.
- Bitcoin Core HWI 3.2.0 at
  `a4d66f8bc18fc2658704fc5875e9d3b33cf22b2a`.

The build applies HWI's own `test/data/keepkey-build.patch` at the firmware
root, `keepkey-googletest.patch` under `deps/googletest`, and
`nanopb-deprecated-mode.patch` at the nanopb root. Patches are read from the
pinned HWI input; BHWI does not vendor copies. The script builds nanopb's
Python generator, configures `cmake/caches/emulator.cmake` with the absolute
nanopb tree and Nix `protoc`, and builds `bin/kkemu`. It performs no network
checkout at runtime.

Current CMake rejects googletest's pre-3.5 minimum, so BHWI applies the
source-only `nix/patches/keepkey/cmake-minimum.patch` to those exact upstream
files. NixOS has no `/bin/sh`, so the build creates local Bash launchers for
GNU Make and nanopb without modifying either pinned source. The compatibility
patch and launcher recipe are included in the build-cache key.

## Flake commands

KeepKey's emulator outputs are available only on `x86_64-linux`:

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

## Cache and profiles

The default cache root is
`${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/keepkey`. `start-keepkey.sh` copies the
two read-only flake inputs into a writable `build` tree. Its `recipe=9` build
key contains both pinned revisions, the firmware and nanopb Nix store paths,
SHA-256 checksums of all four patches, and the exact Nix toolchain identity
`${pkgs.runtimeShell}:${pkgs.lib.makeBinPath [ pkgs.cmake pkgs.gcc pkgs.gnumake pkgs.patch pkgs.protobuf hwiPython ]}`.
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

Only the emulator infrastructure is Linux/x86-64-specific. Physical KeepKey
HID/WebUSB support and browser WebHID/WebUSB support remain cross-platform on
the targets already supported by those BHWI surfaces.

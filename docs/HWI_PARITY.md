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
- Emulator CI (`.github/workflows/emulators.yml`) runs the matching
  `hwi-parity-<device>` app inside each device job, then stops the shared
  emulator and runs the pinned upstream HWI suite as that job's final test
  gate.

## Final acceptance gate

Parity is accepted only when the unmodified Bitcoin Core HWI 3.2.0 device
suite passes against BHWI's CLI adapter. The flake exposes a tailored app for
each supported emulator:

```sh
nix run .#hwi-upstream-bitbox
nix run .#hwi-upstream-coldcard
nix run .#hwi-upstream-ledger
nix run .#hwi-upstream-jade
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

## BitBox02 parity notes

BitBox02 parity is wired against Python HWI's built-in simulator transport. The
pinned reference backend probes `127.0.0.1:15423`, so the BitBox emulator must be
running and initialized before `hwi-parity-bitbox` starts.

The suite covers the same implemented read/sign/display command set as the
other wired devices, plus BitBox02 mnemonic-export `backup`. The remaining
stateful BitBox device-management commands (`setup`, `wipe`, `restore`,
`togglepassphrase`) stay as tracked gaps because BHWI has not claimed that
compatibility surface yet.

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
  `hwi-parity-<device>` app inside each device job.

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

| Device    | HWI parity | Notes |
|-----------|------------|-------|
| Ledger    | Wired      | `hwi-parity-ledger`, in Emulator CI. |
| Coldcard  | Wired      | `hwi-parity-coldcard`, in Emulator CI, including file-producing `backup`. |
| Jade      | Wired      | `hwi-parity-jade`, in Emulator CI. |
| BitBox02  | Wired      | `hwi-parity-bitbox`, in Emulator CI. |

## BitBox02 parity notes

BitBox02 parity is wired against Python HWI's built-in simulator transport. The
pinned reference backend probes `127.0.0.1:15423`, so the BitBox emulator must be
running and initialized before `hwi-parity-bitbox` starts.

The suite covers the same implemented read/sign/display command set as the
other wired devices, plus BitBox02 mnemonic-export `backup`. The remaining
stateful BitBox device-management commands (`setup`, `wipe`, `restore`,
`togglepassphrase`) stay as tracked gaps because BHWI has not claimed that
compatibility surface yet.

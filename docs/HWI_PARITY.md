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
- The suite currently asserts `enumerate` parity (device type, model, and JSON
  shape) with the intended emulator family active.
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

The flake env blocks only supply build/runtime libraries; they do not tell HWI
where the emulator is — the backend already knows. Our candidate `bhwi hwi`
mirrors each with its own `--emulators` enumerate.

## Support matrix

| Device    | HWI parity | Notes |
|-----------|------------|-------|
| Ledger    | Wired      | `hwi-parity-ledger`, in Emulator CI. |
| Coldcard  | Wired      | `hwi-parity-coldcard`, in Emulator CI. |
| Jade      | Wired      | `hwi-parity-jade`, in Emulator CI. |
| BitBox02  | **Gap**    | Not wired — see below. |

## BitBox02 parity gap (intentional)

BitBox02 is intentionally excluded from HWI parity today. Unlike the wired
devices, the blocker is on the **reference** side, not ours:

- Upstream Python HWI's BitBox02 backend talks to the device over **USB HID
  only** (via the `bitbox02` Python library). It has no `--emulators` /
  TCP-simulator enumerate path, so the reference `hwi enumerate` cannot see the
  firmware TCP simulator on `:15423` the way it sees the Coldcard socket, Ledger
  Speculos, or Jade QEMU. There is no upstream simulator enumerate to lean on.
- On top of that, the reference HWI restricts recognized devices to
  `commands.all_devs = ["ledger", "coldcard", "jade"]` in
  [`flake.nix`](../flake.nix), deliberately excluding BitBox02.
- The parity harness (`e2e/hwi-parity`) has no BitBox normalization case, and
  there is no `hwi-parity-bitbox` flake app or CI job.

The candidate side is already ready: `bhwi hwi --emulators --device-type
bitbox02 enumerate` works against the firmware TCP simulator (the CLI gained a
simulator transport, and `parse_device_type` accepts `bitbox02`). Enabling
parity requires:

1. Add `"bitbox02"` to `commands.all_devs` in the reference HWI.
2. **Verify the upstream `hwilib` BitBox02 backend can reach the pinned firmware
   TCP simulator** (`tcp:127.0.0.1:15423`). Upstream HWI drives BitBox02 through
   the `bitbox02` Python library over USB; whether it can enumerate this
   firmware simulator over TCP is unverified and is the main open question. If it
   cannot, parity against this simulator is not achievable without a different
   reference transport, and this row should stay a documented gap.
3. Add a BitBox02 normalization/device case to `e2e/hwi-parity`.
4. Add a `hwi-parity-bitbox` flake app (`mkHwiParityRunner … "bitbox02" …`) and
   expose it under `apps`.
5. Add the parity step to the `bitbox-e2e` job in
   `.github/workflows/emulators.yml`.

Until step 2 is confirmed, BitBox02 HWI parity remains an explicit, tracked gap.

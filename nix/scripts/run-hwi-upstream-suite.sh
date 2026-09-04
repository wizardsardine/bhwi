#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run-hwi-upstream-suite.sh <bitbox02|coldcard|ledger|jade|keepkey|trezor|trezor-t> [extra run_tests.py args...]

Required:
  HWI_BIN                     Path to the BHWI hwi binary under test.

Optional device inputs:
  HWI_LEDGER_APP_ELF          Prebuilt Ledger Bitcoin app ELF.
  HWI_LEDGER_SPECULOS_BIN     Speculos executable. Defaults to SPECULOS_BIN or speculos.
  HWI_COLDCARD_SIMULATOR      Prepared Coldcard simulator.py (otherwise uses its prepare script).
  HWI_JADE_SIMULATOR_DIR      Prepared HWI-compatible Jade directory.
  HWI_BITBOX02_SIMULATOR      BitBox02 simulator binary.
  HWI_TREZOR_EMULATOR         Prebuilt Trezor One emulator (otherwise uses its prepare script).
  HWI_KEEPKEY_EMULATOR        Prepared KeepKey emulator; relative paths use the invocation directory.
  HWI_BITCOIND                Path to bitcoind. Defaults to bitcoind on PATH.

The runner executes Bitcoin Core HWI's upstream test suite in --interface=cli
mode with a PATH wrapper named hwi that delegates to HWI_BIN.
EOF
}

if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 2
fi

device="$1"
shift

if [[ -z "${HWI_BIN:-}" ]]; then
  echo "HWI_BIN must point to the BHWI hwi binary under test" >&2
  exit 2
fi
if [[ ! -x "$HWI_BIN" ]]; then
  echo "HWI_BIN is not executable: $HWI_BIN" >&2
  exit 2
fi

invocation_dir="$PWD"
upstream_src="${HWI_UPSTREAM_SRC:?HWI_UPSTREAM_SRC must point to upstream HWI sources}"
work="$(mktemp -d "${TMPDIR:-/tmp}/bhwi-hwi-upstream.XXXXXXXXXX")"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

cp -R "$upstream_src"/. "$work/HWI"
chmod -R u+w "$work/HWI"

mkdir -p "$work/bin"
cat > "$work/bin/hwi" <<EOF
#!$BASH
exec "$HWI_BIN" "\$@"
EOF
chmod +x "$work/bin/hwi"

export PATH="$work/bin:$PATH"
export PYTHONPATH="$work/HWI${PYTHONPATH:+:$PYTHONPATH}"

bitcoind="${HWI_BITCOIND:-bitcoind}"
common_args=(--device-only --interface=cli --bitcoind "$bitcoind")
python="${HWI_PYTHON:?HWI_PYTHON must point to the pinned HWI Python interpreter}"
cd "$work/HWI/test"

case "$device" in
  bitbox02)
    simulator="${HWI_BITBOX02_SIMULATOR:?HWI_BITBOX02_SIMULATOR must point to the BitBox02 simulator}"
    bitbox_dir="$work/bitbox02-compat"
    mkdir -p "$bitbox_dir"
    ln -s "$simulator" "$bitbox_dir/bitbox02-simulator"
    "$python" run_tests.py "${common_args[@]}" --bitbox02 --bitbox02-path "$bitbox_dir/bitbox02-simulator" "$@"
    ;;
  ledger)
    ledger_dir="$work/ledger-compat"
    mkdir -p "$ledger_dir/apps"
    app_elf="${HWI_LEDGER_APP_ELF:-}"
    if [[ -z "$app_elf" ]]; then
      app_elf="$(bash "${LEDGER_BUILD_APP_SCRIPT:?LEDGER_BUILD_APP_SCRIPT must be set or HWI_LEDGER_APP_ELF provided}")"
    fi
    cp "$app_elf" "$ledger_dir/apps/btc-test.elf"
    cp "$work/HWI/test/data/speculos-automation.json" "$ledger_dir/apps/speculos-automation.json"
    cat > "$ledger_dir/speculos.py" <<'PY'
import os
import signal
import subprocess
import sys

args = sys.argv[1:]
if not args:
    raise SystemExit("missing Speculos arguments")
app = os.path.abspath(args[-1])
speculos_args = args[:-1]
for index, arg in enumerate(speculos_args):
    if arg.startswith("file:"):
        speculos_args[index] = "file:/app/speculos-automation.json"
speculos = os.environ.get("HWI_LEDGER_SPECULOS_BIN") or os.environ.get("SPECULOS_BIN") or "speculos"
process = subprocess.Popen([speculos, app] + speculos_args, start_new_session=True)

def stop_speculos(_signum, _frame):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGINT)

signal.signal(signal.SIGTERM, stop_speculos)
signal.signal(signal.SIGINT, stop_speculos)
raise SystemExit(process.wait())
PY
    "$python" run_tests.py "${common_args[@]}" --ledger --ledger-path "$ledger_dir/speculos.py" "$@"
    ;;
  coldcard)
    simulator="${HWI_COLDCARD_SIMULATOR:-}"
    if [[ -z "$simulator" ]]; then
      simulator="$(bash \
        "${HWI_COLDCARD_PREPARE_SCRIPT:?HWI_COLDCARD_PREPARE_SCRIPT must be set}" \
        --prepare-hwi \
        "$work/HWI/test/data/coldcard-multisig.patch" |
        tail -n 1)"
    fi
    coldcard_python="$(dirname "$simulator")/../ENV/bin/python3"
    mkdir -p "$work/coldcard-bin"
    export HWI_COLDCARD_PYTHON="$coldcard_python"
    cat > "$work/coldcard-bin/python3" <<'SH'
#!/usr/bin/env bash
export LD_LIBRARY_PATH="${COLDCARD_RUNTIME_LIBRARY_PATH:-}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$HWI_COLDCARD_PYTHON" "$@"
SH
    chmod +x "$work/coldcard-bin/python3"
    PATH="$work/coldcard-bin:$PATH" \
      "$python" run_tests.py "${common_args[@]}" --coldcard --coldcard-path "$simulator" "$@"
    ;;
  jade)
    simulator_dir="${HWI_JADE_SIMULATOR_DIR:-}"
    if [[ -z "$simulator_dir" ]]; then
      simulator_dir="$work/jade-compat"
      bash "${HWI_JADE_PREPARE_SCRIPT:?HWI_JADE_PREPARE_SCRIPT must be set}" --prepare-hwi "$simulator_dir"
    fi
    "$python" run_tests.py "${common_args[@]}" --jade --jade-path "$simulator_dir" "$@"
    ;;
  keepkey | trezor | trezor-t)
    if [[ "$device" == keepkey ]]; then
      emulator="${HWI_KEEPKEY_EMULATOR:-}"
      if [[ -n "$emulator" && "$emulator" != /* ]]; then
        emulator="$invocation_dir/$emulator"
      fi
      if [[ -z "$emulator" ]]; then
        emulator="$(bash \
          "${HWI_KEEPKEY_PREPARE_SCRIPT:?HWI_KEEPKEY_PREPARE_SCRIPT must be set}" \
          --prepare-hwi)"
      fi
      emulator_name="kkemu"
      model_args=(--keepkey --keepkey-path)
      debug_port=11045
      compat_dir="$work/keepkey-compat"
    else
      emulator="${HWI_TREZOR_EMULATOR:-}"
      if [[ -z "$emulator" ]]; then
        emulator="$(bash \
          "${HWI_TREZOR_PREPARE_SCRIPT:?HWI_TREZOR_PREPARE_SCRIPT must be set}" \
          --prepare-hwi |
          tail -n 1)"
      fi
      debug_port=21325
      compat_dir="$work/trezor-compat"
      if [[ "$device" == trezor-t ]]; then
        emulator_name="trezor-emu-core"
        model_args=(--trezor-t --trezor-t-path)
      else
        emulator_name="trezor-emu-legacy"
        model_args=(--trezor-1 --trezor-1-path)
      fi
    fi
    if [[ ! -x "$emulator" ]]; then
      echo "emulator is not executable: $emulator" >&2
      exit 2
    fi
    emulator="$(realpath "$emulator")"
    mkdir -p "$compat_dir"
    ln -s "$emulator" "$compat_dir/$emulator_name"
    emulator="$compat_dir/$emulator_name"

    cat > "$work/debuglink-press.py" <<'PY'
import os
import socket
import time

REPORT_SIZE = 64
DECISION = 100
YES = bytes([0x08, 0x01])
DEADLINE = 300

frame = b"##" + DECISION.to_bytes(2, "big") + len(YES).to_bytes(4, "big") + YES
report = bytearray(REPORT_SIZE)
report[0] = 0x3F
report[1 : 1 + len(frame)] = frame

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect(("127.0.0.1", int(os.environ["HWI_DEBUGLINK_PORT"])))
parent = os.getppid()
started = time.monotonic()
while os.getppid() == parent and time.monotonic() - started < DEADLINE:
    time.sleep(0.25)
    try:
        sock.send(bytes(report))
    except OSError:
        pass
PY

    export HWI_DEBUGLINK_PORT="$debug_port"
    cat > "$work/bin/hwi" <<EOF
#!$BASH
press=0
case " \$* " in
  *" wipe "* | *" signtx "* | *" signmessage "* | *" displayaddress "* | *" togglepassphrase "* | *" setup "* | *" restore "*) press=1 ;;
esac
case " \$* " in
  *" sendpin "*) case " \$* " in *" -p "*) press=1 ;; esac ;;
  *" enumerate "*)
    previous=
    for arg in "\$@"; do
      if [[ "\$previous" == "-p" ]]; then
        [[ -n "\$arg" ]] && press=1
        break
      fi
      previous="\$arg"
    done
    ;;
esac
case "\$press" in
  1)
    "$python" "$work/debuglink-press.py" &
    presser=\$!
    trap 'kill "\$presser" 2>/dev/null || true' EXIT HUP INT TERM
    "$HWI_BIN" "\$@"
    status=\$?
    kill "\$presser" 2>/dev/null || true
    wait "\$presser" 2>/dev/null || true
    exit "\$status"
    ;;
esac
exec "$HWI_BIN" "\$@"
EOF
    chmod +x "$work/bin/hwi"

    if "$python" run_tests.py "${common_args[@]}" "${model_args[@]}" "$emulator" "$@"; then
      :
    else
      status=$?
      if [[ "$device" == keepkey && -f keepkey-emulator.stdout ]]; then
        echo "KeepKey emulator log:" >&2
        cat keepkey-emulator.stdout >&2
      fi
      exit "$status"
    fi
    ;;
  *)
    echo "unsupported upstream HWI suite device: $device" >&2
    usage
    exit 2
    ;;
esac

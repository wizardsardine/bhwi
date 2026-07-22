#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run-hwi-upstream-suite.sh <bitbox02|coldcard|ledger|jade> [extra run_tests.py args...]

Required:
  HWI_BIN                     Path to the BHWI hwi binary under test.

Optional device inputs:
  HWI_LEDGER_APP_ELF          Prebuilt Ledger Bitcoin app ELF.
  HWI_LEDGER_SPECULOS_BIN     Speculos executable. Defaults to SPECULOS_BIN or speculos.
  HWI_COLDCARD_SIMULATOR      Prepared Coldcard simulator.py (otherwise uses its prepare script).
  HWI_JADE_SIMULATOR_DIR      Prepared HWI-compatible Jade directory.
  HWI_BITBOX02_SIMULATOR      BitBox02 simulator binary.
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
#!/usr/bin/env bash
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
  *)
    echo "unsupported upstream HWI suite device: $device" >&2
    usage
    exit 2
    ;;
esac

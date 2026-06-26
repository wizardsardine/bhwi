#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run-hwi-upstream-suite.sh <ledger|coldcard|jade> [extra run_tests.py args...]

Required:
  HWI_BIN                     Path to the BHWI hwi binary under test.

Optional device inputs:
  HWI_LEDGER_APP_ELF          Prebuilt Ledger Bitcoin app ELF.
  HWI_LEDGER_SPECULOS_BIN     Speculos executable. Defaults to SPECULOS_BIN or speculos.
  HWI_COLDCARD_SIMULATOR      Path to Coldcard simulator.py.
  HWI_JADE_SIMULATOR_DIR      Directory containing HWI-compatible Jade simulator files.
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

case "$device" in
  ledger)
    ledger_dir="$work/ledger-compat"
    mkdir -p "$ledger_dir/apps"
    app_elf="${HWI_LEDGER_APP_ELF:-}"
    if [[ -z "$app_elf" ]]; then
      app_elf="$(bash "${LEDGER_BUILD_APP_SCRIPT:?LEDGER_BUILD_APP_SCRIPT must be set or HWI_LEDGER_APP_ELF provided}")"
    fi
    ln -s "$app_elf" "$ledger_dir/apps/btc-test.elf"
    cat > "$ledger_dir/speculos.py" <<'PY'
import os
import sys

args = sys.argv[1:]
if not args:
    raise SystemExit("missing Speculos arguments")
app = args[-1]
speculos_args = args[:-1]
speculos = os.environ.get("HWI_LEDGER_SPECULOS_BIN") or os.environ.get("SPECULOS_BIN") or "speculos"
os.execvp(speculos, [speculos, app] + speculos_args)
PY
    python3 "$work/HWI/test/run_tests.py" "${common_args[@]}" --ledger --ledger-path "$ledger_dir/speculos.py" "$@"
    ;;
  coldcard)
    simulator="${HWI_COLDCARD_SIMULATOR:-}"
    if [[ -z "$simulator" ]]; then
      echo "HWI_COLDCARD_SIMULATOR must point to Coldcard simulator.py" >&2
      exit 2
    fi
    python3 "$work/HWI/test/run_tests.py" "${common_args[@]}" --coldcard --coldcard-path "$simulator" "$@"
    ;;
  jade)
    simulator_dir="${HWI_JADE_SIMULATOR_DIR:-}"
    if [[ -z "$simulator_dir" ]]; then
      echo "HWI_JADE_SIMULATOR_DIR must point to an HWI-compatible Jade simulator directory" >&2
      exit 2
    fi
    python3 "$work/HWI/test/run_tests.py" "${common_args[@]}" --jade --jade-path "$simulator_dir" "$@"
    ;;
  *)
    echo "unsupported upstream HWI suite device: $device" >&2
    usage
    exit 2
    ;;
esac

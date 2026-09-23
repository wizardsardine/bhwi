#!/usr/bin/env bash
set -euo pipefail

src="${SPECTER_DIY_SRC:?SPECTER_DIY_SRC must point to the pinned Specter-DIY source}"
rev="${SPECTER_DIY_REV:-$(basename "$src")}"
python="${SPECTER_PYTHON:?SPECTER_PYTHON must point to python3}"
cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/bhwi/specter"
src_key="${rev//[^A-Za-z0-9_.-]/_}"
work="$cache_root/source-$src_key"
binary="$work/bin/micropython_unix"
source_patch_revision="loopback-state-reset-v5"
build_key="rev=$rev patch=$source_patch_revision compiler=${SPECTER_CC:?SPECTER_CC must point to gcc} cxx=${SPECTER_CXX:?SPECTER_CXX must point to g++} cflags=${SPECTER_MPY_CFLAGS:?SPECTER_MPY_CFLAGS must be set} ldflags=${SPECTER_LDFLAGS_EXTRA:?SPECTER_LDFLAGS_EXTRA must be set}"
build_key_file="$work/.bhwi-build-key"

mkdir -p "$cache_root"
if [[ ! -d "$work" ]]; then
  mkdir -p "$work"
  cp -R "$src"/. "$work"/
  chmod -R u+w "$work"
fi

# Keep the pinned source immutable while binding its unauthenticated endpoints
# to loopback and releasing clients that reset during controller handoff.
tcphost="$work/f469-disco/libs/unix/tcphost.py"
cp "$src/f469-disco/libs/unix/tcphost.py" "$tcphost"
chmod u+w "$tcphost"
sed -i 's/socket\.getaddrinfo("0\.0\.0\.0", port)/socket.getaddrinfo("127.0.0.1", port)/' "$tcphost"
"$python" - "$tcphost" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old_client = '''            except OSError as e:
                if "EAGAIN" not in str(e) and "ECONNRESET" not in str(e):
                    raise e
'''
new_client = '''            except OSError as e:
                if "EAGAIN" in str(e):
                    pass
                elif "ECONNRESET" in str(e):
                    self.client.close()
                    self.client = None
                    if not last:
                        self._check()
                else:
                    raise e
'''
old_accept = '''        else:
            # check if got connected
            try:
                res = self.socket.accept()
                self.client = res[0]
                self.client.setblocking(False)
                self._check(last=True)
            except OSError as e:
                if "EAGAIN" not in str(e):
                    raise e
'''
if text.count(old_client) != 1:
    raise SystemExit("unexpected Specter client reset handler")
if text.count(old_accept) != 1:
    raise SystemExit("unexpected Specter accept handler")

text = text.replace(old_client, new_client)
path.write_text(text)
PY

if [[ ! -x "$binary" ]] || [[ ! -f "$build_key_file" ]] || [[ "$(<"$build_key_file")" != "$build_key" ]]; then
  # The pinned helper assumes /usr/bin/env, which NixOS does not provide.
  sed -i "1c#!$python" "$work/tools/embed_git_info.py"

  make -C "$work" clean

  (
    cd "$work"
    export CC="$SPECTER_CC"
    export CXX="${SPECTER_CXX:?SPECTER_CXX must point to g++}"
    export MPY_CFLAGS="$SPECTER_MPY_CFLAGS"
    export LDFLAGS_EXTRA="${SPECTER_LDFLAGS_EXTRA:?SPECTER_LDFLAGS_EXTRA must be set}"
    export SPECTER_REPRODUCIBLE_BUILD=1
    make unix
  )
  printf '%s\n' "$build_key" > "$build_key_file"
fi

cd "$work"
export SDL_VIDEODRIVER="${SDL_VIDEODRIVER:-dummy}"
rm -rf -- "$work/fs"
state_dir="$(mktemp -d "$cache_root/runtime.XXXXXX")"
cleanup_state() {
  rm -rf -- "$state_dir"
}
trap cleanup_state EXIT HUP INT TERM

"$binary" simulate.py "$state_dir" "$@"

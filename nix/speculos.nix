{
  docker-client,
  podman,
  writeShellApplication,
}:

writeShellApplication {
  name = "speculos";

  runtimeInputs = [
    docker-client
    podman
  ];

  text = ''
    set -euo pipefail

    if [ "$#" -lt 1 ]; then
      echo "usage: speculos <app.elf> [speculos args...]" >&2
      exit 2
    fi

    elf="$1"
    shift

    if [ ! -f "$elf" ]; then
      echo "Speculos app ELF does not exist: $elf" >&2
      exit 1
    fi

    image="''${SPECULOS_CONTAINER_IMAGE:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools@sha256:811ed84d8f29d80a8469ac3b33ed5efcc3bef1605016a11a32b99475d91da3dc}"
    elf_dir="$(cd "$(dirname "$elf")" && pwd)"
    elf_name="$(basename "$elf")"

    apdu_port="''${LEDGER_APDU_PORT:-9999}"
    api_port="''${LEDGER_API_PORT:-5000}"
    if [ "$(uname)" = "Darwin" ]; then
      net_args=(-p "$apdu_port:$apdu_port" -p "$api_port:$api_port")
    else
      net_args=(--network host)
    fi

    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      container_runtime="docker"
      elf_mount="$elf_dir:/app:ro"
    elif command -v podman >/dev/null 2>&1; then
      container_runtime="podman"
      elf_mount="$elf_dir:/app:ro,Z"
    else
      echo "Neither docker nor podman is available for Speculos" >&2
      exit 1
    fi

    container_state_dir="$(mktemp -d)"
    container_cidfile="$container_state_dir/container.cid"

    # Invoked indirectly by the EXIT trap below.
    # shellcheck disable=SC2329
    cleanup_container() {
      if [ -s "$container_cidfile" ]; then
        "$container_runtime" rm --force "$(cat "$container_cidfile")" >/dev/null 2>&1 || true
      fi
      rm -f "$container_cidfile"
      rmdir "$container_state_dir" 2>/dev/null || true
    }

    # Stopping the container client alone can leave the container and its host
    # network listeners running. Keep this wrapper alive to own that lifecycle.
    trap cleanup_container EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    "$container_runtime" run --rm --cidfile "$container_cidfile" "''${net_args[@]}" \
      -v "$elf_mount" "$image" speculos "/app/$elf_name" "$@" &
    container_client_pid=$!

    set +e
    wait "$container_client_pid"
    status=$?
    set -e
    exit "$status"
  '';
}

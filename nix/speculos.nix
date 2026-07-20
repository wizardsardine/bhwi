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
      exec docker run --rm "''${net_args[@]}" -v "$elf_dir:/app:ro" "$image" \
        speculos "/app/$elf_name" "$@"
    elif command -v podman >/dev/null 2>&1; then
      exec podman run --rm "''${net_args[@]}" -v "$elf_dir:/app:ro,Z" "$image" \
        speculos "/app/$elf_name" "$@"
    else
      echo "Neither docker nor podman is available for Speculos" >&2
      exit 1
    fi
  '';
}

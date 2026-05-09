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

    image="''${SPECULOS_CONTAINER_IMAGE:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest}"
    elf_dir="$(cd "$(dirname "$elf")" && pwd)"
    elf_name="$(basename "$elf")"

    if command -v docker >/dev/null 2>&1; then
      exec docker run --rm --network host -v "$elf_dir:/app:ro" "$image" \
        speculos "/app/$elf_name" "$@"
    elif command -v podman >/dev/null 2>&1; then
      exec podman run --rm --network host -v "$elf_dir:/app:ro,Z" "$image" \
        speculos "/app/$elf_name" "$@"
    else
      echo "Neither docker nor podman is available for Speculos" >&2
      exit 1
    fi
  '';
}

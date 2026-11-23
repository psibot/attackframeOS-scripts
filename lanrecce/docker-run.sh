#!/usr/bin/env bash
# docker-run.sh -- run lanrecce in Docker with the right networking.
#
#   ./docker-run.sh build                       # build the image
#   ./docker-run.sh scan --auto                 # any lanrecce command
#   ./docker-run.sh scan 192.168.1.0/24 -p quick
#   ./docker-run.sh update-templates            # refresh nuclei templates in the cache volume
#
# Results land in ./runs (owned by you, not root). The KEV/EPSS cache lives in
# the `lanrecce-cache` volume so it survives between runs.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${LANRECCE_IMAGE:-lanrecce:latest}"

if [[ "${1:-}" == "build" ]]; then
  shift
  exec docker build -t "$IMAGE" "$@" "$HERE"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[!] Docker on $(uname -s) runs in a VM: --network host can't reach your LAN" \
       "at layer 2 (no ARP). Results will be incomplete; prefer the native install." >&2
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[*] image $IMAGE not found, building it first" >&2
  docker build -t "$IMAGE" "$HERE"
fi

mkdir -p "$PWD/runs"
tty=(); [[ -t 0 && -t 1 ]] && tty=(-it)

if [[ "${1:-}" == "update-templates" ]]; then
  exec docker run --rm "${tty[@]}" -v lanrecce-templates:/root/nuclei-templates \
       --entrypoint nuclei "$IMAGE" -update-templates
fi

exec docker run --rm "${tty[@]}" \
  --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -e LANRECCE_CHOWN="$(id -u):$(id -g)" \
  -v "$PWD/runs:/data/runs" \
  -v lanrecce-cache:/root/.cache \
  -v lanrecce-templates:/root/nuclei-templates \
  "$IMAGE" "$@"

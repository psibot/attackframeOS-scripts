#!/usr/bin/env bash
# Convenience launcher: ./lanrecce.sh scan --auto
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec env PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}" python3 -m lanrecce "$@"

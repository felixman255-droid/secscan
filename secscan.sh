#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$HERE/.venv/Scripts/python.exe"
[ -x "$PY" ] || PY="$HERE/.venv/bin/python"
exec "$PY" "$HERE/secscan.py" "$@"

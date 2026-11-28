#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$HERE/.venv/Scripts/python.exe"
[ -x "$PY" ] || PY="$HERE/.venv/bin/python"
# plugin instalado: o venv fica na pasta de dados; o secscan.py so usa a stdlib
[ -x "$PY" ] || PY="$(command -v python3 || command -v python)"
exec "$PY" -B "$HERE/secscan.py" "$@"

#!/usr/bin/env bash
# install.sh - baixa os binarios e cria o venv com semgrep (Linux / macOS)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/bin"
mkdir -p "$BIN"

case "$(uname -s)" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) echo "sistema nao suportado: $(uname -s)"; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64)  A=amd64 ;;
  arm64|aarch64) A=arm64 ;;
  *) echo "arquitetura nao suportada: $(uname -m)"; exit 1 ;;
esac

# versoes fixas: o secscan.py depende do formato JSON destas ferramentas.
# trocar de versao exige revalidar o parsing (python -m unittest discover -s tests).
GL_VER=8.30.1
OSV_VER=2.7.1
GL_ARCH=$([ "$A" = "amd64" ] && echo "x64" || echo "arm64")

echo "> gitleaks $GL_VER ($OS/$GL_ARCH)"
TMP="$(mktemp -d)"
curl -sL -o "$TMP/gl.tar.gz" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_${OS}_${GL_ARCH}.tar.gz"
tar -xzf "$TMP/gl.tar.gz" -C "$TMP" gitleaks
mv -f "$TMP/gitleaks" "$BIN/gitleaks"
chmod +x "$BIN/gitleaks"
rm -rf "$TMP"

echo "> osv-scanner $OSV_VER ($OS/$A)"
curl -sL -o "$BIN/osv-scanner" \
  "https://github.com/google/osv-scanner/releases/download/v${OSV_VER}/osv-scanner_${OS}_${A}"
chmod +x "$BIN/osv-scanner"

echo "> semgrep (venv isolado)"
python3 -m venv "$HERE/.venv"
"$HERE/.venv/bin/python" -m pip install --quiet --upgrade pip
"$HERE/.venv/bin/python" -m pip install --quiet semgrep

chmod +x "$HERE/secscan.sh"
echo ""
echo "Instalado em: $HERE"
"$BIN/gitleaks" version
"$BIN/osv-scanner" --version | head -1
"$HERE/.venv/bin/semgrep" --version

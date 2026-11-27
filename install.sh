#!/usr/bin/env bash
# install.sh - baixa os binarios (com verificacao SHA-256) e cria o venv com semgrep
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

# Versoes fixas: o secscan.py depende do formato JSON destas ferramentas.
# Os hashes abaixo vem dos arquivos de checksum oficiais de cada release.
# Trocar de versao exige revalidar o parsing: python -m unittest discover -s tests
GL_VER=8.30.1
OSV_VER=2.7.1
GL_ARCH=$([ "$A" = "amd64" ] && echo "x64" || echo "arm64")

case "$OS/$A" in
  linux/amd64)
    GL_SHA=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
    OSV_SHA=fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8 ;;
  linux/arm64)
    GL_SHA=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
    OSV_SHA=983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81 ;;
  darwin/amd64)
    GL_SHA=dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709
    OSV_SHA=b8420d5485ba792626315f1bf9a5a2046e971d38eea75bf9090c38852dbc3b1b ;;
  darwin/arm64)
    GL_SHA=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5
    OSV_SHA=b22c02877a811c8f78956e8643efa554932b7378f590d13f8e97d4e9448a29f3 ;;
  *) echo "sem hash fixado para $OS/$A"; exit 1 ;;
esac

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

verify() {
  local file="$1" expected="$2" label="$3" actual
  actual="$(sha_of "$file")"
  if [ "$actual" != "$expected" ]; then
    {
      echo "ERRO: $label - checksum nao confere"
      echo "  esperado: $expected"
      echo "  obtido:   $actual"
      echo "Binario descartado. Verifique a conexao ou se a release foi alterada."
    } >&2
    rm -f "$file"
    exit 1
  fi
  echo "  sha256 ok"
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "> gitleaks $GL_VER ($OS/$GL_ARCH)"
curl -sL -o "$TMP/gl.tar.gz" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_${OS}_${GL_ARCH}.tar.gz"
verify "$TMP/gl.tar.gz" "$GL_SHA" "gitleaks"
tar -xzf "$TMP/gl.tar.gz" -C "$TMP" gitleaks
mv -f "$TMP/gitleaks" "$BIN/gitleaks"
chmod +x "$BIN/gitleaks"

echo "> osv-scanner $OSV_VER ($OS/$A)"
curl -sL -o "$BIN/osv-scanner" \
  "https://github.com/google/osv-scanner/releases/download/v${OSV_VER}/osv-scanner_${OS}_${A}"
verify "$BIN/osv-scanner" "$OSV_SHA" "osv-scanner"
chmod +x "$BIN/osv-scanner"

echo "> semgrep (venv isolado)"
python3 -m venv "$HERE/.venv"
"$HERE/.venv/bin/python" -m pip install --quiet --upgrade pip
"$HERE/.venv/bin/python" -m pip install --quiet semgrep

echo "> pre-cache dos rulesets (permite rodar offline depois)"
for pack in p/default p/nodejs p/python p/golang p/java p/ruby p/php p/rust p/csharp; do
  if "$HERE/.venv/bin/semgrep" scan --config "$pack" --validate >/dev/null 2>&1; then
    echo "  $pack"
  else
    echo "  aviso: $pack nao pode ser baixado agora (sera buscado na primeira execucao)" >&2
  fi
done

chmod +x "$HERE/secscan.sh"
echo ""
echo "Instalado em: $HERE"
"$BIN/gitleaks" version
"$BIN/osv-scanner" --version | head -1
"$HERE/.venv/bin/semgrep" --version

# install.ps1 - baixa os binarios e cria o venv com semgrep
# Uso: powershell -ExecutionPolicy Bypass -File install.ps1
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$bin  = Join-Path $here "bin"
$tmp  = Join-Path $env:TEMP ("secscan-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $bin, $tmp | Out-Null

$arm = $env:PROCESSOR_ARCHITECTURE -eq "ARM64"
$glArch = if ($arm) { "arm64" } else { "x64" }
$osvArch = if ($arm) { "arm64" } else { "amd64" }
# versoes fixas: o secscan.py depende do formato JSON destas ferramentas.
# trocar de versao exige revalidar o parsing (python -m unittest discover -s tests).
$glVer = "8.30.1"
$osvVer = "2.7.1"

Write-Host "> gitleaks $glVer ($glArch)"
$glZip = Join-Path $tmp "gitleaks.zip"
Invoke-WebRequest -UseBasicParsing -OutFile $glZip `
  "https://github.com/gitleaks/gitleaks/releases/download/v$glVer/gitleaks_${glVer}_windows_${glArch}.zip"
Expand-Archive -Path $glZip -DestinationPath $tmp -Force
Move-Item -Force (Join-Path $tmp "gitleaks.exe") (Join-Path $bin "gitleaks.exe")

Write-Host "> osv-scanner $osvVer ($osvArch)"
Invoke-WebRequest -UseBasicParsing -OutFile (Join-Path $bin "osv-scanner.exe") `
  "https://github.com/google/osv-scanner/releases/download/v$osvVer/osv-scanner_windows_${osvArch}.exe"

Write-Host "> semgrep (venv isolado)"
& python -m venv (Join-Path $here ".venv")
$py = Join-Path $here ".venv\Scripts\python.exe"
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet semgrep

Remove-Item -Recurse -Force $tmp

Write-Host ""
Write-Host "Instalado em: $here"
& (Join-Path $bin "gitleaks.exe") version
& (Join-Path $bin "osv-scanner.exe") --version | Select-Object -First 1
& (Join-Path $here ".venv\Scripts\semgrep.exe") --version

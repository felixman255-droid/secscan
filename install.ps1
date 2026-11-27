# install.ps1 - baixa os binarios (com verificacao SHA-256) e cria o venv com semgrep
# Uso: powershell -ExecutionPolicy Bypass -File install.ps1
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$bin  = Join-Path $here "bin"
$tmp  = Join-Path $env:TEMP ("secscan-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $bin, $tmp | Out-Null

$arm = $env:PROCESSOR_ARCHITECTURE -eq "ARM64"
$glArch  = if ($arm) { "arm64" } else { "x64" }
$osvArch = if ($arm) { "arm64" } else { "amd64" }

# Versoes fixas: o secscan.py depende do formato JSON destas ferramentas.
# Os hashes abaixo vem dos arquivos de checksum oficiais de cada release.
# Trocar de versao exige revalidar o parsing: python -m unittest discover -s tests
$glVer  = "8.30.1"
$osvVer = "2.7.1"

$glSha = @{
  "x64"   = "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"
  "arm64" = "b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f"
}
$osvSha = @{
  "amd64" = "7121dcf420aefbbf89a7f0050c4d3094e079ff93afd334dfc96f16b02ec85800"
  "arm64" = "5f3998b55c9268f8468502bbcb60645038fd5b145ee5e685e6ae2a32e923afc7"
}

function Assert-Hash($path, $expected, $label) {
  $actual = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $expected) {
    $msg = "$label : checksum nao confere.`n  esperado: $expected`n  obtido:   $actual`n" +
           "Binario descartado. Verifique a conexao ou se a release foi alterada."
    throw $msg
  }
  Write-Host "  sha256 ok"
}

Write-Host "> gitleaks $glVer ($glArch)"
$glZip = Join-Path $tmp "gitleaks.zip"
Invoke-WebRequest -UseBasicParsing -OutFile $glZip `
  "https://github.com/gitleaks/gitleaks/releases/download/v$glVer/gitleaks_${glVer}_windows_${glArch}.zip"
Assert-Hash $glZip $glSha[$glArch] "gitleaks"
Expand-Archive -Path $glZip -DestinationPath $tmp -Force
Move-Item -Force (Join-Path $tmp "gitleaks.exe") (Join-Path $bin "gitleaks.exe")

Write-Host "> osv-scanner $osvVer ($osvArch)"
$osvPath = Join-Path $bin "osv-scanner.exe"
Invoke-WebRequest -UseBasicParsing -OutFile $osvPath `
  "https://github.com/google/osv-scanner/releases/download/v$osvVer/osv-scanner_windows_${osvArch}.exe"
Assert-Hash $osvPath $osvSha[$osvArch] "osv-scanner"

Write-Host "> semgrep (venv isolado)"
& python -m venv (Join-Path $here ".venv")
$py = Join-Path $here ".venv\Scripts\python.exe"
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet semgrep
$semgrep = Join-Path $here ".venv\Scripts\semgrep.exe"

Write-Host "> pre-cache dos rulesets (permite rodar offline depois)"
foreach ($pack in @("p/default", "p/nodejs", "p/python", "p/golang",
                    "p/java", "p/ruby", "p/php", "p/rust", "p/csharp")) {
  & $semgrep scan --config $pack --validate *> $null
  if ($LASTEXITCODE -eq 0) { Write-Host "  $pack" }
  else { Write-Warning "  $pack nao pode ser baixado agora (sera buscado na primeira execucao)" }
}

Remove-Item -Recurse -Force $tmp

Write-Host ""
Write-Host "Instalado em: $here"
& (Join-Path $bin "gitleaks.exe") version
& (Join-Path $bin "osv-scanner.exe") --version | Select-Object -First 1
& $semgrep --version

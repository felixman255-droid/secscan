"""O passo de rulesets do install.ps1 no Windows PowerShell 5.1.

Com `$ErrorActionPreference = "Stop"`, redirecionar o stderr de um programa
nativo transforma a primeira linha em erro fatal. O semgrep escreve a mensagem
de SUCESSO no stderr, e o instalador morria depois de baixar tudo.
O teste roda o trecho real do script com um semgrep falso.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def _trecho():
    texto = (RAIZ / "install.ps1").read_text(encoding="utf-8")
    ini = texto.index('Write-Host "> pre-cache dos rulesets')
    return texto[ini:texto.index("# O bundle de checks do trivy", ini)]


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell"), "so no Windows PowerShell")
class TestPrecacheRulesets(unittest.TestCase):
    def _roda(self, rc):
        with tempfile.TemporaryDirectory() as td:
            falso = Path(td) / "semgrep.cmd"
            falso.write_text(f"@echo Configuration is valid 1>&2\r\n@exit /b {rc}\r\n", encoding="ascii")
            script = Path(td) / "t.ps1"
            script.write_text(f'$ErrorActionPreference = "Stop"\n$semgrep = "{falso}"\n{_trecho()}\n'
                              'Write-Host "CHEGOU-AO-FIM $ErrorActionPreference"\n', encoding="utf-8-sig")
            return subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                                  capture_output=True, text=True, errors="replace", timeout=180)

    def test_success_message_on_stderr_is_not_fatal(self):
        r = self._roda(0)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        self.assertIn("p/default", r.stdout)
        self.assertIn("p/csharp", r.stdout)
        # o modo estrito volta depois do passo
        self.assertIn("CHEGOU-AO-FIM Stop", r.stdout)

    def test_real_failure_warns_and_continues(self):
        r = self._roda(1)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        self.assertIn("nao pode ser baixado", r.stdout)
        self.assertIn("CHEGOU-AO-FIM Stop", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)

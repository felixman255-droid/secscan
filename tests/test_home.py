"""Onde ficam as ferramentas quando o secscan roda como plugin instalado.

A pasta de um plugin muda a cada versao; `bin/`, `.venv/` e `cache/` ficam na
pasta de dados do plugin, que sobrevive. Num clone comum nada muda.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
import secscan as s  # noqa: E402


def _plugin(td, mk="secscan", nome="secscan", versao="1.1.0", manifesto=True):
    base = Path(td).resolve() / "plugins" / "cache" / mk / nome / versao
    base.mkdir(parents=True)
    if manifesto:
        (base / ".claude-plugin").mkdir()
        (base / ".claude-plugin" / "plugin.json").write_text('{"name":"secscan"}', encoding="utf-8")
    return base


class TestDataHome(unittest.TestCase):
    def test_installed_plugin_uses_persistent_data_dir(self):
        with tempfile.TemporaryDirectory() as td:
            base = _plugin(td)
            esperado = Path(td).resolve() / "plugins" / "data" / "secscan-secscan"
            self.assertEqual(s.data_home(base), esperado)

    def test_same_dir_for_every_version(self):
        with tempfile.TemporaryDirectory() as td:
            a, b = _plugin(td, versao="1.1.0"), _plugin(td, versao="2.0.0")
            self.assertEqual(s.data_home(a), s.data_home(b))

    def test_id_is_sanitized_like_claude_code(self):
        with tempfile.TemporaryDirectory() as td:
            base = _plugin(td, mk="meu.mk")
            self.assertEqual(s.data_home(base).name, "secscan-meu-mk")

    def test_clone_keeps_everything_in_its_own_folder(self):
        with tempfile.TemporaryDirectory() as td:
            clone = Path(td) / "skills" / "secscan"
            clone.mkdir(parents=True)
            self.assertEqual(s.data_home(clone), clone)
            sem_manifesto = _plugin(td, manifesto=False)
            self.assertEqual(s.data_home(sem_manifesto), sem_manifesto)


class TestResolveOut(unittest.TestCase):
    def test_report_inside_versioned_folder_moves_to_data(self):
        base, home = Path("/p/cache/m/n/1"), Path("/p/data/n-m")
        self.assertEqual(s.resolve_out(base / "security-report", base, home), home / "security-report")

    def test_report_elsewhere_is_untouched(self):
        base, home = Path("/p/cache/m/n/1"), Path("/p/data/n-m")
        self.assertEqual(s.resolve_out(Path("/x/rel"), base, home), Path("/x/rel"))
        self.assertEqual(s.resolve_out(base / "r", base, base), base / "r")


class TestWrappers(unittest.TestCase):
    """Sem `.venv` ao lado (caso do plugin), o atalho usa o Python do sistema."""

    def _home(self, cmd):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        return Path(r.stdout.strip())

    def _instala(self, td):
        base = _plugin(td)
        for nome in ("secscan.py", "secscan.cmd", "secscan.sh"):
            shutil.copy2(RAIZ / nome, base / nome)
        return base, Path(td).resolve() / "plugins" / "data" / "secscan-secscan"

    def test_home_flag_from_plugin_layout(self):
        with tempfile.TemporaryDirectory() as td:
            base, home = self._instala(td)
            self.assertEqual(self._home([sys.executable, "-B", str(base / "secscan.py"), "--home"]), home)

    @unittest.skipUnless(os.name == "nt", "atalho do Windows")
    def test_cmd_wrapper(self):
        with tempfile.TemporaryDirectory() as td:
            base, home = self._instala(td)
            self.assertEqual(self._home(["cmd", "/c", str(base / "secscan.cmd"), "--home"]), home)

    @unittest.skipIf(os.name == "nt", "atalho POSIX")
    def test_sh_wrapper(self):
        with tempfile.TemporaryDirectory() as td:
            base, home = self._instala(td)
            self.assertEqual(self._home(["bash", str(base / "secscan.sh"), "--home"]), home)


if __name__ == "__main__":
    unittest.main(verbosity=2)

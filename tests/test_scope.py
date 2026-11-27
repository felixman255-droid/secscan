"""Exclusoes por camada: o que cada ferramenta pode e nao pode ignorar.

Os testes de integracao chamam os binarios de verdade de proposito: o defeito
que eles guardam era a diferenca entre o texto que a ferramenta compara com o
padrao e o texto que o codigo supunha. Um teste so com `re` nao ve isso.
Sao pulados quando o binario nao esta instalado (caso do job de testes no CI).
"""
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secscan as s  # noqa: E402

DEVE_VER = [
    "app.py", ".github/workflows/ci.yml", ".gitlab-ci.yml", "buildspec.yml",
    "cloudbuild.yaml", "src/objects/cfg.py", "src/target_env.py",
    "src/rebuild.py", "src/distance.py", "tests/x.py", "build", "dist.py",
]
DEVE_IGNORAR = [
    "build/x.py", "a/b/dist/x.py", "node_modules/p/i.js", ".git/config",
    "apps/web/__pycache__/x.pyc", "obj/Debug/x.cs",
]


def _token():
    # sintetico, gerado na hora: nao grava no repositorio nada com cara de segredo
    return "ghp_" + "".join(random.choices(string.ascii_letters + string.digits, k=36))


def _grava(raiz, rel, texto=None):
    p = raiz / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(texto or f'github_token = "{_token()}"\n', encoding="utf-8")


def _git(raiz, *args):
    subprocess.run(["git", "-C", str(raiz), "-c", "user.email=t@t.test",
                    "-c", "user.name=t", *args], check=True, capture_output=True)


class TestSkipPattern(unittest.TestCase):
    def test_matches_only_whole_directory_segments(self):
        rx = re.compile(s.skip_pattern())
        for p in DEVE_VER:
            for v in (p, p.replace("/", "\\")):
                self.assertIsNone(rx.search(v), f"ignorou indevidamente: {v}")
        for p in DEVE_IGNORAR:
            for v in (p, p.replace("/", "\\")):
                self.assertIsNotNone(rx.search(v), f"deveria ignorar: {v}")

    def test_prefix_is_never_matched_as_a_skip_dir(self):
        rx = re.compile(s.skip_pattern("build/meu app (1)/"))
        self.assertIsNone(rx.search("build/meu app (1)/app.py"))
        self.assertIsNotNone(rx.search("build/meu app (1)/dist/x.py"))

    def test_prefix_escaping_is_accepted_by_go_regex(self):
        # RE2 rejeita `\ `, que e o que re.escape produz para espaco
        self.assertNotIn("\\ ", s.skip_pattern("meu projeto/"))


class TestCommands(unittest.TestCase):
    def test_gitleaks_runs_inside_the_target(self):
        with tempfile.TemporaryDirectory() as td:
            cmd, cwd = s.gitleaks_cmd(Path(td), "dir", "c.toml", "r.json", False)
        self.assertEqual(cwd, Path(td))
        self.assertEqual(cmd[2], ".")

    def test_gitleaks_single_file_target(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "a.py"
            f.write_text("x", encoding="utf-8")
            cmd, cwd = s.gitleaks_cmd(f, "dir", "c.toml", "r.json", False)
        self.assertEqual((cwd, cmd[2]), (Path(td), "a.py"))

    def test_osv_excludes_the_directory_itself(self):
        cmd = [str(c) for c in s.osv_cmd(Path("/x/proj"), Path("/o/osv.json"))]
        self.assertIn("g:**/dist", cmd)
        self.assertNotIn("g:**/dist/**", cmd)

    def test_osv_does_not_exclude_the_target_name(self):
        cmd = [str(c) for c in s.osv_cmd(Path("/x/build"), Path("/o/osv.json"))]
        self.assertNotIn("g:**/build", cmd)
        self.assertIn("g:**/dist", cmd)


class TestScopeSection(unittest.TestCase):
    def _md(self, **extra):
        meta = {"target": "/p/proj", "name": "proj", "when": "x", "tools": [],
                "excluded": [], **extra}
        with tempfile.TemporaryDirectory() as td:
            s.write_markdown([], [], meta, {}, Path(td))
            md = (Path(td) / "relatorio.md").read_text(encoding="utf-8")
        return md.split("## Escopo", 1)[1].split("\n## ", 1)[0]

    def _linha(self, md, camada):
        return next(x for x in md.splitlines() if x.startswith(f"| {camada} "))

    def test_each_layer_lists_its_own_exclusions(self):
        md = self._md()
        for camada in ("gitleaks", "trivy", "osv-scanner"):
            for d in s.SKIP_DIRS:
                self.assertIn(f"`{d}`", self._linha(md, camada))
        sg = self._linha(md, "semgrep")
        for d in s.SEMGREP_EXCLUDES:
            self.assertIn(f"`{d}`", sg)
        self.assertNotIn("`__pycache__`", sg)
        self.assertIn("`tests/`", sg)
        self.assertIn("lockfile", self._linha(md, "osv-scanner"))

    def test_follows_the_constants(self):
        original = s.SEMGREP_EXCLUDES
        s.SEMGREP_EXCLUDES = ("pasta-inventada",)
        try:
            self.assertIn("`pasta-inventada`", self._linha(self._md(), "semgrep"))
        finally:
            s.SEMGREP_EXCLUDES = original

    def test_history_state(self):
        self.assertIn("nao lido", self._linha(self._md(), "gitleaks"))
        self.assertNotIn("nao lido", self._linha(self._md(history=True), "gitleaks"))

    def test_semgrepignore_in_target_is_declared(self):
        self.assertIn(".semgrepignore", self._md(semgrepignore=True))

    def test_target_named_like_skip_dir_is_declared_for_osv(self):
        md = self._md(target="/p/build", name="build")
        self.assertIn("nao excluida", self._linha(md, "osv-scanner"))


@unittest.skipUnless(s.GITLEAKS.exists(), "gitleaks nao instalado")
class TestGitleaksIntegration(unittest.TestCase):
    ARQUIVOS = ["app.py", ".github/workflows/ci.yml", "buildspec.yml",
                "src/objects/cfg.py", "src/distance.py", "build/x.py", "a/dist/x.py"]
    ESPERADO = {"app.py", ".github/workflows/ci.yml", "buildspec.yml",
                "src/objects/cfg.py", "src/distance.py"}

    def _scan(self, alvo, out, history=False):
        out.mkdir(exist_ok=True)
        found, status, msg, _ = s.scan_secrets(alvo, out, history, False, False)
        self.assertEqual(status, s.STATUS_OK, msg)
        return {f["path"] for f in s.normalize_paths(found, alvo)}

    def test_parent_or_target_named_like_skip_dir(self):
        for nome in ("neutro/proj", "build/meu projeto", "node_modules/proj",
                     "objetos-teste/proj", "neutro/build"):
            with self.subTest(nome), tempfile.TemporaryDirectory() as td:
                alvo = Path(td) / nome
                for rel in self.ARQUIVOS:
                    _grava(alvo, rel)
                self.assertEqual(self._scan(alvo, Path(td) / "out"), self.ESPERADO)

    def test_history_from_repository_subfolder(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            alvo = repo / "build" / "meu app"
            _grava(alvo, "removido.py")
            _grava(alvo, "dist/x.py")
            _git(repo, "init", "-q")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", "a")
            (alvo / "removido.py").unlink()   # agora so existe no historico
            _git(repo, "commit", "-qam", "b")
            achados = self._scan(alvo, Path(td) / "out", history=True)
        self.assertIn("build/meu app/removido.py", achados)
        self.assertNotIn("build/meu app/dist/x.py", achados)


@unittest.skipUnless(s.OSV.exists(), "osv-scanner nao instalado")
class TestOsvIntegration(unittest.TestCase):
    def test_parent_or_target_named_like_skip_dir(self):
        for nome in ("neutro/proj", "build/proj", "neutro/build"):
            with self.subTest(nome), tempfile.TemporaryDirectory() as td:
                alvo, out = Path(td) / nome, Path(td) / "out"
                out.mkdir()
                for rel in ("requirements.txt", "apps/web/dist/requirements.txt"):
                    _grava(alvo, rel, "pyyaml==5.1\n")
                found, status, msg, _ = s.scan_deps(alvo, out, False)
                self.assertEqual(status, s.STATUS_OK, msg)
                paths = {f["path"] for f in s.normalize_paths(found, alvo)}
                self.assertEqual(paths, {"requirements.txt"})


@unittest.skipUnless(s.SEMGREP.exists(), "semgrep nao instalado")
class TestSemgrepIntegration(unittest.TestCase):
    def test_target_named_like_skip_dir(self):
        for nome in ("neutro/build", "dist/proj", "tests/proj"):
            with self.subTest(nome), tempfile.TemporaryDirectory() as td:
                alvo, out = Path(td) / nome, Path(td) / "out"
                out.mkdir()
                _grava(alvo, "app.py", "ISCA(1)\n")
                regra = Path(td) / "isca.yml"
                regra.write_text("rules:\n- id: isca\n  languages: [python]\n"
                                 "  severity: ERROR\n  message: isca\n"
                                 "  pattern: ISCA(...)\n", encoding="utf-8")
                found, status, msg, _ = s.scan_code(alvo, out, [str(regra)], False)
                self.assertEqual((status, len(found)), (s.STATUS_OK, 1), msg)


@unittest.skipUnless(s.TRIVY.exists(), "trivy nao instalado")
class TestTrivyIntegration(unittest.TestCase):
    def test_target_named_like_skip_dir(self):
        for nome in ("neutro/build", "dist/proj"):
            with self.subTest(nome), tempfile.TemporaryDirectory() as td:
                alvo, out = Path(td) / nome, Path(td) / "out"
                out.mkdir()
                _grava(alvo, "Dockerfile", "FROM alpine:latest\nUSER root\n")
                found, status, msg, _ = s.scan_iac(alvo, out, False)
                self.assertEqual(status, s.STATUS_OK, msg)
                self.assertTrue(found, "trivy nao viu o Dockerfile")


if __name__ == "__main__":
    unittest.main(verbosity=2)

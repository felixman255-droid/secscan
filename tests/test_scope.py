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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import secscan as s  # noqa: E402

DEVE_VER = [
    "app.py", ".github/workflows/ci.yml", ".gitlab-ci.yml", "buildspec.yml",
    "cloudbuild.yaml", "src/objects/cfg.py", "src/target_env.py",
    "src/rebuild.py", "src/distance.py", "tests/x.py", "build", "dist.py",
    ".nextrc/x", ".next-notas.py",
]
DEVE_IGNORAR = [
    "build/x.py", "a/b/dist/x.py", "node_modules/p/i.js", ".git/config",
    "apps/web/__pycache__/x.pyc", "obj/Debug/x.cs",
    ".next-audit/server/x.js", "a/.next-verify-1/cache/x",
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


class TestSkipWildcard(unittest.TestCase):
    def test_is_skipped_dir(self):
        for nome in (".next", ".next-audit", "dist"):
            self.assertTrue(s.is_skipped_dir(nome), nome)
        for nome in (".nextrc", "distance", "next-app"):
            self.assertFalse(s.is_skipped_dir(nome), nome)

    def test_osv_keeps_target_that_matches_wildcard(self):
        cmd = [str(c) for c in s.osv_cmd(Path("/x/.next-old"), Path("/o/osv.json"))]
        self.assertNotIn("g:**/.next-*", cmd)
        self.assertIn("g:**/.next", cmd)


class TestSemgrepAbort(unittest.TestCase):
    """Sem JSON gravado, o motivo e o processo, nao o parser."""

    def _scan(self, rc, saida, conteudo):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)

            def falso(cmd, label, timeout=1800, stream=False, cwd=None):
                if conteudo is not None:
                    (out / "semgrep.json").write_text(conteudo, encoding="utf-8")
                return rc, saida, 12.0

            with mock.patch.object(s, "run", falso), mock.patch.object(s, "SEMGREP", out):
                return s.scan_code(out, out, ["p/default"], False)

    def test_empty_report_after_timeout(self):
        for conteudo in ("", None):
            _, status, msg, _ = self._scan(124, "semgrep: timeout de 1800s", conteudo)
            self.assertEqual(status, s.STATUS_FAIL)
            self.assertIn("rc=124", msg)
            self.assertIn("timeout de 1800s", msg)
            self.assertNotIn("results", msg)

    def test_keeps_the_end_of_long_output(self):
        _, _, msg, _ = self._scan(2, ("linha" + chr(10)) * 500 + "MemoryError no fim", "")
        self.assertIn("MemoryError no fim", msg)
        self.assertIn("rc=2", msg)


class TestBaselineIdentity(unittest.TestCase):
    """Aceitar um achado nao pode passar a aceitacao para outro."""

    def _gl(self, *matches):
        data = [{"RuleID": "generic-api-key", "File": ".env", "StartLine": i + 1,
                 "Match": m, "Secret": "REDACTED"} for i, m in enumerate(matches)]
        return s.assign_fingerprints(s.parse_gitleaks(data))

    def test_secret_keeps_identity_when_neighbours_change(self):
        antes = self._gl("PUBLICA=REDACTED", "SECRETA=REDACTED", "SENHA=REDACTED")
        depois = self._gl("PUBLICA=REDACTED", "SENHA=REDACTED")
        self.assertEqual(depois[1]["fp"], antes[2]["fp"])
        self.assertNotEqual(depois[1]["fp"], antes[1]["fp"])

    def test_same_identity_redacted_or_revealed(self):
        base = {"RuleID": "r", "File": "a", "StartLine": 1}
        a = s.parse_gitleaks([dict(base, Match="K=REDACTED", Secret="REDACTED")])
        b = s.parse_gitleaks([dict(base, Match="K=valor-qualquer", Secret="valor-qualquer")])
        self.assertEqual(a[0]["snippet"], b[0]["snippet"])

    def test_change_far_into_a_long_line_changes_identity(self):
        a, b = ("x" * 500 + fim for fim in ("seguro()", "perigoso()"))
        self.assertNotEqual(s._snippet(a), s._snippet(b))

    def test_semgrep_without_login_reads_the_code(self):
        with tempfile.TemporaryDirectory() as td:
            alvo = Path(td) / "a.js"
            alvo.write_text("um(x)\ndois(y)\n", encoding="utf-8")
            data = {"results": [{"check_id": "r", "path": str(alvo),
                                 "start": {"line": n}, "end": {"line": n},
                                 "extra": {"lines": "requires login"}} for n in (1, 2)]}
            found = s.fill_snippets(s.parse_semgrep(data))
        self.assertEqual([f["snippet"] for f in found], ["um(x)", "dois(y)"])


class TestSemgrepSkipsNextBuilds(unittest.TestCase):
    def test_command_and_report(self):
        cmd = [str(c) for c in s.semgrep_cmd("/p", Path("/o/s.json"), [])]
        for d in (".next", ".next-*"):
            self.assertIn(d, cmd)
            self.assertIn(d, s.SEMGREP_EXCLUDES)

    @unittest.skipUnless(s.SEMGREP.exists(), "semgrep nao instalado")
    def test_real_run(self):
        with tempfile.TemporaryDirectory() as td:
            alvo, out = Path(td) / "proj", Path(td) / "out"
            out.mkdir()
            for rel in ("a.py", ".next/a.py", ".next-audit/a.py", "w/.next/a.py",
                        "w/.next-old/a.py", ".nextrc/a.py"):
                _grava(alvo, rel, "ISCA(1)\n")
            regra = Path(td) / "isca.yml"
            regra.write_text("rules:\n- id: isca\n  languages: [python]\n  severity: ERROR\n"
                             "  message: isca\n  pattern: ISCA(...)\n", encoding="utf-8")
            found, status, msg, _ = s.scan_code(alvo, out, [str(regra)], False)
            paths = {f["path"] for f in s.normalize_paths(found, alvo)}
        self.assertEqual(status, s.STATUS_OK, msg)
        self.assertEqual(paths, {"a.py", ".nextrc/a.py"})
        self.assertEqual({f["snippet"] for f in found}, {"ISCA(1)"})


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
                "src/objects/cfg.py", "src/distance.py", "build/x.py", "a/dist/x.py",
                ".next-audit/server/x.js"]
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
                for rel in ("requirements.txt", "apps/web/dist/requirements.txt",
                            ".next-old/requirements.txt"):
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

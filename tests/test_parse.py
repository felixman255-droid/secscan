"""Testes do nucleo do secscan. Rodar: python -m unittest discover -s tests"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import secscan as s  # noqa: E402


# ---------------------------------------------------------------- fixtures

GITLEAKS_OK = [{
    "RuleID": "aws-access-token",
    "Description": "Identified a pattern that may indicate AWS credentials",
    "File": "app.py",
    "StartLine": 5,
    "Secret": "REDACTED",
}]

OSV_OK = {"results": [{
    "source": {"path": "requirements.txt", "type": "lockfile"},
    "packages": [{
        "package": {"name": "pyyaml", "version": "5.1.0", "ecosystem": "PyPI"},
        "groups": [{"ids": ["PYSEC-2020-176", "GHSA-xxxx"],
                    "aliases": ["CVE-2020-1747"], "max_severity": "9.8"}],
    }],
}], "experimental_config": {}}

OSV_NO_GROUPS = {"results": [{
    "source": {"path": "requirements.txt", "type": "lockfile"},
    "packages": [{
        "package": {"name": "flask", "version": "1.0.0", "ecosystem": "PyPI"},
        "vulnerabilities": [{"id": "PYSEC-2023-62",
                             "database_specific": {"severity": "MODERATE"},
                             "summary": "Cookie parsing issue"}],
    }],
}]}

SEMGREP_OK = {"results": [{
    "check_id": "python.lang.security.audit.eval-detected",
    "path": "app.py",
    "start": {"line": 17},
    "extra": {"severity": "ERROR", "message": "Detected use of eval()"},
}], "errors": [], "paths": {}}


# ------------------------------------------------------------------ gitleaks

class TestGitleaks(unittest.TestCase):
    def test_valid(self):
        out = s.parse_gitleaks(GITLEAKS_OK)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["sev"], "CRÍTICA")
        self.assertEqual(out[0]["path"], "app.py")
        self.assertEqual(out[0]["line"], 5)
        self.assertEqual(out[0]["rule"], "aws-access-token")

    def test_empty_list_is_valid(self):
        self.assertEqual(s.parse_gitleaks([]), [])

    def test_schema_change_raises(self):
        with self.assertRaises(s.ScanError):
            s.parse_gitleaks({"findings": []})

    def test_item_not_object_raises(self):
        with self.assertRaises(s.ScanError):
            s.parse_gitleaks(["aws-access-token"])

    def test_missing_fields_do_not_crash(self):
        out = s.parse_gitleaks([{}])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["rule"], "unknown")


# ---------------------------------------------------------------------- osv

class TestOsv(unittest.TestCase):
    def test_valid_with_groups(self):
        out = s.parse_osv(OSV_OK)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["sev"], "CRÍTICA")   # 9.8 -> CRITICA
        self.assertEqual(out[0]["pkg"], "pyyaml 5.1.0")
        self.assertEqual(out[0]["rule"], "PYSEC-2020-176")

    def test_fallback_to_vulnerabilities_when_no_groups(self):
        out = s.parse_osv(OSV_NO_GROUPS)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["sev"], "MÉDIA")     # MODERATE
        self.assertEqual(out[0]["rule"], "PYSEC-2023-62")

    def test_empty_results_is_valid(self):
        self.assertEqual(s.parse_osv({"results": [], "experimental_config": {}}), [])

    def test_missing_results_key_raises(self):
        with self.assertRaises(s.ScanError):
            s.parse_osv({"vulnerabilities": []})

    def test_results_not_list_raises(self):
        with self.assertRaises(s.ScanError):
            s.parse_osv({"results": {"a": 1}})

    def test_toplevel_list_raises(self):
        with self.assertRaises(s.ScanError):
            s.parse_osv([])


# ----------------------------------------------------------------- semgrep

class TestSemgrep(unittest.TestCase):
    def test_valid(self):
        out = s.parse_semgrep(SEMGREP_OK)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["sev"], "ALTA")      # ERROR
        self.assertEqual(out[0]["line"], 17)

    def test_empty_results_is_valid(self):
        self.assertEqual(s.parse_semgrep({"results": [], "errors": []}), [])

    def test_missing_results_raises(self):
        with self.assertRaises(s.ScanError):
            s.parse_semgrep({"errors": []})

    def test_warning_maps_to_media(self):
        data = {"results": [{"check_id": "x", "path": "a.py",
                             "start": {"line": 1},
                             "extra": {"severity": "WARNING", "message": "m"}}]}
        self.assertEqual(s.parse_semgrep(data)[0]["sev"], "MÉDIA")


# --------------------------------------------------------------- severidade

class TestSeverity(unittest.TestCase):
    def test_cvss_bands(self):
        self.assertEqual(s.sev_from("9.8"), "CRÍTICA")
        self.assertEqual(s.sev_from("9.0"), "CRÍTICA")
        self.assertEqual(s.sev_from("8.9"), "ALTA")
        self.assertEqual(s.sev_from("7.0"), "ALTA")
        self.assertEqual(s.sev_from("6.9"), "MÉDIA")
        self.assertEqual(s.sev_from("4.0"), "MÉDIA")
        self.assertEqual(s.sev_from("3.9"), "BAIXA")
        self.assertEqual(s.sev_from("0.0"), "INFO")

    def test_text_labels(self):
        self.assertEqual(s.sev_from("HIGH"), "ALTA")
        self.assertEqual(s.sev_from("moderate"), "MÉDIA")
        self.assertEqual(s.sev_from("LOW"), "BAIXA")

    def test_invalid_falls_back(self):
        self.assertEqual(s.sev_from("desconhecido", fallback="BAIXA"), "BAIXA")
        self.assertEqual(s.sev_from(None, fallback="ALTA"), "ALTA")


# ----------------------------------------------------------------- caminhos

class TestPaths(unittest.TestCase):
    def test_strips_target_prefix(self):
        f = [{"path": "/repo/app.py", "tool": "t", "rule": "r"}]
        out = s.normalize_paths(f, Path("/repo"))
        self.assertEqual(out[0]["path"], "app.py")

    def test_backslashes_normalized(self):
        f = [{"path": "C:\\repo\\src\\app.py", "tool": "t", "rule": "r"}]
        out = s.normalize_paths(f, Path("C:/repo"))
        self.assertEqual(out[0]["path"], "src/app.py")

    def test_empty_becomes_dot(self):
        f = [{"path": "", "tool": "t", "rule": "r"}]
        self.assertEqual(s.normalize_paths(f, Path("/repo"))[0]["path"], ".")

    def test_sibling_directory_with_common_prefix_is_preserved(self):
        f = [{"path": "/repo2/app.py", "tool": "t", "rule": "r"}]
        out = s.normalize_paths(f, Path("/repo"))
        self.assertEqual(out[0]["path"], "/repo2/app.py")


# ------------------------------------------------------------------ dedupe

class TestDedupe(unittest.TestCase):
    def test_removes_same_finding_from_overlapping_configs(self):
        a = {"tool": "semgrep", "rule": "eval", "path": "a.py", "line": 3, "pkg": None}
        b = dict(a)
        self.assertEqual(len(s.dedupe([a, b])), 1)

    def test_keeps_different_lines(self):
        a = {"tool": "semgrep", "rule": "eval", "path": "a.py", "line": 3, "pkg": None}
        b = dict(a, line=9)
        self.assertEqual(len(s.dedupe([a, b])), 2)


# ------------------------------------------------------------- fingerprints

class TestFingerprint(unittest.TestCase):
    def _f(self, line=10):
        return {"tool": "semgrep", "rule": "eval", "path": "a.py", "line": line}

    def test_stable_across_line_shifts(self):
        a = s.fingerprint(self._f(10), 0)
        b = s.fingerprint(self._f(99), 0)
        self.assertEqual(a, b)

    def test_duplicates_get_distinct_fingerprints(self):
        fs = [self._f(10), self._f(20)]
        s.assign_fingerprints(fs)
        self.assertNotEqual(fs[0]["fp"], fs[1]["fp"])

    def test_different_rule_changes_fingerprint(self):
        a = s.fingerprint(self._f(), 0)
        b = s.fingerprint(dict(self._f(), rule="shell"), 0)
        self.assertNotEqual(a, b)


# ----------------------------------------------------------------- baseline

class TestBaseline(unittest.TestCase):
    def test_roundtrip(self):
        findings = [{"tool": "semgrep", "rule": "eval", "path": "a.py",
                     "line": 3, "sev": "ALTA", "title": "t", "pkg": None, "fp": "abc123"}]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".secscanignore"
            s.write_baseline(p, findings)
            self.assertEqual(s.load_baseline(p), {"abc123"})

    def test_missing_file_returns_empty(self):
        self.assertEqual(s.load_baseline(Path("/nao/existe/.secscanignore")), set())

    def test_ignores_comments(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".secscanignore"
            p.write_text("# comentario\nabc123  semgrep  eval  a.py\n", encoding="utf-8")
            self.assertEqual(s.load_baseline(p), {"abc123"})


# --------------------------------------------------------------------- sarif

class TestSarif(unittest.TestCase):
    def test_structure_is_valid_sarif(self):
        findings = [
            {"tool": "semgrep", "rule": "eval", "sev": "ALTA", "title": "eval",
             "path": "a.py", "line": 3, "pkg": None},
            {"tool": "gitleaks", "rule": "aws", "sev": "CRÍTICA", "title": "segredo",
             "path": "b.py", "line": 7, "pkg": None},
        ]
        doc = s.build_sarif(findings, {"target": ".", "name": "x", "when": "", "tools": []})
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("$schema", doc)
        self.assertEqual(len(doc["runs"]), 3)
        for run in doc["runs"]:
            self.assertIn("driver", run["tool"])
            self.assertIn("results", run)
        sem = [r for r in doc["runs"] if r["tool"]["driver"]["name"] == "semgrep"][0]
        self.assertEqual(sem["results"][0]["level"], "error")
        self.assertEqual(
            sem["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 3)

    def test_empty_findings_produce_empty_runs(self):
        doc = s.build_sarif([], {"target": ".", "name": "x", "when": "", "tools": []})
        self.assertTrue(all(r["results"] == [] for r in doc["runs"]))


# ------------------------------------------------------------ stack / rules

class TestStacks(unittest.TestCase):
    def test_detects_python_and_node(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "requirements.txt").write_text("flask\n", encoding="utf-8")
            (d / "package-lock.json").write_text("{}", encoding="utf-8")
            packs = s.detect_stacks(d)
            self.assertIn("p/python", packs)
            self.assertIn("p/nodejs", packs)

    def test_empty_project_returns_no_packs(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(s.detect_stacks(Path(td)), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

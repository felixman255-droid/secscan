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
    "extra": {"severity": "ERROR", "message": "Detected use of eval()",
              "lines": "    return eval(entrada)"},
}], "errors": [], "paths": {}}

OSV_WITH_FIX = {"results": [{
    "source": {"path": "package-lock.json", "type": "lockfile"},
    "packages": [{
        "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
        "groups": [{"ids": ["GHSA-1"], "max_severity": "9.1"}],
        "vulnerabilities": [{"id": "GHSA-1", "affected": [{
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        }]}],
    }],
}]}


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

    def test_extracts_fixed_version(self):
        out = s.parse_osv(OSV_WITH_FIX)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["fix"], "4.17.21")
        self.assertEqual(out[0]["sev"], "CRÍTICA")

    def test_fix_is_none_when_advisory_has_no_fixed_event(self):
        out = s.parse_osv(OSV_OK)
        self.assertIsNone(out[0]["fix"])

    def test_commit_hash_is_not_offered_as_fix_version(self):
        data = {"results": [{
            "source": {"path": "requirements.txt", "type": "lockfile"},
            "packages": [{
                "package": {"name": "flask", "version": "1.0.0", "ecosystem": "PyPI"},
                "groups": [{"ids": ["PYSEC-2023-62"], "max_severity": "7.5"}],
                "vulnerabilities": [{"id": "PYSEC-2023-62", "affected": [{
                    "ranges": [{"type": "GIT", "events": [
                        {"introduced": "0"},
                        {"fixed": "70f906c51ce49c485f1d355703e9cc3386b1cc2b"}]}],
                }]}],
            }],
        }]}
        self.assertIsNone(s.parse_osv(data)[0]["fix"])

    def _osv_git_range(self, fixed_value, rtype="GIT"):
        return {"results": [{
            "source": {"path": "requirements.txt", "type": "lockfile"},
            "packages": [{
                "package": {"name": "flask", "version": "1.0.0", "ecosystem": "PyPI"},
                "groups": [{"ids": ["PYSEC-2023-62"], "max_severity": "7.5"}],
                "vulnerabilities": [{"id": "PYSEC-2023-62", "affected": [{
                    "ranges": [{"type": rtype, "events": [
                        {"introduced": "0"},
                        {"fixed": fixed_value}]}],
                }]}],
            }],
        }]}

    def test_short_commit_hash_is_not_offered_as_fix_version(self):
        # hashes abreviados (7-12 chars) passam pelo regex de 40 hex
        out = s.parse_osv(self._osv_git_range("70f906c"))
        self.assertIsNone(out[0]["fix"])

    def test_git_tag_ref_is_not_offered_as_fix_version(self):
        out = s.parse_osv(self._osv_git_range("refs/tags/v2.0.0"))
        self.assertIsNone(out[0]["fix"])

    def test_git_range_is_skipped_but_semver_range_still_used(self):
        data = {"results": [{
            "source": {"path": "requirements.txt", "type": "lockfile"},
            "packages": [{
                "package": {"name": "flask", "version": "1.0.0", "ecosystem": "PyPI"},
                "groups": [{"ids": ["PYSEC-2023-62"], "max_severity": "7.5"}],
                "vulnerabilities": [{"id": "PYSEC-2023-62", "affected": [{
                    "ranges": [
                        {"type": "GIT", "events": [
                            {"introduced": "0"}, {"fixed": "70f906c"}]},
                        {"type": "ECOSYSTEM", "events": [
                            {"introduced": "0"}, {"fixed": "2.2.5"}]},
                    ],
                }]}],
            }],
        }]}
        self.assertEqual(s.parse_osv(data)[0]["fix"], "2.2.5")

    def test_ecosystem_range_still_yields_fix_version(self):
        out = s.parse_osv(self._osv_git_range("2.2.5", rtype="ECOSYSTEM"))
        self.assertEqual(out[0]["fix"], "2.2.5")


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


class TestRuleId(unittest.TestCase):
    """Id de regra local nao pode carregar o caminho absoluto: quebra o baseline."""

    def test_local_config_namespace_is_parent_dir(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "rule.yml"
            cfg.write_text("rules: []", encoding="utf-8")
            ns = s.rule_namespace(str(cfg))
            self.assertTrue(ns)
            for ch in (":", "\\", "/", " "):
                self.assertNotIn(ch, ns)

    def test_windows_path_with_space(self):
        ns = s.rule_namespace(r"C:\a b\rules\x.yml")
        self.assertTrue(ns.endswith("ab.rules"))
        self.assertNotIn(":", ns)
        self.assertNotIn("\\", ns)

    def test_registry_has_no_namespace(self):
        self.assertIsNone(s.rule_namespace("p/default"))
        self.assertEqual(s.strip_rule_prefix("python.lang.x.eval", ["p/default"]),
                         "python.lang.x.eval")

    def test_same_rule_in_different_dirs_gets_same_id(self):
        a = s.strip_rule_prefix(s.rule_namespace("/x/rule.yml") + ".eval-detected", ["/x/rule.yml"])
        b = s.strip_rule_prefix(s.rule_namespace("/y/rule.yml") + ".eval-detected", ["/y/rule.yml"])
        self.assertEqual(a, "eval-detected")
        self.assertEqual(b, "eval-detected")

    def test_parse_semgrep_applies_strip(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "regras.yml"
            cfg.write_text("rules: []", encoding="utf-8")
            ns = s.rule_namespace(str(cfg))
            data = {"results": [{"check_id": f"{ns}.test-eval", "path": "a.py",
                                 "start": {"line": 1},
                                 "extra": {"severity": "ERROR", "message": "m"}}]}
            out = s.parse_semgrep(data, [str(cfg)])
            self.assertEqual(out[0]["rule"], "test-eval")
            self.assertEqual(out[0]["detail"], "test-eval")


class TestSemgrepFailure(unittest.TestCase):
    """Config invalida deixa JSON vazio com rc=7 — nao pode virar 'ok'."""

    def test_invalid_config_rc7_is_failure(self):
        data = {"results": [], "paths": {"scanned": []},
                "errors": [{"message": "invalid configuration file found (1 configs were invalid)"}]}
        self.assertIsNotNone(s.semgrep_failure(data, 7))

    def test_findings_rc1_is_success(self):
        self.assertIsNone(s.semgrep_failure({"results": [], "paths": {"scanned": ["a.py"]}}, 1))

    def test_partial_error_with_files_scanned_is_success(self):
        data = {"results": [], "paths": {"scanned": ["a.py"]},
                "errors": [{"message": "Syntax error at line 3"}]}
        self.assertIsNone(s.semgrep_failure(data, 0))

    def test_nothing_scanned_with_errors_is_failure(self):
        data = {"results": [], "paths": {"scanned": []},
                "errors": [{"message": "Timeout"}]}
        self.assertIsNotNone(s.semgrep_failure(data, 0))

    def test_clean_project_no_errors_is_success(self):
        self.assertIsNone(s.semgrep_failure({"results": [], "paths": {"scanned": []}}, 0))


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


class TestFingerprintContent(unittest.TestCase):
    """Fingerprint por trecho de codigo, nao por indice de ocorrencia."""

    def _mk(self, snippet, line):
        return {"tool": "semgrep", "rule": "eval", "path": "a.py",
                "line": line, "pkg": None, "snippet": snippet}

    def test_reordering_does_not_change_fingerprints(self):
        a, b = self._mk("eval(x)", 10), self._mk("eval(y)", 20)
        s.assign_fingerprints([a, b])
        fp_a, fp_b = a["fp"], b["fp"]

        a2, b2 = self._mk("eval(x)", 5), self._mk("eval(y)", 30)
        s.assign_fingerprints([b2, a2])
        self.assertEqual(a2["fp"], fp_a)
        self.assertEqual(b2["fp"], fp_b)

    def test_identical_snippets_get_distinct_fingerprints(self):
        a, b = self._mk("eval(x)", 10), self._mk("eval(x)", 20)
        s.assign_fingerprints([a, b])
        self.assertNotEqual(a["fp"], b["fp"])


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


# ------------------------------------------------------------------- relatorio

META = {"target": "/proj", "name": "proj", "when": "agora",
        "tools": [("gitleaks", s.STATUS_OK, "", 0.1)]}


def _f(**kw):
    base = {"tool": "semgrep", "rule": "eval", "path": "a.py", "line": 3,
            "sev": "ALTA", "title": "eval do usuario", "pkg": None, "fix": None, "fp": "x"}
    base.update(kw)
    return base


class TestReport(unittest.TestCase):
    def _render(self, findings, ignored):
        counts = {}
        for f in findings:
            counts[f["sev"]] = counts.get(f["sev"], 0) + 1
        with tempfile.TemporaryDirectory() as td:
            s.write_markdown(findings, ignored, META, counts, Path(td))
            return (Path(td) / "relatorio.md").read_text(encoding="utf-8")

    def test_ignored_listed_with_tool_path_rule(self):
        md = self._render([_f()], [_f(tool="gitleaks", rule="aws-key",
                                       path="infra/terraform.tfvars", line=12,
                                       sev="CRÍTICA", title="chave")])
        self.assertIn("## Aceitos por baseline", md)
        self.assertIn("`infra/terraform.tfvars:12`", md)
        self.assertIn("aws-key", md)

    def test_ignored_not_counted_in_findings_table(self):
        md = self._render([_f()], [_f(path="ignorado.py", title="nao deve aparecer")])
        achados = md.split("## Achados", 1)[1].split("## Aceitos por baseline", 1)[0]
        self.assertNotIn("nao deve aparecer", achados)

    def test_no_section_when_baseline_empty(self):
        md = self._render([_f()], [])
        self.assertNotIn("## Aceitos por baseline", md)

    def test_count_row_still_present(self):
        md = self._render([_f()], [_f(), _f(path="b.py")])
        self.assertIn("| _ignorados por baseline_ | _2_ |", md)


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
        self.assertEqual(len(doc["runs"]), len(s.TOOLS))
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

    def test_finds_stack_in_monorepo_subdirectory(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            api = d / "services" / "api"
            api.mkdir(parents=True)
            (api / "go.mod").write_text("module x", encoding="utf-8")
            self.assertIn("p/golang", s.detect_stacks(d))

    def test_does_not_descend_into_ignored_directories(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            nm = d / "node_modules" / "some-pkg"
            nm.mkdir(parents=True)
            (nm / "Cargo.toml").write_text("[package]", encoding="utf-8")
            self.assertNotIn("p/rust", s.detect_stacks(d))


class TestPruneReports(unittest.TestCase):
    def _mk(self, root, name, sensitive=False):
        d = root / name
        d.mkdir(parents=True)
        (d / "relatorio.md").write_text("x", encoding="utf-8")
        if sensitive:
            (d / "SENSIVEL.txt").write_text("credenciais", encoding="utf-8")
        return d

    def test_removes_dirs_beyond_keep(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for n in ("2026-01-01_10-00-00", "2026-01-02_10-00-00",
                      "2026-01-03_10-00-00"):
                self._mk(root, n)
            s.prune_reports(root, keep=2)
            self.assertEqual(sorted(p.name for p in root.iterdir()),
                             ["2026-01-02_10-00-00", "2026-01-03_10-00-00"])

    def test_retains_only_newest_sensitive_report(self):
        # relatorios com SENSIVEL.txt guardam credencial em texto claro:
        # acumular varios amplia a exposicao, mesmo dentro da janela --keep
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._mk(root, "2026-01-01_10-00-00", sensitive=True)
            self._mk(root, "2026-01-02_10-00-00", sensitive=True)
            self._mk(root, "2026-01-03_10-00-00", sensitive=True)
            s.prune_reports(root, keep=20)
            self.assertEqual([p.name for p in root.iterdir()],
                             ["2026-01-03_10-00-00"])

    def test_non_sensitive_reports_are_not_pruned_by_sensitive_rule(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._mk(root, "2026-01-01_10-00-00")
            self._mk(root, "2026-01-02_10-00-00")
            self._mk(root, "2026-01-03_10-00-00", sensitive=True)
            s.prune_reports(root, keep=20)
            self.assertEqual(len(list(root.iterdir())), 3)

    def test_keep_zero_disables_pruning(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._mk(root, "2026-01-01_10-00-00", sensitive=True)
            self._mk(root, "2026-01-02_10-00-00", sensitive=True)
            s.prune_reports(root, keep=0)
            self.assertEqual(len(list(root.iterdir())), 2)


class TestTrivy(unittest.TestCase):
    def _data(self, *misconfs, target="Dockerfile"):
        return {"Results": [{"Target": target, "Class": "config",
                             "Type": "dockerfile",
                             "Misconfigurations": list(misconfs)}]}

    def _m(self, mid="DS-0002", sev="HIGH", status="FAIL", line=4,
           title="Image user should not be 'root'"):
        m = {"ID": mid, "Severity": sev, "Status": status, "Title": title,
             "Message": "Last USER command in Dockerfile should not be 'root'"}
        if line is not None:
            m["CauseMetadata"] = {"StartLine": line, "EndLine": line}
        return m

    def test_parses_fail_entries(self):
        out = s.parse_trivy(self._data(self._m()))
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f["tool"], "trivy")
        self.assertEqual(f["path"], "Dockerfile")
        self.assertEqual(f["line"], 4)
        self.assertEqual(f["rule"], "DS-0002")
        self.assertEqual(f["sev"], "ALTA")
        self.assertIn("DS-0002", f["title"])

    def test_pass_entries_are_skipped(self):
        out = s.parse_trivy(self._data(self._m(status="PASS")))
        self.assertEqual(out, [])

    def test_missing_start_line_yields_none(self):
        out = s.parse_trivy(self._data(self._m(line=None)))
        self.assertIsNone(out[0]["line"])

    def test_severity_mapping(self):
        for raw, want in (("CRITICAL", "CRÍTICA"), ("HIGH", "ALTA"),
                          ("MEDIUM", "MÉDIA"), ("LOW", "BAIXA")):
            out = s.parse_trivy(self._data(self._m(sev=raw)))
            self.assertEqual(out[0]["sev"], want, raw)

    def test_unknown_severity_falls_back_to_media(self):
        out = s.parse_trivy(self._data(self._m(sev="WEIRD")))
        self.assertEqual(out[0]["sev"], "MÉDIA")

    def test_empty_results_is_clean(self):
        self.assertEqual(s.parse_trivy({"Results": []}), [])

    def test_missing_results_key_raises(self):
        with self.assertRaises(s.ScanError):
            s.parse_trivy({"SchemaVersion": 2})

    def test_valid_empty_report_is_not_an_error(self):
        # o trivy OMITE "Results" quando nao detecta nenhum arquivo de config.
        # Isso e um relatorio valido, nao um schema quebrado: marcar como
        # FALHOU gera falha falsa (rc=2) em projeto com k8s/*.yaml que o
        # trivy nao reconhece como kubernetes.
        empty = {"SchemaVersion": 2, "ArtifactName": ".",
                 "Trivy": {"Version": "0.76.2"},
                 "ArtifactType": "filesystem"}
        self.assertEqual(s.parse_trivy(empty), [])

    def test_report_without_trivy_markers_still_raises(self):
        with self.assertRaises(s.ScanError):
            s.parse_trivy({"unexpected": "shape"})

    def test_toplevel_list_raises(self):
        with self.assertRaises(s.ScanError):
            s.parse_trivy([])

    def test_multiple_targets_are_flattened(self):
        data = {"Results": [
            {"Target": "Dockerfile", "Misconfigurations": [self._m()]},
            {"Target": "deploy/app.yaml", "Misconfigurations": [
                self._m(mid="KSV001", sev="CRITICAL")]},
        ]}
        out = s.parse_trivy(data)
        self.assertEqual([f["path"] for f in out], ["Dockerfile", "deploy/app.yaml"])


class TestDetectIac(unittest.TestCase):
    def _touch(self, root, rel):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x", encoding="utf-8")

    def test_detects_dockerfile(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "Dockerfile")
            self.assertEqual(s.detect_iac(root), ["Dockerfile"])

    def test_detects_dockerfile_variant(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "Dockerfile.prod")
            self.assertEqual(s.detect_iac(root), ["Dockerfile.prod"])

    def test_detects_terraform(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "infra/main.tf")
            self.assertEqual(s.detect_iac(root), ["infra/main.tf"])

    def test_detects_kubernetes_manifest_in_known_dir(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "k8s/deployment.yaml")
            self.assertEqual(s.detect_iac(root), ["k8s/deployment.yaml"])

    def test_detects_helm_chart_in_neutral_dir(self):
        # chart aninhado em pasta sem nome de IaC: sem Chart.yaml explicito
        # nos padroes, detect_iac devolve [] e a camada fica "pulado" mesmo
        # com templates/*.yaml inseguros dentro.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "services/web/chart/Chart.yaml")
            self.assertIn("services/web/chart/Chart.yaml", s.detect_iac(root))

    def test_detects_chart_yaml_at_depth_boundary(self):
        # Chart.yaml fica um nivel ACIMA de templates/. Quando templates/ cai
        # fora de max_depth, Chart.yaml ainda precisa ativar a camada - o
        # trivy nao tem esse limite e escaneia o chart inteiro.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "services/web/chart/Chart.yaml")
            self._touch(root, "services/web/chart/templates/deployment.yaml")
            found = s.detect_iac(root)
            self.assertIn("services/web/chart/Chart.yaml", found)

    def test_plain_python_project_has_no_iac(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "app.py")
            self._touch(root, "requirements.txt")
            self.assertEqual(s.detect_iac(root), [])

    def test_skips_vendor_and_node_modules(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "node_modules/pkg/Dockerfile")
            self.assertEqual(s.detect_iac(root), [])

    def test_unrelated_yaml_is_not_iac(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "config/settings.yaml")
            self.assertEqual(s.detect_iac(root), [])

    def test_docker_compose_is_not_scannable(self):
        # o trivy 0.76 nao tem scanner de docker-compose: `Detected config
        # files num=0`. Anunciar como IaC ativaria a camada para nao escanear
        # nada, dando falsa sensacao de cobertura.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "docker-compose.yml")
            self.assertEqual(s.detect_iac(root), [])

    def test_compose_is_reported_as_unsupported(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "docker-compose.yml")
            self._touch(root, "compose.yaml")
            self.assertEqual(s.detect_compose(root),
                             ["compose.yaml", "docker-compose.yml"])

    def test_plain_project_has_no_compose(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._touch(root, "app.py")
            self.assertEqual(s.detect_compose(root), [])


class TestTrivyCmd(unittest.TestCase):
    def _cmd(self):
        return s.trivy_cmd(Path("/proj"), Path("/out"))

    def test_target_is_last_argument(self):
        self.assertEqual(self._cmd()[-1], str(Path("/proj")))

    def test_skips_check_update(self):
        # sem esta flag o trivy tenta baixar o bundle OCI a cada execucao:
        # offline isso vira ERROR + ~7s de espera antes do fallback
        self.assertIn("--skip-check-update", self._cmd())

    def test_skip_dirs_uses_double_star_prefix(self):
        # nome simples so casa na raiz: apps/web/node_modules escapava
        cmd = self._cmd()
        for d in s.SKIP_DIRS:
            self.assertIn(f"**/{d}", cmd, f"padrao ausente para {d}")
            self.assertNotIn(d, cmd, f"nome simples nao casa em profundidade: {d}")

    def test_every_skip_dirs_has_a_value(self):
        cmd = self._cmd()
        for i, a in enumerate(cmd):
            if a == "--skip-dirs":
                self.assertTrue(cmd[i + 1].startswith("**/"))

    def test_cache_dir_is_inside_the_skill(self):
        # cache hermetico: nada e escrito fora da pasta da skill
        cmd = self._cmd()
        self.assertIn("--cache-dir", cmd)
        cache = cmd[cmd.index("--cache-dir") + 1]
        self.assertTrue(str(s.BASE) in cache, cache)

    def test_writes_json_to_outdir(self):
        cmd = self._cmd()
        self.assertIn("--format", cmd)
        self.assertEqual(cmd[cmd.index("--format") + 1], "json")
        self.assertEqual(cmd[cmd.index("--output") + 1], str(Path("/out/trivy.json")))


class TestHermeticContract(unittest.TestCase):
    """Invariantes que valem mesmo com todos os outros testes verdes."""

    def _installers(self):
        root = Path(s.__file__).resolve().parent
        for name in ("install.sh", "install.ps1"):
            yield name, (root / name).read_text(encoding="utf-8")

    def test_installers_do_not_prewarm_trivy_checks(self):
        # Pre-aquecer o bundle OCI quebra a paridade entre SOs: o download
        # falha no Windows (bug de path) e funciona em Linux/macOS, entao as
        # maquinas passariam a usar bundles diferentes. O bundle embutido no
        # binario e o unico conjunto de checks que e igual em todo lugar.
        for name, text in self._installers():
            for i, line in enumerate(text.splitlines(), 1):
                code = line.strip()
                if not code or code.startswith("#"):
                    continue
                low = code.lower()
                self.assertFalse(
                    "trivy" in low and " config" in low,
                    f"{name}:{i} invoca 'trivy config' no instalador — "
                    f"pre-aquecimento reintroduz divergencia entre SOs: {code}")

    def test_trivy_cache_dir_is_not_the_global_default(self):
        cache = str(s.TRIVY_CACHE).replace("\\", "/").lower()
        for bad in ("appdata", ".cache/trivy"):
            self.assertNotIn(bad, cache, f"cache do trivy fora da skill: {cache}")
        self.assertIn(str(s.BASE).replace("\\", "/").lower(), cache)


class TestMissingConfigs(unittest.TestCase):
    def test_registry_packs_are_not_local(self):
        self.assertEqual(s.missing_configs(["p/default", "p/python"]), [])

    def test_url_config_is_not_local(self):
        self.assertEqual(s.missing_configs(["https://example.com/r.yml"]), [])

    def test_existing_local_file_is_ok(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "rules.yml"
            f.write_text("rules: []", encoding="utf-8")
            self.assertEqual(s.missing_configs([str(f)]), [])

    def test_missing_local_file_is_reported(self):
        with tempfile.TemporaryDirectory() as td:
            gone = str(Path(td) / "nope.yml")
            self.assertEqual(s.missing_configs([gone]), [gone])

    def test_mixed_list_reports_only_the_missing_local_one(self):
        with tempfile.TemporaryDirectory() as td:
            gone = str(Path(td) / "nope.yml")
            self.assertEqual(s.missing_configs(["p/default", gone]), [gone])


class TestGitleaksRuns(unittest.TestCase):
    def test_without_history_scans_only_working_tree(self):
        self.assertEqual(s.gitleaks_runs(False), [("dir", "gitleaks.json")])

    def test_with_history_scans_git_and_working_tree(self):
        runs = s.gitleaks_runs(True)
        modes = [m for m, _ in runs]
        self.assertEqual(modes, ["git", "dir"])

    def test_working_tree_is_always_scanned(self):
        # `gitleaks git` so enxerga commits: sem o modo `dir`, um segredo
        # ainda nao commitado fica invisivel e a varredura reporta "limpo".
        for hist in (False, True):
            self.assertIn("dir", [m for m, _ in s.gitleaks_runs(hist)], hist)

    def test_report_names_do_not_collide(self):
        names = [n for _, n in s.gitleaks_runs(True)]
        self.assertEqual(len(names), len(set(names)))


class TestDefaultConfigs(unittest.TestCase):
    def test_default_is_p_default(self):
        # p/default e a base por cobertura, nao por inercia: medido que
        # p/security-audit e p/owasp-top-ten deixam passar chave AWS exposta
        # e SQL injection. Nao trocar por um pacote mais estreito sem medir.
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(s.default_configs(Path(td), False), ["p/default"])

    def test_stack_rules_are_appended_not_replacing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text("flask\n", encoding="utf-8")
            cfgs = s.default_configs(root, True)
            self.assertEqual(cfgs[0], "p/default")
            self.assertIn("p/python", cfgs)

    def test_stack_rules_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text("flask\n", encoding="utf-8")
            self.assertEqual(s.default_configs(root, False), ["p/default"])


class TestGitleaksConfig(unittest.TestCase):
    def _cfg(self, root, outdir):
        s.gitleaks_config(outdir, root)
        return (outdir / "gitleaks.toml").read_text(encoding="utf-8")

    def test_dependency_dirs_are_allowlisted(self):
        with tempfile.TemporaryDirectory() as td:
            root, out = Path(td), Path(td) / "out"
            out.mkdir()
            cfg = self._cfg(root, out)
            for d in ("node_modules", "vendor", ".terraform"):
                self.assertIn(d, cfg)

    def test_gitignore_is_not_inherited(self):
        # Para um scanner de SEGREDOS herdar o .gitignore e contraproducente:
        # e la que ficam `.env`, `*.pem`, `credentials.json`. Medido: com
        # `*.pem` no .gitignore, uma chave RSA real de 2048 bits passava
        # invisivel; removendo a linha, o achado aparecia.
        with tempfile.TemporaryDirectory() as td:
            root, out = Path(td), Path(td) / "out"
            out.mkdir()
            (root / ".gitignore").write_text(".env\n*.pem\nsecrets/\n", encoding="utf-8")
            cfg = self._cfg(root, out)
            for bad in ("pem", "secrets", ".env"):
                self.assertNotIn(bad, cfg, f".gitignore vazou para a allowlist: {bad}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
secscan - varredura de segurança unificada para o seu próprio código.

Roda tres camadas de defesa em um comando:
  1. Segredos  -> gitleaks   (token commitado, chave de API, senha)
  2. Dependencias -> osv-scanner (CVE em biblioteca de terceiros)
  3. Codigo     -> semgrep    (SAST: injecao, XSS, cripto fraca, etc)

Uso:
    python secscan.py [pasta-alvo] [opcoes]

Saida: console + security-report/<timestamp>/relatorio.md + JSONs brutos.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
BIN = BASE / "bin"
IS_WIN = os.name == "nt"

SEV_ORDER = {"CRÍTICA": 0, "ALTA": 1, "MÉDIA": 2, "BAIXA": 3, "INFO": 4}
SEV_WEIGHT = {"CRÍTICA": 10, "ALTA": 6, "MÉDIA": 3, "BAIXA": 1, "INFO": 0}
# rotulos sem acento para o console do Windows, que nao esta em UTF-8
SEV_DISPLAY = {"CRÍTICA": "CRITICA", "ALTA": "ALTA", "MÉDIA": "MEDIA",
               "BAIXA": "BAIXA", "INFO": "INFO"}

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ANSI = sys.stdout.isatty() and not IS_WIN or (IS_WIN and os.environ.get("TERM"))
C = {
    "r": "\033[0m" if ANSI else "",
    "dim": "\033[2m" if ANSI else "",
    "b": "\033[1m" if ANSI else "",
    "red": "\033[31m" if ANSI else "",
    "yel": "\033[33m" if ANSI else "",
    "grn": "\033[32m" if ANSI else "",
    "cya": "\033[36m" if ANSI else "",
}


def exe(name: str) -> Path:
    return BIN / (name + ".exe" if IS_WIN else name)


GITLEAKS = exe("gitleaks")
OSV = exe("osv-scanner")
VENV_DIR = BASE / (".venv/Scripts" if IS_WIN else ".venv/bin")
SEMGREP = VENV_DIR / ("semgrep.exe" if IS_WIN else "semgrep")

SKIP_DIRS = (
    "node_modules", ".venv", "venv", "dist", "build", "target",
    "vendor", "__pycache__", ".git", "site-packages", ".next",
)


def run(cmd, label):
    """Executa um comando e devolve (rc, saida). Nunca levanta excecao."""
    t0 = time.time()
    try:
        p = subprocess.run(
            [str(c) for c in cmd],
            capture_output=True, text=True, errors="replace", timeout=1800,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or ""), time.time() - t0
    except FileNotFoundError:
        return 127, f"binario nao encontrado: {cmd[0]}", 0.0
    except subprocess.TimeoutExpired:
        return 124, f"{label}: timeout de 30 min", time.time() - t0


def short(text: str, n: int) -> str:
    """Trunca em limite de palavra, com reticencias."""
    t = " ".join((text or "").split())
    if len(t) <= n:
        return t
    cut = t[:n].rsplit(" ", 1)[0]
    return (cut or t[:n]).rstrip(",.;:") + "..."


# ----------------------------------------------------------------------------
# 1. Segredos
# ----------------------------------------------------------------------------

def gitleaks_config(outdir: Path) -> Path:
    """Config que herda as regras padrao e ignora pastas de dependencia."""
    cfg = outdir / "gitleaks.toml"
    paths = ", ".join(f"'''{re.escape(d)}'''" for d in SKIP_DIRS)
    cfg.write_text(
        "[extend]\nuseDefault = true\n\n"
        "[[allowlists]]\n"
        'description = "pastas de dependencia e build"\n'
        f"paths = [{paths}]\n",
        encoding="utf-8",
    )
    return cfg


def scan_secrets(target: Path, outdir: Path, history: bool):
    if not GITLEAKS.exists():
        return [], "gitleaks nao instalado", 0.0

    report = outdir / "gitleaks.json"
    cfg = gitleaks_config(outdir)
    mode = "git" if history else "dir"
    cmd = [GITLEAKS, mode, str(target), "-c", cfg,
           "-f", "json", "-r", report, "--no-banner",
           "--exit-code", "0", "--redact", "--max-target-megabytes", "5"]
    if history:
        cmd += ["--log-opts", "--all"]

    rc, out, dt = run(cmd, "gitleaks")
    if rc not in (0, 1) or not report.exists():
        return [], out.strip()[:500] or f"gitleaks falhou (rc={rc})", dt

    try:
        raw = json.loads(report.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError:
        return [], "gitleaks: JSON invalido", dt

    findings = []
    for f in raw or []:
        findings.append({
            "sev": "CRÍTICA",
            "title": f"Segredo exposto: {f.get('RuleID', '?')}",
            "where": f"{f.get('File', '?')}:{f.get('StartLine', '?')}",
            "detail": short(f.get("Description") or "", 150),
            "tool": "gitleaks",
        })
    return findings, "", dt


# ----------------------------------------------------------------------------
# 2. Dependencias
# ----------------------------------------------------------------------------

SEV_MAP = {
    "CRITICAL": "CRÍTICA", "HIGH": "ALTA", "MODERATE": "MÉDIA",
    "MEDIUM": "MÉDIA", "LOW": "BAIXA",
}


def cvss_band(score) -> str:
    """Converte nota CVSS (0-10) na faixa qualitativa padrao."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "MÉDIA"
    if s >= 9.0:
        return "CRÍTICA"
    if s >= 7.0:
        return "ALTA"
    if s >= 4.0:
        return "MÉDIA"
    if s > 0:
        return "BAIXA"
    return "INFO"


def sev_from(value, fallback="MÉDIA") -> str:
    """Aceita rotulo textual ou nota numerica CVSS."""
    if value is None or value == "":
        return fallback
    txt = str(value).strip()
    if txt.upper() in SEV_MAP:
        return SEV_MAP[txt.upper()]
    if re.fullmatch(r"\d+(\.\d+)?", txt):
        return cvss_band(txt)
    return fallback


def scan_deps(target: Path, outdir: Path):
    if not OSV.exists():
        return [], "osv-scanner nao instalado", 0.0

    report = outdir / "osv.json"
    cmd = [OSV, "scan", "source", "-r", target,
           "-f", "json", "--output-file", report, "--verbosity", "error"]
    for d in SKIP_DIRS:
        cmd += ["--x-exclude", f"g:**/{d}/**"]

    rc, out, dt = run(cmd, "osv-scanner")
    if "No package sources found" in out:
        return [], "__NO_SOURCE__", dt
    if not report.exists():
        return [], out.strip()[:500] or f"osv-scanner falhou (rc={rc})", dt

    try:
        data = json.loads(report.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError:
        return [], "osv-scanner: JSON invalido", dt

    findings = []
    for res in data.get("results") or []:
        src = (res.get("source") or {}).get("path", "?")
        for pkg in res.get("packages") or []:
            pinfo = pkg.get("package") or {}
            name = pinfo.get("name", "?")
            ver = pinfo.get("version", "?")
            eco = pinfo.get("ecosystem", "")
            seen = set()
            for grp in pkg.get("groups") or []:
                ids = grp.get("ids") or []
                if not ids:
                    continue
                key = tuple(sorted(ids))
                if key in seen:
                    continue
                seen.add(key)
                score = grp.get("max_severity")
                sev = sev_from(score)
                findings.append({
                    "sev": sev,
                    "title": f"{name} {ver} - {ids[0]}",
                    "where": src,
                    "detail": f"CVSS {score} | {eco}" if score else eco,
                    "pkg": f"{name} {ver}",
                    "tool": "osv",
                })
            if not pkg.get("groups"):
                for v in pkg.get("vulnerabilities") or []:
                    ds = v.get("database_specific") or {}
                    sev = sev_from(ds.get("severity"), fallback="")
                    if not sev:
                        vec = ""
                        for s in v.get("severity") or []:
                            vec = s.get("score", "")
                            break
                        sev = sev_from(vec) if re.fullmatch(r"[\d.]+", vec or "") else "MÉDIA"
                    findings.append({
                        "sev": sev,
                        "title": f"{name} {ver} - {v.get('id', '?')}",
                        "where": src,
                        "detail": short(v.get("summary") or eco, 150),
                        "pkg": f"{name} {ver}",
                        "tool": "osv",
                    })
    return findings, "", dt


# ----------------------------------------------------------------------------
# 3. Codigo (SAST)
# ----------------------------------------------------------------------------

def scan_code(target: Path, outdir: Path, config: str):
    if not SEMGREP.exists():
        return [], "semgrep nao instalado", 0.0

    report = outdir / "semgrep.json"
    cmd = [SEMGREP, "scan", "--config", config, "--json",
           "--output", report, "--quiet", "--metrics", "off",
           "--disable-version-check", "--no-git-ignore",
           "--exclude", "node_modules", "--exclude", ".venv",
           "--exclude", "dist", "--exclude", "build",
           "--timeout", "30", target]
    rc, out, dt = run(cmd, "semgrep")
    if not report.exists():
        return [], out.strip()[:500] or f"semgrep falhou (rc={rc})", dt

    try:
        data = json.loads(report.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError:
        return [], "semgrep: JSON invalido", dt

    sev_map = {"ERROR": "ALTA", "WARNING": "MÉDIA", "INFO": "BAIXA"}
    findings = []
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        sev = sev_map.get((extra.get("severity") or "").upper(), "MÉDIA")
        path = r.get("path", "?")
        line = (r.get("start") or {}).get("line", "?")
        findings.append({
            "sev": sev,
            "title": short((extra.get("message") or r.get("check_id", "?")), 108),
            "where": f"{path}:{line}",
            "detail": (r.get("check_id", "") or "").split(".")[-1][:60],
            "tool": "semgrep",
        })
    return findings, "", dt


# ----------------------------------------------------------------------------
# Relatorio
# ----------------------------------------------------------------------------

def render(findings, meta, outdir: Path):
    findings.sort(key=lambda f: (SEV_ORDER.get(f["sev"], 9), f["where"]))
    counts = {}
    for f in findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1

    bar = "=" * 62
    print(f"\n{C['b']}{bar}{C['r']}")
    print(f"{C['b']}  secscan - {meta['target']}{C['r']}")
    print(f"{C['dim']}  {meta['when']}{C['r']}")
    print(f"{C['b']}{bar}{C['r']}\n")

    for name, dt, err in meta["tools"]:
        if err == "__NO_SOURCE__":
            print(f"  {name:<14} {C['dim']}pulado - nenhum lockfile no projeto{C['r']}")
            continue
        state = f"{C['grn']}ok{C['r']} ({dt:.1f}s)" if not err else f"{C['red']}falhou{C['r']}"
        print(f"  {name:<14} {state}")
        if err:
            print(f"    {C['dim']}{err}{C['r']}")

    print()
    if not findings:
        print(f"  {C['grn']}Nenhum achado. Nada critico exposto.{C['r']}\n")
    else:
        for sev in ("CRÍTICA", "ALTA", "MÉDIA", "BAIXA", "INFO"):
            n = counts.get(sev, 0)
            if not n:
                continue
            color = {"CRÍTICA": C["red"], "ALTA": C["red"],
                     "MÉDIA": C["yel"], "BAIXA": C["dim"]}.get(sev, "")
            print(f"  {color}{SEV_DISPLAY.get(sev, sev):<9}{C['r']} {n:>3}")
        print()

        high = [f for f in findings if f["sev"] in ("CRÍTICA", "ALTA")]
        merged, bypkg = [], {}
        for f in high:
            key = f.get("pkg")
            if key and key in bypkg:
                bypkg[key]["n"] += 1
                continue
            item = dict(f)
            item["n"] = 1
            if key:
                bypkg[key] = item
            merged.append(item)

        if merged:
            print(f"  {C['b']}Prioridade de correcao{C['r']}\n")
            for f in merged[:12]:
                extra = f"  (+{f['n'] - 1} advisories)" if f.get("n", 1) > 1 else ""
                print(f"  * {f['title']}{extra}")
                print(f"    {C['dim']}{f['where']}{C['r']}")
            if len(merged) > 12:
                print(f"    {C['dim']}... e mais {len(merged) - 12} em relatorio.md{C['r']}")
            print()

    # --- markdown ---
    lines = [
        f"# Relatorio de seguranca — {meta['name']}", "",
        f"**Alvo:** `{meta['target']}`  ",
        f"**Gerado:** {meta['when']}  ",
        f"**Ferramentas:** gitleaks (segredos) · osv-scanner (dependencias) · semgrep (SAST)", "",
        "## Resumo", "", "| Severidade | Achados |", "|---|---|",
    ]
    for sev in ("CRÍTICA", "ALTA", "MÉDIA", "BAIXA"):
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")
    lines.append(f"| **Total** | **{len(findings)}** |")

    lines += ["", "## Achados", ""]
    if not findings:
        lines.append("Nenhum achado.")
    else:
        lines += ["| Sev | Ferramenta | Local | Descricao |", "|---|---|---|---|"]
        for f in findings:
            desc = f["title"].replace("|", "\\|")
            loc = f["where"].replace("|", "\\|")
            lines.append(f"| {f['sev']} | {f['tool']} | `{loc}` | {desc} |")

    lines += ["", "## Como corrigir", "",
              "- **Segredo exposto:** revogue o token/credencial *agora* e gere outro. "
              "Remover do codigo nao basta — o valor ja vazou e continua valido.",
              "- **Dependencia vulneravel:** atualize para a versao corrigida. "
              "Se nao houver correcao, avalie substituir ou isolar a biblioteca.",
              "- **Achado de SAST:** confirme se o dado realmente chega do usuario ate o ponto "
              "apontado. Se chega, sanitize na entrada *e* use consulta parametrizada/saida escapada.", ""]
    (outdir / "relatorio.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"  {C['cya']}Relatorio:{C['r']} {outdir / 'relatorio.md'}")
    print(f"  {C['dim']}JSONs brutos em: {outdir}{C['r']}\n")
    return counts


def main():
    ap = argparse.ArgumentParser(
        description="Varredura unificada de seguranca (segredos + dependencias + SAST).")
    ap.add_argument("target", nargs="?", default=".", help="pasta do projeto")
    ap.add_argument("--out", default="security-report", help="pasta de saida")
    ap.add_argument("--history", action="store_true",
                    help="gitleaks tambem no historico do git (mais lento)")
    ap.add_argument("--semgrep-config", default="p/default",
                    help="ruleset do semgrep (padrao: p/default)")
    ap.add_argument("--no-secrets", action="store_true")
    ap.add_argument("--no-deps", action="store_true")
    ap.add_argument("--no-sast", action="store_true")
    ap.add_argument("--fail-on", default="alta",
                    choices=["critica", "alta", "media", "baixa", "nunca"],
                    help="codigo de saida != 0 a partir desta severidade")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"erro: pasta nao encontrada: {target}")
        return 2

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = (Path(args.out).resolve() / stamp)
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"{C['dim']}secscan - alvo: {target}{C['r']}")
    print(f"{C['dim']}saida: {outdir}{C['r']}")

    findings, tools = [], []

    if not args.no_secrets:
        print(f"  {C['dim']}> segredos (gitleaks)...{C['r']}")
        f, err, dt = scan_secrets(target, outdir, args.history)
        findings += f
        tools.append(("gitleaks", dt, err))

    if not args.no_deps:
        print(f"  {C['dim']}> dependencias (osv-scanner)...{C['r']}")
        f, err, dt = scan_deps(target, outdir)
        findings += f
        tools.append(("osv-scanner", dt, err))

    if not args.no_sast:
        print(f"  {C['dim']}> codigo (semgrep)...{C['r']}")
        f, err, dt = scan_code(target, outdir, args.semgrep_config)
        findings += f
        tools.append(("semgrep", dt, err))

    # caminhos relativos ao projeto, para o relatorio ficar legivel
    tpath = str(target).replace("\\", "/")
    for f in findings:
        w = str(f.get("where", "")).replace("\\", "/")
        if w.startswith(tpath):
            w = w[len(tpath):].lstrip("/")
        f["where"] = w or "."

    counts = render(findings, {
        "target": str(target),
        "name": target.name,
        "when": datetime.now().strftime("%d/%m/%Y %H:%M"),
        "tools": tools,
    }, outdir)

    if args.fail_on == "nunca":
        return 0
    limit = {"critica": 0, "alta": 1, "media": 2, "baixa": 3}[args.fail_on]
    worst = min((SEV_ORDER.get(s, 9) for s in counts), default=9)
    return 1 if worst <= limit else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Etapa 3: normaliza SARIF de herramientas deterministas a una lista común de candidatos.

Uso:
    python ingest_sarif.py <archivo.sarif> [<otro.sarif> ...] --out tool-findings.json [--repo <raiz>]

Acepta la salida SARIF 2.1.0 de Semgrep, CodeQL, gitleaks, Trivy, OSV-Scanner, Checkov, Bandit u otras
herramientas que exporten SARIF. Las que no lo hacen (trufflehog, ZAP) se registran como candidatos a mano. Para cada resultado extrae herramienta, regla, nivel, archivo:línea, CWE
y categoría Top 10:2025 (por CWE, o por la etiqueta OWASP de la regla si no hay CWE). Deduplica por
(archivo, línea, CWE). Los resultados son CANDIDATOS: pasan por la verificación de la etapa 5 como el resto.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import cwe_to_top10, load_json, normalize_cwe, utf8_stdout, write_json  # noqa: E402

OWASP_TAG_RE = re.compile(r"\bA(0[1-9]|10)[:_ ]?(2021|2025)\b", re.IGNORECASE)
LEVEL_RANK = {"error": 3, "warning": 2, "note": 1, "none": 0}


def rule_index(run: dict) -> dict[str, dict]:
    rules = {}
    driver = run.get("tool", {}).get("driver", {})
    for comp in [driver] + list(run.get("tool", {}).get("extensions", []) or []):
        for r in comp.get("rules", []) or []:
            rules[r.get("id", "")] = r
    return rules


def collect_tags(*objs: dict) -> list[str]:
    tags: list[str] = []
    for o in objs:
        props = (o or {}).get("properties", {}) or {}
        for key in ("tags", "cwe", "owasp", "CWE", "OWASP"):
            val = props.get(key)
            if isinstance(val, str):
                tags.append(val)
            elif isinstance(val, list):
                tags.extend(str(v) for v in val)
    return tags


def owasp_from_tags(tags: list[str]) -> tuple[str | None, str | None]:
    t2025 = t2021 = None
    for t in tags:
        for m in OWASP_TAG_RE.finditer(t):
            cat, year = f"A{m.group(1)}", m.group(2)
            if year == "2025":
                t2025 = t2025 or cat
            else:
                t2021 = t2021 or cat
    return t2025, t2021


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sarif", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--repo", type=Path, help="Raíz del repo para convertir URIs absolutas en relativas")
    args = ap.parse_args()
    repo = args.repo.resolve().as_posix() if args.repo else None
    mapping_2021 = load_json(Path(__file__).resolve().parent.parent / "data" / "owasp-2021-to-2025.json")["2021"]

    seen: dict[tuple, dict] = {}
    errors = []
    for path in args.sarif:
        try:
            doc = load_json(path)
        except (OSError, ValueError) as exc:
            errors.append(f"{path}: no se pudo leer ({exc})")
            continue
        for run in doc.get("runs", []):
            tool = run.get("tool", {}).get("driver", {}).get("name", path.stem)
            rules = rule_index(run)
            for res in run.get("results", []) or []:
                rid = res.get("ruleId") or (res.get("rule") or {}).get("id", "")
                rule = rules.get(rid, {})
                tags = collect_tags(rule, res)
                cwes = sorted({c for c in (normalize_cwe(t) for t in tags) if c}, key=lambda c: int(c[4:]))
                t2025, t2021 = owasp_from_tags(tags)
                if not t2025 and cwes:
                    cats = [cat for c in cwes for cat in cwe_to_top10(c)]
                    t2025 = cats[0] if cats else None
                if not t2025 and t2021:
                    t2025 = mapping_2021[t2021]["to_2025"]
                loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
                uri = (loc.get("artifactLocation") or {}).get("uri", "")
                uri = re.sub(r"^file:///?", "", uri)
                if repo and uri.replace("\\", "/").lower().startswith(repo.lower()):
                    uri = uri[len(repo):].lstrip("/\\")
                line = (loc.get("region") or {}).get("startLine")
                level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level", "warning")
                sec_sev = (rule.get("properties") or {}).get("security-severity")
                msg = (res.get("message") or {}).get("text", "") or (rule.get("shortDescription") or {}).get("text", "")
                key = (uri, line, cwes[0] if cwes else rid)
                cand = {
                    "tool": tool, "rule_id": rid, "level": level, "security_severity": sec_sev,
                    "file": uri, "line": line, "message": msg[:500], "cwe": cwes,
                    "top10_2025": t2025, "top10_2021_tag": t2021, "also_reported_by": [],
                }
                if key in seen:
                    prev = seen[key]
                    if tool != prev["tool"] and tool not in prev["also_reported_by"]:
                        prev["also_reported_by"].append(tool)
                    if LEVEL_RANK.get(level, 0) > LEVEL_RANK.get(prev["level"], 0):
                        prev["level"] = level
                else:
                    seen[key] = cand

    candidates = sorted(seen.values(), key=lambda c: (-LEVEL_RANK.get(c["level"], 0), c["file"], c["line"] or 0))
    for i, c in enumerate(candidates, 1):
        c["id"] = f"TOOL-{i:03d}"
    out = {
        "sources": [str(p) for p in args.sarif],
        "errors": errors,
        "count": len(candidates),
        "by_top10_2025": {},
        "candidates": candidates,
    }
    for c in candidates:
        k = c["top10_2025"] or "sin_categoria"
        out["by_top10_2025"][k] = out["by_top10_2025"].get(k, 0) + 1
    write_json(args.out, out)
    print(f"{len(candidates)} candidatos de {len(args.sarif)} archivo(s) -> {args.out}")
    for e in errors:
        print("ERROR:", e, file=sys.stderr)
    return 1 if errors and not candidates else 0


if __name__ == "__main__":
    sys.exit(main())

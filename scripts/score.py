#!/usr/bin/env python3
"""Etapa 6: checklist ASVS y puntuación en varios ejes (sin un número único 0-100).

Subcomandos:
    python score.py init-asvs --level 2 [--na-chapters V17,V10] --out asvs-checklist.json
        Genera la checklist de requisitos ASVS 5.0.0 aplicables al nivel objetivo, todos en 'unassessed'.
        Rellena cada uno con status: pass | fail | not_verifiable | not_applicable, y 'evidence'.

    python score.py score --findings findings.json --asvs asvs-checklist.json --arch arch-scorecard.json
                          [--samm samm.json] [--baseline baseline.json] [--exceptions exceptions.json]
                          --out score.json [--md score.md]

Veredicto: NO-SHIP si queda abierto un Critical/High VERIFIED, o LIKELY con confianza >= 0,8 (camino trazado
aunque no se haya podido ejecutar un test); REVISAR si hay Critical/High por debajo de eso o excepciones caducadas;
SHIP en el resto.

Salidas: veredicto SHIP / REVISAR / NO-SHIP; nivel ASVS alcanzado con recuentos (documentación e
implementación por separado; no_verificable nunca cuenta como pass); scorecard de 12 dimensiones (0-3);
SAMM parcial; resumen por Top 10:2025 con su equivalente 2021; hallazgos nuevos frente a la línea base.
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import SEVERITIES, asvs_requirements, data, fingerprint, load_json, utf8_stdout, write_json  # noqa: E402

STATUSES = ("pass", "fail", "not_verifiable", "not_applicable", "unassessed")
ARCH_DIMENSIONS = {
    "trust_boundaries": "Trust boundaries y segmentación",
    "authorization_model": "Modelo de autorización",
    "tenant_isolation": "Aislamiento de tenants",
    "secrets_management": "Gestión de secretos",
    "crypto_agility": "Agilidad criptográfica",
    "egress_ssrf": "Egress y SSRF",
    "logging_alerting": "Logging y alertas",
    "exception_handling": "Manejo de excepciones",
    "supply_chain": "Cadena de suministro",
    "secure_defaults": "Secure defaults y paved road",
    "abuse_cases": "Abuse cases y límites de negocio",
    "documented_decisions": "Decisiones documentadas",
}
ARCH_SCALE = {0: "Ausente", 1: "Ad hoc", 2: "Centralizado", 3: "Aplicado y probado"}
SAMM_REPO_VISIBLE = ["Secure Build", "Secure Deployment", "Defect Management", "Security Testing", "Threat Assessment"]
SAMM_NOT_FROM_REPO = ["Strategy and Metrics", "Policy and Compliance", "Education and Guidance",
                      "Incident Management", "Environment Management", "Operational Management"]


def cmd_init(args) -> int:
    na = {c.strip().upper() for c in (args.na_chapters or "").split(",") if c.strip()}
    results = {}
    for rid, r in asvs_requirements().items():
        if r["level"] > args.level:
            continue
        is_na = r["chapter_id"] in na or r["section_id"] in na
        results[rid] = {
            "status": "not_applicable" if is_na else "unassessed",
            "level": r["level"], "kind": r["kind"],
            "section": f"{r['section_id']} {r['section_name']}",
            "text": r["req_description"],
            "evidence": "capítulo o sección marcado no aplicable en init" if is_na else "",
        }
    write_json(args.out, {"asvs_version": "5.0.0", "target_level": args.level, "results": results})
    c = Counter(v["status"] for v in results.values())
    print(f"{len(results)} requisitos hasta L{args.level} ({dict(c)}) -> {args.out}")
    return 0


def asvs_summary(checklist: dict, target: int) -> dict:
    res = checklist.get("results", {})
    levels = {}
    achieved = 0
    for lvl in range(1, target + 1):
        block = {"documentation": Counter(), "implementation": Counter()}
        for r in res.values():
            if r["level"] <= lvl:
                block[r.get("kind", "implementation")][r.get("status", "unassessed")] += 1
        total = sum(sum(c.values()) for c in block.values())
        na = sum(c["not_applicable"] for c in block.values())
        passed = sum(c["pass"] for c in block.values())
        applicable = total - na
        complete = applicable > 0 and passed == applicable
        if complete and achieved == lvl - 1:
            achieved = lvl
        levels[f"L{lvl}"] = {
            "total": total, "applicable": applicable, "pass": passed,
            "fail": sum(c["fail"] for c in block.values()),
            "not_verifiable": sum(c["not_verifiable"] for c in block.values()),
            "unassessed": sum(c["unassessed"] for c in block.values()),
            "not_applicable": na,
            "pass_pct_of_applicable": round(100 * passed / applicable, 1) if applicable else None,
            "documentation": dict(block["documentation"]),
            "implementation": dict(block["implementation"]),
        }
    failing = sorted((rid for rid, r in res.items() if r.get("status") == "fail"),
                     key=lambda x: [int(n) for n in x.split("-")[1].split(".")])
    return {"target_level": target, "achieved_level": achieved, "levels": levels, "failing_requirements": failing}


def arch_summary(arch: dict) -> dict:
    dims = arch.get("dimensions", {})
    out, problems = {}, []
    for key, label in ARCH_DIMENSIONS.items():
        d = dims.get(key)
        if d is None:
            problems.append(f"falta la dimensión '{key}'")
            out[key] = {"label": label, "score": None, "level": "no evaluada", "evidence": ""}
            continue
        s = d.get("score")
        if s == "N/A":
            level = "No aplica"
        elif s in ARCH_SCALE:
            level = ARCH_SCALE[s]
        else:
            problems.append(f"'{key}': score debe ser 0-3 o \"N/A\"")
            level = "?"
        if not d.get("evidence"):
            problems.append(f"'{key}': sin evidencia (para N/A, explica por qué no aplica)")
        out[key] = {"label": label, "score": s, "level": level, "evidence": d.get("evidence", "")}
    unknown = set(dims) - set(ARCH_DIMENSIONS)
    if unknown:
        problems.append(f"dimensiones desconocidas: {sorted(unknown)}")
    return {"dimensions": out, "problems": problems, "distribution": dict(Counter(str(v["score"]) for v in out.values()))}


def apply_exceptions(findings: list[dict], exceptions: list[dict], today: dt.date) -> list[str]:
    notes = []
    for ex in exceptions:
        for k in ("owner", "expires", "reason"):
            if not ex.get(k):
                notes.append(f"excepción {ex.get('fingerprint') or ex.get('id')} sin '{k}': se ignora")
                break
        else:
            expired = dt.date.fromisoformat(ex["expires"]) < today
            for f in findings:
                if ex.get("fingerprint") == f["_fp"] or ex.get("id") == f.get("id"):
                    if expired:
                        notes.append(f"excepción de {f['id']} caducó el {ex['expires']} (dueño: {ex['owner']}): vuelve a estar abierto")
                    else:
                        f["_accepted"] = ex
    return notes


def cmd_score(args) -> int:
    fdoc = load_json(args.findings)
    findings = fdoc.get("findings", [])
    for f in findings:
        f["_fp"] = fingerprint(f)
    today = dt.date.today()
    notes = []
    if args.exceptions:
        notes += apply_exceptions(findings, load_json(args.exceptions).get("exceptions", []), today)
    baseline: set = set()
    if args.baseline:
        fps = load_json(args.baseline).get("fingerprints", [])
        baseline = set(fps.values() if isinstance(fps, dict) else fps)  # acepta lista o el objeto {id: huella} de score.json

    def is_open(f):
        return f.get("status", "open") == "open" and "_accepted" not in f

    open_f = [f for f in findings if is_open(f)]
    sev_conf = {s: Counter() for s in SEVERITIES}
    for f in open_f:
        sev_conf[f["severity"]][f["verification"]["status"]] += 1
    report_band = data("verification-policy.json")["confidence_bands"]["report"]

    def blocks(f) -> bool:
        # Un Critical/High bloquea si está demostrado (VERIFIED) o si el camino está trazado (LIKELY) con confianza
        # de informe: que no se puedan ejecutar tests en el entorno de auditoría no debe ablandar el veredicto.
        st = f["verification"]["status"]
        return st == "VERIFIED" or (st == "LIKELY" and float(f.get("confidence", 0)) >= report_band)

    high = [f for f in open_f if f["severity"] in ("Critical", "High")]
    blockers = [f for f in high if blocks(f)]
    doubtful = [f["id"] for f in high if not blocks(f)]
    if blockers:
        verdict = "NO-SHIP"
        verified = [f["id"] for f in blockers if f["verification"]["status"] == "VERIFIED"]
        traced = [f["id"] for f in blockers if f["verification"]["status"] == "LIKELY"]
        why = f"{len(blockers)} hallazgo(s) Critical/High abiertos"
        if verified:
            why += f"; demostrados: {', '.join(verified)}"
        if traced:
            why += f"; trazados en el código, sin test ejecutado (confianza >= {report_band}): {', '.join(traced)}"
    elif doubtful or any("caducó" in n for n in notes):
        verdict = "REVISAR"
        why = "Hay Critical/High sin verificar del todo o excepciones caducadas: " + ", ".join(doubtful or ["excepciones"])
    else:
        verdict = "SHIP"
        why = "Sin Critical/High abiertos. No implica ausencia de vulnerabilidades: ver límites y lo no revisado."

    meta_target = fdoc.get("meta", {}).get("asvs_target")
    checklist = load_json(args.asvs) if args.asvs else None
    target = int((checklist or {}).get("target_level") or meta_target or 2)
    if checklist and meta_target and int(meta_target) != target:
        notes.append(f"meta.asvs_target={meta_target} no coincide con target_level={target} de la checklist; se usa la checklist")
    asvs = asvs_summary(checklist, target) if checklist else None
    if asvs and asvs["levels"][f"L{target}"]["unassessed"]:
        notes.append(f"{asvs['levels'][f'L{target}']['unassessed']} requisitos ASVS sin evaluar: el nivel alcanzado no puede afirmarse más allá de L{asvs['achieved_level']}")
    arch = arch_summary(load_json(args.arch)) if args.arch else None

    mapping = data("owasp-2021-to-2025.json")["2025"]
    top10 = {}
    for cat, info in mapping.items():
        fs = [f for f in open_f if (f.get("owasp") or {}).get("top10_2025") == cat]
        top10[cat] = {"name": info["name"], "from_2021": info["from_2021"], "open": len(fs),
                      "by_severity": dict(Counter(f["severity"] for f in fs))}

    samm = None
    if args.samm:
        s = load_json(args.samm)
        practices = s.get("practices", {})
        outside = sorted(set(practices) - set(SAMM_REPO_VISIBLE))
        if outside:
            notes.append(f"SAMM: {outside} no se infieren bien desde un repo; trátalas como orientativas")
        samm = {"assessed_from_repo": practices, "repo_visible_practices": SAMM_REPO_VISIBLE,
                "not_assessable_from_repo": SAMM_NOT_FROM_REPO,
                "note": "SAMM mide el proceso del equipo; desde un repo solo se infieren algunas prácticas."}

    new = [f["id"] for f in findings if f["_fp"] not in baseline] if baseline else None
    result = {
        "generated": today.isoformat(),
        "meta": fdoc.get("meta", {}),
        "verdict": {"value": verdict, "reason": why},
        "findings": {
            "total": len(findings), "open": len(open_f),
            "accepted_by_exception": [f["id"] for f in findings if "_accepted" in f],
            "severity_x_verification": {k: dict(v) for k, v in sev_conf.items() if v},
            "new_vs_baseline": new,
            "fingerprints": {f["id"]: f["_fp"] for f in findings},
        },
        "asvs": asvs,
        "architecture": arch,
        "samm_partial": samm,
        "top10_2025_rollup": top10,
        "notes": notes,
        "wording_rule": "No usar 'cumple el Top 10'. El Top 10 es un documento de awareness; el nivel de garantía es el de ASVS.",
    }
    write_json(args.out, result)
    if args.md:
        Path(args.md).write_text(render_md(result), encoding="utf-8")
    print(f"Veredicto: {verdict} — {why}")
    if asvs:
        print(f"ASVS: objetivo L{target}, alcanzado L{asvs['achieved_level']}")
    for n in notes:
        print("NOTA:", n)
    if arch and arch["problems"]:
        for p in arch["problems"]:
            print("AVISO scorecard:", p)
    return 0


def render_md(r: dict) -> str:
    L = [f"## Veredicto: {r['verdict']['value']}", "", r["verdict"]["reason"], ""]
    a = r.get("asvs")
    if a:
        L += [f"## ASVS 5.0.0 — objetivo L{a['target_level']}, alcanzado L{a['achieved_level']}", "",
              "| Nivel | Aplicables | Pass | Fail | No verificable | Sin evaluar | No aplica | % pass |",
              "|---|---|---|---|---|---|---|---|"]
        for lvl, v in a["levels"].items():
            pct = "—" if v["pass_pct_of_applicable"] is None else f"{v['pass_pct_of_applicable']}%"
            L.append(f"| {lvl} | {v['applicable']} | {v['pass']} | {v['fail']} | {v['not_verifiable']} | {v['unassessed']} | {v['not_applicable']} | {pct} |")
        L.append("")
        if a["failing_requirements"]:
            L += ["Requisitos que fallan: " + ", ".join(a["failing_requirements"]), ""]
    ar = r.get("architecture")
    if ar:
        L += ["## Scorecard de arquitectura (0–3)", "", "| Dimensión | Nivel | Evidencia |", "|---|---|---|"]
        for v in ar["dimensions"].values():
            s = "—" if v["score"] is None else f"{v['score']} · {v['level']}"
            L.append(f"| {v['label']} | {s} | {v['evidence'][:160]} |")
        L.append("")
    L += ["## Resumen por Top 10:2025 (solo para comunicar)", "", "| Categoría | Equivale en 2021 | Abiertos | Por severidad |", "|---|---|---|---|"]
    for cat, v in r["top10_2025_rollup"].items():
        sev = ", ".join(f"{k}: {n}" for k, n in v["by_severity"].items()) or "—"
        L.append(f"| {cat} {v['name']} | {', '.join(v['from_2021']) or 'nueva'} | {v['open']} | {sev} |")
    L.append("")
    if r["notes"]:
        L += ["## Notas", ""] + [f"- {n}" for n in r["notes"]] + [""]
    return "\n".join(L)


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init-asvs")
    i.add_argument("--level", type=int, choices=(1, 2, 3), required=True)
    i.add_argument("--na-chapters", help="Capítulos o secciones que no aplican, p. ej. V17,V10,V4.3")
    i.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("score")
    s.add_argument("--findings", type=Path, required=True)
    s.add_argument("--asvs", type=Path)
    s.add_argument("--arch", type=Path)
    s.add_argument("--samm", type=Path)
    s.add_argument("--baseline", type=Path)
    s.add_argument("--exceptions", type=Path)
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--md", type=Path)
    args = ap.parse_args()
    return cmd_init(args) if args.cmd == "init-asvs" else cmd_score(args)


if __name__ == "__main__":
    sys.exit(main())

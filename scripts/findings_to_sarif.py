#!/usr/bin/env python3
"""Etapa 8: convierte findings.json a SARIF 2.1.0 para GitHub code scanning, DefectDojo, GitLab, etc.

Uso:
    python3 findings_to_sarif.py <findings.json> --out findings.sarif [--fallback-file docs/security/threat-model.md]

Decisiones que afectan a cómo GitHub agrupa las alertas entre ejecuciones:
  - ruleId estable: se deriva de la clase de fallo (CWE principal + categoría Top 10:2025), no del número del
    hallazgo (IMPL-001...), que cambia entre auditorías. El id del hallazgo va en result.properties.
  - Cada resultado lleva archivo y línea (region.startLine). GitHub calcula su huella primaryLocationLineHash a
    partir del contenido de esa línea; sin línea no hay huella y la alerta se duplica o se pierde. Un hallazgo de
    diseño sin archivo se ancla en --fallback-file, línea 1.
  - partialFingerprints.owaspAuditFingerprint/v1 se mantiene para otras plataformas; GitHub no lo usa.
  - La severidad va en rule.properties["security-severity"] (GitHub: >9.0 critical, 7.0-8.9 high, 4.0-6.9
    medium, 0.1-3.9 low; 0.0 significa "sin severidad", por eso Note se exporta como 1.0).
  - Solo se escribe versionControlProvenance si hay URL del repositorio (GitHub rechaza cadenas vacías).
LIKELY y UNVERIFIED se exportan con level 'note' para que no bloqueen como si estuvieran confirmados.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import data, fingerprint, load_json, utf8_stdout, write_json  # noqa: E402

LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Note": "note"}
SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Note": 1}


def rule_id(f: dict) -> str:
    """Identificador estable de la clase de fallo, p. ej. 'owasp-audit/CWE-639/A01'."""
    cwe = (f.get("cwe") or ["CWE-unknown"])[0]
    cat = (f.get("owasp") or {}).get("top10_2025") or (f.get("owasp") or {}).get("llm_2025") or "NA"
    return f"owasp-audit/{cwe}/{cat}"


def location(f: dict, fallback: str) -> tuple[list[dict], list[dict]]:
    """Devuelve (locations, relatedLocations). Siempre hay una ubicación principal con archivo y línea."""
    locs = []
    for e in f.get("evidence") or []:
        if e.get("file"):
            line = e["line"] if isinstance(e.get("line"), int) and e["line"] >= 1 else 1
            locs.append({"physicalLocation": {"artifactLocation": {"uri": e["file"].replace("\\", "/")},
                                              "region": {"startLine": line}}})
    if not locs:
        locs.append({"physicalLocation": {"artifactLocation": {"uri": fallback}, "region": {"startLine": 1}}})
    related = [{**loc, "id": i} for i, loc in enumerate(locs[1:], 1)]
    return locs[:1], related


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--fallback-file", default="docs/security/threat-model.md",
                    help="Archivo donde anclar hallazgos sin evidencia de archivo (por defecto el threat model)")
    args = ap.parse_args()
    doc = load_json(args.findings)
    sev_map = data("verification-policy.json")["severity_to_sarif_security_severity"]
    rules: dict[str, dict] = {}
    results = []
    for f in doc.get("findings", []):
        o = f.get("owasp") or {}
        tags = ["security"] + list(f.get("cwe") or [])
        tags += [f"OWASP-{o[k]}:{y}" for k, y in (("top10_2025", "2025"), ("top10_2021", "2021")) if o.get(k)]
        tags += [o[k] for k in ("api_2023", "llm_2025", "asi_2026") if o.get(k)]
        tags += [f"ASVS-{a}" for a in f.get("asvs") or []]
        status = (f.get("verification") or {}).get("status", "UNVERIFIED")
        rid = rule_id(f)
        sev = max(float(sev_map.get(f["severity"], 5.5)), 1.0 if f["severity"] == "Note" else 0.0)
        rule = rules.get(rid)
        if rule is None:
            rule = rules[rid] = {
                "id": rid,
                "name": re.sub(r"[^A-Za-z0-9]", "", rid.split("/", 1)[1]),
                "shortDescription": {"text": f["title"]},
                "help": {"text": f"Arquitectura: {f['recommendation'].get('architectural', '')}\n"
                                 f"Arreglo rápido: {f['recommendation'].get('quick_fix', '')}",
                         "markdown": f"**Arquitectura:** {f['recommendation'].get('architectural', '')}\n\n"
                                     f"**Arreglo rápido:** {f['recommendation'].get('quick_fix', '')}"},
                "properties": {"tags": sorted(set(tags)), "security-severity": f"{sev:.1f}", "_rank": 0},
            }
        else:
            rule["properties"]["tags"] = sorted(set(rule["properties"]["tags"]) | set(tags))
        # Varias instancias de la misma clase: la regla lleva la severidad más alta.
        if SEV_RANK.get(f["severity"], 3) > rule["properties"]["_rank"]:
            rule["properties"]["_rank"] = SEV_RANK.get(f["severity"], 3)
            rule["properties"]["security-severity"] = f"{sev:.1f}"
        locs, related = location(f, args.fallback_file)
        result = {
            "ruleId": rid,
            "level": LEVEL.get(f["severity"], "warning") if status == "VERIFIED" else "note",
            "message": {"text": f"[{f['id']}] {f['title']} ({status}, confianza {f.get('confidence')})"},
            "locations": locs,
            "partialFingerprints": {"owaspAuditFingerprint/v1": fingerprint(f)},
            "properties": {"findingId": f["id"], "severity": f["severity"], "verification": status,
                           "confidence": f.get("confidence"), "type": f.get("type"),
                           "component": f.get("component"), "test": f.get("test")},
        }
        if related:
            result["relatedLocations"] = related
        results.append(result)
    for r in rules.values():
        r["properties"].pop("_rank", None)
    meta = doc.get("meta", {})
    run = {
        "tool": {"driver": {"name": "owasp-audit",
                            "informationUri": "https://github.com/alenware/owasp-audit",
                            "semanticVersion": "0.2.0", "rules": list(rules.values())}},
        "results": results,
        "properties": {"model": meta.get("model"), "date": meta.get("date"), "mode": meta.get("mode"),
                       "commit": meta.get("commit")},
    }
    repo = (meta.get("repo") or "").strip()
    commit = (meta.get("commit") or "").strip()
    if repo and commit and commit != "sin-git":
        run["versionControlProvenance"] = [{"repositoryUri": repo, "revisionId": commit}]
    write_json(args.out, {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                          "runs": [run]})
    print(f"{len(results)} resultados en {len(rules)} reglas -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

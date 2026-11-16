#!/usr/bin/env python3
"""Etapa 8: convierte findings.json a SARIF 2.1.0 para GitHub code scanning, DefectDojo, etc.

Uso:
    python findings_to_sarif.py <findings.json> --out findings.sarif

Una regla por hallazgo (ruleId = id del hallazgo). La severidad va en rule.properties["security-severity"]
(GitHub: >9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low). Las etiquetas incluyen CWE y OWASP
(2025, 2021, API, LLM, ASI) y ASVS. Los hallazgos LIKELY y UNVERIFIED se exportan con level 'note' para que
no bloqueen como si estuvieran confirmados; solo VERIFIED usa el nivel derivado de la severidad.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import data, fingerprint, load_json, utf8_stdout, write_json  # noqa: E402

LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Note": "note"}


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    doc = load_json(args.findings)
    sev_map = data("verification-policy.json")["severity_to_sarif_security_severity"]
    rules, results = [], []
    for f in doc.get("findings", []):
        o = f.get("owasp") or {}
        tags = ["security"] + list(f.get("cwe") or [])
        tags += [f"OWASP-{o[k]}:{y}" for k, y in (("top10_2025", "2025"), ("top10_2021", "2021")) if o.get(k)]
        tags += [o[k] for k in ("api_2023", "llm_2025", "asi_2026") if o.get(k)]
        tags += [f"ASVS-{a}" for a in f.get("asvs") or []]
        status = (f.get("verification") or {}).get("status", "UNVERIFIED")
        rules.append({
            "id": f["id"],
            "name": f["id"].replace("-", ""),
            "shortDescription": {"text": f["title"]},
            "fullDescription": {"text": (f.get("attack_scenario") or {}).get("impact", f["title"])},
            "help": {"text": f"Arquitectura: {f['recommendation'].get('architectural', '')}\nArreglo rápido: {f['recommendation'].get('quick_fix', '')}",
                     "markdown": f"**Arquitectura:** {f['recommendation'].get('architectural', '')}\n\n**Arreglo rápido:** {f['recommendation'].get('quick_fix', '')}"},
            "properties": {
                "tags": tags,
                "security-severity": f"{sev_map.get(f['severity'], 5.5):.1f}",
                "precision": "high" if status == "VERIFIED" else "medium" if status == "LIKELY" else "low",
            },
        })
        locs = []
        for e in f.get("evidence") or []:
            if e.get("file"):
                region = {"startLine": e["line"]} if isinstance(e.get("line"), int) else {}
                pl = {"artifactLocation": {"uri": e["file"].replace("\\", "/")}}
                if region:
                    pl["region"] = region
                locs.append({"physicalLocation": pl})
        result = {
            "ruleId": f["id"],
            "level": LEVEL.get(f["severity"], "warning") if status == "VERIFIED" else "note",
            "message": {"text": f"{f['title']} [{status}, confianza {f.get('confidence')}]"},
            "partialFingerprints": {"owaspAuditFingerprint/v1": fingerprint(f)},
            "properties": {"verification": status, "confidence": f.get("confidence"), "type": f.get("type"),
                           "component": f.get("component"), "test": f.get("test")},
        }
        if locs:
            result["locations"] = locs[:1]
            if len(locs) > 1:
                result["relatedLocations"] = [{**l, "id": i} for i, l in enumerate(locs[1:], 1)]
        results.append(result)
    meta = doc.get("meta", {})
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "owasp-audit", "informationUri": "https://owasp.org/www-project-application-security-verification-standard/",
                                "semanticVersion": "0.1.0", "rules": rules}},
            "results": results,
            "versionControlProvenance": [{"repositoryUri": meta.get("repo", ""), "revisionId": meta.get("commit", "")}] if meta.get("commit") else [],
            "properties": {"model": meta.get("model"), "date": meta.get("date"), "mode": meta.get("mode")},
        }],
    }
    write_json(args.out, sarif)
    print(f"{len(results)} resultados -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

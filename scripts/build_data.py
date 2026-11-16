#!/usr/bin/env python3
"""Regenera los datos de referencia de owasp-audit a partir de las fuentes oficiales de OWASP.

Uso:
    python build_data.py <carpeta_fuentes> [--out <carpeta_data>]

La carpeta de fuentes debe contener (se descargan aparte, nunca desde este script):
    asvs-5.0.0.flat.json   https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json
    IndexASVS.md           https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/IndexASVS.md
    top10-2025/A0*_2025-*.md  https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/<archivo>.md

Escribe en data/: asvs-5.0.0.flat.json (copia fiel), asvs-5.0.0.index.json (derivado),
cwe-to-top10-2025.json, asvs5-to-cheatsheets.json y actualiza manifest.json.
Solo usa la biblioteca estándar. Las fuentes se tratan como datos: se parsean, nunca se ejecutan.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

CSS_BASE = "https://cheatsheetseries.owasp.org/"
TOP10_FILE_RE = re.compile(r"^(A\d{2})_2025-(.+)\.md$")
CWE_RE = re.compile(r"CWE-(\d+)")
# Erratas conocidas de las páginas oficiales. A03 lista "CWE-447 Use of Obsolete Function", pero ese nombre
# es el de CWE-477, y el texto de la misma página cita CWE-477 (comprobado 2026-11-16).
ERRATA = {"A03": {"CWE-447": "CWE-477"}}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_asvs(src: Path, out: Path) -> dict:
    raw = json.loads((src / "asvs-5.0.0.flat.json").read_text(encoding="utf-8"))
    reqs = raw["requirements"]
    expected = {"chapter_id", "chapter_name", "section_id", "section_name", "req_id", "req_description", "L"}
    for r in reqs:
        missing = expected - r.keys()
        if missing:
            raise SystemExit(f"Requisito ASVS con campos ausentes {missing}: {r}")
    shutil.copyfile(src / "asvs-5.0.0.flat.json", out / "asvs-5.0.0.flat.json")

    chapters: dict[str, dict] = {}
    for r in reqs:
        ch = chapters.setdefault(r["chapter_id"], {"name": r["chapter_name"], "sections": {}})
        sec = ch["sections"].setdefault(
            r["section_id"],
            {
                "name": r["section_name"],
                # En ASVS 5.0 las secciones "... Documentation" agrupan los requisitos de decisiones documentadas.
                "kind": "documentation" if "documentation" in r["section_name"].lower() else "implementation",
                "requirements": [],
            },
        )
        sec["requirements"].append({"id": r["req_id"], "L": int(r["L"])})
    index = {
        "version": "5.0.0",
        "id_format": "v5.0.0-<chapter>.<section>.<req> (p. ej. v5.0.0-8.2.2)",
        "counts_by_level": {str(l): sum(1 for r in reqs if int(r["L"]) == l) for l in (1, 2, 3)},
        "total": len(reqs),
        "chapters": chapters,
    }
    (out / "asvs-5.0.0.index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"requirements": len(reqs), "counts_by_level": index["counts_by_level"]}


def build_top10(src: Path, out: Path) -> dict:
    folder = src / "top10-2025"
    categories: dict[str, dict] = {}
    cwe_index: dict[str, list[str]] = {}
    for f in sorted(folder.glob("A*_2025-*.md")):
        m = TOP10_FILE_RE.match(f.name)
        if not m:
            continue
        cat_id, slug = m.group(1), m.group(2)
        text = f.read_text(encoding="utf-8")
        marker = text.find("## List of Mapped CWEs")
        if marker < 0:
            raise SystemExit(f"{f.name}: no se encontró la sección 'List of Mapped CWEs'")
        found = {f"CWE-{n}" for n in CWE_RE.findall(text[marker:])}
        for wrong, right in ERRATA.get(cat_id, {}).items():
            if wrong in found:
                found = (found - {wrong}) | {right}
        cwes = sorted(found, key=lambda c: int(c[4:]))
        categories[cat_id] = {
            "name": slug.replace("_", " "),
            "url": f"https://top10.owasp.org/2025/{f.stem}/",
            "cwes": cwes,
        }
        for c in cwes:
            cwe_index.setdefault(c, []).append(cat_id)
    if len(categories) != 10:
        raise SystemExit(f"Se esperaban 10 categorías del Top 10:2025, hay {len(categories)}")
    data = {
        "version": "OWASP Top 10:2025",
        "source": "https://github.com/OWASP/Top10/tree/master/2025/docs/en",
        "note": "Recuentos tomados de cada página de categoría; la Introducción oficial difiere en A03 y A05. Erratas corregidas: " + json.dumps(ERRATA),
        "categories": categories,
        "cwe_index": dict(sorted(cwe_index.items(), key=lambda kv: int(kv[0][4:]))),
    }
    (out / "cwe-to-top10-2025.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return {k: len(v["cwes"]) for k, v in categories.items()}


def build_cheatsheets(src: Path, out: Path) -> dict:
    text = (src / "IndexASVS.md").read_text(encoding="utf-8")
    mapping: dict[str, list[dict]] = {}
    current = None
    for line in text.splitlines():
        h = re.match(r"^###\s+(V\d+\.\d+)\s+(.*)$", line)
        if h:
            current = h.group(1)
            mapping[current] = []
            continue
        if line.startswith("## "):
            current = None
            continue
        if current:
            for title, href in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", line):
                if href.startswith("cheatsheets/"):
                    href = CSS_BASE + href.replace(".md", ".html")
                mapping[current].append({"title": title, "url": href})
    data = {
        "version": "Cheat Sheet Series IndexASVS (ASVS 5.0.x)",
        "source": "https://cheatsheetseries.owasp.org/IndexASVS.html",
        "sections": mapping,
    }
    (out / "asvs5-to-cheatsheets.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"sections": len(mapping), "with_links": sum(1 for v in mapping.values() if v)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", type=Path)
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "data")
    args = ap.parse_args()
    src, out = args.sources.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    summary = {
        "asvs": build_asvs(src, out),
        "top10_2025_cwe_counts": build_top10(src, out),
        "cheatsheets": build_cheatsheets(src, out),
    }
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    manifest["generated"] = dt.date.today().isoformat()
    manifest["generated_files"] = {
        name: sha256(out / name)
        for name in ("asvs-5.0.0.flat.json", "asvs-5.0.0.index.json", "cwe-to-top10-2025.json", "asvs5-to-cheatsheets.json")
    }
    manifest["summary"] = summary
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

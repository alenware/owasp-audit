"""Utilidades compartidas por los scripts de owasp-audit (solo biblioteca estándar)."""
from __future__ import annotations

import hashlib
import json
import sys
from functools import lru_cache
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = SKILL_DIR / "data"

SEVERITIES = ["Critical", "High", "Medium", "Low", "Note"]


def utf8_stdout() -> None:
    """La consola de Windows usa cp1252 por defecto; los textos de OWASP contienen caracteres fuera de ese rango."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def load_json(path: Path | str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: Path | str, data) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


@lru_cache(maxsize=None)
def data(name: str):
    return load_json(DATA_DIR / name)


@lru_cache(maxsize=None)
def asvs_requirements() -> dict[str, dict]:
    """Devuelve {'v5.0.0-8.2.2': {...requisito..., 'kind': 'documentation'|'implementation'}}."""
    out = {}
    for r in data("asvs-5.0.0.flat.json")["requirements"]:
        rid = "v5.0.0-" + r["req_id"].lstrip("V")
        kind = "documentation" if "documentation" in r["section_name"].lower() else "implementation"
        out[rid] = {**r, "id": rid, "level": int(r["L"]), "kind": kind}
    return out


def cwe_to_top10(cwe: str) -> list[str]:
    return data("cwe-to-top10-2025.json")["cwe_index"].get(normalize_cwe(cwe) or "", [])


def normalize_cwe(value: str) -> str | None:
    """Acepta 'CWE-89', 'cwe-089', 'external/cwe/cwe-089', 'CWE-89: SQL Injection'."""
    import re

    m = re.search(r"cwe[-_/ ]?0*(\d+)", value, re.IGNORECASE)
    return f"CWE-{int(m.group(1))}" if m else None


def fingerprint(finding: dict) -> str:
    """Huella estable para línea base y excepciones: CWE principal + componente + primer archivo de evidencia."""
    cwe = (finding.get("cwe") or ["?"])[0]
    files = [e.get("file", "") for e in finding.get("evidence", []) if e.get("file")]
    raw = "|".join([cwe, finding.get("component", ""), files[0] if files else finding.get("title", "")])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

#!/usr/bin/env python3
"""Etapa 5: valida findings.json contra el esquema y contra las reglas de verificación.

Uso:
    python validate_findings.py <findings.json> [--repo <raiz>]

Sale con código 1 si hay errores; imprime errores y avisos. Úsalo en bucle: validar, corregir, volver a validar.

Además del esquema (data/finding.schema.json) comprueba reglas que el esquema no expresa:
  - REFUTED y confianza < 0.5 no van en `findings`, van en `excluded_findings` con su motivo.
  - VERIFIED exige failing_test, tool_corroboration o human en verification.method.
  - Un hallazgo excluido por el verificador debe llevar 'cwe'; si alguna es protegida (cripto, cookies,
    trust boundary) exige human_confirmed=true.
  - Todo Critical/High, y todo hallazgo con CWE protegida, debería llevar second_model o human (aviso).
  - La severidad coincide con la matriz OWASP Risk Rating de likelihood e impact (aviso).
  - Evidencia `code` con archivo y línea; evidencia `absence` con la búsqueda y hits=0.
  - Los IDs de ASVS existen en ASVS 5.0.0; la categoría Top 10:2025 es coherente con las CWEs (aviso).
  - Con --repo: los archivos citados existen y la línea no supera el largo del archivo.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib import asvs_requirements, cwe_to_top10, data, load_json, utf8_stdout  # noqa: E402

ENUMS = {
    "type": {"implementation", "design"},
    "severity": {"Critical", "High", "Medium", "Low", "Note"},
    "verification.status": {"VERIFIED", "LIKELY", "UNVERIFIED", "REFUTED"},
    "verification.method": {"trace", "absence_search", "failing_test", "tool_corroboration", "human", "second_model"},
    "evidence.kind": {"code", "absence", "config", "tool", "test"},
    "stride": {"S", "T", "R", "I", "D", "E"},
    "effort": {"S", "M", "L"},
    "status": {"open", "fixed", "accepted"},
    "filter_stage": {"tool_dedup", "verifier", "confidence_below_0.5", "out_of_scope", "baseline_known", "accepted_exception"},
    "mode": {"audit", "arquitectura"},
}
PATTERNS = {
    "id": r"^(IMPL|DES|LLM|SUP)-[0-9]{3}$",
    "top10_2025": r"^A(0[1-9]|10)$",
    "api_2023": r"^API([1-9]|10)$",
    "llm_2025": r"^LLM(0[1-9]|10)$",
    "asi_2026": r"^ASI(0[1-9]|10)$",
    "asvs": r"^v5\.0\.0-[0-9]+\.[0-9]+\.[0-9]+$",
    "cwe": r"^CWE-[0-9]+$",
}
REQUIRED = ["id", "title", "type", "owasp", "cwe", "component", "evidence", "attack_scenario",
            "compensating_controls", "risk", "severity", "confidence", "verification", "recommendation"]


RR_MATRIX = {  # (impact, likelihood) -> severidad, OWASP Risk Rating Methodology
    ("HIGH", "LOW"): "Medium", ("HIGH", "MEDIUM"): "High", ("HIGH", "HIGH"): "Critical",
    ("MEDIUM", "LOW"): "Low", ("MEDIUM", "MEDIUM"): "Medium", ("MEDIUM", "HIGH"): "High",
    ("LOW", "LOW"): "Note", ("LOW", "MEDIUM"): "Low", ("LOW", "HIGH"): "Medium",
}


def rr_band(v) -> str | None:
    if not isinstance(v, (int, float)):
        return None
    return "LOW" if v < 3 else "MEDIUM" if v < 6 else "HIGH"


def rr_severity(likelihood, impact) -> str | None:
    li, im = rr_band(likelihood), rr_band(impact)
    return RR_MATRIX.get((im, li)) if li and im else None


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def err(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    def warn(self, where: str, msg: str) -> None:
        self.warnings.append(f"{where}: {msg}")


def check_finding(f: dict, rep: Report, repo: Path | None, policy: dict, asvs: dict, ids: set) -> None:
    where = f.get("id", "<sin id>")
    for k in REQUIRED:
        if k not in f or f[k] in (None, "", [], {}):
            if k == "compensating_controls" and f.get(k) == "":
                rep.err(where, "compensating_controls vacío: escribe 'ninguno encontrado' y dónde se buscó")
            else:
                rep.err(where, f"falta el campo obligatorio '{k}'")
    if not re.match(PATTERNS["id"], str(f.get("id", ""))):
        rep.err(where, "id debe tener la forma IMPL-001, DES-001, LLM-001 o SUP-001")
    if f.get("id") in ids:
        rep.err(where, "id duplicado")
    ids.add(f.get("id"))
    for k in ("type", "severity", "effort", "status"):
        if k in f and f[k] is not None and f[k] not in ENUMS[k]:
            rep.err(where, f"{k}='{f[k]}' no es válido ({sorted(ENUMS[k])})")

    owasp = f.get("owasp") or {}
    if "top10_2025" not in owasp:
        rep.err(where, "owasp.top10_2025 es obligatorio (puede ser null solo si es LLM/ASI puro)")
    for k in ("top10_2025", "api_2023", "llm_2025", "asi_2026"):
        v = owasp.get(k)
        if v is not None and not re.match(PATTERNS[k], str(v)):
            rep.err(where, f"owasp.{k}='{v}' no tiene el formato esperado")
    cwes = f.get("cwe") or []
    for c in cwes:
        if not re.match(PATTERNS["cwe"], str(c)):
            rep.err(where, f"CWE '{c}' debe tener la forma CWE-89")
    if owasp.get("top10_2025") and cwes:
        mapped = {cat for c in cwes for cat in cwe_to_top10(c)}
        if mapped and owasp["top10_2025"] not in mapped:
            rep.warn(where, f"top10_2025={owasp['top10_2025']} pero las CWEs mapean a {sorted(mapped)} según OWASP; revisa la categoría")
    for a in f.get("asvs") or []:
        if not re.match(PATTERNS["asvs"], str(a)):
            rep.err(where, f"ASVS '{a}' debe tener la forma v5.0.0-8.2.2")
        elif a not in asvs:
            rep.err(where, f"ASVS '{a}' no existe en ASVS 5.0.0")
    for s in f.get("stride") or []:
        if s not in ENUMS["stride"]:
            rep.err(where, f"STRIDE '{s}' no válido")

    for i, e in enumerate(f.get("evidence") or []):
        ew = f"{where}.evidence[{i}]"
        kind = e.get("kind")
        if kind not in ENUMS["evidence.kind"]:
            rep.err(ew, f"kind='{kind}' no válido")
        if kind in ("code", "config", "test"):
            if not e.get("file"):
                rep.err(ew, f"evidencia '{kind}' sin archivo")
            if kind == "code" and not isinstance(e.get("line"), int):
                rep.err(ew, "evidencia 'code' sin línea entera")
            if repo and e.get("file"):
                p = (repo / e["file"]).resolve()
                if not p.is_file():
                    rep.err(ew, f"el archivo citado no existe: {e['file']}")
                elif isinstance(e.get("line"), int):
                    n = len(p.read_text(encoding="utf-8", errors="replace").splitlines())
                    if e["line"] > n:
                        rep.err(ew, f"línea {e['line']} fuera de rango ({e['file']} tiene {n})")
        if kind == "absence":
            if not e.get("query"):
                rep.err(ew, "una afirmación de ausencia debe citar la búsqueda que se hizo (query)")
            if e.get("hits") != 0:
                rep.err(ew, "evidencia 'absence' requiere hits=0")
        if kind == "tool" and not e.get("tool"):
            rep.err(ew, "evidencia 'tool' sin nombre de herramienta")

    sc = f.get("attack_scenario") or {}
    for k in ("preconditions", "steps", "impact"):
        if not sc.get(k):
            rep.err(where, f"attack_scenario.{k} vacío")
    risk = f.get("risk") or {}
    for k in ("likelihood", "impact"):
        v = risk.get(k)
        if not isinstance(v, (int, float)) or not 0 <= v <= 9:
            rep.err(where, f"risk.{k} debe ser un número entre 0 y 9 (OWASP Risk Rating)")
    expected = rr_severity(risk.get("likelihood"), risk.get("impact"))
    if expected and f.get("severity") and f["severity"] != expected:
        rep.warn(where, f"severity={f['severity']} pero la matriz OWASP RR con likelihood={risk.get('likelihood')} e impact={risk.get('impact')} da {expected}; justifica el ajuste o corrígelo")
    if risk.get("cvss_4_0") and not str(risk["cvss_4_0"]).startswith("CVSS:4.0/"):
        rep.err(where, "risk.cvss_4_0 debe empezar por 'CVSS:4.0/'")
    rec = f.get("recommendation") or {}
    if not rec.get("architectural") or not rec.get("quick_fix"):
        rep.err(where, "recommendation necesita 'architectural' y 'quick_fix'")

    conf = f.get("confidence")
    if not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
        rep.err(where, "confidence debe estar entre 0 y 1")
        conf = None
    ver = f.get("verification") or {}
    status = ver.get("status")
    methods = set(ver.get("method") or [])
    if status not in ENUMS["verification.status"]:
        rep.err(where, f"verification.status='{status}' no válido")
    bad = methods - ENUMS["verification.method"]
    if bad:
        rep.err(where, f"verification.method con valores no válidos: {sorted(bad)}")
    if status == "REFUTED":
        rep.err(where, "un hallazgo REFUTED no va en findings: muévelo a excluded_findings con exclusion_reason")
    if conf is not None and conf < policy["confidence_bands"]["review"]:
        rep.err(where, f"confianza {conf} < {policy['confidence_bands']['review']}: va en excluded_findings (filter_stage confidence_below_0.5)")
    if status == "VERIFIED" and not methods & set(policy["verified_requires_one_of"]):
        rep.err(where, f"VERIFIED exige uno de {policy['verified_requires_one_of']} en verification.method; si no, usa LIKELY")
    if status == "VERIFIED" and "failing_test" in methods and not f.get("test"):
        rep.err(where, "dice failing_test pero el campo 'test' está vacío")
    protected = set(policy["protected_cwes"])
    is_protected = bool(set(cwes) & protected)
    if (f.get("severity") in policy["second_opinion_required_for"]["severities"] or is_protected) and not methods & {"second_model", "human"}:
        rep.warn(where, "Critical/High o CWE protegida sin second_model ni human: pide una segunda opinión antes del informe final")
    if f.get("type") == "implementation" and status == "VERIFIED" and not f.get("test"):
        rep.warn(where, "hallazgo de implementación VERIFIED sin test de regresión")


def main() -> int:
    utf8_stdout()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", type=Path)
    ap.add_argument("--repo", type=Path)
    args = ap.parse_args()
    rep = Report()
    try:
        doc = load_json(args.findings)
    except (OSError, ValueError) as exc:
        print(f"ERROR: no se pudo leer {args.findings}: {exc}")
        return 1
    policy = data("verification-policy.json")
    asvs = asvs_requirements()
    repo = args.repo.resolve() if args.repo else None

    for k in ("meta", "findings", "excluded_findings"):
        if k not in doc:
            rep.err("raíz", f"falta '{k}'")
    meta = doc.get("meta") or {}
    for k in ("commit", "model", "date", "mode", "asvs_target"):
        if meta.get(k) in (None, ""):
            rep.err("meta", f"falta '{k}' (el informe debe poder reproducirse)")
    if meta.get("mode") and meta["mode"] not in ENUMS["mode"]:
        rep.err("meta", f"mode='{meta['mode']}' no válido")
    if meta.get("asvs_target") not in (1, 2, 3, None):
        rep.err("meta", "asvs_target debe ser 1, 2 o 3")

    ids: set = set()
    for f in doc.get("findings") or []:
        check_finding(f, rep, repo, policy, asvs, ids)
    protected = set(policy["protected_cwes"])
    for x in doc.get("excluded_findings") or []:
        where = f"excluded:{x.get('id', '<sin id>')}"
        for k in ("id", "title", "exclusion_reason", "filter_stage"):
            if not x.get(k):
                rep.err(where, f"falta '{k}'")
        if x.get("filter_stage") and x["filter_stage"] not in ENUMS["filter_stage"]:
            rep.err(where, f"filter_stage='{x['filter_stage']}' no válido")
        if len(str(x.get("exclusion_reason", ""))) < 10:
            rep.err(where, "exclusion_reason demasiado corto: explica por qué se descarta")
        if x.get("filter_stage") == "verifier" and not x.get("cwe"):
            rep.err(where, "un descarte del verificador debe llevar 'cwe' para poder aplicar la regla de CWEs protegidas")
        if x.get("filter_stage") == "verifier" and set(x.get("cwe") or []) & protected and not x.get("human_confirmed"):
            rep.err(where, "CWE protegida descartada por el verificador sin human_confirmed=true: devuélvela a findings como 'a revisar' (confianza 0.5-0.8)")

    for w in rep.warnings:
        print("AVISO:", w)
    for e in rep.errors:
        print("ERROR:", e)
    n = len(doc.get("findings") or [])
    print(f"\n{n} hallazgos, {len(doc.get('excluded_findings') or [])} excluidos: {len(rep.errors)} errores, {len(rep.warnings)} avisos")
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())

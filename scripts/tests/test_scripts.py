"""Tests de los scripts de owasp-audit. Ejecutar: python -m unittest discover -s scripts/tests"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent


def run(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(SCRIPTS / script), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


VALID_FINDING = {
    "id": "IMPL-001",
    "title": "GET /api/orders/:id no comprueba la propiedad del pedido",
    "type": "implementation",
    "owasp": {"top10_2025": "A01", "top10_2021": "A01", "api_2023": "API1", "llm_2025": None, "asi_2026": None},
    "asvs": ["v5.0.0-8.2.2"],
    "cwe": ["CWE-639"],
    "stride": ["E", "I"],
    "component": "orders",
    "trust_boundary": "internet->api",
    "evidence": [
        {"kind": "code", "file": "src/orders.js", "line": 3, "snippet": "db.get(req.params.id)"},
        {"kind": "absence", "query": "rg owner src/orders.js", "hits": 0},
    ],
    "attack_scenario": {"preconditions": "cuenta válida", "steps": ["GET con id ajeno"], "impact": "lectura de pedidos ajenos"},
    "compensating_controls": "ninguno encontrado en middleware ni gateway",
    "risk": {"method": "owasp_rr", "likelihood": 7.0, "impact": 5.5, "cvss_4_0": None},
    "severity": "High",
    "confidence": 0.9,
    "verification": {"status": "VERIFIED", "method": ["trace", "failing_test", "second_model"], "verifier": "subagente"},
    "recommendation": {"architectural": "repositorio con scope por usuario", "quick_fix": "filtrar por owner_id"},
    "test": "tests/security/bola.test.js::bob no lee pedido de alice",
}
META = {"commit": "abc123", "model": "claude-opus-5-5", "date": "2026-11-16", "mode": "audit", "asvs_target": 1}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def write(self, name: str, obj) -> Path:
        p = self.tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj, encoding="utf-8")
        return p


class ValidateTests(Base):
    def doc(self, findings=None, excluded=None):
        return {"meta": META, "findings": findings if findings is not None else [VALID_FINDING], "excluded_findings": excluded or []}

    def test_valid_passes(self):
        repo = self.tmp / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "src/orders.js").write_text("a\nb\ndb.get(req.params.id)\n", encoding="utf-8")
        r = run("validate_findings.py", str(self.write("f.json", self.doc())), "--repo", str(repo))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_verified_without_strong_method_fails(self):
        f = copy.deepcopy(VALID_FINDING)
        f["verification"]["method"] = ["trace"]
        r = run("validate_findings.py", str(self.write("f.json", self.doc([f]))))
        self.assertEqual(r.returncode, 1)
        self.assertIn("VERIFIED exige", r.stdout)

    def test_refuted_in_findings_fails(self):
        f = copy.deepcopy(VALID_FINDING)
        f["verification"]["status"] = "REFUTED"
        r = run("validate_findings.py", str(self.write("f.json", self.doc([f]))))
        self.assertIn("REFUTED no va en findings", r.stdout)

    def test_low_confidence_fails(self):
        f = copy.deepcopy(VALID_FINDING)
        f["confidence"] = 0.3
        r = run("validate_findings.py", str(self.write("f.json", self.doc([f]))))
        self.assertIn("excluded_findings", r.stdout)

    def test_unknown_asvs_id_fails(self):
        f = copy.deepcopy(VALID_FINDING)
        f["asvs"] = ["v5.0.0-99.1.1"]
        r = run("validate_findings.py", str(self.write("f.json", self.doc([f]))))
        self.assertIn("no existe en ASVS 5.0.0", r.stdout)

    def test_absence_needs_query(self):
        f = copy.deepcopy(VALID_FINDING)
        f["evidence"] = [{"kind": "absence", "hits": 0}]
        r = run("validate_findings.py", str(self.write("f.json", self.doc([f]))))
        self.assertIn("debe citar la búsqueda", r.stdout)

    def test_protected_cwe_cannot_be_dropped_by_verifier(self):
        ex = [{"id": "IMPL-009", "title": "MD5 para contraseñas", "exclusion_reason": "el verificador cree que no es alcanzable",
               "filter_stage": "verifier", "cwe": ["CWE-328"]}]
        r = run("validate_findings.py", str(self.write("f.json", self.doc(excluded=ex))))
        self.assertEqual(r.returncode, 1)
        self.assertIn("human_confirmed", r.stdout)
        ex[0]["human_confirmed"] = True
        r = run("validate_findings.py", str(self.write("f2.json", self.doc(excluded=ex))))
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_category_mismatch_is_warning(self):
        f = copy.deepcopy(VALID_FINDING)
        f["cwe"] = ["CWE-89"]
        r = run("validate_findings.py", str(self.write("f.json", self.doc([f]))))
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("AVISO", r.stdout)

    def test_missing_line_in_repo_fails(self):
        repo = self.tmp / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "src/orders.js").write_text("una sola línea\n", encoding="utf-8")
        r = run("validate_findings.py", str(self.write("f.json", self.doc())), "--repo", str(repo))
        self.assertIn("fuera de rango", r.stdout)


class IngestTests(Base):
    def test_semgrep_and_codeql_dedup_and_map(self):
        semgrep = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep", "rules": [
            {"id": "sqli", "properties": {"tags": ["CWE-89: SQL Injection", "OWASP-A05:2025 - Injection"]}}]}},
            "results": [{"ruleId": "sqli", "level": "error", "message": {"text": "SQL injection"},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 10}}}]}]}]}
        codeql = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [
            {"id": "py/sql-injection", "properties": {"tags": ["security", "external/cwe/cwe-089"], "security-severity": "8.8"}},
            {"id": "py/weak-hash", "properties": {"tags": ["external/cwe/cwe-328"]}}]}},
            "results": [
                {"ruleId": "py/sql-injection", "level": "warning", "message": {"text": "q"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 10}}}]},
                {"ruleId": "py/weak-hash", "message": {"text": "md5"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "auth.py"}, "region": {"startLine": 4}}}]}]}]}
        out = self.tmp / "tf.json"
        r = run("ingest_sarif.py", str(self.write("s.sarif", semgrep)), str(self.write("c.sarif", codeql)), "--out", str(out))
        self.assertEqual(r.returncode, 0, r.stderr)
        res = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(res["count"], 2)
        sqli = next(c for c in res["candidates"] if c["file"] == "app.py")
        self.assertEqual(sqli["top10_2025"], "A05")
        self.assertEqual(sqli["also_reported_by"], ["CodeQL"])
        weak = next(c for c in res["candidates"] if c["file"] == "auth.py")
        self.assertEqual(weak["cwe"], ["CWE-328"])
        self.assertEqual(weak["top10_2025"], "A04")


class ScoreTests(Base):
    def test_init_and_score_no_ship(self):
        chk = self.tmp / "asvs.json"
        r = run("score.py", "init-asvs", "--level", "1", "--na-chapters", "V17,V10", "--out", str(chk))
        self.assertEqual(r.returncode, 0, r.stderr)
        c = json.loads(chk.read_text(encoding="utf-8"))
        self.assertTrue(all(v["level"] == 1 for v in c["results"].values()))
        for rid, v in c["results"].items():
            if v["status"] == "unassessed":
                v["status"] = "pass"
        c["results"]["v5.0.0-8.2.2"]["status"] = "fail"
        chk.write_text(json.dumps(c), encoding="utf-8")
        arch = {"dimensions": {"authorization_model": {"score": 1, "evidence": "checks dispersos en rutas"}}}
        findings = {"meta": META, "findings": [VALID_FINDING], "excluded_findings": []}
        out, md = self.tmp / "score.json", self.tmp / "score.md"
        r = run("score.py", "score", "--findings", str(self.write("f.json", findings)), "--asvs", str(chk),
                "--arch", str(self.write("a.json", arch)), "--out", str(out), "--md", str(md))
        self.assertEqual(r.returncode, 0, r.stderr)
        s = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(s["verdict"]["value"], "NO-SHIP")
        self.assertEqual(s["asvs"]["achieved_level"], 0)
        self.assertIn("v5.0.0-8.2.2", s["asvs"]["failing_requirements"])
        self.assertEqual(s["top10_2025_rollup"]["A01"]["open"], 1)
        self.assertIn("falta la dimensión", " ".join(s["architecture"]["problems"]))
        self.assertNotIn("cumple", md.read_text(encoding="utf-8").lower())

    def test_traced_critical_blocks_without_executed_test(self):
        f = copy.deepcopy(VALID_FINDING)
        f["severity"] = "Critical"
        f["verification"] = {"status": "LIKELY", "method": ["trace", "absence_search"], "verifier": "subagente"}
        f["confidence"] = 0.9
        out = self.tmp / "s.json"
        run("score.py", "score", "--findings", str(self.write("f.json", {"meta": META, "findings": [f], "excluded_findings": []})), "--out", str(out))
        s = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(s["verdict"]["value"], "NO-SHIP")
        self.assertIn("sin test ejecutado", s["verdict"]["reason"])
        f["confidence"] = 0.7
        run("score.py", "score", "--findings", str(self.write("f.json", {"meta": META, "findings": [f], "excluded_findings": []})), "--out", str(out))
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["verdict"]["value"], "REVISAR")

    def test_exception_and_expiry(self):
        findings = {"meta": META, "findings": [VALID_FINDING], "excluded_findings": []}
        exc = {"exceptions": [{"id": "IMPL-001", "owner": "ana", "expires": "2999-01-01", "reason": "mitigado por WAF temporalmente"}]}
        out = self.tmp / "s.json"
        run("score.py", "score", "--findings", str(self.write("f.json", findings)), "--exceptions", str(self.write("e.json", exc)), "--out", str(out))
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["verdict"]["value"], "SHIP")
        exc["exceptions"][0]["expires"] = "2020-01-01"
        run("score.py", "score", "--findings", str(self.write("f.json", findings)), "--exceptions", str(self.write("e.json", exc)), "--out", str(out))
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["verdict"]["value"], "NO-SHIP")


class SarifTests(Base):
    def test_export(self):
        findings = {"meta": META, "findings": [VALID_FINDING], "excluded_findings": []}
        out = self.tmp / "o.sarif"
        r = run("findings_to_sarif.py", str(self.write("f.json", findings)), "--out", str(out))
        self.assertEqual(r.returncode, 0, r.stderr)
        s = json.loads(out.read_text(encoding="utf-8"))
        rule = s["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["security-severity"], "8.0")
        self.assertIn("CWE-639", rule["properties"]["tags"])
        self.assertEqual(s["runs"][0]["results"][0]["level"], "error")


class DetectStackTests(Base):
    def test_detects_express_llm_and_ci(self):
        repo = self.tmp / "repo"
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / ".github/workflows/ci.yml").write_text("on: push\n", encoding="utf-8")
        (repo / "package.json").write_text(json.dumps({"dependencies": {"express": "4", "@anthropic-ai/sdk": "1", "@modelcontextprotocol/sdk": "1"}}), encoding="utf-8")
        (repo / "src").mkdir()
        (repo / "src/app.js").write_text("//", encoding="utf-8")
        (repo / "node_modules/x").mkdir(parents=True)
        (repo / "node_modules/x/i.js").write_text("//", encoding="utf-8")
        r = run("detect_stack.py", str(repo))
        self.assertEqual(r.returncode, 0, r.stderr)
        s = json.loads(r.stdout)
        self.assertIn("express", s["signals"]["framework"])
        self.assertIn("agentic_top10_2026", s["suggested_catalogs"])
        self.assertTrue(s["missing_lockfile"])
        self.assertEqual(s["languages"].get("javascript"), 1)


if __name__ == "__main__":
    unittest.main()

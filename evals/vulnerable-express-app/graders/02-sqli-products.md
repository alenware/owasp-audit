---
type: llm
focus: trace
weight: 1
---

The report identifies SQL injection in GET /api/products because the search parameter is interpolated into the SQL string in src/routes.js (A05, CWE-89).

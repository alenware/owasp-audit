---
type: llm
focus: trace
weight: 1
---

The report identifies that GET /api/orders/:id in src/routes.js returns any order without checking that it belongs to the requesting user (BOLA / IDOR, OWASP A01 or API1), rated High or Critical.

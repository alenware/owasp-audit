---
type: llm
focus: trace
weight: 1
---

The report identifies that PATCH /api/users/me copies req.body into the user, letting a customer set role to admin (mass assignment / BOPLA / privilege escalation).

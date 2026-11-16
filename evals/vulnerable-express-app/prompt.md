---
tags: [owasp-audit]
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash, Agent]
---

Quiero sacar a producción esta API de la tienda el mes que viene. Hazle una auditoría de seguridad OWASP completa con nivel ASVS L1 y dime si está lista. No tengo la app corriendo ni escáneres instalados, así que no ejecutes herramientas externas. Puedes escribir tests en tests/security/ pero no los ejecutes (no hay node_modules). No me hagas preguntas: asume lo que necesites y anótalo en el informe.

Input files: package.json, README.md, src/, tests/

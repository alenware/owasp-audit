---
tags: [owasp-audit]
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash, Agent]
---

Tenemos un asistente de soporte con IA (FastAPI + Claude) que va a atender a clientes de varias marcas. Antes de abrirlo al público quiero una revisión de seguridad de arquitectura y código según OWASP, con nivel ASVS L2. No ejecutes herramientas externas ni el agente; puedes escribir tests en tests/security/ pero sin ejecutarlos. No me hagas preguntas: asume lo razonable y anótalo.

Input files: requirements.txt, README.md, .mcp.json, app/, tests/

---
tags: [owasp-audit]
max_turns: 80
timeout_seconds: 1800
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash, Agent]
---

Ya arreglamos todo lo que salió en la última revisión de seguridad de tienda-api. ¿Puedes hacer una revisión OWASP con nivel ASVS L1 para confirmar si ya la podemos publicar? No hay app corriendo ni escáneres instalados, así que no ejecutes herramientas externas ni los tests. Puedes escribir tests nuevos en tests/security/ si hacen falta. No me hagas preguntas: asume lo razonable y anótalo.

Input files: package.json, README.md, src/, tests/

# owasp-audit

Una [skill de Claude Code](https://docs.claude.com/en/docs/claude-code/skills) que evalúa la seguridad de un repositorio completo con los estándares de OWASP: threat model, verificación contra ASVS 5.0, revisión de arquitectura, hallazgos con evidencia `archivo:línea` y tests de seguridad para CI.

*English summary: a Claude Code skill that audits a whole codebase against OWASP (ASVS 5.0, Top 10:2025, API Top 10 2023, LLM and Agentic Top 10). It writes a threat model, verified findings with file:line evidence, an ASVS checklist, an architecture scorecard, SARIF and security regression tests. Instructions and reports are in Spanish; requests in English also work.*

## Qué produce

Para un repositorio dado, la skill deja:

- `docs/security/threat-model.md`: diagrama de flujo de datos en Mermaid, trust boundaries, amenazas STRIDE y abuse cases.
- `docs/security/authz-matrix.yaml`: matriz rol × endpoint en borrador, para que una persona la confirme.
- `tests/security/`: un test por hallazgo, escrito para fallar antes del arreglo, en el framework de tests del repo.
- `.owasp-audit/<fecha>/findings.json` y `findings.sarif`: hallazgos validados, listos para GitHub code scanning.
- `.owasp-audit/<fecha>/score.md`: veredicto, nivel ASVS alcanzado con recuentos, scorecard de arquitectura y resumen por Top 10.
- Un informe con lo revisado y una sección fija de lo que **no** se revisó.

## Cómo decide

- **ASVS mide, el Top 10 comunica.** La puntuación se apoya en los 345 requisitos de ASVS 5.0.0. El Top 10 solo se usa para resumir; la skill nunca escribe que un proyecto "cumple el Top 10".
- **Veredicto separado del nivel ASVS.** NO-SHIP si queda un hallazgo Critical o High demostrado, o trazado en el código con confianza ≥ 0,8. Un proyecto puede salir SHIP y aun así no alcanzar L1.
- **Verificación independiente.** Un subagente que no ve el razonamiento de quien encontró el fallo intenta refutar cada hallazgo.
- **Fallos de criptografía, cookies y trust boundaries no se descartan sin una persona.** En OWASP Benchmark, la revisión con LLM descartó entre el 50% y el 85% de los casos reales de esas clases ([arXiv:2601.22952](https://arxiv.org/abs/2601.22952)).
- **Severidad y confianza van por separado.** La severidad usa OWASP Risk Rating. La confianza solo responde si el defecto existe tal como se describe.

## Instalación

Requisitos: Python 3.10 o superior (solo biblioteca estándar) y bash. Funciona en Linux, macOS y WSL.

```bash
git clone https://github.com/alenware/owasp-audit.git
cd owasp-audit
./install.sh            # copia la skill a ~/.claude/skills/owasp-audit
```

Otras opciones:

- `./install.sh --link`: enlace simbólico en lugar de copia, para editar la skill en el repo.
- `./install.sh --project`: instala en `.claude/skills/` del directorio actual.
- `./install.sh --check`: comprueba requisitos y pasa los tests de los scripts sin instalar.

En Windows nativo los scripts también funcionan con `python`, pero las rutas de más de 260 caracteres hacen fallar a Python; WSL evita ese problema.

## Uso

La [guía de uso](docs/GUIA-DE-USO.md) explica paso a paso la instalación, las preguntas iniciales, cómo leer el informe, cómo subir los hallazgos a GitHub y cómo repetir la auditoría.

Desde la raíz del proyecto, en Claude Code:

```
haz una auditoría de seguridad OWASP de este repo, nivel ASVS L2
```

La skill pregunta primero el alcance: modo (`audit` o `arquitectura`), nivel ASVS, si puede ejecutar herramientas y si puede escribir tests. Si el proyecto usa LLM, herramientas de agente o servidores MCP, añade los catálogos LLM Top 10 2025 y Agentic Top 10 2026.

Herramientas opcionales que usa si están instaladas: Semgrep, gitleaks, trufflehog, OSV-Scanner, Trivy, Checkov. Lo que no está instalado aparece en el informe como "no ejecutado".

## Estructura

| Carpeta | Contenido |
|---|---|
| `SKILL.md` | Flujo de 9 etapas que sigue Claude |
| `reference/` | 12 guías: catálogos OWASP, threat modeling, criterios de arquitectura, ASVS, severidad, verificación, herramientas, plantillas de tests, plantilla del informe |
| `data/` | ASVS 5.0.0 oficial, CWE → Top 10:2025, equivalencias 2021 ↔ 2025, ASVS → Cheat Sheets, política de verificación, esquema de hallazgos |
| `scripts/` | `detect_stack.py`, `ingest_sarif.py`, `validate_findings.py`, `score.py`, `findings_to_sarif.py`, `build_data.py` y sus tests |
| `evals/` | Tres apps de prueba con fallos plantados y las comprobaciones de cada caso |

`scripts/build_data.py` regenera los datos de `data/` desde las fuentes oficiales de OWASP cuando salga una edición nueva.

## Evaluación

Tres casos, cada uno ejecutado con la skill y sin ella (Claude Opus 5.5, noviembre de 2026):

| Caso | Con skill | Sin skill |
|---|---|---|
| API Express con 7 fallos plantados | 15 de 15 | 14 de 15 |
| La misma API corregida (falsos positivos) | 7 de 7 | 6 de 7 |
| Agente LLM multi-tenant con herramientas y MCP | 12 de 12 | 12 de 12 |

Sin la skill, el modelo encuentra casi los mismos fallos. La diferencia está en el formato y los entregables: IDs de ASVS 5.0 (sin la skill usó ASVS 4.0.3), veredicto separado del nivel ASVS, hallazgos validados, SARIF, threat model y tests en el repo. Con la skill, cada auditoría consumió unas tres veces más tokens y tiempo (24–30 minutos por caso). Son tres casos pequeños: no indican la tasa de detección en proyectos reales.

## Límites

- Sin una aplicación en ejecución no hay pruebas dinámicas; la revisión es de código.
- Los fallos de lógica de negocio y de autorización se proponen, pero su verificación depende de que una persona confirme la matriz y los abuse cases.
- La salida de un LLM no es determinista: dos ejecuciones pueden diferir. El informe registra modelo, fecha y commit.
- Los nombres del Agentic Top 10 2026 vienen de fuentes secundarias.
- Las apps de `evals/` son vulnerables a propósito. Las credenciales que contienen son inventadas.

## Licencia

- Código, instrucciones y referencias: [MIT](LICENSE).
- `data/asvs-5.0.0.flat.json`, `data/asvs-5.0.0.index.json` y `data/asvs5-to-cheatsheets.json` derivan de [OWASP ASVS](https://github.com/OWASP/ASVS) y de la [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/), publicados por la OWASP Foundation bajo [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Esos archivos mantienen esa licencia. `data/cwe-to-top10-2025.json` recoge las listas de CWE de [OWASP Top 10:2025](https://top10.owasp.org/2025/).

Este proyecto no está afiliado a la OWASP Foundation.

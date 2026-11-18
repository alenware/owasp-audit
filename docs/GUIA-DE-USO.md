# Guía de uso de owasp-audit

Cómo instalar la skill, lanzar una auditoría, leer lo que produce y repetirla cuando el código cambia.

## Índice

1. Requisitos
2. Instalación
3. Primera auditoría
4. Qué te pregunta al empezar
5. Qué deja en el repositorio
6. Cómo leer el resultado
7. Qué hacer después
8. Subir los hallazgos a GitHub
9. Repetir la auditoría
10. Herramientas opcionales
11. Problemas frecuentes
12. Actualizar y desinstalar

## 1. Requisitos

- [Claude Code](https://docs.claude.com/en/docs/claude-code) instalado y con sesión iniciada.
- Python 3.10 o superior. Los scripts solo usan la biblioteca estándar.
- bash, para `install.sh`. En Windows, usa WSL.
- El repositorio que quieres auditar, en una carpeta local.

Comprobación rápida:

```bash
claude --version
python3 --version
```

## 2. Instalación

### Linux, macOS o WSL

```bash
git clone https://github.com/alenware/owasp-audit.git ~/code/owasp-audit
cd ~/code/owasp-audit
./install.sh
```

`install.sh` pasa los tests de los scripts y copia la skill a `~/.claude/skills/owasp-audit`. Opciones:

| Opción | Qué hace |
|---|---|
| `--link` | Crea un enlace simbólico en lugar de copiar. Útil si vas a editar la skill: los cambios del repo se aplican sin reinstalar |
| `--project` | Instala en `.claude/skills/` del directorio actual, solo para ese proyecto |
| `--check` | Comprueba requisitos y pasa los tests, sin instalar nada |

Si ya existe una instalación, la mueve a `owasp-audit.bak.<fecha>` antes de instalar.

### Claude Code en WSL

Si Claude Code solo está instalado en Windows, instálalo también dentro de WSL:

```bash
curl -fsSL https://claude.ai/install.sh | bash
```

Abre una terminal nueva de Ubuntu y ejecuta `claude`. La primera vez te pide iniciar sesión.

### Windows sin WSL

Copia la carpeta del repositorio a `C:\Users\<tu-usuario>\.claude\skills\owasp-audit`. Funciona, con una limitación: Python falla con rutas de más de 260 caracteres (ver la sección 11).

## 3. Primera auditoría

Entra en la carpeta del proyecto y abre Claude Code:

```bash
cd ~/code/mi-proyecto
claude
```

Pídelo con tus palabras. Algunos ejemplos que activan la skill:

```text
haz una auditoría de seguridad OWASP de este repo, nivel ASVS L2
¿esta API está lista para producción en seguridad?
la semana que viene tenemos pentest, revisa el proyecto antes
hazme un threat model del backend y guárdalo en el repo
revisa el agente y sus herramientas contra el OWASP LLM Top 10
```

Si Claude no la carga solo, nómbrala: "usa la skill owasp-audit".

**Cuánto tarda.** En las apps de prueba de `evals/` (de 6 a 10 archivos), cada auditoría completa tardó entre 24 y 30 minutos. En un repo grande tardará más; empieza por un proyecto pequeño.

## 4. Qué te pregunta al empezar

Antes de revisar nada, la skill detecta la tecnología del proyecto y te hace estas preguntas de una vez:

| Pregunta | Opciones | Cómo elegir |
|---|---|---|
| Modo | `audit` o `arquitectura` | `audit` revisa diseño y código. `arquitectura` solo diseño: threat model, scorecard y documentación, sin buscar bugs |
| Nivel ASVS | L1, L2 o L3 | L1 para prototipos o herramientas internas. L2 si hay usuarios, datos personales o pagos. L3 para banca, salud o infraestructura crítica |
| Catálogos | Web y API siempre; LLM, agentes, Mobile, Kubernetes, CI/CD | Propone los que detecta. Por ejemplo, añade LLM y agentes si encuentra un SDK de modelos o un `.mcp.json` |
| Herramientas | Sí o no | Si puede ejecutar las herramientas de análisis que tengas instaladas |
| Tests | Sí o no | Si puede escribir tests en `tests/security/` dentro de una rama nueva |
| App en ejecución | Localhost o nada | Para pruebas dinámicas. Staging solo si das tú el host. Producción nunca |

**Sobre el nivel.** Muchos fallos comunes son requisitos de L2. Por ejemplo, guardar contraseñas con SHA-256 cumple el requisito L1 que prohíbe MD5, pero no el L2 que exige un algoritmo lento como bcrypt o argon2. Si eliges L1, la skill sigue reportando esos fallos, pero no cuentan contra el nivel. Para un producto con usuarios, pide L2.

Si quieres saltarte las preguntas, dalo todo en el primer mensaje:

```text
auditoría OWASP en modo audit, ASVS L2, sin ejecutar herramientas,
puedes escribir tests en una rama nueva pero no los ejecutes
```

## 5. Qué deja en el repositorio

```text
mi-proyecto/
├── .owasp-audit/<fecha>/        artefactos de trabajo (añadido a .gitignore)
│   ├── scope.json               lo que respondiste en la sección 4
│   ├── stack.json, inventory.json
│   ├── findings.json            hallazgos validados
│   ├── findings.sarif           los mismos, para GitHub
│   ├── asvs-checklist.json      estado de cada requisito ASVS
│   ├── arch-scorecard.json      las 12 dimensiones de arquitectura
│   ├── score.json, score.md     veredicto y puntuación
│   └── report.md                el informe
├── docs/security/               lo que se versiona
│   ├── threat-model.md          diagrama de flujo, amenazas y abuse cases
│   ├── authz-matrix.yaml        quién puede acceder a qué (borrador)
│   ├── baseline.json            huellas de los hallazgos de esta auditoría
│   └── exceptions.json          riesgos aceptados, si los hay
└── tests/security/              un test por hallazgo
```

No modifica el código de producción. Para arreglar algo, tienes que pedírselo aparte.

## 6. Cómo leer el resultado

### El veredicto

| Veredicto | Significa |
|---|---|
| **NO-SHIP** | Hay al menos un hallazgo Critical o High demostrado, o trazado en el código con confianza de 0,8 o más. No publiques |
| **REVISAR** | Hay Critical o High con dudas, o alguna excepción caducada. Hace falta que alguien decida |
| **SHIP** | No hay Critical ni High abiertos. No significa que no haya vulnerabilidades |

El veredicto y el nivel ASVS son cosas distintas. Un proyecto puede salir SHIP y no alcanzar L1, por ejemplo si falta documentación o hay fallos medios.

### Cada hallazgo

| Campo | Qué dice |
|---|---|
| `IMPL-`, `DES-`, `LLM-`, `SUP-` | Bug de implementación, defecto de diseño, fallo de LLM o agente, cadena de suministro |
| Severidad | Cuánto daño hace, con el método OWASP Risk Rating (probabilidad × impacto) |
| Confianza | Qué tan seguro está el revisor de que el defecto existe. No mide si es fácil de explotar |
| Estado | VERIFIED (demostrado con un test o una herramienta), LIKELY (camino trazado, sin test ejecutado), UNVERIFIED (con huecos) |
| Evidencia | `archivo:línea` de cada paso, o la búsqueda exacta que demuestra que algo falta |
| Arreglo | Uno arquitectónico, de fondo, y uno rápido |
| Test | El test que falla mientras el fallo exista |

El informe separa los hallazgos en tres grupos:
- **cuerpo**: confianza de 0,8 o más;
- **a revisar**: confianza entre 0,5 y 0,8;
- **endurecimiento**: observaciones de diseño de severidad baja.

Los candidatos descartados aparecen al final, con el motivo.

### ASVS y arquitectura

- **Tabla ASVS:** por cada nivel, cuántos requisitos pasan, fallan, no se pueden verificar desde el repo o no aplican. Lo que no se puede verificar nunca cuenta como pass.
- **Scorecard de arquitectura:** 12 dimensiones de 0 (ausente) a 3 (aplicado y probado). Un sistema sin bugs puede puntuar bajo aquí.

### Lo que no se revisó

El informe termina siempre con esta sección. Léela: dice qué herramientas no se ejecutaron, qué no se puede ver desde el código y qué depende de que una persona confirme algo.

## 7. Qué hacer después

1. **Confirma la matriz de autorización.** Abre `docs/security/authz-matrix.yaml` y revisa qué rol puede llamar a cada ruta. La skill la deja como "pendiente de confirmación humana", porque quién debe acceder a qué lo decides tú.
2. **Revisa el threat model.** Corrige en `docs/security/threat-model.md` lo que la skill no podía saber, como qué servicios son internos o qué datos son sensibles.
3. **Ejecuta los tests de seguridad.** Los hallazgos de implementación tienen un test en `tests/security/` que debe fallar hoy. Si falla por la razón esperada, el hallazgo queda demostrado.

   ```bash
   npx jest tests/security       # proyectos Node
   pytest tests/security -q      # proyectos Python
   ```

4. **Arregla por orden:** NO-SHIP primero, luego "a revisar", luego endurecimiento. Cada arreglo debe poner en verde su test.
5. **Mete los tests en CI.** El informe propone qué comprobaciones bloquean un PR y cuáles van a una ejecución nocturna.

## 8. Subir los hallazgos a GitHub

`findings.sarif` se puede subir a GitHub code scanning. Cada hallazgo aparece en la pestaña **Security** y como aviso en la línea afectada dentro de los pull requests.

Opción manual, con la CLI de GitHub:

```bash
gh api repos/<usuario>/<repo>/code-scanning/sarifs \
  -f commit_sha="$(git rev-parse HEAD)" -f ref="refs/heads/main" \
  -f sarif="$(gzip -c .owasp-audit/<fecha>/findings.sarif | base64 -w0)"
```

Opción en un workflow:

```yaml
- uses: github/codeql-action/upload-sarif@<SHA>   # fija la acción por SHA
  with:
    sarif_file: .owasp-audit/<fecha>/findings.sarif
    category: owasp-audit
```

Code scanning está disponible en repositorios públicos. En privados necesita GitHub Advanced Security.

Cómo se ven en GitHub:
- **Agrupación:** la skill agrupa las alertas por clase de fallo (CWE y categoría del Top 10). Así, la misma alerta se mantiene entre auditorías aunque cambie el número del hallazgo.
- **Gravedad en code scanning:** solo los hallazgos VERIFIED aparecen como error o warning. Los LIKELY y UNVERIFIED se suben como nota para no bloquear como si estuvieran confirmados.

## 9. Repetir la auditoría

Pídela de nuevo cuando cambie el código. En la segunda ejecución:
- actualiza el threat model por diferencias, sin reescribirlo;
- compara con `docs/security/baseline.json` y marca qué hallazgos son nuevos.

**Aceptar un riesgo** con dueño y fecha de caducidad, en `docs/security/exceptions.json`:

```json
{
  "exceptions": [
    {
      "id": "IMPL-004",
      "owner": "ana",
      "expires": "2027-03-31",
      "reason": "Mitigado por el WAF hasta migrar el login"
    }
  ]
}
```

Mientras no caduca, ese hallazgo no bloquea. Cuando caduca, vuelve a abrirse y el veredicto pasa a REVISAR.

## 10. Herramientas opcionales

Si están instaladas y lo permites, la skill las ejecuta y usa sus resultados como punto de partida:

| Herramienta | Qué busca |
|---|---|
| Semgrep | Patrones de código vulnerable (`p/owasp-top-ten`) |
| gitleaks o trufflehog | Secretos en el código y en el historial |
| OSV-Scanner o Trivy | Dependencias con vulnerabilidades conocidas |
| Checkov | Configuración de Docker, Kubernetes y Terraform |

Lo que no está instalado aparece en el informe como "no ejecutado", nunca como "pasa". También acepta SARIF de otras herramientas, como CodeQL, `/security-review` o `claude-security`.

## 11. Problemas frecuentes

| Problema | Solución |
|---|---|
| La skill no se activa | Nómbrala en el mensaje. Comprueba que existe `~/.claude/skills/owasp-audit/SKILL.md` |
| Python falla con `FileNotFoundError` en Windows | La ruta supera 260 caracteres. Trabaja desde WSL o mueve el repo a una ruta más corta |
| `python3` no existe en Windows | Allí se llama `python`. La skill lo tiene en cuenta |
| Tarda mucho | Usa el modo `arquitectura`, o limita la auditoría a una carpeta: "audita solo `src/api`" |
| Demasiados hallazgos "a revisar" | Son los que el verificador no pudo confirmar. Ejecuta sus tests para confirmarlos o descartarlos |
| Quieres revisar solo un PR | Usa `/security-review`. Esta skill evalúa el proyecto entero |

## 12. Actualizar y desinstalar

Si instalaste con `--link`:

```bash
cd ~/code/owasp-audit && git pull
```

Si instalaste copiando:

```bash
cd ~/code/owasp-audit && git pull && ./install.sh
```

Desinstalar:

```bash
rm -r ~/.claude/skills/owasp-audit
```

Si es un enlace simbólico, `rm ~/.claude/skills/owasp-audit` borra solo el enlace y deja intacto el repositorio.

# Herramientas deterministas y puertas de CI (etapas 3 y 7)

Etapa 3: ejecutar lo que el alcance permite, con salida SARIF, e ingerirlo. Etapa 7: proponer en el informe un pipeline con puertas para PR y para la ejecución nocturna.

## Índice

1. Reglas de ejecución
2. Lo que dicen las cifras de precisión
3. Comandos por capa
4. Alternativas con Docker
5. Ingesta y registro de lo no ejecutado
6. Puertas de CI: PR frente a nocturna
7. Pipeline de referencia (GitHub Actions)
8. Archivo de excepciones

**Convención de este archivo:** "(verificar flags)" marca comandos o flags que las notas de investigación no comprobaron contra la documentación actual. Antes de ejecutarlos, consulta `--help` de la versión instalada. Lo que no lleva la marca se leyó en la documentación oficial durante la investigación (noviembre de 2026).

## 1. Reglas de ejecución

- Ejecuta solo lo que `scope.json` permite y lo que `stack.json` → `tools_available` encontró. No instales herramientas por tu cuenta.
- Descargar una imagen Docker o un paquete (`npx`, `pipx run`) es una descarga: necesita permiso explícito del usuario, salvo que ya esté en local.
- Toda salida va a `.owasp-audit/<fecha>/`. Nunca escribas resultados en `docs/` ni en el árbol de código.
- **DAST y fuzzing de API solo contra localhost** (o un host de staging que el usuario haya escrito en el chat). Producción, nunca. Un escaneo activo (ZAP full/API, Schemathesis, Nuclei) contra staging requiere además permiso explícito para ese host.
- Usa `--redact` o equivalente en secretos: el informe nunca contiene el valor de una credencial.
- Las herramientas leen el repo; no ejecutes scripts del repo (`npm install` con `postinstall`, `make`) para preparar un escaneo.

## 2. Lo que dicen las cifras de precisión

OWASP Benchmark Java v1.2, medición independiente de 2026 (Xiong y Zhang, arXiv:2601.22952):

| Herramienta | Precisión | Recall | FPR |
|---|---|---|---|
| CodeQL | 60,3% | 97,0% | 68,2% |
| Semgrep | 56,3% | 90,4% | 74,8% |
| SonarQube | 51,9% | 95,6% | 94,6% |
| Unión de las tres | — | — | 98,3% (1.303 de 1.325 casos limpios marcados por al menos una) |

Qué implica:

- **Más escáneres = más ruido.** La unión casi no deja casos limpios sin marcar. Añade una herramienta solo si cubre una capa que no tenías (SCA, secretos, IaC), no una segunda opinión SAST.
- **Las herramientas producen candidatos, no hallazgos.** Todo lo que sale de aquí pasa por la etapa 5 como cualquier otro candidato. `ingest_sarif.py` los numera `TOOL-NNN` y no les asigna estado.
- Una herramienta que dispara en la misma línea que un candidato semántico sí cuenta como `tool_corroboration` (ver `verificacion.md`).
- Benchmark sintético de un solo lenguaje: sirve para comparar ruido relativo, no como tasa real en tu repo.

## 3. Comandos por capa

Variables: `OUT=.owasp-audit/<fecha>`. Ejecuta desde la raíz del repo.

### SAST

```bash
# Semgrep: ruleset p/owasp-top-ten (reglas con metadatos owasp: de 2025)
semgrep scan --config p/owasp-top-ten --sarif -o $OUT/semgrep.sarif .        # (verificar flags)

# CodeQL CLI. Suite "default" (alta precisión) para puertas;
# "security-extended" (más consultas, más falsos positivos) para auditoría y nocturna.
codeql database create $OUT/codeql-db --language=python --source-root .       # (verificar flags)
codeql database analyze $OUT/codeql-db codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=$OUT/codeql.sarif                            # (verificar flags)

# Bandit (Python): el formato SARIF puede requerir el extra bandit[sarif]
bandit -r src -f sarif -o $OUT/bandit.sarif                                   # (verificar flags)

# gosec (Go)
gosec -fmt sarif -out $OUT/gosec.sarif ./...                                  # (verificar flags)
```

En la auditoría completa usa `security-extended`: el verificador filtra. En una puerta de PR usa la suite `default`.

### Secretos

```bash
# gitleaks: historial completo, valores redactados
gitleaks git --redact --report-format sarif --report-path $OUT/gitleaks.sarif .   # (verificar flags)

# trufflehog: --only-verified comprueba en vivo si la credencial funciona (menos ruido).
# Ojo: verificar significa que trufflehog llama al proveedor de la credencial; pide permiso.
trufflehog git file://. --only-verified --json > $OUT/trufflehog.json             # (verificar flags)
```

trufflehog emite JSON, no SARIF (verificar). Si no hay SARIF, `ingest_sarif.py` no lo lee: anota cada resultado verificado como candidato `SUP-` a mano, con `file:line` y sin el valor del secreto.

### SCA, SBOM y cadena de suministro

```bash
osv-scanner scan source -r --format sarif --output $OUT/osv.sarif .              # (verificar flags)
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL \
  --format sarif --output $OUT/trivy-fs.sarif .                                  # (verificar flags)
syft . -o cyclonedx-json > $OUT/sbom.cdx.json                                    # (verificar flags)
grype sbom:$OUT/sbom.cdx.json -o sarif > $OUT/grype.sarif                        # (verificar flags)
```

Revisa además a mano (no hay herramienta en esta lista que lo cubra entero): lockfiles versionados, `npm ci` en CI, Actions fijadas por SHA, `permissions:` mínimos, ningún `pull_request_target` que haga checkout del código del PR, Dependabot/Renovate configurado. SCA solo conoce avisos publicados: un paquete malicioso nuevo no aparece.

### IaC y contenedores

```bash
checkov -d . -o sarif --output-file-path $OUT                                    # (verificar flags)
trivy config --severity HIGH,CRITICAL --format sarif --output $OUT/trivy-config.sarif .   # (verificar flags)
```

### DAST (solo localhost)

```bash
# ZAP baseline: pasivo, apto para PR. rules.tsv define IGNORE/WARN/FAIL por id de alerta.
docker run --rm --network host -v "$PWD/$OUT:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:3000 -c rules.tsv -J zap-baseline.json -r zap-baseline.html   # (verificar flags)

# ZAP API scan: ACTIVO. Solo localhost o el staging que el usuario nombró, con permiso.
docker run --rm --network host -v "$PWD/$OUT:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t http://localhost:3000/openapi.json -f openapi -J zap-api.json   # (verificar flags)
```

`--network host` no funciona igual en Docker Desktop (Windows/macOS): usa `http://host.docker.internal:3000` como objetivo (verificar). ZAP no produce SARIF nativo (verificar): resume sus alertas FAIL como candidatos a mano.

`.zap/rules.tsv` (tabulador entre columnas):

```text
10038	WARN	(Content Security Policy Header Not Set)
40012	FAIL	(Cross Site Scripting (Reflected))
10096	IGNORE	(Timestamp Disclosure)
```

### Fuzzing de API

```bash
# Schemathesis: checks por nombre; object_level_authorization exige al menos dos peers en [auth.wfc]
st run http://localhost:3000/openapi.json --checks not_a_server_error,ignored_auth,negative_data_rejection
st run http://localhost:3000/openapi.json --checks all --max-response-time 1.5   # "all": (verificar flags)
```

`object_level_authorization` necesita que una persona configure dos identidades con datos propios: sin eso no prueba BOLA. Con fuzzing con estado contra un servidor real, se crean datos: solo contra una base de datos desechable.

### LLM (solo si `+llm`)

```yaml
# promptfoo: preset OWASP LLM 2025
redteam:
  plugins: [owasp:llm]
  strategies: [jailbreak-templates, jailbreak]
```

```bash
npx promptfoo@latest redteam run -c promptfooconfig.yaml -o $OUT/promptfoo.json   # (verificar flags)
python3 -m garak --target_type openai --target_name <modelo> --spec probes.encoding   # ver --list_probes
```

El red teaming es probabilístico: un pase solo dice que los ataques muestreados fallaron. Fija modelo, versión y semilla, y revisa a mano una muestra de los veredictos del juez LLM. Los controles deterministas (LLM05, LLM06, LLM08) se prueban con tests, ver `plantillas-de-tests.md`. Ejecutarlo consume la API del modelo: pide permiso.

## 4. Alternativas con Docker

Si `tools_available` no tiene la herramienta pero sí `docker`, y el usuario permite descargar la imagen:

| Herramienta | Imagen (verificar etiqueta y fija por digest) | Montaje |
|---|---|---|
| Semgrep | `semgrep/semgrep` | `-v "$PWD:/src" -w /src` |
| gitleaks | `ghcr.io/gitleaks/gitleaks` | `-v "$PWD:/repo"` y ruta `/repo` |
| trufflehog | `ghcr.io/trufflesecurity/trufflehog` | `git file:///repo` |
| OSV-Scanner | `ghcr.io/google/osv-scanner` | `scan source -r /src` |
| Trivy | `aquasec/trivy` | `fs /src` o `config /src` |
| Syft / Grype | `anchore/syft`, `anchore/grype` | `/src` |
| Checkov | `bridgecrew/checkov` | `-d /src` |
| ZAP | `ghcr.io/zaproxy/zaproxy:stable` | `/zap/wrk` |

Plantilla: `docker run --rm -v "$PWD:/src:ro" -v "$PWD/$OUT:/out" <imagen> <args>` y escribe la salida en `/out`. Monta el repo en solo lectura (`:ro`). En Git Bash de Windows, antepón `MSYS_NO_PATHCONV=1` para que no reescriba las rutas (verificar).

## 5. Ingesta y registro de lo no ejecutado

```bash
python3 -I "$SKILL_DIR/scripts/ingest_sarif.py" $OUT/*.sarif --repo . --out $OUT/tool-findings.json
```

- Deduplica por (archivo, línea, CWE) y anota `also_reported_by`. Dos herramientas en la misma línea no suben la confianza.
- Para cada herramienta prevista, registra en `scope.json` o en el informe uno de: `ejecutado (versión, comando)`, `no instalado`, `no permitido`, `falló (motivo)`. **Nunca** "pasa" para algo que no se ejecutó.
- Un SARIF previo del usuario (`/security-review`, `claude-security`, otro CI) entra igual por esta vía.

## 6. Puertas de CI: PR frente a nocturna

**Aviso:** OWASP DevSecOps Guideline enumera etapas (secretos, SCA, SAST, IaC, cadena de suministro, DAST) pero **no da umbrales numéricos**. Los de esta tabla son convención de practicantes, no guía de OWASP. Dilo así en el informe.

Principio: el PR se bloquea solo con checks rápidos, de alta precisión y limitados al diff. Lo ruidoso o activo va de noche y abre issues.

| Capa | PR (bloquea) | Nocturna (no bloquea, abre issues) |
|---|---|---|
| Secretos | Cualquier secreto verificado; cualquier hit nuevo de gitleaks | Historial completo |
| SAST | Hallazgo HIGH/ERROR **nuevo** en el diff, con reglas de precisión `default` | CodeQL `security-extended`, rulesets amplios de Semgrep |
| SCA | CVE CRITICAL/HIGH **con parche disponible** en dependencias **nuevas** | Todos los CVE, licencias, monitorización del SBOM |
| IaC/contenedor | Misconfiguration HIGH/CRITICAL en archivos cambiados | Repo completo y reescaneo de imágenes |
| Tests de seguridad generados | 100% en verde | — |
| DAST | Reglas FAIL de ZAP baseline contra la app levantada en el runner | ZAP full/API activo, Nuclei, Schemathesis con estado (dos peers) |
| LLM | Subconjunto determinista (tests LLM05/06/08) | `owasp:llm` completo con umbral de attack success rate por categoría (cero para fugas de secretos reales) |

Mide "tiempo hasta el arreglo" y hallazgos nuevos frente a la línea base, no recuentos brutos.

## 7. Pipeline de referencia (GitHub Actions)

Propuesta para el informe. **No la escribas en `.github/` sin permiso.** Fija cada action por SHA completo de 40 caracteres con la versión en comentario; resuelve el SHA con `git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>` y comprueba que la etiqueta es la publicada (el secuestro de etiqueta de `tj-actions/changed-files` en 2025 robó secretos de CI a muchos repos). Los `<SHA>` de abajo son marcadores.

```yaml
name: security
on:
  pull_request: {}
  schedule: [{ cron: "0 3 * * *" }]
permissions: { contents: read }            # mínimo global; cada job pide solo lo que usa
jobs:
  secrets:                                  # PR: bloquea con cualquier secreto verificado
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA> # v4
        with: { fetch-depth: 0, persist-credentials: false }
      - run: docker run --rm -v "$PWD:/repo:ro" ghcr.io/trufflesecurity/trufflehog@sha256:<DIGEST> git file:///repo --only-verified --fail   # (verificar flags)

  sast:                                     # PR: HIGH nuevos con precisión default
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@<SHA> # v4
        with: { persist-credentials: false }
      - uses: github/codeql-action/init@<SHA> # v3 o v4 (verificar la vigente)
        with:
          languages: javascript-typescript
          queries: ${{ github.event_name == 'schedule' && 'security-extended' || '' }}   # vacío = default (verificar flags)
      - uses: github/codeql-action/analyze@<SHA>
      - run: pipx run semgrep==<VERSIÓN> ci --config p/owasp-top-ten --sarif --output semgrep.sarif   # (verificar flags)
      - uses: github/codeql-action/upload-sarif@<SHA>
        if: always()
        with: { sarif_file: semgrep.sarif }

  sca-iac:                                  # PR: CRITICAL/HIGH con fix; misconfig HIGH
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA> # v4
        with: { persist-credentials: false }
      - run: docker run --rm -v "$PWD:/src:ro" aquasec/trivy@sha256:<DIGEST> fs --scanners vuln,misconfig --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 /src   # (verificar flags)

  security-tests:                           # PR: 100% en verde
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA> # v4
        with: { persist-credentials: false }
      - run: npm ci && npm run test:security

  dast-baseline:                            # PR: reglas FAIL de ZAP baseline, app en localhost del runner
    needs: security-tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA> # v4
        with: { persist-credentials: false }
      - run: npm ci && (npm start &) && npx wait-on http://localhost:3000
      - run: docker run --rm --network host -v "$PWD:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost:3000 -c .zap/rules.tsv   # (verificar flags)

  nightly-deep:                             # Nocturna: activo y ruidoso; abre issues, no bloquea
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    permissions: { contents: read, issues: write }
    steps:
      - uses: actions/checkout@<SHA> # v4
        with: { persist-credentials: false }
      - run: npm ci && (npm start &) && npx wait-on http://localhost:3000
      - run: st run http://localhost:3000/openapi.json --checks all     # dos peers para object_level_authorization (verificar flags)
      - run: npx promptfoo@<VERSIÓN> redteam run -c redteam.yaml       # solo si hay LLM (verificar flags)
```

Notas: `persist-credentials`, `wait-on` y el uso de `queries` vacío para la suite default no se comprobaron en las notas (verificar flags). El diff-aware de Semgrep (`semgrep ci`) y las alertas de PR de CodeQL ya filtran por lo nuevo (verificar el comportamiento en la versión usada). ZAP full scan nocturno se añade igual que el baseline con `zap-full-scan.py` contra localhost. Para staging, el host lo da el usuario y el job usa un entorno protegido de GitHub.

## 8. Archivo de excepciones

`docs/security/exceptions.json`, versionado. `score.py --exceptions` lo lee: cada excepción necesita `owner`, `expires` y `reason`, o se ignora; si `expires` ya pasó, el hallazgo vuelve a estar abierto y el veredicto pasa a REVISAR.

```json
{
  "exceptions": [
    {
      "id": "IMPL-004",
      "owner": "equipo-pagos (ana@example.test)",
      "expires": "2027-02-15",
      "reason": "Endpoint legado que se retira en el sprint 2027-05; acceso restringido por VPN mientras tanto."
    },
    {
      "fingerprint": "9c1e4b7a2d3f6e80",
      "owner": "plataforma",
      "expires": "2026-12-31",
      "reason": "Falso positivo aceptado tras revisión humana: la cookie es de preferencias, sin datos de sesión."
    }
  ]
}
```

- Usa `fingerprint` (de `score.json` → `findings.fingerprints`) cuando el `id` pueda cambiar entre ejecuciones: la huella combina CWE principal, componente y primer archivo de evidencia, así que sobrevive a renumeraciones pero no a mover el código de archivo.
- Caducidad máxima recomendada: 90 días (convención, no norma). Una excepción sin fecha no existe.
- Las listas de ignorados propias de cada herramienta (`.trivyignore`, `osv-scanner.toml` con `ignoreUntil`, `.semgrepignore`) siguen la misma regla: dueño y fecha en un comentario (verificar el formato de cada una).

# Evaluar contra ASVS 5.0.0

Contenido:

1. Qué es y cómo se citan los IDs
2. Capítulos V1–V17 con recuentos por nivel
3. Documentación frente a implementación
4. Estados y evidencia que exige cada uno
5. Lo que suele ser `not_applicable`
6. Lo que suele ser `not_verifiable` desde un repo
7. Procedimiento de evaluación
8. Cómo calcula `score.py` el nivel alcanzado
9. Enlaces de remediación
10. Proactive Controls 2024 citan ASVS 4.0
11. SAMM parcial
12. WSTG

## 1. Qué es y cómo se citan los IDs

ASVS 5.0.0 (30 de mayo de 2025) es la única versión estable de la serie 5.x: 17 capítulos, 345 requisitos, cada uno verificable como pass/fail y con nivel L1, L2 o L3 (70 / 183 / 92). Las ediciones posteriores (5.0.1, "Bleeding Edge") no se usan hasta que se regeneren los datos con `scripts/build_data.py`.

- Cita siempre con versión: `v5.0.0-8.2.2` (minúscula, sin la "V"). En `data/asvs-5.0.0.flat.json` el mismo requisito es `req_id: "V8.2.2"`.
- Las secciones se citan como `V8.2` y los capítulos como `V8`.
- Comprueba cada ID que escribas contra el JSON; `validate_findings.py` da error si un ID no existe.
- No reutilices una auditoría de ASVS 4.0.3: el 38% de sus requisitos dejó de existir como ítem separado y la numeración de capítulos cambió.
- ASVS 5.0 ya no trae CWE ni NIST. Los cruces CWE → Top 10 están en `data/cwe-to-top10-2025.json`.

## 2. Capítulos V1–V17 con recuentos por nivel

Recuentos calculados desde `data/asvs-5.0.0.flat.json`. "Hasta L2" es lo que entra en una checklist L2 (los niveles son acumulativos).

| Cap. | Nombre | L1 | L2 | L3 | Total | Hasta L2 | Sección de documentación |
|---|---|---|---|---|---|---|---|
| V1 | Encoding and Sanitization | 8 | 19 | 3 | 30 | 27 | — (V1.1 es "Architecture", cuenta como implementación) |
| V2 | Validation and Business Logic | 4 | 7 | 2 | 13 | 11 | V2.1 |
| V3 | Web Frontend Security | 8 | 11 | 12 | 31 | 19 | V3.1 (solo L3) |
| V4 | API and Web Service | 2 | 8 | 6 | 16 | 10 | — |
| V5 | File Handling | 4 | 5 | 4 | 13 | 9 | V5.1 |
| V6 | Authentication | 13 | 22 | 12 | 47 | 35 | V6.1 |
| V7 | Session Management | 6 | 12 | 1 | 19 | 18 | V7.1 |
| V8 | Authorization | 4 | 3 | 6 | 13 | 7 | V8.1 |
| V9 | Self-contained Tokens | 4 | 3 | 0 | 7 | 7 | — |
| V10 | OAuth and OIDC | 5 | 24 | 7 | 36 | 29 | — |
| V11 | Cryptography | 3 | 11 | 10 | 24 | 14 | V11.1 |
| V12 | Secure Communication | 3 | 6 | 3 | 12 | 9 | — |
| V13 | Configuration | 1 | 12 | 8 | 21 | 13 | V13.1 |
| V14 | Data Protection | 2 | 7 | 4 | 13 | 9 | V14.1 |
| V15 | Secure Coding and Architecture | 3 | 10 | 8 | 21 | 13 | V15.1 |
| V16 | Security Logging and Error Handling | 0 | 16 | 1 | 17 | 16 | V16.1 |
| V17 | WebRTC | 0 | 7 | 5 | 12 | 7 | — |
| | **Total** | **70** | **183** | **92** | **345** | **253** | |

Ya no existe un capítulo de arquitectura: el diseño está en V15 y en las secciones de documentación que abren cada capítulo. V2 (lógica de negocio), V4 (API) y V8 (autorización) son los capítulos con más intención de diseño.

## 3. Documentación frente a implementación

`score.py` clasifica un requisito como `documentation` si el nombre de su sección contiene "Documentation" (las 11 secciones de la tabla: V2.1, V3.1, V5.1, V6.1, V7.1, V8.1, V11.1, V13.1, V14.1, V15.1, V16.1). Son 31 requisitos: 4 en L1, 17 en L2 y 10 en L3. El resto (314) es `implementation`.

En 5.0 cada requisito de documentación va emparejado con uno de implementación: comprobar que la decisión está escrita y comprobar que el código la cumple son dos verificaciones distintas, y `score.py` las cuenta por separado.

Varios requisitos de implementación se miden **contra lo que dice la documentación**, entre ellos v5.0.0-2.3.2 (límites de negocio), v5.0.0-6.3.1 (credential stuffing y fuerza bruta), v5.0.0-7.3.1 y v5.0.0-7.3.2 (timeouts de sesión), v5.0.0-13.3.4 (rotación de secretos), v5.0.0-15.2.1 y v5.0.0-15.2.2 (plazos de dependencias, funcionalidad costosa), v5.0.0-15.2.5 (funcionalidad peligrosa) y v5.0.0-16.3.3 (eventos de seguridad definidos). Para ellos:

- Si el código no tiene ningún control: `fail`, aunque falte también la documentación.
- Si hay un control pero no hay criterio documentado con el que compararlo: `not_verifiable`, y el requisito de documentación emparejado queda en `fail`.
- Si la documentación existe fuera del repo, pide la ruta; si no la dan, `not_verifiable`.

## 4. Estados y evidencia que exige cada uno

| Estado | Cuándo | Evidencia mínima en `evidence` |
|---|---|---|
| `pass` | El control existe, está en el sitio correcto y cubre todos los caminos revisados | `file:line` del control y cómo se comprobó la cobertura (por ejemplo "aplicado en las 27 rutas: `rg -n` …"), o test que lo demuestra |
| `fail` | Falta el control o hay al menos un camino que lo evita | `file:line` del camino que falla o búsqueda de ausencia con 0 resultados; ID del hallazgo si lo hay |
| `not_verifiable` | Depende de algo que no está en el repo (despliegue, config de cloud, proceso, documento externo) | Qué haría falta para verificarlo ("config TLS del load balancer, no está en el repo") |
| `not_applicable` | La funcionalidad no existe en el sistema | Búsqueda que lo demuestra ("`rg -il 'graphql' --type-add …` = 0; sin dependencia en manifiestos") |
| `unassessed` | No se evaluó en esta ejecución | Vacío; el informe los cuenta |

Reglas:

- `not_verifiable` **nunca** cuenta como `pass`, ni se redondea a `pass` por "lo normal es que esté".
- No marques `not_applicable` para esconder un `fail`: si la app debería tener MFA y no la tiene, v5.0.0-6.3.3 es `fail`; los requisitos de mecanismos de MFA concretos que no existen (V6.5–V6.7) pueden ser `not_applicable` con esa explicación.
- Todo `fail` debe tener un hallazgo con ese ID en `finding.asvs` o una línea que explique por qué no se abrió (por ejemplo, Low agrupado en endurecimiento).
- Las CWEs de cripto, cookies y trust boundary (`protected_cwes`) no pasan de `fail` a `pass` porque lo diga un verificador LLM sin una persona.

## 5. Lo que suele ser `not_applicable`

| Qué | Requisitos | Condición para marcarlo |
|---|---|---|
| WebRTC | Todo V17 | No hay TURN, media server ni signaling; pásalo en `init-asvs --na-chapters V17` |
| OAuth y OIDC | V10 | Ningún flujo OAuth/OIDC. Ojo: "Login con Google" hace a la app cliente → aplican V10.1, V10.2 y V10.5; V10.4, V10.6 y V10.7 solo si la app es servidor de autorización u OpenID Provider. Si aplica en parte, no uses `--na-chapters V10` |
| GraphQL | V4.3 | Sin dependencia ni esquema GraphQL |
| WebSocket | V4.4 | Sin WebSocket |
| Archivos | V5.2–V5.4 | Sin subida, almacenamiento ni descarga de archivos de usuario |
| Código no gestionado | V1.4 | Lenguaje con memoria gestionada y sin extensiones nativas propias |
| Frontend web | Gran parte de V3 | API pura sin HTML; revisa igualmente cabeceras que aplican a APIs (v5.0.0-3.4.1, v5.0.0-3.4.2) |
| Tokens autocontenidos | V9 | Sin JWT ni otros tokens autocontenidos emitidos o aceptados por la app |
| IdP externo | V6.8 | Sin federación de identidad |

`init-asvs --na-chapters` solo acepta capítulos completos. Las secciones sueltas (V4.3, V4.4, V1.4…) márcalas a mano en `asvs-checklist.json`: `"status": "not_applicable"` y la evidencia de ausencia.

## 6. Lo que suele ser `not_verifiable` desde un repo

- Configuración TLS y certificados cuando TLS termina fuera de la app: V12.1, v5.0.0-12.2.2.
- Despliegue real: v5.0.0-13.4.1 (`.git` servido), v5.0.0-13.4.3 (listado de directorios), framing en balanceadores (v5.0.0-4.2.1), salvo que la IaC lo muestre.
- Operación de logs: sincronización de hora (v5.0.0-16.2.2), protección y envío a sistema separado (v5.0.0-16.4.2, v5.0.0-16.4.3) si no hay IaC del pipeline de logs.
- Infraestructura criptográfica: HSM o vault para operaciones (v5.0.0-13.3.3), cifrado de memoria (v5.0.0-11.7.1).
- Procesos y documentos que viven en una wiki: plazos de remediación (v5.0.0-15.1.1), política de claves (v5.0.0-11.1.1), retención (v5.0.0-14.2.7).
- Comportamiento que solo se ve en ejecución y sin app en localhost: notificaciones al usuario (v5.0.0-6.3.5, v5.0.0-6.3.7), terminación de sesiones (V7.4).

Con una app en localhost autorizada, parte de esto pasa a verificable con un test. Anota siempre qué evidencia cerraría el requisito.

## 7. Procedimiento de evaluación

1. Genera la checklist: `python3 -I "$SKILL_DIR/scripts/score.py" init-asvs --level <N> --na-chapters <caps> --out .owasp-audit/<fecha>/asvs-checklist.json`.
2. Marca a mano las secciones `not_applicable` de la sección 5, con evidencia.
3. Evalúa por capítulo o grupo de capítulos (un subagente por grupo si el repo es grande), usando el inventario, el threat model y los hallazgos ya verificados. Cada subagente devuelve solo `status` y `evidence` por ID.
4. Cruza: cada `finding.asvs` con `fail` en la checklist; cada `fail` con su hallazgo o su explicación.
5. En modo `arquitectura`, evalúa como mínimo las 11 secciones de documentación y deja el resto `unassessed`.

Forma de cada entrada (la genera `init-asvs`; tú rellenas `status` y `evidence`):

```json
"v5.0.0-8.2.2": {
  "status": "fail",
  "level": 1,
  "kind": "implementation",
  "section": "V8.2 General Authorization Design",
  "text": "Verify that the application ensures that data-specific access is restricted ...",
  "evidence": "src/orders/routes.ts:42 Order.findById(req.params.id) sin filtro de propietario; IMPL-007"
}
```

## 8. Cómo calcula `score.py` el nivel alcanzado

- El nivel objetivo sale de `findings.json` → `meta.asvs_target` (por defecto 2), no de la checklist. Mantén ambos iguales.
- Para cada nivel L, cuenta todos los requisitos de nivel ≤ L. Aplicables = total − `not_applicable`.
- L está **alcanzado** solo si todos los aplicables hasta L son `pass` y el nivel anterior también está alcanzado. Un solo `fail`, `not_verifiable` o `unassessed` bloquea ese nivel.
- Informa `pass_pct_of_applicable` con su recuento ("L1: 58/66 aplicables, 87,9%"), nunca el porcentaje solo.
- Si quedan `unassessed` en el nivel objetivo, `score.py` añade una nota: el nivel alcanzado no puede afirmarse más allá del calculado.
- Documentación e implementación salen por separado en `levels.Ln.documentation` y `levels.Ln.implementation`. En modo `arquitectura` el nivel alcanzado será casi siempre 0: informa la cobertura de documentación, no un nivel.

Redacción: "nivel ASVS 5.0.0 alcanzado: L1 (66/66 aplicables); L2: 180/240 aplicables, 12 no verificables". Nunca "cumple ASVS" sin nivel y recuento.

## 9. Enlaces de remediación

`data/asvs5-to-cheatsheets.json` → `sections["V8.2"]` devuelve una lista de `{title, url}` de la Cheat Sheet Series para esa sección. Úsala en `finding.remediation_refs` y en la tabla de requisitos fallidos del informe. El índice no tiene entradas para V15, V16 ni V17.2–V17.3: en esos casos enlaza la página de la categoría Top 10:2025 correspondiente o la cheat sheet por nombre, y no inventes URLs.

## 10. Proactive Controls 2024 citan ASVS 4.0

Proactive Controls 2024 (C1–C10) sirve para agrupar remediaciones por práctica defensiva, no para puntuar. Sus páginas citan capítulos de **ASVS 4.0**: su "V4 Access Control" es V8 Authorization en 5.0. Traduce antes de citar. Orientación por nombre (no es un mapeo oficial; solo V4 → V8 está comprobado):

| ASVS 4.0 | ASVS 5.0 |
|---|---|
| V1 Architecture | Repartido: V15 y secciones de documentación |
| V2 Authentication / V3 Session | V6 / V7 y V9 |
| V4 Access Control | V8 |
| V5 Validation, Sanitization and Encoding | V1 y V2 |
| V6 Stored Cryptography | V11 |
| V7 Error Handling and Logging | V16 |
| V8 Data Protection / V9 Communication | V14 / V12 |
| V11 Business Logic / V12 Files / V13 API / V14 Configuration | V2 / V5 / V4 / V13 y V3 |

## 11. SAMM parcial

SAMM v2 mide la madurez del proceso del equipo (15 prácticas, 0–3), no el producto. Nunca lo mezcles con el nivel ASVS ni lo promedies en un número. Desde un repo solo se infieren algunas prácticas:

- Con evidencia razonable: Secure Build (CI, SCA, firma), Secure Deployment (IaC, gestión de secretos en despliegue), Defect Management (`SECURITY.md`, etiquetas de issues, línea base), Security Testing (tests y escáneres en CI).
- Parcial: Threat Assessment (existe un threat model), Security Requirements, Secure Architecture, Architecture Assessment, Requirements-driven Testing.
- No evaluable desde el repo: Strategy and Metrics, Policy and Compliance, Education and Guidance, Incident Management, Environment Management, Operational Management.

Si el usuario lo pide, escribe `samm.json` y pásalo con `--samm`:

```json
{"practices": {"Secure Build": {"score": 1, "evidence": ".github/workflows/ci.yml: tests y lint, sin SCA ni firma"},
               "Defect Management": {"score": 1, "evidence": "SECURITY.md con contacto; sin SLA ni etiquetas de seguridad"}}}
```

## 12. WSTG

ASVS dice qué verificar; WSTG dice cómo probarlo. Sin app en ejecución, la skill hace revisión de código "informada por WSTG". Cita tests como `WSTG-v42-ATHZ-04`: los IDs cambian en la v5 en desarrollo (INPV pasa a INJT y aparecen APIT y WASM), así que fija la versión.

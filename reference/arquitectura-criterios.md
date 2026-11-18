# Scorecard de arquitectura: 12 dimensiones

Contenido:

1. Escala y reglas de puntuación
2. Las 12 dimensiones
3. Exclusiones de `/security-review` que vuelven aquí
4. Del scorecard a los hallazgos
5. `arch-scorecard.json`

## 1. Escala y reglas de puntuación

Cada dimensión se puntúa de 0 a 3, con la misma escala de cuatro niveles que SAMM. `score.py` solo acepta estas claves y estos valores:

| Score | Nivel | Significa |
|---|---|---|
| 0 | Ausente | No hay control, o solo existe en comentarios o en la intención |
| 1 | Ad hoc | El control existe en algunos sitios, reimplementado por cada feature, con huecos |
| 2 | Centralizado | Un único mecanismo compartido (middleware, librería, política, plantilla) que usan todos los caminos revisados |
| 3 | Aplicado y probado | Centralizado, falla cerrado y **hay tests o una puerta de CI** que fallan si alguien lo evita |

Reglas:

- **Puntúa lo que se aplica, no lo que existe.** Una librería de autorización que la mitad de las rutas no llama es un 1, no un 2.
- **No hay 3 sin test.** Cita el test o el job de CI que lo demuestra.
- **Evidencia obligatoria.** `score.py` avisa si `evidence` está vacío. Escribe `file:line`, archivos de config, o la búsqueda exacta con su recuento ("`rg -n 'requireRole' src/routes` = 14 de 31 rutas").
- **La dimensión puntúa el diseño, no los bugs.** Un sistema sin bugs puede sacar 0 en `documented_decisions`; un bug aislado no baja a 0 una dimensión centralizada (va como `IMPL-`).
- **Sin "no aplica" en el script.** `score.py` exige 0–3 en las 12. Si una dimensión no aplica por diseño (por ejemplo `tenant_isolation` en un sistema de un solo cliente), pon 2, empieza la evidencia por "No aplica:" con el motivo verificable, y dilo en el informe. No uses 3 para esto.

## 2. Las 12 dimensiones

Los IDs ASVS son de 5.0.0 y existen en `data/asvs-5.0.0.flat.json`. Úsalos en `finding.asvs` y para cruzar con la checklist.

### 2.1 `trust_boundaries` — Trust boundaries y segmentación

Mapeo: A06, A02 · ASVS v5.0.0-15.1.5, v5.0.0-15.2.5, v5.0.0-13.2.1, v5.0.0-13.2.2, v5.0.0-12.3.5

Busca: el DFD de la etapa 2; redes y servicios separados en compose, K8s o Terraform; si la BD o la cache son accesibles desde fuera; credenciales distintas por servicio; dónde se ejecuta la funcionalidad peligrosa (conversión de documentos, ejecución de código, render de plantillas de usuario, plugins) y si está aislada.

- **0**: todo en un proceso o una red plana; la BD expuesta; servicios internos sin autenticación entre sí.
- **1**: alguna separación (red interna en compose), pero servicios que confían entre sí por estar "dentro" y la funcionalidad peligrosa en el proceso principal.
- **2**: fronteras explícitas en IaC, autenticación servicio a servicio con mínimo privilegio, funcionalidad peligrosa en un worker o sandbox aparte.
- **3**: lo anterior más políticas que lo imponen (NetworkPolicy, security groups en IaC revisado por Checkov) y tests o checks que fallan si se rompe.

### 2.2 `authorization_model` — Modelo de autorización

Mapeo: A01 · API1, API3, API5 · ASVS v5.0.0-8.1.1, v5.0.0-8.2.1, v5.0.0-8.2.2, v5.0.0-8.2.3, v5.0.0-8.3.1, v5.0.0-15.3.3

Busca: dónde se decide el acceso (middleware, decoradores, guards, política tipo OPA/Casbin/Cedar, RLS); cuántas rutas lo usan frente al total; si cada acceso por ID comprueba propiedad; si los campos escribibles están en una lista permitida (mass assignment); si la decisión depende de algo que manda el cliente.

- **0**: solo autenticación; cualquier usuario autenticado accede a cualquier objeto; o el rol viene del cliente.
- **1**: `if user.role == ...` dispersos; comprobación de propiedad en unas rutas sí y en otras no.
- **2**: un punto de política del lado servidor, deny-by-default, con propiedad comprobada en la capa de datos o en un repositorio con scope.
- **3**: lo anterior más matriz rol × endpoint versionada, test que falla si aparece una ruta sin clasificar y tests BOLA con dos usuarios.

### 2.3 `tenant_isolation` — Aislamiento de tenants

Mapeo: A01, A06 · LLM08 si hay RAG · ASVS v5.0.0-8.4.1, v5.0.0-8.2.2, v5.0.0-8.3.3

Busca: de dónde sale el `tenant_id` (contexto autenticado o body/query/cabecera); RLS en Postgres, esquemas por tenant o repositorios que inyectan el filtro; jobs, caches, índices de búsqueda y vectoriales con clave de tenant; exportaciones y reportes.

- **0**: `tenant_id` aceptado del cliente o consultas sin filtro de tenant.
- **1**: filtro añadido a mano en cada consulta; caches o colas sin clave de tenant.
- **2**: el tenant se toma solo del contexto autenticado y se aplica en una capa común (RLS, scope del ORM, repositorio base).
- **3**: lo anterior más tests entre tenants (A no ve datos de B en API, jobs, búsqueda y retrieval).

### 2.4 `secrets_management` — Gestión de secretos

Mapeo: A07 (CWE-798), A04, A02 · NHI Top 10 · ASVS v5.0.0-13.3.1, v5.0.0-13.3.2, v5.0.0-13.3.4, v5.0.0-13.1.4, v5.0.0-13.2.3

Busca: secretos en código, imágenes, `committed_env_files` y en el historial (gitleaks/trufflehog); cómo llegan al runtime (vault, KMS, secret manager, variables del orquestador); OIDC en CI frente a claves de larga vida; scope por entorno; credenciales por defecto.

- **0**: secretos en el repo o en la imagen; la misma clave en todos los entornos.
- **1**: variables de entorno sin gestor; `.env` fuera del repo pero sin rotación ni inventario.
- **2**: gestor de secretos o del orquestador, mínimo privilegio por servicio, OIDC en CI.
- **3**: lo anterior más secret scanning como puerta de PR, inventario y rotación documentada y aplicada.

### 2.5 `crypto_agility` — Agilidad criptográfica

Mapeo: A04 · ASVS v5.0.0-11.1.1, v5.0.0-11.1.2, v5.0.0-11.2.1, v5.0.0-11.2.2, v5.0.0-11.4.2, v5.0.0-9.1.2

Busca: algoritmos fijados en el código frente a configuración; un módulo cripto propio frente a librerías validadas; KDF de contraseñas (argon2id, scrypt, bcrypt, PBKDF2 con parámetros); lista permitida de algoritmos JWT (`alg`); CSPRNG para tokens; inventario cripto.

- **0**: MD5/SHA1 para contraseñas, ECB, `Math.random()` para tokens, JWT sin lista de `alg`.
- **1**: primitivas correctas pero esparcidas y fijadas en cada sitio.
- **2**: un módulo o servicio central que expone operaciones de alto nivel; algoritmos y parámetros configurables; KDF adecuado.
- **3**: lo anterior más inventario cripto, tests (hash de contraseña usa el KDF, `alg:none` rechazado) y reglas SAST de cripto como puerta.

Las CWEs de cripto están en `protected_cwes`: un hallazgo aquí no se refuta sin una persona.

### 2.6 `egress_ssrf` — Egress y SSRF

Mapeo: A01 (CWE-918) · API7, API10 · ASVS v5.0.0-1.3.6, v5.0.0-13.1.1, v5.0.0-13.2.4, v5.0.0-13.2.5, v5.0.0-15.3.2

Busca: todo fetch con URL influida por el usuario (webhooks configurables, previews de enlaces, importar desde URL, render de PDF/HTML); si hay un cliente HTTP común; allowlist de destinos; bloqueo de `169.254.169.254`, `localhost`, rangos privados y DNS rebinding; redirecciones automáticas; egress restringido en red.

- **0**: `requests.get(url_del_usuario)` sin validación, redirecciones activas.
- **1**: validación de esquema o dominio en algún sitio, por cadena, evitable con redirección o IP decimal.
- **2**: un cliente saliente central con allowlist resuelta por IP, sin redirecciones automáticas y metadata bloqueada.
- **3**: lo anterior más egress cerrado en red (proxy o política) y tests que rechazan metadata, `localhost` y redirecciones.

### 2.7 `logging_alerting` — Logging y alertas

Mapeo: A09 · ASVS v5.0.0-16.1.1, v5.0.0-16.2.1, v5.0.0-16.2.5, v5.0.0-16.3.1, v5.0.0-16.3.2, v5.0.0-16.4.1, v5.0.0-16.4.3

Busca: eventos de seguridad (login correcto y fallido, fallos de autorización, cambios de credenciales y roles, errores de validación sospechosos); formato estructurado; qué se registra de PII, tokens o contraseñas; envío a un sistema separado; reglas de alerta y runbooks en el repo.

- **0**: solo `print`/`console.log` de depuración; contraseñas o tokens en logs.
- **1**: logs de aplicación sin eventos de seguridad definidos; sin envío central.
- **2**: logger común con eventos de seguridad estructurados, sin datos sensibles, enviados fuera del host.
- **3**: lo anterior más reglas de alerta versionadas y tests que capturan el evento (`auth.failure` con usuario e IP, sin contraseña).

Que alguien responda a la alerta no se ve en el repo: decláralo en límites.

### 2.8 `exception_handling` — Manejo de excepciones

Mapeo: A10 · ASVS v5.0.0-16.5.1, v5.0.0-16.5.2, v5.0.0-16.5.3, v5.0.0-16.5.4, v5.0.0-2.3.3, v5.0.0-13.4.2

Busca: `catch` vacíos o que devuelven éxito; decisiones de seguridad dentro de `try` que permiten al fallar (fail-open); handler global; transacciones sin rollback; stack traces o mensajes internos en la respuesta; modo debug en producción; comportamiento si el IdP, el servicio de autorización o la BD no responden.

- **0**: errores internos al cliente; un fallo del servicio de autorización deja pasar.
- **1**: algunos handlers; mezcla de fail-open y fail-closed; debug activable por variable sin control.
- **2**: handler global con mensaje genérico, fail-closed en los puntos de decisión de seguridad, transacciones con rollback.
- **3**: lo anterior más tests que fuerzan el fallo (autorización lanza excepción → 403/denegado; 400 sin stack trace).

### 2.9 `supply_chain` — Cadena de suministro

Mapeo: A03, A08 · CI/CD Top 10 · ASVS v5.0.0-15.1.1, v5.0.0-15.1.2, v5.0.0-15.2.1, v5.0.0-15.2.4, v5.0.0-3.6.1

Busca: lockfiles (`missing_lockfile`); SCA en CI; SBOM; Actions fijadas por SHA; `permissions:` mínimos; `pull_request_target` con checkout del PR; registros privados y protección frente a dependency confusion; SRI en scripts de CDN; política de actualización (Dependabot/Renovate) y plazos de remediación documentados.

- **0**: sin lockfile, sin SCA, Actions por tag mutable con permisos amplios.
- **1**: lockfile y Dependabot, pero sin puerta ni plazos; workflows con permisos por defecto.
- **2**: SCA en CI, Actions por SHA, permisos mínimos, SBOM generado, plazos documentados.
- **3**: lo anterior más puerta que bloquea CVEs críticas con parche, procedencia o firma del build y control de origen de dependencias.

### 2.10 `secure_defaults` — Secure defaults y paved road

Mapeo: A02, A06 · ASVS v5.0.0-13.4.2, v5.0.0-13.4.5, v5.0.0-15.2.3, v5.0.0-3.4.1, v5.0.0-3.4.2, v5.0.0-3.3.1, v5.0.0-6.3.2

Busca: configuración por defecto segura (debug off, CORS fijo, cookies `Secure`/`HttpOnly`/`SameSite`, cabeceras HSTS y CSP); librerías compartidas de auth y validación frente a reimplementación por feature; plantillas o generadores de servicios; endpoints de docs, métricas o test expuestos; cuentas por defecto.

- **0**: lo inseguro es lo por defecto (debug true, CORS `*` con credenciales, cookies sin flags).
- **1**: endurecimiento manual en algunos servicios; cada equipo configura lo suyo.
- **2**: middleware o plantilla común que aplica cabeceras, cookies y validación; lo inseguro requiere desactivarlo a propósito.
- **3**: lo anterior más tests o un baseline DAST que fallan si falta una cabecera o un flag.

### 2.11 `abuse_cases` — Abuse cases y límites de negocio

Mapeo: A06 · API4, API6 · ASVS v5.0.0-2.1.3, v5.0.0-2.3.1, v5.0.0-2.3.2, v5.0.0-2.3.4, v5.0.0-2.4.1, v5.0.0-6.3.1, v5.0.0-15.2.2, v5.0.0-15.4.2

Busca: rate limits y cuotas (login, SMS, email, búsquedas, exportaciones, tokens de LLM); idempotency keys en pagos; precios, descuentos y cantidades calculados en el servidor; orden de pasos obligatorio; bloqueos o restricciones únicas contra doble uso; límites de tamaño, paginación y coste de consultas.

- **0**: sin límites; el precio o la cantidad vienen del cliente; operaciones caras ilimitadas.
- **1**: rate limit solo en login o solo en el gateway por IP; resto sin límites.
- **2**: límites por usuario y globales definidos en un sitio, idempotencia y cálculo en servidor en los flujos de valor.
- **3**: lo anterior más abuse cases documentados y tests que los ejercitan (concurrencia, repetición, orden).

### 2.12 `documented_decisions` — Decisiones documentadas

Mapeo: A06 · secciones de documentación de ASVS: v5.0.0-2.1.3, v5.0.0-8.1.1, v5.0.0-11.1.2, v5.0.0-13.1.1, v5.0.0-14.1.1, v5.0.0-15.1.1, v5.0.0-16.1.1

Busca: `docs/security/`, ADRs, `SECURITY.md`, threat model, clasificación de datos, inventario de comunicaciones y de logs, política de autorización escrita. Si la documentación vive fuera del repo (wiki), pregunta dónde y anota que no se verificó.

- **0**: nada escrito.
- **1**: notas sueltas o un README de seguridad genérico sin decisiones concretas.
- **2**: threat model y decisiones clave (authz, datos, cripto, logging) escritas y vigentes.
- **3**: lo anterior más mitigaciones enlazadas a tests y revisión del documento en cada cambio relevante (por ejemplo, check de CI o plantilla de PR).

## 3. Exclusiones de `/security-review` que vuelven aquí

La Action y `/security-review` de Anthropic excluyen por regla DoS y agotamiento de recursos, rate limiting, open redirect y ReDoS. Es razonable en una puerta de PR, pero en una revisión de arquitectura son justo terreno de A06, API4 y API6. Recupéralos como observaciones de diseño:

| Excluido en PR | Dimensión | Mapeo |
|---|---|---|
| DoS / agotamiento de recursos | `abuse_cases` | API4, A06 · v5.0.0-15.1.3, v5.0.0-15.2.2, v5.0.0-4.3.1 si hay GraphQL |
| Rate limiting | `abuse_cases` | API4, API6, A06 (CWE-799) · v5.0.0-2.4.1, v5.0.0-6.3.1 |
| Open redirect | `secure_defaults` | A01 (CWE-601) · v5.0.0-3.7.2 |
| ReDoS | `abuse_cases` | v5.0.0-1.3.12 (L3) |

Repórtalas como `DES-` cuando falta el control en un flujo de valor, o en la sección de endurecimiento (Low/Note) si el impacto es menor. No las descartes.

## 4. Del scorecard a los hallazgos

- Una dimensión en 0 o 1 con riesgo real produce un hallazgo `DES-` (`type: "design"`) que nombra la causa raíz, por ejemplo "La autorización se decide en cada handler; no hay punto de política".
- Los bugs concretos que son síntoma de esa causa van como `IMPL-` y citan el `DES-` en `recommendation.architectural`. Así el informe muestra una causa con varios síntomas en lugar de diez hallazgos sueltos.
- La recomendación arquitectónica de un `DES-` es el cambio que sube la dimensión de nivel; la `quick_fix` tapa el síntoma más grave.
- Los IDs ASVS que cites en la dimensión y en sus hallazgos deben tener el mismo estado en `asvs-checklist.json` (un `DES-` sobre v5.0.0-8.2.2 implica `fail` en ese requisito).

## 5. `arch-scorecard.json`

`score.py` lee `dimensions.<clave>.score` (0–3) y `dimensions.<clave>.evidence` (texto no vacío). Avisa si falta una de las 12 claves o si hay claves desconocidas. Los campos extra (`gaps`, `findings`, `asvs`) los ignora; úsalos para el informe.

```json
{
  "dimensions": {
    "trust_boundaries": {"score": 1, "evidence": "docker-compose.yml:12 db publica 5432 al host; worker y api comparten DATABASE_URL (compose:30,44)", "findings": ["DES-002"]},
    "authorization_model": {"score": 1, "evidence": "rg -n 'requireOwner' src/routes = 9 de 27 rutas con :id; sin política central", "findings": ["DES-001", "IMPL-007"], "asvs": ["v5.0.0-8.2.2"]},
    "tenant_isolation": {"score": 2, "evidence": "No aplica: single-tenant por diseño (docs/adr/003-single-tenant.md); sin tenant_id en el esquema"},
    "secrets_management": {"score": 2, "evidence": "Secretos vía AWS Secrets Manager (infra/secrets.tf:8); OIDC en .github/workflows/deploy.yml:15; gitleaks sin hallazgos"},
    "crypto_agility": {"score": 2, "evidence": "src/lib/crypto.ts centraliza argon2id (l.4) y AES-GCM (l.31); jwt.verify con algorithms:['RS256'] (src/auth/jwt.ts:22)"},
    "egress_ssrf": {"score": 0, "evidence": "src/webhooks/test.ts:18 fetch(body.url) sin allowlist; rg 'allowlist|169.254' src = 0"},
    "logging_alerting": {"score": 1, "evidence": "pino en src/lib/log.ts; no se registran fallos de autorización (rg 'authz.denied' = 0); sin reglas de alerta en el repo"},
    "exception_handling": {"score": 2, "evidence": "Handler global src/app.ts:88 devuelve mensaje genérico; authz cae en deny (src/auth/policy.ts:40)"},
    "supply_chain": {"score": 1, "evidence": "package-lock.json presente; Actions por tag (ci.yml:9 actions/checkout@v4); sin SCA en CI"},
    "secure_defaults": {"score": 2, "evidence": "helmet() en src/app.ts:20; cookies httpOnly/secure/sameSite=lax (src/auth/session.ts:12); CORS con lista fija"},
    "abuse_cases": {"score": 0, "evidence": "rg -n 'rateLimit|idempot' src = 0; precio leído de req.body.price (src/cart/checkout.ts:41)", "findings": ["DES-003"]},
    "documented_decisions": {"score": 1, "evidence": "SECURITY.md genérico; sin threat model previo (este run crea docs/security/threat-model.md)"}
  }
}
```

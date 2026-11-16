# Severidad, confianza y triage

Contenido:

1. Tres campos que no se mezclan
2. OWASP Risk Rating: los 16 factores
3. De los factores a la severidad
4. Hoja de cálculo compacta y ejemplo
5. Cuándo añadir CVSS 4.0
6. Confianza
7. Por qué severidad y confianza nunca se combinan
8. Triage senior frente a junior

## 1. Tres campos que no se mezclan

| Campo en `findings.json` | Qué mide | Cómo se obtiene |
|---|---|---|
| `risk.likelihood`, `risk.impact` (0–9) y `severity` | Cuánto daño y con qué probabilidad, en **este** sistema | OWASP Risk Rating, para todo hallazgo (`risk.method: "owasp_rr"`) |
| `risk.cvss_4_0` (opcional) | Severidad técnica estándar del bug | Vector CVSS 4.0, solo en bugs de implementación que lo justifiquen |
| `confidence` (0–1) | Cuánto crees que el hallazgo es real y explotable | Estado de verificación y huecos del camino |

La severidad tiene consecuencias: `score.py` da NO-SHIP con un Critical o High abierto que esté VERIFIED, o LIKELY con confianza ≥ 0,8 (camino trazado aunque no se haya podido ejecutar un test), y REVISAR con un Critical o High por debajo de eso. No la infles para llamar la atención ni la bajes para dar un veredicto mejor.

## 2. OWASP Risk Rating: los 16 factores

Cada factor se puntúa de 0 a 9. La probabilidad sale de 8 factores (agente de amenaza y vulnerabilidad); el impacto, de 8 (técnico y de negocio). Los valores de anclaje siguen la página de la metodología de OWASP; esta investigación no los recomprobó uno por uno, así que si dudas entre dos, elige y justifica.

**Probabilidad: agente de amenaza**

| Factor | Anclajes |
|---|---|
| Skill level | 1 sin conocimientos técnicos · 3 algunos · 5 usuario avanzado · 6 redes y programación · 9 pentesting |
| Motive | 1 poca o ninguna recompensa · 4 recompensa posible · 9 recompensa alta |
| Opportunity | 0 acceso completo o recursos caros · 4 acceso especial · 7 algo de acceso · 9 sin acceso ni recursos |
| Size | 2 desarrolladores o admins · 4 usuarios de intranet · 5 partners · 6 usuarios autenticados · 9 usuarios anónimos de internet |

**Probabilidad: vulnerabilidad**

| Factor | Anclajes |
|---|---|
| Ease of discovery | 1 prácticamente imposible · 3 difícil · 7 fácil · 9 hay herramientas automáticas |
| Ease of exploit | 1 teórico · 3 difícil · 5 fácil · 9 hay herramientas automáticas |
| Awareness | 1 desconocida · 4 oculta · 6 obvia · 9 conocimiento público |
| Intrusion detection | 1 detección activa en la app · 3 se registra y se revisa · 8 se registra sin revisión · 9 no se registra |

**Impacto técnico**

| Factor | Anclajes |
|---|---|
| Loss of confidentiality | 2 pocos datos no sensibles · 6 pocos datos críticos o muchos no sensibles · 7 muchos datos críticos · 9 todos los datos |
| Loss of integrity | 1 poca corrupción leve · 3 poca corrupción grave · 5 mucha corrupción leve · 7 mucha corrupción grave · 9 todos los datos corruptos |
| Loss of availability | 1 poco servicio secundario · 5 poco servicio primario o mucho secundario · 7 mucho servicio primario · 9 todo perdido |
| Loss of accountability | 1 totalmente trazable · 7 posiblemente trazable · 9 totalmente anónimo |

**Impacto de negocio**

| Factor | Anclajes |
|---|---|
| Financial damage | 1 menos que el coste de arreglarlo · 3 efecto menor en el beneficio anual · 7 efecto significativo · 9 quiebra |
| Reputation damage | 1 mínimo · 4 pérdida de cuentas importantes · 5 pérdida de confianza · 9 daño de marca |
| Non-compliance | 2 violación menor · 5 violación clara · 7 violación de alto perfil |
| Privacy violation | 3 una persona · 5 cientos · 7 miles · 9 millones |

Usa 0 cuando el factor no se ve afectado (por ejemplo, integridad en una lectura indebida).

## 3. De los factores a la severidad

1. **Likelihood** = media de los 8 factores de probabilidad.
2. **Impact** = media de los 4 factores de negocio si los conoces con fundamento (qué datos, cuántas personas, qué regulación); si no, media de los 4 técnicos. Escribe en `verification.notes` o en el informe cuál usaste.
3. Clasifica cada media: **LOW** < 3 · **MEDIUM** 3 a < 6 · **HIGH** 6 a 9.
4. Cruza en la matriz:

| Impacto \ Probabilidad | LOW | MEDIUM | HIGH |
|---|---|---|---|
| **HIGH** | Medium | High | Critical |
| **MEDIUM** | Low | Medium | High |
| **LOW** | Note | Low | Medium |

`risk.likelihood` y `risk.impact` guardan las medias (con un decimal); `severity` guarda la celda de la matriz. Si cambias un factor después de la verificación (por ejemplo, porque apareció un control compensatorio), recalcula; no edites la severidad a mano.

Para hallazgos de diseño (`DES-`), puntúa el escenario más grave que la causa raíz permite hoy, no la suma de todos los síntomas.

## 4. Hoja de cálculo compacta y ejemplo

Copia este bloque en tus notas de trabajo por cada hallazgo:

```
ID:
Agente:        skill __  motive __  opportunity __  size __
Vulnerabilidad: discovery __  exploit __  awareness __  detection __
Likelihood = suma/8 = __  -> LOW | MEDIUM | HIGH
Técnico:  conf __  integ __  avail __  account __      media __
Negocio:  financ __  reput __  compliance __  privacy __  media __
Impact usado: técnico | negocio = __  -> LOW | MEDIUM | HIGH
Matriz -> severity:
Controles compensatorios que cambiaron algún factor (file:line):
```

Ejemplo, IMPL-007 "GET /api/orders/:id no comprueba la propiedad del pedido":

```
Agente:        skill 5  motive 4  opportunity 7 (basta una cuenta)  size 6 (usuarios autenticados)
Vulnerabilidad: discovery 7  exploit 5  awareness 6  detection 9 (no se registran fallos de authz)
Likelihood = 49/8 = 6,1 -> HIGH
Técnico:  conf 7  integ 0  avail 0  account 7         media 3,5
Negocio:  financ 3  reput 5  compliance 5  privacy 7   media 5,0
Impact usado: negocio = 5,0 -> MEDIUM
Matriz -> High
```

## 5. Cuándo añadir CVSS 4.0

- Añade `risk.cvss_4_0` solo a hallazgos `IMPL-` con un camino concreto y explotable (injection, BOLA en un endpoint, deserialización, SSRF), cuando el destino lo va a consumir (SARIF, Jira, DefectDojo) o el usuario lo pide.
- No lo uses en hallazgos de diseño: CVSS describe una vulnerabilidad técnica concreta y encaja mal con "falta un punto de política".
- Escribe solo el vector Base, empezando por `CVSS:4.0/` (el esquema lo exige), por ejemplo `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`. Métricas Base: AV, AC, AT, PR, UI y el impacto separado entre el sistema vulnerable (VC, VI, VA) y los sistemas posteriores (SC, SI, SA). Los grupos Threat, Environmental y Supplemental son opcionales; las puntuaciones se etiquetan CVSS-B, CVSS-BT, CVSS-BE o CVSS-BTE según los grupos usados.
- No calcules a mano la puntuación numérica: si hace falta, usa la calculadora oficial de FIRST.
- El detalle de CVSS 4.0 de esta referencia no se verificó en esta investigación contra la especificación de FIRST. Contrástalo antes de depender de él.
- La severidad del informe sigue siendo la de OWASP RR. Si CVSS y RR discrepan mucho, explica por qué (normalmente, el contexto de negocio o un control compensatorio).

## 6. Confianza

Bandas (de `data/verification-policy.json`, iguales en `validate_findings.py`):

| Confianza | Destino | Estado típico |
|---|---|---|
| ≥ 0,8 | Cuerpo del informe | VERIFIED (test que falla, herramienta en la misma línea o persona) o LIKELY con el camino trazado completo |
| 0,5 – < 0,8 | Sección "a revisar" | LIKELY con una precondición sin confirmar, o UNVERIFIED |
| < 0,5 | `excluded_findings` con `filter_stage: "confidence_below_0.5"` y motivo | — (el validador da error si queda en `findings`) |

Cómo fijarla:

- Parte del estado de verificación y baja por cada hueco: un salto del camino sin `file:line`, una precondición que el atacante quizá no cumpla, un control compensatorio que no pudiste ver (otro repo, gateway, WAF).
- Las CWEs de `protected_cwes` (cripto, cookies, trust boundary) que el verificador LLM quería refutar quedan, como mucho, en 0,5–0,8: el LLM descarta la mayoría de los casos reales de esas clases.
- Si el verificador falló o se agotó el tiempo, conserva el hallazgo con la confianza que tenía.
- Las observaciones de diseño Low o Note con confianza alta no se descartan: van a la sección de endurecimiento.

## 7. Por qué severidad y confianza nunca se combinan

Un Critical con confianza 0,5 y un Low con confianza 0,95 piden acciones distintas: el primero, verificarlo hoy; el segundo, programarlo. Un número combinado (por ejemplo, severidad × confianza) los pondría a la misma altura y escondería lo que importa. Por eso:

- No ordenes el informe por un producto de ambos. Ordena por severidad y, dentro de cada severidad, separa "confirmados" de "a revisar".
- No bajes la severidad porque dudas: baja la confianza. No subas la confianza porque el hallazgo es grave.
- `score.py` cruza severidad y estado de verificación en una tabla (`severity_x_verification`), sin fundirlos.

## 8. Triage senior frente a junior

Antes de asignar severidad a un candidato, responde las cuatro preguntas. Si alguna es "no", el hallazgo baja de confianza o se excluye con el motivo:

1. **¿El atacante controla la entrada?** Di de dónde viene el dato (request, webhook, archivo, salida de un LLM, otro tenant) y quién puede enviarlo.
2. **¿Hay un camino alcanzable de la fuente al sink?** Con `file:line` en cada salto; una ruta registrada pero detrás de una feature flag apagada no es alcanzable hoy.
3. **¿Qué alcance tiene el daño?** Un registro, un tenant, todos los tenants, la infraestructura.
4. **¿Puede el atacante cumplir todas las precondiciones?** Cuenta, rol, conocer un ID, estar en la red interna, ganar una carrera.

Busca **controles compensatorios** antes de puntuar: middleware o guard aplicado más arriba, reglas del gateway, política de red o servicio privado, validación o RLS en otra capa, auto-escapado del framework, consultas parametrizadas del ORM. Un control compensatorio verificado baja factores concretos (Opportunity, Ease of exploit, Size), no la severidad por decreto. Uno que no puedes ver (otro repo, consola cloud) no baja nada: anótalo en `compensating_controls` como "no verificable" y en límites. Escribe siempre ese campo; si no hay, "ninguno encontrado" y dónde buscaste.

**Causa raíz frente a síntomas.** Diez endpoints sin comprobación de propiedad no son diez hallazgos High independientes: son un `DES-` ("la autorización se decide en cada handler") y los `IMPL-` más graves como síntomas que lo citan. La recomendación arquitectónica arregla la clase; la `quick_fix`, el síntoma.

| Junior | Senior |
|---|---|
| Parte de patrones ("usa MD5", "no hay rate limit") | Parte de los activos y del threat model |
| Severidad según la clase de vulnerabilidad | Severidad según probabilidad e impacto en este sistema (MD5 para un ETag no es un hallazgo; para contraseñas, sí) |
| Lista plana y larga | Pocos hallazgos que aguantan, agrupados por causa raíz |
| Ignora lo que hay alrededor | Busca controles compensatorios y precondiciones |
| Consejo genérico | Arreglo arquitectónico + parche local + test que lo demuestra |
| Calla lo que no revisó | Declara lo no revisado y con cuánta confianza |

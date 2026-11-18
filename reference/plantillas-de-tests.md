# Plantillas de tests de seguridad (etapa 7)

Plantillas para adaptar al repo. Usa el framework de tests que el repo ya tiene; no añadas uno nuevo. Cada plantilla indica su stack, el hallazgo o la categoría que cubre y los IDs ASVS que comprueba.

## Índice

1. Reglas comunes (rojo antes del arreglo)
2. Formato de `docs/security/authz-matrix.yaml`
3. BOLA con dos usuarios
4. Matriz rol × endpoint y "cada ruta está clasificada"
5. Mass assignment (BOPLA)
6. Lista permitida de campos en la respuesta
7. Fail-closed
8. A10: entrada malformada
9. Rate limit y bloqueo por fuerza bruta
10. Rotación de sesión y logout
11. SSRF
12. JWT: `alg:none` y clave equivocada
13. Logging de seguridad
14. LLM05, LLM06 y LLM08

## 1. Reglas comunes

- **Rojo antes del arreglo.** Un test de regresión de un hallazgo tiene que **fallar en el commit auditado**. Si pasa, o el hallazgo es falso (vuelve a la etapa 5) o el test no prueba lo que dice.
- **Falla por la razón correcta.** El fallo esperado es la aserción de seguridad (200 en vez de 403), no un error de montaje, una ruta mal escrita o un 404 por un ID inexistente. Cada test de autorización lleva un **control positivo**: el dueño sí accede.
- Ejecuta los tests solo con aprobación. Si fallan como se esperaba, añade `failing_test` a `verification.method` y rellena `test` con `ruta::nombre`; el hallazgo puede subir a VERIFIED.
- Ubicación: `tests/security/`. Nombre con el ID del hallazgo en un comentario (`IMPL-001`).
- Datos: usuarios y tenants de prueba creados por el propio test o por las fixtures del repo. Nunca credenciales reales ni bases de datos compartidas.
- Los tests de controles que aún no existen (diseño, `DES-`) se marcan como esperados en rojo (`xfail`, `it.failing`) hasta que se implemente el control, y se dice así en el informe.

## 2. Formato de `docs/security/authz-matrix.yaml`

El borrador lo escribe la skill a partir de las rutas encontradas; **quién debe acceder a qué lo decide una persona**. Mientras no lo confirme, todo queda "pendiente de confirmación humana".

```yaml
version: 1
status: "pendiente de confirmación humana"   # pasa a "confirmada" solo tras revisión de una persona
confirmed_by: null                           # nombre y fecha de quien la revisa
source_commit: "<sha de git rev-parse HEAD>"
roles: [anon, user, admin]
public:                                      # rutas sin autenticación; también se confirman
  - { method: GET,  path: /health }
  - { method: POST, path: /auth/login }
routes:
  - method: GET
    path: /api/orders/{id}
    expect: { anon: 401, user: 200, admin: 200 }
    owner_scoped: true                       # además del rol, solo el dueño (genera test BOLA)
    evidence: "src/orders/routes.ts:40"      # dónde se define la ruta
    status: "pendiente de confirmación humana"
  - method: DELETE
    path: /admin/users/{id}
    expect: { anon: 401, user: 403, admin: 204 }
    evidence: "src/admin/routes.ts:12"
    status: "confirmada"
```

Rutas con parámetros `{nombre}`; los tests normalizan `:id` (Express) y `<int:id>` (Flask) a `{id}`.

## 3. BOLA con dos usuarios

API1 · A01 · v5.0.0-8.2.2. **Jest + supertest (Node/Express, NestJS, Fastify con inject):**

```ts
// tests/security/bola.orders.test.ts — IMPL-001
import request from "supertest";
import { app } from "../../src/app";          // ajusta a cómo exporta la app el repo
import { loginAs } from "./helpers";           // crea el usuario de prueba y devuelve su token

describe("BOLA /api/orders/:id", () => {
  let alice: string, bob: string, id: string;
  beforeAll(async () => {
    alice = await loginAs("alice@test.local");
    bob = await loginAs("bob@test.local");
    const r = await request(app).post("/api/orders").set("Authorization", `Bearer ${alice}`).send({ sku: "X1" });
    id = r.body.id;
  });
  it("alice lee su pedido (control positivo)", async () => {
    const r = await request(app).get(`/api/orders/${id}`).set("Authorization", `Bearer ${alice}`);
    expect(r.status).toBe(200);
  });
  it.each(["get", "put", "delete"] as const)("bob no puede hacer %s sobre el pedido de alice", async (m) => {
    const r = await request(app)[m](`/api/orders/${id}`).set("Authorization", `Bearer ${bob}`).send({ sku: "HACK" });
    expect([403, 404]).toContain(r.status);    // nunca 200/204; después, comprueba que el pedido no cambió
  });
});
```

**pytest (FastAPI `TestClient` o `requests`; con Flask `test_client` usa `r.get_json()` en vez de `r.json()`):**

```python
# tests/security/test_bola_orders.py — IMPL-001
def test_bob_no_lee_pedido_de_alice(client, make_user):
    alice, bob = make_user("alice"), make_user("bob")        # fixtures: devuelven cabeceras con token
    oid = client.post("/api/orders", json={"sku": "X1"}, headers=alice).json()["id"]
    assert client.get(f"/api/orders/{oid}", headers=alice).status_code == 200   # control positivo
    for metodo in ("get", "put", "delete"):
        r = getattr(client, metodo)(f"/api/orders/{oid}", headers=bob)
        assert r.status_code in (403, 404), f"{metodo} devolvió {r.status_code}"
```

## 4. Matriz rol × endpoint y "cada ruta está clasificada"

API5 · A01 · v5.0.0-8.2.1, v5.0.0-8.1.1. **pytest**, alimentado por la matriz:

```python
# tests/security/test_authz_matrix.py
import os, re, yaml, pytest
M = yaml.safe_load(open("docs/security/authz-matrix.yaml", encoding="utf-8"))
INCLUIR_PENDIENTES = os.getenv("AUTHZ_INCLUDE_PENDING") == "1"   # en la auditoría: 1; en la puerta de CI: solo confirmadas
CASOS = [(r["method"], r["path"], rol, esp)
         for r in M["routes"] if INCLUIR_PENDIENTES or r.get("status") == "confirmada"
         for rol, esp in r["expect"].items()]

@pytest.mark.parametrize("method,path,rol,esperado", CASOS)
def test_matriz(client, tokens, ids, method, path, rol, esperado):
    h = {} if rol == "anon" else {"Authorization": f"Bearer {tokens[rol]}"}
    r = client.request(method, path.format(**ids), headers=h)    # ids: objetos de prueba del propio rol
    assert r.status_code == esperado

def norm(p):                                    # :id y <int:id> -> {id}
    return re.sub(r"<(?:\w+:)?(\w+)>|:(\w+)", lambda m: "{%s}" % (m[1] or m[2]), p)

CLASIFICADAS = {(r["method"], r["path"]) for r in M["routes"] + M["public"]}

def test_cada_ruta_esta_clasificada(rutas_de_la_app):           # deny-by-default en CI
    faltan = {(m, norm(p)) for m, p in rutas_de_la_app} - CLASIFICADAS
    assert not faltan, f"Rutas sin clasificar en authz-matrix.yaml: {sorted(faltan)}"
```

Fixture `rutas_de_la_app` según el framework:

```python
# Flask
rutas = [(m, r.rule) for r in app.url_map.iter_rules() for m in r.methods - {"HEAD", "OPTIONS"} if r.endpoint != "static"]
# FastAPI
from fastapi.routing import APIRoute
rutas = [(m, r.path) for r in app.routes if isinstance(r, APIRoute) for m in r.methods]
```

```ts
// Express 4 (app._router) o 5 (app.router). Solo rutas de primer nivel: con routers montados
// con prefijo, usa express-list-endpoints (verificar) o una tabla de rutas propia.
function rutas(app: any): [string, string][] {
  const stack = (app._router ?? app.router).stack;
  return stack.filter((l: any) => l.route).flatMap((l: any) =>
    Object.keys(l.route.methods).map((m) => [m.toUpperCase(), l.route.path] as [string, string]));
}
```

```java
// Spring Boot: enumerar los mappings registrados
@Autowired RequestMappingHandlerMapping mapping;
@Test void cadaRutaEstaClasificada() {
  var rutas = mapping.getHandlerMethods().keySet().stream()
      .flatMap(i -> i.getMethodsCondition().getMethods().stream()
          .flatMap(m -> i.getPathPatternsCondition().getPatternValues().stream().map(p -> m + " " + p)))
      .collect(Collectors.toSet());
  rutas.removeAll(Matriz.cargar("docs/security/authz-matrix.yaml"));   // helper propio que devuelve "GET /ruta"
  assertTrue(rutas.isEmpty(), "Rutas sin clasificar: " + rutas);
}
```

## 5. Mass assignment (BOPLA)

API3 · A08 · v5.0.0-15.3.3, v5.0.0-8.2.3. **pytest:**

```python
def test_usuario_no_se_asigna_campos_protegidos(client, make_user):
    h = make_user("mallory")
    r = client.patch("/api/me", json={"name": "M", "role": "admin", "is_verified": True,
                                      "tenant_id": "otro", "balance": 10**6}, headers=h)
    assert r.status_code in (200, 400, 422)
    me = client.get("/api/me", headers=h).json()
    assert me["role"] == "user" and me.get("is_verified") is not True        # no cambió
    assert me.get("tenant_id") != "otro" and me.get("balance", 0) < 10**6
```

## 6. Lista permitida de campos en la respuesta

API3 · A01 · v5.0.0-15.3.1. **Jest + supertest:**

```ts
const PERMITIDOS = new Set(["id", "name", "email", "createdAt"]);   // de la documentación o la matriz
it("GET /api/users/:id no devuelve campos internos", async () => {
  const r = await request(app).get(`/api/users/${aliceId}`).set("Authorization", `Bearer ${alice}`);
  const extra = Object.keys(r.body).filter((k) => !PERMITIDOS.has(k));
  expect(extra).toEqual([]);                    // falla con passwordHash, resetToken, role interno...
});
```

## 7. Fail-closed

A10 · A01 · v5.0.0-16.5.3. Si el servicio de autorización lanza una excepción o no responde, se deniega. **Jest:**

```ts
import * as authz from "../../src/authz";       // el módulo que toma la decisión
it("si el servicio de autorización falla, se deniega", async () => {
  jest.spyOn(authz, "check").mockRejectedValue(new Error("timeout"));
  const r = await request(app).get(`/api/orders/${id}`).set("Authorization", `Bearer ${alice}`);
  expect([403, 503]).toContain(r.status);       // nunca 200
});
```

En pytest: define `def falla(*a, **k): raise TimeoutError()`, aplica `monkeypatch.setattr("app.authz.check", falla)` y usa la misma aserción.

## 8. A10: entrada malformada

A10 · v5.0.0-16.5.1. **pytest** (con Flask `test_client`, `data=` en vez de `content=`):

```python
import pytest
MALFORMADOS = ['{"sku":', '[]', '{"qty": "1e309"}', '{"qty": -1}', "\x00" * 10]
@pytest.mark.parametrize("cuerpo", MALFORMADOS)
def test_entrada_malformada_400_sin_detalles(client, make_user, cuerpo):
    r = client.post("/api/orders", content=cuerpo, headers={**make_user("a"), "Content-Type": "application/json"})
    assert 400 <= r.status_code < 500                     # nunca 500
    for fuga in ("Traceback", 'File "', "at java.", "goroutine", "SQLSTATE", "node_modules"):
        assert fuga not in r.text                         # sin stack trace ni detalles internos
```

## 9. Rate limit y bloqueo por fuerza bruta

A07 · API4 · v5.0.0-6.3.1. Comprueba primero que el entorno de test no desactiva el rate limit; si lo hace, actívalo solo en este test. **pytest:**

```python
def test_bloqueo_tras_fallos(client, crear_usuario):
    crear_usuario("alice", "Correcta-123456")
    codigos = [client.post("/auth/login", json={"user": "alice", "password": f"mala{i}"}).status_code
               for i in range(11)]
    assert 429 in codigos or 423 in codigos               # se limita antes del intento 11
    r = client.post("/auth/login", json={"user": "alice", "password": "Correcta-123456"})
    assert r.status_code in (423, 429)                    # el bloqueo afecta también a la contraseña buena
```

Ajusta el umbral (10) al documentado (v5.0.0-6.1.1). Si no hay umbral documentado, eso es un hallazgo de diseño.

## 10. Rotación de sesión y logout

A07 · v5.0.0-7.2.4, v5.0.0-7.4.1. **pytest (sesión por cookie; con JWT, cambia la cookie por el refresh token):**

```python
def test_sesion_rota_al_login_y_muere_al_logout(client, crear_usuario):
    crear_usuario("alice", "Correcta-123456")
    client.get("/")                                          # sesión anónima
    antes = client.cookies.get("session")
    client.post("/auth/login", json={"user": "alice", "password": "Correcta-123456"})
    despues = client.cookies.get("session")
    assert despues and despues != antes                      # nuevo identificador al autenticar
    client.post("/auth/logout")
    client.cookies.set("session", despues)                   # reutiliza la cookie vieja
    assert client.get("/api/me").status_code == 401          # el servidor la invalidó
```

## 11. SSRF

A01 · API7 · v5.0.0-1.3.6, v5.0.0-15.3.2. **pytest** sobre el endpoint que descarga URLs. `httpserver` es el fixture de `pytest-httpserver` (verificar), que sirve la redirección:

```python
import pytest
INTERNAS = ["http://169.254.169.254/latest/meta-data/", "http://localhost:6379/", "http://127.0.0.1/",
            "http://[::1]/", "http://0.0.0.0/", "http://2130706433/", "file:///etc/passwd"]

@pytest.mark.parametrize("url", INTERNAS)
def test_rechaza_destinos_internos(client, make_user, url):
    r = client.post("/api/import", json={"url": url}, headers=make_user("a"))
    assert r.status_code in (400, 403, 422)

def test_no_sigue_redirecciones_a_metadata(client, make_user, httpserver):
    httpserver.expect_request("/r").respond_with_data("", status=302,
        headers={"Location": "http://169.254.169.254/latest/meta-data/"})
    r = client.post("/api/import", json={"url": httpserver.url_for("/r")}, headers=make_user("a"))
    assert r.status_code in (400, 403, 422) and "ami-id" not in r.text
```

El servidor de prueba escucha en localhost: si la app rechaza localhost (bien), permite solo ese puerto en la config de test y documéntalo.

## 12. JWT: `alg:none` y clave equivocada

A07 · A04 · v5.0.0-9.1.1, v5.0.0-9.1.2. **pytest + PyJWT:**

```python
import base64, json, time, jwt
def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
CLAIMS = {"sub": "alice", "role": "admin", "exp": int(time.time()) + 600}

def test_rechaza_alg_none(client):
    token = f'{b64({"alg": "none", "typ": "JWT"})}.{b64(CLAIMS)}.'          # sin firma
    assert client.get("/api/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

def test_rechaza_clave_equivocada(client):
    token = jwt.encode(CLAIMS, "clave-que-no-es-la-del-servidor", algorithm="HS256")
    assert client.get("/api/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
# Añade: exp en el pasado y, si el servidor usa RS256, un HS256 firmado con la clave pública.
```

## 13. Logging de seguridad

A09 · v5.0.0-16.3.1, v5.0.0-16.2.5. **pytest con `caplog`** (si el repo usa structlog o un logger JSON, captura su salida):

```python
import logging
def test_fallo_de_login_se_registra_sin_contrasena(client, caplog, crear_usuario):
    crear_usuario("alice", "Correcta-123456")
    with caplog.at_level(logging.INFO):
        client.post("/auth/login", json={"user": "alice", "password": "Secreta-NO-LOG-987"})
    texto = "\n".join(r.getMessage() + str(getattr(r, "__dict__", "")) for r in caplog.records)
    assert "auth.failure" in texto and "alice" in texto  # evento con usuario (y, si existe, IP)
    assert "Secreta-NO-LOG-987" not in texto              # nunca la contraseña
```

Prueba que el evento existe; si alguien responde a la alerta no se ve desde el repo.

## 14. LLM05, LLM06 y LLM08

Tests deterministas: el modelo se sustituye por un doble que devuelve una salida fija. El modelo nunca es la frontera de seguridad.

**LLM05 · salida maliciosa por el sanitizer real** (v5.0.0-1.2.1). pytest:

```python
MALICIOSAS = ['<img src=x onerror=alert(1)>', '[clic](javascript:alert(1))', '<script>fetch("//x")</script>']
@pytest.mark.parametrize("salida", MALICIOSAS)
def test_salida_del_modelo_se_sanea(monkeypatch, salida):
    monkeypatch.setattr("app.llm.complete", lambda *a, **k: salida)   # doble del modelo
    html = render_chat_answer("pregunta cualquiera")                   # la función real que pinta la respuesta
    assert "onerror" not in html and "javascript:" not in html and "<script" not in html
```

**LLM06 · herramienta invocada por un usuario sin privilegios** (v5.0.0-8.2.1). pytest:

```python
def test_herramienta_admin_denegada_a_usuario(monkeypatch):
    llamada = {"tool": "delete_user", "args": {"user_id": "bob"}}       # lo que "pide" el modelo
    ejecutada = []
    monkeypatch.setattr("app.tools.delete_user", lambda **k: ejecutada.append(k))
    res = dispatch_tool_call(llamada, actor=Usuario(id="mallory", role="user"))   # capa de herramientas real
    assert res.denied and not ejecutada          # se deniega en la capa de herramientas, no en el prompt
```

**LLM08 · retrieval por tenant** (v5.0.0-8.4.1). pytest:

```python
def test_retrieval_no_cruza_tenants(vector_store):
    vector_store.add("Contrato secreto de B: precio 42", tenant_id="B")
    vector_store.add("Manual de A", tenant_id="A")
    chunks = retrieve("precio del contrato secreto de B", ctx=Contexto(tenant_id="A"))   # consulta pensada para B
    assert chunks and all(c.tenant_id == "A" for c in chunks)
    # el tenant sale del contexto autenticado; pasarlo en el texto o en el body no lo cambia
    assert all(c.tenant_id == "A" for c in retrieve("tenant_id=B precio", ctx=Contexto(tenant_id="A")))
```

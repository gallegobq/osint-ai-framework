# Orquestación de búsquedas OSINT

## Objetivo

Una búsqueda orquestada recibe un objetivo, un perfil y, opcionalmente, blancos
tipados. El perfil `auto` permite que Ollama proponga fuentes complementarias;
los perfiles reproducibles seleccionan módulos mediante política determinista.
En ambos casos el servidor valida el plan antes de crear trabajos. El modelo
nunca ejecuta código, construye URLs, aporta credenciales ni llama una
herramienta directamente.

Flujo:

1. La API exige `collection:execute`, rol de proyecto `editor` y confirmación de
   uso autorizado.
2. La capa de servicio normaliza dominios, IP públicas, ASN, URL públicas,
   usuarios o palabras clave. Si se omiten, extrae únicamente patrones
   explícitos del objetivo; si no hay ninguno, usa el objetivo como palabra clave.
3. El perfil filtra el catálogo. Sólo `auto` consulta Ollama; los demás perfiles
   producen el mismo plan para el mismo catálogo, blancos y límite.
4. Pydantic y `SearchPlanner` eliminan herramientas desconocidas,
   incompatibles, repetidas, activas no autorizadas o superiores al límite.
5. El worker crea un `collection_job` auditable por paso y ejecuta los
   adaptadores secuencialmente para respetar cuotas.
6. La evidencia conserva fuente, localizador, contenido, hash y fecha. El
   `search_run` termina como `succeeded`, `partial` o `failed`.

Si Ollama no está disponible o devuelve JSON inválido, la configuración
predeterminada usa un plan seguro y determinista con herramientas compatibles.
Configura `ORCHESTRATOR_REQUIRE_OLLAMA=true` si prefieres fallar en lugar de
usar ese fallback.

## Chat que decide el análisis

En cada investigación, **Chat con Linterna** es la entrada sin selectores.
El usuario escribe un pedido y el servidor identifica observables explícitos
o un tema público, explica el tipo de análisis y deja que el planificador local
elija fuentes compatibles. La clasificación inicial usa reglas acotadas
versionadas; no se presenta como razonamiento del modelo. Ollama selecciona
fuentes, con respaldo determinista declarado cuando no devuelve un plan válido.
La interfaz muestra automáticamente el plan, sus motivos y el estado real,
incluidos fallos y resultados parciales. Las ejecuciones conservan los mensajes
y decisiones en la política auditable del caso, sin una nueva base de datos.

`POST /api/v1/investigations/{id}/chat` acepta `prompt`,
`authorization_confirmed` y, para continuar, `parent_run_id`. No acepta perfiles,
módulos, límites ni permisos activos. Sólo crea consultas pasivas, hasta 12
fuentes o el tope del operador si es menor, sin ampliar objetivos descubiertos.
Si falta un objetivo o consentimiento para consultar fuentes externas, responde
una pregunta y no encola nada. El contexto sólo se lee después de comprobar
acceso de editor al caso y nunca se permite usar una búsqueda de otro caso.
Un mensaje como «ahora revisa su reputación» conserva los blancos anteriores;
un dominio explícito nuevo los sustituye. Las conclusiones aún requieren
revisión humana y la evidencia se consulta en el mismo caso.

La única confirmación del flujo básico es la autorización para consultar
fuentes externas. Se recuerda en memoria durante la sesión de ese caso, no
como permiso global permanente. La búsqueda tradicional permanece disponible
en **Opciones avanzadas**. El chat requiere que exista un proyecto y un caso;
no crea ni cambia automáticamente sus permisos o reglas de engagement.

## Búsqueda avanzada

```http
POST /api/v1/investigations/42/search-runs
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "objective": "Mapear infraestructura y huella pública del dominio",
  "profile": "footprint",
  "targets": [
    {"type": "domain", "value": "example.com"},
    {"type": "asn", "value": "AS15169"}
  ],
  "max_tools": 10,
  "follow_discoveries": true,
  "discovery_max_depth": 1,
  "discovery_max_events": 25,
  "allow_active": false,
  "authorization_confirmed": true,
  "scope_note": "Dominio reservado y ASN público usados para validación"
}
```

Consulta `GET /api/v1/search-runs/{id}` hasta recibir un estado terminal. El
campo `planner` indica el proveedor, `deterministic-fallback` o
`profile:<nombre>`; los IDs de los trabajos y evidencias aparecen en
`result_summary`.

## Perfiles de escaneo

| Perfil | Selección | Uso principal |
|---|---|---|
| `auto` | Ollama con allowlist y fallback determinista | Objetivos expresados en lenguaje natural |
| `passive` | Todos los módulos pasivos compatibles | Recolección amplia sin contacto activo |
| `footprint` | DNS, certificados, históricos e infraestructura | Superficie de ataque y exposición |
| `investigate` | Reputación, identidad, vulnerabilidad y contexto | IOC, persona, organización o incidente |
| `all` | Todo el catálogo compatible | Cobertura máxima controlada |

`GET /api/v1/search-profiles` devuelve el catálogo versionado. `all` y
`footprint` no eluden ninguna política: un módulo activo sólo entra en el plan
si la investigación es un pentest vigente, el usuario tiene permiso específico
y la ejecución confirma el alcance. Las programaciones siempre crean runs con
`allow_active=false`, aunque conserven el perfil elegido.

Para el modo más simple puedes omitir `targets`:

```json
{
  "objective": "Investigar la huella pública de example.com",
  "authorization_confirmed": true
}
```

La interfaz local usa este modo automático de forma predeterminada y solicita
hasta 40 adaptadores compatibles. Puedes seleccionar un tipo y valor explícitos
cuando quieras evitar ambigüedad.

## Grafo de descubrimientos

El seguimiento de observables derivados es opt-in mediante
`follow_discoveries=true`. Los colectores declaran los tipos que pueden emitir
y entregan eventos tipados con una relación explícita. El servidor vuelve a
normalizar cada valor, descarta objetivos inválidos o privados, deduplica nodos
por ejecución y conserva una arista hacia el trabajo y la evidencia de origen.

El encadenamiento derivado es determinista: nunca consulta al LLM y sólo
selecciona módulos pasivos compatibles. `discovery_max_depth` limita las capas
y `discovery_max_events` limita las aristas registradas; `max_tools` sigue
siendo el techo total de trabajos iniciales y derivados. Los límites globales
`ORCHESTRATOR_MAX_DISCOVERY_DEPTH` y `ORCHESTRATOR_MAX_DISCOVERY_EVENTS`
impiden que una solicitud amplíe esos valores. Las vigilancias programadas
conservan la misma política y continúan forzando `allow_active=false`.

`GET /api/v1/search-runs/{id}/discoveries` devuelve nodos y aristas con
profundidad, relación, trabajo y evidencia. Los nodos de profundidad cero son
los blancos iniciales; registrar un nodo no implica que se haya ejecutado otro
módulo cuando no existe presupuesto o suscriptor compatible.

## Tipos de blanco

| Tipo | Ejemplo | Controles |
|---|---|---|
| `domain` | `example.com` | IDNA y sintaxis DNS estricta |
| `ip` | `8.8.8.8` | Sólo direcciones públicas globales |
| `asn` | `AS15169` | Rango ASN de 32 bits |
| `url` | `https://example.com/path` | HTTP(S), sin credenciales, host público |
| `username` | `octocat` | Identificador público de 1–63 caracteres |
| `keyword` | `OpenAI Colombia` | Texto normalizado de 2–200 caracteres |

## Límites y seguridad

- Máximo 20 blancos por ejecución y 50 herramientas por contrato; el límite
  operativo predeterminado es 40 y se controla con
  `ORCHESTRATOR_MAX_TOOLS`.
- El seguimiento admite como máximo la profundidad y eventos configurados por
  el operador, siempre dentro de los topes globales del servidor.
- Las respuestas externas están limitadas por bytes e ítems.
- Todos los endpoints de proveedores usan HTTPS, hosts fijados y resolución a
  direcciones públicas; las redirecciones RDAP se validan.
- Las claves se leen como `SecretStr`, se envían sólo al proveedor y no se
  incluyen en planes, consultas persistidas, localizadores, errores o logs.
- Los datos externos y el objetivo se tratan como entrada no confiable frente a
  prompt injection.
- Toda conclusión generada o inferida requiere revisión humana.

## Activación de proveedores con clave

Las variables `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`,
`SECURITYTRAILS_API_KEY` y `URLSCAN_API_KEY` se cargan localmente en `.env`.
No las pegues en Swagger, solicitudes de búsqueda, tickets o chats. Verifica
antes los términos, licencia, cuota, coste y autorización aplicables.

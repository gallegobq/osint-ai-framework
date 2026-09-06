# Orquestación de búsquedas OSINT

## Objetivo

Una búsqueda orquestada recibe un objetivo y, opcionalmente, blancos tipados. Ollama
elige fuentes complementarias del catálogo disponible; una política determinista
valida la propuesta antes de crear trabajos. El modelo nunca ejecuta código,
construye URLs, aporta credenciales ni llama una herramienta directamente.

Flujo:

1. La API exige `collection:execute`, rol de proyecto `editor` y confirmación de
   uso autorizado.
2. La capa de servicio normaliza dominios, IP públicas, ASN, URL públicas,
   usuarios o palabras clave. Si se omiten, extrae únicamente patrones
   explícitos del objetivo; si no hay ninguno, usa el objetivo como palabra clave.
3. Ollama recibe únicamente el catálogo habilitado y propone nombres de
   colector más el índice del blanco.
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

## Crear una búsqueda

```http
POST /api/v1/investigations/42/search-runs
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "objective": "Mapear infraestructura y huella pública del dominio",
  "targets": [
    {"type": "domain", "value": "example.com"},
    {"type": "asn", "value": "AS15169"}
  ],
  "max_tools": 10,
  "allow_active": false,
  "authorization_confirmed": true,
  "scope_note": "Dominio reservado y ASN público usados para validación"
}
```

Consulta `GET /api/v1/search-runs/{id}` hasta recibir un estado terminal. El
campo `plan.planner` indica `ollama` o `deterministic-fallback`; los IDs de los
trabajos y evidencias aparecen en `result_summary`.

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

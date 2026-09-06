# API y permisos

Prefijo: `/api/v1`. Autenticación: `Authorization: Bearer <access_token>`.
Los endpoints protegidos exigen tanto permiso RBAC como acceso al proyecto.

## Salud y autenticación

| Método | Ruta | Acceso |
|---|---|---|
| GET | `/health` | Público; liveness |
| GET | `/health/ready` | Público; readiness PostgreSQL |
| POST | `/auth/login` | Público; JSON |
| POST | `/auth/token` | Público; OAuth2 form |
| POST | `/auth/refresh` | Refresh token |
| GET | `/auth/me` | Access token |
| POST | `/auth/logout` | Access token |
| POST | `/auth/logout-all` | Access token |
| GET | `/auth/sessions` | Metadatos de sesiones propias |
| DELETE | `/auth/sessions/{id}` | Revoca una sesión propia |
| POST | `/auth/mfa/setup` | Inicia enrolamiento TOTP autenticado |
| POST | `/auth/mfa/confirm` | Confirma TOTP y habilita MFA |
| POST | `/auth/mfa/disable` | Exige contraseña y TOTP; revoca sesiones |
| GET | `/metrics` | Prometheus; Bearer si `METRICS_TOKEN` está configurado |

## Usuarios y RBAC

| Operación | Permiso |
|---|---|
| Crear/listar/leer/actualizar usuarios | `users:*` correspondiente |
| Ver eliminados | `users:read_deleted` adicional |
| Cambiar contraseña propia | `users:change_own_password` |
| Reset administrativo | `users:reset_password` |
| Activar/desactivar/eliminar/restaurar | permiso específico `users:*` |
| CRUD de roles | `roles:*` |
| CRUD de permisos | `permissions:*` |
| Asignar roles | `users:update` |
| Asignar permisos a roles | `roles:update` |

## Proyectos

| Método | Ruta | Permiso | Rol mínimo |
|---|---|---|---|
| POST | `/projects` | `projects:create` | — |
| GET | `/projects` | `projects:list` | Devuelve accesibles |
| GET | `/projects/{id}` | `projects:read` | viewer |
| PATCH | `/projects/{id}` | `projects:update` | editor |
| GET | `/projects/{id}/members` | `projects:read` | viewer |
| POST | `/projects/{id}/members` | `projects:manage_members` | owner |
| DELETE | `/projects/{id}/members/{user_id}` | `projects:manage_members` | owner |

La transferencia de propiedad no está implementada. El owner no puede
eliminarse mediante la operación de miembros.

## Investigaciones y tareas

| Método | Ruta | Permiso | Rol mínimo |
|---|---|---|---|
| POST/GET | `/projects/{id}/investigations` | `investigations:create/read` | editor/viewer |
| GET/PATCH | `/investigations/{id}` | `investigations:read/update` | viewer/editor |
| POST/GET | `/investigations/{id}/tasks` | `investigations:update/read` | editor/viewer |
| PATCH | `/investigations/{id}/tasks/{task_id}` | `investigations:update` | editor |
| PATCH | `/investigations/{id}/retention` | `governance:manage_retention` | owner |

Estados: `draft`, `active`, `paused`, `completed`, `archived`. El servicio
rechaza transiciones inválidas.

Cada investigación declara `operation_mode`: `attack_surface`,
`incident_response` o `pentest`. Un pentest exige `authorization_scope`,
`active_testing_authorized=true` y una ventana ISO 8601 completa con zona
horaria. El modo y sus reglas de engagement son inmutables después de crear el
caso.

## Evidencia, entidades y relaciones

| Método | Ruta | Permiso | Rol mínimo |
|---|---|---|---|
| POST/GET | `/investigations/{id}/evidence` | `evidence:create/read` | editor/viewer |
| POST/GET | `/investigations/{id}/entities` | `evidence:update/read` | editor/viewer |
| POST/GET | `/investigations/{id}/relations` | `evidence:update/read` | editor/viewer |

El listado de evidencia admite `kind`, `search` y `limit` (máximo 200).
La deduplicación usa `(investigation_id, SHA-256 canónico)`.

## Recolección

| Método | Ruta | Permiso |
|---|---|---|
| GET | `/collectors` | `collection:read` |
| POST | `/investigations/{id}/collection-jobs` | `collection:execute` |
| GET | `/investigations/{id}/collection-jobs` | `collection:read` |
| GET | `/collection-jobs/{id}` | `collection:read` |

Ejemplo:

```json
{
  "collector": "domain_rdap",
  "query": {"domain": "example.com"}
}
```

Respuesta inicial: HTTP 202 y estado `queued`.

## Orquestación de búsquedas

| Método | Ruta | Permiso |
|---|---|---|
| POST | `/investigations/{id}/search-runs` | `collection:execute` |
| GET | `/investigations/{id}/search-runs` | `collection:read` |
| GET | `/search-runs/{id}` | `collection:read` |

La creación exige `authorization_confirmed=true`, blancos tipados y un límite
de herramientas. Ollama propone el plan y el servidor valida cada paso contra
el catálogo, el tipo de blanco, disponibilidad, modo pasivo y límites. HTTP 202
no significa que la búsqueda terminó; consulta el recurso hasta `succeeded`,
`partial` o `failed`.

`allow_active=true` sólo es aceptado para un pentest autorizado cuya ventana
está vigente y requiere además una `scope_note` específica. El worker repite la
validación antes de ejecutar el plan.

## Análisis

| Método | Ruta | Permiso |
|---|---|---|
| POST | `/investigations/{id}/analysis-jobs` | `analysis:execute` |
| GET | `/investigations/{id}/analysis-jobs` | `analysis:read` |
| GET | `/analysis-jobs/{id}` | `analysis:read` |

Tipos: `summary`, `entities`, `relations`, `sentiment`.

## Hallazgos y vigilancia SOC

| Método | Ruta | Permiso |
|---|---|---|
| POST/GET | `/investigations/{id}/findings` | `findings:create/read` |
| PATCH | `/investigations/{id}/findings/{finding_id}` | `findings:update` |
| POST/GET | `/investigations/{id}/search-schedules` | `schedules:create/read` |
| PATCH | `/investigations/{id}/search-schedules/{schedule_id}` | `schedules:update` |

Las programaciones aceptan intervalos de 15 minutos a 30 días, exigen un
objetivo tipado y una declaración de alcance, y siempre fuerzan
`allow_active=false`. Celery Beat comprueba cada minuto las programaciones
vencidas. Deshabilita una programación para detener ejecuciones futuras.

## Reportes

| Método | Ruta | Permiso |
|---|---|---|
| GET | `/investigations/{id}/report` | `reports:read` |
| GET | `/investigations/{id}/report.md` | `reports:read` |
| GET | `/investigations/{id}/report.stix.json` | `reports:read` |
| GET | `/investigations/{id}/report.ndjson` | `reports:read` |
| GET | `/investigations/{id}/report.cef` | `reports:read` |

STIX 2.1 sirve como formato interoperable para importación en MISP/OpenCTI.
NDJSON y CEF son salidas de ingesta para SIEM; el envío directo a un producto
concreto requiere URL, credenciales, mapeo y aprobación del operador.

## Errores

Los errores de aplicación siguen:

```json
{
  "success": false,
  "error": {"code": "FORBIDDEN", "message": "Permission denied."}
}
```

Códigos relevantes: 400 validación de negocio, 401 autenticación/token, 403
autorización, 404 recurso oculto/inexistente, 409 conflicto y 503 dependencia
temporalmente indisponible.
## Linterna SOC con RAG

- `POST /api/v1/projects/{project_id}/soc-knowledge/documents`: indexa texto SOC
  autorizado y conserva procedencia, hash y modelo de embeddings.
- `GET /api/v1/projects/{project_id}/soc-knowledge/documents`: lista el corpus
  visible del proyecto.
- `POST /api/v1/projects/{project_id}/soc-knowledge/query`: recupera fragmentos
  relevantes y genera una respuesta cuyas citas son validadas por el servidor.

La ingesta exige rol de proyecto `editor` o superior. Las consultas y listados
exigen acceso al proyecto, además de los permisos RBAC `knowledge:*`
correspondientes. El contenido recuperado se trata como datos no confiables y
la respuesta siempre indica que requiere revisión humana.

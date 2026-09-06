# Configuración

Toda la configuración de la aplicación se carga en `app.core.settings`; el
código de negocio no consulta variables de entorno directamente. `.env.example`
es la plantilla versionada y `.env` contiene valores locales o secretos, por lo
que nunca debe confirmarse en Git ni incluirse en una entrega.

## Variables de aplicación

| Variable | Requerida | Propósito |
|---|---:|---|
| `APP_NAME` | Sí | Nombre mostrado por API y liveness |
| `APP_VERSION` | Sí | Versión informativa del servicio |
| `DEBUG` | Sí | Modo local; debe ser `false` fuera de desarrollo |
| `HOST` | Sí | Interfaz de escucha local |
| `PORT` | Sí | Puerto publicado por Compose |

## PostgreSQL

| Variable | Requerida | Propósito |
|---|---:|---|
| `POSTGRES_HOST` | Sí | Host de PostgreSQL; Compose lo sobrescribe a `postgres` |
| `POSTGRES_PORT` | Sí | Puerto; Compose usa internamente `5432` |
| `POSTGRES_DB` | Sí | Base de datos de la aplicación |
| `POSTGRES_USER` | Sí | Usuario de base de datos |
| `POSTGRES_PASSWORD` | Sí, secreto | Contraseña exclusiva para la aplicación |

## Seguridad y bootstrap

| Variable | Requerida | Propósito |
|---|---:|---|
| `SECRET_KEY` | Sí, secreto | Firma JWT; mínimo 32 caracteres de alta entropía |
| `JWT_ALGORITHM` | Sí | Actualmente solo `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Sí | Vida del access token |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Sí | Vida de sesión/refresh token |
| `INITIAL_ADMIN_USERNAME` | Bootstrap | Usuario administrador explícito |
| `INITIAL_ADMIN_EMAIL` | Bootstrap | Correo del administrador explícito |
| `INITIAL_ADMIN_PASSWORD` | Bootstrap, secreto | Contraseña inicial; retirarla tras crear y rotar la cuenta |
| `CORS_ALLOWED_ORIGINS` | No | Lista JSON de orígenes web autorizados |
| `TRUSTED_HOSTS` | No | Lista JSON de hosts HTTP aceptados |

Con `DEBUG=false`, la configuración rechaza `*` tanto en CORS como en hosts.
Cambiar `SECRET_KEY` invalida todos los JWT emitidos.
El host interno `api` permite el smoke test entre contenedores; en despliegue
debes agregar el dominio real sin retirar los nombres internos que utilices.

## Cola, colectores y LLM

| Variable | Valor predeterminado | Propósito |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379/0` | Broker y backend Celery; Compose lo sobrescribe |
| `CELERY_TASK_ALWAYS_EAGER` | `false` | Solo pruebas controladas; no habilitar en producción |
| `OSINT_HTTP_TIMEOUT_SECONDS` | `15` | Timeout de colectores HTTP, rango 0–60 s |
| `OSINT_MAX_RESPONSE_BYTES` | `2000000` | Tamaño máximo descargado por respuesta |
| `OSINT_MAX_ITEMS_PER_COLLECTOR` | `200` | Resultados conservados por fuente |
| `OSINT_USER_AGENT` | Identificador local | User-Agent para proveedores públicos |
| `OSINT_SEARCH_LANGUAGE` | `es` | Idioma de Wikipedia/Wikidata/Google Books |
| `ORCHESTRATOR_MAX_TOOLS` | `40` | Límite operativo por búsqueda |
| `ORCHESTRATOR_REQUIRE_OLLAMA` | `false` | Si `true`, desactiva fallback determinista |
| `LLM_PROVIDER` | `ollama` | Adaptador de inferencia habilitado |
| `OLLAMA_URL` | `http://localhost:11434` | Endpoint Ollama; Compose lo sobrescribe |
| `OLLAMA_MODEL` | `llama3.1:8b` | Modelo comprobado y descargado automáticamente por Compose |
| `LLM_TIMEOUT_SECONDS` | `120` | Timeout de inferencia, máximo 600 s |
| `LLM_MAX_EVIDENCE_CHARACTERS` | `50000` | Límite del contexto de evidencia |
| `SMOKE_BASE_URL` | `http://localhost:8000` | URL de la prueba funcional; Compose usa `http://api:8000` |

## Credenciales opcionales de fuentes

| Variable | Activa |
|---|---|
| `SHODAN_API_KEY` | `ip_shodan` |
| `VIRUSTOTAL_API_KEY` | `domain_virustotal`, `ip_virustotal` |
| `SECURITYTRAILS_API_KEY` | `domain_securitytrails` |
| `URLSCAN_API_KEY` | Mayor cuota para `domain_urlscan` |

Déjalas vacías cuando no se utilicen. Son secretos y no deben aparecer en
planes, cuerpos de API, documentación interna con ejemplos reales ni logs.

## Herramientas opcionales

`PGADMIN_DEFAULT_EMAIL` y `PGADMIN_DEFAULT_PASSWORD` pertenecen únicamente al
perfil Compose `tools`. No son leídas por la aplicación y deben ser distintas
de las credenciales del administrador OSINT.

`ENV_FILE` es una opción exclusiva de Compose para seleccionar otro archivo de
entorno; si no se define, todos los servicios usan `.env`.

## Preparación segura

1. Copia `.env.example` como `.env`.
2. Reemplaza cada valor `replace-with-...`.
3. Genera una clave: `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
4. Restringe permisos del archivo al usuario que ejecuta Docker.
5. En staging/producción, inyecta secretos desde el gestor aprobado en lugar
   de distribuir `.env`.

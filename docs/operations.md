# Runbook de operación

## Servicios

| Servicio | Función | Persistencia |
|---|---|---|
| API | HTTP/OpenAPI | Ninguna local |
| PostgreSQL | Fuente de verdad | volumen `postgres_data` |
| Redis | Broker/resultados Celery | volumen `redis_data` |
| Worker | Recolección, orquestación y análisis | Ninguna local |
| Ollama | Planificación y análisis local; arranque automático | volumen `ollama_data` |
| PgAdmin | Administración opcional | No requerido por la app |

## Arranque

```bash
docker compose up --build -d postgres redis api worker
docker compose exec api alembic upgrade head
docker compose exec api python -m app.seed.admin
docker compose exec api python -m app.seed.rbac
```

Para construir, migrar, inicializar, probar y ejecutar el smoke test en una
sola secuencia reproducible, usa `scripts/verify.ps1` o `scripts/verify.sh`.
El verificador mantiene detenidos API y worker durante Alembic y los seeds para
reducir memoria y solo los arranca cuando el esquema está listo. Si la API no
alcanza estado saludable, muestra automáticamente el estado de Compose y sus
últimos 200 registros para conservar la causa original del fallo. Antes del
arranque también importa la aplicación ASGI en un contenedor efímero, de modo
que errores de módulos, rutas o anotaciones fallen de forma inmediata.
La imagen de pruebas fija `PYTHONPATH=/app`, ejecuta pytest como módulo de
Python y dirige su caché a `/tmp`, ya que el código de la imagen de producción
permanece correctamente en modo de solo lectura para el usuario no privilegiado.

El bootstrap administrativo es idempotente: si ya existe un superusuario
activo y no eliminado, lo conserva sin cambiar su identidad o contraseña. Si
no existe ninguno, crea el usuario definido por `INITIAL_ADMIN_*`; una colisión
con una cuenta normal sigue siendo un error para impedir una elevación de
privilegios accidental.

Para recuperar un volumen heredado cuyo superusuario ya no coincide con
`INITIAL_ADMIN_*`, ejecuta una sola vez
`scripts/verify.ps1 -ReconcileInitialAdmin` en PowerShell o
`scripts/verify.sh --reconcile-initial-admin` en WSL/Linux. La operación adopta
la identidad y contraseña configuradas, revoca las sesiones anteriores y, si
no queda ningún superusuario activo, puede restaurar y promover la cuenta que
ya posea ese nombre o correo. Se niega a continuar si el nombre y el correo
pertenecen a cuentas distintas. Las verificaciones normales no restablecen
credenciales ni elevan privilegios.

PgAdmin opcional:

```bash
docker compose --profile tools up -d pgadmin
```

Ollama no requiere un comando manual: al desplegar API/worker, Compose arranca
el servicio y descarga el `OLLAMA_MODEL` configurado si el volumen aún no lo
contiene. La primera descarga puede tardar; `docker compose logs -f ollama`
muestra el progreso. Si Ollama deja de responder después, el modo
predeterminado ejecuta el plan determinista; revisa `planner` en el
`search_run` para saber cuál se utilizó.

## Comprobaciones

```bash
docker compose ps
docker compose logs --tail=100 api worker postgres redis ollama
curl -fsS http://localhost:8000/api/v1/health
curl -fsS http://localhost:8000/api/v1/health/ready
docker compose exec api alembic current
docker compose exec api alembic heads
```

`health` indica proceso vivo; `health/ready` confirma acceso a PostgreSQL y que
Alembic está en la revisión esperada. La salud de Redis/worker se revisa en
Docker y mediante trabajos de prueba.

## Migraciones

Antes de desplegar:

1. Realiza backup.
2. Ejecuta `alembic upgrade head` en staging.
3. Valida lecturas y escrituras.
4. Despliega API/worker compatibles.
5. Comprueba revisión con `alembic current`.

La revisión `c71db15a2e0f` repara `user_sessions` porque la revisión histórica
con ese propósito estaba vacía. No se debe eliminar ni volver a escribir.

## Backup PostgreSQL

Ejemplo lógico (adapta nombres y rutas):

```bash
docker compose exec -T postgres sh -c \
  'pg_dump --username="$POSTGRES_USER" --format=custom "$POSTGRES_DB"' \
  > osint-backup.dump
```

Prueba restauraciones periódicamente en una base aislada. Los backups contienen
PII y deben cifrarse, limitarse y retenerse según política.

## Rotación de secretos

- PostgreSQL: crea/rota credencial, actualiza el gestor de secretos y reinicia
  API/worker de forma coordinada.
- JWT: cambiar `SECRET_KEY` invalida todos los tokens; planifica una ventana.
- Administrador inicial: solo se usa en bootstrap. Después elimina
  `INITIAL_ADMIN_PASSWORD` del entorno y cambia la contraseña desde la API.

## Fallos comunes

| Síntoma | Diagnóstico |
|---|---|
| readiness 503 | PostgreSQL caído, credenciales o migraciones |
| trabajo queda queued | Redis o worker no disponibles |
| recolección failed | DNS/red, RDAP o consulta inválida |
| búsqueda partial | Una o más fuentes externas fallaron; revisa los trabajos hijos |
| planner `deterministic-fallback` | Ollama ausente, modelo no descargado o plan inválido |
| análisis failed | Ollama/modelo ausente, timeout o JSON inválido |
| 403 | permiso RBAC o rol de proyecto insuficiente |
| refresh 401 | token vencido, rotado, revocado o sesión desactivada |
| `password authentication failed` tras cambiar `.env` | El volumen conserva la credencial con la que PostgreSQL fue inicializado; ejecuta `scripts/align_postgres_password.ps1` y confirma `ALINEAR` para actualizar el rol sin borrar datos |

## Apagado

```bash
docker compose down
```

No uses `docker compose down -v` salvo que quieras eliminar de forma explícita
los volúmenes y hayas verificado el backup.

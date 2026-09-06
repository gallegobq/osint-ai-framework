# Estrategia de pruebas

## Niveles

1. **Sintaxis/importaciones**: todo archivo Python compila y las rutas internas
   existen.
2. **Unidad**: políticas de acceso, sesiones, normalización, hashes y prompts.
3. **HTTP**: rutas, contratos, errores y encabezados.
4. **Integración PostgreSQL**: repositorios, transacciones y constraints.
5. **Migraciones**: instalación limpia, upgrade existente y downgrade.
6. **Worker**: jobs, reintentos, idempotencia y fallos.
7. **Proveedores**: fixtures grabadas/sanitizadas; red real solo bajo marca.

El catálogo RBAC se compara usando exclusivamente los atributos públicos de
sus categorías. El registro de rutas se valida contra `openapi()["paths"]`,
evitando depender de objetos internos que pueden cambiar entre versiones de
FastAPI sin alterar el contrato HTTP.

## Ejecución rápida

```bash
pytest
python -m compileall -q app alembic tests scripts
```

Con Docker:

```bash
docker compose --profile test run --rm tests
docker compose --profile test run --rm tests \
  python scripts/smoke_api.py
docker compose --profile test run --rm tests \
  python scripts/smoke_orchestrator.py
docker compose --profile test run --rm tests \
  python scripts/smoke_soc_readonly.py
```

Los smoke tests requieren API y worker iniciados, migraciones y bootstrap
completados. El test del orquestador usa exclusivamente `example.com` y acepta
`partial` si al menos una fuente produjo evidencia.
El flujo reproducible completo está automatizado en `scripts/verify.ps1` para
PowerShell y `scripts/verify.sh` para WSL/Linux.

## Matriz PostgreSQL

En una base de pruebas desechable:

```bash
alembic upgrade head
pytest
alembic downgrade c71db15a2e0f
alembic upgrade head
```

En una copia anonimizada de la base existente, ejecuta únicamente upgrade y
pruebas de lectura/escritura. No pruebes downgrade destructivo sobre datos
reales.

## Casos obligatorios antes de producción

- Usuario inactivo/eliminado no inicia sesión.
- Refresh rotado o sesión expirada devuelve 401.
- Viewer no edita; editor no administra miembros.
- Usuario ajeno no descubre proyectos/investigaciones.
- Evidencia repetida es idempotente.
- Relación no puede cruzar investigaciones.
- Cola caída produce 503 y job fallido observable.
- Reintento de colector no duplica evidencia.
- Prompt malicioso permanece como dato y no se promueve automáticamente.
- Plan de Ollama no puede seleccionar herramientas desconocidas,
  incompatibles, repetidas ni superiores al límite.
- IP privadas, URLs con credenciales y ejecuciones sin confirmación se rechazan.
- Una fuente externa caída produce `partial` sin descartar evidencia exitosa.
- Reporte cita IDs y hashes de evidencia.
- Logs no contienen Authorization, contraseñas o tokens.
- Un usuario sin `collection:execute_active` no inicia una ejecución activa.
- El sandbox rechaza nombres inválidos, destinos privados y herramientas no
  registradas.
- Un trabajo activo no puede cambiar su consulta a un destino distinto del
  objetivo persistido.

## Estado del entorno de recuperación

El 2026-08-15 el usuario ejecutó `scripts/verify.ps1` desde PowerShell con
acceso al daemon Docker de Windows. La ejecución confirmó:

- construcción de API, worker y tests sobre Python 3.12;
- Alembic en `d84f3c9a1b72 (head)` sobre PostgreSQL 16;
- importación ASGI y health checks de API, PostgreSQL y Redis;
- bootstrap administrativo y RBAC idempotentes;
- 34 pruebas aprobadas;
- smoke test HTTP aprobado, con creación y archivado de un proyecto y una
  investigación sintéticos.

Pytest emitió una advertencia externa de deprecación entre `TestClient` y su
cliente HTTP. No afectó el resultado, pero debe revisarse al renovar FastAPI y
las dependencias de pruebas. En ese checkpoint seguían pendientes las pruebas
sobre una instalación PostgreSQL limpia, una copia anonimizada adicional y el
procedimiento de backup/restore.

## Validación del incremento SOC — 2026-08-16

- Alembic alcanzó `c84f7a2e9d10 (head)`.
- 82 pruebas aprobaron dentro de Docker; Ruff aprobó sin errores.
- El smoke SOC confirmó 42 colectores y 57 rutas OpenAPI.
- API, worker y scheduler iniciaron correctamente con la imagen runtime.
- Trivy encontró 0 vulnerabilidades HIGH/CRITICAL corregibles en el rootfs.
- Un backup real se restauró en una base aislada y devolvió la revisión
  `c84f7a2e9d10`.
- La carga local produjo 0 errores en 100 solicitudes, pero p95 de 2286 ms;
  incumple el umbral local de 1000 ms y requiere optimización/capacidad.

El backup/restore ya no está pendiente en el entorno local actual; sí continúa
pendiente su automatización externa y la aceptación formal de RPO/RTO.

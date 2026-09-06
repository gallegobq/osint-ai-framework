# Evidencia de validación runtime — 2026-08-15

## Entorno observado

- Windows con Docker Desktop y contenedores Linux.
- Imágenes de aplicación basadas en Python 3.12 slim.
- PostgreSQL 16 y Redis 7 Alpine.
- Volumen PostgreSQL heredado, conservado durante toda la recuperación.

## Secuencia ejecutada

El usuario ejecutó desde PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

El verificador realizó, en orden:

1. validación de Docker Compose;
2. construcción de API, worker y tests;
3. health checks de PostgreSQL y Redis;
4. migraciones Alembic;
5. bootstrap administrativo y seed RBAC idempotentes;
6. comprobación de la revisión Alembic;
7. importación de la aplicación ASGI;
8. inicio y health check de API/worker;
9. pytest dentro de la imagen de pruebas;
10. smoke test HTTP contra la API real.

## Resultado

| Control | Resultado observado |
|---|---|
| Alembic | `d84f3c9a1b72 (head)` |
| Administrador | `admin`, reconocido de forma idempotente |
| RBAC | catálogo y asignaciones existentes, sin duplicados |
| API | `healthy`, puerto host `8000` |
| PostgreSQL | `healthy`, puerto host `5432` |
| Redis | `healthy` |
| Worker Celery | iniciado |
| Pytest | 34 aprobadas, 0 fallidas |
| Smoke HTTP | aprobado |
| Recursos smoke | `project=1`, `investigation=1`, archivados por el flujo |

Pytest emitió una advertencia de deprecación de una dependencia de pruebas
relacionada con `TestClient`. No afectó la ejecución ni el resultado funcional;
se conserva como tarea de mantenimiento para la próxima actualización conjunta
de FastAPI y sus clientes de prueba.

## Alcance de esta evidencia

Esta ejecución valida el volumen heredado utilizado durante la recuperación.
No sustituye las pruebas previas a producción sobre una base limpia, una copia
anonimizada adicional, backup/restore, carga, seguridad, vulnerabilidades ni
recuperación ante fallos.

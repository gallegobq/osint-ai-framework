# Dependencias y actualizaciones

## Runtime Python

| Paquete | Rango | Uso |
|---|---|---|
| FastAPI | `>=0.115,<1.0` | API HTTP, validación y OpenAPI |
| Uvicorn | `>=0.30,<1.0` | Servidor ASGI |
| SQLAlchemy | `>=2.0,<3.0` | ORM y unidades de trabajo |
| psycopg2-binary | `>=2.9,<3.0` | Driver PostgreSQL |
| Alembic | `>=1.13,<2.0` | Evolución versionada del esquema |
| Pydantic / Settings | `>=2.x,<3.0` | Contratos y configuración |
| PyJWT + crypto | `>=2.10,<3.0` | Firma y validación JWT |
| pwdlib + Argon2 | `>=0.2,<1.0` | Hash seguro de contraseñas/refresh tokens |
| HTTPX | `>=0.27,<1.0` | RDAP y Ollama |
| Celery + Redis | `>=5.4,<6.0` | Ejecución asíncrona |
| redis | `>=5.0,<7.0` | Cliente del broker/backend |

`python-multipart` soporta el formulario OAuth2 y `email-validator` valida los
correos Pydantic. Las herramientas de desarrollo (`pytest`, `pytest-asyncio`,
`ruff`) viven separadas en `requirements-dev.txt` y solo entran en la etapa
Docker `test`.

## Servicios de contenedor

- Python 3.12 slim para API/worker/tests.
- PostgreSQL 16 como fuente de verdad.
- Redis 7 Alpine como broker y backend Celery.
- Ollama como dependencia local de API/worker, con modelo persistido; PgAdmin
  mediante perfil opcional.

## Política de actualización

1. Renovar una familia a la vez dentro de staging.
2. Revisar changelog, avisos de seguridad y compatibilidad Python/PostgreSQL.
3. Reconstruir sin caché y ejecutar `scripts/verify.ps1` o `verify.sh`.
4. Para producción, generar un lock/constraints aprobado con hashes desde el
   entorno que desplegará; los rangos de este repositorio no sustituyen un lock.
5. Conservar el artefacto y el resultado de pruebas para rollback.

La guía actual de FastAPI usa PyJWT y `pwdlib`; SQLAlchemy permanece en su API
2.x y Celery usa Redis como broker/backend. Referencias oficiales:

- <https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/>
- <https://docs.sqlalchemy.org/en/20/orm/session.html>
- <https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/>
- <https://pypi.org/project/PyJWT/>

## Validación de esta recuperación

Además de la revisión estática, Docker resolvió e instaló las dependencias de
runtime y pruebas sobre Python 3.12. La imagen ejecutó 34 pruebas y el smoke
test HTTP correctamente. Quedó una advertencia de deprecación externa entre el
`TestClient` incluido por FastAPI y el cliente HTTP; debe reevaluarse al renovar
esas familias, sin cambiar dependencias de forma aislada.

Antes de producción todavía se requiere generar un lock/constraints con hashes
y ejecutar un escaneo de vulnerabilidades en el entorno de despliegue.

# OSINT AI Framework

Backend modular para investigaciones OSINT basado en FastAPI, SQLAlchemy 2.0,
PostgreSQL, Alembic, JWT/OAuth2, RBAC, Celery, Redis y proveedores LLM
intercambiables.

## Capacidades

- Usuarios, contraseñas, MFA TOTP, JWT, refresh-token rotation y sesiones.
- RBAC global y autorización contextual por membresía de proyecto.
- Proyectos, miembros, investigaciones y tareas.
- Modos por investigación: superficie de ataque, respuesta a incidentes y
  pentesting autorizado con reglas de engagement.
- Evidencia con procedencia, SHA-256, deduplicación y timestamps.
- Entidades y relaciones citables a evidencia.
- Recolección asíncrona mediante colectores desacoplados.
- Catálogo de 43 perfiles: 42 colectores pasivos para dominio, hostname, IP,
  ASN, URL, email, hash, CVE, usuarios y palabras clave —37 sin claves y 5 con
  credenciales— más una validación activa aislada.
- Sandbox SOC sin shell para una línea base TLS/HTTP de bajo impacto, disponible
  únicamente en pentest autorizado y con alcance explícito.
- Orquestador Ollama restringido con planes validados, ejecución auditable y
  fallback determinista.
- Análisis con Ollama: resumen, entidades, relaciones y sentimiento.
- Linterna SOC con RAG local por proyecto: documentos trazables, embeddings,
  recuperación híbrida, abstención y respuestas con citas validadas.
- Hallazgos SOC con severidad, estado, confianza, remediación y evidencia.
- Búsquedas pasivas programadas para detectar cambios.
- Reportes narrativos y exportaciones STIX 2.1, SIEM NDJSON y CEF.
- Rate limiting con Redis, métricas Prometheus y metadatos de retención/legal hold.
- Auditoría del dominio OSINT y separación liveness/readiness.

Los resultados LLM son hipótesis: nunca se incorporan automáticamente como
hechos o entidades verificadas y siempre requieren revisión humana.

## Inicio rápido con Docker

Requisitos: Docker Desktop con contenedores Linux.

1. Copia `.env.example` como `.env`.
2. Sustituye todas las cadenas `replace-with-...` por valores propios.
3. Genera `SECRET_KEY`:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

4. Inicia PostgreSQL, Redis, Ollama, API, worker y scheduler:

   ```bash
   docker compose up --build -d postgres redis api worker scheduler
   ```

5. Aplica el esquema y crea el administrador explícito:

   ```bash
   docker compose exec api alembic upgrade head
   docker compose exec api python -m app.seed.admin
   docker compose exec api python -m app.seed.rbac
   ```

6. Comprueba el servicio:

   ```bash
   curl http://localhost:8000/api/v1/health
   curl http://localhost:8000/api/v1/health/ready
   ```

Interfaz local: `http://localhost:8000/`.

El servicio Ollama se incluye automáticamente como dependencia. En el primer
arranque descarga `OLLAMA_MODEL` al volumen `ollama_data`; Docker no declara la
aplicación lista hasta que el modelo responde. La descarga se reutiliza en los
arranques posteriores. Ollama permanece en la red interna de Compose y no
publica el puerto 11434, evitando exponer el modelo o chocar con un Ollama del
host.

La interfaz **Linterna** se sirve desde el mismo contenedor de la API y permite
iniciar sesión, crear proyectos e investigaciones, registrar evidencia y
hallazgos, lanzar o programar búsquedas autorizadas y descargar reportes
Markdown, STIX y SIEM. No requiere Node.js ni servicios en la nube.

Swagger: `http://localhost:8000/docs`.

## Ollama automático

El modelo se cambia con `OLLAMA_MODEL` antes de desplegar; el entrypoint local
lo descarga si todavía no existe. Si Ollama falla después del arranque, los
colectores siguen siendo independientes y las búsquedas orquestadas usan el
fallback seguro salvo que `ORCHESTRATOR_REQUIRE_OLLAMA=true`.

## Desarrollo local

Requisitos: Python 3.12, PostgreSQL 16 y Redis 7.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
python -m app.seed.admin
python -m app.seed.rbac
uvicorn app.main:app --reload
```

En PowerShell, activa con `.venv\Scripts\Activate.ps1` y copia con
`Copy-Item .env.example .env`.

Worker local:

```bash
celery --app=app.workers.celery_app:celery_app worker --loglevel=INFO
```

Scheduler local:

```bash
celery --app=app.workers.celery_app:celery_app beat --loglevel=INFO
```

## Flujo mínimo

1. Obtén tokens en `POST /api/v1/auth/token`.
2. Crea un proyecto.
3. Crea una investigación dentro del proyecto.
4. Selecciona el modo operativo. Pentest exige alcance, autorización y ventana
   temporal antes de admitir solicitudes activas.
5. Añade evidencia o escribe una consulta natural en un `search-run`. Si no
   indicas un blanco tipado, el servidor detecta URL, dominio, IP, ASN, email,
   CVE, hash o `@usuario`; en los demás casos usa una palabra clave.
6. Consulta el trabajo hasta `succeeded`, `partial` o `failed`.
7. Opcionalmente encola un análisis LLM.
8. Clasifica resultados como hallazgos y exporta Markdown, STIX 2.1, NDJSON o CEF.

Consulta [docs/api.md](docs/api.md) para rutas y permisos.

## Pruebas

```bash
pytest
```

Validación Docker completa desde PowerShell o WSL:

```powershell
.\scripts\verify.ps1
```

```bash
bash scripts/verify.sh
```

La validación completa con PostgreSQL se describe en
[docs/testing.md](docs/testing.md). Antes de producción se debe probar
`upgrade` y `downgrade` sobre una base limpia y `upgrade` sobre una copia
anonimizada de la base existente.

Prueba funcional separada del orquestador (crea y archiva datos sintéticos):

```bash
docker compose --profile test run --rm tests python scripts/smoke_orchestrator.py
```

Sonda pasiva de los 15 proveedores públicos añadidos (no guarda evidencia):

```bash
docker compose --profile test run --rm tests python scripts/probe_extended_collectors.py
```

## Documentación

- [Guía de uso](docs/user-guide.md)
- [Capacidades, alcance, redes sociales, correo y potencial](docs/capabilities-and-scope.md)
- [Arquitectura](docs/architecture.md)
- [Configuración](docs/configuration.md)
- [Dependencias y actualizaciones](docs/dependencies.md)
- [API y permisos](docs/api.md)
- [Modelo de datos](docs/data-model.md)
- [Operación](docs/operations.md)
- [Seguridad y uso responsable](docs/security.md)
- [Modos operativos](docs/operation-modes.md)
- [Sandbox de validación SOC](docs/soc-sandbox.md)
- [Colectores](docs/collectors.md)
- [Operaciones SOC](docs/soc-operations.md)
- [Preparación para producción](docs/production-readiness.md)
- [Validación runtime del sandbox (2026-08-30)](docs/runtime-validation-2026-08-30.md)
- [Orquestación de búsquedas](docs/orchestration.md)
- [LLM y prompts](docs/llm.md)
- [Pruebas](docs/testing.md)
- [Checklist de despliegue](docs/deployment-checklist.md)
- [Compartir Linterna y crear administradores](docs/sharing-and-administration.md)
- [Puntos de supervisión](docs/supervision.md)
- [Roadmap y decisiones](docs/roadmap.md)
- [Primera entrega y RAG SOC](docs/first-delivery-rag.md)
- [Auditoría de recuperación](docs/audit-2026-08-15.md)
- [Evidencia de validación runtime](docs/runtime-validation-2026-08-15.md)
- [Validación del incremento SOC](docs/runtime-validation-2026-08-16.md)
- [Registros ADR](docs/adr/README.md)

## Límites actuales

**No está listo para producción.** Es una plataforma funcional de
preproducción. Los controles incorporados necesitan integración y validación
con la infraestructura, jurisdicción, identidad, secretos, RPO/RTO y SIEM de
la organización antes de usar datos reales.

- La interfaz local cubre el flujo operativo principal; la administración
  avanzada de usuarios y RBAC continúa disponible mediante OpenAPI.
- No hay multitenancy estricto: es una instancia multiusuario con membresía por
  proyecto.
- No se almacenan binarios; la evidencia guarda texto/JSON y metadatos. Un
  almacenamiento de objetos debe añadirse antes de aceptar archivos grandes.
- El RAG inicial almacena vectores como JSON y recupera un corpus acotado en la
  aplicación. Antes de escalar necesita evaluación, tareas asíncronas y un
  índice vectorial/full-text medido.
- Las fuentes públicas dependen de disponibilidad, cuotas y términos externos;
  un fallo individual produce un resultado de orquestación `partial`.
- No se deben recolectar datos fuera de una base legal o autorización válida.

Nunca publiques `.env`, volcados de PostgreSQL, tokens, contraseñas, resultados
OSINT sensibles ni volúmenes Docker.

# ADR-0002: Celery y Redis para trabajos

- Estado: Accepted
- Fecha: 2026-08-15

## Contexto

DNS, RDAP y LLM pueden tardar o fallar. Ejecutarlos dentro de la petición HTTP
reduce disponibilidad y dificulta reintentos.

## Decisión

Persistir el estado del trabajo en PostgreSQL, transportar únicamente su ID con
Celery/Redis y ejecutar adaptadores en workers. `JobDispatcher` evita acoplar
los servicios a Celery.

## Consecuencias

Redis no es fuente de verdad. La operación añade un servicio, pero permite
reintentos, observación y escalamiento independiente. La idempotencia se apoya
en hashes de evidencia.

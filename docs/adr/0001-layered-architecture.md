# ADR-0001: Arquitectura en capas

- Estado: Accepted
- Fecha: 2026-08-15

## Contexto

El código recibido ya separaba routers, servicios y repositorios, aunque varias
dependencias y transacciones cruzaban fronteras.

## Decisión

Mantener API, composición/DI, servicios, repositorios, ORM y adaptadores
externos como capas diferenciadas. La lógica de autorización contextual y la
unidad de trabajo pertenecen a servicios. SQLAlchemy 2.0 es el adaptador de
persistencia y Alembic es la única vía de evolución del esquema.

## Consecuencias

Hay más clases y composición explícita, pero proveedores, HTTP y persistencia
pueden probarse o sustituirse por separado.

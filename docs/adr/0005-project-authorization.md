# ADR-0005: RBAC global y roles por proyecto

- Estado: Accepted
- Fecha: 2026-08-15

## Contexto

RBAC global por sí solo permitiría que un analista con permiso de lectura viera
investigaciones de cualquier equipo.

## Decisión

Exigir capacidad global y rol contextual. `viewer` lee, `editor` modifica y
`owner` administra miembros. Los servicios realizan la comprobación para que
workers y futuras interfaces apliquen la misma política.

## Consecuencias

No es multitenancy estricto y el superusuario conserva bypass. Si se requieren
tenants aislados deberán añadirse tenant IDs, constraints y políticas en toda
consulta, idealmente con PostgreSQL RLS como defensa adicional.

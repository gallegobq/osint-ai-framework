# ADR-0003: Evidencia inmutable con procedencia

- Estado: Accepted
- Fecha: 2026-08-15

## Contexto

Un hallazgo OSINT sin fuente, timestamp o integridad verificable no puede
auditarse ni citarse responsablemente.

## Decisión

Separar fuente y evidencia. Guardar colector, localizador, metadata, contenido
normalizado, JSON crudo, timestamps y SHA-256 canónico. Deduplicar dentro de la
investigación. Las relaciones pueden citar evidencia.

## Consecuencias

El almacenamiento crece y aún no equivale a cadena de custodia forense firmada.
Habilita reproducibilidad básica, idempotencia y reportes citados.

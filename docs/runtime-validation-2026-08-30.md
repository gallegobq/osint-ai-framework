# Evidencia de validación runtime — 2026-08-30

## Incremento validado

Sandbox SOC para validación activa TLS/HTTP de bajo impacto en investigaciones
de pentest autorizadas.

## Controles observados

| Control | Resultado |
|---|---|
| Compilación Python | Aprobada |
| Docker Compose config | Aprobada |
| Construcción sandbox/API/worker/tests | Aprobada |
| Pytest | 87 aprobadas, 0 fallidas |
| Ruff | Aprobado sin hallazgos |
| Health del sandbox | `healthy` |
| Herramientas expuestas | Sólo `tls_http_baseline` |
| Herramienta no registrada | Rechazada con HTTP 422 |
| Probe `example.com` | TLS 1.3, certificado válido, HTTP 200 |
| Peticiones aplicadas | 1 petición HEAD, 0 redirecciones |

## Aislamiento verificado con Docker inspect

- `Privileged=false`;
- `ReadonlyRootfs=true`;
- `CapDrop=[ALL]`;
- `no-new-privileges=true`;
- ningún puerto publicado;
- red exclusiva `sandbox_egress`;
- 256 MiB de memoria;
- 0,5 CPU;
- máximo 64 procesos;
- `/tmp` limitado, `noexec` y `nosuid`;
- sin volúmenes ni socket Docker.

## Alcance

La sonda funcional utilizó `example.com`, dominio reservado para ejemplos. El
resultado confirma el perfil implementado, no certifica la seguridad del
objetivo ni sustituye un pentest. La suite produjo una advertencia de
deprecación externa de `TestClient`, sin fallos funcionales.

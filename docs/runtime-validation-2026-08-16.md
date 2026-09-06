# Evidencia de validación SOC — 2026-08-16

## Estado

El incremento SOC funciona en el entorno Docker local y conserva la
clasificación de **preproducción**. Esta evidencia no constituye una
autorización para operar datos reales ni una aceptación de riesgo.

## Controles ejecutados

| Control | Resultado observado |
|---|---|
| Migración | `c84f7a2e9d10 (head)` |
| Pruebas | 82 aprobadas, 0 fallidas; 1 advertencia externa de deprecación |
| Estilo estático | Ruff aprobado sobre `app`, `tests` y `scripts` |
| Smoke SOC | 42 colectores y 57 rutas OpenAPI |
| Runtime | API, worker y scheduler iniciados; API saludable |
| Frontend | Login local visible con MFA; sin errores de consola al recargar |
| Cola | Un worker Celery respondió `pong` |
| Vulnerabilidades | Trivy: 0 HIGH/CRITICAL corregibles en Debian y Python |
| Backup | Dump validado con `pg_restore --list` |
| Restore | Restauración aislada aprobada; revisión `c84f7a2e9d10` |
| Carga | 100 solicitudes, 0 errores, 4.81 rps, p95 2286.22 ms |

El escaneo se realiza sobre el rootfs exportado de la imagen runtime. La
imagen no incluye `pip` ni `setuptools`, porque son herramientas de build y no
son necesarias para ejecutar API, worker o scheduler.

## Evidencia de recuperación

- Archivo local: `backups/osint-20260816-173523.dump`.
- SHA-256:
  `28AC42D475CD7612B9D116B81D2E172692CEE847E4CEE1C13E7FCF158D1124FB`.
- La restauración se hizo en una base temporal distinta y esa base se eliminó
  al finalizar. La base operativa no fue reemplazada.

El dump puede contener información de la instancia local y está ignorado por
Git. Debe protegerse, cifrarse o eliminarse conforme a la política aprobada.

## Resultado de capacidad

Aunque no hubo errores HTTP, el p95 de 2286.22 ms supera el umbral local de
1000 ms configurado por `scripts/load_test.py`. Por tanto, la prueba de carga
**no aprueba** el objetivo de latencia. Antes de producción deben medirse rutas
representativas, ajustar recursos y concurrencia, y acordar SLO/capacidad.

## Pendientes de producción

- Certificados, dominio, proxy/WAF y topología definitivos.
- Gestor corporativo de secretos y rotación probada.
- Backups automatizados, cifrados, externos y RPO/RTO aceptados.
- Prometheus/SIEM operados, dashboards, alertas y guardias.
- Pruebas de carga representativas que cumplan un SLO acordado.
- Política legal por jurisdicción y eliminación verificable.
- Recuperación MFA/SSO y pruebas por rol de la organización.
- Importación validada de STIX/NDJSON/CEF en el producto destino.

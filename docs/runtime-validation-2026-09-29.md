# Validación de rendimiento y consultas — 2026-09-29

## Alcance

Esta validación usa exclusivamente la instancia local y datos de desarrollo.
No autoriza una exposición pública ni reemplaza una prueba de capacidad sobre
infraestructura y cardinalidad representativas.

## Corrección de la línea base

Docker publica la API como `127.0.0.1:8000`. El medidor anterior usaba
`localhost`, que en Windows intentaba primero `::1`; el fallback a IPv4 añadía
aproximadamente dos segundos por solicitud. La latencia documentada en agosto
medía ese comportamiento del cliente y no una espera equivalente del servidor.

`scripts/load_test.py` ahora usa IPv4 explícito, calentamiento, repeticiones,
percentiles nearest-rank, desglose de estados y salida JSON reproducible.

## Resultado observado

Comando:

```powershell
python .\scripts\load_test.py `
  --requests 500 `
  --concurrency 20 `
  --warmup 50 `
  --repetitions 3 `
  --max-p95-ms 1000 `
  --json-output .\tmp\benchmark-health.json
```

| Serie | Errores | RPS | p50 ms | p95 ms | p99 ms |
|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 132,79 | 117,76 | 321,59 | 465,49 |
| 2 | 0 | 183,49 | 90,50 | 208,44 | 267,80 |
| 3 | 0 | 103,12 | 179,80 | 345,28 | 532,04 |

Agregado: 1.500 solicitudes, 0 errores, 132,79 rps medianos y p95 mediano de
321,59 ms. Una serie adicional desde la red Docker obtuvo p95 de 274,34 ms.

Una lectura autenticada de `GET /api/v1/projects`, desde la red Docker, ejecutó
100 solicitudes con concurrencia 10: 0 errores, 67,44 rps y p95 de 281,42 ms.
El usuario de esta primera medición era administrador; la siguiente fase debe
usar un rol normal para incluir la ruta RBAC completa.

## Cambios protegidos por pruebas

- Los permisos efectivos se resuelven con `EXISTS` o una consulta unida, sin
  cargar en cascada usuario, roles, asignaciones y permisos.
- El listado de evidencia precarga su fuente en la misma consulta y evita una
  consulta adicional por elemento.
- Hay pruebas de regresión sobre la forma SQL, la delegación de autorización y
  la configuración del benchmark.
- La suite completa aprueba 137 pruebas y Ruff sin errores.

## Interpretación

El objetivo local de liveness y la lectura administrativa quedan aprobados. No
es todavía un benchmark completo de negocio: faltan RBAC no privilegiado,
escritura por lotes, reportes y RAG con datos sintéticos deterministas. Esos
escenarios deben medir
p50/p95/p99, consultas SQL por solicitud, espera del pool, tamaño de respuesta
y throughput antes de aceptar capacidad de producción.

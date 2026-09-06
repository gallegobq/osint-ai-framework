# ADR-0006: Ollama como planificador restringido de búsquedas

## Estado

Aceptado — 2026-08-15.

## Contexto

El catálogo creció de dos colectores a fuentes heterogéneas para dominios, IP,
ASN, URL, usuarios y palabras clave. Codificar una combinación fija por tipo
impide adaptar la búsqueda al objetivo, mientras que permitir a un LLM llamar
red, comandos o herramientas arbitrarias introduce SSRF, prompt injection,
costes no controlados y pérdida de trazabilidad.

## Decisión

Ollama actúa únicamente como planificador. Recibe un catálogo cerrado de
colectores disponibles y devuelve JSON validado con el nombre de la herramienta
y un índice de blanco. El servidor genera y normaliza los argumentos, aplica
RBAC, límites, compatibilidad de tipos y política pasiva/activa, y el worker
ejecuta adaptadores registrados. Existe fallback determinista configurable.

Cada orquestación se persiste como `search_run`; cada herramienta conserva un
`collection_job` hijo y toda salida pasa por `EvidenceService`.

## Consecuencias

- Ollama puede mejorar cobertura sin obtener capacidad de ejecución arbitraria.
- Un modelo ausente o defectuoso no bloquea el uso local predeterminado.
- Agregar una fuente requiere implementar el puerto `Collector`, declarar
  metadatos y registrarla; no cambia el orquestador.
- Las fuentes de pago permanecen visibles pero no disponibles hasta configurar
  la clave correspondiente.
- La ejecución secuencial favorece cuotas y simplicidad; paralelismo controlado
  puede añadirse cuando existan métricas y límites por proveedor.

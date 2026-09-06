# LLM, prompts y revisión humana

## Diseño

`LLMProvider` desacopla el caso de uso del proveedor. La primera implementación
es Ollama para mantener evidencia dentro de la infraestructura controlada. La
selección ocurre mediante `LLM_PROVIDER`.

Los prompts tienen versión (`v1`) y viven en `app/llm/prompts`. El trabajo
registra proveedor y versión para trazabilidad.

## Tipos

- `summary`: resumen, hallazgos con IDs de evidencia y vacíos.
- `entities`: entidades candidatas con confianza y evidencia.
- `relations`: relaciones candidatas con confianza y evidencia.
- `sentiment`: clasificación del texto, no juicio factual sobre personas.

## Controles

- La evidencia se delimita explícitamente como datos no confiables.
- La temperatura es cero y la respuesta solicitada es JSON.
- Cada tipo de análisis tiene un contrato Pydantic estricto; se rechazan campos
  inesperados, confianzas fuera de rango y citas ajenas al contexto.
- El contexto se limita con `LLM_MAX_EVIDENCE_CHARACTERS`.
- Cada resultado conserva los IDs incluidos en el contexto.
- `human_review_required` siempre es verdadero.
- La salida no crea automáticamente entidades o relaciones persistentes.

Estos controles reducen riesgo, pero no eliminan prompt injection,
alucinaciones, sesgo o omisiones.

## Operación Ollama

```bash
docker compose up --build -d postgres redis api worker
docker compose logs -f ollama
```

Compose inicia Ollama como dependencia de API/worker. Su entrypoint espera al
servidor, comprueba `OLLAMA_MODEL`, lo descarga si falta y solo entonces supera
el `healthcheck`. El volumen `ollama_data` evita repetir la descarga. Cambia el
modelo en `.env` antes del despliegue y vuelve a crear el servicio.

Variables:

| Variable | Uso |
|---|---|
| `LLM_PROVIDER` | Adaptador; actualmente `ollama` |
| `OLLAMA_URL` | Endpoint interno |
| `OLLAMA_MODEL` | Modelo exacto |
| `LLM_TIMEOUT_SECONDS` | Timeout por generación |
| `LLM_MAX_EVIDENCE_CHARACTERS` | Límite de contexto |

## Incorporar nube

Antes de añadir un proveedor externo se requiere aprobación explícita de:

1. Región de procesamiento y residencia.
2. Retención/entrenamiento del proveedor.
3. Categorías de evidencia permitidas y redacción de PII.
4. Gestión de claves, presupuesto y límites.
5. Contrato de salida y evaluaciones.

El adaptador nuevo debe implementar `LLMProvider`; el dominio no debe importar
el SDK del proveedor.

## Evaluación

Mantén un corpus anonimizado y versionado con respuestas esperadas. Mide:

- validez JSON;
- precisión de citas;
- afirmaciones no sustentadas;
- omisiones críticas;
- estabilidad por versión de modelo/prompt;
- latencia y consumo.

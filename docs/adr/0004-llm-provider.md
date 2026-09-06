# ADR-0004: Ollama detrás de un puerto LLM

- Estado: Accepted
- Fecha: 2026-08-15

## Contexto

La evidencia puede contener PII y texto hostil. Acoplar el dominio a un SDK de
nube crea riesgo de residencia, costo y fuga.

## Decisión

Definir `LLMProvider` e implementar primero Ollama local. Versionar prompts,
solicitar JSON, limitar contexto y marcar todo resultado para revisión humana.
No promover salidas automáticamente a evidencia o hechos.

## Consecuencias

El operador debe provisionar modelo y recursos. La calidad depende del modelo.
Un proveedor futuro puede añadirse sin cambiar servicios, previa aprobación de
privacidad y seguridad.

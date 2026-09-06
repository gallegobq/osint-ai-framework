# Primera entrega y diferenciación de Linterna

## Tesis de producto

Linterna no debe competir por cantidad de fuentes. Su ventaja defendible es
convertir señales OSINT y conocimiento interno del SOC en decisiones
reproducibles: qué se observó, de dónde salió, qué procedimiento aplica, qué
falta por confirmar y quién aprobó la conclusión.

El bucle distintivo propuesto es:

1. recolectar una señal dentro de un alcance autorizado;
2. preservar procedencia y huella digital;
3. relacionarla con entidades, incidentes y conocimiento SOC;
4. recuperar el playbook o antecedente pertinente;
5. producir una hipótesis citada, nunca un hecho automático;
6. registrar la decisión humana y medir su resultado;
7. reutilizar ese resultado revisado como memoria del equipo.

La novedad práctica está en unir OSINT, operación SOC, memoria institucional y
gobierno de evidencia en un único flujo local. Un chat sin citas o un catálogo
de colectores no constituyen por sí solos una diferenciación sostenible.

## Alcance de la primera entrega

### Ya disponible

- proyectos, investigaciones, RBAC y auditoría;
- evidencia con procedencia, hash y deduplicación;
- recolección pasiva y validación activa aislada;
- hallazgos, vigilancia, reportes y exportaciones SOC;
- LLM local con contratos estrictos y revisión humana;
- interfaz Linterna para el flujo operativo principal;
- base RAG SOC aislada por proyecto;
- ingesta de `playbook`, `runbook`, `standard`, `incident`, `threat_intel` y
  `note`;
- fragmentación estable, embeddings locales y recuperación híbrida;
- respuestas con citas verificadas contra los fragmentos recuperados;
- abstención cuando la relevancia no supera el umbral configurado.

### Criterio de entrega aceptable

La primera entrega se considera cerrada cuando un analista puede, desde la
interfaz:

1. crear un proyecto y una investigación;
2. recolectar o registrar evidencia autorizada;
3. convertirla en un hallazgo trazable;
4. indexar al menos un playbook SOC aprobado;
5. consultar Linterna y abrir la procedencia de cada cita;
6. exportar un reporte y un artefacto SIEM/STIX;
7. repetir el recorrido en una instalación limpia con una prueba documentada.

Además, debe existir un conjunto de evaluación con preguntas conocidas y
umbrales mínimos: recuperación correcta, citas válidas, abstención, latencia y
ausencia de filtración entre proyectos.

## Lo que falta para cerrar la primera entrega

Prioridad P0:

- prueba integral del recorrido completo sobre Docker limpio;
- corpus SOC inicial revisado por un responsable humano;
- evaluación automática de recuperación, citas, abstención y aislamiento;
- apertura directa de cada cita hasta el fragmento y documento fuente;
- reindexado y retiro auditable de documentos obsoletos;
- carga asíncrona para que documentos extensos no bloqueen la API;
- política de clasificación, secretos y caducidad del corpus.

Prioridad P1:

- ingesta segura de PDF, Markdown y texto con antivirus y límites;
- filtros por tipo, fecha, versión y ámbito del playbook;
- incorporación explícita de evidencia de una investigación al contexto RAG;
- feedback del analista (`útil`, `incorrecto`, `cita insuficiente`) sin convertir
  respuestas no revisadas en conocimiento;
- panel de calidad con tasa de abstención, cobertura y citas rechazadas;
- PostgreSQL full-text y `pgvector` cuando las mediciones justifiquen mover la
  recuperación fuera del proceso de aplicación.

## Próximo diferenciador

El siguiente incremento debería ser un “brief de incidente reproducible”:
Linterna combina evidencia del caso, grafo de entidades, diferencias temporales
y playbooks recuperados para proponer una secuencia de triage. Cada paso muestra
su evidencia, su fuente normativa, su incertidumbre y el punto exacto donde debe
decidir un humano. El resultado se exporta y puede reproducirse con los mismos
IDs y versiones de corpus.

No se recomienda ajustar pesos del modelo todavía. Para esta etapa,
“entrenamiento” significa curar, versionar, indexar y evaluar conocimiento con
RAG. Un fine-tuning solo tendría sentido después de reunir ejemplos aprobados,
un objetivo medible y controles para evitar memorizar datos sensibles.

## Arquitectura RAG inicial

- Ámbito: un corpus independiente por proyecto.
- Generación: Ollama local con temperatura cero.
- Embeddings: modelo local configurado por `RAG_EMBEDDING_MODEL`.
- Almacenamiento: vectores JSON en PostgreSQL para una primera escala acotada.
- Recuperación: 75 % similitud coseno y 25 % cobertura léxica.
- Seguridad: contexto marcado como no confiable y salida validada con Pydantic.
- Gobierno: hash SHA-256, URI de origen, creador, fecha, auditoría y revisión
  humana obligatoria.
- Límite: la recuperación actual recorre un máximo configurado de fragmentos;
  no es todavía una solución para corpus masivos.


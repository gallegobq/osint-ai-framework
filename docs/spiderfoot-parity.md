# Paridad de Linterna con SpiderFoot y plataformas OSINT

Fecha de corte: 2026-10-03. Esta matriz separa lo implementado de lo planeado;
no presenta una aspiración como funcionalidad disponible.

## Referencias comparadas

- El commit SpiderFoot OSS de referencia contiene 233 archivos `sfp_*.py`;
  al excluir su plantilla quedan 232 módulos cargables. También ofrece
  publicación/suscripción entre módulos, perfiles, visualizaciones y exportaciones
  CSV/JSON/GEXF en su [repositorio oficial](https://github.com/smicallef/spiderfoot#readme).
- Su [plantilla oficial de módulo](https://github.com/smicallef/spiderfoot/blob/master/modules/sfp_template.py)
  muestra cómo un evento producido conserva el evento padre y notifica a los
  módulos suscritos.
- Su [motor de correlación](https://github.com/smicallef/spiderfoot/blob/master/correlations/README.md)
  usa reglas YAML con colección, agregación, análisis, riesgo y titular.
- IntelOwl organiza extensiones como analizadores, conectores, pivots,
  visualizadores, ingestors y playbooks, con kill/retry/healthcheck, según su
  [documentación oficial](https://github.com/intelowlproject/docs/blob/main/docs/IntelOwl/usage.md).
- Recon-ng aporta workspaces aislados y un marketplace de módulos con versión,
  dependencias y claves declaradas en sus
  [funciones oficiales](https://github.com/lanmaster53/recon-ng/wiki/Features).
- OpenCTI separa conectores de importación, enriquecimiento, stream y archivos,
  normalizados como STIX 2.1, en su
  [documentación oficial](https://github.com/OpenCTI-Platform/opencti/blob/master/docs/docs/deployment/connectors.md).

## Estado de paridad

| Capacidad | Referencia | Linterna | Estado |
|---|---|---|---|
| Perfiles de escaneo | SpiderFoot | `auto`, `passive`, `footprint`, `investigate`, `all`; API/UI y scheduler | Implementado |
| Catálogo declarativo | SpiderFoot / Recon-ng | tipo de blanco, perfil, modo pasivo, clave y disponibilidad | Implementado |
| Jobs durables y reintentos | IntelOwl / OpenCTI | PostgreSQL, Redis, Celery, claim idempotente y backoff | Implementado |
| Investigación multiusuario | IntelOwl / HX | proyectos, membresías, RBAC, MFA, evidencia y hallazgos | Implementado |
| Programación | HX / IntelOwl | vigilancia recurrente pasiva con revalidación | Implementado |
| Procedencia e integridad | SpiderFoot | fuente, localizador, tiempo, SHA-256, HMAC y auditoría encadenada | Implementado |
| Exportación CTI/SIEM | OpenCTI | STIX 2.1, NDJSON y CEF | Implementado |
| Encadenamiento por eventos | SpiderFoot | base implementada: emisores explícitos, grafo durable y recorrido pasivo opt-in con límites; falta ampliar emisores y suscripciones | Parcial |
| Correlación declarativa | SpiderFoot | hallazgos manuales/LLM, sin DSL de reglas | Pendiente |
| Playbooks/pivots | IntelOwl | perfiles disponibles; falta DAG versionado y condiciones | Pendiente |
| Marketplace aislado | Recon-ng | registro cerrado en código; falta SDK firmado y sandbox por módulo | Pendiente |
| Conectores bidireccionales | OpenCTI / IntelOwl | exportación por archivo; falta entrega durable a MISP/OpenCTI/SIEM | Pendiente |
| Amplitud de módulos | SpiderFoot | 85 módulos ejecutables únicos frente a 232; objetivo Linterna: 233 | Parcial |

## Orden de implementación

1. **Correlación**: reglas declarativas versionadas sobre evidencia y grafo,
   resultados explicables y pruebas con datasets sintéticos.
2. **Ampliación del grafo**: más emisores/suscriptores, métricas de cobertura y
   reanudación idempotente de capas interrumpidas.
3. **Playbooks**: DAG con condiciones, retry/cancelación por nodo, snapshots de
   configuración y referencias a secretos, nunca secretos serializados.
4. **Conectores**: importación, enriquecimiento y sinks durables STIX/TAXII,
   MISP, OpenCTI y SIEM con idempotencia y cola de fallos.
5. **Ecosistema**: SDK de módulo, manifiesto, healthcheck, firma, permisos de
   red/secretos y ejecución aislada antes de admitir extensiones externas.

Linterna no copiará debilidades del diseño histórico: módulos importados dentro
del servidor, estado sólo en memoria, secretos exportables, SQL arbitrario o
payloads grandes dentro del bus de eventos. La paridad se medirá por cobertura
funcional, reproducibilidad, seguridad y operación, no sólo por cantidad de
módulos.

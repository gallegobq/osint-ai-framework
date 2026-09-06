# Roadmap

## Implementado en el checkpoint actual

- Sprint 0: estabilización, configuración, migraciones, identidad y RBAC.
- Sprint 1: proyectos, membresía, investigaciones, tareas y auditoría.
- Sprint 2: evidencia, procedencia, hashes, entidades y relaciones.
- Sprint 3: puertos de colector, DNS/RDAP, Celery/Redis y estados de trabajo.
- Sprint 4: puerto LLM, Ollama, prompts versionados y revisión humana.
- Sprint 5: búsqueda básica y reportes JSON/Markdown citados.
- Sprint 6: orquestación Ollama restringida, búsquedas multiobjetivo, 42
  colectores, ejecución auditable y fallback determinista.
- Sprint 7: observables hostname/email/hash/CVE, NVD/CISA KEV/EPSS, hallazgos,
  STIX 2.1, SIEM NDJSON/CEF y vigilancia pasiva programada.
- Endurecimiento de preproducción: MFA TOTP, rate limiting Redis, métricas,
  proxy TLS local, secretos por archivo, scripts de backup/restore/verificación,
  prueba de carga, escaneo Trivy y metadatos de retención/legal hold.
- Sandbox SOC separado con perfil activo TLS/HTTP no destructivo, permiso RBAC
  independiente, red dedicada, alcance exacto y evidencia normalizada.
- Base RAG SOC de Linterna aislada por proyecto, con documentos trazables,
  embeddings locales, recuperación híbrida y citas validadas.

## Próximos incrementos recomendados

### Producción y cumplimiento

- Recuperación MFA administrada, política corporativa de contraseñas y SSO/OIDC.
- Almacenamiento de objetos cifrado para archivos y hash/verificación.
- Ejecución aprobada de eliminación verificable al vencer retención.
- Exportación/rectificación de datos personales según jurisdicción.
- Trazas distribuidas, alertas y envío autenticado al SIEM elegido.
- Auditoría de autenticación, ciclo de vida de identidad y cambios RBAC, con
  exportación inmutable y política de acceso.

### Investigación

- Comentarios, etiquetas, timeline y revisión/aprobación de hallazgos.
- Promoción controlada de candidatos LLM a entidades verificadas.
- Búsqueda full-text PostgreSQL y grafo especializado si el volumen lo exige.
- PDF firmado y paquetes de evidencia reproducibles.
- Evaluación RAG, versionado/retiro de corpus, feedback humano y briefs de
  incidente que unan evidencia, grafo, cambios temporales y playbooks.

### Integraciones sujetas a aprobación

- Nuevas fuentes comerciales distintas de los conectores Shodan, VirusTotal y
  SecurityTrails ya preparados.
- Proveedor LLM de nube con redacción y residencia aprobadas.
- SSO/OIDC corporativo.
- Almacenamiento S3 compatible y antivirus/sandbox de archivos.

## Decisiones pendientes antes de producción

1. Jurisdicciones, base legal y política de retención.
2. Proveedores/datasets autorizados y sus credenciales.
3. Requisitos de multitenancy estricto.
4. Objetivos de disponibilidad, volumen, RPO y RTO.
5. Estrategia de despliegue y gestor de secretos.

Estas decisiones no bloquean desarrollo local, pero sí un despliegue con datos
reales.

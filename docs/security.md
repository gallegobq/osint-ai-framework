# Seguridad y uso responsable

## Modelo de amenazas resumido

| Amenaza | Control implementado | Trabajo adicional |
|---|---|---|
| Robo de contraseña | Argon2 mediante `pwdlib` | MFA/WebAuthn |
| Robo/reuso de token | JTIs, hash de refresh, rotación y revocación | Detección por familia de tokens |
| Escalada horizontal | RBAC + membresía por proyecto en servicio | Pruebas de matriz completas |
| Inyección SQL | Expresiones SQLAlchemy y listas blancas | SAST continuo |
| SSRF | HTTPS, destinos fijos, DNS público validado, límites y blancos normalizados | Proxy de egreso de infraestructura |
| Prompt injection | Evidencia delimitada como no confiable | Clasificador/guardrails adicionales |
| Abuso del agente | Ollama sólo propone nombres de una allowlist; el servidor crea argumentos | Evaluaciones continuas del planificador |
| Prueba activa fuera de alcance | Modo pentest, permiso RBAC separado, alcance persistido y exacto, autorización explícita, ventana, doble validación API/worker y sandbox con perfil cerrado | Proxy de egreso y aprobación de perfiles activos adicionales |
| Alucinación LLM | Evidencia citada y revisión humana obligatoria | Evaluaciones y aprobación UI |
| Fuga de secretos | `.env` ignorado y respuestas sin infraestructura | Gestor de secretos en producción |
| Abuso de API | Validación y RBAC | Rate limiting/WAF |
| Pérdida de evidencia | Hash y procedencia | Firma, WORM y backups inmutables |

## Secretos

- Nunca confirmes `.env` en Git ni lo incluyas en entregas.
- `SECRET_KEY` debe tener alta entropía y rotarse mediante un procedimiento que
  considere la invalidación de tokens existentes.
- Usa secretos Docker/Kubernetes/Vault en producción.
- Separa credenciales de PostgreSQL, PgAdmin y administrador de aplicación.
- No envíes credenciales a prompts o campos JSON de evidencia.

## JWT y sesiones

- Access tokens cortos; refresh tokens más largos y rotados.
- Cada access JTI debe corresponder a una sesión activa del mismo usuario.
- Desactivación, borrado lógico y cambio/reset de contraseña revocan sesiones.
- Los algoritmos permitidos se configuran de forma explícita. Producción debe
  mantener `HS256` con una clave fuerte o migrar de forma planificada a claves
  asimétricas.

## OSINT responsable

Antes de habilitar una fuente verifica:

1. Base legal, autorización y jurisdicción.
2. Términos de servicio, robots y límites documentados.
3. Minimización: recolectar solo lo pertinente.
4. Retención y eliminación acordes al caso.
5. Protección reforzada para PII, menores y categorías sensibles.
6. Revisión humana antes de decisiones con impacto sobre personas.

Cada búsqueda orquestada exige confirmación explícita de autorización. Esa
confirmación es un control de flujo y auditoría, no sustituye asesoría legal ni
convierte un blanco no autorizado en permitido.

Las investigaciones de superficie de ataque y respuesta a incidentes nunca
admiten colectores activos. Pentest los admite únicamente cuando el engagement
tiene alcance documentado, autorización explícita y ventana vigente. Cada
ejecución debe repetir la confirmación y describir el alcance específico.

Este software no debe utilizarse para acceso no autorizado, evasión de límites,
acoso, doxxing ni decisiones exclusivamente automatizadas.

## Despliegue

- Termina TLS en un proxy confiable y conserva `TrustedHostMiddleware`.
- Configura `TRUSTED_HOSTS` y `CORS_ALLOWED_ORIGINS` sin comodines.
- No expongas PostgreSQL, Redis, Ollama o PgAdmin a Internet.
- Ejecuta API y worker con usuarios sin privilegios.
- Centraliza logs excluyendo tokens, cuerpos y parámetros sensibles.
- Los errores persistidos de workers conservan la clase del fallo, no el
  contenido de respuestas externas o del modelo.
- Añade límites de CPU/memoria, cuotas y timeout de salida.

## Respuesta a incidentes

1. Deshabilita el acceso afectado y revoca sesiones.
2. Rota secretos y credenciales comprometidos.
3. Conserva logs/auditoría de forma forense sin alterar evidencia.
4. Determina proyectos y sujetos afectados.
5. Notifica según obligaciones legales.
6. Corrige la causa, agrega prueba de regresión y documenta el incidente.

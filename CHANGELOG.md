# Changelog

## Unreleased — 2026-08-30

### Added

- Sandbox SOC aislado para una línea base TLS/HTTP activa de bajo impacto, sin
  shell ni argumentos arbitrarios y con límites de CPU, memoria, procesos,
  filesystem y red.
- Permiso independiente `collection:execute_active`, comprobación exacta de
  blancos en el alcance del engagement y en la nota de cada ejecución.
- Evidencia normalizada de TLS, certificado, estado HTTP, cabeceras de seguridad
  y límites efectivos del perfil ejecutado.

- Dockerfile y stack Compose con PostgreSQL, Redis, API, worker y Ollama/PgAdmin
  opcionales.
- Bootstrap explícito de superusuario y catálogo RBAC ampliado.
- Ciclo de vida completo de usuarios.
- Proyectos, miembros, investigaciones y tareas.
- Evidencia, fuentes, entidades, relaciones, búsqueda y reportes.
- Jobs Celery persistidos, colectores DNS/RDAP y proveedor Ollama.
- Auditoría, request IDs, headers de seguridad, CORS y trusted hosts.
- Pruebas unitarias/estructurales y documentación operativa/arquitectónica.
- Verificadores integrales para PowerShell y WSL/Linux.
- Auxiliar confirmado para alinear la contraseña de un volumen PostgreSQL
  existente con `.env` sin eliminar datos.
- Verificación Docker reordenada para ejecutar migraciones/seeds con API y
  worker detenidos, reduciendo memoria y evitando readiness prematuro.
- Matrices de configuración, despliegue y supervisión humana.
- Orquestador de búsquedas persistente con Ollama, validación de planes,
  fallback determinista, trabajos hijos y estados parciales.
- Catálogo de 22 recolectores para dominios, IP, ASN, URL, perfiles y palabras
  clave, incluyendo adaptadores opcionales Shodan, VirusTotal y SecurityTrails.
- Cliente HTTP acotado con HTTPS, allowlist de hosts, validación de resolución,
  límites de respuesta y secretos fuera de consultas persistidas.

### Fixed

- Evaluación diferida de anotaciones en servicios con operaciones `list`,
  evitando que el nombre del método oculte al tipo incorporado al importar ASGI.
- Ruta de importación y caché escribible para pytest dentro de la imagen de
  pruebas, manteniendo el código ejecutado por un usuario sin privilegios.
- Pruebas de catálogo RBAC y rutas desacopladas de descriptores especiales y
  objetos internos de FastAPI; ahora validan constantes públicas y OpenAPI.
- Bootstrap administrativo idempotente ante volúmenes que ya contienen un
  superusuario activo, sin restablecer credenciales ni elevar cuentas normales.
- Recuperación explícita y controlada del administrador de volúmenes heredados,
  con restauración segura, detección de colisiones y revocación de sesiones.
- Diagnóstico automático de estado y logs cuando API/worker no alcanzan salud.

- Migración histórica vacía de sesiones mediante revisión de reparación.
- Instalación limpia de la primera migración.
- Importaciones DI inexistentes/circulares.
- Doble implementación accidental en el router de roles.
- Commits prematuros en repositorios.
- Login de usuarios inactivos y validación de expiración/propiedad de sesiones.
- Asignación implícita e insegura del primer usuario como administrador.
- Validación de propiedad de sesión también durante logout.

### Security

- Resultados LLM requieren revisión humana y conservan IDs de evidencia.
- Salidas LLM validadas por tipo y contra el conjunto real de evidencia citada.
- Errores persistidos de worker sanitizados para no copiar contenido externo.
- Colectores usan destinos controlados y validación estricta de dominios.
- Endpoints de salud no revelan nombres de base o modo debug.
- JWT migrado a PyJWT, con claims obligatorios y algoritmo permitido explícito.
- Retiradas utilidades manuales heredadas con IDs fijos, acceso a datos reales
  o impresión de tokens; su cobertura queda en pytest y el smoke test.
- Retirado el inicializador `create_all`; Alembic es el único mecanismo de
  despliegue del esquema.
- La URL PostgreSQL se construye con `SQLAlchemy.URL`, por lo que contraseñas
  con caracteres reservados no rompen la conexión ni se interpolan a mano.
- Todos los modelos se registran antes de consultas ORM, incluidos comandos
  independientes de bootstrap, seed y workers.

### Verified

- Docker Compose, migraciones en `d84f3c9a1b72`, bootstrap, RBAC, importación
  ASGI y health checks ejecutados correctamente sobre el volumen heredado.
- 34 de 34 pruebas y smoke test HTTP aprobados el 2026-08-15.

# Capacidades, alcance y potencial

Este documento describe el estado real de **Linterna / OSINT AI Framework** en
el checkpoint actual. Distingue lo que funciona hoy de las ampliaciones
posibles. La existencia pública de un dato no implica que la aplicación ya
tenga un conector para encontrarlo ni que su tratamiento esté autorizado.

## Resumen ejecutivo

Linterna es una aplicación local para organizar investigaciones OSINT y de
ciberseguridad. Recibe un objetivo en lenguaje natural, detecta blancos
compatibles, pide a Ollama que proponga un plan limitado al catálogo permitido,
ejecuta colectores pasivos en segundo plano y guarda resultados como evidencia
trazable. En pentest autorizado puede ejecutar además una línea base TLS/HTTP
aislada. También admite evidencia manual y genera expedientes Markdown/JSON.

Actualmente ofrece:

- autenticación, sesiones, roles y membresías por proyecto;
- proyectos e investigaciones separadas por modo operativo;
- 43 perfiles: 42 colectores pasivos —37 sin clave y 5 opcionales con
  credencial— y 1 validación TLS/HTTP activa aislada;
- observables de dominio, hostname, IP pública, ASN, URL pública, email, hash,
  CVE, usuario y palabra clave;
- evidencia con procedencia, fecha, SHA-256 y deduplicación;
- análisis local con Ollama y fallback determinista si el modelo falla;
- hallazgos SOC con severidad, estado, confianza y remediación;
- búsquedas pasivas programadas con revalidación de autorización;
- reportes citados Markdown/JSON y exportaciones STIX 2.1, NDJSON y CEF;
- MFA TOTP, rate limiting Redis, métricas, retención y legal hold;
- despliegue local con Docker, PostgreSQL, Redis, Celery y Ollama.

La interfaz, la base de datos y Ollama se ejecutan localmente. Sin embargo, los
colectores consultan servicios externos por Internet: el proveedor consultado
puede observar la IP de salida y el dominio, usuario o término enviado. “Local”
no significa “sin tráfico externo”.

## Flujo funcional actual

1. El operador crea un proyecto y documenta su alcance.
2. Crea una investigación de superficie de ataque, respuesta a incidentes o
   pentesting autorizado.
3. Escribe una pregunta y, opcionalmente, un blanco explícito.
4. El servidor normaliza el blanco. Si se dejó automático, extrae URL, dominio,
   hostname, IP, ASN, email, hash, CVE o `@usuario`; cuando no encuentra uno
   usa la consulta completa como palabra clave.
5. Ollama sólo puede seleccionar colectores registrados y compatibles. No
   ejecuta comandos, no inventa herramientas y no recibe claves de API.
6. El worker consulta cada fuente de forma secuencial y limitada.
7. Cada resultado se persiste como evidencia con fuente y hash. La ejecución
   termina como `succeeded`, `partial` o `failed`.
8. El operador revisa evidencia, registra hallazgos SOC y descarga Markdown,
   STIX 2.1 o formatos SIEM. También puede programar la búsqueda para detectar
   cambios.

Si una fuente responde con límite de cuota, timeout o error temporal, el resto
puede completarse y la ejecución queda `partial`. Esto no significa que toda la
búsqueda haya fallado.

## Modos de ciberseguridad

| Modo | Lo que hace hoy | Límite actual |
|---|---|---|
| Superficie de ataque | Reúne DNS, RDAP, certificados, históricos, presencia pública e infraestructura relacionada mediante consultas pasivas. | No escanea puertos ni valida vulnerabilidades activamente. |
| Respuesta a incidentes | Enriquece IP, dominio, hostname, URL, hash y CVE; conserva evidencia con tiempo y procedencia y exporta STIX/NDJSON/CEF. | No ingiere automáticamente EDR, buzones, archivos o logs, ni envía directamente a un SIEM. |
| Pentesting autorizado | Registra alcance, propietario/autorización, ventana y confirmación por ejecución; aplica la política también en el worker y ofrece una línea base TLS/HTTP aislada. | No hay todavía escaneo de puertos, ZAP, Nuclei, testssl.sh ni explotación. |

El modo no convierte un objetivo ajeno en autorizado. Consulta
[operation-modes.md](operation-modes.md) para las reglas completas.

## Cobertura de fuentes

| Blanco | Fuentes sin clave | Fuentes opcionales con clave |
|---|---|---|
| Dominio | DNS, DNS completo por DoH, RDAP, crt.sh, Cert Spotter, Wayback, Common Crawl, urlscan.io | VirusTotal, SecurityTrails |
| IP pública | RDAP, reverse DNS, RIPEstat, Shodan InternetDB | Shodan, VirusTotal |
| ASN | RDAP, RIPEstat, PeeringDB | — |
| URL pública | Wayback, Common Crawl | — |
| Hostname | DNS, certificados, Wayback, Common Crawl, urlscan.io, Cert Spotter | VirusTotal |
| Email | MX/TXT del dominio; nunca transmite la parte local | — |
| CVE | NIST NVD, CISA KEV, FIRST EPSS | — |
| Hash MD5/SHA-1/SHA-256 | — | VirusTotal |
| Usuario | GitHub, repositorios GitHub, GitLab, Bluesky, Hacker News, paquetes npm | — |
| Palabra clave | Wikidata, Wikipedia, OpenAlex, GDELT, Crossref, Open Library, Stack Overflow, Europe PMC, Google Books, Hacker News | — |

El inventario técnico, controles de red y procedimiento para añadir adaptadores
están en [collectors.md](collectors.md). `GET /api/v1/collectors` es la fuente de
verdad en tiempo de ejecución sobre disponibilidad y claves requeridas.

## Redes sociales

Sí puede consultar una parte de la presencia social pública, pero no todas las
redes ni “todo lo público”. La cobertura actual es la siguiente:

| Plataforma o ámbito | Estado actual | Qué puede obtener |
|---|---|---|
| GitHub | Disponible | Perfil público exacto por usuario y repositorios públicos. |
| GitLab.com | Disponible | Perfil que la API pública expone para el nombre de usuario. |
| Bluesky | Disponible | Perfil público por handle. |
| Hacker News | Disponible | Perfil público, metadatos e identificadores de actividad. |
| npm | Disponible | Paquetes públicos asociados al mantenedor consultado. |
| Stack Overflow | Indirecto | Búsqueda pública por palabra clave, no resolución de identidad personal. |
| LinkedIn | No disponible | La API oficial de perfiles tiene acceso restringido y autorización del miembro; no se consulta un directorio arbitrario. |
| Facebook, Instagram, X/Twitter, TikTok, Reddit | No disponible | No hay colectores registrados en este checkpoint. |

No se eluden inicios de sesión, CAPTCHA, controles de privacidad, paywalls ni
restricciones de API. Un mismo alias en dos plataformas **no demuestra** que
sea la misma persona; es sólo una pista que exige corroboración. GitHub y
GitLab pueden devolver un correo únicamente si el propio perfil/API lo publica,
pero Linterna no lo usa como método de búsqueda inversa.

Referencias oficiales: [GitHub REST Users](https://docs.github.com/en/rest/users/users),
[GitLab Users API](https://docs.gitlab.com/api/users/),
[Bluesky public profiles](https://docs.bsky.app/docs/tutorials/viewing-profiles),
[Hacker News API](https://github.com/HackerNews/API) y
[LinkedIn Profile API](https://learn.microsoft.com/en-us/linkedin/shared/integrations/people/profile-api).

## Correos electrónicos y datos públicos

Existe el tipo de blanco `email`, pero su alcance está deliberadamente
minimizado. La dirección se valida localmente, se extrae su dominio y sólo se
consultan MX/TXT. La parte anterior a `@` no se transmite ni queda en la
evidencia del colector. Esto no equivale a búsqueda de cuentas, filtraciones o
redes sociales. Tampoco se consultan buzones, mensajes privados, contraseñas o
bases filtradas.

Además, un perfil de GitHub/GitLab puede incluir un correo que su titular haya
decidido publicar, y el operador puede registrar una observación lícita como
evidencia manual con su URL y contexto.

Una integración futura razonable es Have I Been Pwned mediante su API oficial,
con clave, minimización de PII, retención definida y base legal. Las búsquedas
de cuentas por correo requieren suscripción; las búsquedas de dominio requieren
verificación del dominio. No se debe almacenar ni mostrar contenido de una
filtración. Referencia: [Have I Been Pwned API v3](https://haveibeenpwned.com/API/V3).

## Qué significa “todo lo público”

La aplicación consulta un catálogo cerrado de APIs e índices conocidos. No es
un motor de búsqueda general, no rastrea toda la web y no garantiza exhaustividad.
Un resultado puede faltar porque:

- la plataforma no tiene conector o exige acceso contractual;
- la API no expone ese campo aunque sea visible en una página;
- el contenido fue eliminado, desindexado, limitado por región o cuota;
- el alias o término es ambiguo;
- el dato requiere autenticación o es privado;
- los términos de la fuente no permiten esa recolección.

La información pública sigue siendo dato personal cuando identifica a alguien.
Debe existir propósito legítimo, minimización, retención controlada y revisión
humana. La herramienta no debe usarse para acoso, doxxing, vigilancia masiva,
suplantación ni acceso no autorizado.

## Ollama: función actual y potencial

Ollama se usa localmente como planificador restringido y para análisis de
resumen, entidades, relaciones y sentimiento. El modelo propone; las reglas del
servidor validan y ejecutan. Los resultados de IA son hipótesis y nunca se
promueven automáticamente a hechos verificados.

El modelo **no se entrena ni aprende de cada búsqueda**. Para especializarlo se
recomienda, en este orden:

1. mejorar prompts y ejemplos versionados;
2. ampliar la recuperación local (RAG ya iniciada) a evidencia autorizada,
   versionado y retiro de corpus, siempre citando la fuente;
3. evaluar con un conjunto de casos y métricas reproducibles;
4. considerar fine-tuning sólo si los tres pasos anteriores no bastan y existe
   un dataset lícito, depurado y sin secretos.

El lenguaje natural no amplía permisos: incluso con otro modelo, sólo podrán
ejecutarse colectores registrados y admitidos por la política.

### Brechas actuales de IA

- Existe un RAG inicial sobre documentos SOC por proyecto, con embeddings
  locales almacenados como JSON y recuperación híbrida acotada. Aún no indexa
  automáticamente la evidencia del caso, no versiona/retira corpus y no usa un
  índice vectorial especializado.
- No hay un corpus dorado ni un banco de evaluaciones para medir selección de
  herramientas, exactitud de citas, omisiones, alucinaciones y regresiones por
  versión.
- Los trabajos registran proveedor y versión del prompt, pero no persisten el
  modelo exacto, digest, parámetros de inferencia ni métricas dedicadas de
  latencia/calidad.
- Sólo existe el proveedor Ollama; no hay enrutamiento por tarea, comparación
  de modelos ni proveedor alternativo aprobado.
- La revisión humana es obligatoria en el contrato, pero falta una experiencia
  completa para aceptar, corregir o rechazar candidatos y reutilizar ese
  feedback en evaluaciones.
- Los controles contra prompt injection se basan en delimitación, allowlist y
  schemas estrictos; no hay clasificador, redacción automática de PII ni
  políticas diferenciadas por sensibilidad.
- No hay memoria entre casos, comparación semántica de cambios, explicación de
  alertas ni mapeo asistido a MITRE ATT&CK.
- Docker no declara GPU para Ollama; funciona con CPU, pero la aceleración y los
  perfiles de recursos deben configurarse y medirse por entorno.
- No existe fine-tuning ni entrenamiento continuo, de forma intencional.

La prioridad recomendada es: primero evaluaciones, trazabilidad exacta del
modelo, telemetría y gobierno del RAG ya iniciado; después flujo de aprobación
humana y evidencia de caso recuperable; luego detección de cambios/mapeo ATT&CK
y sólo finalmente valorar fine-tuning.

## Potencial recomendado

Estas capacidades son roadmap, no funcionalidad existente:

### Prioridad 1: defensa e inteligencia

- conector HIBP con controles de privacidad, auditoría y verificación de
  dominio;
- transporte TAXII y conectores directos a MISP/OpenCTI/SIEM;
- mapeo de técnicas a MITRE ATT&CK;
- comparación estructurada entre ejecuciones y alertas locales;
- ingestión y normalización de logs/IOC autorizados;
- enriquecimiento adicional con proveedores aprobados.

### Prioridad 2: respuesta a incidentes

- importación controlada de logs, IOC y archivos pequeños;
- envío autenticado y bidireccional a MISP, OpenCTI y SIEM;
- línea de tiempo, cadena de custodia y exportación de paquetes de evidencia;
- extracción local de indicadores con redacción de datos sensibles.

### Prioridad 3: validación activa autorizada

- Nmap con perfiles seguros, límites de tasa y lista exacta de destinos;
- testssl.sh y ZAP Baseline sin explotación;
- hallazgos normalizados y evidencia reproducible;
- bloqueo técnico fuera del alcance y ventana registrados.

### Redes adicionales

Se pueden añadir sólo cuando exista una API oficial o dataset autorizado, sus
términos permitan el caso de uso y se definan campos, cuota, retención y base
legal. No se recomienda basar el producto en scraping frágil de sesiones web.

## Límites antes de un uso real o de producción

MFA TOTP, rate limiting, métricas, backup/restore local probado, formatos SIEM
y metadatos de retención ya existen como controles de preproducción. Aún se
requiere:

- aprobar jurisdicciones, bases legales y eliminación verificable;
- recuperación de cuenta/SSO y gestión corporativa de identidad;
- auditoría operada de autenticación y cambios RBAC;
- cifrar almacenamiento de archivos antes de admitir adjuntos;
- aprobar proveedores, credenciales, licencias y presupuesto de cuotas;
- automatizar backups externos, aceptar RPO/RTO y operar alertas/monitoreo;
- validar la importación o envío al SIEM elegido;
- cumplir el objetivo de rendimiento y ejecutar una revisión independiente.

Para operar el estado actual, continúa con la [guía de uso](user-guide.md).

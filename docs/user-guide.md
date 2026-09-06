# Guía de uso de Linterna

Esta guía cubre el flujo disponible en la interfaz local de Linterna. Úsala
únicamente sobre activos propios o dentro de un alcance autorizado.

## 1. Iniciar la aplicación

Desde PowerShell, en la raíz del proyecto:

```powershell
docker compose up --build -d postgres redis api worker scheduler
docker compose exec api alembic upgrade head
docker compose exec api python -m app.seed.admin
docker compose exec api python -m app.seed.rbac
```

Abre `http://localhost:8000/`. Ollama se inicia como dependencia y, en el primer
arranque, descarga `OLLAMA_MODEL`; puede tardar según el tamaño del modelo y la
conexión. El estado técnico está en `http://localhost:8000/api/v1/health/ready`.

Inicia sesión con `INITIAL_ADMIN_USERNAME` e `INITIAL_ADMIN_PASSWORD` definidos
en `.env`. No publiques ese archivo.

## 2. Crear el proyecto

1. En **Proyectos**, pulsa **Crear proyecto**.
2. Escribe un nombre y un identificador en minúsculas con guiones.
3. En la descripción registra propósito, propietario, alcance y exclusiones.
4. Guarda el proyecto.

Ejemplo de descripción:

> Inventario pasivo de mis dominios y perfiles públicos. Sólo se incluyen
> example.com, la IP 203.0.113.10 y los alias que controlo. No se realizarán
> pruebas activas ni se tratarán cuentas de terceros.

Sustituye los ejemplos reservados por objetivos que controles al ejecutar una
búsqueda real.

## 3. Elegir el modo de investigación

Pulsa **Nueva investigación** y elige:

- **Superficie de ataque** para inventario externo y huella pasiva.
- **Respuesta a incidentes** para enriquecer indicadores y documentar un caso.
- **Pentesting autorizado** para un engagement formal. Exige alcance detallado,
  autorización activa y ventana de inicio/fin con zona horaria.

El modo queda fijo para preservar la frontera de autorización. Si cambia el
objetivo, crea otra investigación.

Registra también la jurisdicción, la base legal y la clasificación de los
datos. La política de la instancia puede hacer obligatorios los dos primeros.
Una investigación puede definir una fecha de retención y `legal_hold` mediante
la API de gobierno.

En el estado actual, los tres modos ejecutan colectores pasivos. Pentesting ya
aplica las reglas de autorización, pero todavía no incluye escáneres activos.

## 4. Lanzar una búsqueda

Dentro de la investigación, pulsa **Búsqueda OSINT**.

1. Escribe qué quieres confirmar en **Objetivo**.
2. Para la primera prueba, selecciona un **Objetivo explícito** y escribe su
   valor. Esto evita ambigüedades.
3. Añade una nota de alcance o base legal.
4. Marca la confirmación de autorización.
5. Pulsa **Iniciar búsqueda**.

Los tipos aceptados son:

| Tipo | Ejemplo | Uso |
|---|---|---|
| Dominio | `example.com` | DNS, registro, certificados e históricos. |
| Hostname | `vpn.example.com` | DNS, certificados e históricos del host. |
| IP | `8.8.8.8` | Sólo IP públicas globales; RDAP, rDNS e inteligencia pública. |
| ASN | `AS15169` | Registro, enrutamiento y peering. |
| URL | `https://example.com/path` | Históricos públicos de esa URL. |
| Correo | `analista@example.com` | Consulta sólo MX/TXT del dominio; la parte local no se transmite ni se conserva. |
| Hash | SHA-256, SHA-1 o MD5 | Enriquecimiento en VirusTotal cuando existe clave; no sube archivos. |
| CVE | `CVE-2021-44228` | NVD, CISA KEV y FIRST EPSS. |
| Usuario | `octocat` | Perfiles públicos en las plataformas soportadas. |
| Palabra clave | `nombre de empresa Colombia` | Fuentes documentales y noticias soportadas. |

### Detección automática

Puedes dejar tipo y valor vacíos. La aplicación extrae patrones explícitos del
texto, por ejemplo:

```text
Revisa la huella pública de example.com y el ASN AS15169
```

También reconoce hostname, correo, hash, CVE y `@usuario`. Si no detecta
ninguno, usa la frase completa como palabra clave.

Para resultados fáciles de interpretar, realiza búsquedas separadas por
observable: primero el dominio, luego cada hostname, IP, ASN, URL, correo,
hash, CVE o usuario relacionado. No asumas que la coincidencia de un alias
confirma identidad.

## 5. Probar tu huella digital

La forma más segura es comenzar con datos propios y dividir la prueba:

### Perfil público

- Tipo: **Usuario**
- Valor: tu alias exacto, sin contraseña ni token
- Objetivo: `Localizar mis perfiles públicos soportados y elementos que debo verificar`

Esto consulta GitHub, GitLab, Bluesky, Hacker News, repositorios GitHub y npm.
No consulta LinkedIn, Facebook, Instagram, X/Twitter, TikTok o Reddit.

### Nombre o marca

- Tipo: **Palabra clave**
- Valor: tu nombre público o marca con un término contextual
- Objetivo: `Encontrar menciones públicas de mi nombre profesional en Colombia`

Una palabra clave puede devolver homónimos. Trata cada coincidencia como pista,
no como atribución.

### Dominio propio

- Tipo: **Dominio**
- Valor: el dominio que administras
- Objetivo: `Inventariar registros, certificados e históricos públicos de mi dominio`

Puede revelar DNS, MX/TXT, certificados y URLs históricas. Revisa si hay
subdominios antiguos, metadatos innecesarios o servicios que ya deberían estar
retirados.

### Correo propio

Selecciona **Correo**. El colector valida la dirección localmente, extrae el
dominio y consulta únicamente sus registros MX/TXT. Nunca transmite ni guarda
la parte anterior a `@` en la evidencia generada por ese colector. No realiza
búsqueda inversa de cuentas, consulta de buzones, contraseñas, filtraciones ni
HIBP. Para una observación pública verificada por otro medio, usa **Evidencia
manual** con URL, fecha y contexto sin copiar datos sensibles innecesarios.

### CVE o hash observado en un incidente

- Para una CVE, usa el identificador canónico. Se consultan NVD, CISA KEV y
  FIRST EPSS; el analista debe combinar impacto, exposición y probabilidad.
- Para un hash MD5, SHA-1 o SHA-256, configura `VIRUSTOTAL_API_KEY`. Linterna
  consulta el hash y no carga el archivo que lo originó.

## 6. Leer estados y resultados

En **Búsquedas recientes** verás:

- `queued`: esperando al worker;
- `running`: consultando fuentes;
- `succeeded`: el plan terminó sin fallos registrados;
- `partial`: algunas fuentes respondieron y otras fallaron o limitaron cuota;
- `failed`: no fue posible completar el plan.

Actualiza la investigación con `↻`. Los HTTP 429, 503 y timeouts suelen ser
límites o indisponibilidad del proveedor; no intentes eludirlos. Espera y vuelve
a ejecutar sólo si sus términos lo permiten.

La evidencia automática muestra título, contenido observado, identificador
`E{id}` y fecha. Corrobora los hallazgos en la fuente original antes de tomar
decisiones.

## 7. Añadir evidencia manual

Pulsa **Evidencia manual** cuando necesites registrar una comprobación externa.
Completa:

- título verificable;
- tipo (`note`, `domain`, `profile`, `ioc`, etc.);
- recolector (`manual` si fue revisado por una persona);
- tipo de fuente;
- URL/localizador;
- contenido observado y contexto.

No pegues contraseñas, cookies, tokens, datos privados innecesarios ni grandes
volcados. El sistema calcula SHA-256 y deduplica el contenido por investigación.

## 8. Descargar el expediente

Pulsa **Reporte claro en inglés**. El Markdown abre con un resumen ejecutivo en
lenguaje natural, explica dónde se observó información pública, diferencia
visibilidad de vulnerabilidad y propone verificaciones defensivas. Después
incluye las evidencias con referencias `[E{id}]` y un anexo técnico plegable.

La narrativa principal es determinista: descargar el reporte no llama a Ollama
ni consume tokens. Los análisis de IA sólo aparecen cuando ya existe un trabajo
de análisis completado y siempre se marcan como hipótesis pendientes de revisión.
Protege el archivo porque puede contener datos personales o infraestructura
sensible.

La interfaz también descarga STIX 2.1 para intercambio con MISP/OpenCTI y
NDJSON para ingesta o transformación hacia SIEM. El reporte JSON y CEF, junto
con las rutas administrativas avanzadas, están disponibles en Swagger:
`http://localhost:8000/docs`. Son archivos de intercambio; no se envían a un
servicio externo automáticamente.

## 9. Clasificar hallazgos SOC

Pulsa **Crear hallazgo** y registra título, descripción, severidad, confianza
y remediación. Los estados disponibles por API son `open`, `triaged`,
`in_progress`, `accepted`, `resolved` y `false_positive`. La API también
permite asociar una evidencia y una fecha objetivo. Un hallazgo expresa la
evaluación del analista; una coincidencia de un colector no se convierte por sí
sola en vulnerabilidad confirmada.

## 10. Programar vigilancia pasiva

En **Buscar fuentes**, activa **Repetir esta búsqueda**, proporciona un blanco
explícito, frecuencia y alcance autorizado. La API admite intervalos de 15
minutos a 30 días; la interfaz ofrece cada hora, cada seis horas, diariamente o
semanalmente. La primera ejecución ocurre después del primer intervalo.

El proceso `scheduler` revisa programaciones cada minuto. Todas son pasivas,
incluso en pentest, y revalidan usuario, membresía y permisos antes de cada
ejecución. Deshabilita la programación para impedir ejecuciones futuras.

## 11. Ollama y lenguaje natural

Ollama convierte el objetivo en una propuesta de herramientas dentro del
catálogo permitido. El servidor valida la propuesta y el worker ejecuta los
colectores. Si Ollama no responde, el modo predeterminado usa un plan
determinista compatible.

Ejemplos útiles:

```text
Mapea la exposición pública del dominio que controlo y prioriza fuentes de registro e históricos.
```

```text
Enriquece esta IP pública observada en el incidente y conserva procedencia y fecha.
```

```text
Busca la presencia pública del alias y separa hechos de posibles coincidencias.
```

Ollama no aprende automáticamente de tus casos. Para especialización futura,
consulta [capabilities-and-scope.md](capabilities-and-scope.md#ollama-función-actual-y-potencial).

## 12. Claves opcionales

Los colectores Shodan, VirusTotal —dominio, IP y hash— y SecurityTrails se
habilitan con sus claves en `.env`. `URLSCAN_API_KEY` mejora la cuota de
urlscan.io. Reinicia API, worker y scheduler después de cambiar configuración:

```powershell
docker compose up -d --force-recreate api worker scheduler
```

Nunca pegues claves en el cuadro de búsqueda, Swagger, evidencia, logs o
reportes. Revisa antes licencia, cuota, coste y términos del proveedor.

## 13. Comprobaciones y solución de problemas

Estado de contenedores:

```powershell
docker compose ps
```

Logs de API, worker, scheduler y Ollama:

```powershell
docker compose logs --tail 200 api worker scheduler ollama
```

Validación completa:

```powershell
.\scripts\verify.ps1
```

Si cambió el frontend y aún ves la versión anterior, fuerza la recarga del
navegador con `Ctrl+F5`. Si la búsqueda queda en `queued`, revisa el estado y los
logs de `worker` y `redis`. Si readiness falla por Ollama durante el primer
arranque, espera a que termine la descarga del modelo.

## 14. Reglas de uso responsable

- Investiga únicamente activos propios o expresamente autorizados.
- Recoge sólo lo necesario para el objetivo declarado.
- Respeta términos, cuotas, robots y restricciones aplicables.
- No intentes acceder a cuentas, mensajes, contenido privado o filtraciones.
- No uses coincidencias de nombre o alias como prueba de identidad.
- Verifica manualmente las conclusiones generadas por IA.
- Define retención y elimina datos cuando dejen de ser necesarios.
- Separa claramente hechos, inferencias y falsos positivos.

La matriz completa de lo que existe y lo que es roadmap está en
[capacidades y alcance](capabilities-and-scope.md).

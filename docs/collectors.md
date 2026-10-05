# Colectores OSINT

## Contrato

Cada colector implementa:

- `name`: identificador persistente.
- `description`: descripción visible en API.
- `target_types` y `query_field`: compatibilidad declarativa para el planificador.
- `passive`, `requires_api_key` y `availability()`: política y estado operativo.
- `profiles`: casos de uso declarados (`footprint` o `investigate`); `passive`,
  `auto` y `all` se calculan desde el contrato y la política de ejecución.
- `emitted_target_types`: tipos de observable que el adaptador puede descubrir.
- `validate_query(query)`: valida y normaliza entrada no confiable.
- `collect(query)`: devuelve `CollectedItem` sin conocer PostgreSQL; cada
  descubrimiento explícito usa `DiscoveredTarget` con tipo, valor y relación.

El worker convierte cada `CollectedItem` en evidencia mediante el mismo
`EvidenceService` usado por la API. Esto conserva deduplicación, auditoría y
autorización.

## Catálogo incluido

| Tipo | Sin clave | Con credencial opcional |
|---|---|---|
| Dominio | DNS A/AAAA, DNS completo por DoH, RDAP, crt.sh, Cert Spotter, Wayback, Common Crawl, urlscan.io | VirusTotal, SecurityTrails |
| IP pública | RDAP, reverse DNS, RIPEstat, Shodan InternetDB y pertenencia a rangos de Cloudflare, Fastly, Google Cloud, servicios de Google, GitHub, Oracle Cloud, Atlassian Cloud, DigitalOcean, Microsoft 365 y AWS | Shodan, VirusTotal |
| ASN | RDAP, RIPEstat, PeeringDB | — |
| URL pública | Wayback, Common Crawl, OpenPhish, URLhaus | — |
| Hostname | DNS, CT, Wayback, Common Crawl, urlscan.io, Cert Spotter | VirusTotal |
| Email | MX/TXT del dominio; nunca transmite la parte local | — |
| CVE | NIST NVD, CISA KEV y SSVC, FIRST EPSS, CVE Program/MITRE, Red Hat, SUSE CSAF VEX, GitHub Advisory, Ubuntu/Canonical, Debian y rangos Git de OSV | — |
| Hash MD5/SHA-1/SHA-256 | CIRCL hashlookup y certificados SHA-1 de SSLBL | VirusTotal |
| Usuario | GitHub, repositorios GitHub, GitLab, Bluesky, Hacker News, paquetes npm | — |
| Palabra clave | Wikidata, Wikipedia, OpenAlex, GDELT, Crossref, Open Library, Stack Overflow, Europe PMC, Google Books, Hacker News | — |

El endpoint `GET /api/v1/collectors` informa compatibilidad, perfiles, tipos
emitidos, disponibilidad y la variable necesaria sin revelar su valor. urlscan.io permite una cuota
anónima pequeña; `URLSCAN_API_KEY` amplía la capacidad de acuerdo con el plan.
El catálogo actual suma 84 adaptadores: 78 públicos sin clave, 5 opcionales
con credencial y 1 validación activa de bajo impacto ejecutada en el sandbox.
Los tres adaptadores VirusTotal comparten una sola clave.

El primer paquete de expansión añade 19 módulos ejecutables sin duplicar los
tipos DNS que ya cubría el colector agregado:

- ocho consultas DNS especializadas para DS, DNSKEY, HTTPS, DMARC, SPF,
  MTA-STS, TLS-RPT y BIMI, más descubrimiento acotado de servicios SRV comunes;
- cinco verificaciones exactas en listas IP de Tor, Feodo Tracker, IPsum,
  Emerging Threats y CINS Army;
- enriquecimiento IP de ipapi.co, hashes conocidos de CIRCL, identidades
  Keybase, organizaciones GLEIF y host search de HackerTarget.

El segundo paquete añade cinco vistas de vulnerabilidad complementarias y
validadas por identidad: el registro canónico del CVE Program, estados de
producto de Red Hat y Ubuntu/Canonical, SUSE CSAF VEX y GitHub Global
Advisories. Se omiten los campos que duplican las capacidades dedicadas NVD,
CISA KEV y FIRST EPSS, y las respuestas de proveedor se conservan con límites
recursivos de tamaño y profundidad.

El tercer paquete añade estado de paquetes y versiones corregidas de Debian,
los puntos de decisión SSVC publicados por CISA y los rangos de commits Git de
OSV. Cada adaptador conserva sólo la proyección exclusiva de esa fuente:
excluye descripciones, CVSS, KEV, CPE y metadatos ya cubiertos por módulos
dedicados.

El cuarto paquete atribuye IP públicas por pertenencia exacta a los rangos
oficiales de Cloudflare, Fastly, Google Cloud, los servicios globales de Google,
GitHub, Oracle Cloud, Atlassian Cloud, DigitalOcean, Microsoft 365 y AWS. La
comprobación se realiza
localmente tras descargar el feed fijo: el IP investigado nunca se añade a la
URL ni a parámetros enviados al proveedor, y sólo se conserva el prefijo
coincidente y los metadatos mínimos de la fuente.

El quinto paquete contrasta URLs localmente con los feeds comunitarios de
OpenPhish y URLhaus. La URL investigada nunca se transmite a esos proveedores:
sólo se descargan sus listas públicas fijas y se conserva el resultado exacto
normalizado, sin incorporar el contenido completo del feed a la evidencia.

El sexto paquete contrasta localmente huellas SHA-1 de certificados TLS con la
lista pública vigente de SSLBL. La huella investigada no se transmite al
proveedor; se descarga el CSV fijo, se valida su tamaño y se conserva sólo la
coincidencia, fecha y razón publicadas.

El séptimo paquete comprueba IP públicas contra las subredes /24 de mayor
actividad atacante publicadas por SANS ISC / DShield. Descarga el feed fijo y
compara localmente, valida los extremos y los recuentos de cada subred, conserva
la fecha y atribución de la fuente, y omite los contactos. La pertenencia a una
subred no atribuye ataques a la IP individual. Fuente y condiciones:
[DShield](https://isc.sans.edu/feeds_doc.html),
[CC BY-NC-SA 2.5](https://creativecommons.org/licenses/by-nc-sa/2.5/).

La ampliación AWS preserva todos los prefijos y etiquetas coincidentes de
servicio, región y grupo fronterizo, sin inferir el servicio real de una carga
de trabajo a partir de rangos solapados. Valida IPv4/IPv6, fecha de publicación,
metadatos y límites de 30.000 registros, 128 coincidencias y 8 MB para este
proveedor; no cambia los límites de otros clientes. El feed no incluye BYOIP
ni todos los servicios. Fuente: [rangos oficiales AWS](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html).

`GET /api/v1/collectors/benchmark` devuelve capacidades únicas registradas,
módulos configurados, familias, referencia SpiderFoot inmutable, brecha restante
y metodología. La configuración no se presenta como salud operativa: ésta exige
sondeos en vivo. Alcanzar el número objetivo tampoco activa por sí solo la
paridad; la certificación final es una compuerta separada.

Los datos de vulnerabilidad proceden de APIs primarias: NVD CVE 2.0, el
catálogo CISA Known Exploited Vulnerabilities y FIRST EPSS. Un CVE no incluido
en KEV no significa que sea seguro; significa únicamente que la fuente no lo
marcó como explotado al momento de la consulta. EPSS expresa probabilidad, no
impacto. La severidad final requiere revisión humana.

`email_domain_dns` valida la dirección localmente, extrae el dominio y consulta
solo MX/TXT. La parte anterior a `@` no sale hacia el proveedor DNS ni queda en
la evidencia de ese colector.

Todos los adaptadores añadidos son pasivos: consultan índices o APIs públicas
fijas mediante HTTPS, con allowlist de hosts, timeout, límite de bytes y límite
de elementos. No escanean puertos, fuerzan credenciales, eluden controles ni
siguen destinos proporcionados por una respuesta fuera de las reglas del
cliente seguro. Disponibilidad, cuotas y términos siguen dependiendo de cada
proveedor.

Contratos públicos de referencia para la ampliación:

- [Cert Spotter](https://sslmate.com/help/reference/ct_search_api_v1),
  [Common Crawl](https://commoncrawl.org/url-index) y
  [Shodan InternetDB](https://book.shodan.io/developer-apis/internetdb/).
- [Bluesky](https://docs.bsky.app/docs/tutorials/viewing-profiles),
  [Hacker News](https://github.com/HackerNews/API),
  [GitHub](https://docs.github.com/en/rest/repos/repos#list-repositories-for-a-user)
  y [npm](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).
- [GDELT](https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/amp/),
  [Crossref](https://github.com/CrossRef/rest-api-doc),
  [Open Library](https://openlibrary.org/dev/docs/api/search),
  [Stack Exchange](https://api.stackexchange.com/docs/advanced-search),
  [Europe PMC](https://europepmc.org/RestfulWebService),
  [Google Books](https://developers.google.com/books/docs/v1/reference/volumes/list)
  y [Hacker News Search](https://hn.algolia.com/api).

La sonda no persistente `scripts/probe_extended_collectors.py` permite verificar
la disponibilidad del momento. Un HTTP 429/5xx es un estado externo temporal,
no autoriza evadir cuotas; una búsqueda normal lo conserva como fallo parcial.

### `domain_dns`

Entrada:

```json
{"domain": "example.com"}
```

Usa el resolver del sistema para obtener direcciones A/AAAA. No realiza
enumeración, fuerza bruta, transferencias de zona ni consultas de puertos.

### `domain_rdap`

Entrada idéntica. Consulta el endpoint fijo de RDAP y sigue su redirección al
registro autoritativo. No acepta URLs suministradas por el usuario, reduciendo
la superficie SSRF.

Los demás adaptadores siguen el mismo contrato y están descritos por el
catálogo de API. Consulta [orchestration.md](orchestration.md) para selección,
límites y ejecución agrupada.

## Añadir un colector

1. Confirma autorización, términos, límites y datos esperados.
2. Implementa `Collector` en `app/osint`.
3. Usa schemas/listas blancas estrictas para la consulta.
4. Fija destinos de red o aplica allowlist; nunca descargues URLs arbitrarias.
5. Define timeouts, tamaño máximo, reintentos y User-Agent.
6. No registres tokens ni respuestas sensibles completas.
7. Registra el adaptador en `CollectorRegistry`.
8. Añade pruebas unitarias sin red y una prueba de integración etiquetada.
9. Documenta procedencia, licencia, campos y política de retención.

## Idempotencia y errores

La evidencia usa un hash canónico por investigación. Reintentar el mismo
resultado devuelve el registro existente. Celery reintenta fallos de ejecución
con backoff; el estado persistente conserva intentos y error truncado.

Los resultados públicos pueden cambiar. `collected_at`, `observed_at`,
localizador y contenido crudo permiten reconstruir qué se observó y cuándo.

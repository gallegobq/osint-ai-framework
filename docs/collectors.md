# Colectores OSINT

## Contrato

Cada colector implementa:

- `name`: identificador persistente.
- `description`: descripción visible en API.
- `target_types` y `query_field`: compatibilidad declarativa para el planificador.
- `passive`, `requires_api_key` y `availability()`: política y estado operativo.
- `validate_query(query)`: valida y normaliza entrada no confiable.
- `collect(query)`: devuelve `CollectedItem` sin conocer PostgreSQL.

El worker convierte cada `CollectedItem` en evidencia mediante el mismo
`EvidenceService` usado por la API. Esto conserva deduplicación, auditoría y
autorización.

## Catálogo incluido

| Tipo | Sin clave | Con credencial opcional |
|---|---|---|
| Dominio | DNS A/AAAA, DNS completo por DoH, RDAP, crt.sh, Cert Spotter, Wayback, Common Crawl, urlscan.io | VirusTotal, SecurityTrails |
| IP pública | RDAP, reverse DNS, RIPEstat, Shodan InternetDB | Shodan, VirusTotal |
| ASN | RDAP, RIPEstat, PeeringDB | — |
| URL pública | Wayback, Common Crawl | — |
| Hostname | DNS, CT, Wayback, Common Crawl, urlscan.io, Cert Spotter | VirusTotal |
| Email | MX/TXT del dominio; nunca transmite la parte local | — |
| CVE | NIST NVD, CISA KEV, FIRST EPSS | — |
| Hash MD5/SHA-1/SHA-256 | — | VirusTotal |
| Usuario | GitHub, repositorios GitHub, GitLab, Bluesky, Hacker News, paquetes npm | — |
| Palabra clave | Wikidata, Wikipedia, OpenAlex, GDELT, Crossref, Open Library, Stack Overflow, Europe PMC, Google Books, Hacker News | — |

El endpoint `GET /api/v1/collectors` informa compatibilidad, disponibilidad y
la variable necesaria sin revelar su valor. urlscan.io permite una cuota
anónima pequeña; `URLSCAN_API_KEY` amplía la capacidad de acuerdo con el plan.
El catálogo actual suma 43 adaptadores: 37 públicos sin clave, 5 opcionales
con credencial y 1 validación activa de bajo impacto ejecutada en el sandbox.
Los tres adaptadores VirusTotal comparten una sola clave.

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

# Operaciones SOC

## Qué aporta este incremento

La aplicación acepta observables `hostname`, `email`, `hash` y `cve`, además
de dominio, IP, ASN, URL, usuario y palabra clave. El orquestador solo entrega
cada observable a colectores compatibles y normaliza el valor antes de crear
un trabajo.

Para CVE se consultan tres fuentes complementarias:

- NIST NVD aporta descripción, métricas y referencias del registro CVE.
- CISA KEV confirma si el identificador aparece en el catálogo de
  vulnerabilidades conocidas como explotadas.
- FIRST EPSS aporta probabilidad y percentil de explotación observada.

Ninguna fuente decide por sí sola la severidad. El analista debe considerar
impacto, exposición, KEV, EPSS, controles y contexto del activo.

Los hashes MD5, SHA-1 o SHA-256 pueden enriquecerse con VirusTotal cuando
`VIRUSTOTAL_API_KEY` está configurada. No se suben archivos. Para email, el
colector incluido consulta únicamente MX/TXT del dominio y nunca transmite ni
guarda la parte local de la dirección.

## Flujo recomendado

1. Crea una investigación en modo superficie de ataque o respuesta a
   incidentes y documenta jurisdicción, base legal y clasificación.
2. Abre **Buscar fuentes**, elige el tipo de observable y confirma alcance.
3. Revisa evidencia y procedencia. Una coincidencia sigue siendo una señal,
   no una atribución automática.
4. Crea un **Hallazgo SOC** con severidad, confianza, descripción y remediación.
5. Cambia su estado mediante API entre `open`, `triaged`, `in_progress`,
   `accepted`, `resolved` o `false_positive`.
6. Descarga STIX 2.1 para MISP/OpenCTI o NDJSON/CEF para un SIEM.

## Búsquedas programadas

En el diálogo de búsqueda activa **Repetir esta búsqueda**, indica un blanco
explícito, frecuencia y alcance. La primera ejecución ocurre tras un intervalo;
el proceso `scheduler` revisa trabajos cada minuto. Las programaciones son
exclusivamente pasivas, aun dentro de una investigación de pentest.

La tabla `search_schedules` conserva próxima ejecución, última ejecución,
último `search_run` y último error. Si el propietario queda inactivo, la
programación se deshabilita. Cambiar permisos o membresía impide nuevas
ejecuciones porque la autorización se revalida en cada ciclo.

## Interoperabilidad

`report.stix.json` genera un bundle STIX 2.1 con observables, vulnerabilidades,
notas de hallazgo y un agrupador de investigación. MISP y OpenCTI pueden
importar STIX, pero el operador debe probar el mapeo con su versión concreta.

`report.ndjson` usa campos compatibles con patrones ECS para hallazgos y
`report.cef` produce eventos CEF. Son archivos de intercambio; el framework no
envía datos a servicios externos sin una configuración explícita.

Fuentes primarias:

- NVD CVE API: <https://nvd.nist.gov/developers/vulnerabilities>
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- FIRST EPSS API: <https://www.first.org/epss/api>
- OASIS STIX 2.1: <https://www.oasis-open.org/standard/stix2-1/>

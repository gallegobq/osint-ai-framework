# Sandbox de validación SOC

## Objetivo

El sandbox añade validaciones activas de bajo impacto sin entregar una shell,
Docker ni argumentos arbitrarios al LLM. Es una frontera de ejecución separada
del API, PostgreSQL, Redis y Ollama.

La primera herramienta registrada es `sandbox_tls_http_baseline`. Realiza sobre
un único dominio o hostname autorizado:

1. resolución DNS y rechazo de cualquier dirección no pública;
2. negociación TLS en TCP/443;
3. verificación del certificado con el almacén de confianza del contenedor;
4. una petición `HEAD /` sin seguir redirecciones;
5. inventario de cabeceras HTTP de seguridad;
6. resultado normalizado que Linterna persiste como evidencia.

No escanea puertos, no prueba payloads, no autentica, no explota, no descarga el
cuerpo de la página y no acepta comandos, rutas, puertos ni URLs suministradas
por el modelo.

## Fronteras técnicas

- servicio Docker separado y usuario no privilegiado;
- filesystem de sólo lectura y `/tmp` pequeño con `noexec`;
- todas las capacidades Linux eliminadas;
- `no-new-privileges`;
- límite de 0,5 CPU, 256 MiB y 64 procesos;
- no se publica ningún puerto en el host;
- red dedicada compartida únicamente con el worker;
- sin volumen, secretos, socket Docker ni acceso directo a PostgreSQL;
- timeout, tamaño de solicitud y tamaño de cabeceras limitados;
- catálogo de herramientas cerrado en código.

El contenedor conserva salida a Internet porque necesita alcanzar el objetivo.
El rechazo de destinos privados se realiza después de resolver todas las
direcciones y la conexión usa una de las IP ya validadas para reducir riesgo de
DNS rebinding.

## Política de autorización

Una ejecución activa requiere acumulativamente:

1. permiso RBAC `collection:execute_active` o superusuario;
2. investigación en modo `pentest`;
3. `active_testing_authorized=true`;
4. alcance persistido;
5. ventana de engagement vigente;
6. `allow_active=true` en la ejecución;
7. confirmación de autorización;
8. nota específica de ejecución;
9. aparición textual del dominio en el alcance del engagement y en la nota de
   ejecución;
10. nueva validación en el worker inmediatamente antes de construir el plan.

Las búsquedas programadas siguen siendo exclusivamente pasivas.

## Ejecución

Configura:

```env
SOC_SANDBOX_ENABLED=true
SOC_SANDBOX_URL=http://sandbox:8090
SOC_SANDBOX_TIMEOUT_SECONDS=20
```

Construye y levanta el stack:

```powershell
docker compose up --build -d
docker compose exec api python -m app.seed.rbac
```

El segundo comando incorpora el nuevo permiso de forma idempotente.

## Demostración autorizada

Crea una investigación `pentest` cuya autorización incluya literalmente el
dominio de prueba, por ejemplo `example.com`, y una ventana vigente. En la
búsqueda usa:

```text
Objetivo: Validar de forma no destructiva TLS y las cabeceras HTTP de
example.com en TCP/443 mediante el sandbox.

Blanco: domain / example.com
Nota de alcance: Autorizado únicamente para example.com en TCP/443; una
negociación TLS y una petición HEAD, sin explotación.
```

Marca `Permitir colectores activos`. El resultado debe incluir evidencia de
tipo `tls_http_baseline` con:

- versión TLS y cifrado negociado;
- verificación y huella SHA-256 del certificado;
- emisor, sujeto y vigencia cuando el certificado sea válido;
- estado HTTP;
- cabeceras de seguridad presentes o ausentes;
- límites aplicados por el perfil.

Un resultado es una observación técnica puntual, no una certificación de
seguridad ni un pentest completo.

## Evolución aprobable

Las siguientes herramientas deben añadirse como perfiles separados, nunca como
una shell genérica:

1. `testssl.sh` con límites estrictos y un solo host;
2. Nmap TCP connect sobre una lista pequeña de puertos aprobados;
3. ZAP Baseline sin ataques activos;
4. Nuclei con un conjunto firmado de plantillas no destructivas.

Cada perfil requiere amenaza documentada, límites, fixtures sin red, prueba de
integración, campos de evidencia y aprobación explícita del responsable del
engagement.

# Preparación para producción

## Estado real

**No está listo para producción.** Este incremento añade controles concretos
de preproducción, pero no sustituye decisiones corporativas, pruebas de
recuperación, certificados válidos, un gestor de secretos, monitoreo operado,
revisión legal ni aceptación formal de riesgo.

## Controles incorporados

### MFA TOTP

1. Autentícate y llama `POST /api/v1/auth/mfa/setup`.
2. Importa `provisioning_uri` o el secreto en un autenticador compatible.
3. Confirma un código con `POST /api/v1/auth/mfa/confirm`.
4. Los siguientes logins JSON incluyen `mfa_code`; el formulario OAuth acepta
   el mismo campo.
5. Para deshabilitar, `POST /api/v1/auth/mfa/disable` exige contraseña y código
   y revoca todas las sesiones.

El secreto TOTP se cifra en base de datos con una clave derivada de
`SECRET_KEY`. Rotar esa clave requiere un procedimiento de migración; no la
cambies sin probar recuperación. Antes de producción falta un flujo de
recuperación administrada con identidad verificada y códigos de recuperación.

### Rate limiting

Redis limita por cliente. Login/token/refresh usan una ventana más estricta y
fallan cerrados si Redis no está disponible. Configuración:

- `RATE_LIMIT_ENABLED`
- `RATE_LIMIT_REQUESTS` y `RATE_LIMIT_WINDOW_SECONDS`
- `RATE_LIMIT_AUTH_REQUESTS` y `RATE_LIMIT_AUTH_WINDOW_SECONDS`
- `RATE_LIMIT_FAIL_CLOSED`

Un proxy/WAF corporativo sigue siendo recomendable para límites distribuidos,
IPs reales confiables, bloqueo adaptativo y mitigación volumétrica.

### TLS

El perfil `production` añade Caddy con HTTPS local y CA interna:

```powershell
docker compose --env-file .env --profile production up -d caddy
```

Abre `https://localhost:8443`. La CA interna es útil para validación local, no
es un certificado corporativo. Antes de exponer la aplicación reemplaza la
configuración por DNS/certificados aprobados, restringe el puerto HTTP y prueba
renovación, cadenas, cifrados y headers desde la red objetivo.

### Secretos

El entrypoint acepta archivos `POSTGRES_PASSWORD_FILE`, `SECRET_KEY_FILE`,
`INITIAL_ADMIN_PASSWORD_FILE`, las claves de colectores y
`METRICS_TOKEN_FILE`. Monte secretos de solo lectura desde Docker/Kubernetes o
el gestor corporativo. `.env` continúa siendo válido para uso local, pero no
es el mecanismo recomendado para producción.

### Backup y restauración

```powershell
.\scripts\backup.ps1
.\scripts\verify_restore.ps1 -BackupFile .\backups\osint-AAAAMMDD-HHMMSS.dump
```

La segunda orden restaura en una base temporal aislada, consulta la revisión
Alembic y elimina solo esa base temporal. La restauración real exige nombre de
base exacto y confirmación interactiva:

```powershell
.\scripts\restore.ps1 -BackupFile <archivo> -ConfirmDatabaseName osint_db
```

No declares RPO/RTO cumplidos hasta automatizar periodicidad, cifrado,
retención externa, alertas y ensayos documentados.

### Observabilidad, carga y vulnerabilidades

`GET /api/v1/metrics` expone contadores y duración en formato Prometheus. Si
`METRICS_TOKEN` tiene valor, exige `Authorization: Bearer ...`. Los logs tienen
request ID, ruta y estado, sin incluir tokens.

```powershell
python .\scripts\load_test.py --requests 500 --concurrency 20
.\scripts\security_scan.ps1
```

La prueba de carga es un umbral local inicial, no un plan de capacidad. Trivy
falla ante vulnerabilidades HIGH/CRITICAL corregibles; también deben revisarse
SBOM, imágenes base, dependencias, DAST y hallazgos de código en CI.

### Retención y legal hold

Cada investigación conserva jurisdicción, base legal, clasificación,
`retention_until` y `legal_hold`. `DEFAULT_RETENTION_DAYS` calcula el plazo
inicial. `REQUIRE_LEGAL_METADATA=true` impide crear casos sin jurisdicción y
base legal.

No existe borrado automático: destruir evidencia al vencer un plazo sin una
política aprobada sería inseguro. Antes de producción define responsables,
excepciones, exportación/rectificación, hold, eliminación verificable y
jurisdicciones aplicables.

## Evidencia local más reciente

El 2026-08-16 se creó un dump PostgreSQL, se validó con `pg_restore --list` y
se restauró correctamente en una base temporal aislada. También se aprobaron
82 pruebas, el smoke SOC y el escaneo Trivy del runtime. La prueba local de
100 solicitudes no tuvo errores, pero su p95 fue 2286 ms frente al umbral de
1000 ms; capacidad y rendimiento continúan abiertos. Véase
`docs/runtime-validation-2026-08-16.md`.

## Bloqueadores externos que permanecen

- Certificado, dominio, proxy/WAF y topología de red definitivos.
- Gestor de secretos, rotación y acceso de emergencia.
- Automatización/cifrado externo de backups y RPO/RTO aceptados; el ensayo
  local aislado ya fue aprobado.
- Alertas, paneles, guardias y destino SIEM seleccionados.
- Pruebas de carga con volumen representativo y escaneo en CI.
- Política legal aprobada por jurisdicción y procedimiento de retención.
- SSO/OIDC o proceso corporativo de altas, bajas y recuperación MFA.
- Revisión de aislamiento si se requiere multitenancy estricto.

# Lista de verificación de despliegue

## Validación local o staging

- [x] Docker Desktop usa contenedores Linux y el daemon responde.
- [x] `.env` existe, no contiene plantillas y no está versionado.
- [x] `docker compose --env-file .env config --quiet` finaliza correctamente.
- [x] Las imágenes de API, worker y tests se construyen correctamente.
- [x] PostgreSQL y Redis aparecen saludables.
- [x] `alembic upgrade head` termina en `d84f3c9a1b72`.
- [x] El bootstrap crea o reconoce al administrador configurado.
- [x] El seeder RBAC termina sin duplicar filas.
- [x] `pytest` aprueba 34 de 34 pruebas dentro de la imagen `test`.
- [x] La prueba funcional crea y archiva un proyecto/investigación sintéticos.
- [x] Liveness y readiness responden correctamente.
- [x] La salida del verificador no contiene contraseñas, JWT ni evidencia real.

Los puntos anteriores corresponden al release base validado. Para el release de
orquestación deben repetirse y actualizarse la revisión/cantidad de pruebas:

- [x] `alembic upgrade head` termina en `c84f7a2e9d10`.
- [x] Las pruebas nuevas de planificador, normalización y catálogo aprueban.
- [ ] Una búsqueda sintética orquestada sobre `example.com` crea evidencia.
- [x] Los 82 tests unitarios y de contrato aprueban dentro de Docker.
- [x] `scheduler` permanece activo y ejecuta su comprobación periódica.
- [ ] Una programación sintética vencida se encola y completa en staging.
- [ ] STIX, NDJSON y CEF se importan en los productos destino de staging.
- [ ] `planner` confirma Ollama cuando el perfil LLM está activo, o el fallback
  esperado cuando se prueba sin Ollama.

PowerShell ejecuta el flujo completo con:

```powershell
.\scripts\verify.ps1
```

Desde WSL/Linux:

```bash
bash scripts/verify.sh
```

Los scripts no eliminan contenedores, volúmenes ni bases. Si fallan, conservan
el estado para diagnóstico.

## Antes de datos reales

- [x] `backup.ps1` genera un dump y `verify_restore.ps1` restaura una copia
  aislada; se conserva evidencia del ensayo.
- [ ] El upgrade fue ensayado sobre una copia anonimizada de la base previa.
- [ ] TLS, proxy, CORS, trusted hosts y exposición de puertos fueron revisados.
- [ ] Rate limiting Redis está activo y el WAF/proxy definitivo fue probado.
- [ ] Secretos se entregan mediante el gestor aprobado y tienen responsable.
- [ ] Retención, eliminación y legal hold están definidos.
- [ ] Fuentes OSINT, términos, jurisdicción y base legal están aprobados.
- [ ] Prometheus recolecta `/metrics`; alertas, logs y respuesta tienen responsables.
- [ ] RPO, RTO, capacidad y disponibilidad fueron aceptados. La prueba local
  actual no cumple el umbral p95 de 1000 ms.
- [ ] Se realizó una prueba de autorización por cada rol real.

## Rollback

No uses `docker compose down -v` como rollback. Ante un despliegue fallido:

1. Detén el ingreso de escrituras.
2. Conserva logs y estado de contenedores.
3. Restaura la versión compatible de API/worker.
4. Solo ejecuta downgrade Alembic si fue ensayado y el backup fue verificado.
5. Comprueba integridad, readiness y una prueba funcional antes de reabrir.

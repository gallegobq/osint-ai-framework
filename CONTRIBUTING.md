# Contribuir

## Flujo

1. Crea una rama pequeña y una historia con criterios de aceptación.
2. Mantén routers delgados y reglas en servicios.
3. Toda consulta nueva vive en un repositorio.
4. Todo cambio de modelo incluye revisión Alembic forward y downgrade.
5. Añade pruebas de éxito, autorización, validación y fallo.
6. Actualiza API, operación, seguridad y ADR si corresponde.

## Calidad

```bash
python -m compileall -q app alembic tests scripts
pytest
ruff check app alembic tests
```

No uses `Base.metadata.create_all` para despliegues. No edites migraciones ya
aplicadas salvo una corrección explícitamente documentada y compatible.

## Estilo de integración

- Adaptadores externos implementan un puerto.
- Configuración solo mediante `settings`; no uses `os.getenv` disperso.
- No hagas commits dentro de repositorios; la capa de servicio controla la
  transacción.
- No registres secretos, tokens, cuerpos de autenticación o evidencia completa.
- Excepciones de aplicación usan códigos estables.

## Definition of Done

- Criterios de aceptación cumplidos.
- Migraciones probadas en limpio y upgrade.
- Pruebas y análisis estático pasan.
- Matriz RBAC/proyecto revisada.
- Documentación y `.env.example` actualizados.
- Sin secretos ni datos reales en fixtures.
- Riesgos operativos y rollback documentados.

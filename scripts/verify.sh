#!/usr/bin/env bash
set -euo pipefail

reconcile_initial_admin=false
if [[ "${1:-}" == "--reconcile-initial-admin" ]]; then
  reconcile_initial_admin=true
  shift
fi
if [[ "$#" -ne 0 ]]; then
  echo "Uso: $0 [--reconcile-initial-admin]" >&2
  exit 2
fi

if [[ ! -f .env ]]; then
  echo "Falta .env. Copia .env.example y reemplaza los valores replace-with-..." >&2
  exit 1
fi

if grep -Fq "replace-with-" .env; then
  echo ".env conserva valores replace-with-...; sustituyelos antes de continuar." >&2
  exit 1
fi

run_step() {
  local step_name="$1"
  shift
  printf '\n==> %s\n' "$step_name"
  "$@"
}

run_step "Validar Docker Compose" \
  docker compose --env-file .env config --quiet
run_step "Construir imagenes" \
  docker compose --env-file .env --profile test build api worker scheduler ollama tests
run_step "Iniciar PostgreSQL y Redis" \
  docker compose --env-file .env up -d postgres redis
run_step "Detener API, worker y scheduler anteriores" \
  docker compose --env-file .env stop api worker scheduler
run_step "Aplicar migraciones" \
  docker compose --env-file .env run --rm --no-deps api alembic upgrade head
if [[ "$reconcile_initial_admin" == "true" ]]; then
  run_step "Crear administrador inicial" \
    docker compose --env-file .env run --rm --no-deps api \
    python -m app.seed.admin --reconcile-existing
else
  run_step "Crear administrador inicial" \
    docker compose --env-file .env run --rm --no-deps api \
    python -m app.seed.admin
fi
run_step "Inicializar RBAC" \
  docker compose --env-file .env run --rm --no-deps api \
  python -m app.seed.rbac
run_step "Comprobar revision Alembic" \
  docker compose --env-file .env run --rm --no-deps api alembic current
run_step "Validar importacion ASGI" \
  docker compose --env-file .env run --rm --no-deps api \
  python -c "from app.main import app; assert app is not None"
printf '\n==> %s\n' "Iniciar API y worker"
if ! docker compose --env-file .env up -d --wait --wait-timeout 900 api worker scheduler; then
  printf '\n==> %s\n' "Diagnostico de contenedores"
  docker compose --env-file .env ps || true
  docker compose --env-file .env logs --tail=200 api || true
  docker compose --env-file .env logs --tail=200 ollama || true
  exit 1
fi
run_step "Ejecutar pruebas" \
  docker compose --env-file .env --profile test run --rm tests
run_step "Ejecutar prueba funcional HTTP" \
  docker compose --env-file .env --profile test run --rm tests \
  python scripts/smoke_api.py
run_step "Validar contrato SOC en runtime" \
  docker compose --env-file .env --profile test run --rm tests \
  python scripts/smoke_soc_readonly.py
run_step "Mostrar estado final" \
  docker compose --env-file .env ps

printf '\nValidacion completada. Conserva esta salida como evidencia.\n'

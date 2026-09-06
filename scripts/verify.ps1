param(
    [switch]$ReconcileInitialAdmin
)

function Invoke-VerificationStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StepName,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    Write-Host "`n==> $StepName"
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $StepName (codigo $LASTEXITCODE)."
    }
}

if (-not (Test-Path -LiteralPath ".env" -PathType Leaf)) {
    throw "Falta .env. Copia .env.example y reemplaza todos los valores replace-with-..."
}

$unsafePlaceholders = Select-String `
    -LiteralPath ".env" `
    -Pattern "replace-with-" `
    -SimpleMatch
if ($unsafePlaceholders) {
    throw ".env conserva valores replace-with-...; sustituyelos antes de continuar."
}

Invoke-VerificationStep "Validar Docker Compose" {
    docker compose --env-file .env config --quiet
}
Invoke-VerificationStep "Construir imagenes" {
    docker compose --env-file .env --profile test build api worker scheduler ollama tests
}
Invoke-VerificationStep "Iniciar PostgreSQL y Redis" {
    docker compose --env-file .env up -d postgres redis
}
Invoke-VerificationStep "Detener API y worker anteriores" {
    docker compose --env-file .env stop api worker scheduler
}
Invoke-VerificationStep "Aplicar migraciones" {
    docker compose --env-file .env run --rm --no-deps api `
        alembic upgrade head
}
Invoke-VerificationStep "Crear administrador inicial" {
    if ($ReconcileInitialAdmin) {
        docker compose --env-file .env run --rm --no-deps api `
            python -m app.seed.admin --reconcile-existing
    }
    else {
        docker compose --env-file .env run --rm --no-deps api `
            python -m app.seed.admin
    }
}
Invoke-VerificationStep "Inicializar RBAC" {
    docker compose --env-file .env run --rm --no-deps api `
        python -m app.seed.rbac
}
Invoke-VerificationStep "Comprobar revision Alembic" {
    docker compose --env-file .env run --rm --no-deps api alembic current
}
Invoke-VerificationStep "Validar importacion ASGI" {
    docker compose --env-file .env run --rm --no-deps api `
        python -c "from app.main import app; assert app is not None"
}
Invoke-VerificationStep "Iniciar API y worker" {
    docker compose --env-file .env up -d --wait --wait-timeout 900 api worker scheduler
    if ($LASTEXITCODE -ne 0) {
        $startupExitCode = $LASTEXITCODE
        Write-Host "`n==> Diagnostico de contenedores"
        docker compose --env-file .env ps
        docker compose --env-file .env logs --tail=200 api
        docker compose --env-file .env logs --tail=200 ollama
        throw "API/worker no alcanzaron estado saludable (codigo $startupExitCode)."
    }
}
Invoke-VerificationStep "Ejecutar pruebas" {
    docker compose --env-file .env --profile test run --rm tests
}
Invoke-VerificationStep "Ejecutar prueba funcional HTTP" {
    docker compose --env-file .env --profile test run --rm tests `
        python scripts/smoke_api.py
}
Invoke-VerificationStep "Validar contrato SOC en runtime" {
    docker compose --env-file .env --profile test run --rm tests `
        python scripts/smoke_soc_readonly.py
}
Invoke-VerificationStep "Mostrar estado final" {
    docker compose --env-file .env ps
}

Write-Host "`nValidacion completada. Conserva esta salida como evidencia."

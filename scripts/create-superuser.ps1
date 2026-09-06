param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9_.-]{3,50}$')]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$Email
)

$ErrorActionPreference = "Stop"

$runningApi = @(docker compose ps --status running --services api)
if ($LASTEXITCODE -ne 0 -or $runningApi -notcontains "api") {
    throw "La API no está disponible. Inicia Linterna antes de crear el administrador."
}

docker compose exec api python -m app.seed.rbac
if ($LASTEXITCODE -ne 0) {
    throw "No fue posible preparar el rol Administrator."
}

Write-Host "La contraseña se solicitará dentro del contenedor y no se guardará en el script."
docker compose exec api python -m app.seed.superuser `
    --username $Username `
    --email $Email
if ($LASTEXITCODE -ne 0) {
    throw "No fue posible crear o promover el administrador."
}

Write-Host "Administrador listo. Activa MFA después del primer acceso."

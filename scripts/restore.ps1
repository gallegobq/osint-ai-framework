param(
    [Parameter(Mandatory = $true)]
    [string]$BackupFile,
    [Parameter(Mandatory = $true)]
    [string]$ConfirmDatabaseName
)

$ErrorActionPreference = "Stop"
$resolvedBackup = (Resolve-Path -LiteralPath $BackupFile).Path
$configuredDatabase = (
    Select-String -LiteralPath ".env" -Pattern "^POSTGRES_DB=(.+)$"
).Matches.Groups[1].Value
if (-not $configuredDatabase) { $configuredDatabase = "osint_db" }
if ($ConfirmDatabaseName -cne $configuredDatabase) {
    throw "ConfirmDatabaseName no coincide exactamente con POSTGRES_DB."
}

$containerFile = "/tmp/osint-restore.dump"
docker compose --env-file .env cp $resolvedBackup "postgres:$containerFile"
if ($LASTEXITCODE -ne 0) { throw "No se pudo copiar el backup al contenedor." }
docker compose --env-file .env exec -T postgres pg_restore --list $containerFile | Out-Null
if ($LASTEXITCODE -ne 0) { throw "El backup no es válido." }

Write-Warning "La restauración reemplazará objetos existentes en '$configuredDatabase'."
$confirmation = Read-Host "Escribe RESTAURAR para continuar"
if ($confirmation -cne "RESTAURAR") { throw "Restauración cancelada." }

docker compose --env-file .env stop api worker scheduler
docker compose --env-file .env exec -T postgres sh -c `
    "pg_restore -U `"`$POSTGRES_USER`" -d `"`$POSTGRES_DB`" --clean --if-exists --no-owner '$containerFile'"
if ($LASTEXITCODE -ne 0) { throw "La restauración falló; conserva logs y backup." }
docker compose --env-file .env exec -T postgres rm -f $containerFile
docker compose --env-file .env up -d --wait api worker scheduler
Write-Host "Restauración completada. Ejecuta .\scripts\verify.ps1."

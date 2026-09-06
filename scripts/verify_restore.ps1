param(
    [Parameter(Mandatory = $true)]
    [string]$BackupFile
)

$ErrorActionPreference = "Stop"
$resolvedBackup = (Resolve-Path -LiteralPath $BackupFile).Path
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$testDatabase = "osint_restore_check_$stamp"
$containerFile = "/tmp/$testDatabase.dump"

try {
    docker compose --env-file .env cp $resolvedBackup "postgres:$containerFile"
    if ($LASTEXITCODE -ne 0) { throw "No se pudo copiar el backup." }
    docker compose --env-file .env exec -T postgres sh -c `
        "createdb -U `"`$POSTGRES_USER`" '$testDatabase'"
    if ($LASTEXITCODE -ne 0) { throw "No se pudo crear la base aislada." }
    docker compose --env-file .env exec -T postgres sh -c `
        "pg_restore -U `"`$POSTGRES_USER`" -d '$testDatabase' --no-owner '$containerFile'"
    if ($LASTEXITCODE -ne 0) { throw "El restore aislado falló." }
    docker compose --env-file .env exec -T postgres sh -c `
        "psql -U `"`$POSTGRES_USER`" -d '$testDatabase' -Atc 'SELECT version_num FROM alembic_version'"
    if ($LASTEXITCODE -ne 0) { throw "La base restaurada no pasó la consulta de integridad." }
    Write-Host "Restauración aislada verificada correctamente."
}
finally {
    docker compose --env-file .env exec -T postgres sh -c `
        "dropdb -U `"`$POSTGRES_USER`" --if-exists --force '$testDatabase'" | Out-Null
    docker compose --env-file .env exec -T postgres rm -f $containerFile | Out-Null
}

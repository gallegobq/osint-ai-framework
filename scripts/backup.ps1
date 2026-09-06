param(
    [string]$OutputDirectory = ".\backups"
)

$ErrorActionPreference = "Stop"
$resolvedOutput = [System.IO.Path]::GetFullPath(
    (Join-Path (Get-Location) $OutputDirectory)
)
$workspace = [System.IO.Path]::GetFullPath((Get-Location).Path)
if (-not $resolvedOutput.StartsWith($workspace, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "El directorio de backup debe permanecer dentro del workspace."
}
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$containerFile = "/tmp/osint-$stamp.dump"
$hostFile = Join-Path $resolvedOutput "osint-$stamp.dump"

docker compose --env-file .env exec -T postgres sh -c `
    "pg_dump -U `"`$POSTGRES_USER`" -d `"`$POSTGRES_DB`" -Fc -f '$containerFile'"
if ($LASTEXITCODE -ne 0) { throw "pg_dump falló." }
docker compose --env-file .env cp "postgres:$containerFile" $hostFile
if ($LASTEXITCODE -ne 0) { throw "No se pudo copiar el backup." }
docker compose --env-file .env exec -T postgres rm -f $containerFile

# La validación real se hace sobre la copia descargada mediante un contenedor efímero.
docker run --rm -v "${resolvedOutput}:/backups:ro" postgres:16 `
    pg_restore --list "/backups/$(Split-Path $hostFile -Leaf)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "El archivo no pasó pg_restore --list." }

$hash = (Get-FileHash -LiteralPath $hostFile -Algorithm SHA256).Hash
Write-Host "Backup verificado: $hostFile"
Write-Host "SHA256: $hash"

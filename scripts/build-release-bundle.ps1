param(
    [string]$Version = "2026.08.31",
    [string]$OutputDirectory = ".\output\distribution\linterna-local-$Version"
)

$ErrorActionPreference = "Stop"
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null
$localDockerConfig = Join-Path (Get-Location) "output\docker-release-config"
New-Item -ItemType Directory -Force -Path $localDockerConfig | Out-Null
$env:DOCKER_CONFIG = $localDockerConfig

docker compose build api ollama sandbox
if ($LASTEXITCODE -ne 0) { throw "No fue posible construir las imágenes." }

docker image tag osint-ai-framework-api:latest "linterna/api:$Version"
docker image tag osint-ai-framework-ollama:latest "linterna/ollama:$Version"
docker image tag osint-ai-framework-sandbox:latest "linterna/sandbox:$Version"
if ($LASTEXITCODE -ne 0) { throw "No fue posible etiquetar las imágenes." }

docker image inspect postgres:16 redis:7-alpine | Out-Null
if ($LASTEXITCODE -ne 0) {
    docker pull postgres:16
    docker pull redis:7-alpine
}

$imageArchive = Join-Path $resolvedOutput "linterna-images-$Version.tar"
docker image save `
    --output $imageArchive `
    "linterna/api:$Version" `
    "linterna/ollama:$Version" `
    "linterna/sandbox:$Version" `
    postgres:16 `
    redis:7-alpine
if ($LASTEXITCODE -ne 0) { throw "No fue posible exportar las imágenes." }

Copy-Item -LiteralPath ".\docker-compose.release.yml" -Destination $resolvedOutput -Force
Copy-Item -LiteralPath ".\.env.example" -Destination $resolvedOutput -Force
Copy-Item -LiteralPath ".\docs\LOCAL-INSTALL.txt" -Destination $resolvedOutput -Force

$hashes = Get-ChildItem -LiteralPath $resolvedOutput -File |
    Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash)  $([System.IO.Path]::GetFileName($_.Path))" }
$hashes | Set-Content -LiteralPath (Join-Path $resolvedOutput "SHA256SUMS.txt")

Write-Host "Bundle listo en: $resolvedOutput"
Get-ChildItem -LiteralPath $resolvedOutput | Select-Object Name, Length

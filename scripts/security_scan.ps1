$ErrorActionPreference = "Stop"

$scanImage = "osint-ai-framework-api:security-scan"
$scanDirectory = [System.IO.Path]::GetFullPath(
    (Join-Path (Get-Location) "data\security-scan")
)
$workspace = [System.IO.Path]::GetFullPath((Get-Location).Path)
if (-not $scanDirectory.StartsWith($workspace, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "El directorio temporal debe permanecer dentro del workspace."
}
New-Item -ItemType Directory -Force -Path $scanDirectory | Out-Null
$archive = Join-Path $scanDirectory "api-rootfs.tar"
$scanId = [Guid]::NewGuid().ToString("N")
$scanContainer = "osint-trivy-export-$scanId"
$rootfsVolume = "osint-trivy-rootfs-$scanId"

# Disable BuildKit's attached provenance/SBOM for this local scan. Some upstream
# Python images publish an SBOM that describes the image before our dependency
# upgrade layer; scanning that attestation together with the final filesystem
# produces stale duplicate package findings. Trivy still inventories the final
# image filesystem exported below.
docker build --provenance=false --sbom=false --target runtime --tag $scanImage .
if ($LASTEXITCODE -ne 0) { throw "No se pudo construir la imagen." }

try {
    docker create --name $scanContainer $scanImage | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo crear el contenedor temporal." }
    docker export --output $archive $scanContainer
    if ($LASTEXITCODE -ne 0) { throw "No se pudo exportar el sistema de archivos." }
    docker volume create $rootfsVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo crear el volumen temporal." }
    docker run --rm `
        -v "${scanDirectory}:/scan:ro" `
        -v "${rootfsVolume}:/rootfs" `
        alpine:3.23 `
        tar -xf /scan/api-rootfs.tar -C /rootfs
    if ($LASTEXITCODE -ne 0) { throw "No se pudo preparar el rootfs para escaneo." }
    docker run --rm `
        -v trivy_cache:/root/.cache/ `
        -v "${rootfsVolume}:/rootfs:ro" `
        aquasec/trivy:0.74.0 rootfs `
        /rootfs `
        --scanners vuln `
        --exit-code 1 `
        --severity HIGH,CRITICAL `
        --ignore-unfixed
    if ($LASTEXITCODE -ne 0) {
        throw "Trivy falló o encontró vulnerabilidades HIGH/CRITICAL corregibles."
    }
}
finally {
    docker rm -f $scanContainer 2>$null | Out-Null
    docker volume rm -f $rootfsVolume 2>$null | Out-Null
    if (Test-Path -LiteralPath $archive -PathType Leaf) {
        Remove-Item -LiteralPath $archive -Force
    }
}

Write-Host "Escaneo de vulnerabilidades aprobado."

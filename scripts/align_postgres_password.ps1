param()

if (-not (Test-Path -LiteralPath ".env" -PathType Leaf)) {
    throw "Falta .env en la raíz del proyecto."
}

Write-Warning (
    "Esta operación conservará el volumen y cambiará la contraseña " +
    "del rol PostgreSQL actual para igualarla con POSTGRES_PASSWORD de .env."
)
$alignmentConfirmation = Read-Host "Escribe ALINEAR para continuar"
if ($alignmentConfirmation -cne "ALINEAR") {
    throw "Operación cancelada."
}

$passwordAlignmentSql = @'
SELECT format(
    'ALTER ROLE %I WITH PASSWORD %L',
    :'role_name',
    :'new_password'
) AS command
\gexec
'@

$passwordAlignmentSql | docker compose --env-file .env exec -T postgres `
    sh -c 'psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 -v role_name="$POSTGRES_USER" -v new_password="$POSTGRES_PASSWORD"'

if ($LASTEXITCODE -ne 0) {
    throw "No se pudo alinear la contraseña PostgreSQL."
}

Write-Host "Contraseña PostgreSQL alineada sin eliminar el volumen."

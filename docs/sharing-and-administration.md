# Compartir Linterna y crear administradores

## Qué se comparte

Docker no comparte un contenedor vivo como si fuera un archivo. Hay tres
escenarios distintos:

1. dar acceso a la instancia que ya está ejecutándose;
2. entregar el código y las imágenes para instalar otra instancia;
3. transferir también datos existentes.

La opción 1 es la adecuada para un equipo dentro de una red privada. La opción
2 crea una instalación independiente. La opción 3 requiere un backup cifrado,
autorización sobre los datos y un canal distinto para la contraseña.

Nunca compartas `.env`, `backups/`, `data/`, `output/`, volúmenes Docker,
tokens, resultados OSINT o certificados privados dentro del paquete de la
aplicación.

## Opción A: acceso desde la red local

La API continúa ligada a `127.0.0.1`; el único puerto compartido será el proxy
HTTPS. No publiques PostgreSQL, Redis, Ollama, el sandbox ni el puerto 8000.

1. Obtén la dirección IPv4 privada del equipo servidor:

   ```powershell
   Get-NetIPAddress -AddressFamily IPv4 |
     Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' }
   ```

2. En `.env`, reemplaza `192.168.1.25` por esa dirección:

   ```dotenv
   SHARE_HOST=192.168.1.25
   TLS_PORT=8443
   TRUSTED_HOSTS=["localhost","127.0.0.1","api","testserver","192.168.1.25"]
   CORS_ALLOWED_ORIGINS=["https://192.168.1.25:8443"]
   ```

3. Inicia el proxy HTTPS:

   ```powershell
   docker compose --profile production up -d --build caddy
   docker compose ps
   ```

4. Permite el puerto TCP 8443 únicamente en el perfil de red privada del
   firewall del servidor. No crees una redirección de puertos en el router.

5. Exporta la CA local de esta instancia:

   ```powershell
   docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .\linterna-local-ca.crt
   ```

6. Instala `linterna-local-ca.crt` como autoridad raíz de confianza solo en los
   equipos autorizados. Una CA raíz es sensible: entrégala por un canal
   controlado, no la publiques y revoca su confianza cuando el equipo deje de
   usar Linterna.

7. Accede desde el otro equipo a:

   ```text
   https://192.168.1.25:8443/
   ```

Para acceso por Internet usa un dominio, certificado público y proxy/VPN
gestionado. No expongas directamente los puertos de Compose ni uses la CA local
como sustituto de esa arquitectura.

## Opción B: entregar una instalación independiente

Desde la raíz del proyecto crea un paquete sin datos ni secretos:

```powershell
$items = @(
  "app", "alembic", "docker", "sandbox", "scripts",
  "alembic.ini", "docker-compose.yml", "Dockerfile",
  "Dockerfile.ollama", "Dockerfile.sandbox", "pyproject.toml",
  "requirements.txt", "requirements-dev.txt", ".env.example",
  "README.md", "CHANGELOG.md"
)
Compress-Archive -Path $items -DestinationPath .\linterna-source.zip -Force
```

En el equipo receptor:

```powershell
Expand-Archive .\linterna-source.zip .\linterna
Set-Location .\linterna
Copy-Item .env.example .env
```

El receptor debe generar sus propios secretos y contraseñas en `.env`, y luego:

```powershell
docker compose up -d --build postgres redis ollama api worker scheduler sandbox
docker compose ps
```

Los modelos de Ollama se descargan en el primer inicio. Esta opción no incluye
los datos de tu instancia.

## Crear un administrador con control total

Una cuenta con el rol `Administrator` tiene todos los permisos RBAC, pero una
cuenta marcada además como `superuser` puede acceder a todos los proyectos sin
ser miembro. La utilidad siguiente configura ambos niveles.

1. Asegúrate de que Linterna está activa:

   ```powershell
   docker compose up -d postgres redis ollama api
   ```

2. Ejecuta el asistente, sustituyendo usuario y correo:

   ```powershell
   .\scripts\create-superuser.ps1 `
     -Username soc-admin `
     -Email soc-admin@example.com
   ```

3. Escribe una contraseña nueva cuando se solicite y repítela. La contraseña
   no aparece en pantalla ni se guarda en el comando.

4. Abre Linterna e inicia sesión con la cuenta creada.

5. Activa MFA TOTP en el primer acceso. Mediante Swagger local:

   - autentícate en `https://<servidor>:8443/docs`;
   - ejecuta `POST /api/v1/auth/mfa/setup`;
   - registra el secreto en el autenticador;
   - confirma con `POST /api/v1/auth/mfa/confirm`.

Si el usuario y correo ya pertenecen exactamente a la misma cuenta, la utilidad
la reactiva, cambia su contraseña, la convierte en `superuser`, asigna el rol
`Administrator` y revoca todas sus sesiones. Si solo coincide uno de los dos
datos, se detiene para evitar promover por error otra identidad.

No uses una cuenta superuser para el trabajo diario. Conserva una cuenta de
emergencia con MFA y utiliza roles y membresías de proyecto para los analistas.


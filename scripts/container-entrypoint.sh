#!/bin/sh
set -eu

load_secret_file() {
    target="$1"
    file_variable="${target}_FILE"
    eval "file_path=\${$file_variable:-}"
    if [ -z "$file_path" ]; then
        return
    fi
    if [ ! -r "$file_path" ]; then
        echo "Secret file for $target is not readable." >&2
        exit 1
    fi
    secret_value="$(tr -d '\r\n' < "$file_path")"
    if [ -z "$secret_value" ]; then
        echo "Secret file for $target is empty." >&2
        exit 1
    fi
    export "$target=$secret_value"
    unset "$file_variable"
}

for secret_name in \
    POSTGRES_PASSWORD \
    SECRET_KEY \
    INITIAL_ADMIN_PASSWORD \
    SHODAN_API_KEY \
    VIRUSTOTAL_API_KEY \
    SECURITYTRAILS_API_KEY \
    URLSCAN_API_KEY \
    METRICS_TOKEN
do
    load_secret_file "$secret_name"
done

if [ "$1" = "migrate" ]; then
    echo "Running database migrations..."
    python -m alembic upgrade head
    echo "Creating initial administrator..."
    python -m app.seed.admin
    echo "Running RBAC bootstrap..."
    python -m app.seed.rbac
    exit 0
fi

exec "$@"

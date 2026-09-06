import os


TEST_ENV = {
    "APP_NAME": "OSINT AI Framework Test",
    "APP_VERSION": "0.1.0-test",
    "DEBUG": "false",
    "HOST": "127.0.0.1",
    "PORT": "8000",
    "POSTGRES_HOST": "localhost",
    "POSTGRES_PORT": "5432",
    "POSTGRES_DB": "osint_test",
    "POSTGRES_USER": "osint_test",
    "POSTGRES_PASSWORD": "test-only-password",
    "SECRET_KEY": "test-only-secret-key-with-at-least-32-characters",
    "JWT_ALGORITHM": "HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "15",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
    "RATE_LIMIT_ENABLED": "false",
}

for name, value in TEST_ENV.items():
    os.environ.setdefault(name, value)

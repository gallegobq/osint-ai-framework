FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install all security updates available at build time. The CI security gate
# rejects the resulting image if a fixable high/critical CVE remains.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system app && adduser --system --ingroup app app

COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.lock

FROM base AS runtime

COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY scripts/container-entrypoint.sh /container-entrypoint.sh
RUN chmod 0755 /container-entrypoint.sh

ENTRYPOINT ["/container-entrypoint.sh"]

# Build tooling is not required by the running service. Removing it also avoids
# shipping pip's vendored dependency catalog in the production image.
RUN python -m pip uninstall --yes pip setuptools

USER app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


FROM base AS test

COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY pyproject.toml ./
COPY tests ./tests
COPY scripts ./scripts
COPY sandbox ./sandbox

USER app
CMD ["python", "-m", "pytest"]

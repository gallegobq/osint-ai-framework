FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY scripts/container-entrypoint.sh /container-entrypoint.sh
RUN chmod 0755 /container-entrypoint.sh

ENTRYPOINT ["/container-entrypoint.sh"]


FROM base AS runtime

# Build tooling is not required by the running service. Removing it also avoids
# shipping pip's vendored dependency catalog in the production image.
RUN python -m pip uninstall --yes pip setuptools

USER app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


FROM base AS test

COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY pyproject.toml ./
COPY tests ./tests
COPY scripts ./scripts
COPY sandbox ./sandbox

USER app
CMD ["python", "-m", "pytest"]

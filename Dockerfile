FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq5 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
COPY aiauthz ./aiauthz
COPY scripts ./scripts
COPY config ./config

RUN pip install --upgrade pip \
 && pip install .

RUN useradd --system --uid 10001 --home /app aiauthz \
 && mkdir -p /app/data /app/storage/watermarks \
 && chown -R aiauthz:aiauthz /app

USER aiauthz

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"

CMD ["aiauthz", "serve", "--host", "0.0.0.0", "--port", "8080"]

# Main platform image: the FastAPI web UI + JSON API + CLI.
#
# Build:  docker build -f docker/Dockerfile -t sectest-platform .
# Run:    docker run --rm -p 8100:8100 \
#           -v "$PWD/config:/app/config:ro" \
#           -v "$PWD/.env:/app/.env:ro" \
#           -v sectest-data:/app/data \
#           sectest-platform
# (or see ../docker-compose.yml for a one-command version, SQLite or Postgres)
#
# This runs the WEB APPLICATION — it is not the arbitrary-Python PoC sandbox.
# That is a separate, more locked-down image (Dockerfile.sandbox, network-
# isolated behind an egress-allowlist proxy) used only when
# ENABLE_PYTHON_RUNNER=true. This image talks to real targets exclusively
# through the scope-validated, DNS-pinned HttpRunner, so its own isolation
# need is the ordinary kind: non-root, read-only app directory, nothing
# writable except the two paths that must be.
FROM python:3.12-slim

# requirements-lock.txt (not requirements.txt): the byte-for-byte
# reproducible dependency set, for the same reason CI installs from it — see
# that file's own header.
COPY requirements-lock.txt /tmp/requirements-lock.txt
RUN pip install --no-cache-dir --no-compile -r /tmp/requirements-lock.txt \
    && rm /tmp/requirements-lock.txt

RUN useradd --create-home --uid 10001 sectest
WORKDIR /app

COPY --chown=sectest:sectest app/ ./app/
COPY --chown=sectest:sectest config/engagement.example.json ./config/engagement.example.json

# Writable only where the app actually needs to write: a local SQLite file
# (irrelevant if DATABASE_URL points at Postgres instead) and generated
# reports. Everything else — including the app code itself — is read-only at
# run time when started with `docker run --read-only` / compose's
# `read_only: true` (see ../docker-compose.yml), because a security tool
# whose own code could be rewritten from inside its own container is a much
# worse finding than the one it's there to look for.
RUN mkdir -p /app/data /app/reports && chown sectest:sectest /app/data /app/reports

USER sectest
ENV DATABASE_URL=sqlite:////app/data/sectest.db \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8100

# /api/health needs no auth and no engagement configured to answer — reads
# stay open under AUTH_ENABLED=true specifically so monitoring keeps working
# (see README, "Multi-user auth").
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request as u,sys; sys.exit(0 if u.urlopen('http://127.0.0.1:8100/api/health', timeout=3).status == 200 else 1)"

CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8100"]

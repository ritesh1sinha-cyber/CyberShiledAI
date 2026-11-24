# syntax=docker/dockerfile:1

# Layer 1: dependencies only, so re-copying source does not reinstall the world.
FROM python:3.11-slim AS deps

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt ./
RUN python -m venv /venv \
 && /venv/bin/pip install -r requirements.txt

# Layer 2: the checkout, trimmed by .dockerignore (no .env, no .venv, no bulk snapshots).
FROM deps AS app
WORKDIR /app
COPY . ./

# Optional target: `docker build --target test .` runs the offline suite inside the
# image, which proves the image can execute this code, not just carry the files.
# The three modules left out guard the report, the per-CVE dossier and the browser-matrix
# evidence under docs/, and .dockerignore excludes docs/ because the container runs the
# product, not its documentation. Measured on 24 November: 420 pass on the host, 390 here.
FROM app AS test
RUN /venv/bin/python -m pytest -q -p no:cacheprovider \
    --ignore=tests/test_report_html.py \
    --ignore=tests/test_audit_dossier.py \
    --ignore=tests/test_ui_matrix.py

# Layer 3: runtime = slim base + venv + project. The test layer and build tools stay behind.
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/venv/bin:$PATH

WORKDIR /app
RUN groupadd --system app \
 && useradd --system --gid app --uid 10001 --home-dir /app --shell /usr/sbin/nologin app

COPY --from=deps /venv /venv
COPY --from=app /app ./

# The corpus, the retrieval index and the scored workbooks are read-only inputs. The
# three paths below are the only ones the product writes: investigations, the approved
# web-fallback cache, and its registry of what was ingested.
RUN mkdir -p /app/data/traces /app/data/raw/web_cache \
 && chown -R app:app /app/data/traces /app/data/raw/web_cache \
 && if [ -f /app/data/raw/web_ingested.json ]; then chown app:app /app/data/raw/web_ingested.json; fi
USER app

EXPOSE 8000 8501

# Bound to all interfaces *inside* the container's own network namespace, which is what
# lets Docker forward to it; the host side stays loopback-only in docker-compose.yml.
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD ["/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read(1)"]

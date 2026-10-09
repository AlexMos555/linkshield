# Cleanway API — the image Railway builds and runs.
#
# Replaces Nixpacks + railway.json: Railway stops honouring config-as-code on
# 2026-12-01 and Nixpacks is deprecated. Railway picks up a root Dockerfile on
# its own, so no builder setting is needed.
#
# The start command must expand $PORT inside a shell. The Dockerfile deleted in
# April 2026 quoted it ('${PORT:-8000}') and uvicorn got the literal string.

FROM python:3.11.15-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# tini as PID 1: forwards SIGTERM to uvicorn so Railway's rolling deploy drains
# requests instead of killing them.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

WORKDIR /app

# Every pinned dependency ships a manylinux wheel, so no compiler is installed.
COPY requirements.txt ./
RUN pip install -r requirements.txt

# The API reads data/, docs/transparency, docs/benchmarks and
# packages/email-templates/out at runtime; .dockerignore drops the rest.
COPY . .

# url_features appends its feature log to data/ (best effort, see log_features).
RUN chown -R app:app /app/data

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--"]

# uvicorn reads WEB_CONCURRENCY for the worker count (set on Railway).
CMD ["sh", "-c", "exec python -m uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8080}"]

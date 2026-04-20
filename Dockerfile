# syntax=docker/dockerfile:1.7
# ═════════════════════════════════════════════════════════════════
# LinkShield API — production container
# Multi-stage build, non-root user, no secrets in image.
# ═════════════════════════════════════════════════════════════════

# ─── Stage 1: builder ────────────────────────────────────────────
# Compile wheels here. Toolchain never reaches the runtime image.
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt ./
RUN pip install --user --no-warn-script-location -r requirements.txt

# ─── Stage 2: runtime ────────────────────────────────────────────
# Minimal image. Non-root. Read-only code. No build tools.
FROM python:3.11-slim-bookworm AS runtime

# Labels for image provenance
LABEL org.opencontainers.image.title="LinkShield API" \
      org.opencontainers.image.description="Privacy-first anti-phishing API" \
      org.opencontainers.image.vendor="LinkShield" \
      org.opencontainers.image.source="https://github.com/AlexMos555/linkshield" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/app/.local/bin:${PATH}" \
    PORT=8000

# Security: upgrade base image packages + install ONLY runtime deps + CA certs + curl for healthcheck
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tini \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get clean

# Create non-root user with explicit UID/GID (for k8s compatibility)
RUN groupadd -r app --gid 10001 \
 && useradd -r -g app --uid 10001 --home-dir /home/app --shell /sbin/nologin app \
 && mkdir -p /home/app /app \
 && chown -R app:app /home/app /app

WORKDIR /app

# Copy Python deps from builder stage
COPY --from=builder --chown=app:app /root/.local /home/app/.local

# Copy application code (ownership baked in)
# .dockerignore controls what actually gets copied — keeps secrets OUT
COPY --chown=app:app api/ ./api/
COPY --chown=app:app data/ ./data/

# Drop privileges — never run as root
USER app

# Healthcheck against /health endpoint (10s timeout, 3 retries)
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl --fail --silent --show-error "http://localhost:${PORT}/health" || exit 1

EXPOSE 8000

# tini as PID 1 — proper signal handling + zombie reaping
ENTRYPOINT ["/usr/bin/tini", "--"]

# uvicorn with one worker by default (Railway/k8s scale horizontally, not per-container).
# Override via CMD at runtime if needed.
CMD ["sh", "-c", "exec uvicorn api.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*' --no-server-header"]

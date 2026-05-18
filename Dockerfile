# syntax=docker/dockerfile:1.7

# ============================================================================
# Builder stage: install dependencies into a virtualenv using uv.
# Kept separate from runtime so the final image does not carry uv or its cache.
# ============================================================================
FROM python:3.13-slim AS builder

# Pull the uv binary from the official distroless image (small, signed).
COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /usr/local/bin/uv

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Install runtime dependencies first (cached unless uv.lock changes), then
# copy source. This ordering maximizes Docker layer cache reuse during dev.
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# ============================================================================
# Runtime stage: minimal Python image, non-root user, only the venv and src.
# ============================================================================
FROM python:3.13-slim AS runtime

# curl is needed for the healthcheck; everything else is in the venv.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user. UID 1000 is the convention; matches typical host
# users so bind-mounted data/ stays owned by the same uid outside the container.
RUN groupadd --system --gid 1000 secrecon \
    && useradd --system --uid 1000 --gid secrecon --create-home --shell /sbin/nologin secrecon

WORKDIR /app

# Copy the venv from the builder.
COPY --from=builder --chown=secrecon:secrecon /app/.venv /app/.venv

# Copy source (read-only in container; runtime never writes to /app/src).
COPY --chown=secrecon:secrecon src/ /app/src/
COPY --chown=secrecon:secrecon pyproject.toml /app/

# The only writable path inside the container.
RUN mkdir -p /app/data && chown secrecon:secrecon /app/data

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CHROMA_PERSIST_DIR=/app/data/cve_index

USER secrecon

# Default to API; the compose file overrides this for the MCP service.
# Healthcheck applies to whatever process is running; both API and MCP
# bind a TCP port on 127.0.0.1:8000 / :8001 respectively (overridden via
# env in compose to 0.0.0.0 so the other container can reach it).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/v1/health || exit 1

CMD ["sec-recon-api"]

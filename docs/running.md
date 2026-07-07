# Running and deployment

Operator reference: the no-Docker development path, API authentication and rate limiting, MCP transport auth, and the observability endpoints. The default Docker path is in the [README quick start](../README.md#quick-start).

## Without Docker (for development)

```bash
uv sync                    # backend deps
uv run sec-recon-seed      # ~30s with NVD_API_KEY, ~3-5 min without

# Two terminals for the backend:
uv run sec-recon-mcp       # MCP server on :8001
uv run sec-recon-api       # agent API on :8000

# Third terminal for the frontend (dev mode with HMR):
cd frontend && npm install --legacy-peer-deps && npm run dev
# Set AGENT_API_URL=http://localhost:8000 so the Next.js proxy hits the host
```

Hit `http://localhost:3000`.

## Authentication and rate limiting

Two env switches, both default off so `make up` on a dev laptop works without ceremony.

```bash
# In .env or the host environment
API_KEYS="key-one,key-two,key-three"   # any one of these is accepted
RATE_LIMIT_PER_MINUTE=30               # per-IP cap on /v1/triage
AGENT_API_KEY="key-one"                # propagated by the Next.js proxy
```

`make up` picks them up via docker-compose. With both set:

```bash
# Direct call to the FastAPI surface (auth required)
curl -N -X POST http://localhost:8000/v1/triage \
  -H "Authorization: Bearer key-one" \
  -H "Content-Type: application/json" \
  -d '{"query": "CVE-2021-41773"}'

# Browser flow stays unchanged: the user hits /api/triage on Next.js,
# which attaches AGENT_API_KEY upstream server-side.
```

`API_KEYS` switches on `Authorization: Bearer` / `X-API-Key` enforcement on `/v1/triage` and `/v1/meta`. The auth dependency uses `hmac.compare_digest` for constant-time comparison, and the 429 body never echoes the configured limit. `/v1/health` remains open under any configuration: container orchestrators (Docker, Kubernetes) must be able to run liveness probes without holding a key.

## MCP transport authentication

The MCP server (`:8001`) is the more powerful surface in the stack: direct tool access, no agent guardrails. By default it has no auth of its own and relies on docker-compose internal-network isolation (the port is **not** published to the host). Whenever the port is reachable beyond that perimeter, set a shared bearer secret:

```bash
# In .env or the host environment
MCP_AUTH_TOKEN="long-random-string"
```

With the token set, every HTTP request to the MCP server must carry `Authorization: Bearer long-random-string` or the response is `401 Unauthorized` with `WWW-Authenticate: Bearer realm="mcp"`. Comparison is constant-time (`secrets.compare_digest`). Lifespan and non-HTTP ASGI scopes pass through untouched. The token is held as `SecretStr` in `config.py` so it never leaks into structured logs.

The `agent-api` process needs no extra configuration: it talks to the MCP server over the in-process Pydantic AI client and is co-deployed with the secret. Standalone callers (third-party MCP clients, manual smoke from a separate host) must attach the header explicitly.

## Observability endpoints

OpenTelemetry tracing is enabled in both Python processes. The default exporter writes spans to stdout (zero infrastructure required). Set `OTEL_EXPORTER_OTLP_ENDPOINT` (or use `make obs-up`) to ship spans to an OTLP/HTTP collector; the compose profile `observability` bundles a Jaeger sidecar at `http://localhost:16686`.

```bash
make obs-up                     # mcp-server + agent-api + frontend + jaeger
open http://localhost:16686     # Jaeger UI
make obs-down
```

Each MCP tool emits one span (`tool.cve_lookup`, `tool.exploit_check`, ...) with stable attributes: `tool.name`, `tool.success`, `cve.id`, `cve.cvss_v3_score`, `hosts.count`, `query.length`. User query text and untrusted vendor content are never recorded as attributes; tests in `tests/test_observability.py` enforce that invariant with canary strings. W3C `traceparent` propagation flows from `frontend -> /api/triage -> agent-api -> mcp-server` via the httpx instrumentation, with no manual header handling in our code.

## Audit trail configuration

Settings live in `.env` (see `.env.example`): `AUDIT_LOG_ENABLED`, `AUDIT_DB_PATH`, `AUDIT_INCLUDE_QUERY`, `AUDIT_INCLUDE_SUMMARY`. Default posture is digest-only: plain query and report summary stay off unless explicitly enabled. Audit failures never break a triage call (best-effort with a structured warning log).

```bash
uv run sec-recon-audit count                # total event count
uv run sec-recon-audit tail --limit 5       # last 5 rows, human-readable
uv run sec-recon-audit tail --limit 5 --json
uv run sec-recon-audit verify               # walks the full chain; exit 1 on tamper
```

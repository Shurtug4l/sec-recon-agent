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

## Operational safety rails

Two guards in front of `/v1/triage`, both default off, both refusing with `503` **before** the agent is built (a refused request spends nothing on the LLM). They exist because an LLM endpoint reachable beyond localhost is a denial-of-wallet target: the per-request round cap (`AGENT_REQUEST_LIMIT`) bounds a single run, but nothing otherwise bounds the aggregate an attacker drives by repeating requests.

```bash
# Denial-of-wallet: hard ceiling on estimated LLM spend over a rolling 24h
# window, summed in-process from each run's token usage x the per-model price
# table (eval/cost.py). Over it, /v1/triage returns 503 until older spend ages
# out. The window is in memory, so it resets on restart -- that still bounds
# spend between restarts, which is the threat; a restart-durable counter is the
# production evolution.
DENIAL_OF_WALLET_USD_PER_DAY=5

# Kill-switch (two forms):
KILL_SWITCH=1                                  # persistent off for the container's life
KILL_SWITCH_FILE=/tmp/sec-recon-killswitch     # live toggle, checked per request
```

The file form disables the service without a redeploy and without a restart:

```bash
docker exec sec-recon-api touch /tmp/sec-recon-killswitch   # triage now 503s
docker exec sec-recon-api rm    /tmp/sec-recon-killswitch   # back online
```

In docker-compose `KILL_SWITCH_FILE` defaults to a tmpfs path, so the file toggle is ready to use out of the box but clears on restart; use `KILL_SWITCH=1` when you want the service to come back up still disabled. The 503 bodies are deliberately generic (the ceiling and the switch mechanism are operational details that do not belong in client responses). Network egress restriction is a separate rail (see the egress-proxy compose profile).

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

## Exporting a report

A saved `TriageReport` JSON (the `final` SSE event payload, or the frontend's raw-JSON export) renders into SARIF 2.1.0 or OpenVEX v0.2.0 without touching the LLM:

```bash
uv run sec-recon-export sarif report.json --artifact-uri data/sbom.json > triage.sarif
uv run sec-recon-export openvex report.json \
    --product "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" > triage.vex.json
```

The same renders are exposed statelessly over HTTP (same auth as the other endpoints):

```bash
curl -s localhost:8000/v1/export/sarif \
    -H 'content-type: application/json' \
    -d "{\"report\": $(cat report.json), \"artifact_uri\": \"data/sbom.json\"}"
```

OpenVEX requires the purl(s) of the triaged product (`--product`, repeatable): product identity is never guessed, so a bare-CVE triage exports SARIF but refuses VEX.

## SBOM gate

`sec-recon-gate` chains the same tool logic in-process with no LLM anywhere: `sbom_ingest` -> `osv_lookup` per component -> KEV / EPSS / exploit enrichment per unique CVE -> a deterministic SSVC decision per finding -> a CI verdict.

```bash
uv run sec-recon-gate sbom.json --sarif gate.sarif --openvex gate.vex.json --report gate.json
uv run sec-recon-gate requirements.txt --fail-on attend --strict
```

Exit codes are the CI contract: `0` the gate passed, `1` a finding met the `--fail-on` threshold (default `act`; `attend`, `track-star`, `never` available) or a coverage gap under `--strict`, `2` the gate could not run (unreadable/unusable SBOM, KEV catalog unreachable - a gate that cannot see the Act driver refuses to pass instead of going blind).

Feed posture: the CISA KEV catalog and the ExploitDB index are downloaded once and cached on disk; EPSS is queried per unique CVE with bounded concurrency; the GitHub exploit-search arm runs only when `GITHUB_TOKEN` is set (findings are marked `degraded` otherwise, never silently downgraded) and is skipped entirely for CVEs already on KEV, whose decision is already Act. Components without a version, without a recognizable ecosystem, or outside OSV's seven supported ecosystems are listed in the report's `skipped` section with a reason - nothing is dropped silently. GHSA / PYSEC records aliasing the same CVE fold into one finding with the sibling ids preserved in `aliases`.

The full `GateReport` JSON (findings, per-feed coverage, skipped components, aggregate SSVC, policy) goes to stdout or `--report`; `--sarif` and `--openvex` render through the same renderers as `sec-recon-export`, with every VEX statement bound to the affected component's own purl (synthesized only for PyPI components from requirements.txt, where the mapping is mechanical; other identity-less findings are excluded and reported, never guessed).

### As a GitHub Action

The gate ships as a composite action at the repository root; the action ref is the package source, so pinning the action pins the gate:

```yaml
permissions:
  contents: read
  security-events: write # SARIF upload

steps:
  - uses: actions/checkout@v7
  - uses: anchore/sbom-action@v0.24.0
    with: { path: ., format: cyclonedx-json, output-file: sbom.cdx.json, upload-artifact: false }
  - uses: Shurtug4l/sec-recon-agent@main
    with:
      sbom-path: sbom.cdx.json
      fail-on: act # act | attend | track-star | never
      github-token: ${{ github.token }} # optional: exploit-search arm; omitting = degraded, not silent
```

Inputs mirror the CLI (`strict`, `artifact-uri`, `upload-sarif`, `sarif-category`, `python-version`); outputs expose `verdict`, `exit-code`, and the three document paths. The SARIF upload happens before the verdict is enforced, so alerts reach the Security tab even when the gate fails the job. This repository dogfoods the action in `.github/workflows/ci-sbom-gate.yml` (self-scan on dependency changes + weekly cron, artifact attestations on non-PR runs, verifiable with `gh attestation verify`).

## Prebuilt images (GHCR)

Tagged releases (`v*`) publish both images to GHCR, multi-arch (amd64 + arm64), with BuildKit supply-chain attestations (SLSA provenance `mode=max` + SBOM) attached to the image index:

```bash
docker pull ghcr.io/shurtug4l/sec-recon-agent:0.1.0
docker pull ghcr.io/shurtug4l/sec-recon-frontend:0.1.0

# inspect the published attestations
docker buildx imagetools inspect ghcr.io/shurtug4l/sec-recon-agent:0.1.0
```

`latest` tracks the newest semver tag. To run the stack from the registry instead of a local build, override the two `image:` values in `docker-compose.yml` (the compose file builds locally by design; the registry is the sharing channel, not the dev loop). An Anthropic API key and a seeded ChromaDB volume are still required - see the sections above.

.DEFAULT_GOAL := help

.PHONY: help build seed up down logs ps restart triage test lint clean

help:  ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build:  ## Build the Docker image (multi-stage; uses uv cache mount).
	docker compose build

seed:  ## One-shot: pull CVEs from NVD and populate ChromaDB on the shared volume.
	docker compose --profile seed run --rm seed-job

up:  ## Start MCP server + agent API in the background.
	docker compose up -d

down:  ## Stop both services. The data volume is preserved.
	docker compose down

logs:  ## Tail logs from both services.
	docker compose logs -f

ps:  ## Show running containers.
	docker compose ps

restart:  ## Restart both services.
	docker compose restart

triage:  ## Send a query to the running agent. Usage: make triage Q="your question"
	@if [ -z "$(Q)" ]; then echo "Usage: make triage Q=\"your question\""; exit 1; fi
	@curl -N -X POST http://localhost:8000/v1/triage \
		-H "Content-Type: application/json" \
		-d '{"query": "$(Q)"}'

test:  ## Run the pytest suite locally (outside Docker).
	uv run pytest -q

lint:  ## Run ruff + mypy locally (backend only; frontend linting deferred).
	uv run ruff check src tests
	uv run mypy src

ui:  ## Open the frontend UI in the default browser (assumes `make up` is running).
	@open http://localhost:3000 2>/dev/null || xdg-open http://localhost:3000 2>/dev/null || echo "Frontend at http://localhost:3000"

obs-up:  ## Start the stack WITH the Jaeger sidecar and OTLP enabled. UI on :16686.
	@OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318 docker compose --profile observability up -d
	@echo "Jaeger UI: http://localhost:16686"

obs-down:  ## Stop the observability stack (keeps the data volume).
	docker compose --profile observability down

clean:  ## Stop services and DELETE the ChromaDB volume. Destructive.
	docker compose down --volumes

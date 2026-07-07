"""Centralized settings loaded from environment variables."""

from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    anthropic_api_key: SecretStr | None = None
    nvd_api_key: SecretStr | None = None
    github_token: SecretStr | None = None

    # API authentication: comma-separated list of accepted keys. When
    # the list is empty (default), /v1/triage and /v1/meta are open.
    # When set, every protected endpoint requires
    # `Authorization: Bearer <key>` or `X-API-Key: <key>`. Health stays
    # public.
    #
    # NoDecode opts out of pydantic-settings's default "parse env value
    # as JSON" for list[] fields — we want plain CSV input, handled by
    # the validator below.
    api_keys: Annotated[list[SecretStr], NoDecode] = Field(default_factory=list)
    # Bearer token for the MCP transport. When unset (default), the MCP
    # server is open (relies on the docker-compose internal network /
    # localhost binding for isolation). When set, every HTTP request to
    # the MCP server must carry `Authorization: Bearer <token>`. Use this
    # whenever the MCP port is published beyond the container network.
    mcp_auth_token: SecretStr | None = None
    # Per-IP rate limit on /v1/triage, in requests per minute. 0 or
    # None disables the limiter. Set to e.g. 30 for a dev deployment;
    # production behind a real WAF would set this much lower or rely
    # on the WAF instead.
    rate_limit_per_minute: int | None = Field(default=None, ge=0, le=10_000)

    @field_validator("api_keys", mode="before")
    @classmethod
    def _split_api_keys(cls, raw: object) -> object:
        """Accept either a Python list or a comma-separated env string."""
        if raw is None or raw == "":
            return []
        if isinstance(raw, str):
            return [k.strip() for k in raw.split(",") if k.strip()]
        return raw

    @field_validator("rate_limit_per_minute", mode="before")
    @classmethod
    def _empty_rate_limit_to_none(cls, raw: object) -> object:
        # docker-compose passes RATE_LIMIT_PER_MINUTE: "${RATE_LIMIT_PER_MINUTE:-}",
        # which becomes "" when the host env var is unset. Pydantic 2.x does
        # not coerce "" to None for int|None fields, so treat empty string as
        # "limiter disabled" to keep the documented default behavior.
        if isinstance(raw, str) and raw.strip() == "":
            return None
        return raw

    llm_provider: str = "anthropic"
    # Default cheapest-tier model. Override via LLM_MODEL env (claude-sonnet-4-6
    # or claude-opus-4-7) for stronger reasoning at higher cost per query.
    llm_model: str = "claude-haiku-4-5-20251001"

    mcp_server_host: str = "127.0.0.1"
    mcp_server_port: int = Field(default=8001, ge=1024, le=65535)
    agent_api_host: str = "127.0.0.1"
    agent_api_port: int = Field(default=8000, ge=1024, le=65535)

    chroma_persist_dir: Path = Path("./data/cve_index")
    # Hybrid retrieval switch for cve_semantic_search: dense MiniLM cosine
    # fused (reciprocal-rank fusion) with an in-process BM25 over the same
    # corpus. CVE text is identifier-heavy (product names, version strings),
    # which dense embeddings blur and BM25 matches exactly. False restores
    # the dense-only path.
    retrieval_hybrid_enabled: bool = True
    audit_db_path: Path = Path("./data/audit.db")
    # Master switch. When False the API does not even open the audit
    # database; useful for ephemeral demos and for tests that don't want
    # a stray SQLite file in tmp.
    audit_log_enabled: bool = True
    # Privacy switches: default off. Operators with a compliance posture
    # that requires plain-text retention flip these on per-deployment.
    audit_include_query: bool = False
    audit_include_summary: bool = False

    nvd_rate_limit_per_30s: int = Field(default=5, ge=1, le=50)

    # Runaway-loop guard: the maximum number of model requests (ReAct rounds)
    # one triage may make before Pydantic AI raises UsageLimitExceeded. A
    # legitimate triage converges in a handful of rounds because Anthropic
    # models batch tool calls per turn; a stuck agent (a tool that keeps
    # failing, an over-broad query) otherwise thrashes for 180s+ until the
    # client times out. 25 leaves generous headroom over observed legitimate
    # use while bounding the pathological case; tune down after a live eval.
    # pydantic-ai's own default is 50, deliberately tightened here.
    agent_request_limit: int = Field(default=25, ge=1, le=200)

    log_level: str = "INFO"

    @property
    def mcp_server_url(self) -> str:
        return f"http://{self.mcp_server_host}:{self.mcp_server_port}"


settings = Settings()

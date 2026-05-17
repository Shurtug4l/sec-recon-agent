"""Centralized settings loaded from environment variables."""

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    llm_provider: str = "anthropic"
    llm_model: str = "claude-sonnet-4-6"

    mcp_server_host: str = "127.0.0.1"
    mcp_server_port: int = Field(default=8001, ge=1024, le=65535)
    agent_api_host: str = "127.0.0.1"
    agent_api_port: int = Field(default=8000, ge=1024, le=65535)

    chroma_persist_dir: Path = Path("./data/cve_index")

    nvd_rate_limit_per_30s: int = Field(default=5, ge=1, le=50)
    log_level: str = "INFO"

    @property
    def mcp_server_url(self) -> str:
        return f"http://{self.mcp_server_host}:{self.mcp_server_port}"


settings = Settings()  # type: ignore[call-arg]

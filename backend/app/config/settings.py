"""Environment-driven configuration with safe local defaults (TDD §25/§26).

Every value can be overridden by an environment variable so the same code runs
in Docker Compose and in the local pytest venv. Defaults are deliberately
*safe*: localhost binding, synthetic secrets, no external egress. Nothing here
is a vulnerability — configuration is infrastructure (SEC-004).
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Pydantic-settings reads from the process environment and an optional .env
    # file. `extra="ignore"` means unrelated env vars (e.g. Docker's own) do not
    # crash startup — a small robustness win for infra code.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Application / networking -----------------------------------------
    app_env: str = Field(default="local", alias="APP_ENV")
    # DEP-004: bind to localhost by default; never exposed to external networks.
    bind_host: str = Field(default="127.0.0.1", alias="BIND_HOST")
    backend_port: int = Field(default=8000, alias="BACKEND_PORT")
    frontend_port: int = Field(default=5173, alias="FRONTEND_PORT")

    # --- Persistence ------------------------------------------------------
    # SQLite file, re-seedable for reset (RST-001). A single file keeps reset
    # trivial: drop + re-create + re-seed.
    database_url: str = Field(
        default="sqlite:///./backend/data/vuln_mcp.db", alias="DATABASE_URL"
    )

    # --- MCP plane --------------------------------------------------------
    # D-03: streamable HTTP transport is the production target. During Phase 0
    # the in-backend client talks to an in-process registry (see mcp_client),
    # so these URLs are recorded for telemetry/health but not yet dialled.
    mcp_server_url: str = Field(default="http://mcp-server:9000", alias="MCP_SERVER_URL")
    mcp_transport: str = Field(default="streamable-http", alias="MCP_TRANSPORT")
    # Global default mode. Per-lab overrides live in the DB (labs.mode).
    # Foundation ships every lab in a non-vulnerable baseline (no vuln code yet).
    mcp_mode: str = Field(default="secure", alias="MCP_MODE")

    # --- Sandbox plane (MCP05 only; wired in a later phase) ---------------
    sandbox_url: str = Field(default="http://sandbox:9100", alias="SANDBOX_URL")
    sandbox_timeout_seconds: int = Field(default=5, alias="SANDBOX_TIMEOUT_SECONDS")

    # --- Optional local LLM (never required for any effect; NFR-001) ------
    enable_local_llm: bool = Field(default=False, alias="ENABLE_LOCAL_LLM")
    ollama_url: str = Field(default="http://ollama:11434", alias="OLLAMA_URL")

    # --- Synthetic secret (SEC-002) --------------------------------------
    # This is a *placeholder*, not a real secret. It only becomes a leak target
    # inside the MCP03/MCP10 labs, which are not implemented in Phase 0.
    demo_secret_a: str = Field(default="DEMO_SECRET_A", alias="DEMO_SECRET_A")

    # D-05: the /api/health mode field is a convenience for the owner. It can be
    # disabled for stricter black-box evaluation so it cannot act as an oracle.
    expose_health_mode: bool = Field(default=True, alias="EXPOSE_HEALTH_MODE")

    # Frontend origin allowed through CORS (control-plane infra hardening).
    @property
    def frontend_origin(self) -> str:
        return f"http://{self.bind_host}:{self.frontend_port}"


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor.

    Tests can clear the cache (``get_settings.cache_clear()``) after mutating the
    environment (e.g. pointing DATABASE_URL at a temp file).
    """
    return Settings()

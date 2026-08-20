"""FastAPI control-plane application package.

Layers (TDD §7):
  * api/         -> REST endpoints (strictly validated infra surface)
  * services/    -> lab lifecycle, telemetry capture, evidence recording, reset
  * mcp_client/  -> wraps the MCP client; records every request/response as telemetry
  * models/      -> SQLModel entities (TDD §9 schema)
  * db/          -> engine, seed, reset
  * config/      -> env-driven settings with safe defaults
"""

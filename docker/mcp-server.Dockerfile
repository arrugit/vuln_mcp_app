# MCP server-plane image (TDD §14/§27). Physically separate from the backend.
# Phase 0 runs the stdlib entrypoint (mcp_servers/serve.py); the streamable-HTTP
# MCP SDK transport (D-03) is wired in a later phase.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_BIND_HOST=0.0.0.0 \
    MCP_BIND_PORT=9000

WORKDIR /app

# The Phase 0 server uses only the stdlib, so no pip install is required yet.
COPY mcp_servers /app/mcp_servers

EXPOSE 9000
# MCP_MODE is provided by compose (vulnerable|secure).
CMD ["python", "-m", "mcp_servers.serve"]

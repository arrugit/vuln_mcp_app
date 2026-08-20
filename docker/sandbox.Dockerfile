# Sandbox image (MCP05 execution plane, SEC-003). Minimal + non-root.
# Phase 0 ships the idle placeholder runner; the guarded command runner is added
# in the MCP05 phase. Isolation controls are enforced at compose level (§28).
FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create a non-root user (compose also pins user: 10001:10001).
RUN adduser -D -u 10001 sandboxuser

WORKDIR /app
COPY sandbox/runner.py /app/runner.py

USER sandboxuser
# No network, read-only root, tmpfs /work, cap-drop ALL are applied by compose.
CMD ["python", "/app/runner.py"]

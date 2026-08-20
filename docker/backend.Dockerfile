# Backend / control-plane image (TDD §27). Ordinarily-secure infrastructure.
FROM python:3.12-slim

# Non-root by default is applied at compose level for the sandbox; the backend
# runs as a normal service user here for good hygiene (SEC-004).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install backend deps first for better layer caching.
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy the control plane + the physically-separate mcp_servers package (the
# backend imports it in-process for the Phase 0 transport).
COPY backend /app/backend
COPY mcp_servers /app/mcp_servers

# Data dir for the SQLite file (mounted as a volume in compose).
RUN mkdir -p /app/data

EXPOSE 8000
# uvicorn binds 0.0.0.0 inside the container; compose publishes only to 127.0.0.1.
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

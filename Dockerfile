# CVE MCP Server Dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash cve_mcp

# Set work directory
WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY scripts/ ./scripts/
COPY data/ ./data/

# Install Python dependencies
RUN pip install --no-cache-dir .

# Change ownership
RUN chown -R cve_mcp:cve_mcp /app

# Switch to non-root user
USER cve_mcp

# Default to MCP Streamable HTTP transport for Docker/Azure deployment.
# Override MCP_MODE=http for FastAPI wrapper or MCP_MODE=stdio for stdio.
ENV MCP_MODE=mcp-http \
    MCP_PORT=8307 \
    MCP_HOST=0.0.0.0

# Default command
CMD ["python", "-m", "cve_mcp.main"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8307/health || exit 1

# Expose port
EXPOSE 8307

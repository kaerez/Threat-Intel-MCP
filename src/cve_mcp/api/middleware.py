"""FastAPI middleware for HTTP wrapper.

This module provides middleware for the HTTP wrapper layer that exposes
the MCP server via REST endpoints for Ansvar platform integration.

Note: NO rate limiting middleware - this is internal deployment only.
"""

import time
from typing import Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging HTTP requests and responses.

    Logs request method, path, status code, and response time for all requests.
    Useful for debugging and monitoring HTTP wrapper usage.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log details."""
        start_time = time.time()

        # Log incoming request
        logger.debug(
            "HTTP request",
            method=request.method,
            path=request.url.path,
            query=str(request.url.query) if request.url.query else None,
        )

        # Process request
        response = await call_next(request)

        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Log response
        logger.info(
            "HTTP response",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )

        return response

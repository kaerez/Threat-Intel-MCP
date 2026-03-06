"""Redis caching service for CVE MCP server."""

import hashlib
import json
from typing import Any

import redis.asyncio as redis
import structlog

from cve_mcp.config import get_settings

logger = structlog.get_logger(__name__)


class CacheService:
    """Redis-based caching service for query results.

    All public methods are safe to call even when Redis is unavailable —
    reads return None (cache miss), writes are silently skipped.
    This ensures tool handlers always fall through to the database.
    """

    def __init__(self) -> None:
        """Initialize cache service."""
        self.settings = get_settings()
        self._redis: redis.Redis | None = None

    @property
    def available(self) -> bool:
        """Whether Redis client has been initialized."""
        return self._redis is not None

    async def connect(self) -> None:
        """Connect to Redis."""
        try:
            self._redis = redis.from_url(
                self.settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            await self._redis.ping()
            logger.info("Redis connected")
        except Exception as e:
            logger.warning("Redis unavailable, running without cache", error=str(e))
            self._redis = None

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._redis:
            await self._redis.close()
            self._redis = None

    def _make_key(self, prefix: str, identifier: str) -> str:
        """Create a cache key."""
        return f"{prefix}:{identifier}"

    def _hash_params(self, params: dict[str, Any]) -> str:
        """Create a hash of query parameters for cache key."""
        sorted_params = json.dumps(params, sort_keys=True)
        return hashlib.sha256(sorted_params.encode()).hexdigest()[:16]

    async def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Get cached CVE details. Returns None on miss or Redis failure."""
        if not self._redis:
            return None
        try:
            key = self._make_key("cve", cve_id)
            data = await self._redis.get(key)
            if data:
                return json.loads(data)  # type: ignore[no-any-return]
        except Exception as e:
            logger.debug("Cache read failed", key=f"cve:{cve_id}", error=str(e))
        return None

    async def set_cve(self, cve_id: str, data: dict[str, Any]) -> None:
        """Cache CVE details. Silently skipped if Redis unavailable."""
        if not self._redis:
            return
        try:
            key = self._make_key("cve", cve_id)
            await self._redis.set(
                key,
                json.dumps(data, default=str),
                ex=self.settings.cve_details_cache_ttl_seconds,
            )
        except Exception as e:
            logger.debug("Cache write failed", key=f"cve:{cve_id}", error=str(e))

    async def get_search(self, params: dict[str, Any]) -> dict[str, Any] | None:
        """Get cached search results. Returns None on miss or Redis failure."""
        if not self._redis:
            return None
        try:
            param_hash = self._hash_params(params)
            key = self._make_key("search", param_hash)
            data = await self._redis.get(key)
            if data:
                return json.loads(data)  # type: ignore[no-any-return]
        except Exception as e:
            logger.debug("Cache read failed", key="search", error=str(e))
        return None

    async def set_search(self, params: dict[str, Any], data: dict[str, Any]) -> None:
        """Cache search results. Silently skipped if Redis unavailable."""
        if not self._redis:
            return
        try:
            param_hash = self._hash_params(params)
            key = self._make_key("search", param_hash)
            await self._redis.set(
                key,
                json.dumps(data, default=str),
                ex=self.settings.query_cache_ttl_seconds,
            )
        except Exception as e:
            logger.debug("Cache write failed", key="search", error=str(e))

    async def get_kev_list(self) -> list[str] | None:
        """Get cached list of KEV CVE IDs."""
        if not self._redis:
            return None
        try:
            data = await self._redis.get("kev:list")
            if data:
                return json.loads(data)  # type: ignore[no-any-return]
        except Exception as e:
            logger.debug("Cache read failed", key="kev:list", error=str(e))
        return None

    async def set_kev_list(self, cve_ids: list[str]) -> None:
        """Cache list of KEV CVE IDs."""
        if not self._redis:
            return
        try:
            await self._redis.set(
                "kev:list",
                json.dumps(cve_ids),
                ex=self.settings.cve_details_cache_ttl_seconds,
            )
        except Exception as e:
            logger.debug("Cache write failed", key="kev:list", error=str(e))

    async def invalidate_cve(self, cve_id: str) -> None:
        """Invalidate cached CVE data."""
        if not self._redis:
            return
        try:
            key = self._make_key("cve", cve_id)
            await self._redis.delete(key)
        except Exception as e:
            logger.debug("Cache invalidation failed", key=f"cve:{cve_id}", error=str(e))

    async def invalidate_all_searches(self) -> None:
        """Invalidate all cached search results."""
        if not self._redis:
            return
        try:
            async for key in self._redis.scan_iter("search:*"):
                await self._redis.delete(key)
        except Exception as e:
            logger.debug("Cache invalidation failed", key="search:*", error=str(e))

    async def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        if not self._redis:
            return {"redis_connected": False}
        try:
            info = await self._redis.info()
            return {
                "redis_connected": True,
                "used_memory": info.get("used_memory_human", "unknown"),
                "connected_clients": info.get("connected_clients", 0),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
            }
        except Exception:
            return {"redis_connected": False}

    async def health_check(self) -> bool:
        """Check if Redis is healthy."""
        if not self._redis:
            return False
        try:
            await self._redis.ping()
            return True
        except Exception:
            return False


# Global cache service instance
cache_service = CacheService()

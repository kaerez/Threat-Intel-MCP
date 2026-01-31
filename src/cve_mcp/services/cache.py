"""Redis caching service for CVE MCP server."""

import hashlib
import json
from typing import Any

import redis.asyncio as redis

from cve_mcp.config import get_settings


class CacheService:
    """Redis-based caching service for query results."""

    def __init__(self) -> None:
        """Initialize cache service."""
        self.settings = get_settings()
        self._redis: redis.Redis | None = None

    async def connect(self) -> None:
        """Connect to Redis."""
        self._redis = redis.from_url(
            self.settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._redis:
            await self._redis.close()
            self._redis = None

    @property
    def redis(self) -> redis.Redis:
        """Get Redis client."""
        if not self._redis:
            raise RuntimeError("Redis not connected. Call connect() first.")
        return self._redis

    def _make_key(self, prefix: str, identifier: str) -> str:
        """Create a cache key."""
        return f"{prefix}:{identifier}"

    def _hash_params(self, params: dict[str, Any]) -> str:
        """Create a hash of query parameters for cache key."""
        # Sort keys for consistent hashing
        sorted_params = json.dumps(params, sort_keys=True)
        return hashlib.sha256(sorted_params.encode()).hexdigest()[:16]

    async def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Get cached CVE details."""
        key = self._make_key("cve", cve_id)
        data = await self.redis.get(key)
        if data:
            return json.loads(data)  # type: ignore[no-any-return]
        return None

    async def set_cve(self, cve_id: str, data: dict[str, Any]) -> None:
        """Cache CVE details."""
        key = self._make_key("cve", cve_id)
        await self.redis.set(
            key,
            json.dumps(data, default=str),
            ex=self.settings.cve_details_cache_ttl_seconds,
        )

    async def get_search(self, params: dict[str, Any]) -> dict[str, Any] | None:
        """Get cached search results."""
        param_hash = self._hash_params(params)
        key = self._make_key("search", param_hash)
        data = await self.redis.get(key)
        if data:
            return json.loads(data)  # type: ignore[no-any-return]
        return None

    async def set_search(self, params: dict[str, Any], data: dict[str, Any]) -> None:
        """Cache search results."""
        param_hash = self._hash_params(params)
        key = self._make_key("search", param_hash)
        await self.redis.set(
            key,
            json.dumps(data, default=str),
            ex=self.settings.query_cache_ttl_seconds,
        )

    async def get_kev_list(self) -> list[str] | None:
        """Get cached list of KEV CVE IDs."""
        data = await self.redis.get("kev:list")
        if data:
            return json.loads(data)  # type: ignore[no-any-return]
        return None

    async def set_kev_list(self, cve_ids: list[str]) -> None:
        """Cache list of KEV CVE IDs."""
        await self.redis.set(
            "kev:list",
            json.dumps(cve_ids),
            ex=self.settings.cve_details_cache_ttl_seconds,
        )

    async def invalidate_cve(self, cve_id: str) -> None:
        """Invalidate cached CVE data."""
        key = self._make_key("cve", cve_id)
        await self.redis.delete(key)

    async def invalidate_all_searches(self) -> None:
        """Invalidate all cached search results."""
        async for key in self.redis.scan_iter("search:*"):
            await self.redis.delete(key)

    async def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        info = await self.redis.info()
        return {
            "redis_connected": True,
            "used_memory": info.get("used_memory_human", "unknown"),
            "connected_clients": info.get("connected_clients", 0),
            "keyspace_hits": info.get("keyspace_hits", 0),
            "keyspace_misses": info.get("keyspace_misses", 0),
        }

    async def health_check(self) -> bool:
        """Check if Redis is healthy."""
        try:
            await self.redis.ping()
            return True
        except Exception:
            return False


# Global cache service instance
cache_service = CacheService()

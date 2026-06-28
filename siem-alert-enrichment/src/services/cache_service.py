"""Redis-backed async cache service.

Stores enrichment results as JSON strings, keyed by IOC type + value.
Falls back gracefully when Redis is unavailable.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import redis.asyncio as aioredis

from ..config import get_settings

logger = logging.getLogger(__name__)


class CacheService:
    def __init__(self) -> None:
        settings = get_settings()
        self._ttl = settings.cache_ttl_seconds
        try:
            self._client: aioredis.Redis = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
        except Exception as exc:
            logger.warning("Redis init failed — cache disabled: %s", exc)
            self._client = None  # type: ignore[assignment]

    async def get(self, key: str) -> dict[str, Any] | None:
        if self._client is None:
            return None
        try:
            raw = await self._client.get(key)
            if raw:
                return json.loads(raw)
        except Exception as exc:
            logger.debug("Cache GET error for %s: %s", key, exc)
        return None

    async def set(self, key: str, value: dict[str, Any]) -> None:
        if self._client is None:
            return
        try:
            await self._client.set(key, json.dumps(value), ex=self._ttl)
        except Exception as exc:
            logger.debug("Cache SET error for %s: %s", key, exc)

    async def delete(self, key: str) -> None:
        if self._client is None:
            return
        try:
            await self._client.delete(key)
        except Exception as exc:
            logger.debug("Cache DEL error for %s: %s", key, exc)

    async def flush(self) -> None:
        """Clear all cached enrichments (useful for tests / admin)."""
        if self._client is None:
            return
        try:
            await self._client.flushdb()
        except Exception as exc:
            logger.warning("Cache flush error: %s", exc)

    async def ping(self) -> bool:
        if self._client is None:
            return False
        try:
            return await self._client.ping()
        except Exception:
            return False

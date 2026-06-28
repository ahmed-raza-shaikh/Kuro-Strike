"""Abstract base class for all threat-intelligence enrichers."""
from __future__ import annotations

from abc import ABC


class BaseEnricher(ABC):
    """Common init for every enricher: API key + timeout."""

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        self.api_key = api_key
        self.timeout = timeout

    # Subclasses implement only the methods they support
    async def enrich_ip(self, ip: str):  # type: ignore[return]
        raise NotImplementedError

    async def enrich_domain(self, domain: str):  # type: ignore[return]
        raise NotImplementedError

    async def enrich_hash(self, file_hash: str):  # type: ignore[return]
        raise NotImplementedError

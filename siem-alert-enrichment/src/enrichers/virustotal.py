"""VirusTotal API v3 enricher.

Docs: https://developers.virustotal.com/reference/overview
"""
from __future__ import annotations

import logging

import httpx

from ..models.enrichment import VirusTotalResult
from .base import BaseEnricher

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalEnricher(BaseEnricher):
    """Async enricher wrapping VirusTotal API v3."""

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        super().__init__(api_key, timeout)
        self._headers = {"x-apikey": api_key, "Accept": "application/json"}

    # ── Internal helper ────────────────────────────────────────────────────

    async def _get(self, path: str) -> dict | None:
        """GET *path* and return JSON body, or None on error."""
        url = f"{_VT_BASE}/{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=self._headers)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                logger.debug("VT 404 for %s", path)
                return None
            logger.warning("VT returned %d for %s", resp.status_code, path)
            return None
        except httpx.TimeoutException:
            logger.warning("VT timeout for %s", path)
            return None
        except Exception as exc:
            logger.error("VT request error for %s: %s", path, exc)
            return None

    @staticmethod
    def _parse_attributes(attrs: dict) -> VirusTotalResult:
        stats = attrs.get("last_analysis_stats", {})
        last_date = attrs.get("last_analysis_date")
        return VirusTotalResult(
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            reputation=attrs.get("reputation", 0),
            tags=attrs.get("tags", []),
            last_analysis_date=str(last_date) if last_date else None,
        )

    # ── Public API ────────────────────────────────────────────────────────

    async def enrich_ip(self, ip: str) -> VirusTotalResult:
        data = await self._get(f"ip_addresses/{ip}")
        if data is None:
            return VirusTotalResult(error="No data returned by VirusTotal")
        try:
            return self._parse_attributes(data["data"]["attributes"])
        except (KeyError, TypeError) as exc:
            return VirusTotalResult(error=f"Parse error: {exc}")

    async def enrich_domain(self, domain: str) -> VirusTotalResult:
        data = await self._get(f"domains/{domain}")
        if data is None:
            return VirusTotalResult(error="No data returned by VirusTotal")
        try:
            return self._parse_attributes(data["data"]["attributes"])
        except (KeyError, TypeError) as exc:
            return VirusTotalResult(error=f"Parse error: {exc}")

    async def enrich_hash(self, file_hash: str) -> VirusTotalResult:
        data = await self._get(f"files/{file_hash}")
        if data is None:
            return VirusTotalResult(error="No data returned by VirusTotal")
        try:
            attrs = data["data"]["attributes"]
            result = self._parse_attributes(attrs)
            # File-specific extras
            result.tags = attrs.get("tags", []) or attrs.get("type_tags", [])
            return result
        except (KeyError, TypeError) as exc:
            return VirusTotalResult(error=f"Parse error: {exc}")

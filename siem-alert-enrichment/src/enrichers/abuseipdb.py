"""AbuseIPDB API v2 enricher.

Docs: https://docs.abuseipdb.com/#check-endpoint
"""
from __future__ import annotations

import logging

import httpx

from ..models.enrichment import AbuseIPDBResult
from .base import BaseEnricher

logger = logging.getLogger(__name__)

_ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
_MAX_AGE_DAYS = 90


class AbuseIPDBEnricher(BaseEnricher):
    """Async enricher for AbuseIPDB crowd-sourced abuse reports."""

    async def enrich_ip(self, ip: str) -> AbuseIPDBResult:
        url = f"{_ABUSEIPDB_BASE}/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": _MAX_AGE_DAYS,
            "verbose": "",   # include ISP / usage-type
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers, params=params)

            if resp.status_code == 401:
                return AbuseIPDBResult(error="Invalid AbuseIPDB API key")

            if resp.status_code == 429:
                return AbuseIPDBResult(error="AbuseIPDB rate limit exceeded")

            if resp.status_code != 200:
                return AbuseIPDBResult(error=f"AbuseIPDB returned HTTP {resp.status_code}")

            data = resp.json().get("data", {})

            return AbuseIPDBResult(
                abuse_confidence_score=data.get("abuseConfidenceScore", 0),
                country_code=data.get("countryCode"),
                isp=data.get("isp"),
                domain=data.get("domain"),
                total_reports=data.get("totalReports", 0),
                last_reported_at=data.get("lastReportedAt"),
                is_tor=data.get("isTor", False),
                usage_type=data.get("usageType"),
            )

        except httpx.TimeoutException:
            logger.warning("AbuseIPDB timeout for %s", ip)
            return AbuseIPDBResult(error="AbuseIPDB request timed out")
        except Exception as exc:
            logger.error("AbuseIPDB error for %s: %s", ip, exc)
            return AbuseIPDBResult(error=str(exc))

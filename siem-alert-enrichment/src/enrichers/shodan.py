"""Shodan REST API enricher.

Docs: https://developer.shodan.io/api
"""
from __future__ import annotations

import logging

import httpx

from ..models.enrichment import ShodanResult
from .base import BaseEnricher

logger = logging.getLogger(__name__)

_SHODAN_BASE = "https://api.shodan.io"


class ShodanEnricher(BaseEnricher):
    """Async enricher for Shodan host intelligence."""

    async def enrich_ip(self, ip: str) -> ShodanResult:
        url = f"{_SHODAN_BASE}/shodan/host/{ip}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, params={"key": self.api_key})

            if resp.status_code == 404:
                # Shodan has no record — not necessarily malicious
                return ShodanResult(error="IP not indexed by Shodan")

            if resp.status_code == 401:
                return ShodanResult(error="Invalid Shodan API key")

            if resp.status_code != 200:
                return ShodanResult(error=f"Shodan returned HTTP {resp.status_code}")

            data = resp.json()

            # Ports come from the list of banners
            ports = sorted({item.get("port", 0) for item in data.get("data", []) if item.get("port")})

            return ShodanResult(
                org=data.get("org"),
                country_code=data.get("country_code"),
                city=data.get("city"),
                isp=data.get("isp"),
                open_ports=ports,
                vulns=list(data.get("vulns", {}).keys()),
                hostnames=data.get("hostnames", []),
                tags=data.get("tags", []),
                os=data.get("os"),
            )

        except httpx.TimeoutException:
            logger.warning("Shodan timeout for %s", ip)
            return ShodanResult(error="Shodan request timed out")
        except Exception as exc:
            logger.error("Shodan error for %s: %s", ip, exc)
            return ShodanResult(error=str(exc))

"""API routes for the enrichment service."""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, Header, HTTPException, status

from ..config import Settings, get_settings
from ..models.alert import SplunkAlert, SplunkWebhookPayload
from ..models.enrichment import EnrichedAlert
from ..services.cache_service import CacheService
from ..services.enrichment_service import EnrichmentService

logger = logging.getLogger(__name__)
router = APIRouter()

# Shared service singletons (created once per worker process)
_enrichment_service: EnrichmentService | None = None
_cache_service: CacheService | None = None


def get_enrichment_service() -> EnrichmentService:
    global _enrichment_service
    if _enrichment_service is None:
        _enrichment_service = EnrichmentService()
    return _enrichment_service


def get_cache_service() -> CacheService:
    global _cache_service
    if _cache_service is None:
        _cache_service = CacheService()
    return _cache_service


# ── Auth helper ────────────────────────────────────────────────────────────────

def _verify_webhook_token(
    x_splunk_token: str | None,
    settings: Settings,
) -> None:
    """Validate optional bearer token on webhook endpoint."""
    if not settings.splunk_webhook_token:
        return  # Auth disabled
    if x_splunk_token != settings.splunk_webhook_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Splunk-Token header",
        )


# ── Health / metrics ───────────────────────────────────────────────────────────

@router.get("/health", tags=["ops"])
async def health(
    cache: CacheService = Depends(get_cache_service),
) -> Dict[str, Any]:
    redis_ok = await cache.ping()
    return {
        "status": "ok",
        "redis": "connected" if redis_ok else "unavailable",
    }


# ── Main enrichment endpoints ──────────────────────────────────────────────────

@router.post(
    "/enrich",
    response_model=EnrichedAlert,
    tags=["enrichment"],
    summary="Enrich a SIEM alert with threat intelligence",
)
async def enrich_alert(
    alert: SplunkAlert,
    service: EnrichmentService = Depends(get_enrichment_service),
) -> EnrichedAlert:
    """
    Accept a normalised `SplunkAlert` JSON body, run concurrent
    VirusTotal / Shodan / AbuseIPDB lookups for every extracted IOC,
    and return an `EnrichedAlert` with risk score and triage summary.
    """
    return await service.enrich_alert(alert)


@router.post(
    "/webhook/splunk",
    response_model=EnrichedAlert,
    tags=["enrichment"],
    summary="Splunk native webhook receiver",
)
async def splunk_webhook(
    payload: SplunkWebhookPayload,
    service: EnrichmentService = Depends(get_enrichment_service),
    settings: Settings = Depends(get_settings),
    x_splunk_token: str | None = Header(default=None),
) -> EnrichedAlert:
    """
    Drop-in receiver for Splunk's built-in **Webhook** alert action.
    Configure the action URL as `http://<host>:8000/webhook/splunk`.

    Optionally set `X-Splunk-Token` header and `SPLUNK_WEBHOOK_TOKEN`
    env var to authenticate incoming calls.
    """
    _verify_webhook_token(x_splunk_token, settings)
    alert = payload.to_splunk_alert()
    return await service.enrich_alert(alert)


# ── Cache management (admin) ───────────────────────────────────────────────────

@router.delete(
    "/cache",
    tags=["ops"],
    summary="Flush the enrichment cache",
)
async def flush_cache(
    cache: CacheService = Depends(get_cache_service),
) -> Dict[str, str]:
    await cache.flush()
    return {"status": "cache flushed"}

"""Shared pytest fixtures."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from src.config import get_settings
from src.main import create_app
from src.models.alert import SplunkAlert
from src.models.enrichment import (
    AbuseIPDBResult,
    ShodanResult,
    VirusTotalResult,
)
from src.services.cache_service import CacheService

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ── Settings override ──────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def override_settings(monkeypatch):
    """Use dummy API keys so tests never hit real APIs."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test-key")
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-test-key")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse-test-key")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/15")  # test DB
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ── Sample data ────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_alert_data() -> dict:
    return json.loads((FIXTURES_DIR / "sample_alert.json").read_text())


@pytest.fixture
def sample_alert(sample_alert_data) -> SplunkAlert:
    return SplunkAlert(**sample_alert_data)


# ── Mock enricher results ──────────────────────────────────────────────────────

@pytest.fixture
def malicious_vt_result() -> VirusTotalResult:
    return VirusTotalResult(
        malicious=23, suspicious=2, harmless=60, undetected=5,
        reputation=-80, tags=["malware", "trojan"],
        last_analysis_date="1718458000",
    )


@pytest.fixture
def clean_vt_result() -> VirusTotalResult:
    return VirusTotalResult(malicious=0, suspicious=0, harmless=80, undetected=10)


@pytest.fixture
def high_abuse_result() -> AbuseIPDBResult:
    return AbuseIPDBResult(
        abuse_confidence_score=95,
        country_code="RU",
        isp="Frantech Solutions",
        total_reports=847,
        last_reported_at="2024-06-15T12:00:00+00:00",
        is_tor=False,
        usage_type="Data Center/Web Hosting/Transit",
    )


@pytest.fixture
def shodan_with_vulns() -> ShodanResult:
    return ShodanResult(
        org="AS-CHOOPA",
        country_code="US",
        open_ports=[22, 80, 443, 4444],
        vulns=["CVE-2021-44228", "CVE-2022-0847"],
        hostnames=["evil.host.example"],
    )


# ── Mocked services ───────────────────────────────────────────────────────────

@pytest.fixture
def mock_cache(monkeypatch):
    cache = MagicMock(spec=CacheService)
    cache.get = AsyncMock(return_value=None)   # cache miss by default
    cache.set = AsyncMock()
    cache.ping = AsyncMock(return_value=True)
    cache.flush = AsyncMock()
    return cache


# ── FastAPI test client ────────────────────────────────────────────────────────

@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app)

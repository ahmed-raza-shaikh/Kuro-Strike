"""API endpoint and enrichment service integration tests."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from src.api.routes import get_cache_service, get_enrichment_service
from src.models.enrichment import (
    AbuseIPDBResult,
    DomainEnrichment,
    EnrichedAlert,
    HashEnrichment,
    IPEnrichment,
    ShodanResult,
    VirusTotalResult,
)
from src.models.alert import SplunkAlert
from src.services.enrichment_service import EnrichmentService


# ── IOC extraction ─────────────────────────────────────────────────────────────

class TestIOCExtraction:
    def test_extracts_explicit_ips(self, sample_alert):
        iocs = sample_alert.extract_iocs()
        assert "185.220.101.45" in iocs.ips

    def test_filters_private_ips(self):
        alert = SplunkAlert(
            alert_name="Test",
            source_ip="192.168.1.100",
            destination_ip="185.220.101.45",
        )
        iocs = alert.extract_iocs()
        assert "192.168.1.100" not in iocs.ips
        assert "185.220.101.45" in iocs.ips

    def test_extracts_domain_from_result(self):
        alert = SplunkAlert(
            alert_name="Test",
            result={"domain": "evil.example.com"},
        )
        iocs = alert.extract_iocs()
        assert "evil.example.com" in iocs.domains

    def test_normalizes_domain_from_url(self):
        alert = SplunkAlert(
            alert_name="Test",
            result={"url": "https://Evil.Example.com:8443/path?q=1"},
        )
        iocs = alert.extract_iocs()
        assert "evil.example.com" in iocs.domains

    def test_ignores_internal_hostname_as_domain(self):
        alert = SplunkAlert(
            alert_name="Test",
            domain="ws-finance-07",
            result={"hostname": "localhost"},
        )
        iocs = alert.extract_iocs()
        assert iocs.domains == []

    def test_extracts_md5_hash(self):
        alert = SplunkAlert(
            alert_name="Test",
            file_hash="44d88612fea8a8f36de82e1278abb02f",
        )
        iocs = alert.extract_iocs()
        assert "44d88612fea8a8f36de82e1278abb02f" in iocs.file_hashes

    def test_extracts_sha256_from_result_value(self):
        sha256 = "a" * 64
        alert = SplunkAlert(
            alert_name="Test",
            result={"some_key": sha256},
        )
        iocs = alert.extract_iocs()
        assert sha256 in iocs.file_hashes

    def test_no_iocs_returns_empty_bundle(self):
        alert = SplunkAlert(alert_name="Test", result={"msg": "hello world"})
        iocs = alert.extract_iocs()
        assert iocs.ips == []
        assert iocs.domains == []
        assert iocs.file_hashes == []


# ── Risk scoring ───────────────────────────────────────────────────────────────

class TestRiskScoring:
    def setup_method(self):
        self.service = EnrichmentService.__new__(EnrichmentService)

    def _make_ip_enrichment(self, ip, vt=None, shodan=None, abuseipdb=None):
        return IPEnrichment(
            ip=ip,
            virustotal=vt or VirusTotalResult(),
            shodan=shodan or ShodanResult(),
            abuseipdb=abuseipdb or AbuseIPDBResult(),
        )

    def test_clean_ip_scores_low(self):
        ip_enr = {
            "1.2.3.4": self._make_ip_enrichment(
                "1.2.3.4",
                vt=VirusTotalResult(malicious=0, harmless=80),
                abuseipdb=AbuseIPDBResult(abuse_confidence_score=0),
            )
        }
        score = self.service._calculate_risk_score(ip_enr, {}, {})
        assert score < 25

    def test_high_abuse_scores_high(self):
        ip_enr = {
            "1.2.3.4": self._make_ip_enrichment(
                "1.2.3.4",
                abuseipdb=AbuseIPDBResult(abuse_confidence_score=95, total_reports=900),
            )
        }
        score = self.service._calculate_risk_score(ip_enr, {}, {})
        assert score >= 47  # 95 * 0.5 = 47

    def test_malicious_hash_scores_critical(self):
        hash_enr = {
            "abc123": HashEnrichment(
                file_hash="abc123",
                virustotal=VirusTotalResult(malicious=60),
            )
        }
        score = self.service._calculate_risk_score({}, {}, hash_enr)
        assert score >= 75  # 60 * 6 = 360 → capped at 100

    def test_risk_level_thresholds(self):
        assert self.service._risk_level(0) == "LOW"
        assert self.service._risk_level(24) == "LOW"
        assert self.service._risk_level(25) == "MEDIUM"
        assert self.service._risk_level(50) == "HIGH"
        assert self.service._risk_level(75) == "CRITICAL"
        assert self.service._risk_level(100) == "CRITICAL"

    def test_tor_exit_adds_bonus(self):
        ip_enr = {
            "1.2.3.4": self._make_ip_enrichment(
                "1.2.3.4",
                abuseipdb=AbuseIPDBResult(abuse_confidence_score=0, is_tor=True),
            )
        }
        score = self.service._calculate_risk_score(ip_enr, {}, {})
        assert score >= 10


class TestEnrichmentServiceAccounting:
    @pytest.mark.asyncio
    async def test_counts_cached_and_fresh_results(self):
        service = EnrichmentService.__new__(EnrichmentService)
        service._semaphore = asyncio.Semaphore(10)

        async def enrich_ip(ip):
            return IPEnrichment(ip=ip), True

        async def enrich_domain(domain):
            return DomainEnrichment(domain=domain), False

        async def enrich_hash(file_hash):
            return HashEnrichment(file_hash=file_hash), False

        service._enrich_ip = enrich_ip
        service._enrich_domain = enrich_domain
        service._enrich_hash = enrich_hash

        alert = SplunkAlert(
            alert_name="Test",
            source_ip="8.8.8.8",
            domain="evil.example.com",
            file_hash="44d88612fea8a8f36de82e1278abb02f",
        )

        enriched = await service.enrich_alert(alert)

        assert enriched.cached_results == 1
        assert enriched.fresh_results == 2


# ── API endpoints ──────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_ok(self, client, mock_cache):
        client.app.dependency_overrides[get_cache_service] = lambda: mock_cache
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.json()["redis"] == "connected"
        client.app.dependency_overrides.clear()


class TestEnrichEndpoint:
    def _make_mock_service(self, risk_level="HIGH"):
        svc = AsyncMock(spec=EnrichmentService)
        svc.enrich_alert.return_value = EnrichedAlert(
            original_alert={"alert_name": "Test"},
            risk_score=60,
            risk_level=risk_level,
            triage_summary="🟠 HIGH RISK | Score: 60/100",
            enrichment_duration_ms=250.0,
        )
        return svc

    def test_enrich_returns_200(self, client, sample_alert_data):
        mock_svc = self._make_mock_service()
        client.app.dependency_overrides[get_enrichment_service] = lambda: mock_svc
        resp = client.post("/enrich", json=sample_alert_data)
        assert resp.status_code == 200
        body = resp.json()
        assert body["risk_level"] == "HIGH"
        assert body["risk_score"] == 60
        assert "triage_summary" in body
        client.app.dependency_overrides.clear()

    def test_enrich_missing_alert_name_returns_422(self, client):
        resp = client.post("/enrich", json={"result": {}})
        assert resp.status_code == 422

    def test_splunk_webhook_format(self, client):
        mock_svc = self._make_mock_service("CRITICAL")
        client.app.dependency_overrides[get_enrichment_service] = lambda: mock_svc
        payload = {
            "sid": "scheduler__admin__search_name__1718000000.0",
            "search_name": "SOC-042-Outbound-C2-Traffic",
            "app": "search",
            "result": {
                "src_ip": "185.220.101.45",
                "dest_ip": "104.21.14.88",
                "dest_port": "4444",
            },
        }
        resp = client.post("/webhook/splunk", json=payload)
        assert resp.status_code == 200
        client.app.dependency_overrides.clear()

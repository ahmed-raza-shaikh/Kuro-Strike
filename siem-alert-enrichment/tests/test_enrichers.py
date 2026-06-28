"""Unit tests for the three threat-intelligence enrichers."""
from __future__ import annotations

import pytest
import respx
from httpx import Response

from src.enrichers.abuseipdb import AbuseIPDBEnricher
from src.enrichers.shodan import ShodanEnricher
from src.enrichers.virustotal import VirusTotalEnricher

TEST_IP = "185.220.101.45"
TEST_DOMAIN = "malware-c2-domain.xyz"
TEST_HASH = "44d88612fea8a8f36de82e1278abb02f"


# ── VirusTotal ─────────────────────────────────────────────────────────────────

class TestVirusTotalEnricher:
    @pytest.fixture
    def enricher(self):
        return VirusTotalEnricher(api_key="vt-test-key", timeout=5)

    @respx.mock
    @pytest.mark.asyncio
    async def test_enrich_ip_malicious(self, enricher):
        respx.get(f"https://www.virustotal.com/api/v3/ip_addresses/{TEST_IP}").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 15, "suspicious": 3,
                                "harmless": 72, "undetected": 10,
                            },
                            "reputation": -75,
                            "tags": ["malware", "botnet"],
                            "last_analysis_date": 1718000000,
                        }
                    }
                },
            )
        )
        result = await enricher.enrich_ip(TEST_IP)
        assert result.malicious == 15
        assert result.suspicious == 3
        assert result.reputation == -75
        assert "malware" in result.tags
        assert result.error is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_enrich_ip_not_found(self, enricher):
        respx.get(f"https://www.virustotal.com/api/v3/ip_addresses/{TEST_IP}").mock(
            return_value=Response(404)
        )
        result = await enricher.enrich_ip(TEST_IP)
        assert result.error is not None
        assert result.malicious == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_enrich_domain(self, enricher):
        respx.get(f"https://www.virustotal.com/api/v3/domains/{TEST_DOMAIN}").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 8, "suspicious": 1,
                                "harmless": 80, "undetected": 5,
                            },
                            "reputation": -30,
                            "tags": ["phishing"],
                        }
                    }
                },
            )
        )
        result = await enricher.enrich_domain(TEST_DOMAIN)
        assert result.malicious == 8
        assert result.error is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_enrich_hash(self, enricher):
        respx.get(f"https://www.virustotal.com/api/v3/files/{TEST_HASH}").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 55, "suspicious": 5,
                                "harmless": 0, "undetected": 10,
                            },
                            "reputation": -100,
                            "tags": ["ransomware"],
                        }
                    }
                },
            )
        )
        result = await enricher.enrich_hash(TEST_HASH)
        assert result.malicious == 55
        assert "ransomware" in result.tags

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_returns_error(self, enricher):
        import httpx
        respx.get(f"https://www.virustotal.com/api/v3/ip_addresses/{TEST_IP}").mock(
            side_effect=httpx.TimeoutException("timeout")
        )
        result = await enricher.enrich_ip(TEST_IP)
        assert result.error is not None


# ── Shodan ─────────────────────────────────────────────────────────────────────

class TestShodanEnricher:
    @pytest.fixture
    def enricher(self):
        return ShodanEnricher(api_key="shodan-test-key", timeout=5)

    @respx.mock
    @pytest.mark.asyncio
    async def test_enrich_ip_with_vulns(self, enricher):
        respx.get(f"https://api.shodan.io/shodan/host/{TEST_IP}").mock(
            return_value=Response(
                200,
                json={
                    "ip_str": TEST_IP,
                    "org": "Frantech Solutions",
                    "country_code": "NL",
                    "city": "Amsterdam",
                    "isp": "Frantech Solutions",
                    "hostnames": ["c2.evil.example"],
                    "tags": ["vpn"],
                    "os": None,
                    "vulns": {"CVE-2021-44228": {}, "CVE-2022-0847": {}},
                    "data": [
                        {"port": 22},
                        {"port": 80},
                        {"port": 4444},
                    ],
                },
            )
        )
        result = await enricher.enrich_ip(TEST_IP)
        assert result.org == "Frantech Solutions"
        assert 4444 in result.open_ports
        assert "CVE-2021-44228" in result.vulns
        assert result.error is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_not_indexed(self, enricher):
        respx.get(f"https://api.shodan.io/shodan/host/{TEST_IP}").mock(
            return_value=Response(404, json={"error": "No information available for that IP."})
        )
        result = await enricher.enrich_ip(TEST_IP)
        assert result.error is not None
        assert result.open_ports == []


# ── AbuseIPDB ──────────────────────────────────────────────────────────────────

class TestAbuseIPDBEnricher:
    @pytest.fixture
    def enricher(self):
        return AbuseIPDBEnricher(api_key="abuse-test-key", timeout=5)

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_ip_high_confidence(self, enricher):
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "ipAddress": TEST_IP,
                        "abuseConfidenceScore": 95,
                        "countryCode": "RU",
                        "isp": "Frantech Solutions",
                        "domain": "frantech.ca",
                        "totalReports": 847,
                        "lastReportedAt": "2024-06-15T12:00:00+00:00",
                        "isTor": False,
                        "usageType": "Data Center/Web Hosting/Transit",
                    }
                },
            )
        )
        result = await enricher.enrich_ip(TEST_IP)
        assert result.abuse_confidence_score == 95
        assert result.total_reports == 847
        assert result.country_code == "RU"
        assert result.is_tor is False
        assert result.error is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_tor_flag(self, enricher):
        respx.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "ipAddress": TEST_IP,
                        "abuseConfidenceScore": 100,
                        "countryCode": "DE",
                        "isp": "Tor Project",
                        "domain": "torproject.org",
                        "totalReports": 1200,
                        "lastReportedAt": "2024-06-15T10:00:00+00:00",
                        "isTor": True,
                        "usageType": "Tor Exit Node",
                    }
                },
            )
        )
        result = await enricher.enrich_ip(TEST_IP)
        assert result.is_tor is True
        assert result.abuse_confidence_score == 100

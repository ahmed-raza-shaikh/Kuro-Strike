"""Output models for each threat-intelligence source and the combined result."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


# ── Per-source result models ────────────────────────────────────────────────────

class VirusTotalResult(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0          # -100 (bad) … 100 (good)
    tags: List[str] = []
    last_analysis_date: Optional[str] = None
    error: Optional[str] = None

    @property
    def total_engines(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected

    @property
    def is_clean(self) -> bool:
        return self.malicious == 0 and self.suspicious == 0


class ShodanResult(BaseModel):
    org: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    open_ports: List[int] = []
    vulns: List[str] = []        # CVE IDs
    hostnames: List[str] = []
    tags: List[str] = []
    os: Optional[str] = None
    error: Optional[str] = None


class AbuseIPDBResult(BaseModel):
    abuse_confidence_score: int = 0   # 0–100
    country_code: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    total_reports: int = 0
    last_reported_at: Optional[str] = None
    is_tor: bool = False
    usage_type: Optional[str] = None
    error: Optional[str] = None


# ── Composite per-IOC enrichments ──────────────────────────────────────────────

class IPEnrichment(BaseModel):
    ip: str
    virustotal: Optional[VirusTotalResult] = None
    shodan: Optional[ShodanResult] = None
    abuseipdb: Optional[AbuseIPDBResult] = None


class DomainEnrichment(BaseModel):
    domain: str
    virustotal: Optional[VirusTotalResult] = None


class HashEnrichment(BaseModel):
    file_hash: str
    virustotal: Optional[VirusTotalResult] = None


# ── Final enriched alert ────────────────────────────────────────────────────────

class EnrichedAlert(BaseModel):
    original_alert: Dict[str, Any]
    ip_enrichments: Dict[str, IPEnrichment] = {}
    domain_enrichments: Dict[str, DomainEnrichment] = {}
    hash_enrichments: Dict[str, HashEnrichment] = {}

    risk_score: int = 0           # 0–100
    risk_level: str = "LOW"       # LOW / MEDIUM / HIGH / CRITICAL
    triage_summary: str = ""

    enrichment_duration_ms: float = 0.0
    cached_results: int = 0
    fresh_results: int = 0

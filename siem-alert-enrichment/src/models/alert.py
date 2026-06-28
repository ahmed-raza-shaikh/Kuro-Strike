"""
Alert input models.

Supports two ingestion formats:
  1. Generic JSON POST to /enrich
  2. Splunk webhook format (POSTed by Splunk's built-in webhook alert action)
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_DOMAIN_KEYS = {"domain", "hostname", "fqdn", "dns", "host", "url", "site"}


def _normalize_domain(value: str) -> str | None:
    candidate = value.strip().lower()
    if not candidate:
        return None

    if "://" in candidate:
        candidate = urlparse(candidate).hostname or ""
    else:
        candidate = candidate.split("/", 1)[0]
        candidate = candidate.rsplit("@", 1)[-1]
        candidate = candidate.split(":", 1)[0]

    candidate = candidate.strip(".")
    if not candidate or _IP_RE.fullmatch(candidate):
        return None
    if not _DOMAIN_RE.fullmatch(candidate):
        return None
    return candidate


class IOCBundle(BaseModel):
    ips: List[str] = []
    domains: List[str] = []
    file_hashes: List[str] = []


class SplunkAlert(BaseModel):
    """Normalised alert envelope accepted by the /enrich endpoint."""

    alert_name: str = Field(..., description="Human-readable alert / detection name")
    search_name: Optional[str] = Field(None, description="Splunk saved-search name")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Explicit IOC hints (override auto-extraction when present)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    domain: Optional[str] = None
    file_hash: Optional[str] = None

    # Raw Splunk search result row(s)
    result: Dict[str, Any] = Field(default_factory=dict)
    # Any additional metadata
    extra: Dict[str, Any] = Field(default_factory=dict)

    def extract_iocs(self) -> IOCBundle:
        """
        Walk every string value in *result* and *extra* and collect public IPs,
        domains (from known key names), and file hashes (MD5 / SHA-1 / SHA-256).
        Explicit hint fields take priority.
        """
        ips: set[str] = set()
        domains: set[str] = set()
        hashes: set[str] = set()

        # ── 1. Explicit hints ────────────────────────────────────────────────
        for ip in (self.source_ip, self.destination_ip):
            if ip and _is_public_ip(ip):
                ips.add(ip)
        if self.domain:
            domain = _normalize_domain(self.domain)
            if domain:
                domains.add(domain)
        if self.file_hash and _HASH_RE.match(self.file_hash):
            hashes.add(self.file_hash.lower())

        # ── 2. Auto-extraction from result / extra ───────────────────────────
        all_fields = {**self.result, **self.extra}
        for key, value in all_fields.items():
            if not isinstance(value, str):
                continue
            k = key.lower()

            # IPs anywhere in value
            for ip in _IP_RE.findall(value):
                if _is_public_ip(ip):
                    ips.add(ip)

            # Domains via key name heuristic
            if k in _DOMAIN_KEYS and value and "." in value:
                domain = _normalize_domain(value)
                if domain:
                    domains.add(domain)

            # Hashes: exact full-value match
            stripped = value.strip()
            if _HASH_RE.match(stripped):
                hashes.add(stripped.lower())

        return IOCBundle(
            ips=list(ips),
            domains=list(domains),
            file_hashes=list(hashes),
        )


class SplunkWebhookPayload(BaseModel):
    """
    Splunk's native webhook alert action payload schema.
    Reference: https://docs.splunk.com/Documentation/Splunk/latest/Alert/Webhooks
    """

    sid: Optional[str] = None
    search_name: Optional[str] = None
    app: Optional[str] = None
    owner: Optional[str] = None
    results_link: Optional[str] = None
    result: Dict[str, Any] = Field(default_factory=dict)

    def to_splunk_alert(self) -> SplunkAlert:
        """Convert raw Splunk webhook payload → SplunkAlert."""
        result = self.result
        return SplunkAlert(
            alert_name=self.search_name or result.get("alert_name", "Unknown Alert"),
            search_name=self.search_name,
            source_ip=result.get("src_ip") or result.get("src") or result.get("source_ip"),
            destination_ip=result.get("dest_ip") or result.get("dest") or result.get("destination_ip"),
            domain=result.get("domain") or result.get("hostname"),
            file_hash=result.get("file_hash") or result.get("md5") or result.get("sha256"),
            result=result,
            extra={"sid": self.sid, "app": self.app, "owner": self.owner},
        )

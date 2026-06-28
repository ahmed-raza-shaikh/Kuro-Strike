#!/usr/bin/env python3
"""
Splunk Custom Alert Action — SIEM Alert Enrichment
===================================================
Deploy this script inside a Splunk Technology Add-On (TA) as a
custom alert action.  When a saved search fires, Splunk invokes this
script with alert metadata on stdin (JSON).

The script:
1. Reads the alert payload from stdin
2. POSTs it to the enrichment microservice
3. Writes the enriched result back to a Splunk KV-store collection
   (optional — configure KVSTORE_* vars below)

Installation
────────────
1. Copy this file to:
   $SPLUNK_HOME/etc/apps/<your_ta>/bin/enrich_alert.py
2. Create alert_actions.conf in your TA (see splunk/alert_actions.conf)
3. Set ENRICHMENT_SERVICE_URL to point at your running microservice.

Usage in Splunk UI
──────────────────
  Alerts → Alert Actions → SIEM Enrichment → Run Script
"""
from __future__ import annotations

import json
import logging
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime

# ── Configuration (override via environment) ───────────────────────────────────
ENRICHMENT_SERVICE_URL = os.environ.get(
    "ENRICHMENT_SERVICE_URL", "http://localhost:8000/webhook/splunk"
)
SPLUNK_WEBHOOK_TOKEN = os.environ.get("SPLUNK_WEBHOOK_TOKEN", "")
REQUEST_TIMEOUT = int(os.environ.get("ENRICHMENT_TIMEOUT", "15"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

logging.basicConfig(
    stream=sys.stderr,
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | enrich_alert | %(message)s",
)
logger = logging.getLogger("enrich_alert")


def read_alert_payload() -> dict:
    """Read alert metadata from stdin (Splunk passes it as JSON)."""
    raw = sys.stdin.read()
    if not raw.strip():
        raise ValueError("Empty stdin — no alert payload received")
    return json.loads(raw)


def post_to_enrichment_service(payload: dict) -> dict:
    """POST the raw Splunk payload to the enrichment microservice."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=ENRICHMENT_SERVICE_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            **({"X-Splunk-Token": SPLUNK_WEBHOOK_TOKEN} if SPLUNK_WEBHOOK_TOKEN else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Enrichment service returned HTTP {exc.code}: {body_text}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach enrichment service at {ENRICHMENT_SERVICE_URL}: {exc}") from exc


def write_enriched_alert(enriched: dict) -> None:
    """
    Write the enriched alert to stdout in Splunk's expected format.
    Splunk reads stdout lines and indexes them as events if the script
    is configured with output_mode = json in alert_actions.conf.
    """
    output = {
        "alert_name": enriched.get("original_alert", {}).get("alert_name", "unknown"),
        "risk_level": enriched.get("risk_level", "UNKNOWN"),
        "risk_score": enriched.get("risk_score", 0),
        "triage_summary": enriched.get("triage_summary", ""),
        "enrichment_duration_ms": enriched.get("enrichment_duration_ms", 0),
        "enriched_at": datetime.utcnow().isoformat() + "Z",
    }
    # IP enrichment details (flatten top-level)
    for ip, data in enriched.get("ip_enrichments", {}).items():
        safe_ip = ip.replace(".", "_")
        vt = data.get("virustotal") or {}
        ab = data.get("abuseipdb") or {}
        sh = data.get("shodan") or {}
        output[f"ip_{safe_ip}_vt_malicious"] = vt.get("malicious", 0)
        output[f"ip_{safe_ip}_abuse_score"] = ab.get("abuse_confidence_score", 0)
        output[f"ip_{safe_ip}_open_ports"] = ",".join(map(str, sh.get("open_ports", [])))
        output[f"ip_{safe_ip}_cves"] = ",".join(sh.get("vulns", []))

    print(json.dumps(output))


def main() -> int:
    try:
        payload = read_alert_payload()
        logger.info("Received alert: %s", payload.get("search_name", "?"))
        enriched = post_to_enrichment_service(payload)
        write_enriched_alert(enriched)
        logger.info(
            "Enrichment complete — risk=%s score=%s duration=%.1f ms",
            enriched.get("risk_level"),
            enriched.get("risk_score"),
            enriched.get("enrichment_duration_ms", 0),
        )
        return 0
    except Exception as exc:
        logger.error("Alert enrichment failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

# Splunk Integration Guide

## Overview

Two integration methods are supported. Choose the one that fits your Splunk setup.

---

## Method 1: Built-in Webhook (Recommended — zero Splunk-side code)

Splunk's built-in **Webhook** alert action requires no custom TA. It sends a
JSON POST to any URL when an alert fires.

### Steps

1. Start the enrichment microservice (see root README).
2. In Splunk Web, open a saved search → **Edit** → **Alert Actions**.
3. Click **Add Actions → Webhook**.
4. Set the URL to:

   ```
   http://<enrichment-host>:8000/webhook/splunk
   ```

5. *(Optional)* Set the `X-Splunk-Token` header to match `SPLUNK_WEBHOOK_TOKEN`
   in your `.env`.

The service will enrich the alert and return the result. To surface the
enrichment output in Splunk, configure your saved search to index the response
via a scripted input or use the KV Store approach below.

---

## Method 2: Custom Alert Action Script

Use `alert_action.py` when you need Splunk to automatically index enriched
events or write to a KV Store collection.

### Deployment

```
$SPLUNK_HOME/
└── etc/
    └── apps/
        └── ta-siem-enrichment/
            ├── default/
            │   └── alert_actions.conf
            └── bin/
                └── enrich_alert.py      ← copy from splunk/alert_action.py
```

### alert_actions.conf

```ini
[enrich_alert]
label = SIEM Enrichment
description = Enrich alert IOCs with VirusTotal, Shodan, and AbuseIPDB
icon_path = alert_loupe.png
is_custom = 1
payload_format = json

param.enrichment_service_url = http://localhost:8000/webhook/splunk
param.timeout = 15
```

### Environment variables for the script

| Variable | Default | Description |
|---|---|---|
| `ENRICHMENT_SERVICE_URL` | `http://localhost:8000/webhook/splunk` | Enrichment service URL |
| `SPLUNK_WEBHOOK_TOKEN` | *(empty)* | Optional auth token |
| `ENRICHMENT_TIMEOUT` | `15` | Request timeout in seconds |

---

## Field mapping (Splunk → Service)

The service auto-detects IOCs from any of these common Splunk field names:

| Splunk field | Detected as |
|---|---|
| `src_ip`, `src`, `source_ip` | Source IP |
| `dest_ip`, `dest`, `destination_ip` | Destination IP |
| `domain`, `hostname`, `fqdn`, `host` | Domain |
| `file_hash`, `md5`, `sha256`, `sha1` | File hash |

Any field value that matches an IP pattern, domain key, or hash pattern is
also auto-extracted from the raw `result` dict.

---

## Output fields written back to Splunk

| Field | Description |
|---|---|
| `risk_level` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `risk_score` | 0–100 composite score |
| `triage_summary` | Human-readable summary for analysts |
| `ip_<addr>_vt_malicious` | VirusTotal malicious engine count |
| `ip_<addr>_abuse_score` | AbuseIPDB confidence score (0–100) |
| `ip_<addr>_open_ports` | Comma-separated open port list |
| `ip_<addr>_cves` | Comma-separated CVE IDs from Shodan |
| `enrichment_duration_ms` | End-to-end enrichment latency |

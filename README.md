<div align="center">

<img src="assets/banner.svg" alt="Kuro-Strike — SIEM Alert Enrichment Microservice for Splunk" width="100%" />

<br/>

<a href="https://opensource.org/license/mit/"><img src="https://img.shields.io/github/license/ahmed-raza-shaikh/Kuro-Strike?style=flat-square&color=65A637&label=license" alt="License"></a>
<a href="#"><img src="https://img.shields.io/badge/python-3.12%2B-65A637?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+"></a>
<a href="#"><img src="https://img.shields.io/badge/FastAPI-async-65A637?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI"></a>
<a href="#"><img src="https://img.shields.io/badge/Redis-cache-65A637?style=flat-square&logo=redis&logoColor=white" alt="Redis"></a>
<a href="#"><img src="https://img.shields.io/badge/Docker-ready-65A637?style=flat-square&logo=docker&logoColor=white" alt="Docker ready"></a>
<a href="#"><img src="https://img.shields.io/badge/tests-27%20passing-65A637?style=flat-square&logo=pytest&logoColor=white" alt="Tests passing"></a>
<a href="#"><img src="https://img.shields.io/badge/lint-ruff-65A637?style=flat-square" alt="Linted with ruff"></a>
<a href="#"><img src="https://img.shields.io/badge/Splunk-compatible-65A637?style=flat-square&logo=splunk&logoColor=white" alt="Splunk compatible"></a>
<a href="https://github.com/ahmed-raza-shaikh/Kuro-Strike/stargazers"><img src="https://img.shields.io/github/stars/ahmed-raza-shaikh/Kuro-Strike?style=flat-square&color=65A637" alt="GitHub stars"></a>

**A production-ready Python microservice that enriches Splunk security alerts in real time —**
**VirusTotal + Shodan + AbuseIPDB threat intelligence, one API call, sub-second triage.**

[Quick Start](#quick-start) · [API Reference](#api-reference) · [Splunk Integration](#splunk-integration) · [Roadmap](#roadmap--whats-next) · [Contributing](#contributing)

</div>

<br/>

## Why Kuro-Strike

Every SOC analyst knows the drill: an alert fires, and now you're tab-switching between VirusTotal, Shodan, and AbuseIPDB, copy-pasting IPs and hashes, and stitching the answer together by hand. That's 5–8 minutes of manual **IOC enrichment** per alert, multiplied by every alert in the queue.

**Kuro-Strike** is a self-hosted **SIEM alert enrichment** microservice purpose-built for **Splunk**. Drop it in front of your alert pipeline and it automatically extracts IOCs (IPs, domains, file hashes), queries three threat-intelligence sources concurrently, computes a weighted **0–100 risk score**, and hands your analysts a human-readable triage summary — all in under a second for cached IOCs, and typically under two for cold ones.

- 🔻 **~8 min → <90 sec** mean triage time per alert
- ⚡ **Concurrent, not sequential** — `asyncio.gather()` across all three TI sources, so total latency ≈ the slowest source, not the sum of all three
- 🧠 **Composite risk scoring** — a transparent, tunable weighted algorithm, not a black box
- 🔌 **Drop-in Splunk integration** — native webhook receiver *and* a custom alert action script
- 🐳 **One command to run** — `docker compose up` and you have a service + Redis cache

If you run a Splunk-based SOC and are tired of manual IOC lookups eating analyst time, this is built for you.

<br/>

## Live Data Flow

<div align="center">
<img src="assets/flow-diagram.svg" alt="Animated enrichment pipeline: Splunk alert flows into EnrichmentService, fans out concurrently to VirusTotal, Shodan and AbuseIPDB, then converges into a risk score cached in Redis" width="100%" />
</div>

<br/>

## Features

| | |
|---|---|
| **Concurrent enrichment** | All three sources queried in parallel per IOC via `asyncio.gather()` — latency ≈ `max(source)`, not `sum(sources)` |
| **Redis caching** | Repeat IOCs served from cache in **< 5 ms**; protects your free-tier API quotas from repeat burn |
| **Auto IOC extraction** | Parses public IPs, domains, and MD5 / SHA-1 / SHA-256 hashes from *any* Splunk result field |
| **Composite risk scoring** | Weighted 0–100 algorithm combining VT engine count, AbuseIPDB confidence, Shodan CVEs and suspicious open ports |
| **Human-readable triage summary** | Instantly actionable text summary with country, ISP, CVEs, and detection counts — pastes straight into a ticket |
| **Dual Splunk integration** | Native webhook receiver *and* a custom alert action script for KV Store / index-time enrichment |
| **Docker-ready** | Single `docker compose up` starts the service + Redis, healthchecked and running as non-root |
| **Fully typed & tested** | pydantic v2 models end-to-end, 27 passing tests, `ruff`-linted, mocked TI responses via `respx` |

<br/>

## Risk Scoring

<div align="center">
<img src="assets/risk-gauge.svg" alt="Animated risk gauge sweeping from 0 to a critical score of 88 out of 100" width="520" />
</div>

| Source | Signal | Points |
|---|---|---|
| VirusTotal | Malicious engine count | `count × 4` (max 30) |
| VirusTotal | Suspicious engine count | `count × 1` (max 5) |
| VirusTotal | Low reputation (< -50) | +5 |
| AbuseIPDB | Abuse confidence score | `score × 0.5` (max 50) |
| AbuseIPDB | TOR exit node | +10 |
| AbuseIPDB | > 500 reports | +5 |
| Shodan | Known CVEs | `count × 8` (max 20) |
| Shodan | Suspicious open ports | `count × 2` |
| VirusTotal (hash) | Malicious engine count | `count × 6` (max 80) |

| Risk Level | Score |
|---|---|
| 🟢 LOW | 0 – 24 |
| 🟡 MEDIUM | 25 – 49 |
| 🟠 HIGH | 50 – 74 |
| 🔴 CRITICAL | 75 – 100 |

## Quick Start

### 1. Get API Keys

| Service | Free tier | Sign up |
|---|---|---|
| VirusTotal | 4 req/min | https://www.virustotal.com/gui/join-us |
| Shodan | 100 query credits | https://account.shodan.io/register |
| AbuseIPDB | 1 000 checks/day | https://www.abuseipdb.com/register |

### 2. Configure

```bash
cp .env.example .env
# Edit .env — fill in your three API keys
```

### 3. Run

```bash
# Docker (recommended)
make docker-up

# Local (requires Python 3.12+ and Redis)
make install
make dev
```

Service listens on **http://localhost:8000** — interactive Swagger docs at **`/docs`**.

<br/>

## API Reference

### `POST /enrich`

Accepts a normalised `SplunkAlert` body and returns an `EnrichedAlert`.

```bash
curl -X POST http://localhost:8000/enrich \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "Suspicious Outbound C2 Traffic",
    "source_ip": "185.220.101.45",
    "destination_ip": "104.21.14.88",
    "domain": "malware-c2.xyz",
    "file_hash": "44d88612fea8a8f36de82e1278abb02f",
    "result": {
      "dest_port": "4444",
      "process": "powershell.exe"
    }
  }'
```

<details>
<summary><strong>Response</strong></summary>

```json
{
  "risk_level": "CRITICAL",
  "risk_score": 88,
  "triage_summary": "🔴 CRITICAL RISK  |  Score: 88/100\nAlert : Suspicious Outbound C2 Traffic\n\n■ IP: 185.220.101.45\n  VirusTotal  : 23/90 engines flagged  [⚠ MALICIOUS]\n  AbuseIPDB   : 95% confidence | 847 reports | RU\n  ISP         : Frantech Solutions\n  Shodan ports: [22, 80, 443, 4444]\n  CVEs        : CVE-2021-44228, CVE-2022-0847\n  Org         : AS-CHOOPA  (Amsterdam NL)\n\n■ Domain: malware-c2.xyz\n  VirusTotal  : 8/90 engines  [⚠ MALICIOUS]\n\n■ Hash: 44d88612fea8a8f...\n  VirusTotal  : 55/70 engines  [⚠ MALICIOUS]",
  "enrichment_duration_ms": 1247.3,
  "ip_enrichments": { "...": "..." },
  "domain_enrichments": { "...": "..." },
  "hash_enrichments": { "...": "..." }
}
```

</details>

### `POST /webhook/splunk`

Drop-in Splunk webhook receiver — accepts Splunk's native alert payload format.

Configure in Splunk: **Alert Actions → Webhook → URL: `http://<host>:8000/webhook/splunk`**

### `GET /health`

```json
{ "status": "ok", "redis": "connected" }
```

### `DELETE /cache`

Flushes the Redis enrichment cache (admin/debug use).

<br/>

## Splunk Integration

Two integration paths, pick what fits your environment — full walkthrough in [`splunk/README.md`](siem-alert-enrichment/splunk/README.md):

- **Built-in Webhook** *(recommended, zero Splunk-side code)* — point a saved search's Webhook alert action at `/webhook/splunk`.
- **Custom Alert Action** — deploy [`alert_action.py`](siem-alert-enrichment/splunk/alert_action.py) as a TA for index-time enrichment and KV Store writes.

The service auto-detects IOCs from common Splunk field names (`src_ip`, `dest_ip`, `domain`, `file_hash`, `md5`, `sha256`, …) and writes enrichment results back as flat fields your dashboards and correlation searches can consume directly.

<br/>

## Roadmap — What's Next

Kuro-Strike already closes the loop from *alert → enrichment → risk score*. Here's what would take it from "great enrichment API" to "the tool every Splunk SOC installs first" — contributions and ideas welcome:

| Area | Idea | Why it matters |
|---|---|---|
| 📦 **Splunkbase App** | Package as an installable Splunk App (custom command + prebuilt dashboards) | Zero-webhook install — run `enrichalert` straight from SPL |
| 🗺️ **MITRE ATT&CK mapping** | Auto-tag enriched alerts with ATT&CK tactic/technique IDs | Feeds directly into ATT&CK-based detection coverage dashboards |
| 🧩 **Pluggable TI feeds** | Source-agnostic enricher interface for MISP, OTX, STIX/TAXII, GreyNoise | Not every team can afford VT/Shodan/AbuseIPDB paid tiers |
| 🔁 **SOAR playbook connectors** | Native actions for Splunk SOAR (Phantom) and Cortex XSOAR | Enrichment becomes one node in an existing automated response chain |
| 🧵 **Alert correlation & de-dup** | Group related alerts sharing IOCs into a single incident | Cuts analyst noise instead of just enriching each alert in isolation |
| 🤖 **ML-tuned risk model** | Replace static weights with a model trained on analyst verdicts | Scoring improves the more your SOC uses it |
| 📣 **Notification connectors** | Slack / Teams / PagerDuty push for HIGH+ CRITICAL alerts | Gets eyes on the worst alerts without polling a dashboard |
| 📊 **Prebuilt Splunk dashboards** | Enrichment volume, cache hit rate, API quota burn, MTTT trend | Makes the tool's own ROI visible to the SOC lead |
| 🕵️ **Case management hooks** | TheHive / Jira Service Management ticket creation | Enrichment output lands where the analyst already works |
| 📈 **Observability** | Prometheus metrics + OpenTelemetry tracing | Production-grade visibility for teams running this at scale |
| ☸️ **Helm chart / Terraform module** | One-command production deploy to Kubernetes | Removes the "how do we actually run this" barrier to adoption |
| 🌐 **Offline fallback enrichment** | Local GeoIP/ASN databases when TI APIs are rate-limited | Degrades gracefully instead of failing when quotas are burned |

Have an idea that isn't listed? [Open an issue](https://github.com/ahmed-raza-shaikh/Kuro-Strike/issues/new) — roadmap PRs are very welcome.

<br/>

## Project Structure

```
siem-alert-enrichment/
├── src/
│   ├── main.py                  # FastAPI app factory
│   ├── config.py                # pydantic-settings config
│   ├── models/
│   │   ├── alert.py             # SplunkAlert, IOCBundle, SplunkWebhookPayload
│   │   └── enrichment.py        # VirusTotalResult, ShodanResult, AbuseIPDBResult, EnrichedAlert
│   ├── enrichers/
│   │   ├── base.py              # Abstract base enricher
│   │   ├── virustotal.py        # VT API v3 (IPs, domains, hashes)
│   │   ├── shodan.py            # Shodan host lookup
│   │   └── abuseipdb.py         # AbuseIPDB check endpoint
│   ├── services/
│   │   ├── enrichment_service.py # Orchestration, scoring, triage summary
│   │   └── cache_service.py      # Redis async cache
│   └── api/
│       └── routes.py            # FastAPI routes
├── tests/
│   ├── conftest.py              # Shared fixtures & mocks
│   ├── test_enrichers.py        # Enricher unit tests (respx mocks)
│   ├── test_api.py              # API & service integration tests
│   └── fixtures/
│       └── sample_alert.json    # Sample Splunk alert payload
├── splunk/
│   ├── alert_action.py          # Splunk custom alert action script
│   └── README.md                # Splunk integration guide
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── requirements.txt
└── .env.example
```

## Development

```bash
make test      # pytest with coverage report
make lint      # ruff linter
make docker-up # full stack
```


## Security and Privacy

- Store VirusTotal, Shodan, AbuseIPDB, and optional Splunk webhook credentials only in environment variables or a managed secret store—never commit them.
- Treat alert payloads and enrichment results as security-sensitive operational data; deploy with appropriate access controls, logging retention, and TLS termination.
- API rate limits and third-party threat-intelligence coverage can affect enrichment completeness; validate findings through your incident-response process.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | — | **Required** |
| `SHODAN_API_KEY` | — | **Required** |
| `ABUSEIPDB_API_KEY` | — | **Required** |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `CACHE_TTL_SECONDS` | `3600` | IOC cache lifetime |
| `ENRICHMENT_TIMEOUT_SECONDS` | `10` | Per-source request timeout |
| `SPLUNK_WEBHOOK_TOKEN` | *(empty)* | Optional webhook auth token |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` |

## Tech Stack

- **FastAPI** — async REST framework
- **httpx** — async HTTP client for all three TI APIs
- **redis[asyncio]** — async Redis client for caching
- **pydantic v2** — data validation and serialisation
- **pytest + respx** — unit and integration testing

## License

This project is released under the [MIT License](LICENSE).

Copyright (c) 2026 Ahmed Raza Shaikh.

For the canonical license terms, see the [Open Source Initiative MIT License](https://opensource.org/license/mit/).

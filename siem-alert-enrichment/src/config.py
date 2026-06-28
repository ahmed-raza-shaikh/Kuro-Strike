from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Threat Intelligence API Keys ────────────────────────────────────────
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    abuseipdb_api_key: str = ""

    # ── Redis Cache ─────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    cache_ttl_seconds: int = 3600  # 1 hour

    # ── Service ─────────────────────────────────────────────────────────────
    service_host: str = "0.0.0.0"
    service_port: int = 8000
    log_level: str = "INFO"
    debug: bool = False

    # ── Security ────────────────────────────────────────────────────────────
    splunk_webhook_token: Optional[str] = None

    # ── Enrichment Tuning ───────────────────────────────────────────────────
    enrichment_timeout_seconds: int = 10
    max_concurrent_enrichments: int = 10

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache()
def get_settings() -> Settings:
    return Settings()

"""
SIEM Alert Enrichment Microservice
===================================
FastAPI application factory.  Run with:

    uvicorn src.main:app --reload
"""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router
from .config import get_settings


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks."""
    settings = get_settings()
    _configure_logging(settings.log_level)
    logger = logging.getLogger(__name__)
    logger.info("Starting SIEM Alert Enrichment Service on :%d", settings.service_port)
    yield
    logger.info("Shutting down")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="SIEM Alert Enrichment Microservice",
        description=(
            "Enriches Splunk alerts in real time using VirusTotal, Shodan, "
            "and AbuseIPDB threat intelligence, reducing mean analyst triage "
            "time from ~8 minutes to under 90 seconds."
        ),
        version="1.0.0",
        lifespan=lifespan,
        debug=settings.debug,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


app = create_app()

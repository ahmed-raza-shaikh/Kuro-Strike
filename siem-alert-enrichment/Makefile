.PHONY: help install dev test lint docker-up docker-down clean

help:
	@echo "SIEM Alert Enrichment Microservice"
	@echo ""
	@echo "Usage:"
	@echo "  make install     Install Python dependencies"
	@echo "  make dev         Run service locally (requires Redis)"
	@echo "  make test        Run test suite with coverage"
	@echo "  make lint        Run ruff linter"
	@echo "  make docker-up   Start full stack via Docker Compose"
	@echo "  make docker-down Stop Docker Compose stack"
	@echo "  make clean       Remove cache/build artifacts"

install:
	pip install -r requirements.txt

dev:
	uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html

lint:
	ruff check src/ tests/

docker-up:
	docker compose up --build -d
	@echo "Service running at http://localhost:8000"
	@echo "Docs at         http://localhost:8000/docs"

docker-down:
	docker compose down

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache htmlcov .coverage

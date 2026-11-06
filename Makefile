.PHONY: install migrate dev-api dev-web test lint docker-up docker-down

# Install Python and web dependencies
install:
	pip install -e ".[dev]"
	cd apps/web && npm install

# Run database migrations
migrate:
	alembic upgrade head

# Start the platform API in development mode
dev-api:
	uvicorn ascense.api.main:app --reload --port 8000

# Start the web dashboard in development mode
dev-web:
	cd apps/web && npm run dev

# Run the test suite
test:
	pytest
	cd apps/web && npm test

# Lint Python and TypeScript
lint:
	ruff check .
	mypy platform
	cd apps/web && npm run lint

# Start local development stack via docker compose
docker-up:
	docker compose -f infrastructure/compose/docker-compose.yml up -d

# Stop local development stack
docker-down:
	docker compose -f infrastructure/compose/docker-compose.yml down

# Apply PostgreSQL RLS policies (run once after migrate)
apply-rls:
	psql "$$DATABASE_URL" -f database/policies/rls.sql

# Run all background workers (detection + correlation + normalization)
dev-workers:
	python -m ascense.workers.detection &
	python -m ascense.workers.correlation &
	python -m ascense.workers.ingestion

# Run the gateway simulator (requires running API + seed data)
# Usage: make simulate TENANT_ID=<uuid> GATEWAY_ID=<uuid> RATE=5
simulate:
	python -m ascense.simulators.gateway_simulator \
		--api-url http://localhost:8000 \
		--tenant-id $(TENANT_ID) \
		--gateway-id $(GATEWAY_ID) \
		--rate $(or $(RATE),5)

# Seed the database with test data
seed:
	python -m database.seeds.seed_dev

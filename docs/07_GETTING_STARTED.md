# Ascense — Getting Started

> Local development setup from zero to a running pipeline.

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.11 or 3.12 | 3.12 preferred; 3.11 works via `conftest.py` shim |
| Node.js | 20+ | For the dashboard |
| Docker Desktop | latest | PostgreSQL, RabbitMQ, Redis, MinIO, Jaeger |
| Git | any | |

---

## Step 1 — Install dependencies

```cmd
:: Python
pip install -e ".[dev]"

:: Frontend
cd apps\web
npm install
cd ..\..
```

---

## Step 2 — Environment file

```cmd
copy .env.example .env
```

Default values work out of the box for local development. No changes needed unless you are pointing at a remote database or broker.

---

## Step 3 — Start infrastructure

```cmd
docker compose -f infrastructure/compose/docker-compose.yml up -d
```

Wait about 15 seconds, then verify:

```cmd
docker compose -f infrastructure/compose/docker-compose.yml ps
```

All five services should show `healthy` or `running`:

| Service | Port | Purpose |
|---------|------|---------|
| PostgreSQL | 5432 | Primary database |
| RabbitMQ | 5672 / 15672 | Message broker (management UI on 15672) |
| Redis | 6379 | Cache |
| MinIO | 9000 / 9001 | Object storage (console on 9001) |
| Jaeger | 16686 / 4318 | Distributed tracing |

---

## Step 4 — Database setup

```cmd
:: Run all three migrations
alembic upgrade head

:: Apply Row-Level Security policies (run once after migrate)
psql "postgresql://ascense:ascense_dev_password@localhost:5432/ascense" -f database/policies/rls.sql

:: Create test data: tenant, user, gateway, three assets
python -m database.seeds.seed_dev
```

The seed script prints three IDs — copy them:

```
Seed data created:
  Tenant ID:  019xxxxx-...
  User ID:    019xxxxx-...
  Gateway ID: 019xxxxx-...
  Use X-Tenant-ID header: 019xxxxx-...
  Use X-User-ID header:   019xxxxx-...
```

---

## Step 5 — Start the API

```cmd
uvicorn ascense.api.main:app --reload --port 8000
```

The API starts all background workers automatically (normalization, detection, correlation, lease expiry, investigation). To run workers as separate processes instead, set `ASCENSE_RUN_WORKERS=false` in `.env`.

- API base: `http://localhost:8000`
- Interactive docs: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

---

## Step 6 — Start the dashboard

Open a **second terminal**:

```cmd
cd apps\web
npm run dev
```

Dashboard: `http://localhost:5173`

---

## Step 7 — Configure dashboard identity

The dashboard reads tenant and user context from `localStorage`. Open the browser console on `http://localhost:5173` and run:

```js
localStorage.setItem("ascense_tenant_id", "PASTE_TENANT_ID_HERE")
localStorage.setItem("ascense_user_id",   "PASTE_USER_ID_HERE")
```

Reload the page. All API calls will now include the correct `X-Tenant-ID` and `X-User-ID` headers.

---

## Step 8 — Run the tests

```cmd
:: Unit + contract + security (no Docker needed, ~4 seconds)
python -m pytest tests/unit/ tests/contract/ tests/security/ -v

:: Integration tests (requires live database from steps 3–4)
python -m pytest tests/integration/ -v

:: Everything except integration
python -m pytest tests/ --ignore=tests/integration/ -v
```

---

## Step 9 — Run the gateway simulator

Open a **third terminal**. The simulator sends authenticated event batches and heartbeats without physical hardware:

```cmd
python -m ascense.simulators.gateway_simulator ^
  --api-url http://localhost:8000 ^
  --tenant-id PASTE_TENANT_ID_HERE ^
  --gateway-id PASTE_GATEWAY_ID_HERE ^
  --rate 5 ^
  --duration 120
```

This runs for 2 minutes at 5 events/second. About 20% of traffic targets known-bad IP ranges (`198.51.100.x`, `203.0.113.x`) — those will trigger the `SuspiciousOutboundConnectionRule` and flow through the full detection pipeline.

After the simulator stops, the gateway will transition to `TELEMETRY_STALE` within 2 minutes (the background job checks every 30 seconds).

---

## Step 10 — Watch the pipeline

| Dashboard page | What to look for |
|----------------|-----------------|
| **Events** | Network connection records arriving in real time |
| **Alerts** | Alerts auto-created by the detection worker |
| **Incidents** | Incidents auto-grouped by the correlation worker |
| **Gateways** | Gateway status; expand to see sensor health; goes `TELEMETRY_STALE` when simulator stops |
| **Assets** | Three seeded assets (web-server-01, db-server-01, workstation-01) |
| **Proposals** | Where you approve/reject response actions |
| **Audit Log** | Append-only record of every security-relevant operation |

External UIs:

| Tool | URL | Credentials |
|------|-----|-------------|
| API docs | `http://localhost:8000/docs` | — |
| RabbitMQ management | `http://localhost:15672` | ascense / ascense_dev_password |
| MinIO console | `http://localhost:9001` | ascense / ascense_dev_password |
| Jaeger traces | `http://localhost:16686` | — |

---

## Running workers separately (optional)

If `ASCENSE_RUN_WORKERS=false` in `.env`, start each worker in its own terminal:

```cmd
:: Terminal A
python -m ascense.workers.ingestion

:: Terminal B
python -m ascense.workers.detection

:: Terminal C
python -m ascense.workers.correlation
```

---

## Makefile shortcuts

```cmd
make docker-up      :: Start infrastructure
make docker-down    :: Stop infrastructure
make migrate        :: Run alembic upgrade head
make apply-rls      :: Apply RLS policies to database
make seed           :: Run seed_dev.py
make dev-api        :: Start API with --reload
make dev-web        :: Start Vite dev server
make dev-workers    :: Start all workers as background processes
make test           :: Run all tests
make lint           :: Ruff + mypy + eslint

:: Simulator (requires TENANT_ID and GATEWAY_ID)
make simulate TENANT_ID=019xxx... GATEWAY_ID=019xxx... RATE=5
```

---

## Reset everything

```cmd
:: Stop containers and wipe all data volumes
docker compose -f infrastructure/compose/docker-compose.yml down -v

:: Re-run from Step 3
```

---

## Troubleshooting

**`uuid7` import error on Python 3.11**
The `conftest.py` at the project root provides a compatibility shim. Make sure pytest is run from the project root, not a subdirectory.

**`application/problem+json` responses instead of JSON**
The API returns RFC 9457 Problem Details on errors. Check the `detail` field for the human-readable message and `error_code` for the machine-readable code.

**Dashboard shows errors after page load**
The `localStorage` identity has not been set. Run the Step 7 commands in the browser console.

**Gateway stays `ENROLLMENT_PENDING`**
The seed script creates a gateway in `ACTIVE` state directly. If you created a gateway manually via the enrollment token flow, complete the enrollment:

```cmd
:: POST /edge/v1/gateways/enrollment with your token
curl -X POST http://localhost:8000/edge/v1/gateways/enrollment ^
  -H "Content-Type: application/json" ^
  -d "{\"token\": \"TOKEN\", \"gateway_id\": \"GATEWAY_ID\"}"
```

**RabbitMQ connection refused**
The API connects to RabbitMQ at startup. If RabbitMQ is not yet healthy, the API will fail to start. Wait for the container health check to pass, then restart the API.

**Events ingested but no alerts appear**
Workers may not be running. Check the API logs for `detection_worker.consuming` and `correlation_worker.consuming`. If missing, ensure `ASCENSE_RUN_WORKERS=true` in `.env`.

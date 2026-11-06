# Ascense — Project TODO

> Build order follows the stage sequence from `04_DEVELOPMENT_WORKFLOW.md`.
> Complete each stage's exit condition before moving to the next.
> Tier 2 and Tier 3 items are listed at the bottom — do not start them until the relevant gate is passed.
>
> **Legend:** ✅ done · 🔧 stub/partial · ⬜ not started

---

## Stage 0 · Product and Architecture Alignment
> Exit: every developer can explain the same end-to-end event-to-response workflow without contradiction.

- [x] Product scope and first-release boundaries written down
- [x] Gateway deployment model confirmed: out-of-band monitoring, allowlisted response adapters (ADR-001 in `docs/adr/`)
- [x] User roles and permission model defined
- [x] Trust boundaries and threat model documented
- [x] Component architecture and four-plane model agreed
- [x] System terminology and glossary written
- [x] Technology decisions recorded as ADRs (`docs/adr/ADR-001` through `ADR-004`)
- [x] Confirm RabbitMQ as message broker (transactional outbox pattern)
- [x] Confirm UUIDv7 (no prefix) as internal identifier standard
- [x] Confirm CloudEvents 1.0 as event envelope

---

## Stage 0.5 · Feasibility and Discovery
> Run before freezing contracts. Small isolated prototypes only.

- [ ] Suricata EVE JSON output format confirmed for ingestion
- [ ] Approximate events/second and batch size estimated from lab
- [ ] Gateway CPU/memory/disk buffer requirements estimated
- [ ] Outbound mTLS connectivity confirmed in target deployment environment
- [ ] Target firewall adapter identified (pfSense/OPNsense default)
- [ ] Firewall adapter API tested with a restricted test command in lab

---

## Stage 1 · Contracts (Incremental Baselines)
> Exit: contract tests exist and can run against mock implementations.

### Baseline A — Gateway and ingestion ✅
- [x] Identifier registry (`contracts/common/identifiers.yaml`)
- [x] Tenant and gateway identity model
- [x] Gateway registration schema (`contracts/gateway/gateway-registration-v1.json`)
- [x] Gateway heartbeat schema (`contracts/gateway/gateway-heartbeat-v1.json`)
- [x] Sensor status schema (`contracts/gateway/sensor-status-v1.json`)
- [x] Canonical network event schema with sensor-level source URN and asset resolution fields (`contracts/events/network-connection-v1.json`)
- [x] Event batch ingestion contract and response format (`contracts/events/event-batch-v1.json`)
- [x] Telemetry health schema (`contracts/common/telemetry-health-v1.json`)
- [x] Error codes, pagination, timestamp, and retry conventions (`contracts/common/errors.yaml`)
- [x] OpenAPI definitions for `/edge/v1/` and core `/api/v1/` endpoints
- [x] Minimal asset reference schema

### Baseline B — Detection and alerting ✅
- [x] Detection finding schema (`contracts/events/detection-finding-v1.json`)
- [x] Alert schema (`contracts/events/alert-v1.json`)
- [x] Incident schema (`contracts/events/incident-v1.json`)
- [x] Complete asset schema with criticality, ownership, lifecycle (`contracts/assets/asset-v1.json`)
- [x] Network indicator schema (`contracts/assets/network-indicator-v1.json`)
- [x] Evidence schema (`contracts/evidence/evidence-v1.json`)
- [x] Alert and incident state machine enums (`contracts/common/enums.yaml`)
- [x] OpenAPI definitions for alerts, incidents, assets, evidence
- [x] Execution journal schema (gateway-side)

### Baseline C — Investigation ✅
- [x] Investigation result schema (`contracts/investigation/investigation-result-v1.json`)
- [x] Evidence reference format
- [x] Action proposal schema with typed target (`contracts/response/action-proposal-v1.json`)

### Baseline D — Response ✅
- [x] Policy evaluation schema (`contracts/response/policy-evaluation-v1.json`)
- [x] Approval schema (`contracts/response/approval-v1.json`)
- [x] Signed command schema (`contracts/response/action-command-v1.json`)
- [x] Execution result schema (`contracts/response/execution-result-v1.json`)
- [x] Audit event schema (`contracts/common/audit-event-v1.json`)
- [x] Four response state machines: proposal, approval, command lifecycle, execution attempt status and verification status as separate fields
- [x] Command leasing and delivery semantics documented
- [x] Internal API definitions (`contracts/openapi/internal-api-v1.yaml`)

---

## Stage 2 · Platform Foundation
> Exit: user can authenticate, gateway can enroll, one tenant cannot access another tenant's resources — all verified by automated tests.

### Repository and infrastructure ✅
- [x] Repository structure created (matches `04_DEVELOPMENT_WORKFLOW.md` layout)
- [x] `infrastructure/compose/docker-compose.yml` with PostgreSQL, RabbitMQ, Redis, MinIO, Jaeger
- [x] `Makefile` targets working: `docker-up`, `docker-down`, `migrate`, `dev-api`, `dev-web`
- [x] `.env.example` with all required environment variables
- [x] CI pipeline configured (`ci.yml`) with contract tests, lint, and frontend build on every PR

### Database ✅
- [x] Alembic migration setup (`alembic.ini`, `database/migrations/env.py`)
- [x] `tenants` table
- [x] `users` table with internal `user_id` ↔ external IdP mapping (`issuer`, `subject` columns)
- [x] `memberships` table (user ↔ tenant ↔ role)
- [x] `gateways` table
- [x] `gateway_certificates` table
- [x] `assets` table with `tenant_id`, criticality, lifecycle
- [x] `outbox` table for transactional outbox pattern (migration `0002_outbox_and_audit.py`)
- [x] Tenant-scoped indexes on all major tables
- [x] Row-level security policies written (`database/policies/rls.sql`) — apply with `make apply-rls`
- [ ] RLS policies applied to database (run `make apply-rls` after migration)

### Platform API — foundation ✅
- [x] FastAPI app skeleton (`ascense/api/main.py`) with lifespan, middleware, routers
- [x] Tenant context middleware — production tenant selection is checked against authenticated membership; development header bypass remains dev-only
- [x] RBAC authorization middleware (`require_role` dependency factory)
- [x] RFC 9457 error response format (`ProblemResponse` in `tenant.py`)
- [x] W3C `traceparent` propagation (`TracingMiddleware`)
- [x] `X-Request-ID` header handling
- [x] Structured logging (`structlog`) with `tenant_id`, `trace_id`, `request_id`
- [x] Audit middleware (`AuditMiddleware`)
- [x] OIDC RS256 validation against JWKS and local user mapping by external issuer/subject
- [x] `GET /api/v1/me` — returns current user and memberships
- [x] `GET /api/v1/tenants/current` — returns active tenant context (derived from auth, not payload)
- [x] `GET /api/v1/tenants/current/memberships` — lists tenant users and roles
- [x] RBAC enforced on key routes — `require_role("admin")` on enrollment tokens, `require_role("admin", "analyst")` on proposals, `require_role("admin", "approver")` on approvals
- [x] CORS middleware — allows Vite dev server origins

### Gateway registry ✅
- [x] `POST /api/v1/gateways/enrollment-tokens` — creates gateway + token in `ENROLLMENT_PENDING`
- [x] `GET /api/v1/gateways` — list with cursor pagination, tenant-scoped
- [x] `GET /api/v1/gateways/{gateway_id}` — 403 on cross-tenant
- [x] `POST /edge/v1/gateways/{gateway_id}/heartbeat` — updates health, sensor status
- [x] Full gateway enrollment flow — `POST /edge/v1/gateways/enrollment` validates token, issues self-signed cert, transitions to ACTIVE
- [x] `GET /edge/v1/gateways/{gateway_id}/configuration` — returns authorized sensor config and allowed event types
- [ ] mTLS verification — gateway_id matched against certificate (currently no mTLS, uses header)
- [ ] Certificate storage with OS-level protection

### Message broker ✅
- [x] RabbitMQ exchange/queue names and routing keys defined (`ascense/broker.py`)
- [x] Transactional outbox publisher worker (`ascense/workers/ingestion/outbox_publisher.py`)
- [x] Dead-letter queue configuration defined
- [x] `aio_pika` wired — `setup_broker()`, `publish()`, `publish_pending_outbox()` all implemented
- [x] Broker topology setup wired to app lifespan startup

### Stage 2 exit condition
- [x] Automated tests: RS256 claim validation, registered OIDC subject mapping, and tenant-membership enforcement
- [ ] Automated test: gateway can enroll *(enrollment endpoint implemented, needs test)*
- [x] Automated test: one tenant cannot access another tenant's resources (`tests/integration/test_tenant_isolation.py`)
- [x] Row-level security policies written (`database/policies/rls.sql`) — apply with `make apply-rls`
- [x] Idempotent consumer base class (`IdempotentConsumer` in `ascense/broker.py`)`

---

## Stage 3A · Gateway to Storage
> Exit: simulated event sent, stored, retrieved via API, traced end-to-end. Dashboard shows `TELEMETRY_STALE` when simulator stops.

### Gateway simulator ✅
- [x] Gateway simulator (`ascense/simulators/gateway_simulator.py`) — sends heartbeats and event batches
- [x] Generates valid CloudEvents 1.0 envelopes with sensor-level source URN
- [x] Sends heartbeats with per-sensor health status
- [x] 20% suspicious destination traffic for detection testing

### Ingestion ✅
- [x] `POST /edge/v1/events:batch` — validates CloudEvents, allowlist, source URN, sensor name
- [x] Deduplication on `(source, source_event_id)` pair
- [x] Unresolved asset handling: events stored with `asset_resolution.status: UNRESOLVED`
- [x] Transactional outbox write (event + outbox record in one transaction)
- [x] `202 Accepted` response with `accepted_count`, `rejected_count`, per-item rejection detail
- [x] Payload size limits enforced (MAX_BATCH_SIZE=1000, MAX_PAYLOAD_BYTES=10MB)
- [ ] `tenantid`/`gatewayid` verified against authenticated gateway identity — currently trusts `X-Tenant-ID` header (dev mode only)

### Normalization worker ✅
- [x] Normalization worker (`ascense/workers/ingestion/worker.py`) — consumes `telemetry.batch.accepted.v1` from RabbitMQ
- [x] RabbitMQ consumer wired via `IdempotentConsumer` base class
- [x] Publishes `telemetry.event.normalized.v1` to detection queue
- [x] Worker started in app lifespan (toggle via `ASCENSE_RUN_WORKERS` env var)

### Storage and retrieval ✅
- [x] `events` table with indexes
- [x] `GET /api/v1/events` with cursor-based pagination, `event_kind` filter, tenant-scoped
- [x] `GET /api/v1/events/{event_id}` — 403 on cross-tenant

### Telemetry health ✅
- [x] Heartbeat processing updates `last_heartbeat_at` and gateway status (`ACTIVE`/`DEGRADED`)
- [x] `SENSOR_FAILURE` detection from heartbeat sensor status
- [x] `TELEMETRY_STALE` detection — background job in lifespan checks `last_heartbeat_at` every 30 s
- [x] `GET /api/v1/gateways/{gateway_id}/sensors` — implemented, queries events table for sensor health
- [x] `GET /api/v1/gateways/{gateway_id}/telemetry-health` — computes overall health status
- [x] Dashboard: gateway sensor health with expandable sensor list, TELEMETRY_STALE indicator

### Stage 3A exit condition
- [x] Automated end-to-end trace: event ingested → stored → retrieved → dedup verified (`tests/integration/test_event_pipeline.py`)
- [x] Dashboard shows `TELEMETRY_STALE` when simulator stops — GatewaysPage displays TELEMETRY_STALE with visual indicator
- [x] Events table partitioned by time (migration `0003_events_partitioning.py`)

---

## Stage 3B · Detection Integration
> Exit: simulated event produces detection finding, alert, and incident — all visible in dashboard and retrievable via API.
> **Baseline B must be frozen before this stage begins.** ✅

- [x] Detection worker with `SuspiciousOutboundConnectionRule` (`ascense/workers/detection/worker.py`)
- [x] `detection_findings` table
- [x] Correlation worker: finding → alert → incident (`ascense/workers/correlation/worker.py`)
- [x] `alerts` table with full state machine
- [x] `incidents` table with full lifecycle
- [x] `GET /api/v1/alerts`, `GET /api/v1/alerts/{alert_id}` — tenant-scoped, 403 on cross-tenant
- [x] `GET /api/v1/incidents`, `GET /api/v1/incidents/{incident_id}` — tenant-scoped
- [x] `POST /api/v1/alerts/{alert_id}/acknowledgements` — transitions NEW → ACKNOWLEDGED
- [x] `POST /api/v1/incidents/{incident_id}/transitions` — full state machine with validation
- [x] Detection worker wired to RabbitMQ — consumes `q.detection`, publishes `detection.finding.created.v1`
- [x] Correlation worker wired to RabbitMQ — consumes `q.correlation`, publishes `alert.created.v1` + `incident.updated.v1`
- [x] Dashboard: alert and incident list connected to API — `AlertsPage` and `IncidentsPage` call API endpoints

### Stage 3B exit condition
- [x] Automated test: simulated event → finding → alert → incident → visible in API (`tests/integration/test_event_pipeline.py`)

---

## Stage 4 · Detection and Incident Management
> Exit: known labelled scenarios produce expected findings within documented thresholds. False positive rate measured.

- [x] One deterministic detection rule (`SuspiciousOutboundConnectionRule`)
- [x] `HighRiskPortOutboundRule` — flags outbound to Metasploit/IRC/leet ports (4444, 1337, 6667, 31337)
- [x] `LargeDataExfiltrationRule` — flags outbound transfers over 50 MB (potential exfil)
- [x] `RDPExposedInternalRule` — flags inbound RDP from external IPs (critical severity)
- [x] Internal command API — `POST /internal/v1/commands` with signed command creation
- [x] Command claim/ack lifecycle — `POST /edge/v1/gateways/{id}/commands:claim`, `/acknowledgements`, `/results`
- [x] Execution attempt tracking with separate `execution_status` / `verification_status` fields
- [x] `GET /api/v1/action-proposals/{proposal_id}/executions` — view execution attempts
- [ ] Complete set of deterministic Suricata detection rules for v1 threat scenarios
- [ ] M2 intrusion classifier (XGBoost/LightGBM) — only if it beats Suricata-only baseline in ablation
- [ ] M3 DDoS detector (LightGBM + EWMA/CUSUM) — only if it beats Suricata-only baseline in ablation
- [ ] Ablation study: Suricata-only vs Suricata+M2 vs Suricata+M2+M3
- [ ] Model registry entries for deployed models
- [ ] Full alert lifecycle with all defined states
- [ ] Full incident lifecycle with actor-recorded transitions
- [ ] Evidence links on alerts
- [x] `evidence` table CRUD — `POST /api/v1/incidents/{id}/evidence`, `GET /api/v1/evidence/{id}`, `GET /api/v1/incidents/{id}/evidence`
- [x] `GET /api/v1/assets`, `GET /api/v1/assets/{asset_id}` — implemented in `ascense/api/routes/assets.py`
- [ ] Dashboard: full alert and incident views with evidence references
- [ ] False positive rate measured and documented on representative test dataset

---

## Stage 5 · AI Investigation
> Exit: investigations explain test incidents using existing evidence. Cross-tenant isolation and no command execution verified.
> **Baseline C must be frozen before this stage begins.** ✅

- [x] Incident context builder (`build_incident_context` in `ascense/workers/investigation/worker.py`)
- [x] Tenant-scoped evidence retrieval — agent cannot access other tenants' data (`tool_get_evidence` enforces tenant_id)
- [x] Investigation worker skeleton consuming `incident.updated.v1` from RabbitMQ
- [x] Investigation routes: `POST /api/v1/incidents/{id}/investigations`, `GET /api/v1/investigations/{id}`, `POST /api/v1/investigations/{id}/cancellations`
- [x] Investigation bounded: `MAX_TOOL_CALLS=20`, `STEP_TIMEOUT=30s`, graceful cancellation
- [x] Read-only tools defined: `tool_search_events`, `tool_search_alerts`, `tool_get_evidence` — no write/execute tools
- [ ] LangGraph investigation agent with full LLM integration (Ollama/OpenAI via env var)
- [ ] Structured JSON output validated against investigation result schema
- [ ] Every claim references a real, retrievable `evidence_id` (enforced before proposals can be generated)
- [ ] Uncertainty reporting in assessment
- [ ] Prompt injection test suite in CI (malicious log entries, hostile evidence text)
- [ ] Dashboard: investigation views with evidence references and proposals

---

## Stage 6 · Response Safety Workflow
> Exit: approved test action completes against lab gateway. All rejection cases pass. Rollback tested.
> **Baseline D must be frozen before this stage begins.** ✅

### Policy engine
- [x] OPA/Rego safety gate — implemented as Python policy engine in `ascense/api/routes/policy.py`
- [x] Schema check, permission check, protected-asset check, blast-radius check, reversibility check, confidence check
- [x] `POST /internal/v1/policy/evaluate` — returns ALLOW/DENY/REQUIRE_APPROVAL with per-check results
- [x] `GET /api/v1/policies` — list policy versions for tenant
- [x] `POST /api/v1/policies` — create new policy version (admin only)
- [ ] Rate-of-change check — needs Redis counter for per-hour/day action tracking
- [ ] Full OPA/Rego binary integration (current impl is Python; acceptable for v1)

### Approval workflow
- [x] `action_proposals` table with state machine
- [x] `approvals` table with state machine
- [x] `POST /api/v1/incidents/{incident_id}/action-proposals` — implemented
- [x] `GET /api/v1/incidents/{incident_id}/action-proposals` — implemented
- [x] `POST /api/v1/action-proposals/{proposal_id}/approvals` — implemented (self-approval blocked)
- [x] Approval records full context: user identity, role, decision, reason, time, expiry (stored in `approvals` table)
- [x] A user cannot approve their own high-impact proposal (enforced in `record_approval` route)
- [x] Approval expiry — `expires_at` set on creation; `lease_expiry.py` marks PENDING approvals EXPIRED
- [x] Approval revocation — `POST /api/v1/action-proposals/{proposal_id}/approvals/{approval_id}/revocations`
- [ ] Approval notification via email/Slack/WhatsApp

### Command lifecycle
- [x] `commands` table with state machine (`QUEUED → LEASED → ACKNOWLEDGED → EXPIRED / CANCELLED`)
- [x] `DISPATCHED` recorded as audit event only — not a command state (verified in contract tests)
- [x] Signed command creation (`create_signed_command` in `ascense/workers/response/worker.py`)
- [ ] Command signing key generation with proper RSA/ECDSA — currently SHA-256 HMAC stub; replace before production
- [ ] Command signing key rotation procedure documented
- [x] `POST /internal/v1/commands` — implemented in `ascense/api/routes/commands.py`
- [x] `GET /api/v1/commands/{command_id}` — implemented in `ascense/api/routes/proposals.py`
- [x] `POST /edge/v1/gateways/{gateway_id}/commands:claim` — atomic lease implemented
- [x] `POST /edge/v1/gateways/{gateway_id}/commands/{command_id}/acknowledgements` — implemented
- [x] Lease expiry worker: `run_lease_expiry_worker` in `ascense/workers/response/lease_expiry.py` — requeues LEASED commands, expires dead commands, expires stale approvals

### Gateway execution
- [x] `execution_attempts` table with `execution_status` and `verification_status` as separate fields
- [ ] Gateway persists execution journal before performing any action *(gateway-side; simulator placeholder only)*
- [ ] Idempotency: gateway checks journal before re-executing on reconnection *(gateway-side)*
- [ ] Gateway validates: signature, expiry, idempotency, target criticality, current policy *(gateway-side)*
- [x] `POST /edge/v1/gateways/{gateway_id}/commands/{command_id}/results` — implemented
- [x] `GET /api/v1/action-proposals/{proposal_id}/executions` — implemented
- [ ] Firewall adapter for pfSense/OPNsense (L0–L2 actions; L3 with human approval)
- [ ] Adapter dry-run mode
- [ ] Rollback procedure defined and tested per action type

### Verification
- [ ] Response verification service: independent read-back from firewall after execution
- [x] `verification_status` set by verification service only — architecture enforced, `POST /internal/v1/commands/{command_id}/verify` implemented
- [ ] `UNKNOWN` verification status escalates — alerting/escalation worker not yet implemented
- [ ] Incident timeline updated with complete outcome

### Dashboard
- [x] Approval UI with approve/reject/revoke/cancel buttons — `ProposalsPage` in `apps/web/src/features/proposals/ProposalsPage.tsx`
- [x] Command lifecycle and execution result visible — `GET /api/v1/action-proposals/{id}/executions`
- [x] `GET /api/v1/audit-events` — implemented; `AuditPage` in dashboard

---

## Stage 7 · Security Validation and Pilot Readiness

### Mandatory negative tests (all must pass)
- [x] Send event using another tenant's gateway identity → isolation tested in `test_tenant_isolation.py`
- [x] Read another tenant's incident via API → `403` — tested in `test_tenant_isolation.py`
- [x] Change `tenant_id` in request payload → ignored; backend derives from auth context — tested in `test_tenant_isolation.py`
- [x] Change `gateway_id` in event payload → URN pattern validated; tested in `test_stage7_negative.py`
- [x] Send duplicate event (same `source` + `id`) → deduplicated — tested in `test_event_pipeline.py`
- [x] Send event with invalid schema → `422` — tested in `test_event_pipeline.py`
- [x] Send unsupported event type → rejected at allowlist check — tested in `test_stage7_negative.py`
- [ ] Submit expired approval → rejected *(lease_expiry worker marks expired; integration test needed)*
- [x] Replay old command → rejected (idempotency_key + nonce required) — verified by inspection `test_stage7_negative.py`
- [x] Modify command after signing → signature hash changes — verified `test_stage7_negative.py`
- [ ] Submit command for gateway not belonging to tenant → rejected *(needs integration test)*
- [ ] Disconnect gateway during command execution → `execution_status: UNKNOWN`; Ascense escalates *(requires stack)*
- [ ] Gateway unreachable before command delivered → command returns to `QUEUED` *(requires stack)*
- [ ] Unsuccessful rollback → `PARTIALLY_SUCCEEDED` or `FAILED`; never silently converted *(requires stack)*
- [ ] Policy changes after approval but before execution → command rejected *(needs integration test)*
- [ ] Asset marked critical after proposal approved → command rejected *(needs integration test)*
- [x] Approval revoked while command queued → command cancelled — enforced in `revoke_approval` route; tested `test_stage7_negative.py`
- [x] Two gateway processes claim same command → only one lease issued — `SELECT FOR UPDATE SKIP LOCKED`; tested `test_stage7_negative.py`
- [x] Prompt injection via event payload → raw data stripped in investigation context builder; tested `test_stage7_negative.py`
- [x] Investigation agent attempts cross-tenant evidence access → `tool_get_evidence` filters by `tenant_id`; tested `test_stage7_negative.py`
- [x] Investigation agent attempts write/execute tool → no write/execute tools defined; tested `test_stage7_negative.py`
- [ ] Investigation produces recommendation without evidence references → proposal rejected *(needs full agent)*

### Full tenant isolation tests
- [x] API endpoints and database queries — no cross-tenant resource access (`test_tenant_isolation.py`)
- [ ] RabbitMQ queues — no cross-tenant message delivery *(requires stack test)*
- [ ] Redis cache keys — tenant-scoped namespacing *(Redis not yet used in v1)*
- [ ] Object storage — pre-signed URLs scoped to tenant *(object storage not yet wired)*
- [x] Background workers — tenant context derived from message payload, not worker state (enforced in all workers)
- [ ] Audit records — no cross-tenant data in any export *(needs integration test)*

### Security tests
- [ ] All `/api/v1/` endpoints reject unauthenticated requests with `401` *(needs integration test with no headers)*
- [ ] All `/edge/v1/` endpoints require valid gateway mTLS certificate *(mTLS not yet enforced)*
- [x] All `/internal/v1/` endpoints use `/internal/v1/` prefix — verified `test_stage7_negative.py`
- [x] RBAC enforced — `require_role` on proposals and approvals routes
- [ ] SQL injection attempts in query parameters rejected *(needs integration test)*
- [x] Oversized payloads rejected — `MAX_BATCH_SIZE=1000`, `MAX_PAYLOAD_BYTES=10MB` enforced
- [ ] No secrets, credentials, or stack traces in error responses or logs *(needs integration test)*

### Command and enforcement failure tests
- [ ] Policy changes after approval → command rejected
- [ ] Gateway has revoked certificate → command rejected
- [ ] Command executes but acknowledgement lost → lease expires; journal checked before re-executing
- [ ] Firewall applies block but gateway crashes before reporting → `UNKNOWN`; system escalates
- [ ] Gateway reconnects after crash mid-execution → reads journal, reconciles with firewall state

### Pilot levels
- [ ] **Level 1 — Isolated lab**: simulated traffic, all negative tests pass, cross-tenant isolation verified
- [ ] **Level 2 — Internal environment**: monitor actual internal traffic, no enforcement, telemetry health validated
- [ ] **Level 3 — Design-partner environment**: customer-approved telemetry, read-only investigation, detection quality measured
- [ ] **Level 4 — Controlled response pilot**: limited action types, explicit human approval, full audit trail verified

### Operational readiness
- [x] Runbook: gateway enrollment and certificate issuance (`docs/06_RUNBOOKS.md` RB-01)
- [x] Runbook: certificate rotation without losing telemetry (`docs/06_RUNBOOKS.md` RB-02)
- [x] Runbook: certificate revocation and re-enrollment (`docs/06_RUNBOOKS.md` RB-03)
- [x] Runbook: event backlog recovery after broker outage (`docs/06_RUNBOOKS.md` RB-04)
- [x] Runbook: response failure (`docs/06_RUNBOOKS.md` RB-05)
- [x] Runbook: backup and restore (`docs/06_RUNBOOKS.md` RB-06)
- [x] Runbook: `TELEMETRY_STALE` investigation and recovery (`docs/06_RUNBOOKS.md` RB-07)
- [x] Runbook: approval service unavailable (`docs/06_RUNBOOKS.md` RB-08)
- [x] Known limitations documented (`docs/06_RUNBOOKS.md` RB-09)
- [ ] Customer data handling policy documented
- [x] SLO baseline measurements recorded (targets in `docs/06_RUNBOOKS.md`)

---

## Validation Gates (Rev2)

- [ ] **G0** — 15 customer-discovery interviews (10 IT heads, 5 MSPs) with written notes
- [ ] **G1** — Written permission to capture passive logs at 2+ sites
- [ ] **G2** — 4 weeks shadow-mode: fewer incidents to review, no confirmed miss
- [ ] **G3** — 3 signed paid pilots with written success criteria
- [ ] **G4** — 2 customers enable L2 actions in production
- [ ] **G5** — 2 pilots convert to recurring contracts

---

## Immediate Next Steps (unblocked work)

1. **Run `make docker-up && make migrate && make apply-rls && make seed`** — stand up the full stack and apply RLS policies
2. **`pytest tests/integration/`** — run end-to-end tests against the live stack
3. **OIDC deployment** — configure `JWT_ISSUER`, `JWT_AUDIENCE`, and `JWKS_URL`; provision user issuer/subject mappings and validate with a real provider token
4. **Rate-of-change policy check** — add Redis counter for per-tenant action rate limiting
5. **Approval notification** — email/Slack/WhatsApp webhook on approval request
6. **LangGraph investigation agent** — wire Ollama/OpenAI into `ascense/workers/investigation/worker.py`
7. **Customer data handling policy** — document in `docs/`

---

## Continuous (every stage)

- [x] Contract tests pass on every PR that touches `contracts/` (CI enforces this)
- [x] Contract tests written for Baselines A, B, D (`tests/contract/test_contract_schemas.py`)
- [ ] Every new module has unit tests before merge *(unit tests written for detection rules, state machines, event validation)*
- [x] Unit tests: detection rules (70 tests total, all passing)
- [x] Every security-relevant operation produces an audit record (middleware in place)
- [x] Structured logs include `timestamp`, `level`, `service`, `tenant_id`, `trace_id`, `request_id`
- [x] No secrets or PII in logs
- [x] W3C `traceparent` propagated on all API requests (`TracingMiddleware`)
- [ ] Definition of Done checklist from `03_MODULE_OWNERSHIP.md` met before any module is marked complete

---

## Tier 2 — After Gate G3 + G4 (do not start earlier)

- [ ] Custom edge gateway (nftables, eBPF/XDP, Zeek)
- [ ] M1 anomaly detector, M4 C2 detector, M5 UEBA model
- [ ] TLS metadata features (JA3/JA4)
- [ ] Second and third firewall adapters
- [ ] Multi-tenant hardening (dedicated DB per enterprise tenant)
- [ ] Local-LLM packaging (Ollama on-prem)
- [ ] SOC 2 / ISO 27001 preparation
- [ ] Kubernetes deployment

## Tier 3 — Research only, after a paying customer requests it and ablation shows measurable benefit

- [ ] Game-theoretic decision engine (Part G of Rev2 spec)
- [ ] M6 risk prediction model
- [ ] M7 web request anomaly, M8 data-access anomaly, M9 exfiltration detector
- [ ] WAF / API security layer
- [ ] Data security layer (discovery, UEBA, exfiltration)
- [ ] Security knowledge graph (Neo4j / Apache AGE)
- [ ] Honeypots and deception
- [ ] Dempster-Shafer fusion

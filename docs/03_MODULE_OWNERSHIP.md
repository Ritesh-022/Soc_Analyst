# 03 · Module Ownership

One owner per module. Two people can work on a module, but two people must not independently define the same contract.

---

## Role Definitions

| Role | Owns | Main responsibilities | Must coordinate with |
|---|---|---|---|
| Technical lead / system architect | Overall system and shared contracts | Architecture decisions, interface approval, identifier registry, integration design, code review standards | Every role |
| Backend / platform engineer | API, identity, tenants, database, asset registry, evidence access, policy engine, approval, response orchestration | FastAPI, PostgreSQL, RBAC, gateway registry, ingestion, broker, audit | Gateway, detection, frontend |
| Gateway engineer | Customer-side data plane | Agent, sensor integrations, event emitter, local buffer, command polling, execution adapters, certificate lifecycle | Backend, detection, response |
| Detection / ML engineer | Detection pipeline and model registry | Normalization, rule engine, model inference, scoring, correlation, alert creation, model versioning | Ingestion, investigation |
| AI / investigation engineer | Investigation pipeline | Incident context, RAG, model integration, evidence references, structured recommendations, action proposals | Detection, response |
| Frontend engineer | Dashboard | Login, tenant views, events, alerts, incidents, investigations, approvals, audit timeline | Backend |
| QA / DevSecOps owner | Release quality and deployment | CI/CD, automated testing, security tests, observability, deployment, backups, release verification | Every role |

---

## Practical Division for a Small Team (4 developers)

| Person | Primary responsibility | Secondary responsibility |
|---|---|---|
| Developer A | Platform / backend · Architecture · Response safety authority | Contract ownership · Policy engine · Approval workflow |
| Developer B | Gateway and ingestion · Deployment and infrastructure | Certificate lifecycle · Sensor integrations · Command adapters |
| Developer C | Detection and ML · Model registry | Investigation pipeline · Evidence management |
| Developer D | Frontend and dashboard · Integration quality | API integration · Cross-module test coordination |

### Response safety authority

Developer A is the single accountable owner for the complete response safety process. Other developers implement their pieces, but only Developer A approves:
- The security-critical command contract
- Authorization logic for proposal → approval → command
- Action-specific safety tests
- Rollback definitions per action type

### Architecture authority

The technical lead (Developer A in a 4-person team) must independently review and approve any change to:
- Event schemas
- Tenant identity logic
- Command signing
- Permission models
- Response state machines
- Database tenant ownership
- Public API compatibility

These changes require a documented architecture review, not just a code review.

### Security review independence

Security-critical changes must be reviewed by a developer who did not write them. On a 4-person team, rotate this responsibility explicitly. Do not allow the author of a command signing implementation to be its sole reviewer.

### Workload scheduling

Developer C's workload spans detection, ML, and AI investigation — three substantial tracks. Schedule them sequentially, not simultaneously:
- Stages 3–4: deterministic detection and correlation only
- Stage 5: investigation pipeline after incident and evidence contracts are stable
- Later iterations: advanced RAG, multi-agent workflows, additional ML models

Developer A's workload is the heaviest. Defer advanced response orchestration until the core backend and tenant isolation are working.

---

## Contract Ownership Map

One owner per contract. The owner maintains the contract, tests, examples, and documentation. Other teams may request changes but must not create incompatible local versions.

| Contract | Owner | Supporting |
|---|---|---|
| User authentication and tenant context | Backend (Dev A) | — |
| Gateway identity and enrollment | Backend (Dev A) + Gateway (Dev B) | — |
| Gateway certificate lifecycle | Gateway (Dev B) | Backend (Dev A) |
| Event schema | Backend (Dev A) + Detection (Dev C), technical lead approval | — |
| Detection finding schema | Detection (Dev C) | — |
| Alert and incident data model | Backend (Dev A) + Detection (Dev C) | — |
| Asset registry schema | Backend (Dev A) | Gateway (Dev B), Detection (Dev C) |
| Evidence schema | Backend (Dev A) | Investigation (Dev C) |
| Investigation output | AI / Investigation (Dev C) | — |
| Action proposal schema | AI / Investigation (Dev C) + Response (Dev A) | — |
| Approval policy | Response / Backend (Dev A) | — |
| Signed command schema | Response (Dev A) | — |
| Gateway execution result | Gateway (Dev B) | — |
| Model registry schema | Detection / ML (Dev C) | DevSecOps |
| Policy registry schema | Backend / Response (Dev A) | — |
| Telemetry health schema | Gateway (Dev B) | Backend (Dev A) |
| Audit event schema | Backend (Dev A) | DevSecOps |
| Dashboard API client | Frontend (Dev D) | — |
| API and event compatibility checks | Owner: Developer D (QA coordination). Architecture approval: Developer A. | — |

---

## Module Responsibilities

### Platform API (`platform/api/`)

**Owner:** Developer A (Backend / platform engineer)

Inputs: Authenticated HTTP requests from the dashboard and gateway
Outputs: JSON responses, audit records, broker messages via outbox

Responsibilities:
- User authentication (OIDC integration) and internal `user_id` mapping
- Tenant context derivation and enforcement on every request
- RBAC authorization checks
- Gateway registration and enrollment token issuance
- Asset registry CRUD
- Evidence metadata access and authorization
- Event ingestion endpoint (`/edge/v1/events:batch`)
- Transactional outbox write
- Policy registry read and version management
- Approval workflow (record identity, role, decision, reason, time, expiry)
- Audit log append for all security-relevant operations

Must not: perform detection, run ML inference, execute response commands, or trust caller-supplied `tenant_id`.

---

### Gateway Agent (`edge/gateway-agent/`)

**Owner:** Developer B (Gateway engineer)

Inputs: Sensor output (Suricata, Zeek, firewall logs)
Outputs: Authenticated event batches to `/edge/v1/events:batch`; execution results to `/edge/v1/.../results`

Responsibilities:
- Collect and locally buffer sensor events (bounded buffer with disk exhaustion handling)
- Normalize supported sensor output to the canonical event schema
- Preserve `source_event_id` from the original sensor
- Transmit batches over mTLS using the gateway certificate
- Send heartbeats with per-sensor health status
- Report sensor process status separately from gateway connectivity
- Poll for pending commands via outbound connection using `commands:claim`
- Validate command signatures, expiry, idempotency, and target criticality before execution
- Execute only allowlisted adapter actions (no arbitrary shell commands)
- Report actual enforcement state after execution
- Manage certificate renewal and handle revocation

Must not: decide its own `tenant_id`, accept inbound connections from Ascense, execute unsigned or expired commands, or invent event types not in the approved allowlist.

### Gateway lifecycle states

```
UNREGISTERED → ENROLLMENT_PENDING → ACTIVE → DEGRADED → DISCONNECTED → REVOKED / DECOMMISSIONED
```

Sensor failures must be distinguishable from gateway failure. A gateway can be `ACTIVE` while a specific sensor is in `SENSOR_FAILURE`.

---

### Detection workers (`platform/workers/detection/`, `platform/workers/correlation/`)

**Owner:** Developer C (Detection / ML engineer)

Inputs: Normalized events from the broker
Outputs: Detection finding records, alert records, incident records, evidence references

Responsibilities:
- Consume normalized events from the queue
- Execute deterministic detection rules (with `rule_version`)
- Run approved ML model inference (with `model_version_id` and `feature_schema_version`)
- Return detection findings with `detection_finding_id`, detector identity, version, score, and confidence
- Correlate related findings into alerts
- Group related alerts into incidents
- Link evidence references to alerts
- Maintain model registry entries for deployed models

Must not: send block commands, modify response proposals, access another tenant's events, or mark actions as verified.

---

### Evidence Management (`platform/core/evidence/`)

**Owner:** Developer A (Backend / platform engineer)
**Supporting:** Developer C (Investigation)

Inputs: References from detection, investigation, and ingestion
Outputs: Authorized evidence records and object storage references

Responsibilities:
- Store evidence metadata in PostgreSQL
- Store large evidence objects (packet captures, raw logs) in object storage
- Enforce tenant-scoped access on every retrieval
- Provide evidence IDs that are stable and retrievable
- Support evidence deletion per data lifecycle policy

Must not: allow cross-tenant evidence access under any circumstances.

---

### Asset Registry (`platform/core/assets/`)

**Owner:** Developer A (Backend / platform engineer)
**Supporting:** Developer B (Gateway), Developer C (Detection)

Inputs: Manual registration, gateway-reported asset discovery
Outputs: Asset records with criticality, ownership, and gateway association

Responsibilities:
- Maintain asset identity, IP history, criticality, environment, and status
- Associate assets with their tenant and gateway
- Provide asset criticality to the policy engine for response decisions
- Support asset lifecycle (active, decommissioned, unknown)

---

### Investigation workers (`platform/workers/investigation/`)

**Owner:** Developer C (AI / investigation engineer)

Inputs: Incident context (alerts, events, assets, evidence) from the platform API
Outputs: Investigation reports with evidence references and action proposals

Responsibilities:
- Build incident context from authorized, tenant-scoped evidence
- Run LLM investigation with read-only tool access
- Produce structured investigation results referencing real evidence IDs
- Report uncertainties and missing evidence explicitly
- Propose actions — proposals only, not executable commands

Must not: access evidence outside the tenant scope, execute commands, modify alert or incident status directly, or invent evidence not present in the evidence store.

---

### Response workers (`platform/workers/response/`)

**Owner:** Developer A (response safety authority)

Inputs: Action proposals, policy evaluation results, human approvals
Outputs: Signed commands dispatched to the gateway

Responsibilities:
- Evaluate proposals against deterministic policy rules
- Record human approval with full context (user, role, decision, reason, time, expiry)
- Create signed commands bound to tenant, gateway, target, approval, and policy version
- Dispatch commands to the gateway command queue
- Receive execution results from the gateway
- Verify actual enforcement state
- Record complete outcome in the incident timeline
- Define rollback procedures per action type

Must not: execute commands without a valid approval, reuse expired approvals, skip policy evaluation, or accept unsigned execution results.

---

### Dashboard (`apps/web/`)

**Owner:** Developer D (Frontend engineer)

Inputs: Authenticated API responses from `/api/v1/`
Outputs: User actions sent as API requests

Responsibilities:
- Display alerts, incidents, investigations, evidence, and response history
- Display gateway and sensor health status (including `TELEMETRY_STALE` and `SENSOR_FAILURE`)
- Provide approval UI for sensitive actions
- Show audit timeline
- Admin settings and gateway management views
- Generate typed API clients from OpenAPI definitions in `contracts/generated/`

Must not: enforce authorization logic, trust locally cached permission state for security decisions, or call `/internal/v1/` or `/edge/v1/` endpoints.

---

## Dependency Graph

```
contracts/          ← no dependencies; everything depends on this
    |
    +── platform/api/                    ← contracts, database, broker
    |       |
    |       +── platform/core/identity/
    |       +── platform/core/tenants/
    |       +── platform/core/gateways/
    |       +── platform/core/assets/
    |       +── platform/core/evidence/
    |       +── platform/core/policies/
    |       +── platform/core/audit/
    |       |
    |       +── platform/workers/ingestion/     ← contracts, broker
    |       +── platform/workers/detection/     ← contracts, broker
    |       +── platform/workers/correlation/   ← contracts, broker
    |       +── platform/workers/investigation/ ← contracts, broker, platform/api
    |       +── platform/workers/response/      ← contracts, broker, platform/api
    |
    +── edge/gateway-agent/             ← contracts only
    |
    +── apps/web/                       ← contracts/generated, platform/api
```

The gateway agent and the dashboard have no dependency on each other. Both depend only on the shared contracts and the platform API. This is what enables parallel development after the first contract baseline is frozen.

---

## Definition of Done (per module)

A module is not complete until all of the following are true:

- [ ] Module purpose and ownership documented
- [ ] Inputs and outputs follow the shared contracts
- [ ] API or event schemas updated where necessary
- [ ] Authentication and tenant authorization tested
- [ ] Unit tests written and passing
- [ ] Contract tests written and passing
- [ ] Integration tests written and passing
- [ ] Failures, retries, and timeouts handled
- [ ] Structured logs and W3C trace IDs implemented
- [ ] Sensitive data and secrets protected
- [ ] Audit records created for security-relevant operations
- [ ] README and local run instructions updated
- [ ] Code reviewed by a developer who did not write it
- [ ] Merged through CI with all checks passing

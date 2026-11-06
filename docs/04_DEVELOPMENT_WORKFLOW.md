# 04 · Development Workflow

The sequence below respects architectural dependencies while allowing independent work to proceed in parallel. This is an engineering execution plan, not a feature checklist.

The key principle: **parallelize implementation only after shared interfaces are stable. Integrate early and often — do not wait until every module is finished.**

---

## Stage 0 · Product and Architecture Alignment

**Must happen first. No major feature work begins until this stage exits.**

### Deliverables

- [ ] Product scope and first-release boundaries agreed and written down
- [ ] Gateway deployment model confirmed: out-of-band monitoring with allowlisted response adapters (ADR-001)
- [ ] User roles and permission model defined
- [ ] Trust boundaries and threat model documented
- [ ] Component architecture and four-plane model agreed
- [ ] System terminology and glossary written
- [ ] Technology decisions recorded as ADRs in `docs/adr/`

### Exit condition

Every developer can explain the same end-to-end event-to-response workflow without contradiction.

---

## Stage 0.5 · Feasibility and Discovery

**Run before freezing all contracts. Small, isolated prototypes — not product features.**

Prove these technical assumptions before committing to the full contract design:

| Experiment | What you need to learn |
|---|---|
| Sensor feasibility | What Suricata and Zeek can actually provide for the intended use cases |
| Event volume | Approximate events per second, batch size, and expected storage growth |
| Gateway feasibility | CPU, memory, disk buffer, and certificate storage requirements |
| Network connectivity | Whether outbound mTLS communication works in the target deployment environments |
| Detection data | Whether representative labelled data exists for the initial threat types |
| Response integration | Which existing firewall or device can safely accept a restricted test command |

These experiments inform the contract design. They are not the product.

---

## Stage 1 · Contracts First (Incremental Baselines)

**Freeze contracts incrementally, not all at once. Each baseline is reviewed, tested, and then used by its producer and consumer teams.**

### Contract Baseline A — Gateway and ingestion (freeze before Stage 2)

- [ ] Identifier registry (`contracts/common/identifiers.yaml`)
- [ ] Tenant and gateway identity model
- [ ] Gateway registration and heartbeat schemas
- [ ] Canonical network event schema with sensor-level source identity and asset resolution fields
- [ ] Event batch ingestion contract and response format
- [ ] Sensor status schema
- [ ] Telemetry health schema
- [ ] Error codes, pagination, timestamp, and retry conventions (`contracts/common/errors.yaml`)
- [ ] API definitions for `/edge/v1/` and core `/api/v1/` endpoints
- [ ] Minimal asset reference schema (enough for ingestion to store `asset_resolution`)

### Contract Baseline B — Detection and alerting (freeze before Stage 3 detection integration)

Baseline B must be frozen before the detection rule in Stage 3 is implemented. Stage 3 builds a complete vertical slice that includes detection, so the finding, alert, and incident schemas must exist before that work begins.

- [ ] Detection finding schema (separate from alert)
- [ ] Alert schema
- [ ] Incident schema
- [ ] Complete asset schema (criticality, ownership, lifecycle)
- [ ] Evidence schema
- [ ] Alert and incident state machines (`contracts/common/enums.yaml`)
- [ ] API definitions for alerts, incidents, assets, evidence
- [ ] Execution journal schema (gateway-side, required before Stage 6 but defined here)

### Contract Baseline C — Investigation (freeze before Stage 5)

- [ ] Investigation result schema
- [ ] Evidence reference format
- [ ] Action proposal schema with typed target
- [ ] Network indicator schema

### Contract Baseline D — Response (freeze before Stage 6)

- [ ] Policy evaluation schema
- [ ] Approval schema
- [ ] Signed command schema
- [ ] Execution result schema
- [ ] Four response state machines (proposal, approval, command lifecycle; execution attempt status and verification status as separate fields)
- [ ] Command leasing and delivery semantics

### Exit condition for Stage 1

Every developer can implement against Baseline A, even if the other component is not yet built. Contract tests exist and can run against mock implementations.

---

## Stage 2 · Platform Foundation

**Build the common infrastructure that every other module depends on.**

### Deliverables

- [ ] Repository and package structure established
- [ ] Local development environment working (`infrastructure/compose/`)
- [ ] Database schema and migrations for identity, tenants, gateways, assets (`database/migrations/`)
- [ ] Authentication integration (OIDC) with internal `user_id` mapping
- [ ] Tenant authorization middleware — every request checks tenant ownership
- [ ] Gateway registration and enrollment token flow
- [ ] Certificate issuance and storage
- [ ] Event broker setup (RabbitMQ) with transactional outbox
- [ ] Central structured logging, W3C distributed traces, and audit log structure
- [ ] CI pipeline with automated contract tests on every PR

### Exit condition

A user can authenticate. A gateway can enroll. One tenant cannot access another tenant's resources. These three properties are verified by automated tests.

---

## Stage 3 · First Vertical Slice (End-to-End Ingestion)

**Build the narrowest complete path first. Split into two sub-stages.**

### Stage 3A — Gateway to storage

Target: `Gateway simulator → Ingestion → Normalization → Database → Dashboard event list`

### Deliverables (3A)

- [ ] Gateway simulator (for development and testing without physical hardware)
- [ ] Event schema validation at the ingestion endpoint, including sensor-level source URN
- [ ] Gateway mTLS authentication at `/edge/v1/events:batch`
- [ ] Event ingestion, normalization, and persistence
- [ ] Unresolved asset handling: events with unknown IPs stored with `asset_resolution.status: UNRESOLVED`
- [ ] Transactional outbox publication and queue consumption
- [ ] Basic event listing in the dashboard
- [ ] Telemetry health status visible in the dashboard

### Exit condition (3A)

A simulated network event can be sent, stored, retrieved via the API, and traced end-to-end using a `trace_id`. The dashboard shows `TELEMETRY_STALE` when the simulator stops sending events.

### Stage 3B — Detection integration

**Baseline B must be frozen before this sub-stage begins.**

Target: `Normalized event → One deterministic rule → Detection finding → Alert → Incident → Dashboard`

### Deliverables (3B)

- [ ] One deterministic detection rule producing a `detection_finding_id`
- [ ] Correlation creating one alert and one incident from that finding
- [ ] Alert and incident listing in the dashboard

### Exit condition (3B)

A simulated network event produces a detection finding, alert, and incident. All three are visible in the dashboard and retrievable via the API.

---

## Stage 4 · Detection and Incident Management

**Expand detection coverage. Measure quality before adding ML.**

### Deliverables

- [ ] A complete set of deterministic detection rules for the v1 threat scenarios
- [ ] One or two baseline ML detectors (only if justified by available labelled data)
- [ ] Normalized detector output following the detection finding contract
- [ ] Full alert lifecycle implementation with all defined states
- [ ] Full incident lifecycle with actor-recorded transitions
- [ ] Evidence links and detection explanations on alerts
- [ ] Alert and incident views in the dashboard

### Exit condition

Known labelled scenarios produce expected detection findings within documented performance thresholds. False positive rate is measured and documented on a representative test dataset. Ambiguous and unseen scenarios are evaluated for false positive rate and investigation quality. No unknown finding directly authorizes a high-impact response.

> Note: "Unknown test scenarios do not produce alerts" is not a valid acceptance criterion for a platform that includes anomaly detection. Detecting previously unseen behaviour is a design goal. The requirement is that unseen findings are evaluated, not suppressed.

---

## Stage 5 · AI Investigation

**Give the system investigation ability, not unrestricted authority.**

### Deliverables

- [ ] Incident context builder (collects alerts, events, assets, evidence for a given incident)
- [ ] Tenant-scoped evidence retrieval — no cross-tenant access
- [ ] Read-only investigation tools (no write or execute permissions)
- [ ] Structured investigation results following the investigation result contract
- [ ] Evidence references in every claim — no invented findings
- [ ] Uncertainty reporting in the assessment
- [ ] Action proposals with typed targets — not directly executable
- [ ] Investigation views in the dashboard

### Exit condition

Investigations can explain a test incident using existing evidence. An investigation cannot access another tenant's information. An investigation cannot execute commands. These properties are verified by automated security tests.

---

## Stage 6 · Response Safety Workflow

**Introduce controlled enforcement. Lab environment only.**

### Deliverables

- [ ] Deterministic policy evaluation against an allowlisted action schema
- [ ] Human approval workflow with full context recording
- [ ] Approval expiry and revocation
- [ ] Signed command creation bound to tenant, gateway, target, approval, and policy version
- [ ] Command leasing via `POST .../commands:claim`
- [ ] Gateway command signature validation, expiry check, and idempotency check
- [ ] Idempotent execution adapters (no arbitrary shell commands)
- [ ] Execution result reporting from the gateway
- [ ] Outcome verification and rollback tests per action type
- [ ] Approval UI in the dashboard
- [ ] Command signing key rotation procedure documented

### Exit condition

An approved test action completes correctly against a lab gateway. Expired, replayed, unsigned, unauthorized, and out-of-scope commands are rejected. Rollback from a failed action is tested and documented. A policy change after approval but before execution is handled correctly.

---

## Stage 7 · Security Validation and Pilot Readiness

**Prove the system under failure conditions. Progressive deployment gates — not a single release.**

### Pilot Level 1 — Isolated lab

- Simulated traffic, detection, and test responses
- All negative tests pass
- Cross-tenant isolation verified

### Pilot Level 2 — Internal environment

- Monitor actual internal traffic
- No enforcement actions
- Telemetry health monitoring validated

### Pilot Level 3 — Design-partner environment

- Customer-approved telemetry collection
- Read-only investigation
- No enforcement actions
- Detection quality measured on real traffic

### Pilot Level 4 — Controlled response pilot

- Limited action types
- Explicit human approval required for every action
- Only lab-tested adapters permitted
- Full audit trail verified

Production deployment is a separate release decision based on demonstrated results from Level 4, not simply completion of the feature checklist.

### Stage 7 deliverables

- [ ] Cross-tenant penetration tests (Tenant A cannot read Tenant B's data)
- [ ] Authentication and authorization review
- [ ] Gateway outage and reconnection tests
- [ ] Event loss, duplicate, and out-of-order delivery tests
- [ ] AI agent and RAG red-team tests (prompt injection, evidence fabrication, cross-tenant retrieval)
- [ ] Command race condition tests (two gateway processes claiming the same command)
- [ ] Policy-change-after-approval tests
- [ ] Load and resource-exhaustion tests
- [ ] Backup and restore tests
- [ ] Operational runbooks
- [ ] Customer data handling policy documented
- [ ] Known limitations documented

### Exit condition

The pilot has measurable detection quality, safe response behaviour, documented limitations, and reproducible test results. All Stage 7 tests pass and are part of the CI suite.

---

## Parallel Work Map

After Contract Baseline A is frozen, four workstreams can proceed independently:

```
Baseline A frozen
        |
        +── Backend: auth, tenant model, APIs, database, broker
        |
        +── Gateway: agent, sensors, telemetry simulator, event producer
        |
        +── Frontend: dashboard against mock API responses and generated types
        |
        +── Detection: rule engine against canonical event fixtures

        ↓

Integration checkpoint (Stage 3A exit)
  Gateway → ingestion → storage → dashboard working.
  Telemetry health visible.

        ↓

Baseline B frozen → Detection schemas, alert, incident, asset, evidence

        ↓

Integration checkpoint (Stage 3B exit)
  Detection finding → alert → incident → dashboard working end-to-end.

        ↓

Baseline C frozen → Investigation, incident views, gateway hardening

        ↓

Baseline D frozen → Response policy design, approval workflow, command signing

        ↓

Integration checkpoint (Stage 6 exit)
  Full proposal → approval → command → execution → verification loop working in lab.
```

---

## Integration Checkpoints

| After stage | What must be verified together |
|---|---|
| Stage 2 | Auth, tenant isolation, gateway enrollment, certificate issuance |
| Stage 3A | Gateway → ingestion → normalization → storage → dashboard event list; telemetry health visible |
| Stage 3B | Event → detection finding → alert → incident → dashboard alert view |
| Stage 4 | Full detection pipeline with measured false positive rate |
| Stage 5 | Incident → investigation → evidence references → proposal creation; cross-tenant isolation verified |
| Stage 6 | Proposal → policy → approval → signed command → gateway execution → verification; all rejection cases pass |
| Stage 7 | Full end-to-end scenario under failure conditions at each pilot level |

---

## Repository Structure

```
ascense/
├── apps/
│   └── web/
│       ├── src/
│       │   ├── pages/
│       │   ├── components/
│       │   ├── features/
│       │   │   ├── alerts/
│       │   │   ├── incidents/
│       │   │   ├── investigations/
│       │   │   ├── gateways/
│       │   │   ├── assets/
│       │   │   └── approvals/
│       │   ├── api/
│       │   └── auth/
│       └── tests/
│
├── platform/
│   ├── api/
│   │   ├── routes/
│   │   ├── middleware/
│   │   ├── dependencies/
│   │   └── main.py
│   ├── core/
│   │   ├── identity/
│   │   ├── tenants/
│   │   ├── gateways/
│   │   ├── assets/
│   │   ├── evidence/
│   │   ├── events/
│   │   ├── alerts/
│   │   ├── incidents/
│   │   ├── investigations/
│   │   ├── approvals/
│   │   ├── policies/
│   │   ├── responses/
│   │   └── audit/
│   └── workers/
│       ├── ingestion/
│       ├── detection/
│       ├── correlation/
│       ├── investigation/
│       └── response/
│
├── edge/
│   └── gateway-agent/
│       ├── collectors/
│       ├── normalizers/
│       ├── buffer/
│       ├── transport/
│       ├── command_client/
│       └── adapters/
│
├── contracts/
│   ├── openapi/
│   │   ├── public-api-v1.yaml
│   │   ├── edge-api-v1.yaml
│   │   └── internal-api-v1.yaml
│   ├── events/
│   │   ├── network-connection-v1.json
│   │   ├── detection-finding-v1.json
│   │   ├── alert-v1.json
│   │   └── incident-v1.json
│   ├── gateway/
│   │   ├── gateway-registration-v1.json
│   │   ├── gateway-heartbeat-v1.json
│   │   └── sensor-status-v1.json
│   ├── assets/
│   │   ├── asset-v1.json
│   │   └── network-indicator-v1.json
│   ├── evidence/
│   │   └── evidence-v1.json
│   ├── investigation/
│   │   └── investigation-result-v1.json
│   ├── response/
│   │   ├── action-proposal-v1.json
│   │   ├── policy-evaluation-v1.json
│   │   ├── approval-v1.json
│   │   ├── action-command-v1.json
│   │   └── execution-result-v1.json
│   ├── common/
│   │   ├── identifiers.yaml
│   │   ├── enums.yaml
│   │   ├── errors.yaml
│   │   └── telemetry-health-v1.json
│   └── generated/
│
├── database/
│   ├── migrations/
│   ├── seeds/
│   └── policies/
│
├── infrastructure/
│   ├── docker/
│   ├── compose/
│   ├── monitoring/
│   └── deployment/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   ├── security/
│   ├── end_to_end/
│   └── failure_scenarios/
│
└── docs/
    ├── architecture/
    ├── adr/
    ├── api/
    ├── data_dictionary/
    ├── workflows/
    ├── threat_model/
    └── runbooks/
```

### Key conventions

- `contracts/` is the authoritative source for shared interfaces. No module maintains its own copy.
- `contracts/generated/` contains generated API clients and types. Never edit generated files manually.
- `docs/adr/` stores architecture decisions with rationale (e.g. why RabbitMQ, why outbound gateway polling, why out-of-band monitoring).
- `tests/contract/` verifies that every producer and consumer still follows the shared interface.
- Cross-module tests belong in the root `tests/` directory, not inside individual module directories.
- Contract tests run on every PR that touches `contracts/`. A failing contract test blocks the PR.

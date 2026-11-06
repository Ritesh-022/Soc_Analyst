# 01 · System Architecture

## What Ascense Is

Ascense is a multi-tenant cybersecurity platform with a customer-side security agent and a central cloud-based security control plane. It continuously collects security events from a customer's infrastructure, analyzes them, identifies suspicious behaviour, investigates incidents, and helps the security team make safe response decisions.

Five interconnected capabilities:

1. **Observe** — understand what is happening inside a customer's infrastructure
2. **Detect** — identify suspicious activity through rules, statistical methods, and ML
3. **Investigate** — connect related events and explain what might be happening, using evidence and AI
4. **Decide** — evaluate possible responses using deterministic security policies and human approval
5. **Act and verify** — execute authorized actions and confirm the intended security outcome occurred

---

## First Release Boundary

**Product:** Network Threat Detection and Assisted Response

**Included in v1:**
- Gateway/sensor collects network security events
- Backend authenticates the gateway and receives events
- Events are normalized and stored
- Detection rules and ML models identify suspicious activity
- Investigation service assembles evidence and produces an explanation
- Policy engine checks any proposed response
- Authorized human approves sensitive actions
- Response service executes permitted actions and verifies the outcome
- Dashboard displays alerts, incidents, evidence, and response history

**Excluded from v1:**
- Autonomous blocking without human approval
- Full WAF, API, database, identity, and endpoint protection
- Game-theoretic optimizer
- Every ML model in the long-term specification
- Every third-party integration

---

## Gateway Deployment Model (ADR-001)

**Decision: out-of-band monitoring with controlled integration into existing security controls.**

Customer network traffic does not pass through Ascense. The gateway agent collects telemetry passively from sensors (Suricata, Zeek, firewall logs). Approved response adapters can manage specific controls in a customer's existing firewall or security product when an authorized action is executed.

This means:
- Ascense is not a single point of failure for customer network connectivity.
- Deployment does not require network topology changes.
- Response adapters are allowlisted, scoped, and audited — not arbitrary control-plane access.

Inline inspection is a future product capability, not a v1 requirement.

---

## Six Ascense Layers + External Customer Environment

```
External Customer Environment (not an Ascense layer)
  Network devices, servers, applications, firewalls, DNS, security events

─────────────────────────────────────────────────────────────────────

Layer 1 · Collection and Gateway
  Gateway agent · Suricata/Zeek sensors · Local buffer · Secure command client
  Collect, timestamp, identify source, securely forward.
  The gateway must never invent tenant identity.

Layer 2 · Ingestion and Normalization
  Gateway auth · Schema validation · Tenant binding
  Deduplication · Event normalization · Queue
  Convert sensor formats into one canonical CloudEvents envelope.

Layer 3 · Detection and Correlation
  Rules engine · Statistical detection · ML inference
  Threat intelligence · Correlation
  Produce findings with evidence and detector provenance. Never issue commands.

Layer 4 · Investigation
  Incident context builder · Read-only tools · LLM investigation · RAG/runbooks
  Explain, connect evidence, identify uncertainty, propose actions only.

Layer 5 · Decision and Enforcement
  Deterministic policy engine · Approval workflow
  Response orchestrator · Gateway adapter · Verification
  Sole path that may execute a response. AI recommendations are not commands.

Layer 6 · Application and Visibility
  React dashboard · Alert and incident management
  Approval UI · Audit history · Admin settings
  Display data and request operations through the API. Never enforce permissions.

─────────────────────────────────────────────────────────────────────

Shared Platform Services (used by all layers)
  Identity and access · Tenant registry · PostgreSQL
  RabbitMQ · Object storage (S3/MinIO) · Secrets/KMS
  OpenTelemetry · Audit log · Redis
```

---

## Four Architectural Planes

The six-layer view explains data flow. The four-plane view governs access control and deployment isolation.

| Plane | Contains | Primary responsibility |
|---|---|---|
| Customer data plane | Customer sensors, network telemetry, gateway agent | Observe and collect |
| Cloud control plane | APIs, tenant management, gateway registry, policies, configuration | Manage and control the platform |
| Analytics and investigation plane | Event processing, detection, ML, correlation, AI investigation | Understand security activity |
| Enforcement plane | Approval, signed commands, adapters, verification | Perform authorized security actions |

The LLM investigation worker belongs to the analytics plane. It must not share permissions or execution environment with the response service in the enforcement plane.

---

## Five Required Platform Components

These components are required by the architecture. For v1 they may be modules inside the platform API rather than separate deployed services. Their responsibilities and data models must be defined before implementation begins.

### 1 · Asset Registry

Tracks what belongs to the customer: servers, devices, network segments, services, and protected infrastructure.

Stores: ownership, IP history, criticality, environment, location, gateway association, asset status.

Why it matters: response decisions cannot safely operate without knowing what the target actually is. A block action targeting an IP address is not the same as isolating the asset at that address.

### 2 · Evidence Management

Stores and retrieves original events, normalized events, logs, investigation references, and permitted packet evidence.

Why it matters: AI investigations need traceable evidence with retrievable IDs, not copied text or explanations.

Evidence records and raw evidence objects have distinct retention policies. Define retention periods by data category before implementation. Do not apply indefinite retention to all evidence simply because the audit log is append-only.

### 3 · Model Registry

Maintains model versions, training metadata, approved feature schemas, evaluation results, deployment status, and rollback versions.

Why it matters: Ascense must know exactly which model version generated a detection finding, and must be able to roll back a model without losing the audit trail.

### 4 · Device Identity and Certificate Management

Manages gateway enrollment, certificate issuance, renewal, rotation, revocation, and recovery.

Why it matters: the gateway is the identity of a customer-side deployment. Its certificate is the root of trust for all telemetry and command authorization.

Gateway certificates must be renewable and revocable without losing telemetry continuity. Private keys must be stored with OS-level protection. The gateway must not accept arbitrary commands from the cloud — only signed, allowlisted actions through approved adapters.

### 5 · Policy and Configuration Registry

Maintains versioned detection rules, tenant configurations, response policies, allowed action types, and asset restrictions.

Why it matters: the gateway, detection engine, and response service must use compatible, traceable policy versions. A command must reference the policy version that authorized it.

### Firewall integration credential boundary

When a response adapter manages a customer's existing firewall or security product, the gateway holds the integration credentials for that product. These credentials must be:
- Narrowly scoped to the minimum permissions required for the allowlisted actions
- Never distributed as broad administrative credentials
- Stored with the same OS-level protection as the gateway private key
- Rotatable without requiring gateway re-enrollment

Ascense cloud services must never hold or transmit customer firewall credentials directly.

---

## Trust Boundaries

| Component | Trust level | Permitted responsibility |
|---|---|---|
| Customer gateway | Authenticated, not fully trusted | Collect events; receive commands addressed to itself |
| Ingestion API | Trusted platform service | Authenticate gateway, establish tenant identity, validate and normalize events |
| Detection workers | Trusted, limited permissions | Read normalized events; create detection findings |
| Investigation agent | Untrusted output, restricted tools | Read approved evidence; produce findings or action proposals |
| Policy engine | Authoritative for action permission | Evaluate whether an action is allowed under deterministic policies |
| Approval service | Authoritative for human approval | Record who approved what, for which target, and until when |
| Response service | Sole enforcement authority | Issue signed, authorized commands through approved adapters |
| Dashboard | User interface, not an authority | Display data; request authorized operations through the API |

### Non-negotiable rules

1. The AI agent must never directly execute firewall, shell, database, or identity-provider commands.
2. The browser must never be trusted to enforce permissions. The backend checks authorization on every request.
3. The gateway must not decide which tenant it belongs to by sending a `tenant_id` in its payload. The platform derives and verifies that identity from the authenticated gateway registration.
4. The gateway initiates outbound authenticated connections to retrieve commands. Ascense does not open arbitrary inbound access into customer networks.
5. Use `FAIL_CLOSED` for authorization and command execution. If Ascense cannot prove an action is permitted, it must not issue it. This is separate from gateway traffic handling — a gateway continues passing traffic when Ascense is offline; it simply cannot receive new response commands.

---

## Runtime Workflow

### A · Onboarding and gateway registration

1. Platform admin creates a tenant record and its initial administrator membership.
2. Ascense creates a short-lived, single-use enrollment token tied to the tenant and gateway registration.
3. Gateway agent enrolls, receives a unique identity and certificate, stores its private key securely.
4. Gateway sends heartbeats, reports installed sensors and software version, receives configuration.

Trusted mapping established: `tenant_id → gateway_id → gateway_certificate`

### B · Telemetry collection and ingestion

1. Sensor produces an event with its own source identifier.
2. Agent normalizes to the agreed schema; raw source information and the original `source_event_id` are preserved.
3. Agent sends a batch to the authenticated ingestion endpoint.
4. Ingestion service verifies certificate, derives tenant binding from the authenticated gateway identity, validates event structure, timestamps, and payload limits.
5. Deduplication checks `(source, id)` — the CloudEvents uniqueness pair — not the caller-supplied payload fields.
6. If an event references an IP address or host not yet in the asset registry, the event is stored with `asset_resolution.status: UNRESOLVED`. It is not dropped. Asset resolution runs asynchronously and can associate the event with an asset after verification.
7. Valid events are stored; processing messages are published via the transactional outbox.

Ingestion acknowledges receipt after durable acceptance — not after detection completes.

### C · Detection and alert creation

1. Detection worker consumes normalized events.
2. Executes deterministic rules and selected ML models.
3. Each detector returns a **detection finding** with `detection_finding_id`, detector identity, version, score, and confidence.
4. Correlation groups related findings into **alerts**; related alerts may be grouped into **incidents**.

Detection output is a finding, not an authorization to act.

### D · Investigation

1. Incident context builder collects relevant alerts, events, assets, and historical evidence.
2. Investigation agent receives only the evidence and tools permitted for that tenant and investigation.
3. Agent identifies possible causes, supporting evidence, missing evidence, and uncertainty.
4. Produces an investigation report with evidence references.
5. May propose an action — that proposal must pass through the independent policy and approval workflow.

The AI must reference real, retrievable evidence. It must not invent events, assets, or findings.

### E · Response, approval, and verification

```
Investigation creates action proposal
        |
        v
Policy engine evaluates
(tenant, target, asset criticality, action allowlist,
 TTL, policy version, scope)
        |
   +---------+
   |         |
REJECTED  PENDING_APPROVAL
              |
              v
         Human approves
         (identity, role, decision, reason, time,
          proposal version, approval expiry)
              |
              v
   Response service creates signed command
   (bound to tenant, gateway, target, action,
    expiry, approval_id, policy_version_id,
    nonce, idempotency_key, cryptographic signature)
              |
              v
   Gateway claims command via POST .../commands:claim
   (atomic lease for a defined period)
              |
              v
   Gateway validates signature, expiry, idempotency,
   target criticality, and current policy
              |
              v
   Gateway executes through allowlisted adapter
   (no arbitrary shell commands)
              |
              v
   Gateway reports actual enforcement state
   Ascense verifies result by independent read-back where possible
   Timeline records complete outcome
```

A successful HTTP response from the gateway is not proof of containment. Record the execution result and verify actual enforcement state. If the state is unknown, escalate — do not claim success.

Execution status and verification status are tracked as two separate fields on the execution attempt record:
- `execution_status: FAILED` — gateway confirmed that execution did not succeed
- `execution_status: UNKNOWN` — gateway cannot determine the actual enforcement state; escalate
- `execution_status: SUCCEEDED` — gateway confirmed the action completed; does not imply independent verification
- `verification_status: VERIFIED` — response verification service independently confirmed the enforcement state is in effect
- `verification_status: NOT_VERIFIED` — read-back confirmed the enforcement state is not in effect
- `verification_status: UNKNOWN` — verification could not be completed

For critical controls, prefer an independent read-back from the firewall or security product's authorized management interface rather than relying exclusively on the agent's claim.

### F · Telemetry health monitoring

A separate flow runs continuously alongside event processing:

```
Gateway heartbeat
      |
Sensor health status per sensor
      |
Events received per sensor per time window
      |
Last event timestamp
      |
Ingestion delay and rejection rate
      |
Telemetry coverage status
      |
Dashboard / operational alerts
```

Gateway and sensor health states:

| State | Meaning |
|---|---|
| `HEALTHY` | Heartbeat current, sensors reporting, events arriving |
| `DEGRADED` | Heartbeat current but one or more sensors not reporting |
| `DISCONNECTED` | No heartbeat within the expected window |
| `SENSOR_FAILURE` | Specific sensor process has stopped or is erroring |
| `TELEMETRY_STALE` | Events have not arrived within the expected freshness window |
| `UNKNOWN` | No baseline established yet |

If a customer's Suricata process crashes, Ascense must not show a green status implying no attacks. It must show that visibility has been lost. This is a security product requirement, not a monitoring convenience.

---

## Deployment Architecture

| Deployment | Technology | Responsibility |
|---|---|---|
| Web application | React + TypeScript | Dashboard, alerts, incidents, investigations, approvals, admin |
| Platform API | Python + FastAPI | Auth, tenant management, APIs, authorization, gateway registry, asset registry, evidence access, ingestion, audit |
| Background workers | Python workers | Normalization, detection, correlation, investigation, policy evaluation, response orchestration |
| Gateway agent | Go or Python | Sensor collection, local buffer, event transmission, heartbeat, command polling, execution adapters |

**Infrastructure:** PostgreSQL · RabbitMQ · Redis · S3/MinIO · Docker Compose (initial)

### Why this arrangement

- API and workers scale and restart independently.
- Gateway can be tested without running the full platform.
- Any module can be extracted into its own service later without changing its public contract.
- No premature microservice overhead before features are proven.

### Transactional outbox pattern

Do not write an event to PostgreSQL and publish to RabbitMQ as two separate unrelated operations.

1. Ingestion validates the event.
2. Saves the event and an outbox record in the same database transaction.
3. Publisher worker reads pending outbox records and publishes them to the broker.
4. Publisher marks each record as published.
5. Consumer processes idempotently.
6. Failed messages retry; repeated failures go to a dead-letter queue for inspection.

Design for at-least-once delivery. Duplicate delivery is expected and handled safely, not assumed impossible.

---

## Domain Ownership Structure

```
Tenant
 ├── Users / Memberships
 ├── Gateways
 │    ├── Certificates
 │    ├── Sensors
 │    └── Configurations
 ├── Assets
 ├── Events (source events + normalized events)
 ├── Detection Findings
 │    └── Alerts
 │          └── Incidents
 │                ├── Evidence
 │                ├── Investigations
 │                └── Proposals
 │                      └── Approvals
 │                            └── Commands
 │                                  └── Execution Attempts
 └── Audit Records
```

PostgreSQL holds authoritative metadata for all entities. Large evidence objects (packet captures, raw logs) live in object storage; PostgreSQL holds their references and access controls.

---

## Technology Decisions

| Decision | Choice |
|---|---|
| Frontend | React + TypeScript |
| API | Python + FastAPI |
| Detection and AI | Python modules/workers |
| Database | PostgreSQL |
| Message broker | RabbitMQ |
| Cache | Redis |
| Evidence storage | S3-compatible object storage |
| Event envelope | CloudEvents 1.0 |
| HTTP API contract | OpenAPI 3.2.1 |
| Error contract | RFC 9457 Problem Details |
| Internal identifiers | UUIDv7 (RFC 9562) |
| Distributed tracing | W3C Trace Context (`traceparent`) |
| Authentication | OIDC-compatible user auth; mTLS gateway identity |
| Authorization | RBAC + tenant-scoped resource checks |
| Deployment | Docker Compose initially |
| Monitoring | OpenTelemetry |
| Response model | Human-approved, policy-validated actions |
| Gateway model | Out-of-band monitoring with allowlisted response adapters |
| Versioning | Versioned APIs, event schemas, model artifacts, policies |

Freeze these before development starts. Record rationale in `docs/adr/`. Do not introduce Kafka, Kubernetes, multiple databases, or per-feature microservices unless actual scale or deployment needs justify the complexity.

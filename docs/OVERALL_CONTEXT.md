# ASCENSE — Product Vision, Architecture, Workflow & Engineering Contracts

## 1. Product vision

Ascense is an **AI-assisted, evidence-driven Security Operations and Cyber Defense Platform** designed to help organizations observe their infrastructure, detect suspicious activity, investigate threats, make informed security decisions, and execute authorized responses safely.

The central idea is to connect the entire security operations lifecycle:

**Observe → Detect → Correlate → Investigate → Decide → Respond → Verify**

Traditional security tools often operate in isolation:
- Sensors generate enormous volumes of telemetry.
- Detection systems produce alerts, often with limited context.
- Analysts manually investigate relationships between alerts.
- Response decisions are made using fragmented information.
- Security actions are executed through separate tools.
- Actual containment is not always independently verified.

Ascense aims to connect these activities into one coherent, auditable workflow.

It should not merely generate alerts or provide an AI chatbot. It should establish a reliable chain from original security evidence to verified security outcomes.

### Core product capabilities

1. **Observe:** Collect telemetry from customer infrastructure.
2. **Detect:** Identify suspicious activity using deterministic rules, statistical methods and justified ML models.
3. **Correlate:** Connect related findings into actionable alerts and incidents.
4. **Investigate:** Build evidence-backed explanations using contextual analysis and constrained AI.
5. **Decide:** Evaluate proposed responses through deterministic security policies and human authorization.
6. **Act:** Execute narrowly scoped, authorized actions through customer-side adapters.
7. **Verify:** Independently confirm whether the intended security state was achieved.

### The fundamental design philosophy

Ascense must prioritize:

- Evidence over assumptions.
- Deterministic security controls over unrestricted AI decisions.
- Reliability over feature count.
- Measurable performance over theoretical scalability.
- Controlled automation over unrestricted autonomy.
- Explainability and traceability over black-box conclusions.
- Graceful degradation over total system failure.

An AI-generated explanation is not evidence. A detection score is not automatically an attack probability. A successful command acknowledgement is not proof of containment.

Every important conclusion and action must be traceable to evidence.

---

## 2. Product boundary and deployment philosophy

### First-release scope

The initial product focuses on:

**Network Threat Detection and Assisted Response.**

It includes:

- Network telemetry collection.
- Gateway authentication and event ingestion.
- Event normalization and durable storage.
- Rule-based and selected ML-based detection.
- Alert and incident correlation.
- Evidence-backed AI investigation.
- Deterministic policy evaluation.
- Human-approved response actions.
- Controlled gateway execution.
- Independent verification.
- A dashboard for visibility and operations.

The first release does not attempt to implement every possible cybersecurity capability.

It excludes:
- Unrestricted autonomous blocking.
- Full WAF, API, database, identity and endpoint protection.
- Every proposed ML model.
- Game-theoretic optimization.
- Every possible third-party integration.

These are potential future extensions, not reasons to complicate the first release.

### Deployment model: out-of-band monitoring

Customer network traffic does not pass through Ascense.

Instead:

1. Existing network infrastructure continues operating normally.
2. Sensors such as Suricata and Zeek observe traffic and generate telemetry.
3. The customer-side gateway collects and forwards that telemetry.
4. Ascense analyzes the events centrally.
5. If an authorized response is required, Ascense sends a constrained command to the gateway.
6. The gateway interacts with an existing firewall or security control through an approved adapter.

This avoids making Ascense a single point of failure for customer network connectivity.

Inline inspection is a possible future capability, not a first-release requirement.

---

## 3. The six-layer architecture

Ascense follows a six-layer modular architecture, supported by shared platform services.

Each layer has a clear responsibility and explicit permissions.

### Layer 1 — Collection and Gateway

**Purpose: Collect security telemetry reliably from the customer's environment.**

Components:
- Customer-side gateway agent.
- Suricata and Zeek integrations.
- Sensor/process monitoring.
- Local event buffer.
- Batch transmission.
- Secure command client.
- Gateway execution journal.

Responsibilities:

1. Collect events from configured sensors.
2. Preserve original sensor identifiers and source information.
3. Timestamp and identify sensor instances.
4. Buffer events locally during network interruptions.
5. Batch and forward events securely.
6. Report gateway and sensor health.
7. Receive authorized commands.
8. Execute only allowlisted actions through approved adapters.

Important requirements:

- The gateway must preserve event identity across retries.
- It must not invent or accept arbitrary tenant identity.
- It must not execute arbitrary shell commands received from the cloud.
- It must use secure certificate-based identity.
- It must persist an execution journal before executing a response.
- It must reconcile execution state after reconnection.

The gateway is authenticated, but it is not fully trusted.

### Layer 2 — Ingestion and Normalization

**Purpose: Establish trusted identity, validate incoming telemetry and convert it into canonical events.**

Components:
- FastAPI ingestion endpoints.
- Gateway authentication.
- Tenant binding.
- Schema validation.
- Payload-size enforcement.
- Batch validation.
- Deduplication.
- Event persistence.
- Transactional outbox.
- Normalization workers.

Responsibilities:

1. Authenticate the gateway using mTLS.
2. Derive the tenant from the authenticated gateway registration.
3. Verify the gateway identity and tenant association.
4. Validate event schemas and supported event types.
5. Enforce payload and batch limits.
6. Identify duplicates.
7. Preserve valid original event information.
8. Persist accepted events.
9. Publish downstream processing messages reliably.
10. Normalize different sensor formats into a common schema.

A sensor event may not immediately map to a known asset. Such events should be retained with an explicit unresolved asset status and resolved asynchronously rather than discarded.

**Important:** Ingestion acknowledges durable acceptance, not completed detection.

### Layer 3 — Detection and Correlation

**Purpose: Convert normalized telemetry into actionable security findings and incidents.**

Components:
- Deterministic rule engine.
- Statistical detection.
- Selected ML inference models.
- Threat intelligence integration.
- Feature extraction.
- Time-window processing.
- Correlation engine.
- Alert and incident management.

Responsibilities:

1. Consume normalized events.
2. Run applicable detection rules.
3. Evaluate selected ML models where justified.
4. Preserve detector and model provenance.
5. Generate detection findings.
6. Correlate related findings.
7. Promote findings into actionable alerts.
8. Group related alerts into incidents.
9. Maintain incident lifecycle and evidence relationships.

The detection engine must not directly create executable response commands.

It produces findings. Correlation decides how those findings become alerts and incidents.

### Layer 4 — Investigation

**Purpose: Understand why an incident occurred and establish what the available evidence supports.**

Components:
- Incident context builder.
- Evidence retrieval.
- Read-only investigation tools.
- LLM investigation agent.
- RAG and security runbooks.
- Investigation reports.
- Recommendation generation.

Responsibilities:

1. Retrieve relevant incident, alert, event and asset context.
2. Collect authorized evidence references.
3. Examine relevant historical activity.
4. Identify possible attack explanations.
5. Distinguish supported conclusions from hypotheses.
6. Identify missing evidence and uncertainty.
7. Produce a structured investigation report.
8. Recommend possible response actions.

The AI investigation agent is restricted to approved, read-only tools.

It cannot directly:
- Execute firewall commands.
- Modify security policies.
- Change tenant configurations.
- Execute shell commands.
- Approve its own recommendations.
- Set execution or verification status.

An AI recommendation is a proposal, not authorization.

### Layer 5 — Decision and Enforcement

**Purpose: Convert a proposed response into a safe, authorized and verifiable security action.**

Components:
- Deterministic policy engine.
- Policy and configuration registry.
- Approval workflow.
- Response orchestrator.
- Command signing.
- Command dispatcher.
- Gateway response adapter.
- Execution tracking.
- Independent verification.
- Rollback and reconciliation.

Responsibilities:

1. Receive an action proposal.
2. Validate its target and parameters.
3. Evaluate tenant restrictions and asset criticality.
4. Check action allowlists and policy versions.
5. Enforce risk limits and approval requirements.
6. Obtain human authorization where required.
7. Create a signed, scoped and expiring command.
8. Deliver it to the correct authenticated gateway.
9. Track execution attempts.
10. Verify the actual enforcement state.
11. Handle failures, partial execution and rollback.
12. Maintain an auditable response timeline.

**This is the only layer authorized to execute security responses.**

The AI agent never bypasses it.

### Layer 6 — Application and Visibility

**Purpose: Give security analysts and administrators a clear operational view of the platform.**

Components:
- React and TypeScript dashboard.
- Alert management.
- Incident management.
- Investigation reports.
- Evidence inspection.
- Approval interface.
- Response history.
- Gateway and sensor health.
- Administrative settings.

Responsibilities:

- Display alerts and incidents.
- Present evidence and investigation results.
- Show response proposals and approval requirements.
- Allow authorized analysts to review and approve actions.
- Show command and execution history.
- Display telemetry health and operational status.
- Provide administrative and tenant-management interfaces.

The frontend is not a security authority.

All permissions and state transitions must be enforced by the backend.

### Shared platform services

These services support multiple layers rather than belonging exclusively to one layer.

| Service | Responsibility |
|---|---|
| Identity and access | User authentication, workload identity and authorization |
| Tenant registry | Tenant ownership and isolation |
| PostgreSQL | Durable authoritative application and domain records |
| RabbitMQ | Asynchronous event and task delivery |
| Redis | Caching, temporary state and acceleration where justified |
| S3/MinIO | Large evidence-object storage |
| Secrets/KMS | Key and secret management |
| Audit service | Security-relevant activity history |
| OpenTelemetry | Distributed traces, metrics and instrumentation |
| Asset registry | Protected infrastructure ownership and criticality |
| Evidence management | Traceable evidence records and retrieval |
| Model registry | Model versions, metadata, evaluation and deployment status |
| Device identity management | Gateway enrollment, certificates and revocation |
| Policy/configuration registry | Versioned rules, configurations and response policies |

Redis is not the system of record. PostgreSQL owns durable application state. Large evidence objects can live in object storage, with metadata and authorization references maintained in PostgreSQL.

---

## 4. The four architectural planes

The six layers explain responsibilities. The four planes explain security boundaries and deployment separation.

| Plane | Responsibility |
|---|---|
| Customer data plane | Customer infrastructure, sensors, telemetry and gateway |
| Cloud control plane | APIs, tenant management, gateway registry, identity and configuration |
| Analytics and investigation plane | Processing, normalization, detection, ML, correlation and AI investigation |
| Enforcement plane | Policy evaluation, approval, command signing, execution and verification |

An important isolation rule:

The LLM investigation worker belongs to the analytics and investigation plane. It must not share execution permissions or an unrestricted runtime with the enforcement service.

---

## 5. The complete 13-stage workflow

The six layers contain the following logical end-to-end pipeline.

The stages are asynchronous where appropriate. They do not all need to execute in one synchronous request.

### Stage 1 — Sensor Collection

Suricata, Zeek, firewall logs and other approved sources generate security telemetry.

Examples:
- Network connections.
- DNS activity.
- Suspicious traffic patterns.
- IDS alerts.
- Firewall events.

### Stage 2 — Gateway Buffering

The customer-side gateway collects events and prepares them for transport.

It handles:
- Local buffering.
- Batching.
- Compression where beneficial.
- Retry management.
- Backpressure.
- Stable event identifiers.
- Sensor health reporting.

If the cloud is temporarily unavailable, the gateway should retain events within configured storage limits and recover without silently losing track of telemetry.

### Stage 3 — Ingestion

The cloud ingestion service authenticates the gateway, verifies tenant ownership, validates the payload and applies admission controls.

It handles:
- Authentication.
- Tenant binding.
- Payload limits.
- Schema validation.
- Deduplication.
- Durable acceptance.

### Stage 4 — Message Broker

RabbitMQ distributes accepted processing work to the appropriate consumers.

It provides:
- Asynchronous decoupling.
- Queue separation.
- Acknowledgements.
- Retry and backoff.
- Dead-letter handling.
- Consumer coordination.

The system must tolerate at-least-once delivery.

Duplicate delivery is expected and must be handled through idempotent consumers.

### Stage 5 — Storage

PostgreSQL stores authoritative records, including:
- Event metadata.
- Normalized events.
- Findings.
- Alerts.
- Incidents.
- Evidence references.
- Investigations.
- Proposals.
- Approvals.
- Commands.
- Execution attempts.
- Audit records.

Large evidence objects may be stored in S3-compatible storage.

Retention and archival policies must distinguish raw telemetry, normalized data, evidence and audit records.

### Stage 6 — Normalization

Different sensor formats are transformed into a canonical event representation.

The normalized schema must preserve:
- Original source identity.
- Sensor identity.
- Event timestamp.
- Tenant and gateway context.
- Event type.
- Relevant network fields.
- Asset-resolution status.
- Schema version.

Normalization must not destroy the original evidence.

### Stage 7 — Detection

The detection pipeline evaluates events using a cascade of appropriate methods:

1. Deterministic rules.
2. Statistical detection.
3. Selected ML models.
4. Threat intelligence enrichment.
5. Additional analysis when justified.

Not every event needs every model.

Each detector produces a finding with detector provenance, version, evidence references, score and confidence.

### Stage 8 — Correlation

Related findings are grouped using meaningful relationships such as:
- Affected asset.
- Network entity.
- Indicator.
- Finding type.
- Time window.
- Event relationships.
- Repeated activity.

The output is an actionable alert, and related alerts may be grouped into an incident.

Correlation must avoid grouping unrelated findings merely because they occurred close together in time.

### Stage 9 — Investigation

The investigation service builds context around an incident.

It retrieves:
- Related alerts.
- Original and normalized events.
- Asset information.
- Historical activity.
- Existing evidence.
- Relevant security runbooks.

The AI investigation agent uses this bounded context to produce an evidence-backed report.

### Stage 10 — Proposal

The investigation or an authorized analyst may propose a response.

A proposal must define:
- Intended action.
- Exact typed target.
- Affected assets.
- Parameters and duration.
- Reason.
- Supporting evidence.
- Applicable policy version.
- Expiry.
- Approval requirements.

A proposal is not executable.

### Stage 11 — Policy and Approval

The deterministic policy engine evaluates the proposal.

It considers:
- Tenant ownership.
- Target validity.
- Asset criticality.
- Protected-asset restrictions.
- Allowed action types.
- Parameters and duration.
- Risk and uncertainty.
- Policy version.
- Rate-of-change restrictions.
- Approval requirements.

The result may be rejection or a requirement for human approval.

High model confidence cannot override a hard policy prohibition.

### Stage 12 — Command Creation

After authorization, the response service creates a cryptographically signed command.

The command is bound to:
- Tenant.
- Gateway.
- Exact target.
- Action and parameters.
- Proposal.
- Approval.
- Policy version.
- Creation and expiry time.
- Nonce.
- Idempotency key.

The gateway must be able to verify the command independently.

The intended design uses asymmetric signing, such as Ed25519: the cloud response service holds the signing key and the gateway verifies using the corresponding public key.

### Stage 13 — Execution and Verification

The gateway claims the command through an authenticated outbound connection.

It:
1. Validates the signature.
2. Checks expiry and replay protection.
3. Checks idempotency.
4. Checks target and current authorization constraints.
5. Persists the execution journal.
6. Executes through an allowlisted adapter.
7. Reports the execution result.

Ascense then independently verifies the actual enforcement state where possible.

If execution or verification is uncertain, the system records that uncertainty and escalates. It must never claim successful containment without sufficient evidence.

---

## 6. Canonical contracts and domain model

All shared interfaces must have one authoritative definition in the `contracts/` directory.

No module or developer should invent private versions of shared events, identifiers or statuses.

### Identifier conventions

All internally generated entity IDs use UUIDv7, serialized as lowercase strings.

`trace_id` is different: it follows W3C Trace Context and is a 32-character lowercase hexadecimal value.

Important identifiers:

| Identifier | Meaning |
|---|---|
| `tenant_id` | Customer organization |
| `user_id` | Internal user identity |
| `gateway_id` | Installed gateway |
| `asset_id` | Protected asset |
| `source_event_id` | Original sensor event identifier |
| `event_id` | Ascense normalized event record |
| `detection_finding_id` | One detector output |
| `alert_id` | Correlated actionable finding |
| `incident_id` | Security case |
| `evidence_id` | Stored evidence record |
| `investigation_id` | Investigation run |
| `proposal_id` | Proposed response |
| `approval_id` | Human authorization |
| `command_id` | Signed executable command |
| `execution_attempt_id` | One execution attempt |
| `policy_version_id` | Immutable policy revision |
| `model_version_id` | Model revision |
| `request_id` | Individual API request |
| `trace_id` | Distributed trace |

Every tenant-owned record must carry a `tenant_id`.

Possessing an ID is never proof of authorization.

The backend derives tenant context from authenticated identity. A caller must never be able to change ownership by editing a request payload.

### Canonical event contract

Events use the CloudEvents 1.0 envelope.

The uniqueness pair is:

`UNIQUE(source, id)`

For Ascense, the source identifies both the gateway and the individual sensor instance:

`urn:ascense:gateway:{gateway_id}/sensor/{sensor_instance_id}`

The event ID must remain stable across retransmission retries.

The event contains:
- CloudEvents metadata.
- Original sensor event ID.
- Sensor identity and version.
- Event type.
- Timestamp.
- Schema version.
- Network or security event data.
- Asset-resolution information.

Tenant and gateway values in the payload must be verified against authenticated gateway identity. They are not trusted merely because they were submitted.

Deduplication must be durable and atomic under concurrent requests.

### Domain distinction: Finding → Alert → Incident

These are three separate objects.

| Object | Meaning |
|---|---|
| Detection finding | Output of one detector run |
| Alert | Actionable security finding created by correlation |
| Incident | Security case containing related alerts, assets, evidence, investigations and responses |

A detection engine creates findings. It does not independently decide that a customer-facing incident exists.

### Investigation result

An investigation result contains:
- Investigation identity.
- Incident identity.
- Status.
- Summary.
- Assessment and uncertainty.
- Evidence references.
- Recommendations.

Every evidence reference must identify real, retrievable and authorized evidence.

An AI explanation is not itself evidence.

### Response proposal

A proposal contains:
- `proposal_id`
- `tenant_id`
- `incident_id`
- `action_type`
- Typed `target`
- `affected_asset_ids`
- Parameters
- Reason
- Evidence references
- `policy_version_id`
- Expiry
- Proposal status

The enforcement target and the affected assets are different concepts.

For example, a network indicator being blocked is the target; the protected servers whose security posture changes are the affected assets.

AI must never generate arbitrary shell commands or firewall expressions.

---

## 7. The four separate response state machines

Proposal, approval, command and execution are not one lifecycle.

They must remain separate.

### A. Proposal lifecycle

`DRAFT → SUBMITTED → POLICY_EVALUATION`

Possible outcomes:
- `REJECTED`
- `EXPIRED`
- `APPROVAL_PENDING`

### B. Approval lifecycle

`PENDING → APPROVED`

Other outcomes:
- `REJECTED`
- `EXPIRED`
- `REVOKED`

Approval records must include:
- Approver identity.
- Role.
- Decision.
- Reason.
- Timestamp.
- Proposal version.
- Expiry.

High-impact proposals must not be approved by their creator. Critical actions may require a second authorized approver.

### C. Command lifecycle

`QUEUED → LEASED → ACKNOWLEDGED`

Other outcomes:
- `EXPIRED`
- `CANCELLED`

Important rules:

- `QUEUED` means waiting to be claimed.
- `LEASED` means atomically claimed by the gateway.
- `ACKNOWLEDGED` means the gateway accepted receipt.
- `EXPIRED` means the command or lease window elapsed.
- `CANCELLED` means explicitly cancelled.

`DISPATCHED` is an audit event, not a command state.

If a lease expires before acknowledgement, the same command returns to `QUEUED`. Do not create a replacement command simply because delivery was interrupted.

### D. Execution attempt lifecycle

`NOT_STARTED → RUNNING`

Possible outcomes:

- `SUCCEEDED`
- `FAILED`
- `PARTIALLY_SUCCEEDED`
- `UNKNOWN`
- `ROLLBACK_PENDING`
- `ROLLED_BACK`
- `ROLLBACK_FAILED`

These statuses describe what happened during execution.

### E. Verification lifecycle

`PENDING → VERIFIED`

Other outcomes:
- `NOT_VERIFIED`
- `UNKNOWN`

Verification is independent of execution.

For example:

`execution_status = SUCCEEDED`

does not imply:

`verification_status = VERIFIED`

Only the gateway reports execution status. Only the response verification service sets verification status.

A service may perform only the state transitions it owns.

---

## 8. Critical reliability, optimization and failure-handling requirements

The architecture must be designed for hostile traffic, partial outages and component failures.

### A. Gateway and ingestion reliability

Requirements:
- Local buffering.
- Batching and bounded compression.
- Backpressure.
- Configurable payload and batch limits.
- Gateway authentication.
- Tenant binding.
- Stable event identity.
- Atomic deduplication.
- Admission control.
- Partial batch acceptance.
- Durable acceptance acknowledgement.

The system must prevent oversized or high-volume requests from exhausting application memory or database resources.

### B. Event accounting

Maintain an explicit accounting invariant:

`Accepted events = Processed events + Pending events + Explicitly quarantined events`

Duplicates and documented retention/deletion must be accounted for separately.

Do not silently lose accepted events.

### C. Reliable broker processing

Use RabbitMQ with:
- Appropriate queue separation.
- Publisher confirms.
- Durable message handling.
- Consumer acknowledgements.
- Idempotent consumers.
- Bounded retries and backoff.
- Dead-letter queues.
- Poison-message handling.
- Backpressure.
- Recovery procedures.

Avoid infinite requeue loops.

Use a transactional outbox whenever a database transaction must reliably produce a downstream message.

The intended pattern:

1. Persist the business record and outbox record in one database transaction.
2. Publish the outbox record.
3. Mark it published.
4. Consume idempotently.
5. Retry boundedly.
6. Quarantine repeatedly failing messages for investigation.

### D. Storage efficiency

PostgreSQL is the durable source of truth.

Use:
- Appropriate indexes.
- Time-based partitioning where justified.
- Batched writes.
- Connection-pool limits.
- Retention and archival policies.
- Efficient queries.
- Object storage for large evidence objects.

Redis may accelerate frequently accessed or temporary data.

It must not become a second authoritative database.

Avoid persisting every raw event indefinitely without a retention strategy.

### E. Detection efficiency

Do not run expensive ML models against every event by default.

Use a detection cascade:
1. Cheap deterministic filtering.
2. Relevant rules.
3. Window-based statistical analysis.
4. Selected ML inference.
5. Further investigation only when justified.

Evaluate detectors against labelled benign and attack scenarios.

Measure false positives, false negatives, detection latency and resource cost.

A score of 85/100 is not automatically an 85% probability of an attack.

### F. Correlation efficiency and correctness

Use meaningful entity and time-window relationships.

Prevent:
- Unrelated alerts being grouped together.
- Duplicate alerts on redelivery.
- Duplicate incidents.
- Unbounded correlation windows.
- Expensive repeated database queries.

Correlation decisions must be explainable and traceable.

### G. AI investigation controls

AI must be bounded by:
- Tenant-scoped evidence access.
- Read-only tools.
- Structured outputs.
- Evidence references.
- Token and time budgets.
- Prompt-injection protections.
- Explicit uncertainty.
- Investigation-level deduplication and persistence.

Do not launch an expensive LLM investigation for every raw event.

Investigation should generally occur at the incident level.

If the AI provider becomes unavailable, deterministic detection must continue. The incident should remain available for later investigation, with an honest status.

### H. Safe response controls

Every action must pass through:
- Typed action validation.
- Deterministic policy evaluation.
- Asset criticality checks.
- Tenant authorization.
- Approval requirements.
- Expiry checks.
- Command signing.
- Replay protection.
- Idempotency.
- Gateway-side validation.
- Independent verification.

Customer firewall credentials remain on the customer-side gateway, protected by OS-level security. Cloud services must not hold or transmit broad customer firewall credentials.

### I. Gateway disconnect during execution

This scenario is especially important.

Suppose a gateway receives a command, begins an operation, and disconnects before reporting its result.

Ascense must not assume that the operation failed or succeeded.

The gateway's durable execution journal must allow it to reconcile the same command after reconnection.

If the actual enforcement state cannot be established:

- Report `UNKNOWN`.
- Do not blindly repeat the operation.
- Reconcile with the firewall's actual state.
- Escalate to a human when necessary.

### J. Telemetry visibility

A silent sensor failure must never look like an absence of attacks.

Monitor:
- Gateway heartbeat.
- Sensor health.
- Events received per sensor.
- Last event timestamp.
- Ingestion delay.
- Rejection rate.
- Processing backlog.
- Oldest unprocessed message age.

Possible health states:

`HEALTHY`, `DEGRADED`, `DISCONNECTED`, `SENSOR_FAILURE`, `TELEMETRY_STALE`, `UNKNOWN`.

If a sensor stops reporting, the dashboard must show lost visibility rather than green status.

---

## 9. Performance and security validation

Performance expectations must be measured, not assumed.

The earlier engineering design proposed representative traffic targets such as:

| Workload | Proposed target |
|---|---:|
| Normal traffic | 500 events/sec |
| Moderate traffic | 2,000 events/sec |
| High burst | 10,000 events/sec |
| Sustained workload | 5,000 events/sec for 30 minutes |

These are proposed validation targets, not claims about current capacity.

Validation should include:

- Duplicate-heavy traffic.
- High-cardinality events.
- Large batches.
- Slow database writes.
- Database connection saturation.
- RabbitMQ outage.
- Redis outage.
- Gateway disconnection.
- AI provider outage.
- Worker crashes.
- Delayed and out-of-order events.
- Tenant isolation attacks.
- Replayed commands.
- Stale approvals.
- Rollback failures.

Measure:
- Throughput.
- End-to-end processing latency.
- Queue age.
- Processing backlog.
- Database utilization.
- Worker resource usage.
- Rejection rate.
- Detection latency.
- Recovery time.
- Verification completion rate.

Use OpenTelemetry, Prometheus and Grafana, with distributed tracing and log correlation. Jaeger can provide trace inspection.

---

## 10. Engineering roadmap

There are two related but distinct planning views.

### A. Six engineering capability phases

These phases describe the broad engineering priorities.

**Phase 1 — Reliable ingestion**
- Gateway buffering.
- Payload limits.
- Admission control.
- Batch validation.
- Idempotency.
- Publisher confirms.
- Transactional outbox.

**Phase 2 — Efficient storage**
- Redis where justified.
- Safe aggregation.
- Time-window processing.
- PostgreSQL partitioning.
- Batched persistence.
- Object storage.
- Retention and archival.

**Phase 3 — Reliable processing**
- RabbitMQ queue separation.
- Worker concurrency.
- Prefetch tuning.
- Idempotent consumers.
- Retry and dead-letter handling.
- Backpressure.
- Recovery.

**Phase 4 — Intelligent analysis**
- Normalization.
- Detection cascade.
- Event aggregation.
- Stateful correlation.
- Incident deduplication.
- Bounded AI investigation.
- Evidence validation.

**Phase 5 — Safe response**
- Action catalogue.
- Proposal fingerprints.
- Deterministic policy.
- Approval state machine.
- Cryptographic command signing.
- Gateway execution journal.
- Firewall adapter.
- Independent verification.
- Rollback and reconciliation.

**Phase 6 — Performance and security validation**
- Load and burst testing.
- Database saturation.
- Broker and Redis outage tests.
- Gateway offline scenarios.
- AI outage tests.
- Tenant isolation.
- Recovery validation.

### B. First-release implementation gates

The Full Specification Revision 2's implementation contract establishes a more specific, gated delivery sequence:

| Gate | Scope | Exit condition |
|---|---|---|
| Phase 1 | Deterministic gateway and event pipeline | Reproducible ingestion, tested policy enforcement and verified offline behaviour |
| Phase 2 | Detection and evaluation | Measured per-class metrics, false-positive rate and latency |
| Phase 3 | Fusion and investigation | Measured improvement, grounded findings and prompt-injection/permission tests |
| Phase 4 | Safety-gated response | Safety tests, auditable actions, rollback and independent verification |
| Phase 5 | Shadow pilot | Authorized real traffic without autonomous enforcement; customer acceptance before limited live response |

These are not competing roadmaps. The six phases describe engineering capability areas; the five gates define the first-release delivery sequence.

A phase cannot be declared complete merely because its modules exist. Its exit conditions must be demonstrated.

---

## 11. Technology direction

The intended initial technology direction is:

| Area | Technology |
|---|---|
| Frontend | React + TypeScript |
| Platform API | Python + FastAPI |
| Background processing | Python workers |
| Gateway | Go or Python |
| Database | PostgreSQL |
| Message broker | RabbitMQ |
| Cache | Redis |
| Evidence storage | S3-compatible storage / MinIO |
| Event contract | CloudEvents 1.0 |
| API contract | OpenAPI 3.2.1 |
| Error contract | RFC 9457 Problem Details |
| Internal IDs | UUIDv7 |
| Distributed tracing | W3C Trace Context |
| User authentication | OIDC-compatible identity |
| Gateway authentication | mTLS |
| Authorization | RBAC and tenant-scoped resource checks |
| Deployment | Docker Compose initially |
| Observability | OpenTelemetry |

The system should begin as a modular monolith with independently runnable API, worker and gateway components.

Modules may be extracted into separate services later when actual scaling or ownership requirements justify it.

Do not introduce Kafka, Kubernetes, multiple databases, multiple LLM providers or per-feature microservices without a demonstrated need and an architecture decision record.

---

## 12. Non-negotiable architectural invariants

These are the rules that every implementation and future feature must respect.

1. **Evidence preservation:** Original event identity and evidence must remain traceable.
2. **Tenant isolation:** No cross-tenant access through APIs, workers, queries or commands.
3. **Trusted identity:** Tenant ownership comes from authenticated identity, never arbitrary payload values.
4. **Durable acceptance:** An accepted event must not silently disappear.
5. **At-least-once processing:** Duplicate delivery is expected; consumers must be idempotent.
6. **Explicit ownership:** Each domain object and state transition has an authoritative owner.
7. **AI isolation:** Investigation AI is read-only and cannot directly execute security actions.
8. **Deterministic authorization:** Policies, not model confidence, determine whether an action is permitted.
9. **Human approval:** Sensitive response actions require the defined human authorization.
10. **Least privilege:** Each component receives only the permissions it needs.
11. **Signed commands:** Commands must be scoped, expiring, verifiable and replay-resistant.
12. **Execution journal:** The gateway persists execution state before performing an action.
13. **Independent verification:** Execution acknowledgement is not proof of containment.
14. **Graceful degradation:** Detection must continue when optional AI or infrastructure components fail.
15. **Observable operation:** Every important stage must expose measurable health and processing state.
16. **Contract stability:** Shared schemas and state transitions cannot be changed privately.
17. **Measured optimization:** Performance improvements must be supported by benchmarks.
18. **No premature complexity:** Add infrastructure and abstractions only when justified.

---

## 13. Development and contract governance

The `contracts/` directory is the authoritative source for shared schemas.

The API namespaces are:

- `/api/v1/...` — customer-facing application APIs.
- `/edge/v1/...` — authenticated gateway communication.
- `/internal/v1/...` — trusted backend-worker communication.

All APIs must use:
- `snake_case` JSON.
- UTC RFC 3339 timestamps.
- UUIDv7 entity identifiers.
- Cursor-based pagination.
- RFC 9457 error responses.
- W3C trace context.
- Idempotency protection for side-effecting operations.
- Explicit authorization checks.

Contract changes follow these rules:

1. No private schema versions.
2. Prefer backward-compatible additive changes.
3. Breaking changes require versioning.
4. Every contract change requires valid and invalid examples.
5. Every contract change requires tests.
6. Identifiers must never be reused for different entities.
7. State transitions must remain owned by their designated services.
8. API deprecation must be documented.

A developer must understand the owning layer, contract and acceptance criteria before changing a component.

Every implementation chunk should follow:

**Specification → Decision record → Implementation → Unit tests → Integration tests → Golden scenario → Verification report → Pass/fail gate**

A chunk cannot close with failing required tests, missing evidence or undocumented architectural changes.

---

## 14. What Ascense should ultimately achieve

The intended outcome is a platform where a security analyst can:

1. See the security health of monitored infrastructure.
2. Understand which sensors and gateways are operating correctly.
3. Identify suspicious activity from reliable detection results.
4. See related alerts grouped into meaningful incidents.
5. Investigate an incident using traceable evidence.
6. Understand what is known, what is uncertain and why.
7. Review possible response actions and their impact.
8. Approve or reject actions through a governed workflow.
9. Track exactly which gateway received and executed an authorized command.
10. Verify whether the actual security control changed as intended.
11. Review the complete audit trail and recovery outcome.

The defining characteristic of Ascense should be its **evidence-to-action-to-verification chain**.

It should not merely tell an analyst that something suspicious happened. It should help establish what happened, why the conclusion is justified, what response is permitted, who authorized it, what actually executed and whether the intended outcome was achieved.

That is the product vision and the engineering standard against which every feature should be evaluated.

---

## Reference documents

These documents should remain aligned with this consolidated context:

- System architecture: https://github.com/Ritesh-022/Soc_Analyst/blob/main/docs/01_SYSTEM_ARCHITECTURE.md
- Contracts and identifiers: https://github.com/Ritesh-022/Soc_Analyst/blob/main/docs/02_CONTRACTS_AND_IDENTIFIERS.md
- Module ownership: https://github.com/Ritesh-022/Soc_Analyst/blob/main/docs/03_MODULE_OWNERSHIP.md
- Development workflow: https://github.com/Ritesh-022/Soc_Analyst/blob/main/docs/04_DEVELOPMENT_WORKFLOW.md
- Testing and security strategy: https://github.com/Ritesh-022/Soc_Analyst/blob/main/docs/05_TESTING_AND_SECURITY_STRATEGY.md
- Full specification Revision 2: https://github.com/Ritesh-022/Soc_Analyst/blob/main/docs/Autonomous_Cyber_Defense_Platform_Full_Specification_Revision2.md

**Final rule:** This document defines the intended architecture and contracts. It does not certify that the current repository implements or validates every requirement. Implementation status must be established independently through code inspection, tests, runtime experiments and measurable evidence.

Regarding the policy change in RAG pipeline
Yes. We should account for policy changes and CDC (Change Data Capture) as explicit parts of the Ascense architecture, particularly in the data pipeline feeding RAG.

There are two separate concerns here:

1. Policy lifecycle: policies may remain unchanged for long periods, or change as requirements, threats, assets, and operational conditions evolve. The system must support both.
2. Knowledge freshness: when policies, runbooks, asset metadata, detection rules, or other RAG source documents change, the retrieval index must reflect those changes reliably.

The important distinction: CDC should keep RAG's knowledge synchronized with authoritative sources; it should not make the RAG index the source of truth.

## 1. Updated RAG pipeline for Ascense

I recommend adding CDC as an explicit pipeline capability, not as an isolated component.

## Authoritative knowledge sources

Security policies

Incident runbooks

Detection rules

Asset / configuration data

Threat intelligence

Approved procedures

1\. Source-of-truth stores

PostgreSQL, document storage, approved external feeds

2\. Change detection / CDC

INSERT · UPDATE · DELETE · version changes · source metadata

3\. Change event processing

Validation · deduplication · ordering · tenant checks · change classification

4\. RAG ingestion and indexing

Fetch latest source → parse → normalize → chunk → enrich metadata → embed

5\. Retrieval index

Vector index + keyword index + metadata filters

6\. RAG retrieval and investigation

Retrieve current, authorized, version-aware evidence for the investigation agent

The pipeline should also support an initial full ingestion and reconciliation process. CDC only captures changes after it is enabled; it does not automatically populate the existing corpus.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://www.ibm.com\&sz=32)

IBM+2



## 2. Policies must be version-aware

Policies should not be treated as ordinary documents.

A policy may be:

- Static: no change for months or years.
- Updated: a new version replaces the previous one.
- Temporarily overridden: a time-bound exception applies.
- Retired: no longer applicable.
- Under review: a proposed change is not yet approved.

I recommend a policy lifecycle like this:

`DRAFT → REVIEW → APPROVED → ACTIVE → SUPERSEDED / RETIRED`

An emergency revocation or suspension should also be supported.

Each policy version should preserve:

| Field             | Purpose                                |
| ----------------- | -------------------------------------- |
| `policy_id`       | Stable policy identity                 |
| `policy_version`  | Immutable version                      |
| `status`          | Draft, approved, active, retired, etc. |
| `effective_from`  | When it becomes applicable             |
| `effective_until` | When it stops applying                 |
| `approved_by`     | Authorized approver                    |
| `content_hash`    | Detect content changes                 |
| `tenant_id`       | Ownership and isolation                |

Critical distinction: a policy update must not silently rewrite the policy version used by a previous decision. Every proposal, evaluation and approval must retain the exact policy version against which it was evaluated.

RAG can retrieve policy information and explain it. The deterministic policy engine remains responsible for enforcing it.

## 3. CDC processing requirements

CDC must handle more than new documents.

| Change             | RAG action                                         |
| ------------------ | -------------------------------------------------- |
| INSERT             | Ingest and index                                   |
| UPDATE             | Reprocess affected document                        |
| DELETE             | Remove or tombstone indexed content                |
| VERSION CHANGE     | Preserve version history and update active version |
| ACCESS CHANGE      | Re-evaluate retrieval permissions                  |
| POLICY RETIREMENT  | Exclude from active-policy retrieval               |
| SOURCE RESTORATION | Reconcile and re-index                             |

Some important engineering requirements:

- Idempotent processing: duplicate CDC events must not create duplicate chunks.
- Ordering: older events must not overwrite newer document versions.
- Tenant isolation: a tenant's content must never enter another tenant's retrieval results.
- Deletion propagation: deleted or revoked content must not remain retrievable.
- Retry and dead-letter handling: failed indexing must be recoverable.
- Reconciliation: compare source records against the retrieval index periodically.
- Observability: measure CDC lag, indexing lag, failures and stale-document count.

For PostgreSQL, log-based CDC is a reasonable future direction. The existing RabbitMQ architecture can carry change events; we do not need to introduce Kafka simply to support this feature. The transactional outbox is another option when application-level changes need stable, explicit event contracts.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://docs.aws.amazon.com\&sz=32)

AWS Prescriptive Guidance+2



## 4. Important distinction: not every change belongs in RAG

Ascense has multiple kinds of changing data, and they need different consumers.

| Data                   | Destination                                   |
| ---------------------- | --------------------------------------------- |
| Policies and runbooks  | RAG knowledge index                           |
| Asset metadata         | Asset registry and possibly RAG metadata      |
| Detection rule changes | Detection engine configuration                |
| Network telemetry      | Detection and correlation pipeline            |
| Incident state changes | Incident management and investigation context |
| Approval changes       | Decision/enforcement workflow                 |
| Gateway configuration  | Configuration distribution                    |
| Threat intelligence    | Intelligence store and detection pipeline     |

CDC can be a shared change-propagation mechanism, but each consumer must decide what to do with a particular change. Do not embed every database update into the vector database.

## 5. What I would add to the Ascense architecture

I would formally add these capabilities:

1. Knowledge Source Registry — tracks authoritative sources, ownership, versions and permissions.
2. CDC / Change Propagation — captures relevant source changes.
3. RAG Ingestion Worker — processes additions, updates, deletions and re-indexing.
4. Index Version Manager — tracks document versions, chunk versions and embedding versions.
5. Knowledge Reconciliation Worker — identifies source/index drift.
6. Policy Version Manager — maintains approved policy history and applicability.
7. Retrieval Authorization — checks tenant, document and policy access before returning evidence.

These are logical capabilities, not necessarily seven new microservices.

## 6. Updated logical pipeline

The original Ascense security pipeline remains:

Observe → Detect → Correlate → Investigate → Decide → Respond → Verify

The RAG knowledge pipeline becomes a supporting pipeline:

Source Registration → Initial Ingestion → CDC → Change Processing → Parsing → Chunking → Embedding → Indexing → Reconciliation → Retrieval

The two pipelines connect at Investigation. The RAG pipeline supplies versioned, authorized evidence; it does not control response execution.

My recommendation: add CDC, policy versioning and RAG synchronization to the architecture specification now, but do not immediately implement them all. First establish the source-of-truth ownership and event contracts. Otherwise, you risk building a CDC pipeline that faithfully propagates inconsistent or unauthorized data.

One important design decision remains: should Ascense's RAG knowledge base ingest only Ascense-managed policies/runbooks, or should it also ingest customer-specific documents and approved external threat-intelligence sources? That determines the source registry, tenancy model and CDC boundaries.
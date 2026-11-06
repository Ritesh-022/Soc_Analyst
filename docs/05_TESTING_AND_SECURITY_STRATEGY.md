# 05 · Testing and Security Strategy

Module-level correctness is not enough. The important bugs in Ascense happen when one component trusts another component's output incorrectly. Test the connections, not just the modules.

---

## Test Layers

| Level | What it proves | Example |
|---|---|---|
| Unit tests | A function or module behaves correctly in isolation | A detection rule identifies a known suspicious pattern |
| Contract tests | Producers and consumers agree on schemas | A gateway event passes ingestion schema validation |
| Integration tests | Components work together | Ingestion writes an event and publishes it to the broker |
| End-to-end tests | The full business workflow works | A simulated attack creates an alert visible in the dashboard |
| Security tests | Attackers cannot abuse trust boundaries | Tenant A cannot read Tenant B's incident |
| Failure tests | The system behaves correctly when components fail | The broker is down while the gateway continues buffering events |
| Regression tests | Previously fixed problems do not return | An expired response command remains rejected after a code change |

Every developer owns unit and contract tests for their module. Cross-module integration, end-to-end, security, and failure tests are coordinated by the QA/DevSecOps owner and live in the root `tests/` directory.

---

## The First Mandatory End-to-End Test

Build this incrementally from Stage 3 onward. It must pass as an automated test before any stage is considered complete.

**Scenario: Suspicious network connection**

1. Simulate a customer gateway with an authenticated identity.
2. Generate a test network event from the gateway simulator.
3. Ingest, validate, normalize, and persist the event.
4. Detect the test behaviour using a deterministic rule.
5. Create a detection finding, correlate it into an alert, and group it into an incident.
6. Open an incident and investigate it using read-only access.
7. Create a response proposal with a typed target and require human approval.
8. Execute a test action against a lab gateway via the command leasing flow.
9. Verify the enforcement state and update the incident timeline.

---

## Mandatory Negative Tests

These must pass at every stage where the relevant component exists.

### Identity and tenant isolation
- [ ] Send an event using another tenant's gateway identity → rejected at ingestion
- [ ] Attempt to read another tenant's incident via the API → `403`
- [ ] Attempt to read another tenant's evidence via the investigation agent → blocked
- [ ] Attempt to change `tenant_id` in a request payload → ignored; backend derives from auth context
- [ ] Attempt to change `gateway_id` in an event payload → verified against certificate; rejected if mismatched

### Event integrity
- [ ] Send a duplicate event (same `source` + `id`) → deduplicated, not double-processed
- [ ] Send an event with an invalid schema → `422` with rejection detail
- [ ] Send an unsupported event type → rejected at ingestion allowlist check
- [ ] Send an event with a missing timestamp → rejected with `INVALID_EVENT_SCHEMA`

### Response safety
- [ ] Submit an expired approval → rejected
- [ ] Replay an old command → rejected (idempotency check)
- [ ] Modify a command after signing → signature verification fails, command rejected
- [ ] Submit a command for a gateway that does not belong to the tenant → rejected
- [ ] Disconnect the gateway during command execution → `execution_status: UNKNOWN` (not `FAILED`); `verification_status: PENDING`; Ascense escalates rather than claiming success; incident timeline updated
- [ ] Gateway is unreachable before command is delivered → command returns to `QUEUED` after lease expiry; no execution attempt created; execution status not set (delivery failure is not execution failure)
- [ ] Simulate an unsuccessful rollback → `PARTIALLY_SUCCEEDED` or `FAILED` state recorded; never silently converted to success
- [ ] Policy changes after approval but before command execution → command rejected; proposal requires re-evaluation
- [ ] Asset marked critical after proposal is approved → command rejected; policy re-evaluation required
- [ ] Approval revoked while command is queued → command cancelled; incident timeline updated
- [ ] Two gateway processes claim the same command → only one lease issued; second claim rejected

### AI investigation safety
- [ ] Send malicious instructions inside an event payload → not executed by the investigation agent
- [ ] Send malicious instructions inside investigation evidence → not executed
- [ ] Investigation agent attempts to access evidence outside its tenant scope → blocked
- [ ] Investigation agent attempts to call a write or execute tool → tool not available in its permitted tool set
- [ ] Investigation agent produces a recommendation without evidence references → proposal rejected

---

## Full Tenant Isolation Tests

Tenant isolation must be verified across every data path, not just the main API.

- [ ] API endpoints and database queries — no cross-tenant resource access
- [ ] Database connection pools and row-level security — tenant filter applied at every query
- [ ] RabbitMQ queues, routing, and message consumers — no cross-tenant message delivery
- [ ] Redis cache keys — tenant-scoped key namespacing
- [ ] Object storage and evidence download links — pre-signed URLs scoped to tenant
- [ ] Search indexes and RAG retrieval — embeddings and retrieval results scoped to tenant
- [ ] Audit records and exports — no cross-tenant audit data in any export
- [ ] Background workers — tenant context derived from message, not assumed from worker state

A tenant filter in the main API is not sufficient. Every data path must be tested independently.

---

## Security Test Coverage

### Authentication and authorization
- [ ] All `/api/v1/` endpoints reject unauthenticated requests with `401`
- [ ] All `/api/v1/` endpoints enforce tenant scoping — no resource is accessible across tenants
- [ ] All `/edge/v1/` endpoints require valid gateway mTLS certificate
- [ ] The `gateway_id` in the URL is verified against the authenticated certificate identity on every request
- [ ] All `/internal/v1/` endpoints are unreachable from the public internet and from the dashboard
- [ ] RBAC roles are enforced — a read-only user cannot approve actions or create proposals
- [ ] A user cannot approve their own high-impact proposal

### Input validation
- [ ] All API endpoints validate input against their OpenAPI schema
- [ ] Oversized payloads are rejected with documented limits
- [ ] Malformed JSON returns `400`, not a stack trace
- [ ] SQL injection attempts in query parameters are rejected
- [ ] Path traversal attempts in resource IDs are rejected
- [ ] Event batch size limits are enforced

### Secrets and data protection
- [ ] No secrets, credentials, or private keys appear in logs
- [ ] No stack traces, database queries, or internal service details appear in error responses
- [ ] No other tenant's data appears in any response
- [ ] Gateway private keys are stored securely and never transmitted after enrollment

### OWASP coverage
Use the OWASP API Security Top 10 as the baseline for API-specific threat coverage. Use the OWASP Top 10 2025 for general web application security awareness on the dashboard.

Key items to verify explicitly:
- Broken object-level authorization (BOLA) — every resource access checks tenant ownership
- Broken function-level authorization — admin-only endpoints are not accessible to regular users
- Unrestricted resource consumption — rate limits and payload size limits are enforced
- Security misconfiguration — no default credentials, no unnecessary services exposed
- Injection — all inputs are validated; no dynamic query construction from untrusted input

---

## Command and Enforcement Failure Tests

- [ ] Policy changes after approval but before command execution → command rejected
- [ ] Asset criticality changes after proposal is approved → command rejected; policy re-evaluation required
- [ ] Approval is revoked while command is queued → command cancelled
- [ ] Gateway has an outdated or revoked signing certificate → command rejected
- [ ] Two gateway processes claim the same command → only one lease issued
- [ ] Command executes but acknowledgement is lost → lease expires; command returns to `QUEUED`; gateway checks execution journal before re-executing; idempotency prevents double execution
- [ ] Firewall applies the block but gateway crashes before reporting → enforcement state is `UNKNOWN`; system escalates rather than claiming success
- [ ] Gateway reconnects after crash mid-execution → gateway reads execution journal, reconciles with actual firewall state, reports correct status (`SUCCEEDED`, `FAILED`, or `UNKNOWN`)
- [ ] Gateway execution journal persists before action is taken; on reconnection, journal is checked before re-executing any command
- [ ] Gateway reports `UNKNOWN` (not `FAILED`) when enforcement state cannot be confirmed after reconnection
- [ ] Ascense escalates `UNKNOWN` execution state rather than treating it as success or failure

The system must distinguish delivery failure from execution failure:
- Delivery failure: the command never reached the gateway (gateway unreachable before acknowledgement). The command returns to `QUEUED`. No execution attempt is created. Do not set `execution_status: FAILED`.
- Execution failure: the gateway received and attempted the command but confirmed it did not succeed. `execution_status: FAILED`.
- Uncertain execution: the gateway cannot determine the actual enforcement state (e.g. crashed mid-execution). `execution_status: UNKNOWN`. Escalate.

Verification status is tracked separately from execution status:
- `VERIFIED` — response verification service independently confirmed the enforcement state is in effect
- `NOT_VERIFIED` — read-back confirmed the enforcement state is not in effect
- `UNKNOWN` — verification could not be completed

A gateway reporting `execution_status: SUCCEEDED` does not imply `verification_status: VERIFIED`.

---

## ML and Data Integrity Tests

- [ ] Training/test data leakage checks — no test data in training set
- [ ] Model calibration evaluation — confidence scores reflect actual accuracy
- [ ] Model drift detection — performance degradation triggers an alert
- [ ] Adversarial evasion tests — known evasion techniques are evaluated
- [ ] Data poisoning and malicious feedback tests
- [ ] Feature pipeline consistency checks — same features at training and inference time
- [ ] Model artifact integrity and signature verification
- [ ] Model rollback tests — rolling back to a previous version produces expected findings
- [ ] False positive rate measurement on a representative operational dataset
- [ ] Performance comparison against the best individual deterministic rule

Measure the false positive rate and the operational cost of false alerts. A model with strong benchmark accuracy may still overwhelm analysts in a real deployment.

---

## AI and RAG-Specific Tests

- [ ] Prompt injection via event payload → not executed
- [ ] Prompt injection via investigation evidence → not executed
- [ ] Malicious documents in runbooks → not executed
- [ ] Poisoned threat intelligence → flagged, not acted upon
- [ ] Repeated AI investigation loops → bounded; loop detection prevents runaway cost
- [ ] Token and cost exhaustion → investigation times out gracefully; status set to `failed`
- [ ] Evidence attribution to a non-existent record → proposal rejected
- [ ] Incorrect asset identity association → investigation report flags uncertainty
- [ ] Stale historical evidence influencing a current incident → evidence timestamps are visible in the report
- [ ] External model provider failure → investigation fails gracefully; incident is not left in a broken state
- [ ] Model output that is syntactically valid but semantically unsafe → policy engine rejects the proposal

The AI must never be the source of authority for a security action.

---

## Gateway Resilience and Telemetry Health Tests

- [ ] Local disk buffer becomes full → oldest events are dropped with a logged warning; no crash
- [ ] Sensor process crashes while the agent remains alive → gateway reports `SENSOR_FAILURE`; dashboard shows degraded status
- [ ] Gateway clock drifts significantly → timestamp validation flags events; operator is notified
- [ ] Gateway certificate is revoked during an outage → gateway cannot reconnect until re-enrolled
- [ ] Gateway receives an outdated configuration → configuration version is checked; outdated config is rejected
- [ ] Events are delayed for hours and arrive after an incident is closed → late events are stored; incident can be reopened if warranted
- [ ] Sensor event rate suddenly increases beyond the expected limit → rate limiting applied; operator notified

**Critical test:** when the gateway stops sending events, the dashboard must show `TELEMETRY_STALE` or `SENSOR_FAILURE` — not a clean environment with no alerts. This must be an automated test.

---

## Failure and Resilience Tests

### Gateway failures
- [ ] Gateway disconnects mid-batch → ingestion handles partial batch; no data loss
- [ ] Gateway reconnects after outage → resumes heartbeat and command polling correctly
- [ ] Gateway sends events out of order → ingestion handles without corruption
- [ ] Gateway sends events with clock skew → timestamp validation rejects or flags appropriately

### Broker failures
- [ ] RabbitMQ is unavailable → ingestion writes to outbox; events are not lost
- [ ] RabbitMQ recovers → outbox publisher resumes; no duplicate processing beyond idempotency handling
- [ ] A message is delivered twice → consumer handles idempotently; no duplicate alert created

### Database failures
- [ ] Database is temporarily unavailable → API returns `503`; no partial writes
- [ ] A migration fails → rollback leaves the schema in a consistent state

### Detection and investigation failures
- [ ] A detection worker crashes mid-processing → event is requeued; not silently dropped
- [ ] An ML model returns an unexpected output format → finding is rejected; alert is not created with invalid data
- [ ] The investigation agent times out → investigation status is set to `failed`; incident is not left in a broken state

### Response failures
- [ ] The gateway is unreachable when a command is dispatched → command remains `LEASED` until lease expires, then returns to `QUEUED`; no execution attempt is created; execution status is not set to `FAILED` (the command was never delivered, not executed and failed)
- [ ] The gateway is unreachable after acknowledging a command but before executing → execution attempt is created with `execution_status: UNKNOWN`; Ascense escalates; incident timeline updated
- [ ] The gateway reports partial execution → `execution_status: PARTIALLY_SUCCEEDED`; rollback is attempted
- [ ] Verification times out → `verification_status: UNKNOWN`; operator is notified

---

## Contract Tests

Contract tests live in `tests/contract/` and run on every pull request that touches `contracts/`.

For each event type and API endpoint, maintain:
- A valid example that must pass schema validation
- At least one invalid example that must fail schema validation with a specific error
- A producer test that verifies the component generates output matching the schema
- A consumer test that verifies the component correctly handles valid input

Contract tests must pass before any integration test is run. A failing contract test blocks the PR.

---

## Service Level Objectives

Do not invent performance targets without testing. Establish a baseline in the lab, define the target, and then run load tests to validate it. The following are the metrics to define targets for — fill in actual numbers after baseline measurement.

| Metric | What it measures | Target (fill in after baseline) |
|---|---|---|
| Gateway availability | Agent connected and functioning | TBD |
| Telemetry freshness | Time since last usable event received | TBD |
| Ingestion latency (p95) | Time from receipt to durable acceptance | TBD |
| Event loss rate | Percentage of valid events not processed | TBD |
| Detection latency (p95) | Time from event acceptance to finding | TBD |
| Incident creation latency | Time from related findings to incident availability | TBD |
| Investigation completion (p95) | Time to finish an investigation | TBD |
| Command delivery latency | Time from dispatch to gateway acknowledgement | TBD |
| Verification success rate | Intended enforcement state confirmed | TBD |
| Tenant isolation | Cross-tenant access tests with unauthorized success | 0 |
| False positive rate | Alerts on known-benign traffic | TBD |

---

## Observability Requirements

Every module must emit the following before it is considered complete.

### Structured logs
- Every log entry includes: `timestamp`, `level`, `service`, `tenant_id` (where applicable), `trace_id`, `request_id`, and a structured message
- No sensitive data (credentials, PII, private keys) in logs
- Security-relevant events (auth failures, tenant access denials, command rejections) are logged at `WARN` or above

### Distributed traces
- Every inbound request creates or continues a W3C `traceparent` trace
- Every outbound broker message carries the trace context
- The gateway includes trace context in event batches
- Traces are exported to the configured OpenTelemetry collector

### Metrics
- API request rate, latency (p50/p95/p99), and error rate per endpoint
- Event ingestion rate and rejection rate
- Detection worker queue depth and processing latency
- Alert and incident creation rate
- Command dispatch rate, success rate, and failure rate
- Gateway heartbeat status per registered gateway
- Per-sensor event rate and last-seen timestamp
- Telemetry health state per gateway

### Audit log
The audit log is append-only and independently protected. Every security-relevant operation must produce an audit record containing:
- `event_time` (UTC, RFC 3339)
- `actor_id` and `actor_type` (user or service)
- `tenant_id`
- `action` (namespaced string, e.g. `approval.created`)
- `resource_type` and `resource_id`
- `outcome` (`success` or `failure`)
- `trace_id`

Audit records must never be deleted or modified **during their defined retention period**. The audit store must have independent access controls and a separate storage destination from the main database. Consider WORM storage or tamper-evident integrity mechanisms. An append-only application property is not sufficient on its own — protect the store independently.

### Retention and data lifecycle

Audit immutability and data retention are separate concerns that must be reconciled:

| Data category | Retention rule |
|---|---|
| Audit records | Immutable during defined retention period; period documented per regulatory/contractual requirement |
| Evidence records (metadata) | Defined retention period; deletable after expiry per data lifecycle policy |
| Raw evidence objects (packet captures, logs) | Shorter retention period than metadata; deletable on schedule or by customer request |
| Normalized events | Retention period defined; partitioned storage for volume management |
| Legal holds | Handled separately; override normal deletion schedules |

Do not apply indefinite retention to all data simply because the audit log is append-only. Sensitive personal information must be minimized or pseudonymized. Expiration and deletion must follow applicable legal and contractual requirements.

---

## Operational Runbooks Required Before Pilot

The platform must have a documented answer to each of the following before any customer exposure:

| Scenario | Runbook required |
|---|---|
| Gateway enrollment | Step-by-step enrollment and certificate issuance |
| Certificate rotation | Renew a gateway certificate without losing telemetry |
| Certificate revocation | Revoke a compromised gateway and re-enroll |
| Event backlog recovery | Process a large backlog after a broker outage |
| Model rollback | Revert to a previous model version |
| Response failure | Handle a failed or partially succeeded action |
| Backup restoration | Restore PostgreSQL and object storage from backup |
| Platform security incident | Isolate a compromised service without losing audit data |
| Telemetry gap | Investigate and recover from a `TELEMETRY_STALE` state |
| Approval service unavailable | Handle pending approvals when the approval service is down |

---

## Acceptance Criteria for Pilot Readiness

The system is ready for a controlled pilot (Level 1) when all of the following are true:

- [ ] The mandatory end-to-end test scenario passes in an automated test suite
- [ ] All mandatory negative tests pass
- [ ] Full tenant isolation is verified across all data paths
- [ ] All Stage 6 response safety tests pass, including expired, replayed, unsigned, and race-condition command rejection
- [ ] Policy-change-after-approval rejection is verified
- [ ] AI investigation red-team tests pass (no prompt injection, no cross-tenant evidence access, no command execution)
- [ ] Telemetry health tests pass — dashboard shows degraded status when sensors stop reporting
- [ ] Gateway outage and reconnection tests pass without data loss
- [ ] Duplicate event delivery is handled idempotently
- [ ] Backup and restore has been tested and documented
- [ ] All modules meet the Definition of Done from `03_MODULE_OWNERSHIP.md`
- [ ] Detection quality is measured (true positive rate, false positive rate) on a labelled test dataset
- [ ] SLO baseline measurements are recorded
- [ ] All operational runbooks are written and reviewed
- [ ] Known limitations are documented

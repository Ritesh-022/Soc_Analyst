# 02 · Contracts and Identifiers

The `contracts/` directory is the authoritative source for every shared interface. No team invents its own version of an event, ID, status, or API response.

---

## Identifier Registry

All internally generated entity IDs use **UUIDv7** (RFC 9562), serialized as a lowercase string. Prefixes in logs are display conventions only — the actual identifier is always a plain UUID.

`trace_id` is not a UUIDv7. It follows the W3C Trace Context specification: a 32-character lowercase hexadecimal string representing 16 bytes, carried in the `traceparent` header.

Do not assume the user ID from an external identity provider is your internal UUID. Maintain a mapping between your internal `user_id` and the external identity's issuer and subject claim.

| Identifier | Represents | Created by |
|---|---|---|
| `tenant_id` | Customer organization | Tenant service |
| `user_id` | Internal user identity (mapped from external IdP) | Identity system |
| `gateway_id` | Installed gateway deployment | Gateway registry |
| `asset_id` | Protected host, service, or device | Asset registry |
| `source_event_id` | ID produced by the original sensor (e.g. Zeek UID) | Preserved from source |
| `event_id` | Ascense normalized event record | Ingestion layer |
| `detection_finding_id` | Output from one detector run | Detection layer |
| `alert_id` | Actionable correlated finding | Correlation service |
| `incident_id` | Security case grouping related alerts | Correlation service |
| `evidence_id` | A stored evidence record | Evidence service |
| `investigation_id` | An investigation run | Investigation service |
| `proposal_id` | A proposed response action | Investigation or response workflow |
| `approval_id` | A human authorization record | Approval service |
| `command_id` | An authorized, signed executable command | Response service |
| `execution_attempt_id` | One specific execution attempt | Gateway/response adapter |
| `policy_version_id` | An immutable policy revision | Policy service |
| `model_version_id` | A deployed model revision | Model registry |
| `request_id` | An individual API request | API layer (UUIDv7) |
| `trace_id` | A distributed trace | W3C 32-char hex |

### ID rules

- Every tenant-owned database record must carry a `tenant_id`.
- An internal service must check tenant ownership before reading or modifying an object.
- Never treat possession of an `incident_id`, `gateway_id`, or any other ID as proof of authorization.
- The backend derives tenant context from the authenticated user or gateway identity. The caller must not be able to change tenant ownership by changing request JSON.
- Preserve `source_event_id` separately. It is not a substitute for `event_id` and must not be used as one.
- Keep `request_id`, `trace_id`, and business entity IDs distinct in logs and responses.

---

## Domain Model: Finding → Alert → Incident

These three objects are distinct. Do not conflate them.

| Object | Created by | Represents |
|---|---|---|
| Detection finding | One detector (rule or ML model) | The output of a single detector run against one or more events |
| Alert | Correlation service | An actionable security finding, potentially combining multiple findings or repeated observations |
| Incident | Correlation service | A connected security case containing one or more alerts, related assets, evidence, investigations, and responses |

A detection engine creates a `detection_finding_id`. It does not independently decide that a customer-facing incident exists. The correlation service promotes findings into alerts and groups alerts into incidents.

---

## Canonical Event Contract

Events use the **CloudEvents 1.0** envelope. The `tenantid` and `gatewayid` extension attributes are verified against the authenticated gateway identity — they are never trusted from the payload alone.

The CloudEvents `dataschema` attribute identifies the payload schema URI. The `data.schema_version` field inside the payload is the Ascense-specific payload version. Document the relationship between these two versioning mechanisms in `docs/adr/`.

### Sensor-level event source identity

A single gateway may run multiple sensors (e.g. Zeek and Suricata). Their event identifiers can overlap. The CloudEvents `source` must therefore identify the gateway **and** the specific sensor instance, not just the gateway.

Source URN format:
```
urn:ascense:gateway:{gateway_id}/sensor/{sensor_instance_id}
```

Deduplication uniqueness rule:
```
UNIQUE(source, id) = UNIQUE(gateway_id + sensor_instance_id, source_event_id)
```

When the original sensor does not provide a stable event identifier, the gateway must generate one before first transmission and preserve it across all retransmission retries. It must not generate a new ID on retry.

```json
{
  "specversion": "1.0",
  "id": "zeek-conn-0198e72a",
  "source": "urn:ascense:gateway:0198e729-.../sensor/zeek-01",
  "type": "com.ascense.network.connection.observed.v1",
  "subject": "asset/0198e72a-...",
  "time": "2026-11-06T06:30:00Z",
  "datacontenttype": "application/json",
  "dataschema": "https://schemas.ascense.example/events/network-connection/1.0.0",
  "tenantid": "0198e728-...",
  "gatewayid": "0198e729-...",
  "data": {
    "schema_version": "1.0",
    "source_event_id": "zeek-conn-0198e72a",
    "event_kind": "network.connection",
    "sensor": {
      "name": "zeek",
      "instance_id": "zeek-01",
      "version": "7.x"
    },
    "asset_resolution": {
      "status": "RESOLVED",
      "source_asset_id": "0198e72a-...",
      "destination_asset_id": null
    },
    "network": {
      "source_ip": "192.0.2.10",
      "source_port": 51432,
      "destination_ip": "198.51.100.20",
      "destination_port": 443,
      "transport": "tcp",
      "direction": "outbound",
      "bytes_sent": 1200,
      "bytes_received": 5400
    }
  }
}
```

### Event deduplication

Deduplication uses the combination of `source` and `id` (the CloudEvents uniqueness pair), which maps to `(gateway_id + sensor_instance_id, source_event_id)` in Ascense terms.

Sequence:
1. Sensor creates an event with its own identifier.
2. Gateway preserves that identifier as `source_event_id` in `data` and as the CloudEvents `id`. If the sensor provides no stable ID, the gateway generates one before first transmission and reuses it on retries.
3. Ingestion checks `(source, id)` against the deduplication store.
4. If new: Ascense creates its internal `event_id` after acceptance and normalization.
5. If duplicate: the platform recognizes it and does not create another logical event.

The ingestion service attaches authoritative `tenant_id` and `gateway_id` from the authenticated gateway registration. The submitted payload values are verified, not trusted.

### Event field rules

| Field | Rule |
|---|---|
| `specversion` | Must be `"1.0"` |
| `id` | Unique within its `source`; equals `source_event_id` |
| `source` | Must identify a registered gateway URN including sensor instance: `urn:ascense:gateway:{id}/sensor/{sensor_instance_id}` |
| `type` | Namespaced event type with version suffix (e.g. `.v1`) |
| `time` | Event occurrence time in UTC, RFC 3339 |
| `dataschema` | URI identifying the payload schema |
| `tenantid` | Verified against authenticated gateway identity |
| `gatewayid` | Must match the authenticated gateway certificate |
| `data.schema_version` | Version of the Ascense event payload |
| `data.source_event_id` | Original sensor-assigned identifier; gateway-generated if sensor provides none |
| `data.sensor.instance_id` | Stable identifier for the specific sensor process on this gateway |
| `data.asset_resolution.status` | `RESOLVED`, `UNRESOLVED`, `AMBIGUOUS`, or `STALE_MAPPING` |
| `data.asset_resolution.source_asset_id` | Asset ID for the source IP, if resolved; null otherwise |
| `data.asset_resolution.destination_asset_id` | Asset ID for the destination IP, if resolved; null otherwise |
| `sensor.name` | Controlled identifier from the approved sensor allowlist |

An event may be stored with `asset_resolution.status: UNRESOLVED` when the source or destination IP is not yet in the asset registry. Do not reject the event. Asset resolution runs asynchronously and can associate the event with an asset after verification. A network connection involves two endpoints; source and destination asset references are tracked separately.

Use an explicit allowlist of event types. A sensor must not invent arbitrary event categories that silently enter the detection pipeline.

---

## Detection Finding Contract

Every detector — rule-based or ML-based — returns the same finding structure. For rule-based detections, `model_version_id` is null and `rule_version` is populated. For ML-based detections, `rule_version` is null and `model_version_id` is populated.

```json
{
  "detection_finding_id": "0198e72b-...",
  "tenant_id": "0198e728-...",
  "event_ids": ["0198e72a-..."],
  "detector_id": "network_anomaly_v1",
  "detector_version": "1.2.0",
  "model_version_id": "0198e72f-...",
  "rule_version": null,
  "feature_schema_version": "1.0",
  "evaluation_window_seconds": 300,
  "finding_type": "suspicious_outbound_connection",
  "severity": "high",
  "risk_score": 82,
  "confidence": 0.91,
  "observed_at": "2026-11-06T06:30:00Z"
}
```

### Score distinctions

- `severity` — categorical business priority: `low`, `medium`, `high`, `critical`
- `risk_score` — integer 0–100 used for ranking and policy thresholds
- `confidence` — float 0–1 expressing model or detector confidence

Neither `risk_score` nor `confidence` should be described as the probability of an attack unless it has been properly calibrated.

---

## Alert Contract

The correlation service promotes findings into alerts.

```json
{
  "alert_id": "0198e72c-...",
  "tenant_id": "0198e728-...",
  "incident_id": null,
  "alert_type": "suspicious_outbound_connection",
  "severity": "high",
  "risk_score": 82,
  "status": "NEW",
  "detection_finding_ids": ["0198e72b-..."],
  "event_ids": ["0198e72a-..."],
  "evidence_ids": ["0198e72d-..."],
  "affected_asset_ids": ["0198e72a-..."],
  "summary": "Unusual outbound connection pattern from a monitored server.",
  "observed_at": "2026-11-06T06:30:00Z",
  "created_at": "2026-11-06T06:30:05Z"
}
```

---

## Investigation Result Contract

```json
{
  "investigation_id": "0198e72e-...",
  "incident_id": "0198e72f-...",
  "status": "completed",
  "summary": "Potential suspicious outbound activity.",
  "assessment": {
    "classification": "possible_command_and_control",
    "confidence": 0.78,
    "uncertainties": [
      "Insufficient historical traffic baseline for this asset."
    ]
  },
  "evidence": [
    {
      "evidence_id": "0198e72d-...",
      "event_id": "0198e72a-...",
      "supports": "Unusual outbound connection to an external IP on port 443."
    }
  ],
  "recommendations": [
    {
      "action_type": "block_network_indicator",
      "target": {
        "kind": "network_indicator",
        "address": "198.51.100.20/32",
        "direction": "egress",
        "gateway_id": "0198e729-...",
        "protocol": "tcp",
        "ports": [443]
      },
      "affected_asset_ids": ["0198e72a-..."],
      "requires_approval": true
    }
  ]
}
```

The `evidence` list must refer to real, retrievable, authorized evidence records. An AI explanation is not itself evidence.

---

## Response Proposal Contract

A proposal is not a command. A command is not proof of execution. An execution acknowledgement is not proof of successful containment. Keep these four objects separate: proposal, approval, command, execution attempt.

### Typed action target

The enforcement target and the affected asset are different things. Separate them.

- `target` — what the firewall or adapter will act on (a network indicator, an asset to isolate, etc.)
- `affected_asset_ids` — the protected assets whose security posture is being changed

```json
{
  "proposal_id": "0198e730-...",
  "tenant_id": "0198e728-...",
  "incident_id": "0198e72f-...",
  "action_type": "block_network_indicator",
  "target": {
    "kind": "network_indicator",
    "address": "198.51.100.20/32",
    "direction": "egress",
    "gateway_id": "0198e729-...",
    "protocol": "tcp",
    "ports": [443]
  },
  "affected_asset_ids": ["0198e72a-..."],
  "parameters": {
    "duration_seconds": 900
  },
  "reason": "Suspicious outbound activity supported by linked evidence.",
  "evidence_ids": ["0198e72d-..."],
  "policy_version_id": "0198e731-...",
  "expires_at": "2026-11-06T06:45:00Z",
  "status": "PENDING_APPROVAL"
}
```

For isolating a protected host, use `action_type: "isolate_asset"` with `target.kind: "asset"`. This distinction is critical when endpoint, identity, and database response actions are added later.

The policy engine validates the actual target and parameters against an allowlisted action schema. An AI agent must not choose arbitrary command strings, shell scripts, or firewall expressions.

### Signed command (additional required fields)

A signed command binds all of the following:

- `command_id` — unique identifier
- `tenant_id` and `gateway_id` — exact identities
- `target` — exact typed target (same structure as proposal)
- `action_type` and `parameters` — exact action
- `proposal_id` and `approval_id` — authorization chain
- `policy_version_id` — policy version used at authorization time
- `created_at` and `expires_at` — short expiry window
- `nonce` — unique per command to prevent replay
- `idempotency_key`
- Cryptographic signature verifiable by the gateway

The gateway must reject commands that are expired, replayed, incorrectly signed, mismatched, or unauthorized. It must also reject a command if the target's criticality or relevant policy has changed since approval.

Any material change to proposal parameters invalidates its earlier approval.

---

## Four Response State Machines

Maintain four separate state machines. Do not combine them into one field.

### Proposal states

```
DRAFT → SUBMITTED → POLICY_EVALUATION → REJECTED
                                      → EXPIRED
                                      → APPROVAL_PENDING
```

### Approval states

```
PENDING → APPROVED → (command created)
        → REJECTED
        → EXPIRED
        → REVOKED
```

A user must not approve their own high-impact proposal. Critical actions may require a second authorized approver. Approval has an explicit expiry and supports revocation.

### Command states

```
QUEUED → LEASED → ACKNOWLEDGED → EXPIRED
                              → CANCELLED
```

`DISPATCHED` is not a command lifecycle state. It is a named audit event recorded when the dispatcher places the command in the gateway's outbound queue. Do not add it as a value in the command status column. Record it as a timestamped event in the command audit trail.

| Command state | Meaning |
|---|---|
| `QUEUED` | Command created and waiting to be claimed |
| `LEASED` | Atomically claimed by a gateway; lease has a defined expiry |
| `ACKNOWLEDGED` | Gateway has confirmed receipt and accepted the command |
| `EXPIRED` | Lease or command window elapsed before acknowledgement |
| `CANCELLED` | Explicitly cancelled before or after leasing |

If the lease expires before the gateway acknowledges, the command returns to `QUEUED`. The same `command_id` is reused — do not create a new command.

### Execution attempt status

Execution status tracks what the gateway did. It is separate from verification status.

```
NOT_STARTED → RUNNING → SUCCEEDED
                      → FAILED
                      → PARTIALLY_SUCCEEDED → ROLLBACK_PENDING → ROLLED_BACK
                                                               → ROLLBACK_FAILED
                      → UNKNOWN
```

| Execution status | Meaning |
|---|---|
| `NOT_STARTED` | Attempt created but execution has not begun |
| `RUNNING` | Execution is in progress |
| `SUCCEEDED` | Gateway confirmed the action completed without error |
| `FAILED` | Gateway confirmed the action did not succeed |
| `PARTIALLY_SUCCEEDED` | Some operations completed; others did not |
| `UNKNOWN` | Execution state cannot be determined (e.g. gateway crashed mid-execution) |
| `ROLLBACK_PENDING` | Partial execution requires rollback |
| `ROLLED_BACK` | Rollback completed successfully |
| `ROLLBACK_FAILED` | Rollback attempted but did not complete |

### Verification status

Verification status tracks independent confirmation that the intended enforcement state exists. It is separate from execution status.

```
PENDING → VERIFIED
        → NOT_VERIFIED
        → UNKNOWN
```

| Verification status | Meaning |
|---|---|
| `PENDING` | Verification has not yet been attempted |
| `VERIFIED` | Independent read-back confirmed the enforcement state is in effect |
| `NOT_VERIFIED` | Read-back confirmed the enforcement state is not in effect |
| `UNKNOWN` | Verification could not be completed (e.g. firewall unreachable for read-back) |

A gateway reporting `execution_status: SUCCEEDED` does not imply `verification_status: VERIFIED`. These are two separate fields on the execution attempt record. An AI investigation worker cannot set either field. Only the gateway sets execution status; only the response verification service sets verification status.

`FAILED`, `PARTIALLY_SUCCEEDED`, and rollback outcomes are first-class states. Never silently convert a partial operation into success. If the enforcement state is unknown after a timeout, record `UNKNOWN` on the verification status and escalate — do not claim success.

A service may only perform the transitions it owns.

---

## Execution Journal Contract

The gateway must persist an execution journal record **before** performing any action. This record is the basis for idempotency on reconnection.

```json
{
  "command_id": "0198e740-...",
  "tenant_id": "0198e728-...",
  "gateway_id": "0198e729-...",
  "execution_attempt_id": "0198e741-...",
  "command_hash": "sha256:...",
  "received_at": "2026-11-06T06:30:10Z",
  "execution_started_at": "2026-11-06T06:30:11Z",
  "execution_completed_at": null,
  "execution_status": "RUNNING",
  "verification_status": "PENDING",
  "observed_enforcement_state": null,
  "result_reference": null
}
```

On reconnection after a disconnect, the gateway checks the journal before acting:

```
Receive command_id
        |
        v
Check persistent execution journal
        |
   +----+----+
   |         |
Already    Never
executed   executed
   |         |
Return     Validate authorization
previous   and execute
result         |
   |       Record in journal first
   +----+----+
        |
        v
     Report result
```

If the gateway's execution state is uncertain after reconnection, reconcile with the actual firewall state before reporting. Do not report `SUCCEEDED` when the actual state is unknown. Report `UNKNOWN` and let Ascense escalate.

Three distinct execution status values relevant to failure handling:
- `FAILED` — gateway confirmed that execution did not succeed
- `UNKNOWN` — gateway cannot determine the actual enforcement state (e.g. crashed mid-execution)
- `SUCCEEDED` — gateway confirmed the action completed; does not imply independent verification

Verification status is separate:
- `VERIFIED` — response verification service independently confirmed the enforcement state is in effect
- `NOT_VERIFIED` — read-back confirmed the enforcement state is not in effect
- `UNKNOWN` — verification could not be completed

---

## Command Transition Ownership

Each state transition has one responsible component. No other component may perform that transition.

| Transition | Responsible component |
|---|---|
| Proposal submitted | Investigation service or authorized user workflow |
| Policy evaluated | Policy engine |
| Approval recorded | Approval service |
| Command created (`QUEUED`) | Response service |
| Dispatch audit event recorded | Command dispatcher (audit trail only — not a state transition) |
| Command claimed (`LEASED`) | Gateway (via `commands:claim`) |
| Command acknowledged (`ACKNOWLEDGED`) | Gateway |
| Execution attempt created (`RUNNING`) | Gateway |
| Execution status reported | Gateway |
| Verification status set (`VERIFIED` / `NOT_VERIFIED` / `UNKNOWN`) | Response verification service |

`DISPATCHED` is recorded as a timestamped audit event when the dispatcher places the command in the outbound queue for the gateway to claim. It is not a command lifecycle state and must not appear as a value in the command status column. The gateway transitions the command to `LEASED` by claiming it, and to `ACKNOWLEDGED` by confirming receipt.

---

## Command Delivery and Leasing

The gateway retrieves commands using an atomic claim operation, not a simple GET.

```
POST /edge/v1/gateways/{gateway_id}/commands:claim
```

This atomically leases pending commands to the authenticated gateway for a short, defined period.

Command delivery sequence:

```
COMMAND CREATED (QUEUED)
      |
      v
DISPATCHER PLACES COMMAND IN OUTBOUND QUEUE
DISPATCHER RECORDS DISPATCH AUDIT EVENT (not a state change)
      |
      v
GATEWAY CLAIMS COMMAND (QUEUED → LEASED)
      |
      v
GATEWAY ACKNOWLEDGES RECEIPT (LEASED → ACKNOWLEDGED)
      |
      v
GATEWAY VALIDATES SIGNATURE, EXPIRY, IDEMPOTENCY, TARGET CRITICALITY
      |
      v
EXECUTION ATTEMPT CREATED (execution_status: NOT_STARTED → RUNNING)
      |
      v
EXECUTION RESULT REPORTED (execution_status: SUCCEEDED / FAILED / UNKNOWN / PARTIALLY_SUCCEEDED)
      |
      v
ASCENSE VERIFIES ACTUAL ENFORCEMENT STATE (verification_status: VERIFIED / NOT_VERIFIED / UNKNOWN)
```

If the gateway disconnects after claiming a command but before acknowledging, the lease expires and the command returns to `QUEUED`. The same `command_id` is reused — do not create a new command. Use idempotency and durable execution state to avoid repeating dangerous operations.

If the gateway is unreachable when the dispatcher attempts delivery, the command remains `LEASED` until the lease expires, then returns to `QUEUED`. This is a delivery failure — the command never reached the gateway. Do not record an execution attempt and do not set execution status to `FAILED`. `FAILED` means the gateway confirmed the action did not succeed. An unreachable gateway means the command was not delivered, which is a different condition.

Command signing keys require rotation and revocation procedures. Define these before the response workflow is implemented.

---

## State Machines: Alert and Incident

### Alert lifecycle

```
NEW → ACKNOWLEDGED → UNDER_INVESTIGATION → RESOLVED
                                         → FALSE_POSITIVE
```

`FALSE_POSITIVE` is a distinct outcome. Do not treat it as successful containment.

### Incident lifecycle

```
OPEN → TRIAGED → INVESTIGATING → CONTAINMENT_IN_PROGRESS
    → CONTAINED → RECOVERING → RESOLVED → CLOSED
```

Allow explicit transitions for incidents that are reopened or determined to be false alarms. Each transition records the actor, timestamp, and reason. A service may only perform the transitions it owns.

---

## Schema Catalogue

Every schema lives in `contracts/`. The following schemas must exist before parallel development begins.

| Schema file | Purpose |
|---|---|
| `gateway-registration-v1.json` | Enrollment and gateway identity |
| `gateway-heartbeat-v1.json` | Health and sensor status |
| `sensor-status-v1.json` | Individual sensor availability |
| `event-batch-v1.json` | Batch ingestion and partial acceptance |
| `network-connection-v1.json` | Canonical network event |
| `asset-v1.json` | Infrastructure ownership and criticality |
| `network-indicator-v1.json` | IP, CIDR, domain, and other network indicators |
| `detection-finding-v1.json` | Individual detector output |
| `alert-v1.json` | Correlated actionable finding |
| `incident-v1.json` | Security case |
| `evidence-v1.json` | Traceable evidence and storage reference |
| `investigation-result-v1.json` | AI or analyst investigation |
| `action-proposal-v1.json` | Proposed response |
| `policy-evaluation-v1.json` | Allow, deny, or request approval |
| `approval-v1.json` | Human authorization |
| `action-command-v1.json` | Signed executable command |
| `execution-result-v1.json` | Actual gateway execution result |
| `audit-event-v1.json` | Security-relevant activity record |
| `telemetry-health-v1.json` | Detection visibility and sensor health |

---

## HTTP API Contracts

### API namespaces

| Namespace | Consumers |
|---|---|
| `/api/v1/...` | Web application and authorized platform clients |
| `/edge/v1/...` | Authenticated gateway communication only |
| `/internal/v1/...` | Trusted backend workers only — never exposed as customer endpoints |

### Customer-facing API

| Resource | Method | Endpoint | Responsibility |
|---|---|---|---|
| Identity | GET | `/api/v1/me` | Return current authenticated user and memberships |
| Tenants | GET | `/api/v1/tenants/current` | Get active tenant context |
| Memberships | GET | `/api/v1/tenants/current/memberships` | View tenant users and roles |
| Gateways | GET | `/api/v1/gateways` | List authorized gateways |
| Gateways | GET | `/api/v1/gateways/{gateway_id}` | Gateway status and details |
| Enrollment | POST | `/api/v1/gateways/enrollment-tokens` | Create gateway enrollment token |
| Sensors | GET | `/api/v1/gateways/{gateway_id}/sensors` | View installed and active sensors |
| Assets | GET | `/api/v1/assets` | List protected infrastructure |
| Assets | GET | `/api/v1/assets/{asset_id}` | View asset details and criticality |
| Events | GET | `/api/v1/events` | Search normalized events |
| Events | GET | `/api/v1/events/{event_id}` | Get event details |
| Alerts | GET | `/api/v1/alerts` | List alerts |
| Alerts | GET | `/api/v1/alerts/{alert_id}` | Get alert and evidence references |
| Alert acknowledgement | POST | `/api/v1/alerts/{alert_id}/acknowledgements` | Acknowledge an alert |
| Incidents | GET | `/api/v1/incidents` | List incidents |
| Incidents | GET | `/api/v1/incidents/{incident_id}` | Get incident details |
| Incident transition | POST | `/api/v1/incidents/{incident_id}/transitions` | Move an incident through an authorized state transition |
| Investigation | POST | `/api/v1/incidents/{incident_id}/investigations` | Request an investigation |
| Investigation | GET | `/api/v1/investigations/{investigation_id}` | Get investigation result |
| Investigation cancel | POST | `/api/v1/investigations/{investigation_id}/cancellations` | Stop an investigation run |
| Evidence | GET | `/api/v1/evidence/{evidence_id}` | Retrieve authorized evidence metadata |
| Proposals | GET | `/api/v1/incidents/{incident_id}/action-proposals` | List proposed responses |
| Proposals | POST | `/api/v1/incidents/{incident_id}/action-proposals` | Create a proposal through an authorized workflow |
| Approvals | POST | `/api/v1/action-proposals/{proposal_id}/approvals` | Approve or reject a proposal |
| Commands | GET | `/api/v1/commands/{command_id}` | View command lifecycle and result |
| Executions | GET | `/api/v1/action-proposals/{proposal_id}/executions` | View execution results |
| Policies | GET | `/api/v1/policies` | View effective security policies |
| Detectors | GET | `/api/v1/detectors` | View available detector versions and health |
| Audit | GET | `/api/v1/audit-events` | View authorized audit history |

Approval requests must record: approving user identity, role, decision, reason, time, proposal version, and approval expiry. Do not accept `{ "approved": true }` alone.

Do not expose all internal operations as customer-facing API calls. AI-generated action proposals are created through the investigation workflow or a restricted internal interface, not directly by the customer.

### Gateway-facing API

| Method | Endpoint | Responsibility |
|---|---|---|
| POST | `/edge/v1/gateways/{gateway_id}/heartbeat` | Gateway heartbeat and sensor health |
| POST | `/edge/v1/events:batch` | Send telemetry batch |
| POST | `/edge/v1/gateways/{gateway_id}/commands:claim` | Atomically claim pending commands (lease) |
| POST | `/edge/v1/gateways/{gateway_id}/commands/{command_id}/acknowledgements` | Confirm command receipt |
| POST | `/edge/v1/gateways/{gateway_id}/commands/{command_id}/results` | Report actual execution result |
| GET | `/edge/v1/gateways/{gateway_id}/configuration` | Retrieve authorized configuration |

Gateway authenticates using mutual TLS. The service verifies that the URL's `gateway_id` matches the authenticated certificate identity on every request.

Ingestion response (`202 Accepted`):

```json
{
  "batch_id": "0198e732-...",
  "status": "accepted",
  "accepted_count": 98,
  "rejected_count": 2,
  "rejections": [
    {
      "index": 7,
      "code": "INVALID_EVENT_SCHEMA",
      "message": "Missing required event timestamp."
    }
  ],
  "received_at": "2026-11-06T06:30:01Z"
}
```

`202 Accepted` means the batch has been accepted for processing. It does not mean detection has completed.

### Internal service API

| Method | Endpoint | Owner | Purpose |
|---|---|---|---|
| POST | `/internal/v1/detection/evaluate` | Detection | Evaluate an event or event batch |
| POST | `/internal/v1/incidents/{incident_id}/investigate` | Investigation | Start an investigation run |
| POST | `/internal/v1/policy/evaluate` | Policy | Evaluate an action proposal |
| POST | `/internal/v1/commands` | Response | Create an authorized, signed command |
| POST | `/internal/v1/commands/{command_id}/verify` | Response | Verify execution state |
| POST | `/internal/v1/audit-events` | Platform | Append a service audit record |

Internal endpoints use service authentication and least-privilege workload identities. Do not use a shared internal API key distributed to every worker.

### Common HTTP conventions

| Concern | Standard |
|---|---|
| JSON naming | `snake_case` |
| Date/time | UTC, RFC 3339 (e.g. `2026-11-06T06:30:00Z`) |
| IDs | UUIDv7 strings |
| Pagination | Cursor-based: `limit` and `cursor`; document maximum page size and stable cursor ordering |
| Authentication | User token/session for `/api/v1`; mTLS for `/edge/v1`; workload identity for `/internal/v1` |
| Retry protection | `Idempotency-Key` header for operations with side effects; document scope, storage duration, and replay behaviour |
| Concurrency | `ETag` and `If-Match` for updates where stale writes matter |
| Tracing | W3C `traceparent` on all API requests and broker messages |
| Request tracking | `X-Request-ID` (distinct from `trace_id`) |
| Errors | `application/problem+json` (RFC 9457) |
| Schema | OpenAPI 3.2.1 and shared JSON Schemas |
| Long-running operations | Return `202 Accepted`; provide a status endpoint for polling |
| Cross-tenant lookups | Return `403`, not a concealed `404`, for resources that exist but are not accessible |

### Error response format (RFC 9457)

```json
{
  "type": "https://api.ascense.example/problems/tenant-access-denied",
  "title": "Tenant access denied",
  "status": 403,
  "detail": "The requested resource is not accessible.",
  "instance": "/api/v1/incidents/0198e72f-...",
  "error_code": "TENANT_ACCESS_DENIED",
  "request_id": "0198e733-..."
}
```

### HTTP status code rules

- `401` — authentication is absent or invalid
- `403` — authenticated caller lacks permission (use for cross-tenant resources too)
- `409` — state conflict, duplicate operation, or stale state
- `422` — structurally valid request that fails domain validation
- Never return stack traces, secrets, internal prompts, database queries, or another tenant's data in an error response

---

## Internal Message Catalogue

Every broker message must define: message ID, schema version, producer, permitted consumers, tenant context, routing key, delivery guarantee, duplicate handling, retry/backoff rules, dead-letter behaviour, retention, and ordering requirements.

| Message type | Producer | Consumer |
|---|---|---|
| `gateway.heartbeat.received.v1` | Ingestion | Gateway health |
| `telemetry.batch.accepted.v1` | Ingestion | Normalization |
| `telemetry.event.normalized.v1` | Normalization | Detection |
| `detection.finding.created.v1` | Detection | Correlation |
| `alert.created.v1` | Correlation | Incident management |
| `incident.updated.v1` | Incident management | Investigation and dashboard |
| `investigation.completed.v1` | Investigation | Proposal workflow |
| `response.proposal.created.v1` | Investigation / user workflow | Policy |
| `response.approval.recorded.v1` | Approval service | Response |
| `response.command.created.v1` | Response | Gateway dispatcher |
| `response.execution.reported.v1` | Gateway | Response verification |
| `response.verification.completed.v1` | Verification | Incident management |

Do not assume events arrive in timestamp order. The system must handle late and duplicate deliveries.

---

## Database Schema Conventions

Every tenant-owned table must carry `tenant_id` as a non-nullable column with a foreign key constraint. Add tenant-scoped indexes and enable row-level security where appropriate. Application authorization is still required — database RLS is an additional layer, not a replacement.

```sql
CREATE TABLE detection_findings (
    id                   UUID        PRIMARY KEY,
    tenant_id            UUID        NOT NULL,
    detector_id          TEXT        NOT NULL,
    detector_version     TEXT        NOT NULL,
    model_version_id     UUID,
    rule_version         TEXT,
    feature_schema_version TEXT,
    finding_type         TEXT        NOT NULL,
    severity             TEXT        NOT NULL,
    risk_score           INTEGER     NOT NULL,
    confidence           NUMERIC(5,4),
    observed_at          TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL
);

CREATE TABLE alerts (
    id          UUID        PRIMARY KEY,
    tenant_id   UUID        NOT NULL,
    incident_id UUID,
    alert_type  TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    risk_score  INTEGER     NOT NULL,
    status      TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE execution_attempts (
    id                        UUID        PRIMARY KEY,
    tenant_id                 UUID        NOT NULL,
    command_id                UUID        NOT NULL,
    gateway_id                UUID        NOT NULL,
    command_hash              TEXT        NOT NULL,
    received_at               TIMESTAMPTZ NOT NULL,
    execution_started_at      TIMESTAMPTZ,
    execution_completed_at    TIMESTAMPTZ,
    execution_status          TEXT        NOT NULL,  -- NOT_STARTED, RUNNING, SUCCEEDED, FAILED, PARTIALLY_SUCCEEDED, UNKNOWN, ROLLBACK_PENDING, ROLLED_BACK, ROLLBACK_FAILED
    verification_status       TEXT        NOT NULL DEFAULT 'PENDING',  -- PENDING, VERIFIED, NOT_VERIFIED, UNKNOWN
    observed_enforcement_state TEXT,
    result_reference          TEXT,
    created_at                TIMESTAMPTZ NOT NULL
);
```

Do not create a table and later retrofit tenant isolation.

---

### Manual proposal permissions

The customer-facing `POST /api/v1/incidents/{incident_id}/action-proposals` endpoint serves two distinct actors:

- **AI investigation service** — creates proposals through a restricted internal workflow using a service identity; proposals are tagged `created_by: "investigation_service"`
- **Authorized security analyst** — manually requests a response through the customer-facing API; proposals are tagged `created_by: "user"` and must include a recorded user identity and reason

Define separate permissions:

| Permission | Who holds it |
|---|---|
| `investigation.proposal:create` | Investigation service (internal) |
| `response.proposal:create` | Authorized security analyst role |
| `response.proposal:approve` | Authorized approver role (not the proposal creator for high-impact actions) |
| `response.command:execute` | Response service (internal only) |

The AI service must not use the customer-facing proposal endpoint. A human analyst's proposal must have a recorded user identity and reason before it can proceed to policy evaluation.

---

## Contract Change Rules

1. **No private schema versions.** A developer cannot silently add a field to their local version and expect another module to understand it.
2. **Additive changes are preferred.** Adding an optional field is usually compatible. Renaming, removing, or changing the meaning of a field requires a version bump.
3. **Version breaking changes.** Use versioned type names, e.g. `com.ascense.network.connection.observed.v2`.
4. **Every contract change needs an example and a test.** A schema definition without valid and invalid examples is not sufficient.
5. **Do not reuse an identifier for a different object.** An `event_id` always represents the same event record.
6. **Status transitions are owned.** A service may not change another service's state simply because its database connection permits it.
7. **API deprecation policy.** Define how long old versions are supported and how consumers are notified before removal.

Enforce these rules through pull-request checks on `contracts/`.

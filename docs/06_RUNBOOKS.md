# Ascense Operational Runbooks

> These runbooks cover the most common operational scenarios for Stage 7 readiness.
> Each runbook describes: symptoms, impact, diagnosis steps, and resolution.

---

## RB-01 · Gateway Enrollment and Certificate Issuance

**When to use:** Enrolling a new gateway or re-enrolling after certificate expiry/revocation.

### Steps
1. Create an enrollment token via the dashboard or API:
   ```
   POST /api/v1/gateways/enrollment-tokens
   {"name": "site-gw-01", "expires_in_seconds": 3600}
   ```
   Note the `token` and `gateway_id` from the response.

2. On the gateway host, submit the enrollment request:
   ```
   POST /edge/v1/gateways/enrollment
   {"token": "<token>", "gateway_id": "<gateway_id>", "hostname": "site-gw-01"}
   ```
   The response contains the signed certificate PEM. Store it securely.

3. Configure the gateway to use the certificate for mTLS connections.

4. Verify the gateway appears as `ACTIVE` in the dashboard within 2 minutes of sending the first heartbeat.

**Rollback:** Delete the gateway record and enrollment token if the enrollment was created in error.

---

## RB-02 · Certificate Rotation Without Losing Telemetry

**Symptoms:** Certificate approaching expiry (`certificate_expires_at` within 30 days).

**Impact:** Gateway stops sending telemetry when certificate expires.

### Steps
1. While the current certificate is still valid, create a new enrollment token for the same gateway.
2. On the gateway, perform the enrollment flow to receive a new certificate.
3. The gateway switches to the new certificate on the next heartbeat cycle.
4. Verify `last_heartbeat_at` continues updating after rotation.
5. Revoke the old certificate via the gateway certificate management endpoint.

**Never:** Revoke the old certificate before the new one is confirmed working.

---

## RB-03 · Certificate Revocation and Re-Enrollment

**When to use:** Gateway hardware is compromised, stolen, or decommissioned.

### Steps
1. Identify the `certificate_fingerprint` for the gateway.
2. Mark the certificate as revoked in the `gateway_certificates` table.
3. Set the gateway status to `REVOKED`.
4. All subsequent commands targeting this gateway will be rejected.
5. If re-enrolling new hardware: create a fresh gateway record and enrollment token.

**Impact:** Telemetry stops immediately. Any queued commands are cancelled.

---

## RB-04 · Event Backlog Recovery After Broker Outage

**Symptoms:** `TELEMETRY_STALE` on multiple gateways. RabbitMQ was down.

**Impact:** Events buffered on gateways were not processed; detection pipeline stalled.

### Steps
1. Confirm RabbitMQ is healthy: `docker compose ps rabbitmq`
2. Check the outbox table for unpublished records:
   ```sql
   SELECT COUNT(*) FROM outbox WHERE published = false;
   ```
3. The outbox publisher worker (running in the API process) will automatically retry unpublished records on the next poll cycle (every 2 seconds).
4. Monitor the retry count — records with `retry_count >= 5` have failed permanently and are in the dead-letter queue.
5. Review `q.dead_letter` in the RabbitMQ management UI for failed messages.
6. Once the backlog clears, `TELEMETRY_STALE` gateways will return to `ACTIVE` on the next heartbeat.

---

## RB-05 · Response Failure (Failed or Partially Succeeded Action)

**Symptoms:** `execution_status: FAILED` or `PARTIALLY_SUCCEEDED` on a command.

**Impact:** The intended enforcement action did not complete. Threat may still be active.

### Steps
1. Check the execution attempt: `GET /api/v1/action-proposals/{proposal_id}/executions`
2. Review `observed_enforcement_state` for partial state.
3. Check `verification_status` — if `UNVERIFIABLE`, the verification service could not confirm state.
4. If `PARTIALLY_SUCCEEDED`: determine what completed and what did not. Manual remediation may be required.
5. If rollback is needed: create a new proposal with `action_type: block_network_indicator` reversed, go through the full approval flow.
6. Update the incident status to reflect the outcome.

**Never:** Treat `UNKNOWN` verification_status as success. Always escalate.

---

## RB-06 · Backup and Restore (PostgreSQL + Object Storage)

### PostgreSQL backup
```bash
pg_dump -h localhost -U ascense -d ascense > ascense_backup_$(date +%Y%m%d).sql
```

### PostgreSQL restore
```bash
psql -h localhost -U ascense -d ascense < ascense_backup_YYYYMMDD.sql
```

### MinIO/S3 evidence backup
```bash
# Sync evidence bucket to local storage
mc mirror minio/ascense-evidence ./backup/evidence/
```

**Note:** Audit records must never be deleted. If restoring, ensure audit records are not overwritten.

---

## RB-07 · TELEMETRY_STALE Investigation and Recovery

**Symptoms:** One or more gateways show `TELEMETRY_STALE` in the dashboard.

**Diagnostic tree:**
1. Is the gateway process running on the hardware? → Check gateway host uptime.
2. Is the network path between gateway and platform open? → Check firewall rules, VPN.
3. Is the heartbeat being received? → Check `last_heartbeat_at` in the gateways table.
4. Are events arriving? → Check `SELECT COUNT(*) FROM events WHERE gateway_id = '<id>' AND observed_at > now() - interval '5 minutes';`
5. Is the sensor process running? → Check sensor status from last heartbeat.

**Resolution:** Address whichever step fails. After recovery, `TELEMETRY_STALE` clears automatically when events resume (background job runs every 30 seconds).

---

## RB-08 · Approval Service Unavailable

**Symptoms:** `POST /api/v1/action-proposals/{id}/approvals` returns 503.

**Impact:** Approved proposals cannot be recorded; command creation is blocked.

### Steps
1. Check the API process health: `GET /health`
2. Check the database connection: verify `DATABASE_URL` and PostgreSQL availability.
3. Approvals are stored in PostgreSQL — no separate service is required in v1.
4. If the API is down, queued commands will not be dispatched (lease expiry worker is also down).
5. Commands will remain `QUEUED` until the API recovers. No phantom executions will occur.
6. Once recovered, the lease expiry worker will clean up any stale leases and re-queue commands.

---

## RB-09 · Known Limitations (v1)

- **Production mTLS deployment**: Development may use `X-Tenant-ID` and `X-Gateway-ID` headers only when `ASCENSE_ENV=development`. Production must deploy the HAProxy configuration in `infrastructure/deployment/haproxy.cfg`, which terminates gateway mTLS, strips client-supplied identity headers, forwards one Base64-DER certificate header, and authenticates to the API with internal mTLS. The API container must use the production Compose command and mount `api-server.pem`, `api-server-key.pem`, and `proxy-ca.pem`; otherwise the proxy-to-API client certificate is not enforced.
- **OIDC not yet integrated**: User authentication uses `X-User-ID` header in development. Production requires a real OIDC provider configured via `JWT_ISSUER` and `JWT_AUDIENCE`.
- **AI investigation is a stub**: The investigation worker exists but does not yet call an LLM. Full LangGraph integration is Stage 5 work.
- **OPA/Rego policy gate is in-process**: The policy engine runs as a Python function, not a separate OPA process. Production should use the OPA binary for policy isolation.
- **Events table partitioning**: The partitioning migration creates monthly partitions. Future partitions must be created ahead of time (via pg_partman or a cron job).
- **Object storage not yet integrated**: Evidence `storage_reference` is stored but no presigned URL generation is implemented.

---

## SLO Baseline Measurements (target)

| Metric | Target | Measurement |
|--------|--------|-------------|
| Event ingestion latency (p95) | < 500ms | From gateway send to DB write |
| Normalization latency (p95) | < 2s | From outbox publish to detection queue |
| Detection latency (p95) | < 5s | From event ingestion to finding created |
| Alert creation latency (p95) | < 10s | From finding to alert |
| API response time (p95) | < 200ms | For list/get endpoints |
| Command delivery latency (p95) | < 30s | From QUEUED to ACKNOWLEDGED |

> Baseline measurements will be recorded in the first pilot deployment.

# ADR-003: Internal Identifiers

**Status:** Accepted
**Date:** 2026-11-06

## Context

The platform needs a consistent identifier strategy across all entities, logs, and API responses. Identifiers must be unique, time-ordered for database indexing, and distinguishable from distributed trace identifiers.

## Decision

**UUIDv7 (RFC 9562) for all internally generated entity IDs, serialized as lowercase strings. W3C Trace Context `trace_id` for distributed tracing.**

- UUIDv7 provides time-ordered IDs that are index-friendly and globally unique.
- `trace_id` is a 32-character lowercase hex string (16 bytes) carried in the `traceparent` header.
- The external IdP subject is NOT the internal `user_id`. A mapping is maintained.
- Prefixes in logs (e.g. `gw:`, `inc:`) are display conventions only — the actual identifier is always a plain UUID.

## Consequences

- All database primary keys are UUIDv7.
- No sequential integer IDs exposed in APIs.
- `source_event_id` from sensors is preserved as-is (opaque string).
- Deduplication uses `(source, id)` = `(gateway_id + sensor_instance_id, source_event_id)`.

## Alternatives Considered

1. **UUIDv4** — random IDs cause index fragmentation in PostgreSQL.
2. **Sequential integers** — leak business volume and require coordination.
3. **ULID** — similar properties to UUIDv7 but UUIDv7 is now an RFC standard.

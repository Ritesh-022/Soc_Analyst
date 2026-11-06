# ADR-004: Event Envelope Format

**Status:** Accepted
**Date:** 2026-11-06

## Context

The platform collects events from multiple sensor types (Suricata, Zeek, firewall logs). A canonical event format is needed so detection rules, correlation, and investigation all work against one structure regardless of the source sensor.

## Decision

**CloudEvents 1.0 as the event envelope.**

Every event uses the CloudEvents 1.0 spec with Ascense-specific extension attributes:
- `tenantid` and `gatewayid` are verified against the authenticated gateway identity — never trusted from the payload alone.
- `source` identifies both the gateway and the specific sensor instance: `urn:ascense:gateway:{gateway_id}/sensor/{sensor_instance_id}`
- `dataschema` identifies the payload schema URI; `data.schema_version` is the Ascense-specific payload version.
- `id` equals `source_event_id` — the original sensor identifier preserved from source.

## Consequences

- An explicit allowlist of event types prevents sensors from inventing arbitrary categories.
- Deduplication uses `(source, id)` which maps to `(gateway_id + sensor_instance_id, source_event_id)`.
- When a sensor provides no stable ID, the gateway generates one before first transmission and reuses it on retries.

## Alternatives Considered

1. **Custom JSON format** — would not benefit from the CloudEvents ecosystem (SDKs, routing, tooling).
2. **Protobuf** — adds complexity and is harder to debug in development.

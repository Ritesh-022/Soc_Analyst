# ADR-001: Gateway Deployment Model

**Status:** Accepted
**Date:** 2026-11-06

## Context

Ascense needs to collect security events from customer infrastructure and optionally execute response actions through the customer's existing security controls. The deployment model must not introduce a single point of failure for customer network connectivity or require network topology changes.

## Decision

**Out-of-band monitoring with controlled integration into existing security controls.**

Customer network traffic does not pass through Ascense. The gateway agent collects telemetry passively from sensors (Suricata, Zeek, firewall logs). Approved response adapters can manage specific controls in a customer's existing firewall or security product when an authorized action is executed.

## Consequences

- Ascense is not a single point of failure for customer network connectivity.
- Deployment does not require network topology changes.
- Response adapters are allowlisted, scoped, and audited — not arbitrary control-plane access.
- The gateway initiates outbound connections; Ascense does not open inbound access into customer networks.
- Inline inspection is a future product capability, not a v1 requirement.

## Alternatives Considered

1. **Inline gateway (bump-in-the-wire)** — would require network topology changes, introduce a single point of failure, and require HA design from day one. Deferred to Tier 2.
2. **Cloud-only SaaS without gateway** — cannot collect network telemetry from customer infrastructure without an agent on the customer side.

# ADR-002: Message Broker Selection

**Status:** Accepted
**Date:** 2026-11-06

## Context

The platform needs a message broker to decouple event ingestion from detection, detection from correlation, and the response workflow stages. The broker must support the transactional outbox pattern and handle at-least-once delivery with dead-letter routing.

## Decision

**RabbitMQ as the message broker.**

RabbitMQ provides topic exchanges for routing, dead-letter queues for failed messages, and management UI for operational visibility. It integrates cleanly with the transactional outbox pattern.

## Consequences

- At-least-once delivery is the model. Duplicate delivery is expected and handled safely by idempotent consumers.
- Failed messages retry with exponential backoff, then go to a dead-letter queue for inspection.
- No Kafka, NATS, or other brokers are introduced. The single-broker choice avoids operational complexity for a small team.

## Alternatives Considered

1. **Kafka** — operational overhead is too high for a 4-person team and the event volume does not justify partitioned log semantics.
2. **NATS** — viable but less ecosystem support and management tooling than RabbitMQ.
3. **PostgreSQL LISTEN/NOTIFY** — not suitable for the at-least-once delivery guarantee with retry and dead-letter routing.

## Notes

Revision 2 of the full specification mentions "PostgreSQL-backed queue or Redis streams" as a simplified MVP alternative. The refined docs (01-05) standardize on RabbitMQ. This ADR follows the refined docs.

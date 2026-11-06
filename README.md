# Ascense

Autonomous cyber defense platform with an out-of-band monitoring model, controlled response workflow, and tenant-isolated multi-tenant architecture.

The system spans four planes: edge gateway agents, the central platform (API, core domain modules, and workers), the web dashboard, and shared contracts that bind them together.

## Documentation

- [01 System Architecture](docs/01_SYSTEM_ARCHITECTURE.md)
- [02 Contracts and Identifiers](docs/02_CONTRACTS_AND_IDENTIFIERS.md)
- [03 Module Ownership](docs/03_MODULE_OWNERSHIP.md)
- [04 Development Workflow](docs/04_DEVELOPMENT_WORKFLOW.md)
- [05 Testing and Security Strategy](docs/05_TESTING_AND_SECURITY_STRATEGY.md)
- [Full Specification](docs/Autonomous_Cyber_Defense_Platform_Full_Specification_Revision2.md)

## Repository layout

```
apps/web/        React + TypeScript + Vite dashboard
ascense/        FastAPI platform (api, core domain, workers)
edge/            Go gateway agent
contracts/       Shared, authoritative schemas and OpenAPI definitions
database/        Migrations, seeds, and row-level policies
infrastructure/  Docker, compose, monitoring, and deployment tooling
tests/           Cross-module unit, integration, contract, security, e2e, and failure tests
docs/            Architecture, ADRs, runbooks, and threat model
```

## Quick start

```bash
make install      # install Python and web dependencies
make docker-up    # start local stack (Postgres, RabbitMQ, etc.)
make migrate      # run database migrations
make dev-api      # start the platform API on :8000
make dev-web      # start the dashboard on :5173
```

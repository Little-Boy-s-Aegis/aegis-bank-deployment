# Aegis Bank Deployment

[![Git Clones](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Little-Boy-s-Aegis/aegis-bank-deployment/main/aegis-bank-deployment-clone-badge.json)](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment)
[![Unique Cloners](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Little-Boy-s-Aegis/aegis-bank-deployment/main/aegis-bank-deployment-uniques-badge.json)](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment)
[![Release Downloads](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Little-Boy-s-Aegis/aegis-bank-deployment/main/downloads-badge.json)](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment/releases)
[![Stars](https://img.shields.io/github/stars/Little-Boy-s-Aegis/aegis-bank-deployment?style=flat&color=F59E0B&logo=github&label=stars)](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment/stargazers)

Local orchestration and deployment assets for the complete Little Boy's Aegis
banking and AI-native SOC platform. The default Docker Compose stack joins the
bank applications, telemetry pipeline, Layer 1/Layer 2 processing, SOAR
execution, SOC dashboard, policy engine, secrets service, and safe staging
targets behind a loopback-only Nginx gateway.

## Stack Overview

```text
browser --> Nginx :80
              |-- /           --> Next.js banking portal
              |-- /api-bank/  --> Spring Boot banking API
              |-- /soc/       --> React SOC dashboard
              `-- /api/       --> Go SOC API

bank + gateway logs --> Fluent Bit --> Kafka --> log parser / Layer 1
                                                |
                                                v
                                        SOAR orchestrators (HA)
                                                |
                                      OPA + Redis + PostgreSQL
                                                |
                                      action workers (HA)
                                                |
                                   staging sandbox / notifications
```

## Included Services

| Group | Services | Role |
|---|---|---|
| Data | `postgres`, `redis`, `qdrant` | Durable application/audit data, SOAR state, vectors |
| Streaming | `kafka-1..3`, `kafka-init`, `kafka-ui` | Three-node KRaft event bus, topic bootstrap, Kafdrop UI |
| Banking | `be-backend`, `fe-web` | Spring Boot API and Next.js client |
| SOC | `dashboard-backend`, `dashboard-frontend` | Go API and React operator UI |
| Telemetry | `fluent-bit`, `log-parser`, `vector-db-init` | Log collection, classification, and vector bootstrap |
| SOAR | active/standby orchestrators and action workers | Decision, HA, and response execution |
| Policy/secrets | `opa`, `vault`, `vault-init` | Authorization and runtime secret initialization |
| Gateway/sandbox | `nginx`, `staging-sandbox` | Single entrypoint and safe connector target |

## Prerequisites

- Docker Engine with the Compose v2 plugin
- At least 8 GB RAM available to Docker; more is recommended for the full stack
- `openssl` or another secure random generator for local secrets
- The component repositories checked out as siblings

The Compose build contexts expect this workspace shape. Symlinks may be used for
the historical `BE`, `FE_Web`, and `soar-engine` names:

```text
workspace/
├── BE/ or BE -> aegis-bank-backend
├── FE_Web/ or FE_Web -> aegis-bank-web-client
├── dashboard/
├── soar-engine/ or soar-engine -> aegis-soar-engine
├── agent-layer-1/
├── agent-layer-2/
└── aegis-bank-deployment/
```

## Configure Secrets

Create `.env` only if one is not already present:

```bash
cp .env.example .env
```

At minimum, set independent values for:

- `POSTGRES_PASSWORD`
- `JWT_SECRET`
- `AEGIS_SECURITY_SYNC_TOKEN`
- `VAULT_ROOT_TOKEN`

Generate local values with `openssl rand -hex 32`. Configure LLM and vendor
credentials only for integrations you intend to exercise. Defaults prefixed
with `mock-` keep many connectors in simulation mode.

Never commit `.env`, generated backup data, real customer telemetry, cloud
credentials, or vendor tokens. Before starting, render and validate the merged
configuration without printing it into shared logs:

```bash
docker compose config --quiet
```

## Start the Platform

```bash
docker compose up --build -d
docker compose ps
```

Initial startup waits for PostgreSQL, Redis, Kafka, Qdrant, topic creation,
Vault initialization, and vector ingestion before dependent services settle.
Follow progress with:

```bash
docker compose logs -f --tail=100
```

## Entrypoints

Only the gateway and staging UI are published to the host by the default file;
both bind to `127.0.0.1`.

| Component | URL | Notes |
|---|---|---|
| Banking portal | `http://localhost/` | Nginx to Next.js |
| Banking API | `http://localhost/api-bank/` | Nginx strips `/api-bank` before Spring Boot |
| SOC dashboard | `http://localhost/soc/` | React SPA |
| SOC API | `http://localhost/api/` | Go API |
| Staging sandbox | `http://localhost:8095/` | Basic-auth simulator UI |

PostgreSQL, Redis, Qdrant, Kafka brokers, Kafdrop, Vault, OPA, and application
ports are internal-only. Use `docker compose exec`, an explicit temporary
override, or a secure tunnel for diagnostics; do not publish them broadly.

## Event Pipeline

Kafka runs three combined KRaft broker/controller nodes with replication factor
`3` and minimum in-sync replicas `2`. One broker can fail without losing write
availability; two broker failures remove quorum.

`kafka-init` provisions the required topics before the telemetry consumers
start. Fluent Bit tails shared Nginx and Spring Boot logs, while the log parser
classifies events, maintains threshold state in Redis, writes raw-log backups,
and emits Layer 1 or deterministic fast-path findings. The SOAR layer consumes
those findings and publishes decisions/actions back to Kafka and the dashboard.

Inspect a topic from inside the first broker:

```bash
docker compose exec kafka-1 \
  /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka-1:29092 \
  --topic l1.agent.findings \
  --from-beginning --max-messages 5
```

## SOAR and Autopilot Warning

The current Compose file sets `SOC_AUTOPILOT_ENABLED` to `true` for the SOAR
orchestrators. OPA, verification, critical-asset checks, rate limits, and the
staging Fortinet target still gate execution, but you must review the rendered
configuration before supplying any real AWS or vendor credentials.

For analysis-only operation, override autopilot for both orchestrator services
in a local Compose override or edit a private deployment copy. Confirm that
actions remain suggested/queued and exercise rollback in the staging sandbox
before connecting production integrations.

## Common Operations

```bash
docker compose ps
docker compose logs -f dashboard-backend soar-orchestrator soar-action-worker
docker compose restart dashboard-backend
docker compose build be-backend
docker compose up -d be-backend
docker compose pull
```

Stop containers while retaining volumes:

```bash
docker compose down
```

Delete all named volumes and local service data:

```bash
docker compose down -v
```

The `-v` operation is destructive: it removes database, Kafka, Redis, Qdrant,
Vault, and Fluent Bit state. Use the scripts in `scripts/` and test restoration
before relying on backups.

## Validation and Tests

Configuration and policy checks:

```bash
docker compose config --quiet
docker compose exec opa opa test /policies -v
docker compose ps
```

Deployment tests are Python/pytest based:

```bash
python3 -m pytest -q tests
```

The suite includes container-security, frontend-security, pentest automation,
prompt evaluation, and SOAR security checks. Some tests require the full stack
to be healthy and should run only against an authorized local/staging target.

## Alternative Deployment Assets

- `docker-compose.network-enforcement.yml` adds the firewall-enforcement path.
- `kubernetes/base/` provides raw Kustomize resources for core services.
- `helm/aegis-platform/` provides a configurable Helm chart for local/AWS
  environments.
- `opa/policies/` contains authorization and SOAR policy data/tests.
- `scripts/` contains backup and Kafka initialization helpers.

These targets have separate secret, storage, ingress, and image requirements.
Review manifests and replace demonstration values before cluster deployment.

## Repository Layout

```text
docker-compose.yml                     # Full local platform
docker-compose.network-enforcement.yml # Optional enforcement overlay
nginx/                                 # Gateway and route policy
fluent-bit/                            # Log collection and filtering
log-parser/                            # Telemetry classification
opa/                                   # Authorization policies and tests
vault/                                 # Development Vault configuration/init
staging-sandbox/                       # Embedded safe response simulator
firewall-enforcer/                     # Network enforcement helper
kubernetes/base/                       # Kustomize manifests
helm/aegis-platform/                   # Helm chart
scripts/                               # Backup and bootstrap utilities
tests/                                 # Security/integration tests
```

## Troubleshooting

- Run `docker compose config --quiet` first for missing variables or YAML errors.
- Use `docker compose ps` to find unhealthy dependencies, then inspect that
  service's logs.
- If vector initialization fails, check Qdrant health, mounted Layer 1/2 paths,
  and the selected embedding provider.
- If the gateway returns `502`, verify the target container is healthy and on
  `aegis-network`; Nginx uses Docker DNS for service resolution.
- If Kafka consumers stall, inspect broker health and `kafka-init` completion.
- If SOAR actions are denied, inspect OPA, verification strength, critical-asset
  results, execution windows, Redis rate limits, and autopilot state.

### Current sandbox asset-inventory gap

The Compose file points `ASSET_INVENTORY_API_URL` at
`asset-inventory:8083/api/v1/assets/critical`, but the embedded
`staging-sandbox/app.py` currently starts only its `8095` listener. The separate
`aegis-staging-sandbox` repository includes the `8083` asset-inventory listener.
Until the embedded copy is synchronized, use that repository as the sandbox
build context or point the policy evaluator at another reviewed inventory
service; otherwise critical-asset lookups fail closed or return the evaluator's
unavailable behavior.

## Related Repositories

- [`aegis-bank-backend`](https://github.com/Little-Boy-s-Aegis/aegis-bank-backend)
- [`aegis-bank-web-client`](https://github.com/Little-Boy-s-Aegis/aegis-bank-web-client)
- [`dashboard`](https://github.com/Little-Boy-s-Aegis/dashboard)
- [`agent-layer-1`](https://github.com/Little-Boy-s-Aegis/agent-layer-1)
- [`agent-layer-2`](https://github.com/Little-Boy-s-Aegis/agent-layer-2)
- [`aegis-soar-engine`](https://github.com/Little-Boy-s-Aegis/aegis-soar-engine)
- [`aegis-bank-terraform`](https://github.com/Little-Boy-s-Aegis/aegis-bank-terraform)

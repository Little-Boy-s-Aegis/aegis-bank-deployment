# Aegis Bank Ecosystem Orchestration & Deployment

This folder contains the complete orchestration configuration for the Aegis Bank Attack & Defense Ecosystem. With Nginx configured as a reverse proxy, the entire multi-service stack runs through a single gateway port, avoiding port collisions and Cross-Origin Resource Sharing (CORS) issues.

---

## Folder Structure

```text
aegis-bank-deployment/
├── .env.example         # Template file for environment variables
├── docker-compose.yml   # Multi-service container definitions
├── nginx/
│   └── default.conf     # Reverse proxy / API gateway configuration
└── README.md            # This documentation
```

---

## Quick Start (Running with 1 Command)

### 1. Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

### 2. Configure Environment Variables
Copy the template `.env.example` file to `.env`:
```bash
cp .env.example .env
```
*(Open the `.env` file to customize passwords, ports, or secrets if necessary. By default, it works out-of-the-box.)*

### 3. Launch the Stack
Run this command from inside the `aegis-bank-deployment` directory:
```bash
docker compose up --build -d
```
This command will:
1. Compile the Java REST API (`BE`) and build its docker image.
2. Compile the Go SOC Backend (`dashboard/backend`) and build its docker image.
3. Package the React SOC Dashboard (`dashboard/frontend`) and build its docker image.
4. Compile the Next.js Web Portal (`FE_Web`) and build its docker image.
5. Launch PostgreSQL, 3-node Kafka HA cluster, Kafdrop, and Nginx.

---

## Kafka High Availability (3-Node KRaft Cluster)

The deployment uses a **3-node Apache Kafka cluster** running in **KRaft mode** (no Zookeeper dependency). This provides fault tolerance and data durability for the security event streaming pipeline.

### Architecture

```text
                    ┌──────────────────────────────────────────────┐
                    │        KRaft Controller Quorum (Raft)        │
                    │  kafka-1:9093  kafka-2:9093  kafka-3:9093    │
                    └──────────────────────────────────────────────┘
                           │              │              │
                    ┌──────┴──────┐┌──────┴──────┐┌──────┴──────┐
                    │  Broker #1  ││  Broker #2  ││  Broker #3  │
                    │  kafka-1    ││  kafka-2    ││  kafka-3    │
                    │  :29092 int ││  :29092 int ││  :29092 int │
                    │  :9094 ext  ││  :9095 ext  ││  :9096 ext  │
                    └─────────────┘└─────────────┘└─────────────┘
                           │              │              │
              ┌────────────┴──────────────┴──────────────┘
              │    Producers & Consumers connect to all brokers
              ├── be-backend     (Spring Boot - Security Event Producer)
              └── dashboard-backend  (Go - Security Event Consumer)
```

### HA Configuration Parameters

| Parameter | Value | Purpose |
|---|---|---|
| `replication.factor` | `3` | Each partition is replicated across all 3 brokers |
| `min.insync.replicas` | `2` | At least 2 replicas must acknowledge a write |
| `controller.quorum.voters` | `1@kafka-1,2@kafka-2,3@kafka-3` | Raft consensus with 3 voters |
| `transaction.state.log.replication.factor` | `3` | Transaction logs replicated across all brokers |

### Failure Tolerance
- **1 broker down**: Cluster continues operating normally. No data loss.
- **2 brokers down**: Cluster loses quorum and stops accepting writes. Existing data is preserved on the surviving node.

---

## Entrypoints & Ports

Once the containers are running, you can access the components at the following URLs:

| Component | Host Port | Docker Internal | URL / Entrypoint |
|---|---|---|---|
| **API Gateway (Nginx)** | `80` | `80` | **`http://localhost/`** *(Main Entrance)* |
| **Next.js Web Portal** | `3000` | `3000` | `http://localhost/` *(Proxied by Nginx)* |
| **Banking Java API** | `8080` | `8080` | `http://localhost/api-bank/` *(Proxied by Nginx)* |
| **Go SOC API** | `8082` | `8082` | `http://localhost/api/` *(Proxied by Nginx)* |
| **SOC Dashboard Frontend** | `3001` | `3001` | `http://localhost/soc/` *(Proxied by Nginx)* |
| **Kafdrop (Kafka UI)** | `9000` | `9000` | `http://localhost:9000/` *(Direct)* |
| **Kafka Broker 1** | `9094` | `29092` | External client access |
| **Kafka Broker 2** | `9095` | `29092` | External client access |
| **Kafka Broker 3** | `9096` | `29092` | External client access |

---

## Useful Management Commands

### Stop the entire ecosystem
```bash
docker compose down
```

### Stop and clean data volumes (resets database/Kafka logs)
```bash
docker compose down -v
```

### View real-time container logs
```bash
docker compose logs -f
```

### View Kafka cluster logs only
```bash
docker compose logs -f kafka-1 kafka-2 kafka-3
```

### View the centralized logging pipeline
```bash
docker compose logs -f fluent-bit log-parser
```

Fluent Bit is the Fluentd-family log forwarder used by this stack. It tails:
- Nginx access logs from `/var/log/nginx/aegis_access.log` into `l0.input.apigw`
- Nginx error logs from `/var/log/nginx/aegis_error.log` into `l0.input.waf`
- Spring Boot app logs from `/var/log/bank/application.log` into `l0.input.ebanking-app`
- cloned threat alerts into `aegis.security.events`

Kafka topics are provisioned by `kafka-init` before Fluent Bit and `log-parser` start. To inspect a stream:
```bash
docker compose exec kafka-1 /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server kafka-1:29092 --topic l0.input.apigw --from-beginning --max-messages 5
```

### Restart a specific service (e.g. rebuild backend changes)
```bash
docker compose restart be-backend
```
*(To build from scratch after code updates: `docker compose build be-backend && docker compose up -d be-backend`)*

---

## Advanced Deployment and Gateway Hardening

* **Nginx Reverse Proxy Security**: Patched an Nginx config bug regarding security headers inheritance (ensuring CORS, Content-Security-Policy, and clickjacking protection headers flow correctly to downstream proxy routes). 
* **Proxy Gateway Resilience**: Resolved Nginx DNS cache failures yielding `502 Bad Gateway` errors. Enabled dynamic name resolution for backend containers (using the Docker internal DNS resolver `127.0.0.11` with a short `valid=5s` TTL).
* **API Cache Tuning**: Integrated structured `Cache-Control` header rules to ensure browser clients do not cache sensitive financial transactions or security states.
* **GAP Agent Controls**: Configured and deployed specialist Named Agent Routers (GAP-02) and Layer 1 Dynamic Prompts (GAP-01) setups to customize telemetry collection prompts.
* **Centralized Logging (Fluent-Bit)**: Deployed Fluent-Bit containers to ingest, parse, and structure multi-container log fields for downstream Kafka events delivery.

---

## Related Repositories

| Repository | Description | Clone directory |
|---|---|---|
| [aegis-bank-backend](https://github.com/Little-Boy-s-Aegis/aegis-bank-backend) | Spring Boot banking REST API | `BE/` |
| [aegis-bank-web-client](https://github.com/Little-Boy-s-Aegis/aegis-bank-web-client) | Next.js banking portal | `FE_Web/` |
| [aegis-bank-mobile-app](https://github.com/Little-Boy-s-Aegis/aegis-bank-mobile-app) | Flutter mobile banking app | `FE_App/` |
| [dashboard](https://github.com/Little-Boy-s-Aegis/dashboard) | SOC Dashboard (Go + React) | `dashboard/` |
| [agent-layer-1](https://github.com/Little-Boy-s-Aegis/agent-layer-1) | AI Sensor Agents | `agent-layer-1/` |
| [agent-layer-2](https://github.com/Little-Boy-s-Aegis/agent-layer-2) | Meta Analyzer / SOAR orchestrator prompts | `agent-layer-2/` |
| [aegis-soar-engine](https://github.com/Little-Boy-s-Aegis/aegis-soar-engine) | SOAR Decision Engine | `soar-engine/` |
| [aegis-staging-sandbox](https://github.com/Little-Boy-s-Aegis/aegis-staging-sandbox) | Staging simulation APIs | `staging-sandbox/` |
| [aegis-bank-terraform](https://github.com/Little-Boy-s-Aegis/aegis-bank-terraform) | AWS Terraform infrastructure | `terraform/` |

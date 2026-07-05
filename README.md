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
5. Launch PostgreSQL, Kafka, Kafdrop, and Nginx.

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

### Restart a specific service (e.g. rebuild backend changes)
```bash
docker compose restart be-backend
```
*(To build from scratch after code updates: `docker compose build be-backend && docker compose up -d be-backend`)*

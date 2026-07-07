# Aegis Platform - Enterprise Banking & SOAR System

This chart deploys the **Aegis Banking and SOAR Defensive Platform** inside your Kubernetes cluster.

## Features
- **Core Banking Application**: Secure Spring Boot e-banking application with SQLi/XSS/Brute Force hardened endpoints.
- **SOC Alert Dashboard**: Go/React real-time security events dashboard with Kafka stream listeners.
- **SOAR Active Response Engine**: Dual active-standby Python orchestrators deploying automated mitigation playbooks via Fortinet API sandbox.
- **Log Processing & WAF**: Fluent-Bit log forwarder with real-time Lua log parsing engine.

## Prerequisites
- Kubernetes 1.20+
- Helm 3.0+
- Rancher 2.5+ (optional for Catalog UI)

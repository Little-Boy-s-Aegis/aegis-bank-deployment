#!/bin/bash

echo "=================================================="
echo "      AEGIS SYSTEM KAFKA TOPICS INITIALIZER       "
echo "=================================================="

# Wait for Kafka brokers to be ready
echo "Waiting for Kafka broker (kafka-1:29092) to respond..."
until /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka-1:29092 --list > /dev/null 2>&1; do
  echo "Kafka is not fully active yet. Retrying in 3 seconds..."
  sleep 3
done

echo "Kafka is responsive! Beginning topic provisioning..."

# Array of all required security logging and verification topics
TOPICS=(
  # --------------------------------------------------
  # L0 Inputs (14 log sources)
  # --------------------------------------------------
  "l0.input.edr"
  "l0.input.ndr"
  "l0.input.server"
  "l0.input.waf"
  "l0.input.apigw"
  "l0.input.ebanking-app"
  "l0.input.session-token"
  "l0.input.tx-audit"
  "l0.input.ueba"
  "l0.input.atm"
  "l0.input.iam-mfa"
  "l0.input.pam-vpn"
  "l0.input.ad-directory"
  "l0.input.firmware-usb"

  # --------------------------------------------------
  # L2 Verification (14 sources)
  # --------------------------------------------------
  "l2.verification.clean-log"
  "l2.verification.raw-log"
  "l2.verification.siem"
  "l2.verification.edr"
  "l2.verification.waf"
  "l2.verification.apigw"
  "l2.verification.iam"
  "l2.verification.network"
  "l2.verification.database"
  "l2.verification.threat-intel"
  "l2.verification.vector-db"
  "l2.verification.asset-inventory"
  "l2.verification.object-storage-pcap"
  "l2.verification.opa"

  # --------------------------------------------------
  # L1 Agent Findings (LLM Security Analyst output)
  # --------------------------------------------------
  "l1.agent.findings"

  # --------------------------------------------------
  # Notification (5 channels)
  # --------------------------------------------------
  "notification.dashboard"
  "notification.alert"
  "notification.telegram-teams"
  "notification.email"
  "notification.jira"
)

# Provision topics
for topic in "${TOPICS[@]}"; do
  echo "Provisioning topic: $topic"
  /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka-1:29092 \
    --create \
    --if-not-exists \
    --topic "$topic" \
    --partitions 3 \
    --replication-factor 3
done

echo "=================================================="
echo "  All 33 Kafka topics initialized successfully!   "
echo "=================================================="

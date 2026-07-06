#!/bin/sh
set -e

# Install curl and jq if not present (runs quickly on alpine)
if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  echo "Installing curl and jq..."
  apk add --no-cache curl jq
fi

# Wait for Vault to start up and be responsive
until curl -s http://vault:8200/v1/sys/health >/dev/null 2>&1; do
  echo "Waiting for Vault..."
  sleep 2
done

KEYS_FILE="/vault/file/keys.json"

# Check if Vault is initialized
INIT_STATUS=$(curl -s http://vault:8200/v1/sys/init)
IS_INITIALIZED=$(echo "$INIT_STATUS" | jq -r '.initialized')

if [ "$IS_INITIALIZED" = "false" ]; then
  echo "Vault is not initialized. Initializing..."
  # Initialize Vault with 1 key share and 1 key threshold for single-node setup
  INIT_RESPONSE=$(curl -s -X POST -d '{"secret_shares": 1, "secret_threshold": 1}' http://vault:8200/v1/sys/init)
  
  # Extract root token and unseal key
  UNSEAL_KEY=$(echo "$INIT_RESPONSE" | jq -r '.keys[0]')
  ROOT_TOKEN=$(echo "$INIT_RESPONSE" | jq -r '.root_token')
  
  # Save to persistent file
  echo "{\"unseal_key\": \"$UNSEAL_KEY\", \"root_token\": \"$ROOT_TOKEN\"}" > "$KEYS_FILE"
  echo "Vault initialized. Unseal key and root token saved."
else
  echo "Vault is already initialized."
fi

# Read unseal key and root token
UNSEAL_KEY=$(jq -r '.unseal_key' "$KEYS_FILE")
ROOT_TOKEN=$(jq -r '.root_token' "$KEYS_FILE")

# Check seal status and unseal if sealed
SEAL_STATUS=$(curl -s http://vault:8200/v1/sys/seal-status)
IS_SEALED=$(echo "$SEAL_STATUS" | jq -r '.sealed')

if [ "$IS_SEALED" = "true" ]; then
  echo "Vault is sealed. Unsealing..."
  curl -s -X POST -d "{\"key\": \"$UNSEAL_KEY\"}" http://vault:8200/v1/sys/unseal > /dev/null
  echo "Vault unsealed."
else
  echo "Vault is already unsealed."
fi

# Mount KV v2 engine at secret/ if it's not already mounted
MOUNT_CHECK=$(curl -s -H "X-Vault-Token: $ROOT_TOKEN" http://vault:8200/v1/sys/mounts)
if ! echo "$MOUNT_CHECK" | grep -q '"secret/"'; then
  echo "Mounting KV v2 engine at secret/..."
  curl -s -X POST \
    -H "X-Vault-Token: $ROOT_TOKEN" \
    -d '{"type": "kv", "options": {"version": "2"}}' \
    http://vault:8200/v1/sys/mounts/secret > /dev/null
fi

# Create expected root token (aegis-vault-root-token) for applications to connect
echo "Checking/creating custom root token..."
curl -s -o /dev/null -X POST \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d "{\"id\": \"$VAULT_ROOT_TOKEN\", \"policies\": [\"root\"]}" \
  http://vault:8200/v1/auth/token/create

# Provision secrets
echo "Provisioning secrets..."
curl -s -o /dev/null \
  -H "X-Vault-Token: $VAULT_ROOT_TOKEN" \
  -X POST \
  -d "{\"data\": {\"FORTINET_API_TOKEN\": \"$FORTINET_API_TOKEN\", \"CROWDSTRIKE_CLIENT_SECRET\": \"$CROWDSTRIKE_CLIENT_SECRET\", \"ENTRA_CLIENT_SECRET\": \"$ENTRA_CLIENT_SECRET\", \"AD_LDAP_PASSWORD\": \"$AD_LDAP_PASSWORD\", \"AWS_SECRET_ACCESS_KEY\": \"$AWS_SECRET_ACCESS_KEY\"}}" \
  http://vault:8200/v1/secret/data/aegis/soar

echo "Secrets provisioned successfully."

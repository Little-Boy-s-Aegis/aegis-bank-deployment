#!/bin/sh
set -eu

API_URL="${DASHBOARD_BANNED_IPS_URL:-http://127.0.0.1:80/api/banned-ips}"
INTERVAL_SECONDS="${IP_BAN_ENFORCER_INTERVAL_SECONDS:-3}"
IPSET_V4="${IP_BAN_IPSET_V4:-aegis_banned_ipv4}"

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

ensure_rule() {
  table="$1"
  chain="$2"
  shift 2
  if ! iptables -w -t "$table" -C "$chain" "$@" 2>/dev/null; then
    iptables -w -t "$table" -I "$chain" 1 "$@" || true
  fi
}

ensure_firewall_hooks() {
  ipset create "$IPSET_V4" hash:net family inet -exist

  ensure_rule filter INPUT -m set --match-set "$IPSET_V4" src -j DROP
  ensure_rule filter OUTPUT -m set --match-set "$IPSET_V4" dst -j DROP
  ensure_rule filter FORWARD -m set --match-set "$IPSET_V4" src -j DROP
  ensure_rule filter FORWARD -m set --match-set "$IPSET_V4" dst -j DROP

  if iptables -w -L DOCKER-USER >/dev/null 2>&1; then
    ensure_rule filter DOCKER-USER -m set --match-set "$IPSET_V4" src -j DROP
    ensure_rule filter DOCKER-USER -m set --match-set "$IPSET_V4" dst -j DROP
  fi
}

is_safe_to_apply() {
  rule="$1"
  case "$rule" in
    ""|127.*|0.*|169.254.*|224.*|225.*|226.*|227.*|228.*|229.*|230.*|231.*|232.*|233.*|234.*|235.*|236.*|237.*|238.*|239.*|240.*|241.*|242.*|243.*|244.*|245.*|246.*|247.*|248.*|249.*|250.*|251.*|252.*|253.*|254.*|255.*|*:* )
      return 1
      ;;
  esac
  return 0
}

fetch_active_bans() {
  if [ -n "${AEGIS_INTERNAL_TOKEN:-}" ]; then
    curl -fsS -H "X-Aegis-Internal-Key: ${AEGIS_INTERNAL_TOKEN}" "$API_URL"
  else
    curl -fsS "$API_URL"
  fi
}

apply_active_bans() {
  tmp_json="$(mktemp)"
  tmp_rules="$(mktemp)"

  if ! fetch_active_bans > "$tmp_json"; then
    log "[WARN] Cannot fetch active banned IPs from $API_URL"
    rm -f "$tmp_json" "$tmp_rules"
    return 1
  fi

  jq -r '.[] | select(.status == "active") | .ipAddress' "$tmp_json" > "$tmp_rules"

  ipset flush "$IPSET_V4"
  applied=0
  while IFS= read -r rule; do
    if is_safe_to_apply "$rule"; then
      if ipset add "$IPSET_V4" "$rule" -exist 2>/dev/null; then
        applied=$((applied + 1))
      else
        log "[WARN] Invalid IPv4 ban rule skipped: $rule"
      fi
    else
      log "[WARN] Unsafe or unsupported ban rule skipped at kernel layer: $rule"
    fi
  done < "$tmp_rules"

  log "[OK] Kernel firewall denylist synced: $applied IPv4 rule(s)"
  rm -f "$tmp_json" "$tmp_rules"
}

if ! command -v iptables >/dev/null 2>&1 || ! command -v ipset >/dev/null 2>&1; then
  log "[ERROR] iptables/ipset are required"
  exit 1
fi

ensure_firewall_hooks
log "[OK] Aegis kernel IP ban enforcer started. Source: $API_URL"

while true; do
  apply_active_bans || true
  sleep "$INTERVAL_SECONDS"
done

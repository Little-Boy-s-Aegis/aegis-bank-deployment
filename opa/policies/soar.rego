package aegis.soar.policy

default allow = false

# Allow action by default unless safety violations occur
allow {
    not deny_actions
}

# Rule 1: Deny blocking critical IPs (e.g. DNS, Active Directory, Core Banking Gateway)
deny_actions {
    input.action_type == "block_ip"
    is_critical_ip(input.target)
}

# Rule 2: Deny quarantining critical hosts (e.g. primary database DB-PROD)
deny_actions {
    input.action_type == "quarantine_host"
    is_critical_host(input.target)
}

# Rule 3: Deny automatic containment actions if risk score is too low (< 5.0)
deny_actions {
    input.phase == "contain"
    input.approval_mode == "AUTO"
    input.risk_score < 5.0
}

# Helper: Critical IP list
is_critical_ip(ip) {
    critical_ips := ["10.0.0.1", "10.0.0.2", "192.168.1.1", "192.168.1.254"]
    critical_ips[_] == ip
}

# Helper: Critical host list
is_critical_host(host) {
    critical_hosts := ["DB-PROD-01", "DC-PROD-AD", "CORE-BANK-GW"]
    critical_hosts[_] == host
}

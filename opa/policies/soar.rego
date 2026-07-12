package aegis.autopilot

default allow = false

config := data.aegis_config.autopilot

allow {
    count(violations) == 0
}

decision := {
    "allow": allow,
    "decision_id": input.request.action_id,
    "policy_revision": config.policy_revision,
    "reasons": reasons,
}

reasons := [r | violations[r]]

violations["missing_required_identity"] { input.request.action_id == "" }
violations["missing_required_identity"] { not input.request.action_id }
violations["missing_required_identity"] { input.request.incident_id == "" }
violations["missing_required_identity"] { not input.request.incident_id }
violations["missing_required_identity"] { input.request.tenant_id == "" }
violations["missing_required_identity"] { not input.request.tenant_id }
violations["invalid_execution_mode"] { input.execution.mode != "autopilot" }
violations["untrusted_orchestrator"] { input.execution.orchestrator_id != config.orchestrator_id }
violations["untrusted_caller"] { not trusted_caller }
violations["policy_revision_mismatch"] { input.execution.policy_revision != config.policy_revision }
violations["unsupported_action"] { not supported_action }
violations["missing_target"] { input.action.target.value_masked == "" }
violations["missing_target"] { not input.action.target.value_masked }
violations["autopilot_disabled"] { input.evidence.autopilot_enabled != true }
violations["layer2_ineligible"] { input.evidence.layer2_eligible != true }
violations["outside_execution_window"] { input.evidence.execution_window_ok != true }
violations["stale_evidence"] { input.evidence.data_fresh != true }
violations["invalid_risk_score"] { not is_number(input.evidence.risk_score) }
violations["risk_below_floor"] { is_number(input.evidence.risk_score); input.evidence.risk_score < config.min_risk_score }
violations["protected_target"] { protected_target }
violations["private_or_loopback_ip"] {
    input.action.type == "block_ip"
    cidr := config.protected_ip_ranges[_]
    net.cidr_contains(cidr, input.action.target.value_masked)
}
violations["target_denied"] { input.guardrails.denied_targets[_] == input.action.target.value_masked }
violations["rate_limit_exceeded"] { input.guardrails.action_rate_count >= config.max_actions_per_window }
violations["duration_exceeded"] { is_number(input.action.duration_seconds); input.action.duration_seconds > config.max_duration_seconds }
violations["duplicate_action"] {
    prior := input.guardrails.prior_actions[_]
    prior.idempotency_key == input.request.idempotency_key
    prior.status == "completed"
}

violations["critical_ip_blocked"] {
    input.action.type == "block_ip"
    is_critical_ip(input.action.target.value_masked)
}

is_critical_ip(ip) {
    critical_ips := ["10.0.0.1", "10.0.0.2", "192.168.1.1", "192.168.1.254"]
    critical_ips[_] == ip
}

violations["low_risk_auto_containment"] {
    is_number(input.evidence.risk_score)
    input.evidence.risk_score < 5.0
}

supported_action {
    config.allowed_action_types[_] == input.action.type
}

trusted_caller {
    config.caller_ids[_] == input.execution.service_claims.subject
}

protected_target {
    config.protected_targets[_] == input.action.target.value_masked
}

protected_target {
    input.guardrails.protected_assets[_] == input.action.target.value_masked
}

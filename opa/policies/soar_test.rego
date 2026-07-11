package aegis.autopilot

base_input := {
    "request": {"action_id":"act-1", "incident_id":"inc-1", "tenant_id":"bank", "idempotency_key":"idem-1"},
    "execution": {"mode":"autopilot", "orchestrator_id":"layer2_orchestrator_soar", "policy_revision":"aegis-autopilot-v1", "service_claims":{"subject":"soar-action-worker"}},
    "action": {"type":"block_ip", "target":{"value_masked":"198.51.100.7"}, "duration_seconds":60},
    "evidence": {"autopilot_enabled":true, "layer2_eligible":true, "execution_window_ok":true, "data_fresh":true, "risk_score":9.0},
    "guardrails": {"protected_assets":[], "denied_targets":[], "action_rate_count":0, "prior_actions":[]},
}

test_valid_action_allowed { allow with input as base_input }
test_low_risk_denied { not allow with input as object.union(base_input, {"evidence": object.union(base_input.evidence, {"risk_score": 4.0})}) }
test_protected_target_denied { not allow with input as object.union(base_input, {"action": object.union(base_input.action, {"target":{"value_masked":"10.0.0.1"}})}) }
test_private_ip_denied { not allow with input as object.union(base_input, {"action": object.union(base_input.action, {"target":{"value_masked":"10.25.1.9"}})}) }
test_unknown_action_denied { not allow with input as object.union(base_input, {"action": object.union(base_input.action, {"type":"format_datacenter"})}) }
test_disabled_autopilot_denied { not allow with input as object.union(base_input, {"evidence": object.union(base_input.evidence, {"autopilot_enabled":false})}) }
test_revision_mismatch_denied { not allow with input as object.union(base_input, {"execution": object.union(base_input.execution, {"policy_revision":"old"})}) }
test_missing_facts_denied { not allow with input as {} }

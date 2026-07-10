# L2 Orchestrator Offline Playbook - Banking SOC

Source files used as authority:
- `mitre_attack_full.json`
- `mitre_attack_full.md`

This playbook is designed for an L2 SOC orchestrator that has no internet access. The orchestrator must use verified evidence, the offline MITRE ATT&CK KB, this playbook, and reasoning over attacker progression to decide what to contain, what to hunt, what to queue for approval, and what to monitor next.

## 1. Operating Contract

1. Treat Layer 1 mappings as hypotheses until verified against raw evidence.
2. Use only facts that are present in the alert, raw logs, local telemetry, or the offline MITRE KB.
3. Never invent users, hosts, IP addresses, event IDs, transaction IDs, or tool results.
4. Parent/subtechnique matching is mandatory. If `T1003.001` is verified, route it as both `T1003.001` and parent `T1003`. If only parent `T1003` is verified, keep all child-specific actions conditional until child evidence is known.
5. Technique routing and tactic routing are separate. A technique may be useful in a playbook even when its official tactic is different, but the rationale must say why the behavior fits that playbook.
6. If no technique matches but behavior is abnormal, route to `PB-ANOMALY`; absence of known MITRE mapping is not absence of attack.
7. Execute environment-changing low/medium impact actions marked `AUTO` only when every `automation_control.auto_containment_gates` field is true. Queue all high impact, critical impact, service-disruptive, customer notification, regulator notification, SWIFT, HSM, Core Banking, and DR actions for approval.
8. Preserve evidence before disruptive containment when feasible.
9. Every action must be recorded with `priority`, `timestamp`, `target`, `approval_mode`, `status`, and `playbook_source`.
10. Use the predictive flow after every confirmed or partially confirmed alert: current technique -> MITRE `prediction_chains` -> same CAPEC/CWE family -> next kill-chain phase -> banking blast radius.

## 2. Normalization For Playbook Matching

The orchestrator should construct this internal matching object before route selection:

```json
{
  "verified_techniques": ["T1003.001"],
  "expanded_techniques": ["T1003.001", "T1003"],
  "verified_tactics": ["TA0006"],
  "domains": ["enterprise", "cloud", "mobile", "ics"],
  "banking_flags": {
    "swift_or_payment_involved": false,
    "core_banking_involved": false,
    "customer_data_involved": false,
    "atm_or_hsm_involved": false,
    "privileged_identity_involved": false,
    "backup_or_recovery_involved": false,
    "security_control_involved": false,
    "fraud_control_involved": false
  },
  "entities": {},
  "evidence": {},
  "verification_state": "confirmed|not_confirmed|contradicted|insufficient|not_required|sources_unavailable|query_timeout|stale_context|not_found",
  "verification_source_statuses": ["matched|not_found|source_unavailable|query_timeout|stale|error"],
  "verification_strength": "strong|supported|weak|none|contradicted"
}
```

Matching order:

1. Expand every verified subtechnique to its parent using the offline KB.
2. Match high priority banking playbooks first.
3. Match exact technique and parent technique triggers.
4. Match tactic fallback when no specific playbook trigger exists.
5. Apply banking sensitivity override.
6. Add `PB-ANOMALY` if the behavior is abnormal but no known technique is verified.
7. Activate multiple playbooks when the evidence supports multiple attacker objectives.

## 3. Response Modes And Approval

| Mode | Use When | Default Action Bias |
|------|----------|---------------------|
| `MONITOR` | Recon, resource development, weak evidence, blocked attack | Increase logging, add watchlists, create hunts |
| `CONTAIN` | Initial access, execution, persistence, confirmed compromise with limited blast radius | Stop active execution, isolate user workstation if allowed, preserve evidence |
| `CONTAIN_AND_HUNT` | Privilege escalation, stealth, credential access, discovery, lateral movement, collection, C2 | Contain confirmed nodes, hunt laterally, revoke confirmed compromised credentials |
| `CRISIS` | Impact, exfiltration, financial theft, destructive activity, confirmed customer data exposure, critical banking system risk | Evidence preservation, business escalation, queue critical controls, execute safe auto-controls |

Approval rules:

| Action Class | Approval Mode |
|--------------|---------------|
| Add IOC/watchlist, raise monitoring, create temporary detection/hunt | `AUTO` |
| Block known malicious IP/domain with supported or strong Layer 2 verification and narrow scope | `AUTO` |
| WAF virtual patch scoped to exploit pattern | `AUTO` |
| Reset one confirmed compromised password | `AUTO` |
| Disable one confirmed compromised account | `AUTO` |
| Kill verified malicious process | `AUTO` |
| Isolate user workstation with active compromise | `AUTO` |
| Isolate server or shared service | `APPROVAL_REQUIRED` |
| Freeze payments, disconnect SWIFT, isolate Core Banking, HSM, ATM switch, or VLAN | `MANUAL_ONLY` |
| Notify regulator, SWIFT, card network, customer, law enforcement | `MANUAL_ONLY` |
| Activate DR or mass password reset | `MANUAL_ONLY` |

Risk score action gate:

| Final Risk Score | Required Handling |
|------------------|-------------------|
| `0.0-5.0` | Monitor, preserve, hunt, or request more evidence according to verification state. Do not auto-contain only because Layer 1 alerted. |
| `>5.0` | Execute all available non-disruptive SOC actions: preserve logs/evidence, raise monitoring, add scoped watchlists or temporary detections, create hunt tasks, open/update SOC ticket, and notify SOC. |
| `>5.0` **AND** all `automation_control.auto_containment_gates` fields are true | Execute eligible containment: scoped IP block, WAF virtual patch, force logout, host quarantine, limited network control, or access revocation. |
| Any score with manual-only target or high business-impact action | Queue for approval or manual escalation. Never automatically isolate SWIFT, Core Banking, HSM, ATM switch, critical VLAN, DR, broad services, external notifications, destructive cleanup, or data deletion. |

Populate `automation_control.auto_containment_gates` with these boolean fields and their source conditions:

| Gate Field | Required Source Condition |
|------------|---------------------------|
| `threat_confirmed` | `verified_case.threat_confirmed=true` |
| `l2_verification_performed` | `l2_independent_verification.performed=true` |
| `verification_confirmed` | `l2_independent_verification.verification_state="confirmed"` |
| `verification_supported_or_strong` | `l2_independent_verification.verification_strength` is `supported` or `strong` |
| `risk_above_floor` | `scoring.final_risk_score_0_10 > 5.0` |
| `opa_allow` | `policy_guardrails.opa_result="allow"` |
| `soc_autopilot_on` | `automation_control.soc_autopilot_enabled=true` |
| `execution_window_open` | current time is inside the configured execution window, default `08:00-20:00 Asia/Ho_Chi_Minh` |
| `action_scoped_timebound_reversible` | selected action is low/medium impact, scoped, time-bound, reversible, and not manual-only |
| `rollback_available` | rollback support exists for the selected action |
| `dangerous_now_behavior` | confirmed behavior is active compromise, exfiltration, fraud/payment manipulation, malware/ransomware, privileged misuse, security-control disablement, destructive behavior, or critical banking path abuse |
| `verified_target_entity` | the action targets only the verified entity, not a broad service or business process |

Verification cap handling: `sources_unavailable`, `query_timeout`, `stale_context`, `not_found`, `insufficient`, `not_confirmed`, and `not_required` cap final risk at `5.5`; `contradicted` caps final risk at `2.0`. Only `confirmed` with `supported` or `strong` verification can exceed `5.5`.

Layer 1 vote count, worker count, or worker confidence must not be used as an action gate. A single Layer 1 positive finding can lead to action when Layer 2 independently verifies the case and the gate above passes.

## 4. Banking Sensitivity Override

| Banking Condition | Minimum Mode | Required Handling |
|-------------------|--------------|-------------------|
| Confirmed SWIFT/payment manipulation or financial theft | `CRISIS` | Queue transaction freeze and SWIFT/payment operations approval path |
| SWIFT/payment system touched but fraud not confirmed | `CONTAIN_AND_HUNT` | Preserve transaction evidence and monitor payment queues |
| Core Banking touched | `CONTAIN_AND_HUNT` | Queue service-impacting actions; no automatic segment isolation |
| Customer data confirmed exposed or staged | `CRISIS` | Legal/compliance assessment required |
| Customer data at risk but not confirmed exposed | `CONTAIN_AND_HUNT` | DLP/hunt and data access audit |
| ATM/HSM/payment hardware touched | `CONTAIN`; `CRISIS` for impact, inhibit response, impair process, destructive behavior, cash integrity, or key integrity risk | Escalate to operations and physical security; HSM isolation is manual only |
| Privileged identity involved | `CONTAIN` | Confirm compromise before disable/reset; expand hunt to admin sessions |
| Backup/recovery touched | `CONTAIN_AND_HUNT` | Verify immutable backups and queue DR readiness review |
| Security control impaired | `CONTAIN_AND_HUNT` | Restore control, preserve tamper evidence, hunt for impact prep |

## 5. Kill Chain Fallback Routing

Use this table when a verified technique has no specific playbook trigger. This table covers the enterprise, cloud, mobile, and ICS tactic IDs present in the offline KB.

| Tactic ID | KB Tactic Name | Fallback Playbook | Default Mode |
|-----------|----------------|-------------------|--------------|
| `TA0043` | Reconnaissance | `PB-RECON` | `MONITOR` |
| `TA0042` | Resource Development | `PB-RESOURCE` | `MONITOR` |
| `TA0001` | Initial Access | `PB-INITIAL-ACCESS` | `CONTAIN` |
| `TA0002` | Execution | `PB-EXECUTION` | `CONTAIN` |
| `TA0003` | Persistence | `PB-PERSIST` | `CONTAIN` |
| `TA0004` | Privilege Escalation | `PB-PRIVESC` | `CONTAIN_AND_HUNT` |
| `TA0005` | Defense Evasion | `PB-STEALTH` | `CONTAIN_AND_HUNT` |
| `TA0112` | Defense Impairment | `PB-DEFENSE-IMPAIR` | `CONTAIN_AND_HUNT` |
| `TA0006` | Credential Access | `PB-CRED` | `CONTAIN_AND_HUNT` |
| `TA0007` | Discovery | `PB-DISCOVERY` | `CONTAIN_AND_HUNT` |
| `TA0008` | Lateral Movement | `PB-LATERAL` | `CONTAIN_AND_HUNT` |
| `TA0009` | Collection | `PB-COLLECTION` | `CONTAIN_AND_HUNT` |
| `TA0010` | Exfiltration | `PB-EXFIL` | `CRISIS` |
| `TA0011` | Command and Control | `PB-C2` | `CONTAIN_AND_HUNT` |
| `TA0040` | Impact | `PB-IMPACT` | `CRISIS` |
| `TA0027` | Initial Access | `PB-MOBILE` | `CONTAIN` |
| `TA0028` | Persistence | `PB-MOBILE` | `CONTAIN` |
| `TA0029` | Privilege Escalation | `PB-MOBILE` | `CONTAIN_AND_HUNT` |
| `TA0030` | Defense Evasion | `PB-MOBILE` | `CONTAIN_AND_HUNT` |
| `TA0031` | Credential Access | `PB-MOBILE` | `CONTAIN_AND_HUNT` |
| `TA0032` | Discovery | `PB-MOBILE` | `CONTAIN_AND_HUNT` |
| `TA0033` | Lateral Movement | `PB-MOBILE` | `CONTAIN_AND_HUNT` |
| `TA0034` | Impact | `PB-MOBILE` | `CRISIS` |
| `TA0035` | Collection | `PB-MOBILE` | `CONTAIN_AND_HUNT` |
| `TA0041` | Execution | `PB-EXECUTION` | `CONTAIN` |
| `TA0037` | Command and Control | `PB-MOBILE` | `CONTAIN_AND_HUNT` |
| `TA0108` | Initial Access | `PB-ICS-ATM-HSM` | `CONTAIN` |
| `TA0104` | Execution | `PB-ICS-ATM-HSM` | `CONTAIN` |
| `TA0110` | Persistence | `PB-ICS-ATM-HSM` | `CONTAIN` |
| `TA0111` | Privilege Escalation | `PB-ICS-ATM-HSM` | `CONTAIN_AND_HUNT` |
| `TA0103` | Evasion | `PB-ICS-ATM-HSM` | `CONTAIN_AND_HUNT` |
| `TA0102` | Discovery | `PB-ICS-ATM-HSM` | `CONTAIN_AND_HUNT` |
| `TA0109` | Lateral Movement | `PB-ICS-ATM-HSM` | `CONTAIN_AND_HUNT` |
| `TA0100` | Collection | `PB-ICS-ATM-HSM` | `CONTAIN_AND_HUNT` |
| `TA0036` | Exfiltration | `PB-MOBILE` | `CRISIS` |
| `TA0101` | Command and Control | `PB-ICS-ATM-HSM` | `CONTAIN_AND_HUNT` |
| `TA0105` | Impact | `PB-ICS-ATM-HSM` | `CRISIS` |
| `TA0106` | Impair Process Control | `PB-ICS-ATM-HSM` | `CRISIS` |
| `TA0107` | Inhibit Response Function | `PB-ICS-ATM-HSM` | `CRISIS` |

## 6. Specific Playbook Routing Table

| Priority | Playbook | Technique Triggers | Context Triggers | Mode |
|----------|----------|--------------------|------------------|------|
| 1 | `PB-FINANCIAL-FRAUD` | `T1657`, `T1565` | SWIFT/payment manipulation, abnormal beneficiary, transaction integrity issue | `CRISIS` |
| 2 | `PB-RANSOM-IMPACT` | `T1486`, `T1490`, `T1489`, `T1485`, `T1529`, `T1491` | Backup/recovery touched, mass encryption, destructive change | `CRISIS` |
| 3 | `PB-DOS` | `T1498`, `T1499` | Banking availability degradation, ATM/API/service saturation | `CRISIS` |
| 4 | `PB-EXFIL` | `T1041`, `T1048`, `T1020`, `T1567`, `T1029`, `T1030`, `T1052`, `T1011` | Customer data involved, DLP alert, unusual outbound transfer | `CRISIS` |
| 5 | `PB-CRED` | `T1003`, `T1110`, `T1558`, `T1552`, `T1556`, `T1539`, `T1528`, `T1649`, `T1555` | Privileged identity, token/session/cookie/key theft | `CONTAIN_AND_HUNT` |
| 6 | `PB-VALID-ACCOUNT-MISUSE` | `T1078`, `T1550`, `T1133`, `T1098` | Valid login from abnormal source, impossible travel, stale external access | `CONTAIN_AND_HUNT` |
| 7 | `PB-WEB-EDGE` | `T1190`, `T1189`, `T1505`, `T1505.003`, `T1059.007` | Public app, API gateway, WAF, DMZ host | `CONTAIN` |
| 8 | `PB-SUPPLY` | `T1195`, `T1199` | Vendor account, third-party remote access, software update trust path | `CONTAIN_AND_HUNT` |
| 9 | `PB-EXECUTION` | `T1059`, `T1203`, `T1204`, `T1047`, `T1218`, `T1105` | Malicious code execution or tool transfer | `CONTAIN` |
| 10 | `PB-PERSIST` | `T1547`, `T1053`, `T1543`, `T1546`, `T1133`, `T1136`, `T1098`, `T1505`, `T1556` | Repeated access, new account, service, scheduled task, web shell | `CONTAIN` |
| 11 | `PB-PRIVESC` | `T1548`, `T1134`, `T1068`, `T1055` | Admin token abuse, local exploit, privileged process injection | `CONTAIN_AND_HUNT` |
| 12 | `PB-STEALTH` | `T1070`, `T1036`, `T1218`, `T1574`, `T1553`, `T1222` | Log deletion, masquerading, proxy execution, trust subversion | `CONTAIN_AND_HUNT` |
| 13 | `PB-DEFENSE-IMPAIR` | `T1685`, `T1685.005`, `T1686`, `T1112`, `T1553`, `T1222` | Security control disabled, firewall tampered, audit weakened | `CONTAIN_AND_HUNT` |
| 14 | `PB-DISCOVERY` | `T1082`, `T1016`, `T1046`, `T1087`, `T1069`, `T1482`, `T1018`, `T1083`, `T1012`, `T1057` | Internal mapping after foothold | `CONTAIN_AND_HUNT` |
| 15 | `PB-LATERAL` | `T1021`, `T1570`, `T1563`, `T1534`, `T1210`, `T1550` | East-west movement, admin share, RDP/SMB/WinRM, remote exploit | `CONTAIN_AND_HUNT` |
| 16 | `PB-COLLECTION` | `T1005`, `T1039`, `T1025`, `T1074`, `T1114`, `T1119`, `T1185`, `T1557`, `T1113`, `T1056`, `T1213`, `T1530`, `T1602` | Staging, mailbox access, screenshots, keylogging, repository/cloud data | `CONTAIN_AND_HUNT` |
| 17 | `PB-C2` | `T1071`, `T1573`, `T1095`, `T1105`, `T1132`, `T1090`, `T1001`, `T1568`, `T1572`, `T1102` | Beaconing, encrypted tunnel, web service C2, proxy chain | `CONTAIN_AND_HUNT` |
| 18 | `PB-RECON` | `T1595`, `T1592`, `T1589`, `T1590`, `T1591`, `T1593`, `T1594`, `T1598` | External recon, phishing for information | `MONITOR` |
| 19 | `PB-RESOURCE` | `T1583`, `T1584`, `T1585`, `T1586`, `T1587`, `T1588` | Staged attacker infrastructure or capabilities | `MONITOR` |
| 20 | `PB-CLOUD-SAAS` | `T1528`, `T1530`, `T1567`, `T1098`, `T1078` | Cloud control plane, SaaS, OAuth, storage, IAM app consent | `CONTAIN_AND_HUNT` |
| 21 | `PB-MOBILE` | Any mobile-domain technique | Mobile app, mobile banking, mobile device, MDM, customer mobile session | `CONTAIN_AND_HUNT` |
| 22 | `PB-ICS-ATM-HSM` | Any ICS-domain technique | ATM, HSM, POS, payment switch, physical terminal, OT-like banking device; use `CRISIS` for `TA0105`, `TA0106`, or `TA0107` | `CONTAIN_AND_HUNT` |
| 23 | `PB-INSIDER` | `T1078` + `T1098` + data access technique | Internal source, slow velocity, policy deviation, privileged misuse | `CONTAIN_AND_HUNT` |
| 24 | `PB-ANOMALY` | No MITRE match required | Unknown anomaly, zero-day-like behavior, telemetry gap | `CONTAIN_AND_HUNT` |
| 25 | `PB-INITIAL-ACCESS` | `TA0001` tactic fallback (no specific technique trigger) | Generic initial access not covered by PB-WEB-EDGE, PB-VALID-ACCOUNT-MISUSE, or PB-SUPPLY | `CONTAIN` |
| 26 | `PB-IMPACT` | `T1531`, `T1561`, `T1499.004`, `T1657` (non-financial), any `TA0040` technique | Business disruption, availability impact, data destruction not matching PB-RANSOM-IMPACT, PB-DOS, or PB-FINANCIAL-FRAUD | `CRISIS` |

## 7. Playbook Library

Each playbook follows this action sequence: verify, preserve, contain, hunt, recover, predict.

### PB-INITIAL-ACCESS

Trigger: verified `TA0001` or `TA0027` initial access behavior that does not fit a more specific playbook.

Attacker objective: gain the first foothold through exposed service, phishing, valid account, drive-by, removable media, trusted relationship, or external remote service.

Immediate actions:
1. AUTO: preserve entry-vector evidence: email, WAF, VPN, SSO, endpoint, browser, API gateway, and network logs.
2. AUTO: add source IP/domain/account/device/user agent to watchlists.
3. AUTO: block Layer 2-verified malicious source or URL when scoped.
4. AUTO: create temporary hunts for execution, persistence, credential access, and C2 from the same entity.
5. APPROVAL_REQUIRED: queue server isolation or account restriction if the entry point is shared or business-critical.

Hunt and scope:
1. Identify entry vector and first successful execution or session.
2. Determine whether the attacker has code execution, valid credentials, SaaS session, or only attempted access.
3. Search for `T1059`, `T1105`, `T1547`, `T1505.003`, `T1003`, and `T1071`.

Predict and mitigate:
1. Predict execution, persistence, credential access, C2, and lateral movement.
2. Apply or stage `M1037`, `M1035`, `M1032`, `M1050`, `M1051`, `M1047`, and `M1017`.

### PB-IMPACT

Trigger: verified `TA0040`, `TA0034`, or `TA0105` impact behavior that does not fit fraud, ransomware, DoS, or ATM/HSM-specific playbooks.

Attacker objective: disrupt, destroy, manipulate, degrade, or otherwise cause operational, financial, or customer harm.

Immediate actions:
1. AUTO: preserve impacted system logs, command history, process/file metadata, application state, transaction state, and control-plane audit records.
2. AUTO: stop a verified malicious process if active harm is ongoing and evidence is captured.
3. AUTO: add destructive indicators to watchlists and increase monitoring on peer systems.
4. APPROVAL_REQUIRED: queue isolation, rollback, service failover, or emergency change for shared systems.
5. MANUAL_ONLY: queue customer, regulator, law enforcement, and public communication through Legal/Compliance.

Hunt and scope:
1. Identify impact type: data destruction, data manipulation, account/resource abuse, defacement, shutdown, service stop, or operational disruption.
2. Search backward for initial access, credential access, lateral movement, collection, exfiltration, and defense impairment.
3. Verify backup integrity, transaction integrity, and customer/service impact.

Predict and mitigate:
1. Predict repeated impact, recovery inhibition, indicator removal, and fraud/exfiltration cover-up.
2. Apply or stage `M1053`, `M1040`, `M1030`, `M1031`, `M1047`, `M1057`, and `M1041`.

### PB-FINANCIAL-FRAUD

Trigger: `T1657`, `T1565`, confirmed or suspected SWIFT/payment/core transaction manipulation.

Attacker objective: move money, alter transaction state, hide unauthorized transfer, or corrupt balances.

Immediate actions:
1. AUTO: lock relevant audit logs to immutable storage and add all involved entities to SIEM watchlists.
2. AUTO: increase monitoring on payment queues, maker-checker events, beneficiary changes, transaction approval workflow, and privileged sessions.
3. AUTO: preserve application logs, database audit, API gateway logs, IAM logs, SWIFT/payment gateway logs, and workstation telemetry.
4. MANUAL_ONLY: queue transaction freeze, payment rail isolation, SWIFT workstation isolation, or reversal workflow through CISO, business owner, and Legal/Compliance.
5. MANUAL_ONLY: queue external notification to regulator, SWIFT, card network, correspondent bank, or customer.

Hunt and scope:
1. Compare beneficiary, amount, account, approval chain, source IP, device, session, and timestamp against baseline and approved workflow.
2. Search for preceding valid-account misuse, credential access, web exploit, C2, or defense impairment.
3. Verify transaction database integrity with before/after snapshots and reconciliation logs.
4. Identify whether fraud is single transaction, batch, recurring scheduled transfer, or systemic logic tampering.

Predict and mitigate:
1. Predict `T1070`, `T1485`, `T1003`, `T1021`, and `T1041`.
2. Apply or stage `M1018`, `M1032`, `M1030`, `M1047`, and `M1057`.
3. If Core Banking or SWIFT is involved, escalate immediately even if direct financial loss is not confirmed.

### PB-RANSOM-IMPACT

Trigger: `T1486`, `T1490`, `T1489`, `T1485`, `T1529`, `T1491`, destructive file changes, backup deletion, or service stop patterns.

Attacker objective: deny service, encrypt or destroy data, inhibit recovery, extort the bank.

Immediate actions:
1. AUTO: isolate confirmed compromised user workstations if active encryption or destructive process is observed.
2. AUTO: kill verified malicious encryption or destructive process only after preserving process metadata and command line.
3. AUTO: add hashes, filenames, mutexes, ransom-note names, and C2 indicators to watchlists.
4. AUTO: verify backup telemetry, snapshot immutability, backup admin logins, and recent deletion attempts.
5. APPROVAL_REQUIRED: queue server isolation, network segment isolation, backup network isolation, and DR activation.
6. MANUAL_ONLY: never pay ransom; external communication requires Legal/Compliance.

Hunt and scope:
1. Search for preceding `T1685`, `T1686`, `T1003`, `T1021`, `T1078`, `T1489`, and `T1490`.
2. Identify encryption start time, patient zero, propagation method, affected shares, and privileged accounts used.
3. Check ESXi, storage, backup, domain controllers, file servers, and Core Banking dependencies.
4. Preserve ransom notes, malware samples, memory, EDR timelines, and event logs.

Predict and mitigate:
1. Predict additional `T1490`, `T1489`, `T1485`, `T1070`, and `T1041`.
2. Apply or stage `M1053`, `M1040`, `M1030`, `M1031`, `M1026`, and `M1047`.

### PB-DOS

Trigger: `T1498`, `T1499`, service saturation, API flood, ATM switch availability issue, or endpoint service crash wave.

Attacker objective: disrupt banking availability, distract SOC, or degrade fraud controls.

Immediate actions:
1. AUTO: enable rate limiting and block confirmed hostile sources at WAF, DNS, proxy, CDN, or perimeter where scoped.
2. AUTO: increase monitoring on API gateway, load balancer, DNS, firewall, NDR, ATM switch, and service health metrics.
3. AUTO: preserve NetFlow, packet samples, request samples, ASN/geo distribution, user agents, and bot signatures.
4. APPROVAL_REQUIRED: queue traffic scrubbing, service failover, or server isolation if customer service is impacted.

Hunt and scope:
1. Distinguish volumetric network DoS, application-layer DoS, endpoint DoS, and business-logic abuse.
2. Check whether DoS coincides with financial fraud, data exfiltration, or backup deletion.
3. Identify protected vs unprotected endpoints and critical customer journeys.

Predict and mitigate:
1. Predict parallel `T1657`, `T1041`, `T1070`, and `T1190` if DoS is distraction.
2. Apply or stage `M1037`, `M1030`, `M1031`, `M0811`, and `M0807`.

### PB-EXFIL

Trigger: `T1041`, `T1048`, `T1020`, `T1567`, `T1029`, `T1030`, `T1052`, `T1011`, confirmed staging followed by outbound transfer, or customer data egress.

Attacker objective: move customer, card, payment, credential, or operational data out of the bank.

Immediate actions:
1. AUTO: add destination IP/domain/account/object IDs to DLP, proxy, SIEM, and DNS watchlists.
2. AUTO: block Layer 2-verified malicious destination if scoped and not business-critical.
3. AUTO: increase DLP sensitivity for affected users, hosts, repositories, buckets, mailboxes, and data classes.
4. AUTO: preserve proxy, DNS, NetFlow, firewall, DLP, CASB, cloud storage, database audit, and endpoint file access logs.
5. APPROVAL_REQUIRED: queue broad egress block, SaaS tenant-level restriction, or server isolation.
6. MANUAL_ONLY: customer/regulatory notification requires Legal/Compliance.

Hunt and scope:
1. Identify data type, volume, time window, source repository, staging path, and destination.
2. Search for preceding collection `T1074`, cloud storage access `T1530`, mailbox access `T1114`, credential access `T1003`, and C2 `T1071`.
3. Determine whether data was viewed, staged, compressed, encrypted, or successfully transferred.
4. Map customer impact: none, potential, confirmed.

Predict and mitigate:
1. Predict `T1070`, `T1485`, `T1657`, and further `T1041` or `T1567`.
2. Apply or stage `M1057`, `M1041`, `M1030`, `M1031`, `M1037`, and `M0947`.

### PB-CRED

Trigger: `T1003`, `T1110`, `T1558`, `T1552`, `T1556`, `T1539`, `T1528`, `T1649`, `T1555`, or evidence of credential, token, cookie, certificate, or secret theft.

Attacker objective: obtain reusable authentication material for privilege escalation, lateral movement, persistence, cloud access, or payment fraud.

Immediate actions:
1. AUTO: preserve process tree, memory metadata, command lines, AD/IAM logs, Kerberos logs, SSO logs, MFA logs, PAM logs, and endpoint telemetry.
2. AUTO: reset one confirmed compromised password or revoke one confirmed compromised session/token.
3. AUTO: disable one confirmed compromised account when abuse is active and scoped.
4. AUTO: isolate workstation if active credential dumping is confirmed.
5. APPROVAL_REQUIRED: queue domain controller isolation, service account rotation, broad privileged credential rotation, or mass reset.

Hunt and scope:
1. If `T1003.001` is present, preserve LSASS evidence and verify Credential Guard/ASR status.
2. If `T1003.006` is present, review replication rights and isolate the source from domain controllers after evidence capture.
3. If `T1558.001` or `T1558.002` is suspected, plan krbtgt or service account rotation through AD change control.
4. If `T1528` is present, revoke OAuth/application tokens and review app consent.
5. Search for next-step `T1078`, `T1550`, `T1021`, `T1098`, and `T1657`.

Predict and mitigate:
1. Predict `T1078`, `T1550`, `T1021`, `T1098`, `T1136`, and `T1041`.
2. Apply or stage `M1043`, `M1027`, `M1026`, `M1015`, `M1032`, and `M1047`.

### PB-VALID-ACCOUNT-MISUSE

Trigger: `T1078`, `T1550`, `T1133`, `T1098`, valid login from abnormal source, impossible travel, new device, unusual privilege, or session hijack.

Attacker objective: blend in using legitimate access and avoid malware indicators.

Immediate actions:
1. AUTO: force re-authentication or revoke active sessions for confirmed compromised account.
2. AUTO: reset one user password or disable one account when compromise is confirmed.
3. AUTO: add source IP, device, session, user agent, and account to watchlists.
4. AUTO: preserve IAM, VPN, SSO, MFA, PAM, AD, SaaS, cloud audit, and endpoint logs.
5. APPROVAL_REQUIRED: queue privileged role removal, service account key rotation, or broad conditional access change.

Hunt and scope:
1. Review account changes, group membership, MFA changes, recovery email/phone changes, OAuth consent, API keys, SSH keys, and cloud access keys.
2. Search all systems accessed by the account before and after first abnormal event.
3. Determine whether access is external attacker, insider misuse, vendor misuse, or false positive.

Predict and mitigate:
1. Predict `T1021`, `T1098`, `T1136`, `T1003`, `T1530`, and `T1657`.
2. Apply or stage `M1032`, `M1036`, `M1026`, `M1018`, `M1047`, and `M1035`.

### PB-WEB-EDGE

Trigger: `T1190`, `T1189`, `T1505`, `T1505.003`, `T1059.007`, exploit traffic on public app, API, WAF, DMZ, or web shell evidence.

Attacker objective: gain initial foothold, execute code, persist through web shell, pivot inward, or access customer data.

Immediate actions:
1. AUTO: deploy scoped WAF virtual patch for confirmed exploit pattern.
2. AUTO: block Layer 2-verified hostile source IP/domain if scoped.
3. AUTO: preserve WAF, web server, API gateway, application, container, file integrity, EDR, and database audit logs.
4. AUTO: snapshot suspected web shell path, hash, owner, timestamps, and process connections; do not delete before preservation.
5. APPROVAL_REQUIRED: queue web server isolation or pool removal if service impact is material.

Hunt and scope:
1. Identify exploit path, request payload, exploited component, writeable directory, child processes, outbound connections, and credentials exposed to the app.
2. Search sibling web servers, containers, CI/CD artifacts, secrets, and database access.
3. Check for `T1059`, `T1105`, `T1505.003`, `T1003`, `T1021`, and `T1041` after exploit.

Predict and mitigate:
1. Predict `T1059`, `T1505.003`, `T1105`, `T1003`, and `T1021`.
2. Apply or stage `M1048`, `M1050`, `M1051`, `M1037`, `M1030`, and `M1026`.

### PB-SUPPLY

Trigger: `T1195`, `T1199`, vendor remote access, trusted relationship abuse, signed update anomaly, CI/CD compromise, or third-party system pivot.

Attacker objective: enter through trusted supplier, managed service, software update, or business partner.

Immediate actions:
1. AUTO: preserve vendor session logs, VPN/ZTNA logs, IAM logs, EDR telemetry, update metadata, package hashes, and CI/CD logs.
2. AUTO: restrict affected vendor account/session if compromise is confirmed and scoped.
3. AUTO: add suspicious package hashes, domains, certificates, and vendor IPs to watchlists.
4. APPROVAL_REQUIRED: queue vendor access suspension, software rollback, update channel block, or production deployment halt.

Hunt and scope:
1. Enumerate systems reachable by vendor trust path.
2. Verify code signing chain, build artifacts, deployment timestamps, and package integrity.
3. Search for post-access execution, persistence, credential access, C2, and lateral movement.

Predict and mitigate:
1. Predict `T1059`, `T1547`, `T1105`, `T1003`, and `T1021`.
2. Apply or stage `M1016`, `M1051`, `M1018`, `M1032`, `M1030`, and `M1047`.

### PB-EXECUTION

Trigger: `T1059`, `T1203`, `T1204`, `T1047`, `T1218`, `T1105`, or verified malicious execution/tool transfer.

Attacker objective: run code, fetch tools, execute script, abuse system binaries, or exploit client-side execution.

Immediate actions:
1. AUTO: preserve process tree, command line, parent process, script content hash, network connections, loaded modules, and file writes.
2. AUTO: kill verified malicious process when active harm is confirmed.
3. AUTO: block known malicious hash or download URL if scoped.
4. APPROVAL_REQUIRED: queue host isolation if server or shared service is involved.

Hunt and scope:
1. Identify initial trigger: phishing, web exploit, valid account, drive-by, or tool download.
2. Search for persistence, credential access, C2, and lateral movement after execution.
3. Review script interpreters, WMI, PowerShell, shell, JavaScript, system binary proxy execution, and scheduled tasks.

Predict and mitigate:
1. Predict `T1547`, `T1053`, `T1105`, `T1003`, and `T1071`.
2. Apply or stage `M1038`, `M1040`, `M1049`, `M1050`, `M1021`, and `M1047`.

### PB-PERSIST

Trigger: `T1547`, `T1053`, `T1543`, `T1546`, `T1133`, `T1136`, `T1098`, `T1505`, `T1556`, or repeated unauthorized access mechanism.

Attacker objective: keep access after reboot, password change, session expiry, patching, or initial containment.

Immediate actions:
1. AUTO: preserve persistence artifact, owner, timestamp, command, binary/script hash, account, and related log entries.
2. AUTO: disable one unauthorized account or revoke one unauthorized token when confirmed.
3. AUTO: add artifact IOC to EDR/SIEM and sweep all endpoints.
4. APPROVAL_REQUIRED: queue removal from critical servers after forensic capture; queue rebuild if artifact integrity is uncertain.

Hunt and scope:
1. Search for multiple persistence mechanisms; assume more than one until disproven.
2. Check scheduled tasks, services, boot/logon entries, event triggers, external remote services, accounts, authentication process changes, and web shells.
3. Determine whether persistence was installed before or after credential theft.

Predict and mitigate:
1. Predict `T1548`, `T1055`, `T1003`, `T1021`, and `T1071`.
2. Apply or stage `M1038`, `M1024`, `M1047`, `M1026`, `M1032`, and `M1030`.

### PB-PRIVESC

Trigger: `T1548`, `T1134`, `T1068`, `T1055`, token manipulation, local exploit, UAC bypass, or privileged process abuse.

Attacker objective: gain higher privileges to dump credentials, move laterally, disable controls, or reach critical banking systems.

Immediate actions:
1. AUTO: preserve exploit artifact, process injection evidence, token use, parent-child process tree, kernel/security logs, and EDR telemetry.
2. AUTO: kill verified malicious process if active and evidence is captured.
3. AUTO: remove single confirmed malicious local admin membership if scoped.
4. APPROVAL_REQUIRED: queue patch, reboot, server isolation, or privileged role cleanup for critical assets.

Hunt and scope:
1. Identify privilege boundary crossed: local admin, domain admin, cloud admin, database admin, application admin, HSM/SWIFT operator.
2. Search for immediate follow-on credential dumping and lateral movement.
3. Review vulnerable software inventory and patch state.

Predict and mitigate:
1. Predict `T1003`, `T1021`, `T1685`, `T1070`, and `T1041`.
2. Apply or stage `M1051`, `M1038`, `M1026`, `M1052`, `M1040`, and `M1047`.

### PB-STEALTH

Trigger: `T1070`, `T1036`, `T1218`, `T1574`, `T1553`, `T1222`, log deletion, masquerading, trust subversion, proxy execution, or permission tampering.

Attacker objective: avoid detection, bypass controls, hide artifacts, and prepare for credential theft or impact.

Immediate actions:
1. AUTO: preserve central logs, endpoint logs, EDR timeline, file metadata, certificate/signature evidence, and registry/file permission state.
2. AUTO: create temporary high-sensitivity detections for suspicious system binary use, renamed binaries, and unusual parent-child process chains.
3. AUTO: add known masqueraded names, hashes, and paths to SIEM/EDR watchlists.
4. APPROVAL_REQUIRED: queue host isolation or trust-store rollback on critical servers.

Hunt and scope:
1. Compare local logs with SIEM to detect log tampering.
2. Search for nearby credential access, defense impairment, C2, and impact preparation.
3. Identify whether stealth is opportunistic malware behavior or hands-on-keyboard activity.

Predict and mitigate:
1. Predict `T1003`, `T1021`, `T1486`, `T1041`, and `T1071`.
2. Apply or stage `M1047`, `M1022`, `M1024`, `M1045`, `M1038`, and `M1040`.

### PB-DEFENSE-IMPAIR

Trigger: `T1685`, `T1685.005`, `T1686`, `T1112`, `T1553`, `T1222`, disabled EDR/AV, firewall tampering, cleared logs, audit policy reduction, or security control outage.

Attacker objective: reduce bank visibility and increase success probability of credential theft, exfiltration, ransomware, or fraud.

Immediate actions:
1. AUTO: re-enable affected control from management plane if scoped and low risk.
2. AUTO: preserve control-plane audit logs, policy snapshots, local logs, registry/file permission state, and operator identity.
3. AUTO: create emergency detection for any host reporting disabled controls.
4. AUTO: verify central logging still receives events.
5. APPROVAL_REQUIRED: queue host isolation or policy rollback on servers and critical network/security devices.

Hunt and scope:
1. Identify all hosts where control status changed within the same time window.
2. Search for preceding valid account misuse or privilege escalation.
3. Search for immediate follow-on ransomware, credential access, exfiltration, or financial fraud.

Predict and mitigate:
1. Predict `T1486`, `T1490`, `T1003`, `T1041`, and `T1070`.
2. Apply or stage `M1047`, `M1022`, `M1024`, `M1031`, `M1037`, and `M1040`.

### PB-DISCOVERY

Trigger: `T1082`, `T1016`, `T1046`, `T1087`, `T1069`, `T1482`, `T1018`, `T1083`, `T1012`, `T1057`, or internal enumeration after initial access.

Attacker objective: map the environment to find credentials, high-value systems, reachable hosts, data stores, and banking targets.

Immediate actions:
1. AUTO: add source account/host to watchlists and increase monitoring on internal scans, LDAP queries, SMB/RDP attempts, and DNS lookups.
2. AUTO: preserve command lines, process tree, network flows, directory queries, and authentication events.
3. AUTO: block or throttle scan traffic only if active harm or sensitive network probing is confirmed.

Hunt and scope:
1. Identify discovery target class: hosts, network, domain, groups, processes, files, cloud inventory, data repositories, or banking applications.
2. Check if discovery follows phishing, web exploit, valid account misuse, or privilege escalation.
3. Search for follow-on lateral movement and collection.

Predict and mitigate:
1. Predict `T1021`, `T1570`, `T1005`, `T1074`, and `T1003`.
2. Apply or stage `M1030`, `M1035`, `M1047`, `M1018`, and `M1026`.

### PB-LATERAL

Trigger: `T1021`, `T1570`, `T1563`, `T1534`, `T1210`, `T1550`, east-west access, remote service abuse, admin share activity, RDP/SMB/WinRM/SSH pivot, or remote exploit.

Attacker objective: expand from foothold to high-value systems, domain controllers, Core Banking, SWIFT, databases, and backup systems.

Immediate actions:
1. AUTO: preserve authentication logs, remote service logs, process creation, network flows, file copy events, and tool artifacts.
2. AUTO: disable one confirmed compromised account or revoke one session if lateral movement is active.
3. AUTO: block confirmed malicious source-to-target remote connection if scoped.
4. AUTO: isolate user workstation if active compromise is confirmed.
5. APPROVAL_REQUIRED: queue server isolation, east-west ACL block, or critical segment containment.

Hunt and scope:
1. Build hop graph: source host, user, protocol, target, time, tool, credential used.
2. Search all targets touched by same account/source in the prior 72 hours.
3. Check for credential dumping on newly reached hosts.

Predict and mitigate:
1. Predict `T1003`, `T1486`, `T1041`, `T1098`, and `T1657`.
2. Apply or stage `M1030`, `M1032`, `M1035`, `M1026`, `M1018`, and `M1047`.

### PB-COLLECTION

Trigger: `T1005`, `T1039`, `T1025`, `T1074`, `T1114`, `T1119`, `T1185`, `T1557`, `T1113`, `T1056`, `T1213`, `T1530`, `T1602`, data staging, mailbox collection, keylogging, screenshots, repository access, or cloud storage access.

Attacker objective: gather data for exfiltration, fraud, extortion, credential theft, or intelligence.

Immediate actions:
1. AUTO: preserve file access, database audit, mailbox audit, cloud storage logs, endpoint telemetry, screenshots/keylogger artifacts, and staging directory metadata.
2. AUTO: increase DLP and repository monitoring on affected data class.
3. AUTO: add staging paths, object IDs, mailbox IDs, bucket names, and process hashes to watchlists.
4. APPROVAL_REQUIRED: queue access revocation or repository isolation for shared critical systems.

Hunt and scope:
1. Classify collected data: customer PII, card data, payment data, credentials, transaction records, source code, configuration, keys, operational runbooks.
2. Determine whether collection is local, network share, cloud, SaaS, email, browser, or screen/input capture.
3. Search for compression, encryption, staging, and outbound transfer after collection.

Predict and mitigate:
1. Predict `T1041`, `T1048`, `T1567`, `T1020`, and `T1070`.
2. Apply or stage `M1057`, `M1041`, `M1030`, `M1031`, `M1047`, and `M1026`.

### PB-C2

Trigger: `T1071`, `T1573`, `T1095`, `T1105`, `T1132`, `T1090`, `T1001`, `T1568`, `T1572`, `T1102`, beaconing, tunnel, proxy, newly registered domain, or web-service C2.

Attacker objective: maintain remote control, transfer tools, execute commands, and coordinate next stages.

Immediate actions:
1. AUTO: block Layer 2-verified malicious IP/domain when scoped.
2. AUTO: add destination, SNI, URI, JA3/JA4, user-agent, process, hash, and DNS indicators to watchlists.
3. AUTO: preserve DNS, proxy, firewall, NetFlow, EDR network, process, packet samples, and TLS metadata.
4. APPROVAL_REQUIRED: queue host/server isolation if active compromise is confirmed on critical systems.

Hunt and scope:
1. Identify beacon periodicity, protocol, encryption, parent process, and destination infrastructure.
2. Search for other hosts with same C2 pattern.
3. Check for tool transfer, credential access, collection, exfiltration, and lateral movement after C2 begins.

Predict and mitigate:
1. Predict `T1105`, `T1041`, `T1570`, `T1003`, and `T1021`.
2. Apply or stage `M1031`, `M1037`, `M1020`, `M1030`, and `M1040`.

### PB-RECON

Trigger: `T1595`, `T1592`, `T1589`, `T1590`, `T1591`, `T1593`, `T1594`, `T1598`, external scanning, information gathering, or phishing for information.

Attacker objective: learn exposed systems, employees, technologies, banking workflows, and trust paths before intrusion.

Immediate actions:
1. AUTO: add source IP/domain/email infrastructure to watchlists.
2. AUTO: increase monitoring on exposed services, email targets, VPN portals, internet-facing APIs, and employee enumeration signals.
3. AUTO: preserve WAF, firewall, DNS, email gateway, web server, and identity telemetry.
4. AUTO: create temporary detection for follow-on `T1566`, `T1190`, `T1133`, and `T1078`.

Hunt and scope:
1. Identify target assets and whether scanning is commodity, focused, or banking-specific.
2. Correlate recon with later login failures, exploit attempts, vendor access, or phishing.

Predict and mitigate:
1. Predict `T1566`, `T1190`, `T1133`, `T1078`, and `T1583`.
2. Apply or stage `M1056`, `M1019`, `M1037`, `M1035`, and `M1017`.

### PB-RESOURCE

Trigger: `T1583`, `T1584`, `T1585`, `T1586`, `T1587`, `T1588`, attacker infrastructure setup, registered domains, acquired certificates, staged payloads, or compromised infrastructure associated with the bank.

Attacker objective: prepare infrastructure, identities, capabilities, or access for later compromise.

Immediate actions:
1. AUTO: add domains, certificates, IPs, hosting ASNs, emails, and brand-abuse indicators to threat intel watchlists.
2. AUTO: monitor for inbound connections, phishing, and spoofed bank domains.
3. AUTO: preserve passive DNS, certificate transparency export if available locally, email gateway, DNS, and proxy telemetry.

Hunt and scope:
1. Determine if infrastructure imitates bank brand, supplier, VPN, SSO, or customer portal.
2. Correlate with recon and phishing attempts.

Predict and mitigate:
1. Predict `T1566`, `T1190`, `T1071`, and `T1105`.
2. Apply or stage `M1019`, `M1056`, `M1037`, and `M1031`.

### PB-CLOUD-SAAS

Trigger: `T1528`, `T1530`, `T1567`, `T1098`, `T1078`, cloud/SaaS login anomaly, OAuth token theft, app consent abuse, storage access, mailbox/repository access, or cloud control-plane manipulation.

Attacker objective: abuse cloud identity, application tokens, storage, SaaS data, and control-plane permissions.

Immediate actions:
1. AUTO: revoke one confirmed compromised OAuth token/session/API key.
2. AUTO: disable one confirmed malicious app consent or service principal if scoped.
3. AUTO: preserve cloud audit, SaaS audit, IAM, CASB, DLP, storage access, and API logs.
4. AUTO: add tenant IDs, app IDs, object IDs, IPs, user agents, and token IDs to watchlists.
5. APPROVAL_REQUIRED: queue tenant-wide conditional access change, broad key rotation, or storage lockdown.

Hunt and scope:
1. Review OAuth consent, delegated permissions, app-only permissions, role assignments, access keys, storage reads, mailbox rules, and external sharing links.
2. Search for data collection, exfiltration to web service, account manipulation, and persistence through app credentials.

Predict and mitigate:
1. Predict `T1098`, `T1530`, `T1567`, `T1078`, and `T1041`.
2. Apply or stage `M1032`, `M1036`, `M1018`, `M1026`, `M1057`, and `M1047`.

### PB-MOBILE

Trigger: any verified mobile-domain technique, mobile banking app compromise, mobile device compromise, MDM alert, SIM/session abuse, or suspicious mobile API behavior.

Attacker objective: compromise mobile banking sessions, steal credentials/tokens, bypass MFA, collect data, or control mobile endpoint.

Immediate actions:
1. AUTO: revoke confirmed compromised mobile session/token.
2. AUTO: add device ID, app version, IP, user agent, account, and API client ID to watchlists.
3. AUTO: preserve mobile app telemetry, API gateway logs, MDM logs, identity logs, fraud engine events, and customer session events.
4. APPROVAL_REQUIRED: queue app version block, device quarantine, customer account restriction, or fraud workflow hold.

Hunt and scope:
1. Determine whether compromise is customer device, employee device, app backend, API abuse, or fraud automation.
2. Check for credential/token theft, MFA bypass, account takeover, and fraudulent transaction attempts.

Predict and mitigate:
1. Predict credential access, collection, exfiltration, C2, and impact within mobile tactic set.
2. Apply or stage `M1006`, `M1012`, `M1011`, `M1009`, `M1010`, and banking fraud controls.

### PB-ICS-ATM-HSM

Trigger: any verified ICS-domain technique, `atm_or_hsm_involved=true`, ATM/POS/payment switch/HSM abnormality, terminal firmware/peripheral signal, or OT-like network behavior.

Attacker objective: disrupt physical banking devices, steal cash/card data, abuse cryptographic operations, alter payment paths, or impair response functions.

Severity rule: use `CRISIS` when the verified ICS/ATM/HSM evidence maps to impact, inhibit response function, impair process control, destructive behavior, cash integrity risk, or cryptographic key integrity risk.

Immediate actions:
1. AUTO: preserve terminal logs, HSM audit, ATM switch logs, firmware/peripheral state, network flows, jump host logs, IAM/PAM logs, and physical access records.
2. AUTO: increase monitoring on terminal fleet, switch messages, HSM operations, maintenance accounts, and vendor remote access.
3. AUTO: block confirmed hostile network source if scoped and no safety/service impact.
4. MANUAL_ONLY: queue HSM isolation, ATM switch isolation, terminal shutdown, key rotation, or physical dispatch through operations and CISO.

Hunt and scope:
1. Determine device class, physical location, maintenance window, vendor activity, and business process affected.
2. Check for command misuse, firmware change, credential use, lateral movement from IT, C2, and process impairment.
3. Validate HSM/key integrity and ATM cash/card operation state.

Predict and mitigate:
1. Predict lateral movement, inhibit response, impair process control, collection, C2, and impact in ICS tactic set.
2. Apply or stage `M0801`, `M0802`, `M0807`, `M0808`, `M0811`, `M0813`, `M0817`, `M0818`, and `M0930`.

### PB-INSIDER

Trigger: valid access plus suspicious data access, privilege change, policy deviation, slow progression, internal source, or behavior inconsistent with role.

Attacker objective: misuse legitimate access for fraud, data theft, sabotage, or unauthorized privilege.

Immediate actions:
1. AUTO: preserve access logs, user activity, HR/legal hold indicators if available, database/mailbox/cloud logs, endpoint telemetry, and approval workflow records.
2. AUTO: increase monitoring on account, peer accounts, accessed repositories, and transaction workflows.
3. APPROVAL_REQUIRED: queue account restriction, privileged role removal, or HR/legal escalation.
4. MANUAL_ONLY: employment or disciplinary actions are outside SOC automation.

Hunt and scope:
1. Compare actions against role, schedule, business process, historical baseline, and peer group.
2. Determine whether activity is malicious insider, compromised insider account, policy violation, or operational exception.
3. Search for data staging, exfiltration, transaction manipulation, and evidence tampering.

Predict and mitigate:
1. Predict `T1005`, `T1114`, `T1530`, `T1041`, `T1070`, and `T1657`.
2. Apply or stage `M1018`, `M1026`, `M1032`, `M1047`, `M1057`, and segregation-of-duties controls.

### PB-ANOMALY

Trigger: verified abnormal behavior with no known MITRE technique match, zero-day-like pattern, telemetry gap, unexplained resource/process/network/auth/crash/data anomaly.

Attacker objective: unknown. Treat as potentially novel exploitation, stealth, misconfiguration abuse, or early-stage compromise until disproven.

Immediate actions:
1. AUTO: preserve volatile evidence, memory metadata, process tree, network flows, relevant logs, crash dumps, and affected configuration state.
2. AUTO: increase logging and create temporary detection around the affected entity, behavior, and peer group.
3. AUTO: add observed indicators to local watchlists with provisional labels.
4. AUTO: isolate user workstation if active compromise or active damage is confirmed.
5. APPROVAL_REQUIRED: queue server isolation if banking-critical or anomaly spreads across systems.

Hunt and scope:
1. Classify anomaly as resource, process, network, auth, crash, data, or telemetry gap.
2. Compare against baseline and peer group; identify first-seen timestamp and propagation.
3. Map the behavior to nearest MITRE tactic, CAPEC pattern, or CWE weakness if possible.
4. If unexplained anomaly persists across two or more systems, escalate to `CRISIS` for banking-critical systems.

Predict and mitigate:
1. If likely exploit, stage `PB-WEB-EDGE`, `PB-EXECUTION`, and `PB-PERSIST` detections.
2. If likely credential/session issue, stage `PB-CRED`, `PB-VALID-ACCOUNT-MISUSE`, and `PB-LATERAL` detections.
3. If likely data issue, stage `PB-COLLECTION` and `PB-EXFIL` detections.
4. Apply general `M1047`, `M1030`, `M1031`, `M1032`, `M1051`, and evidence preservation.

## 8. Predictive Defense Workflow

After every activated playbook:

1. Read `prediction_chains[technique_id].next_likely_techniques` from `mitre_attack_full.json` for every verified technique.
2. Add `same_capec_techniques` when CAPEC-linked techniques exist.
3. Expand predicted subtechniques to parents and route predicted techniques through this playbook.
4. Rank predicted techniques by severity, banking flag, kill-chain distance, number of independent current indicators, and blast radius.
5. For the top predictions, create temporary detection rules using each technique's MITRE data sources.
6. Apply only low/medium impact mitigations automatically; queue high/critical changes.
7. Record predictive defenses even when no action is executed.

Generic attacker progression when KB prediction is empty:

| Current Evidence | Most Likely Next | Pre-stage Defense |
|------------------|------------------|-------------------|
| Recon/resource development | `T1566`, `T1190`, `T1133`, `T1078` | Watch exposed services, email targets, VPN/SSO, brand domains |
| Initial access | `T1059`, `T1105`, `T1505.003`, `T1547` | Script/tool download detections, web root FIM, EDR high sensitivity |
| Execution | `T1547`, `T1053`, `T1003`, `T1071` | Startup persistence hunt, credential access watch, C2 detection |
| Persistence | `T1548`, `T1055`, `T1003`, `T1021` | Admin token monitoring, LSASS protection, remote service monitoring |
| Privilege escalation | `T1003`, `T1021`, `T1685`, `T1070` | Credential protections, east-west monitoring, control tamper detection |
| Stealth/defense impairment | `T1003`, `T1041`, `T1486`, `T1490` | Backup verification, DLP, log immutability, ransomware canaries |
| Credential access | `T1078`, `T1550`, `T1021`, `T1098` | Session revocation plan, MFA challenge, group membership monitoring |
| Discovery | `T1021`, `T1570`, `T1005`, `T1074` | Remote service monitoring, staging path detection, repository audit |
| Lateral movement | `T1003`, `T1486`, `T1041`, `T1657` | Protect new targets, monitor data egress and banking workflows |
| Collection | `T1041`, `T1048`, `T1567`, `T1070` | DLP high sensitivity, egress monitoring, WORM log preservation |
| C2 | `T1105`, `T1041`, `T1570`, `T1003` | Block C2, hunt tool transfer, DLP and lateral movement detections |
| Exfiltration | `T1070`, `T1485`, `T1657` | Preserve logs, snapshot data, integrity checks, fraud monitoring |
| Impact | `T1490`, `T1489`, `T1070`, repeat impact | Protect backups, restore services, preserve evidence, crisis response |

## 9. Evidence Preservation Checklist

Use the relevant items before disruptive action:

1. Identity: AD/IAM/SSO/MFA/PAM/VPN/Kerberos logs, session IDs, token IDs, account changes.
2. Endpoint: memory metadata, process tree, command lines, loaded modules, file paths, hashes, registry keys, services, scheduled tasks.
3. Network: firewall, proxy, DNS, NetFlow, packet samples, TLS metadata, NDR, VPN, IDS/IPS.
4. Application/API: WAF, API gateway, application logs, database audit, transaction workflow, fraud engine.
5. Data: DLP, database queries, object storage, file share, mailbox, cloud storage, repository logs.
6. Banking: SWIFT/payment gateway, Core Banking workflow, ATM switch, HSM audit, card/POS, reconciliation logs.
7. Control plane: EDR/AV policy, firewall rules, SIEM rules, cloud IAM, SaaS admin audit, CI/CD logs.
8. Physical/vendor: maintenance window, vendor session, terminal location, physical access, change ticket.

## 10. Regulatory And Escalation Routing

These are assessment triggers, not automatic external notifications.

| Condition | Internal Escalation | External Handling |
|-----------|---------------------|-------------------|
| Confirmed customer personal data breach | CISO, Legal/Compliance, Data Protection owner | Legal/Compliance assesses Vietnam personal data obligations |
| Cardholder data breach | CISO, Legal/Compliance, Card program owner | Legal/Compliance and card program owner assess PCI/card brand path |
| SWIFT/payment fraud or manipulation | CEO, Board, CISO, CTO, Legal/Compliance, payment business owner | Regulator/SWIFT/correspondent handling only after approval |
| Core Banking compromise | CEO, Board, CISO, CTO, Core Banking owner, Legal/Compliance | Regulator liaison prepares assessment package |
| ATM/HSM/payment hardware compromise | CISO, Operations, Physical Security, Legal/Compliance | Law enforcement/regulator path requires approval |
| Service disruption affecting banking operations | CISO, CTO, Operations, Customer Support lead | Compliance assesses reporting threshold |

## 11. Quality Gates For Orchestrator Output

Before final Layer 2 output, verify:

1. Every activated playbook has a verified technique, verified tactic, banking flag, or anomaly rationale.
2. Every technique ID in rationale exists in the offline KB.
3. Every action has `priority`, `timestamp`, `target`, `approval_mode`, `status`, and `playbook_source`.
4. Every queued action has approver and reason.
5. High/critical action is not marked `AUTO` unless a local emergency runbook explicitly allows it.
6. Parent/subtechnique expansion was applied.
7. Predictive defenses are present or explicitly empty with rationale.
8. Banking impact is assessed for SWIFT/payment, Core Banking, customer data, ATM/HSM, privileged identity, backup/recovery, and security controls.
9. Evidence preservation is listed before disruptive containment.
10. Regulatory assessment is separated from external notification.
11. If `final_risk_score_0_10 > 6.0`, output includes `decision.risk_response_floor.triggered=true` and every available non-disruptive floor action is present with `status="executed"` or a documented blocked/unavailable reason.
12. If an environment-changing action has `status="executed"`, the full auto-containment gate is documented under `automation_control.auto_containment_gates` and every gate field is `true`: `threat_confirmed`, `l2_verification_performed`, `verification_confirmed`, `verification_supported_or_strong`, `risk_above_floor`, `opa_allow`, `soc_autopilot_on`, `execution_window_open`, `action_scoped_timebound_reversible`, `rollback_available`, `dangerous_now_behavior`, and `verified_target_entity`.
13. If `correlation.same_attack_assessment=true`, `correlation.correlation_keys.entities` contains at least one concrete entity link such as user, account, host, IP, session, request, transaction, or object ID; worker count, same broad domain, or time-only overlap is not sufficient.
14. If Layer 1 findings overlap only by time window, every non-primary finding is listed in `correlation.unrelated_findings[]` with `recommended_handling`; it is not hidden only in narrative quality notes.
15. If correlation is uncertain, `scoring.score_rationale` records both the independent-incident interpretation and the hypothetical chain interpretation before response-mode selection.
16. Every verification source records `query_status`; source unavailability, timeout, stale context, or no matching evidence is reflected in `verification_state` and risk-cap rationale.

"""
Aegis Lightweight Log Classifier — 3-Stage Pipeline
=====================================================
Production-grade pre-processing classifier that filters out noise, catches obvious
attacks, and only forwards truly suspicious logs to the LLM for analysis.

Pipeline Architecture (all routing via Kafka — no secondary broker):
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Stage 1: Pydantic Validation                                      │
  │    → DROP invalid/malformed logs                                    │
  ├─────────────────────────────────────────────────────────────────────┤
  │  Stage 2: Static Filtering (Fast Path) — O(1), pure CPU            │
  │    → DROP: health checks, static assets, internal noise             │
  │    → SOAR_FAST_PATH: obvious attacks (SQLi, traversal, Log4j)       │
  │    → CONTINUE: needs further analysis                               │
  ├─────────────────────────────────────────────────────────────────────┤
  │  Stage 3: Redis Thresholding (State Path) — sliding window          │
  │    → Enriches with threshold signals (brute-force, burst, etc.)     │
  │    → Boosts anomaly score when thresholds triggered                 │
  ├─────────────────────────────────────────────────────────────────────┤
  │  Stage 4: Multi-Signal Scoring (existing)                           │
  │    → Regex, entropy, baseline, banking-domain signals               │
  │    → Classify: benign | suspicious | anomalous | threat             │
  └─────────────────────────────────────────────────────────────────────┘

Routing Output:
  - DROP:           Silently dropped (optionally archived to S3)
  - SOAR_FAST_PATH: Produce to `soar.actions.fast-path` (bypass AI)
  - LLM_QUEUE:      Forward to LLM agent for deep analysis
  - BENIGN_DROP:    Low-score logs dropped after scoring

Integration:
  - Called from parser.py as the single entry point
  - Kafka is the ONLY message broker (no RabbitMQ/Redis as queue)
  - Redis used ONLY for state management (threshold counters)
"""

import math
import re
import time
from collections import defaultdict
from datetime import datetime, timezone

from event_schema import SecurityEventValidator
from static_rules import StaticRules, ACTION_DROP, ACTION_SOAR_FAST_PATH, ACTION_CONTINUE
from threshold_rules import ThresholdRules

# ==================================================
# Signal Weight Configuration
# ==================================================
SIGNAL_WEIGHTS = {
    # Regex threat signals (heaviest)
    "regex_threat":          0.50,
    "prompt_injection":      0.45,
    "path_traversal":        0.40,
    "command_injection":     0.40,
    "sql_injection":         0.40,

    # Behavioral signals
    "high_entropy_payload":  0.25,
    "rare_endpoint":         0.20,
    "high_error_rate":       0.20,
    "burst_request":         0.25,
    "off_hours_access":      0.15,
    "long_payload":          0.15,
    "suspicious_user_agent": 0.20,

    # Context signals
    "critical_asset_access": 0.15,
    "external_ip":           0.10,
    "non_standard_method":   0.15,

    # Banking-domain signals (from agent-layer-1 CAPEC matrix)
    "swift_payment_path":    0.30,
    "core_banking_path":     0.25,
    "customer_data_path":    0.20,
    "atm_hsm_path":          0.25,
    "privileged_identity":   0.25,
    "fraud_control_path":    0.20,

    # Threshold-triggered signals (from Stage 3)
    "threshold_brute_force":     0.40,
    "threshold_burst":           0.30,
    "threshold_error_spike":     0.25,
    "threshold_scan":            0.35,
    "threshold_auth_spike":      0.45,
}

# Anomaly score classification thresholds
THRESHOLD_SUSPICIOUS = 0.25
THRESHOLD_ANOMALOUS  = 0.50
THRESHOLD_THREAT     = 0.75

# ==================================================
# Lightweight Regex Patterns for Known Attack Vectors
# (used in Stage 4 scoring — different from Stage 2 SOAR bypass)
# ==================================================
ATTACK_PATTERNS = {
    "sql_injection": re.compile(
        r"(?i)(\b(union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into|"
        r"update\s+.*\s+set|delete\s+from|alter\s+table|exec\s*\(|xp_cmdshell|"
        r"0x[0-9a-f]{8,}|char\s*\(\d+\)|concat\s*\(|information_schema|"
        r"or\s+1\s*=\s*1|'\s*or\s*'|--\s*$|;\s*drop)\b)",
        re.IGNORECASE
    ),
    "path_traversal": re.compile(
        r"(\.\./|\.\.\\|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|"
        r"/proc/self|/var/log|/windows/system32|boot\.ini)",
        re.IGNORECASE
    ),
    "command_injection": re.compile(
        r"(?i)(;\s*(ls|cat|whoami|id|uname|curl|wget|nc|ncat|bash|sh|cmd|powershell)\b|"
        r"\|\s*(ls|cat|whoami|id)\b|`[^`]+`|\$\(.*\)|%0a|%0d)",
        re.IGNORECASE
    ),
    "xss_attack": re.compile(
        r"(?i)(<script[^>]*>|javascript\s*:|on(error|load|click|mouseover)\s*=|"
        r"<img[^>]+onerror|<svg[^>]+onload|document\.cookie|alert\s*\(|eval\s*\()",
        re.IGNORECASE
    ),
    "prompt_injection": re.compile(
        r"(?i)(<\|.*?\|>|\[/?INST\]|\[/?SYS\]|<<SYS>>|<system>|"
        r"\b(ignore\s+previous|forget\s+instructions|you\s+are\s+now|act\s+as\s+|"
        r"override\s+safety|output\s+only|disregard\s+all)\b)",
        re.IGNORECASE
    ),
    "log4j_jndi": re.compile(
        r"(?i)\$\{jndi:[a-zA-Z0-9]+://|"
        r"\$\{(lower|upper|env|sys|java|date):",
        re.IGNORECASE
    ),
    "ssrf_attempt": re.compile(
        r"(?i)(169\.254\.169\.254|metadata\.google\.internal|"
        r"localhost:\d+|127\.0\.0\.1:\d+|0\.0\.0\.0:\d+)",
        re.IGNORECASE
    ),
}

# Suspicious User-Agent fragments
SUSPICIOUS_UA_PATTERNS = re.compile(
    r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|burpsuite|zaproxy|"
    r"havij|acunetix|nessus|openvas|w3af|wpscan|hydra|medusa|"
    r"python-requests/|curl/|wget/|Go-http-client|"
    r"scrapy|phantomjs|headlesschrome)",
    re.IGNORECASE
)

# HTTP methods considered unusual/suspicious
UNUSUAL_METHODS = frozenset(["TRACE", "CONNECT", "OPTIONS", "PATCH", "DELETE", "PUT"])


# ==================================================
# Statistical Baseline Tracker
# ==================================================
class BaselineTracker:
    """
    Maintains rolling statistical baselines for:
    - Request rate per source IP (burst detection)
    - Error rate per source IP
    - Endpoint frequency distribution (rare endpoint detection)
    - Time-of-day activity patterns
    """

    def __init__(self, window_seconds=300):
        self.window = window_seconds
        self.ip_request_times = defaultdict(list)
        self.ip_error_counts  = defaultdict(int)
        self.ip_request_counts = defaultdict(int)
        self.endpoint_counts  = defaultdict(int)
        self.total_requests   = 0
        self.last_cleanup     = time.time()

    def _cleanup(self):
        now = time.time()
        if now - self.last_cleanup < 30:
            return
        self.last_cleanup = now
        cutoff = now - self.window

        for ip in list(self.ip_request_times.keys()):
            self.ip_request_times[ip] = [
                t for t in self.ip_request_times[ip] if t > cutoff
            ]
            if not self.ip_request_times[ip]:
                del self.ip_request_times[ip]

    def record(self, ip, endpoint, status_code):
        now = time.time()
        self._cleanup()

        self.ip_request_times[ip].append(now)
        self.ip_request_counts[ip] += 1
        self.total_requests += 1

        # Normalize endpoint (strip query params)
        base_endpoint = endpoint.split("?")[0] if endpoint else "/"
        self.endpoint_counts[base_endpoint] += 1

        if status_code and status_code >= 400:
            self.ip_error_counts[ip] += 1

    def get_burst_score(self, ip, threshold=20):
        """Returns 0.0-1.0 based on request rate in the last 10 seconds."""
        now = time.time()
        recent = [t for t in self.ip_request_times.get(ip, []) if now - t < 10]
        count = len(recent)
        if count <= 3:
            return 0.0
        return min(1.0, count / threshold)

    def get_error_rate(self, ip):
        """Returns error rate for an IP (0.0-1.0)."""
        total = self.ip_request_counts.get(ip, 0)
        if total < 5:
            return 0.0
        errors = self.ip_error_counts.get(ip, 0)
        return errors / total

    def is_rare_endpoint(self, endpoint, percentile_threshold=0.01):
        """True if endpoint is in the bottom 1% of frequency."""
        base_endpoint = endpoint.split("?")[0] if endpoint else "/"
        if self.total_requests < 50:
            return False
        count = self.endpoint_counts.get(base_endpoint, 0)
        return (count / self.total_requests) < percentile_threshold


# ==================================================
# Entropy Calculator
# ==================================================
def calculate_entropy(text):
    """Shannon entropy of a string. High entropy = potentially encoded/obfuscated."""
    if not text or len(text) < 8:
        return 0.0
    freq = defaultdict(int)
    for ch in text:
        freq[ch] += 1
    length = len(text)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return entropy


# ==================================================
# Main Classifier — 3-Stage Pipeline
# ==================================================
class LightweightClassifier:
    """
    Production-grade 3-stage classifier pipeline.
    
    Usage:
        classifier = LightweightClassifier()
        result = classifier.classify(log_record)
        
        if result["routing_action"] == "SOAR_FAST_PATH":
            # Send to soar.actions.fast-path topic
        elif result["routing_action"] == "LLM_QUEUE":
            # Send to LLM agent for analysis
        else:
            # DROP — silently discard
    """

    def __init__(self):
        # Stage 1: Pydantic validation
        self.validator = SecurityEventValidator()
        
        # Stage 2: Static filtering
        self.static_rules = StaticRules()
        
        # Stage 3: Redis thresholding
        self.threshold_rules = ThresholdRules()
        
        # Stage 4: Scoring baseline
        self.baseline = BaselineTracker(window_seconds=300)
        
        # Pipeline stats
        self.stats = {
            "total_processed": 0,
            "stage1_invalid_dropped": 0,
            "stage2_static_dropped": 0,
            "stage2_soar_fast_path": 0,
            "stage3_threshold_triggered": 0,
            "benign_dropped": 0,
            "suspicious_forwarded": 0,
            "anomalous_forwarded": 0,
            "threat_forwarded": 0,
        }

    def classify(self, record):
        """
        Run the full 3-stage classification pipeline.
        
        Args:
            record: dict with keys like message, sourceIp, statusCode, etc.
        
        Returns:
            dict with:
              - routing_action: "DROP" | "SOAR_FAST_PATH" | "LLM_QUEUE"
              - anomaly_score: float [0.0 – 1.0]
              - classification: "benign" | "suspicious" | "anomalous" | "threat"
              - signals: list of triggered signal names
              - should_forward: bool (backward compatible)
              - soar_metadata: dict (only if SOAR_FAST_PATH)
              - threshold_rules: list (only if thresholds triggered)
        """
        self.stats["total_processed"] += 1

        # ==========================================
        # Stage 1: Pydantic Validation
        # ==========================================
        validated = self.validator.validate(record)
        if validated is None:
            self.stats["stage1_invalid_dropped"] += 1
            return {
                "routing_action": "DROP",
                "anomaly_score": 0.0,
                "classification": "invalid",
                "signals": ["invalid_schema"],
                "should_forward": False,
            }
        # Use validated record from here
        record = validated

        # ==========================================
        # Stage 2: Static Filtering (Fast Path)
        # ==========================================
        action, metadata = self.static_rules.evaluate(record)

        if action == ACTION_DROP:
            self.stats["stage2_static_dropped"] += 1
            return {
                "routing_action": "DROP",
                "anomaly_score": 0.0,
                "classification": "noise",
                "signals": [f"static_drop:{metadata.get('reason', 'unknown')}"],
                "should_forward": False,
            }

        if action == ACTION_SOAR_FAST_PATH:
            self.stats["stage2_soar_fast_path"] += 1
            attack_type = metadata.get("attack_type", "UNKNOWN")
            return {
                "routing_action": "SOAR_FAST_PATH",
                "anomaly_score": 1.0,
                "classification": "threat",
                "signals": [f"soar_bypass:{attack_type}"],
                "should_forward": True,
                "soar_metadata": metadata,
            }

        # ==========================================
        # Stage 3: Redis Thresholding
        # ==========================================
        threshold_triggered, triggered_rules = self.threshold_rules.evaluate(record)
        if threshold_triggered:
            self.stats["stage3_threshold_triggered"] += 1

        # ==========================================
        # Stage 4: Multi-Signal Scoring
        # ==========================================
        signals = []
        score = 0.0

        # Inject threshold signals into scoring
        for rule in triggered_rules:
            rule_name = rule.get("rule", "unknown")
            signal_key = f"threshold_{rule_name}"
            signals.append(f"threshold:{rule_name}={rule['count']}/{rule['threshold']}")
            score += SIGNAL_WEIGHTS.get(signal_key, 0.20)

        # Extract fields
        message     = record.get("message", "")
        payload     = record.get("decodedPayload", message)
        source_ip   = record.get("sourceIp", "127.0.0.1")
        status_code = record.get("statusCode", 0)
        facility    = record.get("facility", "")
        severity    = record.get("severity", "info")
        threat_flag = record.get("threatFlagged", False)
        criticality = record.get("assetCritical", "LOW")
        user_agent  = record.get("agent", "") or ""
        method      = record.get("method", "GET")
        endpoint    = record.get("url.original", payload)

        # 0. Fast path: if already threat-flagged by regex rules
        if threat_flag:
            threat_type = record.get("threatType", "unknown")
            signals.append(f"regex_threat:{threat_type}")
            score += SIGNAL_WEIGHTS["regex_threat"]

        # 1. Attack Pattern Scanning
        for attack_name, pattern in ATTACK_PATTERNS.items():
            if pattern.search(payload):
                if f"regex_threat:{attack_name}" not in signals:
                    signals.append(f"attack_pattern:{attack_name}")
                    score += SIGNAL_WEIGHTS.get(attack_name, 0.30)

        # 2. Entropy Analysis
        if len(payload) > 20:
            entropy = calculate_entropy(payload)
            if entropy > 5.0:
                signals.append(f"high_entropy:{entropy:.2f}")
                score += SIGNAL_WEIGHTS["high_entropy_payload"] * min(1.0, (entropy - 5.0) / 2.0)

        # 3. Behavioral Baseline Signals
        self.baseline.record(source_ip, endpoint, status_code)

        burst_score = self.baseline.get_burst_score(source_ip)
        if burst_score > 0.3:
            signals.append(f"burst_request:{burst_score:.2f}")
            score += SIGNAL_WEIGHTS["burst_request"] * burst_score

        error_rate = self.baseline.get_error_rate(source_ip)
        if error_rate > 0.3:
            signals.append(f"high_error_rate:{error_rate:.2f}")
            score += SIGNAL_WEIGHTS["high_error_rate"] * error_rate

        if self.baseline.is_rare_endpoint(endpoint):
            signals.append("rare_endpoint")
            score += SIGNAL_WEIGHTS["rare_endpoint"]

        # 4. Off-hours detection (banking hours: 07:00 – 22:00 UTC+7)
        now_utc = datetime.now(timezone.utc)
        local_hour = (now_utc.hour + 7) % 24
        if local_hour < 6 or local_hour >= 23:
            signals.append(f"off_hours:{local_hour:02d}h")
            score += SIGNAL_WEIGHTS["off_hours_access"]

        # 5. Payload length anomaly
        if len(payload) > 500:
            signals.append(f"long_payload:{len(payload)}")
            score += SIGNAL_WEIGHTS["long_payload"]

        # 6. Suspicious User-Agent
        if user_agent and SUSPICIOUS_UA_PATTERNS.search(user_agent):
            signals.append("suspicious_user_agent")
            score += SIGNAL_WEIGHTS["suspicious_user_agent"]

        # 7. Non-standard HTTP method
        if method.upper() in UNUSUAL_METHODS:
            signals.append(f"non_standard_method:{method}")
            score += SIGNAL_WEIGHTS["non_standard_method"]

        # 8. Critical asset access boost
        if criticality in ("HIGH", "CRITICAL"):
            signals.append(f"critical_asset:{criticality}")
            score += SIGNAL_WEIGHTS["critical_asset_access"]

        # 9. External IP boost (non-private)
        if source_ip and not (
            source_ip.startswith("127.") or
            source_ip.startswith("10.") or
            source_ip.startswith("192.168.") or
            source_ip.startswith("172.")
        ):
            signals.append("external_ip")
            score += SIGNAL_WEIGHTS["external_ip"]

        # 10. HTTP error code signal
        if status_code >= 500:
            signals.append(f"server_error:{status_code}")
            score += 0.15
        elif status_code in (401, 403):
            signals.append(f"auth_error:{status_code}")
            score += 0.10

        # 11. Banking-domain path detection
        payload_lower = payload.lower()
        banking_domain = {}
        if any(kw in payload_lower for kw in ("/swift", "/payment", "/transfer", "/beneficiary")):
            signals.append("banking:swift_payment_path")
            score += SIGNAL_WEIGHTS["swift_payment_path"]
            banking_domain["swift_or_payment_path"] = True
        if any(kw in payload_lower for kw in ("/core-banking", "/account/", "/ledger", "/settlement")):
            signals.append("banking:core_banking_path")
            score += SIGNAL_WEIGHTS["core_banking_path"]
            banking_domain["core_banking_path"] = True
        if any(kw in payload_lower for kw in ("/customer", "/profile", "/kyc", "/statement", "/personal")):
            signals.append("banking:customer_data_path")
            score += SIGNAL_WEIGHTS["customer_data_path"]
            banking_domain["customer_data_path"] = True
        if any(kw in payload_lower for kw in ("/atm", "/hsm", "/xfs", "/cash-dispenser")):
            signals.append("banking:atm_hsm_path")
            score += SIGNAL_WEIGHTS["atm_hsm_path"]
            banking_domain["atm_or_hsm_path"] = True
        if any(kw in payload_lower for kw in ("/iam", "/pam", "/sso", "/ldap", "/kerberos", "/admin/role")):
            signals.append("banking:privileged_identity")
            score += SIGNAL_WEIGHTS["privileged_identity"]
            banking_domain["privileged_identity_path"] = True
        if any(kw in payload_lower for kw in ("/fraud", "/aml", "/compliance", "/sanctions")):
            signals.append("banking:fraud_control_path")
            score += SIGNAL_WEIGHTS["fraud_control_path"]
            banking_domain["fraud_control_path"] = True

        # Store banking domain flags for LLM agent enrichment
        if banking_domain:
            record["_banking_domain"] = banking_domain

        # Clamp score
        score = min(1.0, score)

        # Classify
        if score >= THRESHOLD_THREAT:
            classification = "threat"
            self.stats["threat_forwarded"] += 1
        elif score >= THRESHOLD_ANOMALOUS:
            classification = "anomalous"
            self.stats["anomalous_forwarded"] += 1
        elif score >= THRESHOLD_SUSPICIOUS:
            classification = "suspicious"
            self.stats["suspicious_forwarded"] += 1
        else:
            classification = "benign"
            self.stats["benign_dropped"] += 1

        should_forward = classification != "benign"

        result = {
            "routing_action": "LLM_QUEUE" if should_forward else "DROP",
            "anomaly_score":   round(score, 4),
            "classification":  classification,
            "signals":         signals,
            "should_forward":  should_forward,
        }

        # Attach threshold rules if triggered
        if triggered_rules:
            result["threshold_rules"] = triggered_rules

        return result

    def get_stats(self):
        s = self.stats.copy()
        total = s["total_processed"]
        if total > 0:
            effective_dropped = (
                s["stage1_invalid_dropped"] +
                s["stage2_static_dropped"] +
                s["benign_dropped"]
            )
            s["drop_rate"] = round(effective_dropped / total * 100, 1)
            s["forward_rate"] = round((total - effective_dropped) / total * 100, 1)
            s["soar_bypass_rate"] = round(s["stage2_soar_fast_path"] / total * 100, 1)
        
        # Include sub-stage stats
        s["validator_stats"] = self.validator.get_stats()
        s["static_rules_stats"] = self.static_rules.get_stats()
        s["threshold_stats"] = self.threshold_rules.get_stats()
        return s

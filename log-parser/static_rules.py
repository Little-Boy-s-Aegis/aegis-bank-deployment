"""
Aegis Static Filtering Rules (Stage 2 — Fast Path)
====================================================
High-speed IF/ELSE rules that run BEFORE any statistical or AI analysis.

Three possible outcomes for each log:
  - DROP:           Known-safe noise (health checks, static assets, internal login success)
  - SOAR_FAST_PATH: Obvious attacks that bypass AI → straight to SOAR for blocking
  - CONTINUE:       Needs further analysis (thresholding + scoring + LLM)

Design principles:
  - O(1) lookups for IP whitelist (frozenset + prefix matching)
  - Compiled regex for attack patterns (reuse from classifier.py)
  - No external I/O (no Redis, no DB) — pure CPU
"""

import ipaddress
import re
from typing import Tuple

# ==================================================
# Routing Actions
# ==================================================
ACTION_DROP = "DROP"
ACTION_SOAR_FAST_PATH = "SOAR_FAST_PATH"
ACTION_CONTINUE = "CONTINUE"

# ==================================================
# Internal IP Networks (Bank's trusted ranges)
# ==================================================
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# ==================================================
# Health Check / Monitoring Paths (always DROP)
# ==================================================
HEALTH_CHECK_PATHS = frozenset([
    "/health", "/healthz", "/ready", "/readyz", "/live", "/livez",
    "/metrics", "/prometheus", "/status",
    "/actuator/health", "/actuator/info", "/actuator/metrics",
    "/api/health", "/api/status", "/api/v1/health", "/api/v2/health",
    "/_ping", "/ping",
])

# ==================================================
# Static Asset Extensions (always DROP)
# ==================================================
STATIC_EXTENSIONS = frozenset([
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".webp", ".avif", ".mp4", ".webm", ".pdf",
    ".min.js", ".min.css", ".bundle.js", ".chunk.js",
])

# ==================================================
# Obvious Attack Patterns → SOAR Fast Path (bypass AI)
# These are high-confidence, unambiguous attack signatures
# ==================================================
SOAR_ATTACK_PATTERNS = {
    "SQL_INJECTION": re.compile(
        r"(?i)(\bunion\s+select\b|\bselect\s+.*\s+from\b|"
        r"\bdrop\s+table\b|\binsert\s+into\b|"
        r"\bor\s+1\s*=\s*1\b|'\s*or\s*'|--\s*$|"
        r"\bexec\s*\(|xp_cmdshell|information_schema)",
        re.IGNORECASE
    ),
    "PATH_TRAVERSAL": re.compile(
        r"(\.\./\.\./|%2e%2e%2f|"
        r"/etc/passwd|/etc/shadow|/proc/self|"
        r"/windows/system32|boot\.ini|"
        r"\.\.\\\.\.\\)",
        re.IGNORECASE
    ),
    "LOG4J_JNDI": re.compile(
        r"(?i)\$\{jndi:[a-zA-Z0-9]+://|"
        r"\$\{(lower|upper|env|sys|java):",
        re.IGNORECASE
    ),
    "COMMAND_INJECTION": re.compile(
        r"(?i)(;\s*(cat|whoami|id|uname|curl|wget|nc|bash|sh|cmd|powershell)\b|"
        r"\|\s*(cat|whoami|id)\b|"
        r"`[^`]+`|\$\(.*\))",
        re.IGNORECASE
    ),
    "XSS_ATTACK": re.compile(
        r"(?i)(<script[^>]*>|javascript\s*:|"
        r"on(error|load|click|mouseover)\s*=|"
        r"document\.cookie|alert\s*\(|eval\s*\()",
        re.IGNORECASE
    ),
    "SSRF_ATTEMPT": re.compile(
        r"(?i)(169\.254\.169\.254|metadata\.google\.internal|"
        r"localhost:\d+|127\.0\.0\.1:\d+|0\.0\.0\.0:\d+)",
        re.IGNORECASE
    ),
}

# Safe severities for internal IPs (drop noise)
SAFE_SEVERITIES = frozenset(["info", "debug", "trace", "notice"])


def _is_internal_ip(ip_str: str) -> bool:
    """Check if IP belongs to internal/private ranges."""
    if not ip_str:
        return True  # No IP = treat as internal (container-to-container)
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


def _is_static_asset(url: str) -> bool:
    """Check if URL points to a static asset."""
    if not url:
        return False
    # Strip query params
    path = url.split("?")[0].split("#")[0].lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def _is_health_check(url: str) -> bool:
    """Check if URL is a health check endpoint."""
    if not url:
        return False
    path = url.split("?")[0].rstrip("/").lower()
    return path in HEALTH_CHECK_PATHS


def _check_soar_attacks(payload: str) -> Tuple[bool, str]:
    """
    Scan payload for obvious attack patterns.
    Returns (is_attack, attack_type).
    """
    if not payload or len(payload) < 3:
        return False, ""
    for attack_type, pattern in SOAR_ATTACK_PATTERNS.items():
        if pattern.search(payload):
            return True, attack_type
    return False, ""


class StaticRules:
    """
    Stage 2: Static filtering engine.
    
    Runs high-speed IF/ELSE checks on every log record.
    No external I/O — pure CPU, O(1) lookups.
    """

    def __init__(self):
        self.stats = {
            "total_checked": 0,
            "dropped_internal_noise": 0,
            "dropped_static_asset": 0,
            "dropped_health_check": 0,
            "soar_fast_path": 0,
            "continued": 0,
        }

    def evaluate(self, record: dict) -> Tuple[str, dict]:
        """
        Evaluate a log record against static rules.
        
        Args:
            record: Validated log dict from Stage 1.
            
        Returns:
            Tuple of (action, metadata):
            - action: DROP | SOAR_FAST_PATH | CONTINUE
            - metadata: dict with details (attack_type, drop_reason, etc.)
        """
        self.stats["total_checked"] += 1

        source_ip = record.get("sourceIp", "")
        severity = record.get("severity", "info")
        status_code = record.get("statusCode", 0)
        message = record.get("message", "")
        payload = record.get("decodedPayload", message)
        url = record.get("url.original", payload)
        method = record.get("method", "GET")
        is_internal = _is_internal_ip(source_ip)

        # ----- DROP Rules (known-safe noise) -----

        # Rule 1: Health check endpoints
        if _is_health_check(url):
            self.stats["dropped_health_check"] += 1
            return ACTION_DROP, {"reason": "health_check", "url": url[:100]}

        # Rule 2: Static assets
        if _is_static_asset(url):
            self.stats["dropped_static_asset"] += 1
            return ACTION_DROP, {"reason": "static_asset", "url": url[:100]}

        # Rule 3: Internal IP + safe severity + no error → noise
        if (is_internal and 
            severity in SAFE_SEVERITIES and 
            status_code < 400 and
            not record.get("threatFlagged", False)):
            self.stats["dropped_internal_noise"] += 1
            return ACTION_DROP, {"reason": "internal_noise", "ip": source_ip}

        # ----- SOAR Fast Path (obvious attacks, bypass AI) -----

        # Rule 4: Scan for unambiguous attack signatures (external IPs only)
        is_attack, attack_type = _check_soar_attacks(payload)
        if is_attack and not is_internal:
            self.stats["soar_fast_path"] += 1
            return ACTION_SOAR_FAST_PATH, {
                "attack_type": attack_type,
                "source_ip": source_ip,
                "is_internal": is_internal,
                "payload_snippet": payload[:200],
                "recommended_action": _get_soar_action(attack_type, is_internal),
            }

        # ----- CONTINUE (needs further analysis) -----
        self.stats["continued"] += 1
        return ACTION_CONTINUE, {}

    def get_stats(self):
        return self.stats.copy()


def _get_soar_action(attack_type: str, is_internal: bool) -> str:
    """Determine recommended SOAR action for obvious attacks."""
    if is_internal:
        # Internal attacks need investigation, not blocking
        return "INVESTIGATE_INTERNAL"
    
    action_map = {
        "SQL_INJECTION": "BLOCK_IP",
        "PATH_TRAVERSAL": "BLOCK_IP",
        "LOG4J_JNDI": "BLOCK_IP",
        "COMMAND_INJECTION": "BLOCK_IP",
        "XSS_ATTACK": "BLOCK_IP",
        "SSRF_ATTEMPT": "BLOCK_IP",
    }
    return action_map.get(attack_type, "BLOCK_IP")

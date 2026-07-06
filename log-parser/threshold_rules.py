"""
Aegis Threshold Rules (Stage 3 — State Path)
==============================================
Redis-backed sliding window counters for detecting behavioral anomalies
that require tracking state across multiple log events.

Uses Redis INCR + EXPIRE for atomic, distributed counting.
Falls back to in-memory counters when Redis is unavailable.

Key patterns:
  bf:{ip}     — Brute-force login failures     (60s window, threshold=5)
  burst:{ip}  — Request burst detection         (10s window, threshold=30)
  err:{ip}    — Error spike                     (60s window, threshold=10)
  scan:{ip}   — Sensitive path scanning         (120s window, threshold=5)
  auth:{ip}   — Auth failure spike              (300s window, threshold=15)
"""

import os
import time
from collections import defaultdict
from typing import Optional, Tuple

# ==================================================
# Configuration
# ==================================================
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
REDIS_ENABLED = os.getenv("REDIS_ENABLED", "true").lower() == "true"

# Threshold configurations: (window_seconds, threshold_count)
THRESHOLD_CONFIGS = {
    "brute_force": {
        "key_prefix": "bf",
        "window": 60,
        "threshold": 5,
        "description": "Login failures from same IP",
    },
    "burst_request": {
        "key_prefix": "burst",
        "window": 10,
        "threshold": 30,
        "description": "Excessive requests in short window",
    },
    "error_spike": {
        "key_prefix": "err",
        "window": 60,
        "threshold": 10,
        "description": "High error rate from same IP",
    },
    "sensitive_scan": {
        "key_prefix": "scan",
        "window": 120,
        "threshold": 5,
        "description": "Multiple sensitive path accesses",
    },
    "auth_failure_spike": {
        "key_prefix": "auth",
        "window": 300,
        "threshold": 15,
        "description": "Sustained auth failures → SOAR",
    },
}

# Sensitive paths that count toward scanning detection
SENSITIVE_PATHS = frozenset([
    "/admin", "/api/admin", "/console", "/phpmyadmin", "/wp-admin",
    "/wp-login", "/.env", "/.git", "/config", "/backup",
    "/swagger", "/api-docs", "/debug", "/trace",
    "/actuator", "/management", "/internal",
])


# ==================================================
# Redis Client Wrapper
# ==================================================
class RedisClient:
    """Thread-safe Redis client with graceful fallback."""

    def __init__(self):
        self.client = None
        self.available = False

        if REDIS_ENABLED:
            try:
                import redis
                self.client = redis.from_url(
                    REDIS_URL,
                    decode_responses=True,
                    socket_timeout=2,
                    socket_connect_timeout=2,
                    retry_on_timeout=True,
                )
                # Test connection
                self.client.ping()
                self.available = True
                print(f"[THRESHOLD] Redis connected: {REDIS_URL}")
            except ImportError:
                print("[THRESHOLD] WARNING: redis package not installed. Using in-memory fallback.")
            except Exception as e:
                print(f"[THRESHOLD] WARNING: Redis unavailable ({e}). Using in-memory fallback.")
        else:
            print("[THRESHOLD] Redis disabled via REDIS_ENABLED=false. Using in-memory fallback.")

    def incr_with_ttl(self, key: str, ttl_seconds: int) -> int:
        """Atomically increment key and set TTL. Returns new count."""
        if not self.available:
            return -1  # Signal to use fallback

        try:
            pipe = self.client.pipeline()
            pipe.incr(key)
            pipe.expire(key, ttl_seconds)
            results = pipe.execute()
            return results[0]  # INCR result
        except Exception:
            self.available = False
            return -1

    def get_count(self, key: str) -> int:
        """Get current count for a key."""
        if not self.available:
            return -1
        try:
            val = self.client.get(key)
            return int(val) if val else 0
        except Exception:
            return -1


# ==================================================
# In-Memory Fallback Counter
# ==================================================
class InMemoryCounter:
    """Simple in-memory sliding window counter (single-instance only)."""

    def __init__(self):
        self.counters = defaultdict(list)  # key → [timestamps]
        self.last_cleanup = time.time()

    def incr_with_ttl(self, key: str, ttl_seconds: int) -> int:
        now = time.time()

        # Periodic cleanup (every 30s)
        if now - self.last_cleanup > 30:
            self._cleanup()
            self.last_cleanup = now

        # Add current timestamp
        self.counters[key].append(now)

        # Count entries within window
        cutoff = now - ttl_seconds
        self.counters[key] = [t for t in self.counters[key] if t > cutoff]
        return len(self.counters[key])

    def _cleanup(self):
        now = time.time()
        for key in list(self.counters.keys()):
            # Remove keys with no recent activity (> 600s)
            self.counters[key] = [t for t in self.counters[key] if now - t < 600]
            if not self.counters[key]:
                del self.counters[key]


# ==================================================
# Threshold Rules Engine
# ==================================================
class ThresholdRules:
    """
    Stage 3: Redis-backed threshold detection.
    
    Tracks event frequency per IP using sliding windows.
    Triggers alerts when thresholds are exceeded.
    Falls back to in-memory counting when Redis unavailable.
    """

    def __init__(self):
        self.redis = RedisClient()
        self.fallback = InMemoryCounter()
        self.stats = {
            "total_checked": 0,
            "thresholds_triggered": 0,
            "brute_force_triggered": 0,
            "burst_triggered": 0,
            "error_spike_triggered": 0,
            "scan_triggered": 0,
            "auth_spike_triggered": 0,
            "redis_fallback_used": 0,
        }

    def _increment(self, key: str, ttl: int) -> int:
        """Increment counter, using Redis or fallback."""
        count = self.redis.incr_with_ttl(key, ttl)
        if count == -1:
            # Redis unavailable, use fallback
            self.stats["redis_fallback_used"] += 1
            count = self.fallback.incr_with_ttl(key, ttl)
        return count

    def evaluate(self, record: dict) -> Tuple[bool, list]:
        """
        Evaluate a log record against threshold rules.
        
        Args:
            record: Validated log dict that passed Stage 2 (CONTINUE).
            
        Returns:
            Tuple of (threshold_triggered, triggered_rules):
            - threshold_triggered: True if any threshold was exceeded
            - triggered_rules: list of dicts with rule details
        """
        self.stats["total_checked"] += 1

        source_ip = record.get("sourceIp", "")
        if not source_ip:
            return False, []

        status_code = record.get("statusCode", 0)
        message = record.get("message", "").lower()
        payload = record.get("decodedPayload", record.get("message", ""))
        url = record.get("url.original", payload)
        severity = record.get("severity", "info")

        triggered_rules = []

        # ----- Rule 1: Brute-force login detection -----
        is_login_fail = (
            status_code == 401 or
            "login_failed" in message or
            "authentication failed" in message or
            "invalid password" in message or
            "login failure" in message or
            "bad credentials" in message
        )
        if is_login_fail:
            cfg = THRESHOLD_CONFIGS["brute_force"]
            key = f"{cfg['key_prefix']}:{source_ip}"
            count = self._increment(key, cfg["window"])
            if count >= cfg["threshold"]:
                triggered_rules.append({
                    "rule": "brute_force",
                    "count": count,
                    "threshold": cfg["threshold"],
                    "window_seconds": cfg["window"],
                    "source_ip": source_ip,
                    "recommended_action": "LOCK_ACCOUNT",
                })
                self.stats["brute_force_triggered"] += 1

        # ----- Rule 2: Burst request detection -----
        cfg = THRESHOLD_CONFIGS["burst_request"]
        key = f"{cfg['key_prefix']}:{source_ip}"
        count = self._increment(key, cfg["window"])
        if count >= cfg["threshold"]:
            triggered_rules.append({
                "rule": "burst_request",
                "count": count,
                "threshold": cfg["threshold"],
                "window_seconds": cfg["window"],
                "source_ip": source_ip,
                "recommended_action": "RATE_LIMIT",
            })
            self.stats["burst_triggered"] += 1

        # ----- Rule 3: Error spike detection -----
        if status_code >= 400:
            cfg = THRESHOLD_CONFIGS["error_spike"]
            key = f"{cfg['key_prefix']}:{source_ip}"
            count = self._increment(key, cfg["window"])
            if count >= cfg["threshold"]:
                triggered_rules.append({
                    "rule": "error_spike",
                    "count": count,
                    "threshold": cfg["threshold"],
                    "window_seconds": cfg["window"],
                    "source_ip": source_ip,
                    "recommended_action": "INVESTIGATE",
                })
                self.stats["error_spike_triggered"] += 1

        # ----- Rule 4: Sensitive path scanning -----
        if url:
            path = url.split("?")[0].rstrip("/").lower()
            if any(path.startswith(sp) or path == sp for sp in SENSITIVE_PATHS):
                cfg = THRESHOLD_CONFIGS["sensitive_scan"]
                key = f"{cfg['key_prefix']}:{source_ip}"
                count = self._increment(key, cfg["window"])
                if count >= cfg["threshold"]:
                    triggered_rules.append({
                        "rule": "sensitive_scan",
                        "count": count,
                        "threshold": cfg["threshold"],
                        "window_seconds": cfg["window"],
                        "source_ip": source_ip,
                        "recommended_action": "BLOCK_IP",
                    })
                    self.stats["scan_triggered"] += 1

        # ----- Rule 5: Auth failure spike (→ SOAR) -----
        if status_code in (401, 403):
            cfg = THRESHOLD_CONFIGS["auth_failure_spike"]
            key = f"{cfg['key_prefix']}:{source_ip}"
            count = self._increment(key, cfg["window"])
            if count >= cfg["threshold"]:
                triggered_rules.append({
                    "rule": "auth_failure_spike",
                    "count": count,
                    "threshold": cfg["threshold"],
                    "window_seconds": cfg["window"],
                    "source_ip": source_ip,
                    "recommended_action": "BLOCK_IP",
                })
                self.stats["auth_spike_triggered"] += 1

        if triggered_rules:
            self.stats["thresholds_triggered"] += 1

        return bool(triggered_rules), triggered_rules

    def get_stats(self):
        s = self.stats.copy()
        s["redis_available"] = self.redis.available
        return s

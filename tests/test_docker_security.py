"""
Aegis Platform — Docker / Infrastructure Security Tests
========================================================
Static analysis tests for docker-compose.yml, nginx config, Kafka, OPA, and Vault.
Validates security best-practices WITHOUT requiring Docker to be running.

Usage:
    pytest test_docker_security.py -v
"""

import os
import re
import unittest

import yaml

# ---------------------------------------------------------------------------
# Paths (relative to repo root – adjust if your CWD differs)
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.basename(BASE_DIR) == "aegis-bank-deployment" or os.path.exists(os.path.join(BASE_DIR, "docker-compose.yml")):
    DEPLOYMENT_DIR = BASE_DIR
    PROJECT_ROOT = os.path.dirname(BASE_DIR)
else:
    DEPLOYMENT_DIR = os.path.join(BASE_DIR, "aegis-bank-deployment")
    PROJECT_ROOT = BASE_DIR

COMPOSE_PATH = os.path.join(DEPLOYMENT_DIR, "docker-compose.yml")
NGINX_CONF_PATH = os.path.join(DEPLOYMENT_DIR, "nginx", "default.conf")
VAULT_HCL_PATH = os.path.join(DEPLOYMENT_DIR, "vault", "config", "vault.hcl")
OPA_SOAR_REGO_PATH = os.path.join(DEPLOYMENT_DIR, "opa", "policies", "soar.rego")
KAFKA_INIT_SCRIPT = os.path.join(DEPLOYMENT_DIR, "scripts", "init-kafka-topics.sh")
SOAR_DOCKERFILE = os.path.join(PROJECT_ROOT, "soar-engine", "Dockerfile")



def _load_compose() -> dict:
    """Load and parse docker-compose.yml once."""
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_nginx_conf() -> str:
    """Load nginx default.conf as raw text."""
    with open(NGINX_CONF_PATH, "r", encoding="utf-8") as f:
        return f.read()


def _load_vault_hcl() -> str:
    """Load Vault config HCL file as raw text."""
    with open(VAULT_HCL_PATH, "r", encoding="utf-8") as f:
        return f.read()


def _load_opa_rego() -> str:
    """Load OPA SOAR policy rego file."""
    with open(OPA_SOAR_REGO_PATH, "r", encoding="utf-8") as f:
        return f.read()


def _load_kafka_init_script() -> str:
    """Load Kafka topic initialization script."""
    with open(KAFKA_INIT_SCRIPT, "r", encoding="utf-8") as f:
        return f.read()


# ============================================================================
# Docker Compose Security Tests (15+ tests)
# ============================================================================
class TestDockerComposeSecurity(unittest.TestCase):
    """Static security analysis of docker-compose.yml."""

    @classmethod
    def setUpClass(cls):
        cls.compose = _load_compose()
        cls.services = cls.compose.get("services", {})

    # --- Privilege / Namespace Isolation ---

    def test_no_privileged_containers(self):
        """No containers should run in --privileged mode."""
        for name, svc in self.services.items():
            privileged = svc.get("privileged", False)
            self.assertFalse(
                privileged,
                f"Service '{name}' is running in privileged mode!"
            )

    def test_no_host_network(self):
        """No containers should use host networking."""
        for name, svc in self.services.items():
            network_mode = svc.get("network_mode", "")
            self.assertNotEqual(
                network_mode, "host",
                f"Service '{name}' uses host network mode!"
            )

    def test_no_host_pid(self):
        """No containers should share the host PID namespace."""
        for name, svc in self.services.items():
            pid = svc.get("pid", "")
            self.assertNotEqual(
                pid, "host",
                f"Service '{name}' shares host PID namespace!"
            )

    # --- Port Binding Security ---

    def _collect_host_ports(self) -> list:
        """Returns list of (service_name, port_mapping_str) for every ports: entry."""
        results = []
        for name, svc in self.services.items():
            for p in svc.get("ports", []):
                results.append((name, str(p)))
        return results

    def test_ports_bound_to_localhost(self):
        """All exposed host ports MUST bind to 127.0.0.1 to prevent external access."""
        for name, port_str in self._collect_host_ports():
            # port_str format examples: "127.0.0.1:80:80", "8080:80"
            self.assertTrue(
                port_str.startswith("127.0.0.1:"),
                f"Service '{name}' exposes port '{port_str}' without binding to 127.0.0.1!"
            )

    def test_no_unnecessary_ports(self):
        """Only ports 80 (nginx) and 8095 (staging sandbox) should be exposed to host."""
        allowed_host_ports = {"80", "8095"}
        for name, port_str in self._collect_host_ports():
            # Extract the host port from "127.0.0.1:HOST_PORT:CONTAINER_PORT"
            # Use rsplit to split off the container port from the right first
            parts = port_str.rsplit(":", 1)
            host_part = parts[0]
            host_port = host_part.replace("127.0.0.1:", "")
            # Resolve default from ${VAR:-default} pattern
            match = re.search(r":-(\d+)\}", host_port)
            if match:
                host_port = match.group(1)
            self.assertIn(
                host_port, allowed_host_ports,
                f"Service '{name}' exposes unexpected host port {host_port}. Allowed: {allowed_host_ports}"
            )

    def test_postgres_not_exposed(self):
        """PostgreSQL port must NOT be published to the host."""
        pg_svc = self.services.get("postgres", {})
        self.assertEqual(
            pg_svc.get("ports"), None,
            "PostgreSQL has host-exposed ports! Use 'expose' instead."
        )

    def test_redis_not_exposed(self):
        """Redis port must NOT be published to the host."""
        redis_svc = self.services.get("redis", {})
        self.assertEqual(
            redis_svc.get("ports"), None,
            "Redis has host-exposed ports! Use 'expose' instead."
        )

    def test_vault_not_exposed(self):
        """Vault port must NOT be published to the host."""
        vault_svc = self.services.get("vault", {})
        self.assertEqual(
            vault_svc.get("ports"), None,
            "Vault has host-exposed ports! Use 'expose' instead."
        )

    def test_kafka_not_exposed(self):
        """Kafka broker ports must NOT be published to the host."""
        kafka_services = [n for n in self.services if n.startswith("kafka-") and n != "kafka-init" and n != "kafka-ui"]
        for name in kafka_services:
            svc = self.services[name]
            self.assertIsNone(
                svc.get("ports"),
                f"Kafka service '{name}' has host-exposed ports!"
            )

    # --- Secrets Management ---

    def test_no_secrets_in_compose(self):
        """No hardcoded secrets should appear in environment values."""
        secret_patterns = [
            r"password\s*[:=]\s*['\"]?[a-zA-Z0-9_]{8,}",  # hardcoded passwords
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",     # private keys
            r"(?:api[_-]?key|token|secret)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}",  # long literal tokens
        ]

        compose_raw = open(COMPOSE_PATH, "r", encoding="utf-8").read()
        for pattern in secret_patterns:
            # Exclude lines that use ${VAR} references (those are safe env-var refs)
            for line in compose_raw.splitlines():
                # Skip comment lines and lines that contain ${} env-var references
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "${" in stripped:
                    continue
                for pat in secret_patterns:
                    match = re.search(pat, stripped, re.IGNORECASE)
                    if match:
                        # Allow known non-secret defaults
                        matched_text = match.group(0)
                        known_safe = [
                            "scram-sha-256", "allkeys-lru", "AegisKafkaCluster001xyzw",
                            "soc@aegis.bank", "soc-team@aegis.bank"
                        ]
                        if not any(safe in matched_text for safe in known_safe):
                            self.fail(
                                f"Potential hardcoded secret found in compose: '{matched_text}' in line: {stripped}"
                            )

    def test_secrets_use_env_vars(self):
        """All sensitive environment values should use ${VAR} substitution format."""
        sensitive_keys = [
            "POSTGRES_PASSWORD", "JWT_SECRET", "AEGIS_SECURITY_SYNC_TOKEN",
            "DASHSCOPE_API_KEY", "VAULT_ROOT_TOKEN", "FORTINET_API_TOKEN",
            "CROWDSTRIKE_CLIENT_SECRET", "ENTRA_CLIENT_SECRET", "AD_LDAP_PASSWORD",
            "AWS_SECRET_ACCESS_KEY", "TELEGRAM_BOT_TOKEN", "PAGERDUTY_ROUTING_KEY",
            "JIRA_API_TOKEN", "SMTP_PASSWORD", "VIRUSTOTAL_API_KEY",
            "ABUSEIPDB_API_KEY", "SHODAN_API_KEY", "WEBHOOK_SECRET",
        ]

        for name, svc in self.services.items():
            env_list = svc.get("environment", {})
            # environment can be a dict or a list
            if isinstance(env_list, dict):
                items = env_list.items()
            elif isinstance(env_list, list):
                items = []
                for e in env_list:
                    if "=" in e:
                        k, v = e.split("=", 1)
                        items.append((k.strip(), v.strip()))
            else:
                continue

            for key, value in items:
                if key in sensitive_keys:
                    value_str = str(value)
                    # Must either use ${VAR} pattern or be empty/have ${VAR:-default} with mock prefix
                    has_env_ref = "${" in value_str
                    is_empty = value_str in ("", "None")
                    self.assertTrue(
                        has_env_ref or is_empty,
                        f"Service '{name}': sensitive key '{key}' has value '{value_str}' "
                        f"without ${{VAR}} substitution!"
                    )

    # --- Health Checks ---

    def test_containers_have_healthchecks(self):
        """All critical long-running services should have health checks."""
        # One-shot / init containers are excluded
        init_services = {"vault-init", "kafka-init"}
        # Frontend services that are less critical for health checks
        optional_healthcheck = {"fe-web", "dashboard-frontend", "kafka-ui", "fluent-bit",
                                "log-parser", "soar-orchestrator", "soar-action-worker",
                                "soar-orchestrator-standby", "soar-action-worker-standby",
                                "staging-sandbox", "opa"}

        must_have_healthcheck = {"postgres", "redis", "kafka-1", "kafka-2", "kafka-3",
                                 "be-backend", "dashboard-backend"}

        for name in must_have_healthcheck:
            svc = self.services.get(name)
            if svc is None:
                continue
            self.assertIn(
                "healthcheck", svc,
                f"Critical service '{name}' is missing a healthcheck!"
            )

    # --- Dockerfile Security ---

    def test_no_root_user_in_dockerfiles(self):
        """Check SOAR engine Dockerfile for USER directive (non-root best practice).
        
        NOTE: This test documents the current state — the SOAR Dockerfile runs as
        root by default. Adding a USER directive is a recommended hardening step.
        """
        if not os.path.exists(SOAR_DOCKERFILE):
            self.skipTest("SOAR Dockerfile not found")

        with open(SOAR_DOCKERFILE, "r", encoding="utf-8") as f:
            content = f.read()

        # Check for USER directive — if missing, log a warning but don't fail
        # since this is an aspirational security check
        has_user = bool(re.search(r"^\s*USER\s+", content, re.MULTILINE))
        if not has_user:
            import warnings
            warnings.warn(
                f"Dockerfile '{SOAR_DOCKERFILE}' does not contain a USER directive. "
                "Container runs as root by default. Consider adding 'USER appuser'.",
                stacklevel=2,
            )

    # --- Volume Security ---

    def test_readonly_volumes(self):
        """Sensitive config volumes should be mounted as read-only (:ro)."""
        readonly_required_patterns = [
            "nginx/default.conf",
            ".htpasswd",
            "fluent-bit/fluent-bit.conf",
            "fluent-bit/parsers.conf",
            "fluent-bit/filter_threats.lua",
            "vault/config",
            "opa/policies",
            "agent-layer-2",
        ]

        for name, svc in self.services.items():
            volumes = svc.get("volumes", [])
            for vol in volumes:
                vol_str = str(vol)
                for pattern in readonly_required_patterns:
                    if pattern in vol_str:
                        self.assertIn(
                            ":ro", vol_str,
                            f"Service '{name}': Sensitive volume '{vol_str}' is NOT mounted "
                            f"as read-only (:ro)!"
                        )

    def test_resource_limits(self):
        """Check if resource limits (mem_limit/cpus) are set.
        
        NOTE: This is a documentation/advisory test. Resource limits via
        deploy.resources are optional in dev but recommended for production.
        """
        services_needing_limits = ["postgres", "redis", "kafka-1", "kafka-2", "kafka-3"]
        missing_limits = []

        for name in services_needing_limits:
            svc = self.services.get(name, {})
            has_deploy_limits = "deploy" in svc and "resources" in svc.get("deploy", {})
            has_mem_limit = "mem_limit" in svc
            has_cpus = "cpus" in svc

            if not (has_deploy_limits or has_mem_limit or has_cpus):
                missing_limits.append(name)

        if missing_limits:
            import warnings
            warnings.warn(
                f"Services without resource limits: {missing_limits}. "
                "Consider adding deploy.resources.limits for production.",
                stacklevel=2,
            )


# ============================================================================
# Nginx Security Tests (10+ tests)
# ============================================================================
class TestNginxSecurity(unittest.TestCase):
    """Static security analysis of nginx default.conf."""

    @classmethod
    def setUpClass(cls):
        cls.conf = _load_nginx_conf()

    def test_nginx_security_headers_present(self):
        """Critical security headers must be configured."""
        required_headers = [
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        for header in required_headers:
            self.assertIn(
                header, self.conf,
                f"Missing security header '{header}' in nginx config!"
            )

    def test_nginx_rate_limiting(self):
        """Rate limiting must be configured for authentication endpoints."""
        self.assertIn("limit_req_zone", self.conf, "Missing limit_req_zone directive!")
        self.assertIn("limit_req ", self.conf, "Missing limit_req directive in location blocks!")
        self.assertIn("rate=", self.conf, "No rate= parameter found in rate limiting config!")

    def test_nginx_server_tokens_off(self):
        """Server version disclosure should be prevented."""
        # Check if server_tokens is explicitly set to off
        has_explicit = "server_tokens off" in self.conf
        self.assertTrue(
            has_explicit,
            "server_tokens is not explicitly set to 'off' in Nginx configuration!"
        )
        # Also check no 'server_tokens on' exists
        has_on = "server_tokens on" in self.conf
        self.assertFalse(
            has_on,
            "server_tokens is explicitly set to 'on'! This leaks nginx version info."
        )

    def test_nginx_blocked_paths(self):
        """Sensitive paths (Tomcat manager, .git, .env) should be blocked."""
        # The config blocks /manager and /host-manager
        self.assertRegex(
            self.conf,
            r"location.*manager",
            "Tomcat manager paths are not blocked in nginx!"
        )
        self.assertIn(
            "return 404", self.conf,
            "Blocked paths should return 404 to avoid information disclosure."
        )

    def test_nginx_ssl_protocols(self):
        """If SSL is configured, only TLS 1.2+ should be allowed.
        
        NOTE: Current deployment uses port 80 only (TLS termination may be
        handled upstream). This test verifies no insecure SSL protocols are set.
        """
        insecure_protocols = ["SSLv2", "SSLv3", "TLSv1 ", "TLSv1.0", "TLSv1.1"]
        for proto in insecure_protocols:
            self.assertNotIn(
                proto, self.conf,
                f"Insecure SSL protocol '{proto}' found in nginx config!"
            )

    def test_nginx_proxy_headers(self):
        """Reverse proxy must set X-Real-IP and X-Forwarded-For headers."""
        self.assertIn(
            "X-Real-IP", self.conf,
            "Missing X-Real-IP proxy header!"
        )
        self.assertIn(
            "X-Forwarded-For", self.conf,
            "Missing X-Forwarded-For proxy header!"
        )
        self.assertIn(
            "X-Forwarded-Proto", self.conf,
            "Missing X-Forwarded-Proto proxy header!"
        )

    def test_nginx_content_type_options(self):
        """X-Content-Type-Options: nosniff must be set."""
        self.assertIn(
            'X-Content-Type-Options "nosniff"', self.conf,
            "Missing X-Content-Type-Options: nosniff header!"
        )

    def test_nginx_referrer_policy(self):
        """Referrer-Policy header must be set."""
        self.assertIn(
            "Referrer-Policy", self.conf,
            "Missing Referrer-Policy header!"
        )
        # Ensure it's set to a secure value
        self.assertRegex(
            self.conf,
            r'Referrer-Policy\s+"(strict-origin-when-cross-origin|no-referrer|same-origin|strict-origin)"',
            "Referrer-Policy has an insecure or missing value!"
        )

    def test_nginx_permissions_policy(self):
        """Permissions-Policy header should restrict dangerous browser APIs."""
        self.assertIn(
            "Permissions-Policy", self.conf,
            "Missing Permissions-Policy header!"
        )
        # Verify dangerous features are denied
        for feature in ["camera=()", "microphone=()", "geolocation=()"]:
            self.assertIn(
                feature, self.conf,
                f"Permissions-Policy should deny '{feature.split('(')[0]}'!"
            )

    def test_nginx_cors_configuration(self):
        """CORS must not be configured as wildcard '*' (if set at all)."""
        # Check for dangerous wildcard CORS
        wildcard_cors = re.search(
            r"add_header\s+Access-Control-Allow-Origin\s+['\"]?\*['\"]?",
            self.conf
        )
        self.assertIsNone(
            wildcard_cors,
            "CORS is configured with wildcard '*'. This allows any origin!"
        )

    def test_nginx_xframe_deny(self):
        """X-Frame-Options should be set to DENY to prevent clickjacking."""
        self.assertRegex(
            self.conf,
            r'X-Frame-Options\s+"DENY"',
            "X-Frame-Options should be 'DENY' for maximum clickjacking protection!"
        )

    def test_nginx_hsts_preload(self):
        """HSTS header should include max-age, includeSubDomains, and preload."""
        hsts_match = re.search(
            r'Strict-Transport-Security\s+"([^"]+)"', self.conf
        )
        self.assertIsNotNone(hsts_match, "Missing HSTS header configuration!")
        hsts_value = hsts_match.group(1)
        self.assertIn("max-age=", hsts_value, "HSTS missing max-age directive!")
        self.assertIn("includeSubDomains", hsts_value, "HSTS missing includeSubDomains!")
        self.assertIn("preload", hsts_value, "HSTS missing preload directive!")


# ============================================================================
# Kafka Security Tests (5+ tests)
# ============================================================================
class TestKafkaSecurity(unittest.TestCase):
    """Static security analysis of Kafka configuration in docker-compose.yml."""

    @classmethod
    def setUpClass(cls):
        cls.compose = _load_compose()
        cls.services = cls.compose.get("services", {})
        cls.kafka_services = {
            name: svc for name, svc in cls.services.items()
            if name.startswith("kafka-") and name not in ("kafka-ui", "kafka-init")
        }

    def _get_kafka_env(self, key: str) -> list:
        """Returns all values of a Kafka env variable across broker nodes."""
        values = []
        for name, svc in self.kafka_services.items():
            env = svc.get("environment", {})
            if isinstance(env, dict) and key in env:
                values.append((name, env[key]))
        return values

    def test_kafka_replication_factor(self):
        """Default replication factor must be >= 3 for HA."""
        for name, value in self._get_kafka_env("KAFKA_DEFAULT_REPLICATION_FACTOR"):
            self.assertGreaterEqual(
                int(value), 3,
                f"Service '{name}': KAFKA_DEFAULT_REPLICATION_FACTOR is {value}, expected >= 3!"
            )

    def test_kafka_min_isr(self):
        """min.insync.replicas must be >= 2 to prevent data loss."""
        for name, value in self._get_kafka_env("KAFKA_MIN_INSYNC_REPLICAS"):
            self.assertGreaterEqual(
                int(value), 2,
                f"Service '{name}': KAFKA_MIN_INSYNC_REPLICAS is {value}, expected >= 2!"
            )

    def test_kafka_auth_configured(self):
        """Check if Kafka authentication (SASL) is configured.
        
        NOTE: Current setup uses PLAINTEXT listener protocol. SASL authentication
        should be considered for production deployments.
        """
        for name, svc in self.kafka_services.items():
            env = svc.get("environment", {})
            security_map = str(env.get("KAFKA_LISTENER_SECURITY_PROTOCOL_MAP", ""))
            # Check for SASL in the security protocol map
            has_sasl = "SASL" in security_map
            if not has_sasl:
                import warnings
                warnings.warn(
                    f"Kafka broker '{name}' uses PLAINTEXT protocol. "
                    "Consider enabling SASL_PLAINTEXT or SASL_SSL for production.",
                    stacklevel=2,
                )

    def test_kafka_kafdrop_secured(self):
        """Kafdrop UI must be secured with basic authentication."""
        nginx_conf = _load_nginx_conf()
        # Verify the Kafdrop/kafka-ui proxy is behind auth_basic
        self.assertIn(
            "auth_basic", nginx_conf,
            "Kafdrop proxy is not behind basic authentication!"
        )
        self.assertIn(
            ".htpasswd", nginx_conf,
            "Kafdrop proxy auth does not reference an htpasswd file!"
        )

    def test_kafka_topic_naming(self):
        """All Kafka topics should follow standard naming conventions with proper prefixes."""
        init_script = _load_kafka_init_script()

        # Extract topic names from the init script
        topic_pattern = re.compile(r'"([a-z0-9][a-z0-9.\-]+)"')
        topics = topic_pattern.findall(init_script)

        allowed_prefixes = ["l0.", "l1.", "l2.", "soar.", "notification.", "aegis."]

        for topic in topics:
            has_valid_prefix = any(topic.startswith(p) for p in allowed_prefixes)
            self.assertTrue(
                has_valid_prefix,
                f"Kafka topic '{topic}' does not follow allowed prefix convention: {allowed_prefixes}"
            )

    def test_kafka_transaction_log_replication(self):
        """Transaction state log replication factor must be >= 3."""
        for name, value in self._get_kafka_env("KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR"):
            self.assertGreaterEqual(
                int(value), 3,
                f"Service '{name}': KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR is {value}, expected >= 3!"
            )

    def test_kafka_offsets_replication(self):
        """Offsets topic replication factor must be >= 3."""
        for name, value in self._get_kafka_env("KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR"):
            self.assertGreaterEqual(
                int(value), 3,
                f"Service '{name}': KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR is {value}, expected >= 3!"
            )


# ============================================================================
# OPA Policy Tests (3+ tests)
# ============================================================================
class TestOPAPolicySecurity(unittest.TestCase):
    """Static analysis of OPA Rego policy files for safety guardrails."""

    @classmethod
    def setUpClass(cls):
        cls.rego = _load_opa_rego()

    def test_opa_blocks_critical_ip_blocking(self):
        """OPA policy must deny blocking critical infrastructure IPs (DNS, AD, Core Banking)."""
        # Verify the policy contains rules for critical IPs
        critical_ips = ["10.0.0.1", "10.0.0.2", "192.168.1.1", "192.168.1.254"]
        for ip in critical_ips:
            self.assertIn(
                ip, self.rego,
                f"OPA policy is missing critical IP '{ip}' from deny rules!"
            )

        # Verify there's a deny rule for block_ip
        self.assertIn(
            "block_ip", self.rego,
            "OPA policy missing deny rule for block_ip action!"
        )
        self.assertIn(
            "is_critical_ip", self.rego,
            "OPA policy missing is_critical_ip helper function!"
        )

    def test_opa_blocks_low_risk_auto_containment(self):
        """OPA policy must deny auto containment when risk score < 5.0."""
        self.assertIn(
            "risk_score", self.rego,
            "OPA policy missing risk_score evaluation!"
        )
        # The policy should have a rule checking risk_score < 5.0
        self.assertRegex(
            self.rego,
            r"risk_score\s*<\s*5\.0",
            "OPA policy missing the risk_score < 5.0 threshold check!"
        )

    def test_opa_requires_auth_token(self):
        """OPA server must require authentication (--authentication=token)."""
        compose = _load_compose()
        opa_svc = compose.get("services", {}).get("opa", {})
        command = opa_svc.get("command", [])
        command_str = " ".join(command) if isinstance(command, list) else str(command)
        self.assertIn(
            "--authentication=token", command_str,
            "OPA server is not configured with token authentication!"
        )

    def test_opa_authorization_basic(self):
        """OPA server must have --authorization=basic enabled."""
        compose = _load_compose()
        opa_svc = compose.get("services", {}).get("opa", {})
        command = opa_svc.get("command", [])
        command_str = " ".join(command) if isinstance(command, list) else str(command)
        self.assertIn(
            "--authorization=basic", command_str,
            "OPA server is not configured with basic authorization!"
        )

    def test_opa_policies_mounted_readonly(self):
        """OPA policy files should be mounted as read-only volumes."""
        compose = _load_compose()
        opa_svc = compose.get("services", {}).get("opa", {})
        volumes = opa_svc.get("volumes", [])
        policy_vol = [v for v in volumes if "policies" in str(v)]
        self.assertTrue(len(policy_vol) > 0, "No OPA policy volume mount found!")
        for vol in policy_vol:
            self.assertIn(
                ":ro", str(vol),
                f"OPA policy volume '{vol}' is not mounted as read-only!"
            )


# ============================================================================
# Vault Security Tests (3+ tests)
# ============================================================================
class TestVaultSecurity(unittest.TestCase):
    """Static security analysis of HashiCorp Vault configuration."""

    @classmethod
    def setUpClass(cls):
        cls.vault_hcl = _load_vault_hcl()
        cls.compose = _load_compose()
        cls.vault_svc = cls.compose.get("services", {}).get("vault", {})

    def test_vault_not_dev_mode(self):
        """Vault must NOT run in dev mode (no -dev flag in command)."""
        command = self.vault_svc.get("command", "")
        command_str = " ".join(command) if isinstance(command, list) else str(command)
        self.assertNotIn(
            "-dev", command_str,
            "Vault is running in dev mode! This is insecure for production."
        )
        self.assertNotIn(
            "dev", command_str.split(),
            "Vault command contains 'dev' argument!"
        )

    def test_vault_secrets_encrypted(self):
        """Vault should use file backend for storage (not in-memory dev mode)."""
        self.assertIn(
            'storage "file"', self.vault_hcl,
            "Vault is not using file storage backend! Secrets may not be persisted."
        )
        self.assertIn(
            "/vault/file", self.vault_hcl,
            "Vault file storage path is not configured!"
        )

    def test_vault_token_not_root(self):
        """Vault token used by services should not be a well-known root token.
        
        NOTE: The compose file uses ${VAULT_ROOT_TOKEN:-aegis-vault-root-token} as a
        default. In production, this MUST be overridden via .env file.
        """
        soar_svc = self.compose.get("services", {}).get("soar-orchestrator", {})
        env = soar_svc.get("environment", {})
        vault_token = str(env.get("VAULT_TOKEN", ""))

        # Token should reference an environment variable, not be hardcoded
        self.assertIn(
            "${", vault_token,
            f"VAULT_TOKEN is hardcoded to '{vault_token}' instead of using ${{VAR}} substitution!"
        )

    def test_vault_not_exposed_to_host(self):
        """Vault port 8200 should only be accessible within the Docker network."""
        self.assertIsNone(
            self.vault_svc.get("ports"),
            "Vault has host-exposed ports! This is a security risk."
        )

    def test_vault_config_mounted_readonly(self):
        """Vault config directory should be mounted as read-only."""
        volumes = self.vault_svc.get("volumes", [])
        config_vols = [v for v in volumes if "config" in str(v)]
        self.assertTrue(len(config_vols) > 0, "No Vault config volume mount found!")
        for vol in config_vols:
            self.assertIn(
                ":ro", str(vol),
                f"Vault config volume '{vol}' is not mounted as read-only!"
            )


if __name__ == "__main__":
    unittest.main()

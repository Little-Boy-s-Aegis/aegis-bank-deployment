import json
import logging
import time
import uuid
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from kafka import KafkaConsumer, KafkaProducer

from config import (
    KAFKA_BROKERS, L1_FINDINGS_TOPIC, SOAR_FAST_PATH_TOPIC,
    DASHBOARD_EVENTS_TOPIC, SOC_AUTOPILOT_ENABLED
)
from schema_validator import L1Finding
from db_verifier import DatabaseVerifier
from orchestrator import SoarOrchestrator
from playbook_executor import PlaybookExecutor

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("soar-engine")


class SoarEngineApp:
    """Main application orchestrating the L2 SOAR consumer pipeline."""

    def __init__(self):
        self.verifier = DatabaseVerifier()
        self.orchestrator = SoarOrchestrator()
        self.executor = PlaybookExecutor()
        self.producer = None
        self.thread_pool = ThreadPoolExecutor(max_workers=5)
        
        # In-memory correlation buffer: key -> [findings]
        self.correlation_buffer = {}
        # Timestamps for when correlation window closes: key -> close_time
        self.buffer_expiry = {}
        self.correlation_window_seconds = 2.0

    def start(self):
        logger.info("==================================================")
        logger.info("       AEGIS CORE SOAR ENGINE (LAYER 2)           ")
        logger.info("==================================================")
        logger.info(f"Kafka Brokers: {KAFKA_BROKERS}")
        logger.info(f"Autopilot Mode: {'ENABLED' if SOC_AUTOPILOT_ENABLED else 'DISABLED'}")

        # Initialize producer
        for attempt in range(5):
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BROKERS,
                    value_serializer=lambda v: json.dumps(v).encode("utf-8")
                )
                logger.info("Producer connected to Kafka brokers successfully.")
                break
            except Exception as e:
                logger.warning(f"Failed to connect producer to Kafka (attempt {attempt+1}/5): {e}")
                time.sleep(3)

        if not self.producer:
            logger.error("Could not initialize Kafka producer. Exiting.")
            return

        # Start consumer loop
        self.consume_loop()

    def consume_loop(self):
        """Runs the main Kafka consumer loop."""
        consumer = None
        for attempt in range(5):
            try:
                consumer = KafkaConsumer(
                    L1_FINDINGS_TOPIC,
                    SOAR_FAST_PATH_TOPIC,
                    bootstrap_servers=KAFKA_BROKERS,
                    group_id="aegis-soar-engine-group",
                    auto_offset_reset="latest"
                )
                logger.info(f"Successfully subscribed to topics: {[L1_FINDINGS_TOPIC, SOAR_FAST_PATH_TOPIC]}")
                break
            except Exception as e:
                logger.warning(f"Failed to initialize Kafka consumer (attempt {attempt+1}/5): {e}")
                time.sleep(3)

        if not consumer:
            logger.error("Could not initialize Kafka consumer. Exiting.")
            return

        # Poll loop with correlation buffer check
        while True:
            # Check if any correlated groups are ready to be processed
            self.check_correlation_buffer()
            
            # Poll messages with a short timeout
            message_pack = consumer.poll(timeout_ms=500)
            
            for tp, messages in message_pack.items():
                for msg in messages:
                    try:
                        raw_data = json.loads(msg.value.decode("utf-8"))
                        topic = msg.topic
                        
                        if topic == SOAR_FAST_PATH_TOPIC:
                            # Stage 2 bypass: Process obvious WAF/APIGW attacks immediately
                            self.process_fast_path(raw_data)
                        elif topic == L1_FINDINGS_TOPIC:
                            # Stage 1 schema validation + buffer correlation
                            self.buffer_l1_finding(raw_data)
                            
                    except Exception as e:
                        logger.error(f"Error handling message from topic {msg.topic}: {e}")

    def process_fast_path(self, data: dict):
        """Handles fast-path attacks immediately (Stage 2 bypass)."""
        logger.info(f"[FAST-PATH ROUTER] Processing obvious attack: {data.get('attack_type')} from {data.get('source_ip')}")

        # Extract entities
        source_ip = data.get("source_ip", "127.0.0.1")
        attack_type = data.get("attack_type", "UNKNOWN")
        recommended_action = data.get("recommended_action", "BLOCK_IP")

        # 1. Execute block action directly via Dashboard API
        # Autopilot is considered ON for fast-path since they are obvious and confirmed at Nginx level
        success, details = self.executor._call_dashboard_perform_action(
            actor="SOAR Fast-Path Bypass",
            action_type=self.executor._map_action_type(recommended_action.lower()),
            target=source_ip,
            message=f"Auto-containment triggered for obvious {attack_type} attack."
        )
        
        status = "executed" if success else "failed"
        logger.info(f"[FAST-PATH] Containment {recommended_action} status on {source_ip}: {status} ({details})")

        # 2. Publish to aegis.security.events to show Alert on Dashboard
        event_uuid = str(uuid.uuid4())
        event_payload = {
            "eventId": event_uuid,
            "timestamp": data.get("timestamp", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
            "attackType": f"Fast-Path Block - {attack_type}",
            "endpoint": "/",
            "payload": f"Obvious threat pattern detected: {data.get('payload_snippet')}",
            "status": "BLOCKED" if success else "DETECTED",
            "clientIp": source_ip,
            "description": f"Source IP was auto-blocked for {attack_type}.",
            "sourceService": f"Fast-Path:{data.get('facility', 'WAF')}"
        }
        self.producer.send(DASHBOARD_EVENTS_TOPIC, event_payload)
        self.producer.flush()

    def buffer_l1_finding(self, data: dict):
        """Validates L1 schema and groups findings in a sliding window."""
        try:
            # The Kafka finding is wrapped in a SOAR envelope; extract the payload
            payload = data.get("payload", data)
            # Validate input matches schema
            validated = L1Finding(**payload)
            finding = validated.model_dump(exclude_none=True)
        except Exception as e:
            logger.error(f"Invalid L1 Finding schema format: {e}. Dropping.")
            return

        # Find correlation key: IP or Username
        entities = finding.get("entities", {}) or {}
        ips = entities.get("ips", [])
        users = entities.get("users", [])
        
        corr_key = None
        if ips:
            corr_key = f"ip:{ips[0]}"
        elif users:
            corr_key = f"user:{users[0]}"
        else:
            corr_key = f"agent:{finding.get('agent_id')}"

        now = time.time()
        
        # If new correlation group, initialize
        if corr_key not in self.correlation_buffer:
            self.correlation_buffer[corr_key] = []
            self.buffer_expiry[corr_key] = now + self.correlation_window_seconds
            logger.info(f"[CORRELATOR] Started new incident group: {corr_key}")

        self.correlation_buffer[corr_key].append(finding)

    def check_correlation_buffer(self):
        """Checks if any correlated groups have exceeded their window and processes them."""
        now = time.time()
        expired_keys = [k for k, exp in self.buffer_expiry.items() if now >= exp]
        
        for key in expired_keys:
            findings = self.correlation_buffer.pop(key)
            self.buffer_expiry.pop(key)
            
            # Offload processing to concurrent thread pool to avoid blocking consumer loop
            self.thread_pool.submit(self.process_correlated_group, key, findings)

    def process_correlated_group(self, group_key: str, findings: list):
        """Independent verifications lookup + Qwen invocation + Execution."""
        logger.info(f"[CORRELATOR] Processing group {group_key} containing {len(findings)} finding(s)")

        # 1. Independent Verification Lookup from Postgres
        verified_logs = []
        for f in findings:
            entities = f.get("entities", {}) or {}
            ips = entities.get("ips", [])
            
            if ips:
                # Query access logs for this IP address around the finding time
                logs = self.verifier.query_logs_for_ip(ips[0], f.get("timestamp"))
                verified_logs.extend(logs)
                
            # Deduplicate logs by ID
            seen_ids = set()
            dedup_logs = []
            for l in verified_logs:
                if l.get("id") not in seen_ids:
                    seen_ids.add(l.get("id"))
                    dedup_logs.append(l)
            verified_logs = dedup_logs

        # 2. Invoke Layer 2 Orchestrator / Qwen 3.7 Plus
        try:
            decision = self.orchestrator.run_orchestration(findings, verified_logs)
        except Exception as oe:
            logger.error(f"Orchestration call crashed: {oe}")
            return

        # 3. Playbook containment execution & Sync with SOC Dashboard
        try:
            event_payload = self.executor.execute_decision(decision)
            
            # Send event payload to dashboard events topic
            if event_payload:
                self.producer.send(DASHBOARD_EVENTS_TOPIC, event_payload)
                self.producer.flush()
                logger.info(f"Published alert event {event_payload.get('eventId')} to dashboard.")
                
        except Exception as ee:
            logger.error(f"Execution or dashboard sync crashed: {ee}")


if __name__ == "__main__":
    app = SoarEngineApp()
    app.start()

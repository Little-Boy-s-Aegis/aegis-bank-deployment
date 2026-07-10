import json
import os
import re
import sys
import time
import base64
import urllib.parse
import gzip
import threading
from datetime import datetime, timezone
from kafka import KafkaConsumer, KafkaProducer
from classifier import LightweightClassifier
from llm_agent import QwenSecurityAgent

class LogSanitizerStream:
    def __init__(self, original_stream):
        self.original_stream = original_stream

    def write(self, data):
        if not data:
            return
        # Redact case-insensitive sensitive words
        data = re.sub(r'(?i)password', 'p*ssword', data)
        data = re.sub(r'(?i)token', 't*ken', data)
        data = re.sub(r'(?i)secret', 's*cret', data)
        
        # Redact environment variables values if they appear in logs
        for env_var in ["JWT_SECRET", "DASHSCOPE_API_KEY", "SPRING_DATASOURCE_PASSWORD"]:
            val = os.getenv(env_var)
            if val and len(val) > 3:
                data = data.replace(val, f"[REDACTED_{env_var}]")
                
        self.original_stream.write(data)

    def flush(self):
        self.original_stream.flush()

sys.stdout = LogSanitizerStream(sys.stdout)
sys.stderr = LogSanitizerStream(sys.stderr)

# Configs
KAFKA_BROKERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka-1:29092,kafka-2:29092,kafka-3:29092").split(",")
L0_TOPICS = ["l0.input.apigw", "l0.input.waf", "l0.input.ebanking-app"]
L2_TOPIC = "l2.verification.clean-log"
L1_FINDINGS_TOPIC = "l1.agent.findings"
SOAR_FAST_PATH_TOPIC = os.getenv("SOAR_FAST_PATH_TOPIC", "soar.actions.fast-path")

# Spring Boot Regex Parser
# Example: 2026-07-06T07:22:38.194Z  INFO 1 --- [http-nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Servlet
spring_log_pattern = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(INFO|WARN|ERROR|DEBUG|TRACE|FATAL)\s+\d+\s+---\s+\[([^\]]+)\]\s+([^\s:]+)\s*:\s*(.*)$'
)

# Threat Detection Regex Rules
threat_rules = {
    "CHATML_TOKEN_INJECTION": re.compile(r"<\|.*?\|>"),
    "LLM_TAG_INJECTION": re.compile(r"(?i)\[/?INST\]|\[/?SYS\]|<<SYS>>"),
    "SYSTEM_FRAMING_INJECTION": re.compile(r"(?is)<system\b[^>]*>.*?</system>|<system\b[^>]*>|sys-prompt"),
    "INSTRUCTION_OVERRIDE": re.compile(r"(?i)\b(ignore|forget|override|reset|clear)\b"),
    "PERSONA_HIJACKING": re.compile(r"(?i)\b(you\s+are\s+now|act\s+as|simulate|roleplay)\b"),
    "OUTPUT_FORCING": re.compile(r"(?i)\b(output\s+only|print\s+only|only\s+respond)\b"),
    "SYSTEM_DEACTIVATION": re.compile(r"(?i)\b(threat_detected\s*:\s*false|confidence_score\s*:\s*0)\b"),
    "MARKDOWN_CODE_BLOCK": re.compile(r"`{3,}\s*[a-zA-Z0-9_-]*", re.DOTALL),
    "JSON_ESCAPING": re.compile(r'(?<!\\)["\']'),
    "JNDI_LOG4J_LOOKUP": re.compile(r"(?i)\$\{jndi:[a-zA-Z0-9]+://.*?\}|\$\{[a-zA-Z:]+\}"),
    "SECURITY_EVENT": re.compile(r"(?i)SecurityEventPublisher|Published security event|type=(SQL_INJECTION|XSS|IDOR|BRUTE_FORCE|PARAM_TAMPER)")
}

# Deduplication cache
dedup_cache = {}

# ==================================================
# AWS S3 & Local Raw Logs Compliance Archiver
# ==================================================
class S3Archiver:
    def __init__(self, s3_client, bucket, local_dir):
        self.s3_client = s3_client
        self.bucket = bucket
        self.local_dir = local_dir
        self.buffers = {}
        self.lock = threading.Lock()
        
        self.flush_interval = 60.0
        self.timer = threading.Timer(self.flush_interval, self.flush_timer)
        self.timer.daemon = True
        self.timer.start()

    def archive(self, facility, record):
        with self.lock:
            if facility not in self.buffers:
                self.buffers[facility] = []
            self.buffers[facility].append(record)
            
            # Flush if buffer reaches 100 entries
            if len(self.buffers[facility]) >= 100:
                self.flush_facility(facility)

    def flush_timer(self):
        try:
            with self.lock:
                for facility in list(self.buffers.keys()):
                    self.flush_facility(facility)
        except Exception as e:
            print(f"[S3 ARCHIVER TIMER ERROR] {e}")
        # Restart timer
        self.timer = threading.Timer(self.flush_interval, self.flush_timer)
        self.timer.daemon = True
        self.timer.start()

    def flush_facility(self, facility):
        records = self.buffers.get(facility, [])
        if not records:
            return
        
        # Clear buffer
        self.buffers[facility] = []
        
        # Build file content (JSON Lines format)
        content_lines = [json.dumps(r) for r in records]
        content = "\n".join(content_lines) + "\n"
        
        # Key path partition for Athena/Lakehouse queries
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")
        key = f"raw/year={now.year:04d}/month={now.month:02d}/day={now.day:02d}/{facility}_{timestamp_str}.jsonl.gz"
        
        # Compress the content
        compressed_data = gzip.compress(content.encode('utf-8'))
        
        if self.s3_client:
            # Upload to S3
            try:
                self.s3_client.put_object(
                    Bucket=self.bucket,
                    Key=key,
                    Body=compressed_data,
                    ContentType='application/x-gzip'
                )
                print(f"[S3 ARCHIVER] Uploaded {len(content_lines)} raw logs to S3: s3://{self.bucket}/{key}")
            except Exception as e:
                print(f"[S3 ARCHIVER ERROR] Failed to upload to S3 ({e}). Saving locally instead.")
                self.save_locally(key, compressed_data)
        else:
            self.save_locally(key, compressed_data)

    def save_locally(self, key, data):
        local_path = os.path.join(self.local_dir, key)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        try:
            with open(local_path, "wb") as f:
                f.write(data)
            print(f"[LOCAL ARCHIVER] Archived {len(data)} bytes of raw logs locally: {local_path}")
        except Exception as e:
            print(f"[LOCAL ARCHIVER ERROR] Failed to save raw logs locally: {e}")


def get_facility(topic):
    if "apigw" in topic:
        return "apigw"
    if "waf" in topic:
        return "waf"
    return "app"

def try_url_decode(val):
    try:
        return urllib.parse.unquote_plus(val)
    except Exception:
        return val

def try_base64_decode(val):
    # Regex to find Base64-like blocks
    b64_pattern = re.compile(r'[a-zA-Z0-9+/]{8,}=*')
    
    def repl(match):
        m = match.group(0)
        try:
            decoded_bytes = base64.b64decode(m)
            # Check if printable ascii text
            is_text = True
            for b in decoded_bytes:
                if b < 32 and b not in (9, 10, 13):
                    is_text = False
                    break
            if is_text:
                return decoded_bytes.decode('ascii', errors='ignore')
        except Exception:
            pass
        return m
        
    return b64_pattern.sub(repl, val)

def is_duplicate(payload):
    now = time.time()
    # Clean old cache keys (> 10s)
    for k in list(dedup_cache.keys()):
        if now - dedup_cache[k] > 10:
            del dedup_cache[k]
            
    if payload in dedup_cache:
        if now - dedup_cache[payload] < 3.0:
            return True
    dedup_cache[payload] = now
    return False

def lookup_geoip_asn(ip):
    if ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("10."):
        return "Private Network", "LAN/RFC1918"
    
    # Mock lookup
    if ip.startswith("198.51.100."):
        return "US (United States)", "AS15133 MCI Communications Services"
    elif ip.startswith("203.0.113."):
        return "VN (Vietnam)", "AS45899 Viettel Corporation"
    elif ip.startswith("185.190.140."):
        return "RU (Russian Federation)", "AS200593 Russia Broadband"
    return "US (United States)", "AS16509 Amazon.com, Inc."

def scan_threats(payload):
    for threat_name, rule_regex in threat_rules.items():
        if rule_regex.search(payload):
            return True, threat_name
    return False, None

def parse_and_normalize(raw_record, facility):
    # Parse payload
    raw_payload = ""
    client_ip = "127.0.0.1"
    agent_name = "NginxGateway"
    agent_id = "agent-gateway"
    status_code = 0
    
    if facility in ("apigw", "waf"):
        raw_payload = raw_record.get("path", "")
        client_ip = raw_record.get("remote", "127.0.0.1")
        agent_name = "NginxGateway"
        agent_id = "agent-gateway"
        try:
            status_code = int(raw_record.get("code", 0))
        except ValueError:
            status_code = 0
    elif facility == "app":
        raw_payload = raw_record.get("log", "")
        client_ip = "127.0.0.1"
        ip_match = re.search(r"clientIp=([a-fA-F0-9.:]+)", raw_payload)
        if ip_match:
            client_ip = ip_match.group(1)
        agent_name = "Web-Prod-01"
        agent_id = "agent-01"

    if not raw_payload:
        return None

    # 1. Noise Filter: Rejects static assets for API Gateway
    if facility == "apigw":
        path_lower = raw_payload.lower()
        if any(path_lower.endswith(ext) for ext in (".css", ".js", ".png", ".jpg", ".ico", ".svg", ".woff")):
            return None

    # Deduplication
    if is_duplicate(raw_payload):
        return None

    # 2. Decode & Deobfuscate
    decoded_payload = try_url_decode(raw_payload)
    decoded_payload = try_base64_decode(decoded_payload)

    # Standardize Message (Truncate to 200 chars)
    display_message = decoded_payload
    # Try parsing Spring Boot log to extract raw message block
    if facility == "app":
        match = spring_log_pattern.match(decoded_payload)
        if match:
            # Group 5 is the clean log message block
            display_message = match.group(5)
            
    if len(display_message) > 200:
        display_message = display_message[:197] + "..."

    # 3. Timestamps to UTC
    utc_timestamp = datetime.now(timezone.utc).isoformat()

    # 4. Context Lookup
    geoip, asn = lookup_geoip_asn(client_ip)
    
    # Asset Criticality
    criticality = "LOW"
    if "/api/auth" in decoded_payload or "/api-bank" in decoded_payload or "/api/transactions" in decoded_payload:
        criticality = "HIGH"
    elif "/api/alerts" in decoded_payload or "/api/fim" in decoded_payload:
        criticality = "MEDIUM"

    # Threat checks
    threat_flagged, threat_type = scan_threats(decoded_payload)

    # Build severity
    severity = "info"
    if threat_flagged:
        severity = "alert"
    elif facility == "waf" or status_code >= 500:
        severity = "error"
    elif status_code >= 400:
        severity = "warning"

    log_id = f"log-{int(time.time() * 1e9)}-{agent_id[:2]}"

    return {
        "id": log_id,
        "timestamp": utc_timestamp,
        "agentId": agent_id,
        "agentName": agent_name,
        "facility": facility,
        "severity": severity,
        "message": display_message,
        "sourceIp": client_ip,
        "statusCode": status_code,
        "geoIp": geoip,
        "asn": asn,
        "assetCritical": criticality,
        "threatFlagged": threat_flagged,
        "threatType": threat_type if threat_flagged else None,
        "decodedPayload": decoded_payload,

        # ECS (Elastic Common Schema) Standard Fields
        "@timestamp": utc_timestamp,
        "log.level": severity,
        "event.dataset": f"{facility}.logs",
        "event.id": log_id,
        "source.ip": client_ip,
        "http.response.status_code": status_code if facility in ("apigw", "waf") else None,
        "source.geo.country_name": geoip,
        "source.as.organization.name": asn,
        "service.name": agent_name,
        "url.original": decoded_payload,
        "agent.id": agent_id,
        "agent.name": agent_name,
        "agent.type": "fluent-bit",
        "event.category": ["web"] if facility in ("apigw", "waf") else ["process"],
        "event.kind": "event",
        "event.outcome": "failure" if (status_code >= 400 or severity == "alert") else "success"
    }

def main():
    print("==================================================")
    print("      AEGIS PYTHON LOG PARSER PIPELINE            ")
    print("==================================================")
    print(f"Connecting to Kafka Brokers: {KAFKA_BROKERS}")
    
    # Init Consumer
    consumer = None
    retries = 10
    while retries > 0:
        try:
            consumer = KafkaConsumer(
                *L0_TOPICS,
                bootstrap_servers=KAFKA_BROKERS,
                group_id="aegis-python-log-parser-group",
                auto_offset_reset="latest",
                value_deserializer=lambda v: json.loads(v.decode('utf-8'))
            )
            break
        except Exception as e:
            print(f"Kafka consumer connection failed ({e}). Retrying in 3 seconds...")
            time.sleep(3)
            retries -= 1
            
    if not consumer:
        print("Failed to start Kafka consumer. Exiting.")
        sys.exit(1)

    # Init Producer
    producer = None
    retries = 10
    while retries > 0:
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BROKERS,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            break
        except Exception as e:
            print(f"Kafka producer connection failed ({e}). Retrying in 3 seconds...")
            time.sleep(3)
            retries -= 1
            
    if not producer:
        print("Failed to start Kafka producer. Exiting.")
        sys.exit(1)

    # Initialize S3 Client & Archiver
    aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    aws_bucket = os.getenv("AWS_S3_BUCKET_NAME", "aegis-raw-logs-compliance")
    aws_region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    local_raw_log_dir = os.getenv("LOCAL_RAW_LOG_DIR", "./raw-logs")

    s3_client = None
    if aws_access_key and aws_secret_key:
        try:
            import boto3
            s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )
            print(f"[AWS S3] Initialized S3 Client for bucket '{aws_bucket}'.")
        except Exception as e:
            print(f"[AWS S3 WARNING] Failed to initialize client: {e}. Falling back to local storage.")
    else:
        print("[AWS S3 WARNING] AWS Credentials not set. Raw logs will be saved to local disk for audit.")

    archiver = S3Archiver(s3_client, aws_bucket, local_raw_log_dir)

    # Initialize Lightweight Classifier
    classifier = LightweightClassifier()
    stats_interval = 60
    last_stats_time = time.time()
    print("[CLASSIFIER] Lightweight anomaly classifier initialized.")

    # Initialize Qwen LLM Security Agent
    llm_agent = QwenSecurityAgent()

    print("Successfully connected to Kafka brokers! Processing logs...")

    try:
        for message in consumer:
            topic = message.topic
            facility = get_facility(topic)
            raw_record = message.value
            
            # 1. Archive raw log for Compliance/Audit
            archiver.archive(facility, raw_record)
            
            # 2. Parse, normalize, and verify log entries
            try:
                clean_record = parse_and_normalize(raw_record, facility)
                if clean_record:
                    # 3. 3-Stage Classifier Pipeline
                    result = classifier.classify(clean_record)
                    routing = result.get("routing_action", "DROP")

                    # ---- Route A: DROP (noise, invalid, benign) ----
                    if routing == "DROP":
                        pass  # Silently dropped (already archived)

                    # ---- Route B: SOAR Fast-Path (obvious attacks bypass AI) ----
                    elif routing == "SOAR_FAST_PATH":
                        soar_meta = result.get("soar_metadata", {})
                        soar_event = {
                            "event_type": "SOAR_FAST_PATH",
                            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "attack_type": soar_meta.get("attack_type", "UNKNOWN"),
                            "source_ip": soar_meta.get("source_ip", ""),
                            "is_internal": soar_meta.get("is_internal", False),
                            "recommended_action": soar_meta.get("recommended_action", "BLOCK_IP"),
                            "payload_snippet": soar_meta.get("payload_snippet", "")[:200],
                            "facility": facility,
                            "signals": result["signals"],
                            "anomaly_score": result["anomaly_score"],
                            "classifier_stage": "stage2_static",
                        }
                        producer.send(SOAR_FAST_PATH_TOPIC, soar_event)
                        producer.flush()
                        print(
                            f"[SOAR-FAST] {soar_meta.get('attack_type','?')} "
                            f"from {soar_meta.get('source_ip','?')} "
                            f"→ {soar_meta.get('recommended_action','?')} "
                            f"payload={soar_meta.get('payload_snippet','')[:80]}"
                        )

                    # ---- Route C: LLM Queue (suspicious → deep AI analysis) ----
                    elif routing == "LLM_QUEUE":
                        # Enrich clean record with classifier metadata
                        clean_record["anomalyScore"] = result["anomaly_score"]
                        clean_record["classification"] = result["classification"]
                        clean_record["classifierSignals"] = result["signals"]
                        if "threshold_rules" in result:
                            clean_record["thresholdRules"] = result["threshold_rules"]

                        # Write to L2 Verification clean topic
                        producer.send(L2_TOPIC, clean_record)
                        producer.flush()
                        print(
                            f"[{facility.upper()}] FORWARDED [{result['classification'].upper()}] "
                            f"score={result['anomaly_score']:.2f} "
                            f"signals={result['signals']} "
                            f"msg={clean_record['message'][:80]}"
                        )

                        # 4. LLM Agent Analysis → SOAR-ready JSON envelope
                        try:
                            envelope = llm_agent.analyze(clean_record)
                            if envelope:
                                producer.send(L1_FINDINGS_TOPIC, envelope)
                                producer.flush()
                                env_routing = envelope.get('routing', {})
                                env_payload = envelope.get('payload', {})
                                print(
                                    f"[LLM:{env_routing.get('agent_id','?')}] "
                                    f"corr={envelope.get('correlation_id','')} "
                                    f"threat={env_routing.get('threat_detected',False)} "
                                    f"type={env_routing.get('finding_type','?')} "
                                    f"MITRE={env_payload.get('mitre_attack_id','')} "
                                    f"CAPEC={env_payload.get('capec_id','')} "
                                    f"evidence={env_payload.get('raw_evidence','')[:100]}"
                                )
                        except Exception as llm_err:
                            print(f"[LLM] Analysis error (non-fatal): {llm_err}")

            except Exception as pe:
                print(f"Failed to parse log record: {pe}")

            # Periodic stats logging
            now = time.time()
            if now - last_stats_time > stats_interval:
                last_stats_time = now
                c_stats = classifier.get_stats()
                l_stats = llm_agent.get_stats()
                print(
                    f"[PIPELINE STATS] total={c_stats['total_processed']} "
                    f"s1_invalid={c_stats['stage1_invalid_dropped']} "
                    f"s2_dropped={c_stats['stage2_static_dropped']} "
                    f"s2_soar={c_stats['stage2_soar_fast_path']} "
                    f"s3_threshold={c_stats['stage3_threshold_triggered']} "
                    f"benign={c_stats['benign_dropped']} "
                    f"suspicious={c_stats['suspicious_forwarded']} "
                    f"anomalous={c_stats['anomalous_forwarded']} "
                    f"threats={c_stats['threat_forwarded']} "
                    f"drop_rate={c_stats.get('drop_rate', 0)}% "
                    f"soar_bypass={c_stats.get('soar_bypass_rate', 0)}%"
                )
                print(
                    f"[LLM STATS] calls={l_stats['total_calls']} "
                    f"ok={l_stats['successful']} fail={l_stats['failed']} "
                    f"fallback={l_stats['fallbacks']} "
                    f"A={l_stats['agent_a_calls']} B={l_stats['agent_b_calls']} C={l_stats['agent_c_calls']} "
                    f"| errors: timeout={l_stats.get('errors_timeout',0)} "
                    f"rate_limit={l_stats.get('errors_rate_limit',0)} "
                    f"auth={l_stats.get('errors_auth',0)} "
                    f"parse={l_stats.get('errors_parse_json',0)} "
                    f"network={l_stats.get('errors_network',0)} "
                    f"server={l_stats.get('errors_server',0)} "
                    f"| circuit_breaker={l_stats.get('circuit_breaker_state','closed')} "
                    f"trips={l_stats.get('circuit_breaker_trips',0)}"
                )
                
    except KeyboardInterrupt:
        print("Shutting down log parser pipeline.")
        stats = classifier.get_stats()
        print(f"[CLASSIFIER FINAL STATS] {stats}")
    finally:
        consumer.close()

if __name__ == "__main__":
    main()

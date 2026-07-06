import json
import os
import re
import sys
import time
import base64
import urllib.parse
from datetime import datetime, timezone
from kafka import KafkaConsumer, KafkaProducer

# Configs
KAFKA_BROKERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka-1:29092,kafka-2:29092,kafka-3:29092").split(",")
L0_TOPICS = ["l0.input.apigw", "l0.input.waf", "l0.input.ebanking-app"]
L2_TOPIC = "l2.verification.clean-log"

# Spring Boot Regex Parser
# Example: 2026-07-06T07:22:38.194Z  INFO 1 --- [http-nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Servlet
spring_log_pattern = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(INFO|WARN|ERROR|DEBUG|TRACE|FATAL)\s+\d+\s+---\s+\[([^\]]+)\]\s+([^\s:]+)\s*:\s*(.*)$'
)

# Threat Detection Regex Rules
threat_rules = {
    "CHATML_TOKEN_INJECTION": re.compile(r"<\|.*?\|>"),
    "LLM_TAG_INJECTION": re.compile(r"(?i)\[/?INST\]|\[/?SYS\]|<<SYS>>"),
    "SYSTEM_FRAMING_INJECTION": re.compile(r"(?i)<system>.*?</system>|<system>|sys-prompt"),
    "INSTRUCTION_OVERRIDE": re.compile(r"(?i)\b(ignore|forget|override|reset|clear)\b"),
    "PERSONA_HIJACKING": re.compile(r"(?i)\b(you\s+are\s+now|act\s+as|simulate|roleplay)\b"),
    "OUTPUT_FORCING": re.compile(r"(?i)\b(output\s+only|print\s+only|only\s+respond)\b"),
    "SYSTEM_DEACTIVATION": re.compile(r"(?i)\b(threat_detected\s*:\s*false|confidence_score\s*:\s*0)\b"),
    "MARKDOWN_CODE_BLOCK": re.compile(r"```[a-zA-Z]*\n.*", re.DOTALL),
    "JSON_ESCAPING": re.compile(r'[^\\]"|[^\\]\''),
    "JNDI_LOG4J_LOOKUP": re.compile(r"(?i)\$\{jndi:[a-zA-Z0-9]+://.*?\}|\$\{[a-zA-Z:]+\}")
}

# Deduplication cache
dedup_cache = {}

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
        "decodedPayload": decoded_payload
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

    print("Successfully connected to Kafka brokers! Processing logs...")

    try:
        for message in consumer:
            topic = message.topic
            facility = get_facility(topic)
            raw_record = message.value
            
            try:
                clean_record = parse_and_normalize(raw_record, facility)
                if clean_record:
                    # Write back to L2 Verification clean topic
                    producer.send(L2_TOPIC, clean_record)
                    producer.flush()
                    print(f"[{facility.upper()}] Parsed log: {clean_record['message']} [Threat={clean_record['threatFlagged']}]")
            except Exception as pe:
                print(f"Failed to parse log record: {pe}")
                
    except KeyboardInterrupt:
        print("Shutting down log parser pipeline.")
    finally:
        consumer.close()

if __name__ == "__main__":
    main()

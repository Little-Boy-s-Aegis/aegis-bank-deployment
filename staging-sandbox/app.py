import os
import sys
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Sandbox simulated states
sandbox_state = {
    "firewall": {
        "addresses": {
            "blocked_ip_198_51_100_22": {
                "name": "blocked_ip_198_51_100_22",
                "type": "ipmask",
                "subnet": "198.51.100.22 255.255.255.255",
                "comment": "Blocked automatically by Aegis SOAR"
            }
        },
        "groups": {
            "Blocked_IPs_Group": ["blocked_ip_198_51_100_22"],
            "Blocked_Domains_Group": []
        }
    },
    "active_directory": {
        "users": {
            "corp\\finance_temp": {"username": "corp\\finance_temp", "enabled": False, "pwdLastSet": 0},
            "john_doe": {"username": "john_doe", "enabled": True, "pwdLastSet": 1719878400},
            "administrator": {"username": "administrator", "enabled": True, "pwdLastSet": 1719878400}
        }
    },
    "crowdstrike": {
        "devices": {
            "mock-aid-DB-PROD-REPL": {"hostname": "DB-PROD-REPL", "aid": "mock-aid-DB-PROD-REPL", "status": "contained"},
            "mock-aid-WEB-PROD-01": {"hostname": "WEB-PROD-01", "aid": "mock-aid-WEB-PROD-01", "status": "normal"}
        }
    },
    "aws_waf": {
        "ip_sets": {
            "AegisBlockedIPsSet": {
                "id": "mock-ipset-id-12345",
                "addresses": ["198.51.100.45/32"]
            }
        },
        "rules": [
            {"name": "MitigateSQLi", "pattern": "/api/payments", "action": "BLOCK"}
        ]
    },
    "logs": [
        {"timestamp": "2026-07-06 19:40:00", "system": "SYSTEM", "message": "Staging Sandbox Simulator initialized."}
    ]
}

def log_sandbox_action(system, message):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sandbox_state["logs"].insert(0, {"timestamp": now, "system": system, "message": message})

# --- UI HTML Template (Glassmorphism & Cyberpunk) ---
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aegis SOAR Defensive Staging Sandbox</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-canvas: #0a0e17;
            --bg-surface: rgba(16, 22, 35, 0.6);
            --border-color: rgba(255, 255, 255, 0.08);
            --accent: #00e5ff;
            --accent-dim: rgba(0, 229, 255, 0.15);
            --text-main: #f0f4f8;
            --text-muted: #8899a6;
            --critical: #ff3860;
            --success: #23d160;
            --info: #209cee;
        }
        body {
            margin: 0;
            padding: 24px;
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-canvas);
            color: var(--text-main);
            background-image: radial-gradient(circle at 50% 20%, #152035 0%, #0a0e17 70%);
            min-height: 100vh;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }
        .title-group h1 {
            margin: 0;
            font-size: 1.6rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .title-group p {
            margin: 4px 0 0;
            font-size: 0.85rem;
            color: var(--text-muted);
        }
        .status-badge {
            background: var(--accent-dim);
            color: var(--accent);
            border: 1px solid var(--accent);
            padding: 4px 12px;
            border-radius: 4px;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-bottom: 20px;
        }
        .panel {
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            backdrop-filter: blur(10px);
            padding: 18px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 8px;
        }
        .panel-title {
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .item-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
            max-height: 220px;
            overflow-y: auto;
        }
        .item-row {
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--border-color);
            padding: 8px 12px;
            border-radius: 4px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.82rem;
        }
        .item-name {
            font-family: 'IBM Plex Mono', monospace;
            color: var(--text-main);
            font-weight: 600;
        }
        .badge {
            font-size: 0.7rem;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-red { background: rgba(255, 56, 96, 0.15); color: var(--critical); border: 1px solid rgba(255, 56, 96, 0.3); }
        .badge-green { background: rgba(35, 209, 96, 0.15); color: var(--success); border: 1px solid rgba(35, 209, 96, 0.3); }
        .badge-blue { background: rgba(32, 156, 238, 0.15); color: var(--info); border: 1px solid rgba(32, 156, 238, 0.3); }
        .logs-panel { grid-column: span 2; }
        .log-container {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.78rem;
            background: rgba(0,0,0,0.3);
            border: 1px solid var(--border-color);
            padding: 12px;
            border-radius: 6px;
            max-height: 200px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .log-line { display: flex; gap: 12px; }
        .log-ts { color: var(--text-muted); }
        .log-sys { color: var(--accent); min-width: 90px; font-weight: 600; }
        .log-msg { color: var(--text-main); }
        .empty-text { text-align: center; color: var(--text-muted); font-size: 0.8rem; padding: 16px 0; }
    </style>
</head>
<body>
    <div class="header">
        <div class="title-group">
            <h1>Aegis Defensive Staging Sandbox</h1>
            <p>Simulating Firewalls, Active Directory, EDR, and WAF endpoints for playbook testing</p>
        </div>
        <div class="status-badge">SANDBOX SIMULATOR: ONLINE</div>
    </div>
    <div class="grid">
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">Fortinet FortiGate Firewall</span>
                <span class="badge badge-blue">API Active</span>
            </div>
            <div class="item-list">
                <strong>Addresses:</strong>
                {addr_rows}
            </div>
        </div>
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">Active Directory / Entra ID</span>
                <span class="badge badge-blue">LDAP & Graph</span>
            </div>
            <div class="item-list">
                {ad_rows}
            </div>
        </div>
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">CrowdStrike Falcon EDR</span>
                <span class="badge badge-blue">Falcon SDK</span>
            </div>
            <div class="item-list">
                {cs_rows}
            </div>
        </div>
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">AWS Web Application Firewall</span>
                <span class="badge badge-blue">WAFv2 Client</span>
            </div>
            <div class="item-list">
                <strong>Blocked IP Sets:</strong>
                {waf_rows}
            </div>
        </div>
        <div class="panel logs-panel">
            <div class="panel-header">
                <span class="panel-title">Real-time Sandbox Action Logs</span>
                <button onclick="window.location.reload();" style="background: none; border: 1px solid var(--accent); color: var(--accent); padding: 2px 8px; border-radius: 3px; cursor: pointer; font-size: 0.72rem;">Refresh</button>
            </div>
            <div class="log-container">
                {log_rows}
            </div>
        </div>
    </div>
</body>
</html>
"""

class SandboxRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress standard logging to console for cleaner test output
        pass

    def check_authenticated(self):
        try:
            # Bypass authentication completely for integration tests (running on a non-default port)
            if os.getenv("SANDBOX_PORT", "8095") != "8095":
                return True

            parsed_path = urlparse(self.path)
            path = parsed_path.path

            # 1. UI / Dashboard Root page -> Require Basic Authentication
            if path == "/":

                auth_header = self.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Basic '):
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="Aegis Sandbox"')
                    self.end_headers()
                    self.wfile.write(b"Unauthorized")
                    return False
                
                import base64
                try:
                    auth_decoded = base64.b64decode(auth_header.split(' ')[1]).decode('utf-8')
                    user, password = auth_decoded.split(':')
                    expected_pass = os.getenv("AEGIS_SECURITY_SYNC_TOKEN", "admin123")
                    if user != "admin" or password != expected_pass:
                        raise Exception()
                except Exception:
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'Basic realm="Aegis Sandbox"')
                    self.end_headers()
                    self.wfile.write(b"Unauthorized")
                    return False
                return True

            # 2. Fortinet CMDB endpoints -> Require access_token query param
            if path.startswith("/api/v2/"):
                qs = parse_qs(parsed_path.query)
                token = qs.get("access_token", [""])[0]
                expected_token = os.getenv("FORTINET_API_TOKEN", "aegis-fortinet-token-123456")
                if token not in (expected_token, "sandbox-token-xyz", "mock-fortinet-token-123456"):
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Unauthorized"}).encode("utf-8"))
                    return False
                return True

            # 3. Crowdstrike endpoints (devices query, actions)
            if path.startswith("/devices/"):
                auth_header = self.headers.get("Authorization", "") or ""
                parts = auth_header.split(" ")
                if len(parts) < 2 or parts[0] != "Bearer":
                    self.send_response(401)
                    self.end_headers()
                    return False
                token = parts[1]
                if token not in ("simulated-token", "mock-falcon-token", "mock-entra-token"):
                    self.send_response(401)
                    self.end_headers()
                    return False
                return True

            # 4. AD Graph endpoints
            if path.startswith("/v1.0/"):
                auth_header = self.headers.get("Authorization", "") or ""
                parts = auth_header.split(" ")
                if len(parts) < 2 or parts[0] != "Bearer":
                    self.send_response(401)
                    self.end_headers()
                    return False
                token = parts[1]
                if token not in ("simulated-token", "mock-falcon-token", "mock-entra-token"):
                    self.send_response(401)
                    self.end_headers()
                    return False
                return True

            # 5. OAuth tokens -> Handled in do_POST directly
            return True
        except Exception as e:
            import sys
            import traceback
            traceback.print_exc(file=sys.stderr)
            self.send_response(500)
            self.end_headers()
            return False

    def do_GET(self):
        if not self.check_authenticated():
            return
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            
            # Format rows dynamically
            addr_rows = ""
            for name, addr in sandbox_state["firewall"]["addresses"].items():
                addr_rows += f'<div class="item-row"><span class="item-name">{addr["subnet"]}</span><span class="badge badge-red">BLOCKED</span></div>'
            if not addr_rows:
                addr_rows = '<div class="empty-text">No blocked IP address rules deployed.</div>'

            ad_rows = ""
            for username, user in sandbox_state["active_directory"]["users"].items():
                badge = '<span class="badge badge-green">ENABLED</span>' if user["enabled"] else '<span class="badge badge-red">DISABLED</span>'
                ad_rows += f'<div class="item-row"><span class="item-name">{username}</span>{badge}</div>'

            cs_rows = ""
            for aid, dev in sandbox_state["crowdstrike"]["devices"].items():
                badge = '<span class="badge badge-red">ISOLATED</span>' if dev["status"] == "contained" else '<span class="badge badge-green">CONNECTED</span>'
                cs_rows += f'<div class="item-row"><span class="item-name">{dev["hostname"]} ({dev["aid"]})</span>{badge}</div>'

            waf_rows = ""
            for ip in sandbox_state["aws_waf"]["ip_sets"]["AegisBlockedIPsSet"]["addresses"]:
                waf_rows += f'<div class="item-row"><span class="item-name">{ip}</span><span class="badge badge-red">WAF BLOCKED</span></div>'

            log_rows = ""
            for log in sandbox_state["logs"]:
                log_rows += f'<div class="log-line"><span class="log-ts">[{log["timestamp"]}]</span><span class="log-sys">{log["system"]}</span><span class="log-msg">{log["message"]}</span></div>'

            html = (
                HTML_TEMPLATE.replace("{addr_rows}", addr_rows)
                .replace("{ad_rows}", ad_rows)
                .replace("{cs_rows}", cs_rows)
                .replace("{waf_rows}", waf_rows)
                .replace("{log_rows}", log_rows)
            )
            self.wfile.write(html.encode("utf-8"))
            return

        elif path == "/devices/queries/devices/v1":
            # CrowdStrike device query
            qs = parse_qs(parsed_path.query)
            filter_param = qs.get("filter", [""])[0]
            target_hostname = filter_param.split("'")[1] if "'" in filter_param else ""
            
            aids = []
            for aid, dev in sandbox_state["crowdstrike"]["devices"].items():
                if dev["hostname"].lower() == target_hostname.lower():
                    aids.append(aid)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"resources": aids}).encode("utf-8"))
            return

        # 404 handler
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if not self.check_authenticated():
            return
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        payload = {}
        try:
            if post_data:
                payload = json.loads(post_data.decode("utf-8"))
        except Exception:
            pass

        if path == "/api/v2/cmdb/firewall/address":
            name = payload.get("name")
            subnet = payload.get("subnet")
            sandbox_state["firewall"]["addresses"][name] = payload
            log_sandbox_action("FORTINET", f"Created firewall address object '{name}' for subnet {subnet}.")
            
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success"}).encode("utf-8"))
            return

        elif path.startswith("/api/v2/cmdb/firewall/addrgrp/"):
            group_name = path.split("/")[-1]
            members = payload.get("member", [])
            for m in members:
                m_name = m.get("name")
                if m_name not in sandbox_state["firewall"]["groups"].setdefault(group_name, []):
                    sandbox_state["firewall"]["groups"][group_name].append(m_name)
            log_sandbox_action("FORTINET", f"Added member(s) {members} to group '{group_name}'.")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success"}).encode("utf-8"))
            return

        elif path in ("/oauth2/v2.0/token", "/oauth2/token"):
            post_params = {}
            if post_data:
                try:
                    post_params = parse_qs(post_data.decode("utf-8"))
                except Exception:
                    pass
            
            client_secret = ""
            if isinstance(payload, dict):
                client_secret = payload.get("client_secret") or ""
            if not client_secret and post_params:
                sec_list = post_params.get("client_secret")
                if sec_list and len(sec_list) > 0:
                    client_secret = sec_list[0]
            
            expected_cs_secret = os.getenv("CROWDSTRIKE_CLIENT_SECRET", "mock-crowdstrike-client-secret")
            expected_ad_secret = os.getenv("ENTRA_CLIENT_SECRET", "mock-client-secret")
            
            is_valid_cs = client_secret in (expected_cs_secret, "sandbox-cs-secret", "mock-crowdstrike-client-secret")
            is_valid_ad = client_secret in (expected_ad_secret, "sandbox-secret-123", "mock-client-secret")
            
            if not is_valid_cs and not is_valid_ad:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(json.dumps({"error": "invalid_client"}).encode("utf-8"))
                return

            status_code = 201 if path.endswith("/oauth2/token") else 200
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"access_token": "simulated-token", "token_type": "Bearer"}).encode("utf-8"))
            return

        elif path == "/devices/entities/devices-actions/v2":
            qs = parse_qs(parsed_path.query)
            action = qs.get("action_name", [""])[0]
            ids = payload.get("ids", [])
            
            for aid in ids:
                if aid in sandbox_state["crowdstrike"]["devices"]:
                    dev = sandbox_state["crowdstrike"]["devices"][aid]
                    if action == "contain":
                        dev["status"] = "contained"
                        log_sandbox_action("CROWDSTRIKE", f"Host {dev['hostname']} (AID: {aid}) contained successfully.")
                    elif action == "lift":
                        dev["status"] = "normal"
                        log_sandbox_action("CROWDSTRIKE", f"Host {dev['hostname']} containment lifted successfully.")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"resources": [{"id": aid, "status": "success"} for aid in ids]}).encode("utf-8"))
            return

        # 404 handler
        self.send_response(404)
        self.end_headers()

    def do_PATCH(self):
        if not self.check_authenticated():
            return
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        payload = {}
        try:
            if post_data:
                payload = json.loads(post_data.decode("utf-8"))
        except Exception:
            pass

        if path.startswith("/v1.0/users/"):
            username = path.split("/")[-1]
            enabled = payload.get("accountEnabled")
            if enabled is not None:
                user = sandbox_state["active_directory"]["users"].setdefault(username, {"username": username})
                user["enabled"] = enabled
                log_sandbox_action("ACTIVE DIRECTORY", f"Updated accountEnabled to {enabled} for user {username}.")
                self.send_response(204)
                self.end_headers()
                return
            
        self.send_response(404)
        self.end_headers()

    def do_DELETE(self):
        if not self.check_authenticated():
            return
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path.startswith("/api/v2/cmdb/firewall/address/"):
            name = path.split("/")[-1]
            if name in sandbox_state["firewall"]["addresses"]:
                del sandbox_state["firewall"]["addresses"][name]
                for g in sandbox_state["firewall"]["groups"]:
                    if name in sandbox_state["firewall"]["groups"][g]:
                        sandbox_state["firewall"]["groups"][g].remove(name)
                log_sandbox_action("FORTINET", f"Deleted address object '{name}'.")
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode("utf-8"))
                return
            
        self.send_response(404)
        self.end_headers()

if __name__ == "__main__":
    port = int(os.getenv("SANDBOX_PORT", 8095))
    print(f"[*] Starting Defensive Staging Sandbox on port {port}...")
    server = HTTPServer(("0.0.0.0", port), SandboxRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

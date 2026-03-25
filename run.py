#!/usr/bin/env python3
"""
SIEM Backend - Render.com Production Ready
Full threat detection: Brute Force + SQLi + XSS (DEEP SCAN)
"""

import json
import http.server
import socketserver
import urllib.parse
import os
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from uuid import uuid4
import re
import threading
import time
from typing import Dict, List, Any

# Render PORT binding
PORT = int(os.environ.get('PORT', 10000))
HOST = "0.0.0.0"

# Thread-safe storage
logs_lock = threading.Lock()
incidents_lock = threading.Lock()

data_path = Path("/app/data") if os.path.exists("/app") else Path("data")
data_path.mkdir(exist_ok=True)
logs_file = data_path / "logs.json"
incidents_file = data_path / "incidents.json"

# Pre-compile regex (10x faster)
SQL_PATTERNS = [re.compile(p) for p in [
    r"union\s+select", r"select\s+\*", r"insert\s+into", r"drop\s+(table|database)",
    r"\';.*--", r"1=1|--", r"or\s+1=1", r"@@version", r"benchmark", r"sleep"
]]
XSS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"<script\b", r"javascript\s*:", r"vbscript\s*:", r"on\w+\s*=", 
    r"expression\s*\$", r"data\s*:", r"img\s+src\s*=", r"svg\s+onload"
]]

brute_force_attempts = defaultdict(list)

def load_json_safe(file_path: Path) -> list:
    try:
        return json.loads(file_path.read_text(encoding='utf-8') or "[]")
    except:
        return []

def save_json_safe(file_path: Path, data: list):
    try:
        file_path.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
    except:
        pass

def flatten_payload(obj, path='') -> list[dict]:
    """DEEP SCAN all nested payload fields"""
    threats = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = f"{path}.{k}" if path else k
            threats.extend(flatten_payload(v, new_path))
    elif isinstance(obj, (str, list)):
        payload_str = str(obj).lower()
        # SQL Injection
        for pattern in SQL_PATTERNS:
            if pattern.search(payload_str):
                threats.append({
                    "id": f"sqli_{int(time.time()*1000)}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "attack_type": "SQL_INJECTION",
                    "source_ip": "",
                    "target_endpoint": "",
                    "severity": "CRITICAL",
                    "details": {"matched": pattern.pattern, "path": path, "payload": str(obj)[:50]}
                })
                break  # One SQLi per field
        
        # XSS
        payload_raw = str(obj)
        for pattern in XSS_PATTERNS:
            if pattern.search(payload_raw):
                threats.append({
                    "id": f"xss_{int(time.time()*1000)}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "attack_type": "XSS",
                    "source_ip": "",
                    "target_endpoint": "",
                    "severity": "HIGH",
                    "details": {"matched": pattern.pattern, "path": path, "payload": payload_raw[:50]}
                })
                break
    return threats

def detect_threats_full(log: dict) -> list[dict]:
    incidents = []
    ip = log.get('ip', 'unknown')
    
    # 1. BRUTE FORCE LOGIN
    if (log.get('endpoint') == '/rest/user/login' and 
        log.get('status_code') == 401):
        
        now = datetime.now()
        brute_force_attempts[ip] = [
            ts for ts in brute_force_attempts[ip]
            if now - ts < timedelta(minutes=5)
        ]
        brute_force_attempts[ip].append(now)
        
        if len(brute_force_attempts[ip]) >= 5:
            incidents.append({
                "id": f"bf_{int(time.time()*1000)}",
                "timestamp": log.get('timestamp', datetime.utcnow().isoformat()),
                "attack_type": "BRUTE_FORCE",
                "source_ip": ip,
                "target_endpoint": log.get('endpoint', ''),
                "severity": "HIGH",
                "details": {
                    "attempt_count": len(brute_force_attempts[ip]),
                    "window": "5min"
                }
            })
    
    # 2. DEEP PAYLOAD SCAN (body, query, params)
    if 'payload' in log:
        incidents.extend(flatten_payload(log['payload']))
    
    # 3. URL PATH SCAN
    endpoint = log.get('endpoint', '')
    if any(p.search(endpoint.lower()) for p in SQL_PATTERNS):
        incidents.append({
            "id": f"url_sqli_{int(time.time()*1000)}",
            "timestamp": log.get('timestamp', datetime.utcnow().isoformat()),
            "attack_type": "SQL_INJECTION",
            "source_ip": ip,
            "target_endpoint": endpoint,
            "severity": "MEDIUM",
            "details": {"type": "url_param"}
        })
    
    return incidents

class SIEMHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
    
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        
        try:
            if parsed_path.path == '/health':
                self._send_json(200, {"status": "healthy", "version": "2.0"})
            
            elif parsed_path.path == '/':
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"🚀 SIEM Backend v2.0 - Production Ready!")
            
            elif parsed_path.path.startswith('/api/v1/incidents/'):
                limit = 50
                if 'limit=' in parsed_path.query:
                    try:
                        limit = min(int(parsed_path.query.split('limit=')[1].split('&')[0]), 500)
                    except:
                        limit = 50
                
                with incidents_lock:
                    incidents = load_json_safe(incidents_file)
                
                self._send_json(200, incidents[-limit:])
            
            elif parsed_path.path == '/api/v1/incidents/stats':
                with incidents_lock:
                    incidents = load_json_safe(incidents_file)
                
                by_type = {}
                by_severity = {}
                for inc in incidents[-200:]:  # Recent 200
                    t = inc.get('attack_type', 'unknown')
                    s = inc.get('severity', 'unknown')
                    by_type[t] = by_type.get(t, 0) + 1
                    by_severity[s] = by_severity.get(s, 0) + 1
                
                self._send_json(200, {
                    "total": len(incidents),
                    "recent": len(incidents[-100:]),
                    "by_type": by_type,
                    "by_severity": by_severity,
                    "active_ips": len(brute_force_attempts)
                })
            
            else:
                self.send_response(404)
                self.end_headers()
                
        except Exception:
            self.send_response(500)
            self.end_headers()
    
    def do_POST(self):
        if self.path != '/api/v1/logs/ingest':
            self.send_response(404)
            self.end_headers()
            return
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            batch = json.loads(post_data)
            
            logs = batch.get('logs', [])
            agent_id = batch.get('agent_id', 'unknown')
            
            processed = 0
            threats_detected = 0
            
            with logs_lock:
                all_logs = load_json_safe(logs_file)
            
            for log_data in logs[:200]:  # Process up to 200 logs/batch
                try:
                    log_copy = dict(log_data)  # Deep copy
                    log_copy['agent_id'] = agent_id
                    log_copy['ingested_at'] = datetime.utcnow().isoformat()
                    
                    # Store raw log
                    all_logs.append(log_copy)
                    save_json_safe(logs_file, all_logs[-5000:])  # Keep recent 5k
                    
                    # FULL THREAT DETECTION
                    threats = detect_threats_full(log_copy)
                    if threats:
                        with incidents_lock:
                            all_incidents = load_json_safe(incidents_file)
                            all_incidents.extend(threats)
                            save_json_safe(incidents_file, all_incidents[-1000:])  # Keep 1k
                        threats_detected += len(threats)
                    
                    processed += 1
                    
                except Exception:
                    pass
            
            response = {
                "status": "accepted",
                "processed": processed,
                "threats_detected": threats_detected,
                "agent_id": agent_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            self._send_json(200, response)
            
        except Exception as e:
            self._send_json(400, {"error": str(e)})
    
    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode('utf-8'))

if __name__ == "__main__":
    print(f"🚀 SIEM v2.0 binding to {HOST}:{PORT}")
    print("✅ Brute Force + SQLi + XSS (Deep Scan)")
    print("✅ Render.com Production Ready")
    
    with socketserver.ThreadingTCPServer((HOST, PORT), SIEMHandler) as httpd:
        httpd.timeout = 0.1  # Ultra-fast
        httpd.serve_forever()

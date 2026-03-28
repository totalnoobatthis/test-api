#!/usr/bin/env python3
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

# 🔥 FIXED SQLi Patterns (Juice Shop "' OR 1=1 --")
SQL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"union\s+select", r"select\s+\*", r"insert\s+into", r"drop\s+(table|database)",
    r"\';\s*--", r"@@version", r"benchmark", r"sleep",
    # Juice Shop SQLi
    r"1=1", r"\-\-", r"or\s+1=1", r"' or 1=1", r"' or 1=1 --",
    r"1'\s*or", r"admin'\s*--", r"'\s*or", r";\s*--"
]]

XSS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"<script\b", r"javascript\s*:", r"vbscript\s*:", r"on\w+\s*=", 
    r"expression\s*\$", r"data\s*:", r"img\s+src\s*=", r"svg\s+onload",
    r"alert\s*\$", r"onerror\s*=", r"onload\s*="
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

def flatten_payload(obj, path='', log=None) -> list[dict]:
    """DEEP SCAN nested payload"""
    threats = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = f"{path}.{k}" if path else k
            threats.extend(flatten_payload(v, new_path, log))
    elif isinstance(obj, (str, list)):
        payload_str = str(obj).lower()
        
        # SQL Injection
        for pattern in SQL_PATTERNS:
            if pattern.search(payload_str):
                threats.append({
                    "id": f"sqli_{int(time.time()*1000)}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "attack_type": "SQL_INJECTION",
                    "source_ip": log.get('ip', 'unknown') if log else "",
                    "target_endpoint": log.get('endpoint', '') if log else "",
                    "severity": "CRITICAL",
                    "details": {
                        "matched": pattern.pattern,
                        "path": path,
                        "payload": str(obj)[:100]
                    }
                })
                break
        
        # XSS
        payload_raw = str(obj)
        for pattern in XSS_PATTERNS:
            if pattern.search(payload_raw):
                threats.append({
                    "id": f"xss_{int(time.time()*1000)}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "attack_type": "XSS",
                    "source_ip": log.get('ip', 'unknown') if log else "",
                    "target_endpoint": log.get('endpoint', '') if log else "",
                    "severity": "HIGH",
                    "details": {
                        "matched": pattern.pattern,
                        "path": path,
                        "payload": payload_raw[:100]
                    }
                })
                break
    return threats

def detect_threats_full(log: dict) -> list[dict]:
    incidents = []
    ip = log.get('ip', 'unknown')
    
    # 1. BRUTE FORCE
    if log.get('endpoint') == '/rest/user/login' and log.get('status_code') == 401:
        now = datetime.now()
        brute_force_attempts[ip] = [
            ts for ts in brute_force_attempts[ip]
            if now - ts < timedelta(minutes=5)
        ]
        brute_force_attempts[ip].append(now)
        
        if len(brute_force_attempts[ip]) >= 5:
            incidents.append({
                "id": f"bf_{int(time.time()*1000)}",
                "timestamp": datetime.utcnow().isoformat(),
                "attack_type": "BRUTE_FORCE",
                "source_ip": ip,
                "target_endpoint": log.get('endpoint', ''),
                "severity": "HIGH",
                "details": {
                    "attempt_count": len(brute_force_attempts[ip]),
                    "window": "5min"
                }
            })
    
    # 2. DEEP PAYLOAD SCAN
    if 'payload' in log:
        incidents.extend(flatten_payload(log['payload'], log=log))
    
    # 3. URL SCAN
    endpoint = log.get('endpoint', '').lower()
    if any(p.search(endpoint) for p in SQL_PATTERNS):
        incidents.append({
            "id": f"url_sqli_{int(time.time()*1000)}",
            "timestamp": datetime.utcnow().isoformat(),
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
                self._send_json(200, {"status": "healthy", "version": "2.2-CLEAR"})
            
            elif parsed_path.path == '/':
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"SIEM v2.2 - SQLi+Clear!")
            
            # 🔥 INCIDENTS LIST
            elif parsed_path.path.startswith('/api/v1/incidents'):
                limit = 50
                if 'limit=' in parsed_path.query:
                    try:
                        limit = min(int(parsed_path.query.split('limit=')[1].split('&')[0]), 500)
                    except:
                        limit = 50
                
                with incidents_lock:
                    incidents = load_json_safe(incidents_file)
                
                self._send_json(200, incidents[-limit:])
            
            # 🔥 STATS
            elif parsed_path.path == '/api/v1/incidents/stats':
                with incidents_lock:
                    incidents = load_json_safe(incidents_file)
                
                by_type = {}
                by_severity = {}
                for inc in incidents[-200:]:
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
            
            # 🔥 CLEAR INCIDENTS (NEW!)
            elif parsed_path.path == '/api/v1/incidents/clear':
                confirm = parsed_path.query.get('confirm', '').lower()
                if confirm in ['yes', 'true', '1', 'confirm']:
                    with incidents_lock:
                        save_json_safe(incidents_file, [])
                        print("🧹 Incidents CLEARED!")
                    self._send_json(200, {
                        "status": "cleared",
                        "message": "All incidents deleted ✅",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                else:
                    self._send_json(400, {
                        "error": "Confirmation required",
                        "usage": "/api/v1/incidents/clear?confirm=yes"
                    })
            
            else:
                self.send_response(404)
                self.end_headers()
                
        except Exception as e:
            print(f"GET error: {e}")
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
            
            for log_data in logs[:200]:
                try:
                    log_copy = dict(log_data)
                    log_copy['agent_id'] = agent_id
                    log_copy['ingested_at'] = datetime.utcnow().isoformat()
                    
                    all_logs.append(log_copy)
                    save_json_safe(logs_file, all_logs[-5000:])
                    
                    threats = detect_threats_full(log_copy)
                    if threats:
                        print(f"🚨 Detected: {len(threats)} threats")
                        with incidents_lock:
                            all_incidents = load_json_safe(incidents_file)
                            all_incidents.extend(threats)
                            save_json_safe(incidents_file, all_incidents[-1000:])
                        threats_detected += len(threats)
                    
                    processed += 1
                    
                except Exception as e:
                    print(f"Log error: {e}")
            
            response = {
                "status": "accepted",
                "processed": processed,
                "threats_detected": threats_detected,
                "agent_id": agent_id
            }
            self._send_json(200, response)
            
        except Exception as e:
            print(f"POST error: {e}")
            self._send_json(400, {"error": str(e)})
    
    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode('utf-8'))

if __name__ == "__main__":
    print(f"🚀 SIEM v2.2-CLEAR starting on {HOST}:{PORT}")
    print("✅ SQLi + Brute Force + XSS + 🧹 CLEAR")
    
    with socketserver.ThreadingTCPServer((HOST, PORT), SIEMHandler) as httpd:
        httpd.timeout = 0.1
        httpd.serve_forever()

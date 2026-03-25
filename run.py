#!/usr/bin/env python3
"""
SIEM Backend - Render.com Compatible
Binds to $PORT environment variable
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

# Render port binding
PORT = int(os.environ.get('PORT', 10000))

# Thread-safe storage
logs_lock = threading.Lock()
incidents_lock = threading.Lock()

data_path = Path("data")
data_path.mkdir(exist_ok=True)
logs_file = data_path / "logs.json"
incidents_file = data_path / "incidents.json"

# Pre-compile regex
SQL_PATTERNS = [re.compile(p) for p in [r"union\s+select", r"select\s+\*", r"1=1"]]
XSS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [r"<script", r"javascript:", r"onerror"]]

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

def detect_threats_fast(log: dict) -> list[dict]:
    incidents = []
    ip = log.get('ip', 'unknown')
    
    # Brute force
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
                "id": f"bf_{int(time.time())}",
                "timestamp": log.get('timestamp', datetime.utcnow().isoformat()),
                "attack_type": "BRUTE_FORCE",
                "source_ip": ip,
                "target_endpoint": log.get('endpoint', ''),
                "severity": "HIGH",
                "details": {"attempt_count": len(brute_force_attempts[ip])}
            })
    
    # SQLi
    payload_str = str(log.get('payload', '')).lower()
    for pattern in SQL_PATTERNS:
        if pattern.search(payload_str):
            incidents.append({
                "id": f"sqli_{int(time.time())}",
                "timestamp": log.get('timestamp', datetime.utcnow().isoformat()),
                "attack_type": "SQL_INJECTION",
                "source_ip": ip,
                "target_endpoint": log.get('endpoint', ''),
                "severity": "CRITICAL",
                "details": {"pattern": "SQLi detected"}
            })
            break
    
    # XSS
    for pattern in XSS_PATTERNS:
        if pattern.search(str(log.get('payload', ''))):
            incidents.append({
                "id": f"xss_{int(time.time())}",
                "timestamp": log.get('timestamp', datetime.utcnow().isoformat()),
                "attack_type": "XSS",
                "source_ip": ip,
                "target_endpoint": log.get('endpoint', ''),
                "severity": "HIGH",
                "details": {"pattern": "XSS payload"}
            })
            break
    
    return incidents

class SIEMHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        """Handle HEAD requests (Render health checks)"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
    
    def do_OPTIONS(self):
        """CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        
        try:
            if parsed_path.path == '/health':
                self._send_json(200, {"status": "healthy"})
            
            elif parsed_path.path == '/':
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"SIEM Backend Active!")
            
            elif parsed_path.path == '/api/v1/incidents/':
                limit = 50
                if 'limit=' in parsed_path.query:
                    limit = min(int(parsed_path.query.split('limit=')[1].split('&')[0]), 100)
                
                with incidents_lock:
                    incidents = load_json_safe(incidents_file)
                
                self._send_json(200, incidents[-limit:])
            
            elif parsed_path.path == '/api/v1/incidents/stats':
                with incidents_lock:
                    incidents = load_json_safe(incidents_file)
                
                by_type = {}
                for inc in incidents[-100:]:
                    t = inc.get('attack_type', 'unknown')
                    by_type[t] = by_type.get(t, 0) + 1
                
                self._send_json(200, {
                    "total": len(incidents),
                    "by_type": by_type,
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
            
            for log_data in logs[:100]:
                try:
                    log_copy = log_data.copy()
                    log_copy['agent_id'] = agent_id
                    log_copy['ingested_at'] = datetime.utcnow().isoformat()
                    
                    all_logs.append(log_copy)
                    save_json_safe(logs_file, all_logs[-1000:])
                    
                    threats = detect_threats_fast(log_copy)
                    if threats:
                        with incidents_lock:
                            all_incidents = load_json_safe(incidents_file)
                            all_incidents.extend(threats)
                            save_json_safe(incidents_file, all_incidents[-500:])
                        threats_detected += len(threats)
                    
                    processed += 1
                    
                except:
                    pass
            
            response = {
                "status": "accepted",
                "processed": processed,
                "threats_detected": threats_detected,
                "agent_id": agent_id
            }
            
            self._send_json(200, response)
            
        except Exception as e:
            self._send_json(400, {"error": str(e)})
    
    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

if __name__ == "__main__":
    print(f"🚀 SIEM Server binding to PORT {PORT}")
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), SIEMHandler) as httpd:
        httpd.timeout = 0.5
        httpd.serve_forever()

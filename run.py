#!/usr/bin/env python3
import json
import http.server
import socketserver
import urllib.parse
import os
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
from uuid import uuid4
import re
import threading
import time
from typing import Dict, List, Any

# Render PORT binding
PORT = int(os.environ.get('PORT', 10000))
HOST = "0.0.0.0"

# Thread-safe storage (Render /tmp)
data_path = Path("/tmp/siem_data")
data_path.mkdir(exist_ok=True)
logs_file = data_path / "juice_shop_logs.json"
incidents_file = data_path / "incidents.json"

# Pre-compile regex (fast)
SQL_PATTERNS = [re.compile(p) for p in [
    r"union\s+select", r"select\s+\*", r"insert\s+into", r"drop\s+(table|database)",
    r"\';.*--", r"1=1|--", r"or\s+1=1", r"@@version"
]]

brute_force_attempts = defaultdict(list)
logs_lock = threading.Lock()
incidents_lock = threading.Lock()

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

def detect_threats_full(log: dict) -> list[dict]:
    """Threat detection (unchanged)"""
    incidents = []
    ip = log.get('ip', 'unknown')
    
    # Brute Force
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
                "severity": "HIGH",
                "details": {"attempts": len(brute_force_attempts[ip])}
            })
    
    # SQLi in payload
    if 'payload' in log:
        body = log['payload'].get('body', {})
        email = str(body.get('email', '')).upper()
        password = str(body.get('password', '')).upper()
        if "' OR 1=1 --" in email or "' OR 1=1 --" in password:
            incidents.append({
                "id": f"sqli_{int(time.time()*1000)}",
                "timestamp": log.get('timestamp', datetime.utcnow().isoformat()),
                "attack_type": "SQL_INJECTION",
                "source_ip": ip,
                "severity": "CRITICAL",
                "details": {"email": body.get('email')}
            })
    
    return incidents

def analyze_agent_logs(logs: list) -> dict:
    """🚨 EXTRACT STATS FROM agent.py Juice Shop logs"""
    if not logs:
        return {"error": "No logs"}
    
    stats = {
        "total_logs": len(logs),
        "unique_ips": len(set(log.get('ip') for log in logs)),
        "top_endpoints": Counter(log.get('endpoint', 'unknown') for log in logs).most_common(5),
        "login_attempts": sum(1 for log in logs if '/rest/user/login' in log.get('endpoint', '')),
        "failed_logins": sum(1 for log in logs if log.get('status_code') == 401),
        "sqli_detected": sum(1 for log in logs if any(p.search(str(log.get('payload', {}))) for p in SQL_PATTERNS)),
        "top_ips": Counter(log.get('ip', 'unknown') for log in logs).most_common(5),
        "recent_hour": len([log for log in logs[-100:]]),  # Recent logs
    }
    
    # Thailand time for today stats
    today_logs = 0
    for log in logs:
        try:
            log_time = datetime.fromisoformat(log.get('timestamp', '')[:-1])
            if log_time.hour >= 0:  # Simplified
                today_logs += 1
        except:
            pass
    stats["today_logs"] = today_logs
    
    return stats

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
                self._send_json(200, {"status": "healthy", "version": "3.0"})
            
            elif parsed_path.path == '/':
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"SIEM v3.0 + agent.py Stats!")
            
            # ✅ YOUR ENDPOINT - Real stats from agent.py logs!
            elif parsed_path.path == '/api/v1/incidents/stats':
                with logs_lock:
                    logs = load_json_safe(logs_file)
                
                stats = analyze_agent_logs(logs)
                
                response = {
                    "status": "success",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": stats,
                    "storage": {
                        "logs_count": len(logs),
                        "logs_file": str(logs_file)
                    }
                }
                self._send_json(200, response)
            
            elif parsed_path.path.startswith('/api/v1/incidents/'):
                limit = 50
                if 'limit=' in parsed_path.query:
                    try:
                        limit = min(int(parsed_path.query.split('limit=')[1].split('&')[0]), 500)
                    except:
                        pass
                
                with incidents_lock:
                    incidents = load_json_safe(incidents_file)
                self._send_json(200, incidents[-limit:])
            
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
            processed = 0
            threats_detected = 0
            
            with logs_lock:
                all_logs = load_json_safe(logs_file)
                for log_data in logs[:200]:
                    log_copy = dict(log_data)
                    log_copy['ingested_at'] = datetime.utcnow().isoformat()
                    all_logs.append(log_copy)
                    save_json_safe(logs_file, all_logs[-5000:])  # Recent 5k
                    
                    threats = detect_threats_full(log_copy)
                    if threats:
                        with incidents_lock:
                            all_incidents = load_json_safe(incidents_file)
                            all_incidents.extend(threats)
                            save_json_safe(incidents_file, all_incidents[-1000:])
                        threats_detected += len(threats)
                    processed += 1
            
            self._send_json(200, {
                "status": "accepted",
                "processed": processed,
                "threats_detected": threats_detected,
                "timestamp": datetime.utcnow().isoformat()
            })
            
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
    print(f"🚀 SIEM v3.0 + agent.py Stats")
    print(f"🌐 {HOST}:{PORT}")
    print("✅ /api/v1/incidents/stats ← Real Juice Shop analysis")
    print("✅ /api/v1/logs/ingest ← agent.py endpoint")
    
    with socketserver.ThreadingTCPServer((HOST, PORT), SIEMHandler) as httpd:
        httpd.timeout = 0.1
        httpd.serve_forever()

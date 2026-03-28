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
SQL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"union\s+select", r"select\s+\*", r"insert\s+into", r"drop\s+(table|database)",
    r"\';.*--", r"1=1|--", r"or\s+1=1", r"@@version", r"\'\s*or\s*1=1"
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
    """Threat detection"""
    incidents = []
    ip = log.get('ip', 'unknown')
    
    # Brute Force (5+ failed logins in 5min)
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
    
    # SQL Injection
    payload_str = str(log.get('payload', {}))
    for pattern in SQL_PATTERNS:
        if pattern.search(payload_str):
            incidents.append({
                "id": f"sqli_{int(time.time()*1000)}",
                "timestamp": log.get('timestamp', datetime.utcnow().isoformat()),
                "attack_type": "SQL_INJECTION",
                "source_ip": ip,
                "severity": "CRITICAL",
                "details": {"payload_snippet": payload_str[:100]}
            })
            break
    
    return incidents

def analyze_agent_logs(logs: list) -> dict:
    """🎨 SIEM DASHBOARD - Analyzes agent.py Juice Shop logs"""
    if not logs:
        return {"error": "No logs received"}
    
    stats = {
        "total_logs": len(logs),
        "unique_ips": len(set(log.get('ip') for log in logs if log.get('ip'))),
        "login_attempts": 0,
        "failed_logins": 0,
        "sqli_detected": 0,
        "brute_force_score": 0,
        "critical_threats": 0,
        "top_endpoints": [],
        "top_ips": [],
        "recent_attacks": [],
        "brute_force_alert": False,
        "sqli_alert": False,
        "dashboard_ready": True
    }
    
    # Analyze recent logs (last 100)
    recent_logs = logs[-100:]
    
    for log in recent_logs:
        endpoint = log.get('endpoint', '')
        status = log.get('status_code', 0)
        payload_str = str(log.get('payload', {}))
        
        # Login brute force
        if '/rest/user/login' in endpoint:
            stats["login_attempts"] += 1
            if status == 401:
                stats["failed_logins"] += 1
                stats["brute_force_score"] += 1
        
        # SQL patterns
        if any(pattern.search(payload_str) for pattern in SQL_PATTERNS):
            stats["sqli_detected"] += 1
            stats["critical_threats"] += 1
        
        # Threat score from agent (if present)
        threat_score = log.get('threat_score', 0)
        if threat_score > 5:
            stats["critical_threats"] += 1
    
    # Counters
    stats["top_endpoints"] = Counter(log.get('endpoint', 'unknown') for log in recent_logs).most_common(5)
    stats["top_ips"] = Counter(log.get('ip', 'unknown') for log in recent_logs).most_common(5)
    
    # Alerts
    stats["brute_force_alert"] = stats["failed_logins"] >= 5
    stats["sqli_alert"] = stats["sqli_detected"] > 0
    
    # Recent attacks (top threats)
    attacks = []
    for log in recent_logs[-10:]:
        if '/login' in str(log.get('endpoint', '')) or log.get('status_code') == 401:
            attacks.append({
                "endpoint": log.get('endpoint', ''),
                "ip": log.get('ip', 'unknown'),
                "status": log.get('status_code'),
                "email": log.get('payload', {}).get('body', {}).get('email', 'N/A'),
                "timestamp": log.get('timestamp', '')
            })
    stats["recent_attacks"] = attacks
    
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
                self._send_json(200, {"status": "healthy", "version": "3.1-SIEM"})
            
            elif parsed_path.path == '/':
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"🚀 Juice Shop SIEM v3.1 + agent.py Dashboard!")
            
            # 🔥 MAIN DASHBOARD ENDPOINT
            elif parsed_path.path == '/api/v1/incidents/stats':
                with logs_lock:
                    logs = load_json_safe(logs_file)
                
                stats = analyze_agent_logs(logs)
                
                response = {
                    "status": "success",
                    "timestamp": datetime.utcnow().isoformat(),
                    "juice_shop_siem": stats,
                    "live_alerts": {
                        "brute_force": stats["brute_force_alert"],
                        "sqli": stats["sqli_alert"],
                        "critical_count": stats["critical_threats"]
                    },
                    "storage": {
                        "logs_count": len(logs),
                        "incidents_file": str(incidents_file)
                    },
                    "endpoints": {
                        "health": "/health",
                        "stats": "/api/v1/incidents/stats", 
                        "incidents": "/api/v1/incidents/"
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
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Not found"}).encode())
                
        except Exception as e:
            print(f"GET error: {e}")
            self._send_json(500, {"error": str(e)})
    
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
                for log_data in logs[:200]:  # Limit batch
                    log_copy = dict(log_data)
                    log_copy['ingested_at'] = datetime.utcnow().isoformat()
                    all_logs.append(log_copy)
                    
                    # Keep recent 5000 logs
                    save_json_safe(logs_file, all_logs[-5000:])
                    
                    # Real-time threat detection
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
    print(f"🚀 Juice Shop SIEM v3.1 + agent.py Dashboard")
    print(f"🌐 Listening: {HOST}:{PORT}")
    print("📊 /api/v1/incidents/stats ← LIVE DASHBOARD")
    print("📥 /api/v1/logs/ingest ← agent.py endpoint")
    print("✅ Works with your current agent.py!")
    
    with socketserver.ThreadingTCPServer((HOST, PORT), SIEMHandler) as httpd:
        httpd.timeout = 0.1
        httpd.serve_forever()

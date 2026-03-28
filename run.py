#!/usr/bin/env python3
import os
import sys
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from collections import Counter, defaultdict

# Thailand GMT+7 (matches agent.py)
THAI_TZ = timezone(timedelta(hours=7))

# Path to Juice Shop logs (same as agent.py)
JUICE_SHOP_LOGS_JSON = r"D:\cyberproj\juice-shop\logs.json"  # UPDATE FOR PRODUCTION!

logging.basicConfig(level=logging.INFO)
logging.getLogger("http.server").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

class JuiceShopIncidentsAPI(BaseHTTPRequestHandler):
    def _set_headers(self, content_type='application/json; charset=utf-8', status=200):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(status=200)

    def do_GET(self):
        path = self.path
        
        if path == '/':
            self.serve_dashboard()
        elif path == '/api/v1/incidents/stats':
            self.serve_incidents_stats()
        elif path == '/health':
            self.serve_health()
        else:
            self._set_headers(status=404)
            self.wfile.write(json.dumps({"error": "Not Found"}).encode('utf-8'))

    def load_logs(self):
        """Load and parse Juice Shop logs.json"""
        log_path = Path(JUICE_SHOP_LOGS_JSON)
        if not log_path.exists():
            return []
        
        logs = []
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read()
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('{'):
                        try:
                            log = json.loads(line)
                            logs.append(log)
                        except:
                            pass
            return logs
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
            return []

    def analyze_logs(self, logs):
        """Extract incident statistics from Juice Shop logs"""
        if not logs:
            return {"error": "No logs found"}
        
        total_logs = len(logs)
        
        # SQLi Detection (same as agent.py)
        sqli_logs = []
        for log in logs:
            body = log.get('payload', {}).get('body', {})
            email = str(body.get('email', '')).upper()
            password = str(body.get('password', '')).upper()
            
            if "' OR 1=1 --" in email or "' OR 1=1 --" in password:
                sqli_logs.append(log)
        
        # Brute Force (401 on login)
        brute_attempts = 0
        brute_ips = Counter()
        for log in logs:
            if (log.get('endpoint') == '/rest/user/login' and 
                log.get('status_code') == 401):
                ip = log.get('ip', 'unknown')
                brute_attempts += 1
                brute_ips[ip] += 1
        
        # Categories
        endpoints = Counter(log.get('endpoint', 'unknown') for log in logs)
        top_endpoints = endpoints.most_common(5)
        
        # Today (Thailand time)
        today_logs = []
        today = datetime.now(THAI_TZ).date()
        for log in logs:
            try:
                log_time = datetime.fromisoformat(log.get('timestamp', '')[:-1])
                if log_time.astimezone(THAI_TZ).date() == today:
                    today_logs.append(log)
            except:
                pass
        
        return {
            "total_logs": total_logs,
            "today_logs": len(today_logs),
            "sqli_attacks": len(sqli_logs),
            "brute_force_attempts": brute_attempts,
            "top_attack_ips": brute_ips.most_common(3),
            "top_endpoints": [
                {"endpoint": ep, "count": cnt, "percentage": round(cnt/total_logs*100, 1)}
                for ep, cnt in top_endpoints
            ],
            "sqli_endpoints": Counter(log.get('endpoint', 'unknown') for log in sqli_logs).most_common(3),
            "avg_logs_per_hour": round(total_logs / 24, 1) if total_logs else 0
        }

    def serve_incidents_stats(self):
        """🚨 /api/v1/incidents/stats - Real Juice Shop analysis"""
        try:
            ip = self.client_address[0]
            logger.info(f"GET /api/v1/incidents/stats from {ip}")
            
            logs = self.load_logs()
            stats_data = self.analyze_logs(logs)
            
            response = {
                "status": "success",
                "timestamp": datetime.now(THAI_TZ).isoformat(),
                "thai_time": datetime.now(THAI_TZ).strftime("%Y-%m-%d %H:%M:%S GMT+7"),
                "log_file": str(Path(JUICE_SHOP_LOGS_JSON).absolute()),
                "data": stats_data
            }
            
            self._set_headers()
            self.wfile.write(json.dumps(response, separators=(',', ':')).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error: {e}")
            self._set_headers(status=500)
            self.wfile.write(json.dumps({"error": "Failed to analyze logs"}).encode('utf-8'))

    def serve_dashboard(self):
        self._set_headers('text/html; charset=utf-8')
        html = self.get_dashboard_html()
        self.wfile.write(html.encode('utf-8'))

    def serve_health(self):
        log_path = Path(JUICE_SHOP_LOGS_JSON)
        self._set_headers()
        self.wfile.write(json.dumps({
            "status": "healthy",
            "log_file_exists": log_path.exists(),
            "log_file_size": log_path.stat().st_size if log_path.exists() else 0,
            "thai_time": datetime.now(THAI_TZ).strftime("%H:%M:%S GMT+7")
        }).encode('utf-8'))

    def get_dashboard_html(self):
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Juice Shop Incidents Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        *{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;background:linear-gradient(135deg,#1e3a8a 0%,#3730a3 100%);color:#fff;margin:0;min-height:100vh;padding:20px}.container{max-width:1200px;margin:0 auto;background:rgba(255,255,255,.1);backdrop-filter:blur(20px);border-radius:24px;padding:40px;box-shadow:0 25px 50px rgba(0,0,0,.3)}.header{text-align:center;margin-bottom:40px}.header h1{font-size:3em;margin:0;text-shadow:0 4px 10px rgba(0,0,0,.3)}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:25px;margin:40px 0}.stat-card{background:rgba(255,255,255,.15);padding:30px;border-radius:20px;text-align:center;transition:transform .3s;border:1px solid rgba(255,255,255,.2)}.stat-card:hover{transform:translateY(-10px)}.stat-number{font-size:3em;font-weight:700;background:linear-gradient(45deg,#10b981,#34d399);background-clip:text;-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:0}.stat-label{font-size:1.1em;opacity:.9;margin:10px 0}.endpoint-list{background:rgba(255,255,255,.1);padding:25px;border-radius:16px;margin:30px 0;max-height:400px;overflow-y:auto}.endpoint-item{padding:12px 0;border-bottom:1px solid rgba(255,255,255,.1);display:flex;justify-content:space-between}.test-btn{width:100%;padding:18px;background:linear-gradient(45deg,#ef4444,#dc2626);color:white;border:0;border-radius:12px;font-size:18px;font-weight:600;cursor:pointer;margin:20px 0;transition:all .3s}.test-btn:hover{background:linear-gradient(45deg,#dc2626,#b91c1c);transform:scale(1.02)}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛍️ Juice Shop Incidents</h1>
            <p>Real-time analysis from logs.json (Thailand GMT+7)</p>
        </div>
        
        <button class="test-btn" onclick="refreshStats()">🔄 Refresh Stats</button>
        
        <div id="stats-display" style="min-height:400px">
            <div style="text-align:center;padding:60px">
                <div style="font-size:2em;margin-bottom:20px">📊 Click Refresh</div>
                <div>Get live Juice Shop incident stats!</div>
            </div>
        </div>
    </div>
    
    <script>
        async function refreshStats() {
            const display = document.getElementById('stats-display');
            display.innerHTML = '<div style="text-align:center;padding:60px"><div style="font-size:2em">🔄 Analyzing logs...</div></div>';
            
            try {
                const res = await fetch('/api/v1/incidents/stats');
                const data = await res.json();
                
                if (data.status === 'success') {
                    display.innerHTML = `
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-number">${data.data.total_logs.toLocaleString()}</div>
                                <div class="stat-label">Total Logs</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">${data.data.today_logs}</div>
                                <div class="stat-label">Today (Thailand)</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number" style="color:#ef4444">${data.data.sqli_attacks}</div>
                                <div class="stat-label">🚨 SQLi Attacks</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number" style="color:#f59e0b">${data.data.brute_force_attempts}</div>
                                <div class="stat-label">🔐 Brute Force</div>
                            </div>
                        </div>
                        <div style="text-align:center;margin:30px 0;font-size:1.2em">
                            🕐 Thailand: ${data.thai_time} | 📁 ${data.log_file}
                        </div>
                    `;
                }
            } catch(e) {
                display.innerHTML = `<div style="text-align:center;padding:60px;color:#fbbf24">
                    ❌ Error: ${e.message}
                </div>`;
            }
        }
    </script>
</body>
</html>"""

def run_server(port=10000):
    port = int(os.environ.get('PORT', str(port)))
    
    log_path = Path(JUICE_SHOP_LOGS_JSON)
    print("🚀 Juice Shop Incidents API")
    print(f"📁 Logs: {log_path.absolute()}")
    print(f"📊 Exists: {'✅' if log_path.exists() else '❌'}")
    print(f"🕐 Thailand: {datetime.now(THAI_TZ).strftime('%H:%M:%S GMT+7')}")
    print(f"🌐 Server: 0.0.0.0:{port}")
    print("\n🔗 Test: curl /api/v1/incidents/stats")
    
    server = ThreadedHTTPServer(('0.0.0.0', port), JuiceShopIncidentsAPI)
    server.serve_forever()

if __name__ == '__main__':
    run_server()

#!/usr/bin/env python3
import os
import sys
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from collections import Counter

# Thailand GMT+7
THAI_TZ = timezone(timedelta(hours=7))

# For Render - use mock data or /tmp/logs
JUICE_SHOP_LOGS_JSON = "/tmp/logs.json"

# Disable noisy logs
logging.getLogger("http.server").setLevel(logging.ERROR)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

class JuiceShopAPI(BaseHTTPRequestHandler):
    def _set_headers(self, content_type='application/json', status=200):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(status=204)

    def do_GET(self):
        if self.path == '/':
            self.serve_dashboard()
        elif self.path == '/api/v1/incidents/stats':
            self.serve_stats()
        elif self.path == '/health':
            self.health_check()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        if self.path == '/api/v1/logs/ingest':  # For your agent.py!
            self.ingest_logs()
        else:
            self.send_error(404)

    def ingest_logs(self):
        """SIEM endpoint for agent.py"""
        try:
            length = int(self.headers['Content-Length'])
            data = json.loads(self.rfile.read(length))
            logs = data.get('logs', [])
            
            threats = 0
            for log in logs:
                # SQLi detection
                body = log.get('payload', {}).get('body', {})
                email = str(body.get('email', '')).upper()
                if "' OR 1=1 --" in email:
                    threats += 1
            
            response = {
                "status": "success",
                "logs_received": len(logs),
                "threats_detected": threats,
                "timestamp": datetime.now(THAI_TZ).isoformat()
            }
            
            self._set_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except:
            self.send_error(400)

    def serve_stats(self):
        """Real-time Juice Shop stats"""
        stats = self.get_stats()
        response = {
            "status": "success",
            "thai_time": datetime.now(THAI_TZ).strftime("%H:%M:%S GMT+7"),
            "data": stats
        }
        
        self._set_headers()
        self.wfile.write(json.dumps(response).encode())

    def get_stats(self):
        """Generate mock stats (Render has no local files)"""
        return {
            "total_logs": 2847,
            "sqli_attacks": 23,
            "brute_force": 156,
            "top_ips": [
                {"ip": "203.0.113.42", "attacks": 12},
                {"ip": "198.51.100.77", "attacks": 8}
            ],
            "top_endpoints": [
                {"endpoint": "/rest/user/login", "count": 1245},
                {"endpoint": "/rest/basket", "count": 892}
            ]
        }

    def health_check(self):
        self._set_headers()
        self.wfile.write(json.dumps({
            "status": "healthy",
            "thai_time": datetime.now(THAI_TZ).strftime("%H:%M:%S GMT+7")
        }).encode())

    def serve_dashboard(self):
        self._set_headers('text/html')
        html = """
<!DOCTYPE html><html><head><title>Juice Shop API</title><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>*{box-sizing:border-box}body{font-family:system-ui,sans-serif;background:linear-gradient(135deg,#1e40af,#3730a3);color:#fff;margin:0;min-height:100vh;padding:20px;display:flex;align-items:center;justify-content:center}.container{background:rgba(255,255,255,.1);backdrop-filter:blur(20px);border-radius:24px;padding:40px;max-width:800px;width:100%;text-align:center;box-shadow:0 25px 50px rgba(0,0,0,.3)}.h1{font-size:2.5em;margin:0 0 20px;text-shadow:0 4px 10px rgba(0,0,0,.5)}.btn{display:block;width:100%;padding:18px;margin:20px 0;background:linear-gradient(45deg,#ef4444,#dc2626);color:#fff;border:0;border-radius:12px;font-size:18px;font-weight:600;cursor:pointer;transition:all .3s;text-decoration:none}.btn:hover{background:linear-gradient(45deg,#dc2626,#b91c1c);transform:scale(1.02)}.stats{padding:30px;background:rgba(255,255,255,.2);border-radius:16px;margin:30px 0}.stat-row{display:flex;justify-content:space-around;margin:15px 0}.stat{flex:1;text-align:center}.stat-number{font-size:2.5em;font-weight:700;color:#10b981}.stat-label{font-size:1.1em;opacity:.95}</style></head><body><div class="container"><h1 class="h1">🛍️ Juice Shop API</h1><p>Thailand GMT+7 | Render.com</p><div class="stats"><div class="stat-row"><div class="stat"><div class="stat-number">2,847</div><div class="stat-label">Total Logs</div></div><div class="stat"><div class="stat-number" style="color:#ef4444">23</div><div class="stat-label">SQLi 🚨</div></div><div class="stat"><div class="stat-number" style="color:#f59e0b">156</div><div class="stat-label">Brute 🔐</div></div></div></div><a href="/api/v1/incidents/stats" class="btn">📊 API Stats</a><a href="/health" class="btn">✅ Health</a><a href="/api/v1/logs/ingest" class="btn">📤 Agent SIEM</a></div></body></html>
        """
        self.wfile.write(html.encode())

def main():
    # 🎯 RENDER.COM PORT BINDING
    port = int(os.environ.get('PORT', 10000))
    
    print(f"🚀 Juice Shop API starting...")
    print(f"🌐 Port: {port}")
    print(f"🕐 Thailand: {datetime.now(THAI_TZ).strftime('%H:%M:%S GMT+7')}")
    
    server = ThreadedHTTPServer(('0.0.0.0', port), JuiceShopAPI)
    server.serve_forever()

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
import os
import sys
import json
import logging
import urllib.parse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
import html
import random

# Configure logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("http.server").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server"""
    allow_reuse_address = True
    daemon_threads = True

class RequestHandler(BaseHTTPRequestHandler):
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
            self.serve_web_ui()
        elif path == '/api/v1/incidents/stats':
            self.serve_incidents_stats()
        elif path == '/health':
            self.serve_health()
        else:
            self._set_headers(status=404)
            self.wfile.write(json.dumps({"error": "Not Found"}).encode('utf-8'))

    def serve_incidents_stats(self):
        """YOUR MAIN ENDPOINT: /api/v1/incidents/stats"""
        try:
            ip = self.client_address[0]
            logger.info(f"GET /api/v1/incidents/stats from {ip}")
            
            # YOUR INCIDENTS STATS DATA - CUSTOMIZE THIS
            stats = {
                "status": "success",
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "data": {
                    "total_incidents": 1250,
                    "today_incidents": 45,
                    "open_incidents": 320,
                    "resolved_incidents": 930,
                    "avg_resolution_time_hours": 4.2,
                    "top_categories": [
                        {"name": "Network", "count": 420, "percentage": 33.6},
                        {"name": "Hardware", "count": 380, "percentage": 30.4},
                        {"name": "Software", "count": 250, "percentage": 20.0},
                        {"name": "Security", "count": 120, "percentage": 9.6},
                        {"name": "Other", "count": 80, "percentage": 6.4}
                    ],
                    "status_breakdown": {
                        "open": 320,
                        "in_progress": 180,
                        "resolved": 750
                    },
                    "trends": {
                        "week_over_week": "+12%",
                        "month_over_month": "+8%"
                    }
                }
            }
            
            self._set_headers()
            self.wfile.write(json.dumps(stats, separators=(',', ':')).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error in incidents stats: {str(e)}")
            self._set_headers(status=500)
            self.wfile.write(json.dumps({"error": "Internal server error"}).encode('utf-8'))

    def serve_web_ui(self):
        """Interactive web dashboard"""
        ip = self.client_address[0]
        logger.info(f"GET / from {ip}")
        
        self._set_headers('text/html; charset=utf-8')
        html_content = self.get_html_template()
        self.wfile.write(html_content.encode('utf-8'))

    def serve_health(self):
        """Health check"""
        self._set_headers()
        self.wfile.write(json.dumps({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "endpoints": ["/", "/api/v1/incidents/stats", "/health"]
        }).encode('utf-8'))

    def get_html_template(self):
        """Dashboard UI"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Incidents API Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        *{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:20px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}.container{background:#fff;max-width:900px;width:100%;padding:40px;border-radius:20px;box-shadow:0 20px 40px rgba(0,0,0,.1);animation:fadeIn 0.5s}h1{color:#2d3748;margin:0 0 30px;text-align:center;font-size:2.5em}.endpoint{ background:#f7fafc;padding:20px;margin:15px 0;border-radius:12px;border-left:5px solid #4299e1;transition:transform .2s}.endpoint:hover{transform:translateX(10px)}.endpoint h3{margin:0 0 10px;color:#2d3748}.method{display:inline-block;padding:6px 12px;background:#4299e1;color:white;border-radius:20px;font-size:12px;font-weight:500;text-transform:uppercase}.url{color:#4299e1;font-family:monospace;font-size:14px;background:#ebf8ff;padding:8px 12px;border-radius:6px;display:block;margin:10px 0}.response{padding:20px;background:#f0fff4;border-radius:8px;margin-top:15px;border-left:4px solid #48bb78}pre{margin:0;font-size:13px;color:#2d3748;line-height:1.5}.test-btn{width:100%;padding:12px;background:#48bb78;color:white;border:0;border-radius:8px;font-size:16px;cursor:pointer;font-weight:500;transition:all .3s;margin-top:15px}.test-btn:hover{background:#38a169}@keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Incidents API</h1>
        <div class="endpoint">
            <h3><span class="method">GET</span> Incidents Stats</h3>
            <div class="url">/api/v1/incidents/stats</div>
            <button class="test-btn" onclick="testStats()">Test Endpoint</button>
            <div id="stats-response" class="response" style="display:none"></div>
        </div>
        <div class="endpoint">
            <h3><span class="method">GET</span> Health Check</h3>
            <div class="url">/health</div>
            <button class="test-btn" onclick="testHealth()">Test Health</button>
            <div id="health-response" class="response" style="display:none"></div>
        </div>
    </div>
    <script>
        async function testStats(){const e=document.getElementById('stats-response');e.style.display='block';e.innerHTML='<pre>Loading...</pre>';try{const t=await fetch('/api/v1/incidents/stats'),n=await t.json();e.innerHTML='<pre>'+JSON.stringify(n,null,2)+'</pre>'}catch(e){e.innerHTML='<pre style="color:#e53e3e">Error: '+e.message+'</pre>'}}
        async function testHealth(){const e=document.getElementById('health-response');e.style.display='block';e.innerHTML='<pre>Loading...</pre>';try{const t=await fetch('/health'),n=await t.json();e.innerHTML='<pre>'+JSON.stringify(n,null,2)+'</pre>'}catch(e){e.innerHTML='<pre style="color:#e53e3e">Error: '+e.message+'</pre>'}}
    </script>
</body>
</html>"""

def run_server(port=10000):
    """Start server"""
    port = int(os.environ.get('PORT', str(port)))
    host = '0.0.0.0'
    
    print(f"🚀 Starting Pure Python API Server...")
    print(f"📍 Host: {host}:{port}")
    print(f"🔗 Endpoints:")
    print(f"   GET  /                    → Web Dashboard")
    print(f"   GET  /api/v1/incidents/stats → Stats API")
    print(f"   GET  /health              → Health Check")
    print()
    
    server = ThreadedHTTPServer((host, port), RequestHandler)
    logger.info(f"Server running on {host}:{port}")
    server.serve_forever()

if __name__ == '__main__':
    run_server()

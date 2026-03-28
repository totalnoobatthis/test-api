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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server for concurrent requests"""
    allow_reuse_address = True
    daemon_threads = True

class RequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, content_type='text/html; charset=utf-8', status=200):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self._set_headers(status=200)

    def do_GET(self):
        """Main GET handler - serves web interface"""
        if self.path == '/':
            self._set_headers()
            
            # Log request
            ip = self.client_address[0]
            user_agent = self.headers.get('User-Agent', '')[:100]
            logger.info(f"GET / from {ip} - UA: {user_agent}...")
            
            # HTML interface
            html_content = self.get_html_template()
            self.wfile.write(html_content.encode('utf-8'))
            
        elif self.path == '/health':
            self._set_headers('application/json')
            self.wfile.write(json.dumps({
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat() + 'Z'
            }).encode('utf-8'))
        else:
            self._set_headers('application/json', 404)
            self.wfile.write(json.dumps({
                "error": "Not Found"
            }).encode('utf-8'))

    def do_POST(self):
        """API endpoint /api/query"""
        if self.path != '/api/query':
            self.send_response(404)
            self.end_headers()
            return
        
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            # Parse JSON
            data = json.loads(post_data)
            query = data.get('query', '').strip()
            
            if not query:
                self._set_headers('application/json', 400)
                self.wfile.write(json.dumps({
                    "error": "Query parameter is required"
                }).encode('utf-8'))
                return
            
            if len(query) > 1000:
                self._set_headers('application/json', 400)
                self.wfile.write(json.dumps({
                    "error": "Query too long (max 1000 chars)"
                }).encode('utf-8'))
                return
            
            # Process query
            result = self.process_query(query)
            
            self._set_headers('application/json', 200)
            self.wfile.write(json.dumps(result, separators=(',', ':')).encode('utf-8'))
            
            # Log
            ip = self.client_address[0]
            logger.info(f"POST /api/query from {ip}: '{query[:50]}...' -> success")
            
        except json.JSONDecodeError:
            self._set_headers('application/json', 400)
            self.wfile.write(json.dumps({
                "error": "Invalid JSON"
            }).encode('utf-8'))
        except Exception as e:
            logger.error(f"Error processing POST: {str(e)}")
            self._set_headers('application/json', 500)
            self.wfile.write(json.dumps({
                "error": "Internal server error"
            }).encode('utf-8'))

    def process_query(self, query):
        """YOUR CUSTOM LOGIC HERE - Pure Python processing"""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        # Example processing (replace with your logic)
        words = query.split()
        response = f"Processed: {query}"
        
        return {
            "status": "success",
            "timestamp": timestamp,
            "query": query,
            "response": response,
            "word_count": len(words),
            "char_count": len(query),
            "processed_at": timestamp
        }

    def get_html_template(self):
        """Interactive HTML interface"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Pure Python API</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        *{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;max-width:800px;margin:0 auto;padding:20px;background:#f5f7fa}.container{background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.1)}h1{color:#1a202c;margin-bottom:30px;font-size:2em}.input-group{margin-bottom:20px}input{width:100%;padding:16px;font-size:16px;border:2px solid #e2e8f0;border-radius:8px;transition:all .3s}input:focus{outline:0;border-color:#4299e1;box-shadow:0 0 0 3px rgba(66,153,225,.1)}button{width:100%;padding:16px;font-size:16px;background:#4299e1;color:#fff;border:0;border-radius:8px;cursor:pointer;transition:background .3s;font-weight:500}button:hover{background:#3182ce}button:disabled{background:#a0aec0;cursor:not-allowed}#response{margin-top:30px;padding:20px;background:#f7fafc;border-radius:8px;border-left:4px solid #4299e1;min-height:100px}#response pre{margin:0;padding:16px;background:#fff;border-radius:6px;font-size:14px;overflow-x:auto;white-space:pre-wrap}.loading{color:#718096}.error{border-left-color:#f56565;background:#fed7d7;color:#742a2a}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Pure Python API</h1>
        <div class="input-group">
            <input type="text" id="query" placeholder="Enter your query..." maxlength="1000">
        </div>
        <button onclick="sendRequest()">Send Request</button>
        <div id="response"></div>
    </div>
    <script>
        async function sendRequest(){const e=document.getElementById('query').value.trim(),t=document.getElementById('response'),n=document.querySelector('button');if(!e)return t.innerHTML='<pre class="error">Please enter a query!</pre>';n.disabled=!0,n.textContent='Processing...',t.innerHTML='<pre class="loading">Processing...</pre>';try{const o=await fetch('/api/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:e})}),r=await o.json();o.ok?t.innerHTML='<pre>'+JSON.stringify(r,null,2)+'</pre>':t.innerHTML='<pre class="error">Error: '+(r.error||'Unknown error')+'</pre>'}catch(e){t.innerHTML='<pre class="error">Error: '+e.message+'</pre>'}finally{n.disabled=!1,n.textContent='Send Request'}}document.getElementById('query').addEventListener('keypress',e=>'Enter'===e.key&&sendRequest());
    </script>
</body>
</html>"""

def run_server(port=10000):
    """Start the server"""
    port = int(os.environ.get('PORT', str(port)))
    host = '0.0.0.0'
    
    logger.info(f"Starting Pure Python server on {host}:{port}")
    logger.info("Endpoints: / (web UI), /api/query (POST), /health")
    
    server = ThreadedHTTPServer((host, port), RequestHandler)
    server.serve_forever()

if __name__ == '__main__':
    run_server()

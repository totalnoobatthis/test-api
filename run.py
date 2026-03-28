#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run.py - Main application handler
"""

import os
import logging
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from werkzeug.exceptions import BadRequest

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# HTML template for the main page
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>API Service</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .container { background: #f5f5f5; padding: 30px; border-radius: 10px; }
        input, button { padding: 10px; margin: 5px; font-size: 16px; }
        button { background: #007cba; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #005a87; }
        #response { margin-top: 20px; padding: 15px; background: white; border-radius: 5px; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body>
    <div class="container">
        <h1>API Service</h1>
        <input type="text" id="query" placeholder="Enter your query..." style="width: 70%;">
        <button onclick="sendRequest()">Send Request</button>
        <div id="response"></div>
    </div>

    <script>
        async function sendRequest() {
            const query = document.getElementById('query').value;
            const responseDiv = document.getElementById('response');
            
            try {
                responseDiv.innerHTML = '<pre>Loading...</pre>';
                const response = await fetch('/api/query', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({query: query})
                });
                const data = await response.json();
                responseDiv.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            } catch (error) {
                responseDiv.innerHTML = '<pre>Error: ' + error.message + '</pre>';
            }
        }
    </script>
</body>
</html>
"""

def process_query(query):
    """Process the incoming query - replace with your logic"""
    # Example processing logic
    timestamp = datetime.now().isoformat()
    
    return {
        "status": "success",
        "timestamp": timestamp,
        "query": query,
        "response": f"Processed: {query}",
        "processed_at": timestamp
    }

@app.route('/', methods=['GET'])
def do_get():
    """Main handler for GET requests - serves the web interface"""
    try:
        user_agent = request.headers.get('User-Agent', '')
        ip = request.remote_addr or 'unknown'
        
        logger.info(f"GET / - User-Agent: {user_agent[:100]}..., IP: {ip}")
        
        # Serve the HTML interface
        return render_template_string(HTML_TEMPLATE), 200
        
    except Exception as e:
        logger.error(f"Error in do_get: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500

@app.route('/api/query', methods=['POST'])
def api_query():
    """API endpoint for processing queries"""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({"error": "Missing 'query' field"}), 400
        
        query = data['query'].strip()
        if not query:
            return jsonify({"error": "Query cannot be empty"}), 400
        
        result = process_query(query)
        return jsonify(result), 200
        
    except BadRequest:
        return jsonify({"error": "Invalid JSON"}), 400
    except Exception as e:
        logger.error(f"Error in api_query: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    # For local development
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=True)

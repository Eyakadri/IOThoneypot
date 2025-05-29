#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Logging and event tracking for the IoT Honeypot.
Provides a unified interface for logging events, attacks, and system messages.
"""

import os
import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional

# Configure standard Python logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Thread-safe lock for file operations
_log_lock = threading.Lock()

class EventLogger:
    """Event logger for the IoT Honeypot."""
    
    def __init__(self, log_file: str = "logs/honeypot.log"):
        """
        Initialize the event logger.
        
        Args:
            log_file: Path to log file
        """
        self.log_file = log_file
        self.logger = logging.getLogger("honeypot")
        
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Initialize log file with header if it doesn't exist
        if not os.path.exists(log_file):
            with open(log_file, "w") as f:
                f.write(f"# IoT Honeypot Log - Started {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# Format: JSON entries, one per line\n")
    
    def log_event(self, event_type: str, source_ip: str, protocol: str, details: Dict[str, Any]) -> None:
        """
        Log an event to the honeypot log file.
        
        Args:
            event_type: Type of event (e.g., 'connection', 'login_attempt', 'command')
            source_ip: Source IP address
            protocol: Protocol (e.g., 'telnet', 'http')
            details: Additional event details
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        log_entry = {
            "timestamp": timestamp,
            "type": "event",
            "event_type": event_type,
            "source_ip": source_ip,
            "protocol": protocol,
            "details": details
        }
        
        self._write_log_entry(log_entry)
        self.logger.info(f"Event: {event_type} from {source_ip} via {protocol}")
    
    def log_attack(self, attack_type: str, source_ip: str, protocol: str, details: Dict[str, Any]) -> None:
        """
        Log an attack to the honeypot log file.
        
        Args:
            attack_type: Type of attack (e.g., 'brute_force', 'command_injection')
            source_ip: Source IP address
            protocol: Protocol (e.g., 'telnet', 'http')
            details: Additional attack details
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        log_entry = {
            "timestamp": timestamp,
            "type": "attack",
            "attack_type": attack_type,
            "source_ip": source_ip,
            "protocol": protocol,
            "details": details
        }
        
        self._write_log_entry(log_entry)
        self.logger.warning(f"Attack: {attack_type} from {source_ip} via {protocol}")
    
    def log_malware(self, source_ip: str, protocol: str, file_hash: str, details: Dict[str, Any]) -> None:
        """
        Log malware capture to the honeypot log file.
        
        Args:
            source_ip: Source IP address
            protocol: Protocol (e.g., 'telnet', 'http')
            file_hash: Hash of captured file
            details: Additional malware details
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        log_entry = {
            "timestamp": timestamp,
            "type": "malware",
            "source_ip": source_ip,
            "protocol": protocol,
            "file_hash": file_hash,
            "details": details
        }
        
        self._write_log_entry(log_entry)
        self.logger.critical(f"Malware: Captured from {source_ip} via {protocol}, hash: {file_hash}")
    
    def log_system(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Log system message to the honeypot log file.
        
        Args:
            message: System message
            details: Additional system details
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        log_entry = {
            "timestamp": timestamp,
            "type": "system",
            "message": message,
            "details": details or {}
        }
        
        self._write_log_entry(log_entry)
        self.logger.info(f"System: {message}")
    
    def _write_log_entry(self, log_entry: Dict[str, Any]) -> None:
        """
        Write a log entry to the log file.
        
        Args:
            log_entry: Log entry dictionary
        """
        try:
            with _log_lock:
                with open(self.log_file, "a") as f:
                    json.dump(log_entry, f)
                    f.write("\n")
        except Exception as e:
            self.logger.error(f"Error writing to log file: {e}")
    
    def get_recent_events(self, count: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recent events from the log file.
        
        Args:
            count: Maximum number of events to return
            event_type: Filter by event type (e.g., 'event', 'attack', 'malware', 'system')
            
        Returns:
            List of recent events
        """
        events = []
        
        try:
            with _log_lock:
                if not os.path.exists(self.log_file):
                    return []
                
                with open(self.log_file, "r") as f:
                    # Skip header lines
                    for line in f:
                        if line.startswith("#"):
                            continue
                        
                        try:
                            entry = json.loads(line)
                            
                            # Filter by event type if specified
                            if event_type and entry.get("type") != event_type:
                                continue
                            
                            events.append(entry)
                            
                            # Keep only the most recent events
                            if len(events) > count:
                                events.pop(0)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            self.logger.error(f"Error reading log file: {e}")
        
        return events

# Singleton instance
_event_logger = None

def get_event_logger(log_file: Optional[str] = None) -> EventLogger:
    """
    Get the singleton EventLogger instance.
    
    Args:
        log_file: Path to log file
        
    Returns:
        EventLogger instance
    """
    global _event_logger
    
    if _event_logger is None:
        _event_logger = EventLogger(log_file)
    
    return _event_logger

# For direct testing
if __name__ == "__main__":
    # Create test log directory
    os.makedirs("logs", exist_ok=True)
    
    # Test logging
    logger = get_event_logger("logs/test.log")
    
    # Log some test events
    logger.log_system("Honeypot started")
    logger.log_event("connection", "192.168.1.100", "telnet", {"port": 23})
    logger.log_event("login_attempt", "192.168.1.100", "telnet", {"username": "admin", "password": "password123"})
    logger.log_attack("brute_force", "192.168.1.100", "telnet", {"attempts": 5, "last_username": "root"})
    logger.log_event("command", "192.168.1.100", "telnet", {"command": "ls -la"})
    logger.log_malware("192.168.1.100", "http", "a1b2c3d4e5f6", {"filename": "malware.bin", "size": 1024})
    
    # Get recent events
    recent_events = logger.get_recent_events(count=3)
    print(f"Recent events (last 3):")
    for event in recent_events:
        print(json.dumps(event, indent=2))
    
    # Get recent attacks
    recent_attacks = logger.get_recent_events(event_type="attack")
    print(f"\nRecent attacks:")
    for attack in recent_attacks:
        print(json.dumps(attack, indent=2))

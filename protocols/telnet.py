#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telnet protocol handler for the IoT Honeypot.
Implements a realistic Telnet server emulating IoT devices.
"""

import socket
import threading
import time
import logging
import re
from typing import Dict, Any, Optional, Tuple, List

# Import base protocol handler
from .base import BaseProtocolHandler

# Configure logging
logger = logging.getLogger("honeypot.protocols.telnet")

# Telnet protocol constants
IAC = bytes([255])  # Interpret As Command
DONT = bytes([254])
DO = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
SB = bytes([250])  # Subnegotiation Begin
SE = bytes([240])  # Subnegotiation End

# Telnet options
OPT_ECHO = bytes([1])
OPT_SGA = bytes([3])  # Suppress Go Ahead
OPT_TTYPE = bytes([24])  # Terminal Type
OPT_NAWS = bytes([31])  # Negotiate About Window Size

class TelnetHandler(BaseProtocolHandler):
    """Telnet protocol handler for IoT device emulation."""
    
    def __init__(self):
        """Initialize the Telnet protocol handler."""
        super().__init__("telnet")
        
        # Authentication settings
        self.max_auth_attempts = 3
        
        # Session state
        self.sessions = {}  # client_address -> session_info
    
    def handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
        """
        Handle a Telnet client connection.
        
        Args:
            client_socket: Client socket
            client_address: Client address tuple (ip, port)
        """
        source_ip = client_address[0]
        session_id = f"{source_ip}:{client_address[1]}"
        
        # Create session
        self.sessions[session_id] = {
            "socket": client_socket,
            "address": client_address,
            "authenticated": False,
            "username": None,
            "auth_attempts": 0,
            "commands": [],
            "start_time": time.time()
        }
        
        # Log connection
        self.log_interaction(source_ip, "connection", {
            "port": client_address[1],
            "protocol": "telnet",
            "session_id": session_id
        })
        
        try:
            # Perform Telnet negotiation
            self._telnet_negotiation(client_socket)
            
            # Send banner
            banner = self.get_banner()
            client_socket.sendall(banner.encode('utf-8', errors='ignore'))
            
            # Authentication loop
            if not self._authenticate(client_socket, source_ip, session_id):
                return
            
            # Command loop
            self._command_loop(client_socket, source_ip, session_id)
            
        except (socket.error, ConnectionResetError) as e:
            logger.error(f"Connection error with {source_ip}: {e}")
            self.log_interaction(source_ip, "connection_error", {
                "error": str(e),
                "session_id": session_id
            })
        except Exception as e:
            logger.error(f"Error handling Telnet client {source_ip}: {e}")
            self.log_interaction(source_ip, "error", {
                "error": str(e),
                "session_id": session_id
            })
        finally:
            # Clean up
            try:
                client_socket.close()
            except:
                pass
            
            # Log disconnection
            self.log_interaction(source_ip, "disconnection", {
                "duration": time.time() - self.sessions[session_id]["start_time"],
                "commands": len(self.sessions[session_id]["commands"]),
                "session_id": session_id
            })
            
            # Remove session
            if session_id in self.sessions:
                del self.sessions[session_id]
    
    def _telnet_negotiation(self, client_socket: socket.socket) -> None:
        """
        Perform Telnet option negotiation.
        
        Args:
            client_socket: Client socket
        """
        # Send initial negotiation
        # WILL ECHO, WILL SGA
        client_socket.sendall(IAC + WILL + OPT_ECHO)
        client_socket.sendall(IAC + WILL + OPT_SGA)
        
        # DO TTYPE, DO NAWS
        client_socket.sendall(IAC + DO + OPT_TTYPE)
        client_socket.sendall(IAC + DO + OPT_NAWS)
        
        # Give client time to respond
        time.sleep(0.1)
        
        # Read any pending data (negotiation responses)
        try:
            client_socket.settimeout(0.5)
            data = client_socket.recv(1024)
            # Process negotiation responses if needed
        except socket.timeout:
            pass
        finally:
            client_socket.settimeout(None)
    
    def _authenticate(self, client_socket: socket.socket, source_ip: str, session_id: str) -> bool:
        """
        Authenticate the client.
        
        Args:
            client_socket: Client socket
            source_ip: Source IP address
            session_id: Session ID
            
        Returns:
            True if authentication is successful, False otherwise
        """
        session = self.sessions[session_id]
        attempts = 0
        
        while attempts < self.max_auth_attempts:
            # Get username
            username = self._get_input(client_socket, "").strip()
            if not username:
                return False
            
            # Get password
            password = self._get_input(client_socket, "Password: ").strip()
            if not password:
                return False
            
            # Log authentication attempt
            self.log_interaction(source_ip, "login_attempt", {
                "username": username,
                "password": password,
                "session_id": session_id
            })
            
            # Check credentials
            if self.authenticate(username, password):
                # Authentication successful
                client_socket.sendall(b"\r\nLogin successful!\r\n")
                
                # Update session
                session["authenticated"] = True
                session["username"] = username
                
                # Log successful authentication
                self.log_interaction(source_ip, "login_success", {
                    "username": username,
                    "session_id": session_id
                })
                
                return True
            else:
                # Authentication failed
                attempts += 1
                session["auth_attempts"] += 1
                
                if attempts < self.max_auth_attempts:
                    client_socket.sendall(b"\r\nLogin incorrect\r\n\r\nLogin: ")
                else:
                    client_socket.sendall(b"\r\nLogin incorrect\r\nMaximum login attempts exceeded\r\n")
                    
                    # Log failed authentication
                    self.log_interaction(source_ip, "login_failure", {
                        "username": username,
                        "attempts": attempts,
                        "session_id": session_id
                    })
                    
                    # Check for brute force attack
                    if attempts >= self.max_auth_attempts:
                        self.log_attack(source_ip, "brute_force", {
                            "attempts": attempts,
                            "last_username": username,
                            "session_id": session_id
                        })
                    
                    return False
        
        return False
    
    def _command_loop(self, client_socket: socket.socket, source_ip: str, session_id: str) -> None:
        """
        Handle the command loop after successful authentication.
        
        Args:
            client_socket: Client socket
            source_ip: Source IP address
            session_id: Session ID
        """
        session = self.sessions[session_id]
        
        # Get device profile for prompt
        device_profile = self.device_manager.get_device_profile(self.device_type)
        telnet_config = device_profile.get("telnet", {})
        prompt = telnet_config.get("prompt", "# ")
        
        # Send initial prompt
        client_socket.sendall(prompt.encode('utf-8', errors='ignore'))
        
        while True:
            # Get command
            command = self._get_input(client_socket, "").strip()
            if not command:
                break
            
            # Log command
            self.log_interaction(source_ip, "command", {
                "command": command,
                "session_id": session_id
            })
            
            # Add to command history
            session["commands"].append(command)
            
            # Check for exit command
            if command.lower() in ["exit", "logout", "quit"]:
                client_socket.sendall(b"\r\nGoodbye!\r\n")
                break
            
            # Check for reboot command
            if command.lower() in ["reboot", "restart"]:
                client_socket.sendall(b"\r\nThe system is going down for reboot NOW!\r\n")
                time.sleep(1)
                break
            
            # Get command response
            response = self.get_command_response(command)
            
            # Check for potential command injection
            if self._check_command_injection(command):
                self.log_attack(source_ip, "command_injection", {
                    "command": command,
                    "session_id": session_id
                })
            
            # Send response
            client_socket.sendall(response.encode('utf-8', errors='ignore'))
            
            # Send prompt
            client_socket.sendall(prompt.encode('utf-8', errors='ignore'))
    
    def _get_input(self, client_socket: socket.socket, prompt: str) -> str:
        """
        Get input from the client.
        
        Args:
            client_socket: Client socket
            prompt: Prompt to display
            
        Returns:
            Input string
        """
        if prompt:
            client_socket.sendall(prompt.encode('utf-8', errors='ignore'))
        
        buffer = ""
        while True:
            try:
                data = client_socket.recv(1)
                if not data:
                    return ""
                
                # Handle backspace
                if data == b'\x08' or data == b'\x7f':
                    if buffer:
                        buffer = buffer[:-1]
                        client_socket.sendall(b'\x08 \x08')
                    continue
                
                # Handle enter
                if data == b'\r':
                    client_socket.sendall(b'\r\n')
                    break
                
                # Handle other characters
                if data.isalnum() or data in b' !@#$%^&*()-_=+[]{}|;:\'",.<>/?`~':
                    buffer += data.decode('utf-8', errors='ignore')
                    
                    # Echo character if it's a password prompt
                    if "password" in prompt.lower():
                        client_socket.sendall(b'*')
                    else:
                        client_socket.sendall(data)
            except Exception as e:
                logger.error(f"Error getting input: {e}")
                return ""
        
        return buffer
    
    def _check_command_injection(self, command: str) -> bool:
        """
        Check if a command contains potential command injection.
        
        Args:
            command: Command string
            
        Returns:
            True if command injection is detected, False otherwise
        """
        # Check for common command injection patterns
        patterns = [
            r'[;&|`]',  # Shell command separators
            r'\$\(',    # Command substitution
            r'>\s*/',   # Redirection to system directories
            r'<\s*/',   # Input from system files
        ]
        
        for pattern in patterns:
            if re.search(pattern, command):
                return True
        
        return False

def start_telnet_server(port: int, device_type: str) -> None:
    """
    Start the Telnet server.
    
    Args:
        port: Port to listen on
        device_type: Device type to emulate
    """
    handler = TelnetHandler()
    handler.start(port, device_type)

# For direct testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create necessary directories
    import os
    os.makedirs("logs", exist_ok=True)
    
    # Start server
    start_telnet_server(2323, "router")

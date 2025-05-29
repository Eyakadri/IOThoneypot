#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base protocol handler for the IoT Honeypot.
Provides common functionality for all protocol handlers.
"""

import socket
import threading
import logging
import time
from typing import Dict, Any, Optional, Tuple, Callable

# Import core modules
from ..core.logger import get_event_logger
from ..core.devices import get_device_profile_manager

# Configure logging
logger = logging.getLogger("honeypot.protocols")

class BaseProtocolHandler:
    """Base protocol handler with common functionality."""
    
    def __init__(self, protocol_name: str):
        """
        Initialize the base protocol handler.
        
        Args:
            protocol_name: Protocol name (e.g., 'telnet', 'http')
        """
        self.protocol_name = protocol_name
        self.running = False
        self.server_socket = None
        self.client_threads = []
        self.event_logger = get_event_logger()
        self.device_manager = get_device_profile_manager()
    
    def start(self, port: int, device_type: str) -> None:
        """
        Start the protocol handler.
        
        Args:
            port: Port to listen on
            device_type: Device type to emulate
        """
        if self.running:
            logger.warning(f"{self.protocol_name.upper()} handler already running")
            return
        
        self.port = port
        self.device_type = device_type
        self.running = True
        
        # Create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(5)
            
            logger.info(f"{self.protocol_name.upper()} handler started on port {port}")
            self.event_logger.log_system(f"{self.protocol_name.upper()} handler started", {
                "port": port,
                "device_type": device_type
            })
            
            # Accept connections in a loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Start client handler thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                    self.client_threads.append(client_thread)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  # Only log if we're still supposed to be running
                        logger.error(f"Error accepting connection: {e}")
                        self.event_logger.log_system(f"Error in {self.protocol_name} handler", {
                            "error": str(e),
                            "stage": "accept"
                        })
            
        except Exception as e:
            logger.error(f"Error starting {self.protocol_name.upper()} handler: {e}")
            self.event_logger.log_system(f"Error starting {self.protocol_name} handler", {
                "error": str(e)
            })
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the protocol handler."""
        self.running = False
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                logger.error(f"Error closing server socket: {e}")
        
        # Wait for client threads to finish
        for thread in self.client_threads:
            if thread.is_alive():
                thread.join(timeout=1)
        
        logger.info(f"{self.protocol_name.upper()} handler stopped")
        self.event_logger.log_system(f"{self.protocol_name.upper()} handler stopped", {})
    
    def handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
        """
        Handle a client connection.
        
        Args:
            client_socket: Client socket
            client_address: Client address tuple (ip, port)
        """
        # This method should be overridden by subclasses
        raise NotImplementedError("Subclasses must implement handle_client")
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate a user.
        
        Args:
            username: Username
            password: Password
            
        Returns:
            True if authentication is successful, False otherwise
        """
        return self.device_manager.authenticate(self.device_type, self.protocol_name, username, password)
    
    def log_interaction(self, source_ip: str, event_type: str, details: Dict[str, Any]) -> None:
        """
        Log an interaction.
        
        Args:
            source_ip: Source IP address
            event_type: Event type
            details: Event details
        """
        self.event_logger.log_event(event_type, source_ip, self.protocol_name, details)
    
    def log_attack(self, source_ip: str, attack_type: str, details: Dict[str, Any]) -> None:
        """
        Log an attack.
        
        Args:
            source_ip: Source IP address
            attack_type: Attack type
            details: Attack details
        """
        self.event_logger.log_attack(attack_type, source_ip, self.protocol_name, details)
    
    def get_banner(self) -> str:
        """
        Get the banner for the current device type.
        
        Returns:
            Banner string
        """
        return self.device_manager.get_banner(self.device_type, self.protocol_name)
    
    def get_command_response(self, command: str) -> str:
        """
        Get response for a command.
        
        Args:
            command: Command string
            
        Returns:
            Command response string
        """
        return self.device_manager.get_command_response(self.device_type, command)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main entry point for the IoT Honeypot.
Initializes and coordinates all components.
"""

import os
import sys
import time
import signal
import logging
import argparse
import threading
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

logger = logging.getLogger("honeypot")

# Global variables
running = True
threads = []

def signal_handler(sig, frame):
    """Handle signals to gracefully shut down."""
    global running
    logger.info("Shutting down...")
    running = False

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='IoT Honeypot')
    
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-d', '--device', type=str, default='router', 
                        choices=['router', 'ip_camera', 'dvr'], 
                        help='Device type to emulate')
    parser.add_argument('--telnet-port', type=int, help='Telnet port (overrides config)')
    parser.add_argument('--http-port', type=int, help='HTTP port (overrides config)')
    parser.add_argument('--dashboard-port', type=int, help='Dashboard port (overrides config)')
    parser.add_argument('--no-dashboard', action='store_true', help='Disable dashboard')
    parser.add_argument('--no-telnet', action='store_true', help='Disable Telnet')
    parser.add_argument('--no-http', action='store_true', help='Disable HTTP')
    
    return parser.parse_args()

def main():
    """Main entry point."""
    global running, threads
    
    # Parse arguments
    args = parse_arguments()
    
    # Initialize configuration
    config_manager = get_config_manager(args.config)
    
    # Initialize logger
    event_logger = get_event_logger()
    
    # Initialize device profile manager
    device_manager = get_device_profile_manager()
    
    # Initialize malware handler
    malware_handler = get_malware_handler()
    
    # Log startup
    logger.info("Starting IoT Honeypot...")
    event_logger.log_system("Honeypot started", {
        "device_type": args.device,
        "version": "1.0.0"
    })
    
    # Create necessary directories
    os.makedirs("logs", exist_ok=True)
    os.makedirs("data", exist_ok=True)
    os.makedirs("captures", exist_ok=True)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start services
    try:
        # Start Telnet server
        if not args.no_telnet and config_manager.is_protocol_enabled("telnet"):
            telnet_config = config_manager.get_protocol_config("telnet")
            telnet_port = args.telnet_port or telnet_config.get("port", 23)
            
            telnet_thread = threading.Thread(
                target=start_telnet_server,
                args=(telnet_port, args.device)
            )
            telnet_thread.daemon = True
            telnet_thread.start()
            threads.append(telnet_thread)
            
            logger.info(f"Telnet server started on port {telnet_port}")
        
        # Start HTTP server
        if not args.no_http and config_manager.is_protocol_enabled("http"):
            http_config = config_manager.get_protocol_config("http")
            http_port = args.http_port or http_config.get("port", 80)
            
            http_thread = threading.Thread(
                target=start_http_server,
                args=(http_port, args.device)
            )
            http_thread.daemon = True
            http_thread.start()
            threads.append(http_thread)
            
            logger.info(f"HTTP server started on port {http_port}")
        
        # Start dashboard
        if not args.no_dashboard and config_manager.is_dashboard_enabled():
            dashboard_config = config_manager.get_dashboard_config()
            dashboard_port = args.dashboard_port or dashboard_config.get("port", 8080)
            
            dashboard_thread = threading.Thread(
                target=start_dashboard,
                args=(dashboard_port,)
            )
            dashboard_thread.daemon = True
            dashboard_thread.start()
            threads.append(dashboard_thread)
            
            logger.info(f"Dashboard started on port {dashboard_port}")
        
        # Keep main thread alive
        while running:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Error in main thread: {e}")
    finally:
        # Shutdown
        running = False
        
        # Wait for threads to finish
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=1)
        
        # Log shutdown
        event_logger.log_system("Honeypot stopped", {})
        logger.info("Honeypot stopped")

if __name__ == "__main__":
    main()

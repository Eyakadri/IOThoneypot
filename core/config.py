#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration management for the IoT Honeypot.
Handles loading, validation, and access to configuration settings.
"""

import os
import json
import yaml
import logging
from typing import Dict, Any, Optional

# Default configuration
DEFAULT_CONFIG = {
    "general": {
        "name": "IoT Honeypot",
        "version": "1.0.0",
        "log_level": "INFO",
        "log_file": "logs/honeypot.log",
        "data_dir": "data"
    },
    "protocols": {
        "telnet": {
            "enabled": True,
            "port": 23,
            "max_connections": 10,
            "timeout": 300,
            "banner_delay": 1
        },
        "http": {
            "enabled": True,
            "port": 80,
            "max_connections": 20,
            "timeout": 60
        }
    },
    "devices": {
        "default_type": "router",
        "types": ["router", "ip_camera", "dvr"]
    },
    "dashboard": {
        "enabled": True,
        "port": 8080,
        "refresh_rate": 5,
        "max_events": 100
    },
    "security": {
        "malware_capture": True,
        "capture_dir": "captures",
        "max_file_size": 1048576,  # 1MB
        "signature_file": "security/signatures.json"
    }
}

class ConfigManager:
    """Configuration manager for the IoT Honeypot."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to configuration file (JSON or YAML)
        """
        self.config = DEFAULT_CONFIG.copy()
        self.config_path = config_path
        
        if config_path:
            self.load_config(config_path)
    
    def load_config(self, config_path: str) -> bool:
        """
        Load configuration from file.
        
        Args:
            config_path: Path to configuration file (JSON or YAML)
            
        Returns:
            True if configuration was loaded successfully, False otherwise
        """
        if not os.path.exists(config_path):
            logging.error(f"Configuration file not found: {config_path}")
            return False
        
        try:
            ext = os.path.splitext(config_path)[1].lower()
            
            if ext == '.json':
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
            elif ext in ['.yaml', '.yml']:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
            else:
                logging.error(f"Unsupported configuration file format: {ext}")
                return False
            
            # Merge user configuration with defaults
            self._merge_config(self.config, user_config)
            
            logging.info(f"Configuration loaded from {config_path}")
            return True
            
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")
            return False
    
    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]) -> None:
        """
        Recursively merge override configuration into base configuration.
        
        Args:
            base: Base configuration dictionary
            override: Override configuration dictionary
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get the complete configuration.
        
        Returns:
            Complete configuration dictionary
        """
        return self.config
    
    def get_protocol_config(self, protocol_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific protocol.
        
        Args:
            protocol_name: Protocol name (e.g., 'telnet', 'http')
            
        Returns:
            Protocol configuration dictionary
        """
        protocols = self.config.get('protocols', {})
        return protocols.get(protocol_name, {})
    
    def get_device_config(self, device_type: str) -> Dict[str, Any]:
        """
        Get configuration for a specific device type.
        
        Args:
            device_type: Device type (e.g., 'router', 'ip_camera', 'dvr')
            
        Returns:
            Device configuration dictionary
        """
        devices = self.config.get('devices', {})
        device_types = devices.get('types', [])
        
        if device_type not in device_types:
            logging.warning(f"Unknown device type: {device_type}, using default")
            device_type = devices.get('default_type', 'router')
        
        # In a real implementation, we would have device-specific configs
        # For now, we just return a placeholder
        return {
            'type': device_type,
            'name': f"{device_type.capitalize()} Device",
            'firmware': "1.0.0"
        }
    
    def get_dashboard_config(self) -> Dict[str, Any]:
        """
        Get dashboard configuration.
        
        Returns:
            Dashboard configuration dictionary
        """
        return self.config.get('dashboard', {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """
        Get security configuration.
        
        Returns:
            Security configuration dictionary
        """
        return self.config.get('security', {})
    
    def is_protocol_enabled(self, protocol_name: str) -> bool:
        """
        Check if a protocol is enabled.
        
        Args:
            protocol_name: Protocol name (e.g., 'telnet', 'http')
            
        Returns:
            True if protocol is enabled, False otherwise
        """
        protocol_config = self.get_protocol_config(protocol_name)
        return protocol_config.get('enabled', False)
    
    def is_dashboard_enabled(self) -> bool:
        """
        Check if the dashboard is enabled.
        
        Returns:
            True if dashboard is enabled, False otherwise
        """
        dashboard_config = self.get_dashboard_config()
        return dashboard_config.get('enabled', False)
    
    def is_malware_capture_enabled(self) -> bool:
        """
        Check if malware capture is enabled.
        
        Returns:
            True if malware capture is enabled, False otherwise
        """
        security_config = self.get_security_config()
        return security_config.get('malware_capture', False)

# Singleton instance
_config_manager = None

def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    """
    Get the singleton ConfigManager instance.
    
    Args:
        config_path: Path to configuration file (JSON or YAML)
        
    Returns:
        ConfigManager instance
    """
    global _config_manager
    
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    
    return _config_manager

# For direct testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create a test configuration file
    test_config = {
        "general": {
            "name": "Test Honeypot"
        },
        "protocols": {
            "telnet": {
                "port": 2323
            }
        }
    }
    
    test_config_path = "test_config.json"
    with open(test_config_path, 'w') as f:
        json.dump(test_config, f, indent=2)
    
    # Test loading configuration
    config_manager = get_config_manager(test_config_path)
    
    # Print configuration
    print("Complete configuration:")
    print(json.dumps(config_manager.get_config(), indent=2))
    
    print("\nTelnet configuration:")
    print(json.dumps(config_manager.get_protocol_config('telnet'), indent=2))
    
    print("\nRouter configuration:")
    print(json.dumps(config_manager.get_device_config('router'), indent=2))
    
    # Clean up
    os.remove(test_config_path)

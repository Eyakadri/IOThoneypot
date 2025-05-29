#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Device profile management for the IoT Honeypot.
Provides device profiles, command responses, and behavior configuration.
"""

import os
import json
import random
import logging
from typing import Dict, Any, List, Optional, Tuple

# Configure logging
logger = logging.getLogger("honeypot.devices")

class DeviceProfileManager:
    """Device profile manager for the IoT Honeypot."""
    
    def __init__(self, profiles_dir: str = "data/profiles"):
        """
        Initialize the device profile manager.
        
        Args:
            profiles_dir: Directory containing device profiles
        """
        self.profiles_dir = profiles_dir
        self.profiles = {}
        
        # Create profiles directory if it doesn't exist
        if not os.path.exists(profiles_dir):
            os.makedirs(profiles_dir, exist_ok=True)
        
        # Load built-in profiles
        self._load_builtin_profiles()
    
    def _load_builtin_profiles(self) -> None:
        """Load built-in device profiles."""
        # Router profile
        router_profile = {
            "type": "router",
            "name": "Generic Router",
            "manufacturer": "NetDevice",
            "model": "HomeRouter 2000",
            "firmware": "1.2.3",
            "services": ["telnet", "http", "ssh"],
            "telnet": {
                "enabled": True,
                "banner": "Welcome to \r\n\r\nNetDevice HomeRouter 2000\r\n\r\nLogin: ",
                "prompt": "router> ",
                "admin_prompt": "router# ",
                "credentials": [
                    {"username": "admin", "password": "admin"},
                    {"username": "root", "password": "root"},
                    {"username": "user", "password": "user"}
                ],
                "filesystem": {
                    "/": {"type": "dir"},
                    "/bin": {"type": "dir"},
                    "/etc": {"type": "dir"},
                    "/etc/config": {"type": "file", "content": "# Router Configuration\nWAN_INTERFACE=eth0\nLAN_INTERFACE=eth1\nWIFI_ENABLED=1\nSSID=HomeRouter\nPASSWORD=password123\n"},
                    "/etc/passwd": {"type": "file", "content": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\n"},
                    "/var": {"type": "dir"},
                    "/var/log": {"type": "dir"}
                },
                "commands": {
                    "help": "Available commands: help, exit, ls, cat, ps, ifconfig, route, reboot, passwd\r\n",
                    "ls": "bin  dev  etc  lib  proc  sbin  tmp  usr  var\r\n",
                    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\n",
                    "ifconfig": "eth0      Link encap:Ethernet  HWaddr 00:11:22:33:44:55  \n          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\n          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n\neth1      Link encap:Ethernet  HWaddr 66:77:88:99:AA:BB  \n          inet addr:10.0.0.1  Bcast:10.0.0.255  Mask:255.255.255.0\n          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n",
                    "route": "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n0.0.0.0         192.168.1.254   0.0.0.0         UG    0      0        0 eth0\n192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0 eth0\n10.0.0.0        0.0.0.0         255.255.255.0   U     0      0        0 eth1\n",
                    "ps": "  PID USER       VSZ STAT COMMAND\n    1 root      1200 S    init       \n    2 root      1300 S    httpd\n    3 root      1100 S    telnetd\n    4 root      1400 S    dnsmasq\n",
                    "reboot": "System is going down for reboot now.\r\n",
                    "passwd": "Changing password for admin\nNew password: "
                }
            },
            "http": {
                "enabled": True,
                "title": "NetDevice HomeRouter 2000",
                "server": "httpd/1.0",
                "credentials": [
                    {"username": "admin", "password": "admin"}
                ],
                "pages": {
                    "/": {"title": "Login", "template": "router_login.html"},
                    "/login.cgi": {"title": "Login Process", "template": None},
                    "/status.html": {"title": "Router Status", "template": "router_status.html", "auth": True},
                    "/network.html": {"title": "Network Settings", "template": "router_network.html", "auth": True},
                    "/wireless.html": {"title": "Wireless Settings", "template": "router_wireless.html", "auth": True},
                    "/admin.html": {"title": "Administration", "template": "router_admin.html", "auth": True}
                }
            }
        }
        
        # IP Camera profile
        camera_profile = {
            "type": "ip_camera",
            "name": "IP Security Camera",
            "manufacturer": "SecureCam",
            "model": "SC-1080P",
            "firmware": "2.4.1",
            "services": ["telnet", "http", "rtsp"],
            "telnet": {
                "enabled": True,
                "banner": "Welcome to \r\n\r\nSecureCam SC-1080P\r\n\r\nLogin: ",
                "prompt": "camera> ",
                "admin_prompt": "camera# ",
                "credentials": [
                    {"username": "admin", "password": "admin"},
                    {"username": "root", "password": "123456"}
                ],
                "filesystem": {
                    "/": {"type": "dir"},
                    "/bin": {"type": "dir"},
                    "/etc": {"type": "dir"},
                    "/etc/config": {"type": "file", "content": "# Camera Configuration\nRESOLUTION=1080p\nFRAMERATE=30\nRTSP_PORT=554\nHTTP_PORT=80\nUSERNAME=admin\nPASSWORD=admin\n"},
                    "/etc/passwd": {"type": "file", "content": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\n"},
                    "/var": {"type": "dir"},
                    "/var/log": {"type": "dir"},
                    "/mnt": {"type": "dir"},
                    "/mnt/sd": {"type": "dir"}
                },
                "commands": {
                    "help": "Available commands: help, exit, ls, cat, ps, reboot, get_status, set_resolution\r\n",
                    "ls": "bin  dev  etc  lib  mnt  proc  sbin  tmp  usr  var\r\n",
                    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\n",
                    "ps": "  PID USER       VSZ STAT COMMAND\n    1 root      1200 S    init       \n    2 root      1300 S    httpd\n    3 root      1100 S    telnetd\n    4 root      2400 S    rtspd\n    5 root      1800 S    recorder\n",
                    "reboot": "System is going down for reboot now.\r\n",
                    "get_status": "Camera Status:\nResolution: 1080p\nFramerate: 30fps\nRecording: Active\nStorage: 68% used\n",
                    "set_resolution": "Usage: set_resolution [720p|1080p|4K]\n"
                }
            },
            "http": {
                "enabled": True,
                "title": "SecureCam SC-1080P",
                "server": "lighttpd/1.4.45",
                "credentials": [
                    {"username": "admin", "password": "admin"}
                ],
                "pages": {
                    "/": {"title": "Login", "template": "camera_login.html"},
                    "/login.cgi": {"title": "Login Process", "template": None},
                    "/live.html": {"title": "Live View", "template": "camera_live.html", "auth": True},
                    "/settings.html": {"title": "Camera Settings", "template": "camera_settings.html", "auth": True},
                    "/network.html": {"title": "Network Settings", "template": "camera_network.html", "auth": True},
                    "/storage.html": {"title": "Storage", "template": "camera_storage.html", "auth": True}
                }
            }
        }
        
        # DVR profile
        dvr_profile = {
            "type": "dvr",
            "name": "Digital Video Recorder",
            "manufacturer": "SecureView",
            "model": "DVR-8CH",
            "firmware": "3.1.0",
            "services": ["telnet", "http"],
            "telnet": {
                "enabled": True,
                "banner": "Welcome to \r\n\r\nSecureView DVR-8CH\r\n\r\nLogin: ",
                "prompt": "dvr> ",
                "admin_prompt": "dvr# ",
                "credentials": [
                    {"username": "admin", "password": "admin"},
                    {"username": "root", "password": "dvr12345"}
                ],
                "filesystem": {
                    "/": {"type": "dir"},
                    "/bin": {"type": "dir"},
                    "/etc": {"type": "dir"},
                    "/etc/config": {"type": "file", "content": "# DVR Configuration\nCHANNELS=8\nRECORDING_QUALITY=HIGH\nMOTION_DETECTION=1\nSTORAGE_PATH=/media/hdd1\nREMOTE_ACCESS=1\n"},
                    "/etc/passwd": {"type": "file", "content": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\n"},
                    "/var": {"type": "dir"},
                    "/var/log": {"type": "dir"},
                    "/media": {"type": "dir"},
                    "/media/hdd1": {"type": "dir"},
                    "/media/hdd1/recordings": {"type": "dir"}
                },
                "commands": {
                    "help": "Available commands: help, exit, ls, cat, ps, reboot, get_recordings, start_recording\r\n",
                    "ls": "bin  dev  etc  lib  media  proc  sbin  tmp  usr  var\r\n",
                    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\n",
                    "ps": "  PID USER       VSZ STAT COMMAND\n    1 root      1200 S    init       \n    2 root      1300 S    httpd\n    3 root      1100 S    telnetd\n    4 root      2400 S    recorder\n    5 root      1800 S    motion_detect\n",
                    "reboot": "System is going down for reboot now.\r\n",
                    "get_recordings": "Recent Recordings:\nCH1_20250520_083000.mp4 - 256MB\nCH2_20250520_090000.mp4 - 128MB\nCH3_20250520_100000.mp4 - 512MB\n",
                    "start_recording": "Usage: start_recording [channel] [duration]\n"
                }
            },
            "http": {
                "enabled": True,
                "title": "SecureView DVR-8CH",
                "server": "mini_httpd/1.30",
                "credentials": [
                    {"username": "admin", "password": "admin"}
                ],
                "pages": {
                    "/": {"title": "Login", "template": "dvr_login.html"},
                    "/login.cgi": {"title": "Login Process", "template": None},
                    "/index.html": {"title": "Dashboard", "template": "dvr_dashboard.html", "auth": True},
                    "/live.html": {"title": "Live View", "template": "dvr_live.html", "auth": True},
                    "/playback.html": {"title": "Playback", "template": "dvr_playback.html", "auth": True},
                    "/settings.html": {"title": "Settings", "template": "dvr_settings.html", "auth": True}
                }
            }
        }
        
        # Add profiles to the manager
        self.profiles["router"] = router_profile
        self.profiles["ip_camera"] = camera_profile
        self.profiles["dvr"] = dvr_profile
        
        logger.info(f"Loaded built-in device profiles: {', '.join(self.profiles.keys())}")
    
    def get_device_profile(self, device_type: str) -> Dict[str, Any]:
        """
        Get a device profile by type.
        
        Args:
            device_type: Device type (e.g., 'router', 'ip_camera', 'dvr')
            
        Returns:
            Device profile dictionary
        """
        if device_type not in self.profiles:
            logger.warning(f"Unknown device type: {device_type}, using router as default")
            device_type = "router"
        
        return self.profiles[device_type]
    
    def get_command_response(self, device_type: str, command: str) -> str:
        """
        Get response for a command on a specific device type.
        
        Args:
            device_type: Device type (e.g., 'router', 'ip_camera', 'dvr')
            command: Command string
            
        Returns:
            Command response string
        """
        profile = self.get_device_profile(device_type)
        telnet_config = profile.get("telnet", {})
        commands = telnet_config.get("commands", {})
        
        # Check for exact command match
        if command in commands:
            return commands[command]
        
        # Check for command prefix match (e.g., "cat /etc/config" matches "cat")
        for cmd_prefix in commands:
            if command.startswith(cmd_prefix + " "):
                # Handle special cases like 'cat' that need to check the filesystem
                if cmd_prefix == "cat":
                    # Extract the file path
                    file_path = command[len(cmd_prefix):].strip()
                    return self._get_file_content(device_type, file_path)
                elif cmd_prefix == "ls":
                    # Extract the directory path
                    dir_path = command[len(cmd_prefix):].strip()
                    return self._get_directory_listing(device_type, dir_path)
        
        # Default response for unknown commands
        return f"Unknown command: {command}\r\n"
    
    def _get_file_content(self, device_type: str, file_path: str) -> str:
        """
        Get content of a file in the device's filesystem.
        
        Args:
            device_type: Device type
            file_path: File path
            
        Returns:
            File content or error message
        """
        profile = self.get_device_profile(device_type)
        telnet_config = profile.get("telnet", {})
        filesystem = telnet_config.get("filesystem", {})
        
        # Normalize path
        if not file_path.startswith("/"):
            file_path = "/" + file_path
        
        if file_path in filesystem:
            file_info = filesystem[file_path]
            if file_info.get("type") == "file":
                return file_info.get("content", "")
            else:
                return f"{file_path}: Is a directory\r\n"
        else:
            return f"{file_path}: No such file or directory\r\n"
    
    def _get_directory_listing(self, device_type: str, dir_path: str) -> str:
        """
        Get listing of a directory in the device's filesystem.
        
        Args:
            device_type: Device type
            dir_path: Directory path
            
        Returns:
            Directory listing or error message
        """
        profile = self.get_device_profile(device_type)
        telnet_config = profile.get("telnet", {})
        filesystem = telnet_config.get("filesystem", {})
        
        # Normalize path
        if not dir_path:
            dir_path = "/"
        elif not dir_path.startswith("/"):
            dir_path = "/" + dir_path
        
        # Remove trailing slash
        if dir_path != "/" and dir_path.endswith("/"):
            dir_path = dir_path[:-1]
        
        # Check if directory exists
        if dir_path in filesystem:
            dir_info = filesystem[dir_path]
            if dir_info.get("type") == "dir":
                # Find all entries in this directory
                entries = []
                for path, info in filesystem.items():
                    if path.startswith(dir_path + "/") and "/" not in path[len(dir_path)+1:]:
                        entries.append(path.split("/")[-1])
                
                if entries:
                    return "  ".join(sorted(entries)) + "\r\n"
                else:
                    return "\r\n"  # Empty directory
            else:
                return f"{dir_path}: Not a directory\r\n"
        else:
            return f"{dir_path}: No such file or directory\r\n"
    
    def get_http_response(self, device_type: str, path: str, method: str) -> Tuple[int, Dict[str, str], str]:
        """
        Get HTTP response for a specific device type, path, and method.
        
        Args:
            device_type: Device type (e.g., 'router', 'ip_camera', 'dvr')
            path: HTTP path
            method: HTTP method (e.g., 'GET', 'POST')
            
        Returns:
            Tuple of (status_code, headers, content)
        """
        profile = self.get_device_profile(device_type)
        http_config = profile.get("http", {})
        pages = http_config.get("pages", {})
        
        # Default headers
        headers = {
            "Server": http_config.get("server", "httpd/1.0"),
            "Content-Type": "text/html; charset=UTF-8"
        }
        
        # Check if path exists
        if path in pages:
            page_info = pages[path]
            
            # Check if authentication is required
            if page_info.get("auth", False):
                # In a real implementation, we would check for authentication
                # For now, we'll just return a login page
                return 401, headers, f"<html><head><title>Authentication Required</title></head><body><h1>Authentication Required</h1><p>Please <a href='/'>login</a> to access this page.</p></body></html>"
            
            # Get template
            template = page_info.get("template")
            if template:
                # In a real implementation, we would load and render the template
                # For now, we'll just return a placeholder
                title = page_info.get("title", "Page")
                return 200, headers, f"<html><head><title>{title} - {http_config.get('title')}</title></head><body><h1>{title}</h1><p>This is a placeholder for the {template} template.</p></body></html>"
            else:
                # Special handling for login.cgi
                if path == "/login.cgi" and method == "POST":
                    return 302, {"Location": "/index.html", **headers}, ""
        
        # Default response for unknown paths
        return 404, headers, f"<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested URL {path} was not found on this server.</p></body></html>"
    
    def get_banner(self, device_type: str, protocol: str) -> str:
        """
        Get banner for a specific device type and protocol.
        
        Args:
            device_type: Device type (e.g., 'router', 'ip_camera', 'dvr')
            protocol: Protocol (e.g., 'telnet', 'http')
            
        Returns:
            Banner string
        """
        profile = self.get_device_profile(device_type)
        protocol_config = profile.get(protocol, {})
        
        if protocol == "telnet":
            return protocol_config.get("banner", f"Welcome to {profile.get('name')}\r\n\r\nLogin: ")
        elif protocol == "http":
            return protocol_config.get("title", profile.get('name'))
        else:
            return f"{profile.get('name')}"
    
    def get_credentials(self, device_type: str, protocol: str) -> List[Dict[str, str]]:
        """
        Get credentials for a specific device type and protocol.
        
        Args:
            device_type: Device type (e.g., 'router', 'ip_camera', 'dvr')
            protocol: Protocol (e.g., 'telnet', 'http')
            
        Returns:
            List of credential dictionaries
        """
        profile = self.get_device_profile(device_type)
        protocol_config = profile.get(protocol, {})
        
        return protocol_config.get("credentials", [])
    
    def authenticate(self, device_type: str, protocol: str, username: str, password: str) -> bool:
        """
        Authenticate a user for a specific device type and protocol.
        
        Args:
            device_type: Device type (e.g., 'router', 'ip_camera', 'dvr')
            protocol: Protocol (e.g., 'telnet', 'http')
            username: Username
            password: Password
            
        Returns:
            True if authentication is successful, False otherwise
        """
        credentials = self.get_credentials(device_type, protocol)
        
        for cred in credentials:
            if cred.get("username") == username and cred.get("password") == password:
                return True
        
        return False

# Singleton instance
_device_profile_manager = None

def get_device_profile_manager(profiles_dir: Optional[str] = None) -> DeviceProfileManager:
    """
    Get the singleton DeviceProfileManager instance.
    
    Args:
        profiles_dir: Directory containing device profiles
        
    Returns:
        DeviceProfileManager instance
    """
    global _device_profile_manager
    
    if _device_profile_manager is None:
        _device_profile_manager = DeviceProfileManager(profiles_dir)
    
    return _device_profile_manager

# For direct testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test device profile manager
    manager = get_device_profile_manager()
    
    # Test getting device profiles
    router_profile = manager.get_device_profile("router")
    print(f"Router profile: {router_profile['name']} ({router_profile['manufacturer']} {router_profile['model']})")
    
    camera_profile = manager.get_device_profile("ip_camera")
    print(f"Camera profile: {camera_profile['name']} ({camera_profile['manufacturer']} {camera_profile['model']})")
    
    # Test command responses
    print("\nRouter command responses:")
    print(f"help: {manager.get_command_response('router', 'help')}")
    print(f"ls: {manager.get_command_response('router', 'ls')}")
    print(f"cat /etc/passwd: {manager.get_command_response('router', 'cat /etc/passwd')}")
    
    # Test HTTP responses
    print("\nRouter HTTP responses:")
    status, headers, content = manager.get_http_response("router", "/", "GET")
    print(f"GET /: {status} {headers.get('Server')}")
    
    # Test authentication
    print("\nAuthentication tests:")
    print(f"Router telnet (admin/admin): {manager.authenticate('router', 'telnet', 'admin', 'admin')}")
    print(f"Router telnet (admin/wrong): {manager.authenticate('router', 'telnet', 'admin', 'wrong')}")
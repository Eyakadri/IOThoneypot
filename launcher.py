#!/usr/bin/env python3
# launcher.py - Simple launcher script for the DeceptIoT honeypot

import os
import sys

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the main function
from main import main

if __name__ == "__main__":
    main()

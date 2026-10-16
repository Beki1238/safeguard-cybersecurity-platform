"""
SafeGuard Passenger WSGI Entrypoint for cPanel / CloudLinux Hosting
This file is automatically detected by cPanel's 'Setup Python App' (Phusion Passenger).
"""

import sys
import os

# Set current directory to sys.path so modules and packages resolve smoothly
app_dir = os.path.dirname(__file__)
sys.path.insert(0, app_dir)

# Import the WSGI application instance
from app import app as application

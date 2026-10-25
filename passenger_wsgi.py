"""
Gasha — cPanel / Phusion Passenger WSGI Entry Point
=========================================================
This file is ONLY for cPanel hosting using the "Setup Python App" feature
(Phusion Passenger / CloudLinux). cPanel auto-detects passenger_wsgi.py.

For all other deployments (VPS, Docker, bare gunicorn) use wsgi.py instead.

cPanel deployment checklist:
  1. Upload all project files to your cPanel app directory.
  2. In cPanel > Setup Python App, set:
       - Python version: 3.x
       - Application root: /home/<user>/<app-dir>
       - Application startup file: passenger_wsgi.py
       - Application Entry point: application
  3. Set environment variables (SECRET_KEY, DB_HOST, DB_USER, DB_PASSWORD, etc.)
     in the cPanel Python App environment variables panel.
  4. Run "pip install -r requirements.txt" from the cPanel terminal.
  5. Restart the app from the cPanel interface.
"""

import sys
import os

# Ensure the app directory is on sys.path so all imports resolve correctly
app_dir = os.path.dirname(os.path.abspath(__file__))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

from app import app as application

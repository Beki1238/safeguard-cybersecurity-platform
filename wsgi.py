"""
Gasha — Standard WSGI Entry Point
======================================
Use this file when deploying with any standard WSGI server:

    gunicorn wsgi:application -w 4 -b 0.0.0.0:5000
    gunicorn wsgi:application -w 4 -b 0.0.0.0:5000 --timeout 120

For development only:
    python app.py

DO NOT use passenger_wsgi.py for standard deployments — that file is
specifically for cPanel / Phusion Passenger (Python App) hosting.
"""

from app import app as application

if __name__ == "__main__":
    application.run()

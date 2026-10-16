"""
SafeGuard Standard WSGI Entrypoint
Can be run directly via: gunicorn wsgi:application -w 4 -b 0.0.0.0:5000
"""

from app import app as application

if __name__ == "__main__":
    application.run()

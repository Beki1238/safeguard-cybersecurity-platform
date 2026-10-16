# SafeGuard — cPanel Deployment Guide
### Enterprise Cybersecurity & Threat Intelligence Platform

This platform is architected with a native **Python WSGI (Phusion Passenger)** backend that integrates cleanly into standard cPanel shared hosting, VPS, or dedicated servers.

---

## 📋 cPanel Quick-Deploy Checklist (5 Steps)

### Step 1: Upload Project Files to cPanel
1. Compress the `safeguard/` folder into a `.zip` archive.
2. In your cPanel dashboard, open **File Manager**.
3. Create a folder (for example `/home/youruser/safeguard` or directly inside your subdomain/domain root).
4. Upload the `.zip` file and extract it.

### Step 2: Create Python Application in cPanel
1. In cPanel, navigate to the **Software** section and click **"Setup Python App"**.
2. Click **Create Application**.
3. Fill in the fields:
   - **Python version**: Select **3.10**, **3.11**, **3.12**, or **3.13**.
   - **Application root**: Enter the folder path (e.g. `safeguard`).
   - **Application URL**: Select your domain or subdomain (e.g. `safeguard.yourdomain.com`).
   - **Application startup file**: `passenger_wsgi.py`
   - **Application Entry point**: `application`
4. Click **CREATE** (in the top right).

### Step 3: Install Dependencies
1. Scroll down to the **Configuration files** section in the Python App manager.
2. Under "Configuration files", enter: `requirements.txt` and click **Add**.
3. Click the **Run Pip Install** button next to `requirements.txt`.
   *(Or SSH into your cPanel account and run `source virtualenv/bin/activate && pip install -r requirements.txt`)*

### Step 4: Verify passenger_wsgi.py
cPanel sometimes auto-generates a placeholder `passenger_wsgi.py`.
Verify that your `passenger_wsgi.py` contains:
```python
import sys
import os

app_dir = os.path.dirname(__file__)
sys.path.insert(0, app_dir)

from app import app as application
```

### Step 5: Restart the Python App
1. In the "Setup Python App" screen, click **Restart** on your application.
2. Visit your domain URL in the browser (e.g., `https://safeguard.yourdomain.com`).
3. You should see the SafeGuard Cyber Command Center running live with full API capabilities!

---

## 🔒 Security Hardening in cPanel
- **SSL Certificate**: Enable **cPanel AutoSSL** / Let's Encrypt for HTTPS.
- **WAF / ModSecurity**: SafeGuard works alongside cPanel's ModSecurity.
- **Firewall**: The built-in sliding window rate limiter protects endpoints from bot flood.

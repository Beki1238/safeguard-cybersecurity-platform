"""
SafeGuard MySQL Enterprise Database Management Layer
Connects to local MariaDB/MySQL (XAMPP/cPanel), handles schema migrations,
user authentication hashing, and scan telemetry persistence.
"""

import os
import json
import pymysql
from pymysql.cursors import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash

# Configuration from environment with local defaults
DB_HOST = os.environ.get('DB_HOST', '127.0.0.1')
DB_PORT = int(os.environ.get('DB_PORT', 3306))
DB_USER = os.environ.get('DB_USER', 'root')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
DB_NAME = os.environ.get('DB_NAME', 'safeguard_db')

def get_server_connection():
    """Returns raw connection to MySQL server without selecting database."""
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        cursorclass=DictCursor,
        autocommit=True
    )

def get_db_connection():
    """Returns connection to the SafeGuard database."""
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=DictCursor,
        autocommit=True
    )

def initialize_database():
    """Initializes safeguard_db and all production tables."""
    try:
        # Step 1: Ensure database exists
        server_conn = get_server_connection()
        with server_conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        server_conn.close()

        # Step 2: Ensure schema tables exist
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `users` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `username` VARCHAR(60) NOT NULL UNIQUE,
                    `email` VARCHAR(120) NOT NULL UNIQUE,
                    `password_hash` VARCHAR(255) NOT NULL,
                    `role` VARCHAR(40) DEFAULT 'SecOps Analyst',
                    `avatar_url` VARCHAR(255) DEFAULT '',
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    `last_login` TIMESTAMP NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Scans history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `scans` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `user_id` INT NULL,
                    `scan_type` VARCHAR(40) NOT NULL,
                    `target_input` TEXT NOT NULL,
                    `threat_score` INT NOT NULL,
                    `verdict` VARCHAR(80) NOT NULL,
                    `verdict_tier` VARCHAR(30) NOT NULL,
                    `summary` TEXT NOT NULL,
                    `details_json` LONGTEXT NOT NULL,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX `idx_scan_type` (`scan_type`),
                    INDEX `idx_threat_score` (`threat_score`),
                    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Active incidents stream
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `incidents` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `title` VARCHAR(255) NOT NULL,
                    `category` VARCHAR(100) NOT NULL,
                    `severity` VARCHAR(40) NOT NULL,
                    `target_node` VARCHAR(120) NOT NULL,
                    `status` VARCHAR(50) DEFAULT 'ACTIVE',
                    `day_number` VARCHAR(10) NOT NULL,
                    `month_label` VARCHAR(10) NOT NULL,
                    `participants_count` INT DEFAULT 3,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Threat intelligence feed table
            # Threat intelligence feed table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `threat_intel_feed` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `title` VARCHAR(255) NOT NULL,
                    `severity_badge` VARCHAR(60) NOT NULL,
                    `preview_tag` VARCHAR(60) NOT NULL,
                    `description` TEXT NOT NULL,
                    `footer_note` TEXT NOT NULL,
                    `image_url` VARCHAR(255) NOT NULL,
                    `author_name` VARCHAR(80) NOT NULL,
                    `author_avatar` VARCHAR(255) NOT NULL,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Learning Courses table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `courses` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `title` VARCHAR(255) NOT NULL,
                    `category` VARCHAR(100) NOT NULL,
                    `level` VARCHAR(50) NOT NULL,
                    `duration` VARCHAR(50) NOT NULL,
                    `video_embed_url` VARCHAR(255) NOT NULL,
                    `thumbnail_url` VARCHAR(255) NOT NULL,
                    `description` TEXT NOT NULL,
                    `instructor` VARCHAR(100) NOT NULL,
                    `lessons_json` LONGTEXT NOT NULL,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Quizzes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `quizzes` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `title` VARCHAR(255) NOT NULL,
                    `category` VARCHAR(100) NOT NULL,
                    `difficulty` VARCHAR(50) NOT NULL,
                    `questions_count` INT NOT NULL,
                    `pass_score` INT DEFAULT 70,
                    `questions_json` LONGTEXT NOT NULL,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Course Materials & Cheatsheets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `course_materials` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `title` VARCHAR(255) NOT NULL,
                    `type` VARCHAR(50) NOT NULL,
                    `category` VARCHAR(100) NOT NULL,
                    `file_format` VARCHAR(20) NOT NULL,
                    `size_label` VARCHAR(30) NOT NULL,
                    `description` TEXT NOT NULL,
                    `content_preview` TEXT NOT NULL,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # User Quiz Results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS `user_quiz_results` (
                    `id` INT AUTO_INCREMENT PRIMARY KEY,
                    `user_id` INT NULL,
                    `quiz_id` INT NOT NULL,
                    `score` INT NOT NULL,
                    `passed` TINYINT(1) DEFAULT 0,
                    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

            # Seed default admin user if users table is empty
            cursor.execute("SELECT COUNT(*) as cnt FROM `users`;")
            if cursor.fetchone()['cnt'] == 0:
                default_pw = generate_password_hash("Admin@123456")
                cursor.execute("""
                    INSERT INTO `users` (`username`, `email`, `password_hash`, `role`)
                    VALUES (%s, %s, %s, %s);
                """, ('admin', 'admin@safeguard.local', default_pw, 'Lead SecOps Officer'))

            # Seed incidents if empty
            cursor.execute("SELECT COUNT(*) as cnt FROM `incidents`;")
            if cursor.fetchone()['cnt'] == 0:
                incidents_data = [
                    ('Spearphishing Campaign Intercepted', 'Identity Threat', 'CRITICAL', 'Executive Finance Subnet', 'ACTIVE', '16', 'oct', 4),
                    ('Credential Spray Defended', 'Authentication Flood', 'HIGH', 'Edge Auth Gateway AS16509', 'MITIGATED', '15', 'oct', 2),
                    ('C2 Beacon Domain Sinkholed', 'Malware C2', 'MEDIUM', 'Perimeter DNS Resolver', 'RESOLVED', '14', 'oct', 3),
                    ('Zero-Day Patch Deployed', 'Vulnerability Hotfix', 'HIGH', 'Gateway Core PAN-OS', 'COMPLETED', '13', 'oct', 5)
                ]
                cursor.executemany("""
                    INSERT INTO `incidents` (`title`, `category`, `severity`, `target_node`, `status`, `day_number`, `month_label`, `participants_count`)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                """, incidents_data)

            # Seed threat intel feed if empty
            cursor.execute("SELECT COUNT(*) as cnt FROM `threat_intel_feed`;")
            if cursor.fetchone()['cnt'] == 0:
                feed_data = [
                    (
                        'CVE-2024-3400 (PAN-OS GlobalProtect)',
                        'CVSS 10.0 • CRITICAL',
                        'RCE EXPLOITATION',
                        'Command injection vulnerability confirmed in Palo Alto GlobalProtect. Heuristic perimeter signatures deployed.',
                        'All 48 edge gateways updated with live mitigation heuristics.',
                        'https://images.unsplash.com/photo-1563089145-599997674d42?w=600&auto=format&fit=crop&q=80',
                        'SOC Alert • Jane',
                        'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=100&auto=format&fit=crop&q=80'
                    ),
                    (
                        'Global Banking Smishing Wave',
                        'THREAT CAMPAIGN • HIGH',
                        'CREDENTIAL HARVEST',
                        'Automated lookalike domains with deceptive urgency tokens detected targeting customer banking credentials.',
                        'NLP weight updated to flag SMS verification urgency.',
                        'https://images.unsplash.com/photo-1510511459019-5dda7724fd87?w=600&auto=format&fit=crop&q=80',
                        'Intel Feed • Mike',
                        'https://images.unsplash.com/photo-1570295999919-56ceb5ecca61?w=100&auto=format&fit=crop&q=80'
                    )
                ]
                cursor.executemany("""
                    INSERT INTO `threat_intel_feed` (`title`, `severity_badge`, `preview_tag`, `description`, `footer_note`, `image_url`, `author_name`, `author_avatar`)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                """, feed_data)

            # Seed courses if empty
            cursor.execute("SELECT COUNT(*) as cnt FROM `courses`;")
            if cursor.fetchone()['cnt'] == 0:
                courses_data = [
                    (
                        'Phishing & Social Engineering Heuristics',
                        'Human Defense & Threat NLP',
                        'Intermediate',
                        '45 Mins',
                        'https://www.youtube.com/embed/gW9p_xP_1o4',
                        'https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=600&auto=format&fit=crop&q=80',
                        'Master the detection of zero-day spearphishing, brand lookalikes, Punycode attacks, and coercive psychological urgency markers.',
                        'Sarah Chen, CISSP (Senior Threat Hunter)',
                        json.dumps([
                            {"title": "Anatomy of Modern Spearphishing & BEC Attacks", "duration": "8m", "topics": ["Attack vectors", "Executive impersonation"]},
                            {"title": "Lexical Analysis & Domain Typosquatting Mechanics", "duration": "10m", "topics": ["Homoglyphs", "Entropy", "Subdomain depth"]},
                            {"title": "Linguistic Urgency & Psychological Coercion Profiling", "duration": "9m", "topics": ["NLP tokens", "Emotional triggers"]},
                            {"title": "Email Headers Deep Dive: DKIM, SPF & DMARC Alignments", "duration": "11m", "topics": ["Header parsing", "Relay inspection"]},
                            {"title": "Hands-on Lab: Triaging Suspicious Inbound Payloads", "duration": "7m", "topics": ["SOC workflow", "Mitigation actions"]}
                        ])
                    ),
                    (
                        'Web Application Security & OWASP Top 10',
                        'Perimeter & AppSec',
                        'Advanced',
                        '1h 15m',
                        'https://www.youtube.com/embed/2_lswM1S264',
                        'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=600&auto=format&fit=crop&q=80',
                        'Hands-on walkthrough of SQL injection, Broken Auth, SSRF, Cross-Site Scripting, and configuring enterprise HTTP security headers.',
                        'David Thorne (Principal AppSec Engineer)',
                        json.dumps([
                            {"title": "SQL Injection & Parameterized Defenses", "duration": "14m", "topics": ["Blind SQLi", "ORM flaws"]},
                            {"title": "Broken Authentication & Token Security", "duration": "12m", "topics": ["JWT flaws", "Session hijacking"]},
                            {"title": "Cross-Site Scripting (XSS) & Modern CSP Bypasses", "duration": "15m", "topics": ["DOM XSS", "Sanitization"]},
                            {"title": "Server-Side Request Forgery (SSRF) in Cloud Apps", "duration": "16m", "topics": ["AWS Metadata", "Internal pivots"]},
                            {"title": "Hardening HTTP Headers (HSTS, CSP, Permissions-Policy)", "duration": "18m", "topics": ["Perimeter defenses", "Compliance"]}
                        ])
                    ),
                    (
                        'Network Threat Hunting & C2 Beaconing Detection',
                        'Network Security & Threat Hunting',
                        'Advanced',
                        '55 Mins',
                        'https://www.youtube.com/embed/3Kq1MIfTWCE',
                        'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=600&auto=format&fit=crop&q=80',
                        'Investigate suspicious network traffic, Cobalt Strike malleable profiles, DNS tunneling, and fast-flux domain evasion.',
                        'Elena Rostova (Lead Incident Responder)',
                        json.dumps([
                            {"title": "C2 Beaconing Cycles & Jitter Analysis", "duration": "12m", "topics": ["Beacon timing", "Periodic connections"]},
                            {"title": "Detecting DNS Tunneling & Exfiltration Streams", "duration": "10m", "topics": ["TXT records", "Subdomain lengths"]},
                            {"title": "TLS Fingerprinting (JA3 / JA4) & Certificate Anomalies", "duration": "11m", "topics": ["Cipher suites", "Self-signed C2"]},
                            {"title": "Packet Capture Forensics in Wireshark & Suricata", "duration": "13m", "topics": ["PCAP parsing", "Signature writing"]},
                            {"title": "Quarantining Infected Subnets & Perimeter Isolation", "duration": "9m", "topics": ["Firewall ACLs", "DNS Sinkholes"]}
                        ])
                    ),
                    (
                        'Incident Response Runbooks & SOC Containment',
                        'SOC Operations',
                        'Beginner to Pro',
                        '40 Mins',
                        'https://www.youtube.com/embed/qg_w0jD_Nfc',
                        'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&auto=format&fit=crop&q=80',
                        'Step-by-step incident response workflows: Preparation, Detection, Containment, Eradication, and Post-Mortem reporting.',
                        'Marcus Brody (SOC Manager)',
                        json.dumps([
                            {"title": "The SANS / NIST Incident Response Life Cycle", "duration": "8m", "topics": ["PICERL methodology"]},
                            {"title": "Live Memory Acquisition & Volatility Basics", "duration": "11m", "topics": ["RAM dumping", "Process trees"]},
                            {"title": "Endpoint Host Isolation & Active Directory Quarantine", "duration": "9m", "topics": ["Account disable", "Revoking Kerberos"]},
                            {"title": "Post-Mortem Root Cause Analysis & Threat Sharing", "duration": "12m", "topics": ["MISP", "IoC distribution"]}
                        ])
                    )
                ]
                cursor.executemany("""
                    INSERT INTO `courses` (`title`, `category`, `level`, `duration`, `video_embed_url`, `thumbnail_url`, `description`, `instructor`, `lessons_json`)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, courses_data)

            # Seed quizzes if empty
            cursor.execute("SELECT COUNT(*) as cnt FROM `quizzes`;")
            if cursor.fetchone()['cnt'] == 0:
                quizzes_data = [
                    (
                        'Phishing Heuristics & Social Engineering Challenge',
                        'Phishing & Threat NLP',
                        'Intermediate',
                        5,
                        80,
                        json.dumps([
                            {
                                "id": 1,
                                "question": "Which indicator is the strongest sign of a homoglyph domain attack?",
                                "options": [
                                    "Domain uses HTTPS with a Let's Encrypt certificate",
                                    "Punycode prefix 'xn--' in the DNS name with Cyrillic character substitution",
                                    "Domain was registered more than 5 years ago",
                                    "Hostname resolves to multiple cloud IP addresses"
                                ],
                                "correct": 1,
                                "explanation": "Punycode (xn--) allows foreign character sets to imitate Latin letters (e.g. Cyrillic 'а' replacing Latin 'a') to deceive users."
                            },
                            {
                                "id": 2,
                                "question": "What does a high Shannon entropy score in a domain name typically indicate?",
                                "options": [
                                    "The domain is hosted on high-availability infrastructure",
                                    "High algorithmic randomness, common in DGA (Domain Generation Algorithms) used by malware",
                                    "The domain has strong SPF and DKIM authentication",
                                    "The domain belongs to an educational institution (.edu)"
                                ],
                                "correct": 1,
                                "explanation": "Shannon entropy quantifies character unpredictability. Random-looking strings like 'x7z9q2w1.com' have high entropy (>3.8 bits/sym), characteristic of DGAs."
                            },
                            {
                                "id": 3,
                                "question": "In an email header analysis, which combination indicates SPF alignment failure?",
                                "options": [
                                    "Sender IP is included in the SPF ip4 record of the Return-Path domain",
                                    "Connecting IP address is not listed in the domain's authorized SPF record",
                                    "DKIM signature verification returned status 'pass'",
                                    "DMARC policy is set to p=none"
                                ],
                                "correct": 1,
                                "explanation": "SPF validates that the sending server IP is explicitly authorized by the domain owner in DNS. If unlisted, SPF returns softfail or fail."
                            },
                            {
                                "id": 4,
                                "question": "Which psychological coercion tactic is most prevalent in business email compromise (BEC)?",
                                "options": [
                                    "Humor and casual small talk",
                                    "Manufactured time urgency and strict confidentiality demands from executive leadership",
                                    "Detailed technical inquiries about network switches",
                                    "Offers of customer support survey rewards"
                                ],
                                "correct": 1,
                                "explanation": "BEC actors exploit authority and urgency ('Wire these funds by 3 PM; keep this confidential due to an acquisition') to bypass verification checks."
                            },
                            {
                                "id": 5,
                                "question": "What should be the FIRST containment action when an analyst confirms an active credential harvest URL in an inbound email?",
                                "options": [
                                    "Reply to the phishing email demanding they cease operations",
                                    "Block the malicious domain at the perimeter DNS/proxy and purge all copies from mailboxes",
                                    "Reinstall the operating system on all network workstations immediately",
                                    "Wait 24 hours to see if more users report the message"
                                ],
                                "correct": 1,
                                "explanation": "Immediate containment requires blocking the domain at perimeter DNS resolvers/proxies and purging existing deliveries from all recipient inboxes."
                            }
                        ])
                    ),
                    (
                        'Web Application Security & OWASP Top 10 Drill',
                        'AppSec & Web Defense',
                        'Advanced',
                        5,
                        80,
                        json.dumps([
                            {
                                "id": 1,
                                "question": "Which HTTP response header effectively prevents Clickjacking attacks?",
                                "options": [
                                    "X-Content-Type-Options: nosniff",
                                    "X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'",
                                    "Strict-Transport-Security: max-age=31536000",
                                    "Access-Control-Allow-Origin: *"
                                ],
                                "correct": 1,
                                "explanation": "X-Frame-Options: DENY and CSP frame-ancestors prevent malicious sites from framing the application inside invisible iframes."
                            },
                            {
                                "id": 2,
                                "question": "What is the primary root cause of Server-Side Request Forgery (SSRF)?",
                                "options": [
                                    "Lack of database password hashing",
                                    "The server fetches a remote resource based on user-supplied URL input without validating the target IP",
                                    "Client browser runs unminified JavaScript",
                                    "Missing SSL certificate on port 80"
                                ],
                                "correct": 1,
                                "explanation": "SSRF happens when a backend server fetches a user-supplied URL, allowing attackers to access internal endpoints like 169.254.169.254."
                            },
                            {
                                "id": 3,
                                "question": "What is the most secure method for defending against SQL Injection?",
                                "options": [
                                    "String concatenation with single quotes stripped",
                                    "Parameterized queries (Prepared Statements) with bound parameters",
                                    "Using client-side HTML5 input validation",
                                    "Encoding user input with base64 before inserting into SQL"
                                ],
                                "correct": 1,
                                "explanation": "Prepared statements ensure that the database engine treats user input strictly as data parameters, never as executable SQL instructions."
                            },
                            {
                                "id": 4,
                                "question": "Which flag should ALWAYS be set on sensitive session cookies to prevent theft via JavaScript XSS?",
                                "options": [
                                    "Domain",
                                    "HttpOnly",
                                    "Path=/",
                                    "Max-Age"
                                ],
                                "correct": 1,
                                "explanation": "The HttpOnly flag forbids client-side scripts from reading document.cookie, mitigating session theft via XSS."
                            },
                            {
                                "id": 5,
                                "question": "How does HSTS (HTTP Strict Transport Security) protect web users?",
                                "options": [
                                    "It encrypts passwords in the browser's local storage",
                                    "It forces the browser to communicate exclusively over HTTPS, preventing SSL stripping MITM attacks",
                                    "It scans incoming requests for malware signatures",
                                    "It limits the number of HTTP requests a client can send"
                                ],
                                "correct": 1,
                                "explanation": "HSTS instructs browsers to automatically upgrade all HTTP requests to HTTPS and reject connections with certificate warnings."
                            }
                        ])
                    )
                ]
                cursor.executemany("""
                    INSERT INTO `quizzes` (`title`, `category`, `difficulty`, `questions_count`, `pass_score`, `questions_json`)
                    VALUES (%s, %s, %s, %s, %s, %s);
                """, quizzes_data)

            # Seed course materials if empty
            cursor.execute("SELECT COUNT(*) as cnt FROM `course_materials`;")
            if cursor.fetchone()['cnt'] == 0:
                materials_data = [
                    (
                        'MITRE ATT&CK Enterprise Matrix Cheat Sheet',
                        'Reference Cheatsheet',
                        'Threat Hunting',
                        'PDF / Markdown',
                        '2.4 MB',
                        'Quick-reference guide mapping 14 enterprise tactics (Initial Access, Execution, Persistence, Defense Evasion, Exfiltration) to defensive mitigations.',
                        'TACTICS & TECHNIQUES:\n- TA0001 Initial Access: T1566 Phishing, T1190 Exploit Public-Facing App\n- TA0002 Execution: T1059 Command & Scripting Interpreter\n- TA0003 Persistence: T1053 Scheduled Task, T1547 Boot Autostart\n- TA0005 Defense Evasion: T1027 Obfuscated Files, T1036 Masquerading\n- TA0011 Command and Control: T1071 App Layer Protocol, T1090 Proxy'
                    ),
                    (
                        'Phishing Email Header Forensics & Triage Checklist',
                        'Standard Operating Procedure',
                        'Human Defense',
                        'PDF / Guide',
                        '1.1 MB',
                        'Step-by-step triage guide for examining RFC 5322 headers, DKIM cryptographic signatures, Authentication-Results, and hop latency.',
                        'TRIAGE CHECKLIST:\n1. Inspect Received: lines from bottom to top to identify original client IP.\n2. Check Authentication-Results for dkim=pass, spf=pass, dmarc=pass.\n3. Compare From: display name vs From: envelope address vs Return-Path.\n4. Extract URLs: run through Shannon entropy and IDN homoglyph analyzers.\n5. Hash attachments (SHA256) and query threat intelligence reputation.'
                    ),
                    (
                        'OWASP Top 10 Remediation & Secure Code Handout',
                        'AppSec Reference',
                        'Application Security',
                        'PDF / Reference',
                        '3.8 MB',
                        'Actionable secure development standards for preventing injection, broken access control, cryptographic failures, and insecure design.',
                        'TOP 10 REMEDIATION PATTERNS:\n- A01: Broken Access Control -> Enforce deny-by-default on all endpoints.\n- A02: Cryptographic Failures -> Use Argon2id / PBKDF2 with >= 600k iterations.\n- A03: Injection -> Utilize parameterized queries with ORM/PreparedStatement.\n- A04: Insecure Design -> Threat model early with STRIDE framework.\n- A05: Security Misconfiguration -> Disable debug flags, strip server banners.'
                    ),
                    (
                        'Linux Live Forensics & Incident Response One-Liners',
                        'Field Cheatsheet',
                        'Incident Response',
                        'Shell / Guide',
                        '850 KB',
                        'Essential bash commands for volatile memory collection, active network socket inspection, persistence detection, and binary verification.',
                        'ESSENTIAL IR COMMANDS:\n# Active network connections with process info:\nss -tulpn\n# Inspect listening processes and deleted open binaries:\nlsof -i -P -n | grep LISTEN\nls -l /proc/*/exe | grep deleted\n# Check user logins and failed attempts:\nlast -F -n 20\njournalctl -u ssh -n 50 --no-pager\n# Cron persistence search:\ncrontab -l; ls -la /etc/cron*'
                    )
                ]
                cursor.executemany("""
                    INSERT INTO `course_materials` (`title`, `type`, `category`, `file_format`, `size_label`, `description`, `content_preview`)
                    VALUES (%s, %s, %s, %s, %s, %s, %s);
                """, materials_data)

        conn.close()
        return True, "Database initialized successfully"
    except Exception as e:
        return False, str(e)

# ==============================================================================
# USER AUTHENTICATION & MANAGEMENT
# ==============================================================================
def create_user(username, email, password, role="SecOps Analyst"):
    """Creates a new user record with hashed password."""
    username = username.strip()
    email = email.strip().lower()

    if len(username) < 3:
        return None, "Username must be at least 3 characters long."
    if len(password) < 6:
        return None, "Password must be at least 6 characters long."

    hashed = generate_password_hash(password)
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Check if username or email exists
            cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s;", (username, email))
            if cursor.fetchone():
                conn.close()
                return None, "Username or email is already registered."

            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s, %s, %s, %s);
            """, (username, email, hashed, role))
            user_id = cursor.lastrowid
        conn.close()
        return get_user_by_id(user_id), None
    except Exception as e:
        return None, f"Database error: {str(e)}"

def authenticate_user(username_or_email, password):
    """Verifies credentials and returns user dict on success."""
    query = username_or_email.strip()
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, username, email, password_hash, role, avatar_url, created_at
                FROM users
                WHERE username = %s OR email = %s;
            """, (query, query.lower()))
            user = cursor.fetchone()
            if not user:
                conn.close()
                return None, "Invalid username or password."

            if not check_password_hash(user['password_hash'], password):
                conn.close()
                return None, "Invalid username or password."

            # Update last login
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s;", (user['id'],))
        conn.close()

        del user['password_hash']
        return user, None
    except Exception as e:
        return None, f"Database error: {str(e)}"

def get_user_by_id(user_id):
    """Retrieves safe user profile by ID."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, username, email, role, avatar_url, created_at, last_login FROM users WHERE id = %s;", (user_id,))
            user = cursor.fetchone()
        conn.close()
        return user
    except Exception:
        return None

# ==============================================================================
# SCANS STORAGE & REAL TELEMETRY
# ==============================================================================
def save_scan(user_id, scan_type, target_input, threat_score, verdict, verdict_tier, summary, details_dict):
    """Persists a completed threat scan result into the database."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO scans (user_id, scan_type, target_input, threat_score, verdict, verdict_tier, summary, details_json)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
            """, (
                user_id,
                scan_type,
                target_input,
                threat_score,
                verdict,
                verdict_tier,
                summary,
                json.dumps(details_dict)
            ))
            scan_id = cursor.lastrowid
        conn.close()
        return scan_id
    except Exception as e:
        print(f"Error saving scan to DB: {e}")
        return None

def get_recent_scans(limit=10):
    """Retrieves recent scans executed on the platform."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT s.id, s.scan_type, s.target_input, s.threat_score, s.verdict, s.verdict_tier, s.summary, s.created_at,
                       u.username, u.username as scanned_by
                FROM scans s
                LEFT JOIN users u ON s.user_id = u.id
                ORDER BY s.id DESC
                LIMIT %s;
            """, (limit,))
            scans = cursor.fetchall()
        conn.close()
        return scans
    except Exception as e:
        print(f"Error fetching recent scans: {e}")
        return []

def get_dashboard_metrics():
    """Calculates live metrics from actual database records."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as total_scans FROM scans;")
            total_scans = cursor.fetchone()['total_scans']

            cursor.execute("SELECT COUNT(*) as threats_blocked FROM scans WHERE threat_score >= 50;")
            threats_blocked = cursor.fetchone()['threats_blocked']

            cursor.execute("SELECT COUNT(*) as total_users FROM users;")
            total_users = cursor.fetchone()['total_users']

            cursor.execute("SELECT COUNT(*) as clean_scans FROM scans WHERE threat_score < 50;")
            clean_scans = cursor.fetchone()['clean_scans']
        conn.close()

        # Compute dynamic defense posture percentage
        posture_percent = 94 if total_scans == 0 else max(75, min(99, 100 - int((threats_blocked / max(1, total_scans)) * 25)))

        return {
            "total_scans": total_scans,
            "threats_blocked": threats_blocked,
            "clean_scans": clean_scans,
            "total_users": total_users,
            "posture_percent": posture_percent,
            "defense_score": posture_percent
        }
    except Exception as e:
        print(f"Error getting metrics: {e}")
        return {
            "total_scans": 0,
            "threats_blocked": 0,
            "clean_scans": 0,
            "total_users": 1,
            "posture_percent": 94,
            "defense_score": 94
        }

def get_incidents_list():
    """Retrieves active incidents from database."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 6;")
            incidents = cursor.fetchall()
        conn.close()
        return incidents
    except Exception:
        return []

def get_threat_feed_list():
    """Retrieves threat intelligence feed items from database."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM threat_intel_feed ORDER BY id DESC LIMIT 5;")
            feed = cursor.fetchall()
        conn.close()
        return feed
    except Exception:
        return []

# ==============================================================================
# LEARNING ACADEMY (COURSES, QUIZZES & MATERIALS)
# ==============================================================================
def get_courses():
    """Retrieves all active learning courses."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM courses ORDER BY id ASC;")
            courses = cursor.fetchall()
            for c in courses:
                try:
                    c['lessons'] = json.loads(c['lessons_json'])
                except Exception:
                    c['lessons'] = []
        conn.close()
        return courses
    except Exception as e:
        print(f"Error fetching courses: {e}")
        return []

def get_course_by_id(course_id):
    """Retrieves single course by ID."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM courses WHERE id = %s;", (course_id,))
            course = cursor.fetchone()
            if course:
                try:
                    course['lessons'] = json.loads(course['lessons_json'])
                except Exception:
                    course['lessons'] = []
        conn.close()
        return course
    except Exception as e:
        print(f"Error fetching course {course_id}: {e}")
        return None

def get_quizzes():
    """Retrieves all interactive quizzes."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, title, category, difficulty, questions_count, pass_score, created_at FROM quizzes ORDER BY id ASC;")
            quizzes = cursor.fetchall()
        conn.close()
        return quizzes
    except Exception as e:
        print(f"Error fetching quizzes: {e}")
        return []

def get_quiz_by_id(quiz_id):
    """Retrieves quiz details including questions."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM quizzes WHERE id = %s;", (quiz_id,))
            quiz = cursor.fetchone()
            if quiz:
                try:
                    quiz['questions'] = json.loads(quiz['questions_json'])
                except Exception:
                    quiz['questions'] = []
        conn.close()
        return quiz
    except Exception as e:
        print(f"Error fetching quiz {quiz_id}: {e}")
        return None

def save_quiz_attempt(user_id, quiz_id, score, passed):
    """Records a user's quiz attempt result."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO user_quiz_results (user_id, quiz_id, score, passed)
                VALUES (%s, %s, %s, %s);
            """, (user_id, quiz_id, score, 1 if passed else 0))
            attempt_id = cursor.lastrowid
        conn.close()
        return attempt_id
    except Exception as e:
        print(f"Error saving quiz attempt: {e}")
        return None

def get_course_materials():
    """Retrieves reference cheatsheets and course materials."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM course_materials ORDER BY id ASC;")
            materials = cursor.fetchall()
        conn.close()
        return materials
    except Exception as e:
        print(f"Error fetching materials: {e}")
        return []

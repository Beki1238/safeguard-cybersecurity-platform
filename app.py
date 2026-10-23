"""
SafeGuard — Enterprise Cybersecurity & Threat Intelligence Platform
Production WSGI & Flask Application for Local & cPanel Deployment with MySQL Storage
"""

from dotenv import load_dotenv
load_dotenv()

import os
import re
import time
import hmac
import hashlib
import secrets
import logging
import logging.handlers
from collections import defaultdict
from flask import Flask, request, jsonify, render_template, session

# ── Logging setup ─────────────────────────────────────────────────────────────
# Structured log format: timestamp | level | logger name | message
_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_LOG_LEVEL  = logging.DEBUG if os.environ.get('FLASK_ENV') == 'development' else logging.INFO

logging.basicConfig(level=_LOG_LEVEL, format=_LOG_FORMAT)
logger = logging.getLogger("safeguard")

# Suppress noisy third-party loggers in production
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# Import Core Heuristic Engines
from engine.url_scanner import analyze_url
from engine.phishing_detector import analyze_message
from engine.breach_checker import audit_email
from engine.password_audit import audit_password
from engine.header_inspector import inspect_headers
from engine.ip_intel import audit_ip
from engine.crypto_tools import compute_hashes, analyze_hash, encode_decode_payload
from engine.threat_intel import get_threat_intel_snapshot, INCIDENT_PLAYBOOKS

# Import MySQL Database Layer
import database

app = Flask(__name__, static_folder='static', template_folder='templates')

# ── Secret key: must be set explicitly in production ─────────────────────────
_secret_key = os.environ.get('SECRET_KEY', '')
_is_dev = os.environ.get('FLASK_ENV', 'production') == 'development' or os.environ.get('FLASK_DEBUG', '0') == '1'

if not _secret_key:
    if _is_dev:
        import secrets as _secrets
        _secret_key = _secrets.token_hex(32)
        print("[SafeGuard WARNING] SECRET_KEY not set. Using a temporary random key — sessions will not persist across restarts. Set SECRET_KEY in .env for development.")
    else:
        raise RuntimeError(
            "[SafeGuard FATAL] SECRET_KEY environment variable is not set. "
            "This is required in production to prevent session forgery. "
            "Set it in your .env file or environment before starting the server."
        )

app.secret_key = _secret_key
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB maximum payload security constraint
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# Auto-initialize MySQL schema on boot
try:
    init_ok, init_msg = database.initialize_database()
    logger.info("Database: %s", init_msg)
except Exception as e:
    logger.warning("Database unavailable at startup: %s", e)

# ── Rate limiter ─────────────────────────────────────────────────────────────
# Sliding-window implemented with per-minute time buckets so it survives the
# Flask debug reloader (child processes share the same wall-clock minute bucket
# key and the dict is module-level, populated fresh each minute naturally).
# For a multi-worker / multi-process production deployment, swap this for Redis.
RATE_LIMIT_WINDOW = 60   # seconds per window
MAX_REQUESTS_PER_WINDOW = 120

# { (client_ip, minute_bucket): hit_count }
_rate_buckets: dict[tuple, int] = defaultdict(int)
_rate_last_purge: float = 0.0


def is_rate_limited(client_ip: str) -> bool:
    """
    Returns True if client_ip has exceeded MAX_REQUESTS_PER_WINDOW hits in the
    current 60-second clock minute. Expired buckets are purged once per minute.
    """
    global _rate_last_purge
    now = time.time()
    current_bucket = int(now // RATE_LIMIT_WINDOW)

    # Purge stale buckets once per window to keep memory bounded
    if now - _rate_last_purge > RATE_LIMIT_WINDOW:
        stale = [k for k in _rate_buckets if k[1] < current_bucket - 1]
        for k in stale:
            del _rate_buckets[k]
        _rate_last_purge = now

    key = (client_ip, current_bucket)
    _rate_buckets[key] += 1
    exceeded = _rate_buckets[key] > MAX_REQUESTS_PER_WINDOW
    if exceeded:
        logger.warning("Rate limit exceeded: ip=%s bucket=%s hits=%d", client_ip, current_bucket, _rate_buckets[key])
    return exceeded


# ── Input validation helpers ──────────────────────────────────────────────────
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
_IP_RE    = re.compile(r'^[0-9a-fA-F.:]+$')   # rough pre-check before ipaddress module
_URL_RE   = re.compile(r'^https?://', re.IGNORECASE)

MAX_URL_LEN     = 2048
MAX_TEXT_LEN    = 10_000
MAX_EMAIL_LEN   = 254     # RFC 5321
MAX_IP_LEN      = 45      # max IPv6 with zone ID
MAX_HEADER_URL  = 2048
MAX_PASSWORD_LEN = 128    # reject suspiciously long passwords (DoS via entropy calc)


def _validate_url(value: str) -> str | None:
    """Returns an error string if the URL is invalid, else None."""
    if not value:
        return "URL is required."
    if len(value) > MAX_URL_LEN:
        return f"URL exceeds maximum allowed length ({MAX_URL_LEN} chars)."
    # Allow bare domains — the engine prepends scheme itself
    return None


def _validate_email(value: str) -> str | None:
    if not value:
        return "Email address is required."
    if len(value) > MAX_EMAIL_LEN:
        return f"Email exceeds maximum allowed length ({MAX_EMAIL_LEN} chars)."
    if not _EMAIL_RE.match(value):
        return "Invalid email address format."
    return None


def _validate_ip(value: str) -> str | None:
    if not value:
        return "IP address is required."
    if len(value) > MAX_IP_LEN:
        return f"IP address exceeds maximum allowed length."
    if not _IP_RE.match(value):
        return "IP address contains invalid characters."
    return None


def _validate_text(value: str) -> str | None:
    if not value:
        return "Message text is required."
    if len(value) > MAX_TEXT_LEN:
        return f"Message text exceeds maximum allowed length ({MAX_TEXT_LEN} chars)."
    return None


def _validate_password(value: str) -> str | None:
    if not value:
        return "Password is required."
    if len(value) > MAX_PASSWORD_LEN:
        return f"Password exceeds maximum allowed length ({MAX_PASSWORD_LEN} chars)."
    return None


# ── CSRF protection ───────────────────────────────────────────────────────────
# Double-submit cookie pattern:
#   1. GET  /api/csrf-token  → sets an HttpOnly session token + returns a JS-readable token
#   2. Client sends X-CSRF-Token header on every state-changing POST
#   3. Before each mutating API call we verify the header matches the session token
#
# Exempt: read-only GETs, /api/auth/login, /api/auth/register (no session yet),
#         and the health endpoint.
_CSRF_EXEMPT = {
    '/api/auth/login',
    '/api/auth/register',
    '/api/csrf-token',
    '/api/health',
}

def _generate_csrf_token() -> str:
    return secrets.token_hex(32)

def _get_csrf_token() -> str:
    """Returns (creating if needed) the CSRF token stored in the session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = _generate_csrf_token()
    return session['csrf_token']

def _verify_csrf() -> bool:
    """
    Validates X-CSRF-Token header against the session token using a
    constant-time comparison to prevent timing attacks.
    """
    session_token = session.get('csrf_token', '')
    header_token  = request.headers.get('X-CSRF-Token', '')
    if not session_token or not header_token:
        return False
    return hmac.compare_digest(session_token, header_token)

# ============================================================================
# SECURITY HEADERS & CORS MIDDLEWARE
# ============================================================================
@app.after_request
def apply_security_headers(response):
    """Enforces enterprise perimeter HTTP security headers and CORS."""
    # Log every API response (path, method, status)
    if request.path.startswith('/api/'):
        logger.debug("%s %s -> %d", request.method, request.path, response.status_code)

    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # CSP permitting cdnjs FontAwesome, Google Fonts, YouTube educational embeds, and data URIs
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
        "img-src 'self' data: https:; "
        "media-src 'self' https: data:; "
        "frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    return response

@app.before_request
def security_pre_flight():
    """Performs rate limiting, CSRF verification, and method validation."""
    if request.method == 'OPTIONS':
        return ('', 204)

    if request.path.startswith('/api/'):
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1').split(',')[0].strip()
        if is_rate_limited(client_ip):
            return jsonify({
                "status": "ERROR",
                "code": 429,
                "message": "Rate limit exceeded. Security throttling engaged. Please retry in 60 seconds."
            }), 429

        # CSRF check for all state-changing API calls (POST/PUT/DELETE/PATCH)
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            if request.path not in _CSRF_EXEMPT:
                if not _verify_csrf():
                    logger.warning("CSRF validation failed: ip=%s path=%s", client_ip, request.path)
                    return jsonify({
                        "status": "ERROR",
                        "code": 403,
                        "message": "CSRF token missing or invalid. Fetch a token from GET /api/csrf-token and include it as the X-CSRF-Token header."
                    }), 403

# ============================================================================
# WEB UI ROUTE
# ============================================================================
@app.route('/')
def index():
    """Renders the primary SafeGuard Cyber Intelligence HUD."""
    return render_template('index.html')


# ============================================================================
# CSRF TOKEN ENDPOINT
# ============================================================================
@app.route('/api/csrf-token', methods=['GET'])
def api_csrf_token():
    """
    Issues a CSRF token for the current session.
    Clients must fetch this token and include it as the X-CSRF-Token
    header on every state-changing POST/PUT/DELETE request.
    """
    token = _get_csrf_token()
    return jsonify({"status": "SUCCESS", "csrf_token": token})

# ============================================================================
# AUTHENTICATION & USER MANAGEMENT (MySQL)
# ============================================================================
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """Registers a new user into MySQL with password hashing."""
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'SecOps Analyst')

    if not username or not email or not password:
        return jsonify({"status": "ERROR", "message": "Username, email, and password are required."}), 400

    user, err = database.create_user(username, email, password, role)
    if err:
        logger.warning("Registration failed for username=%s email=%s: %s", username, email, err)
        return jsonify({"status": "ERROR", "message": err}), 400

    session['user_id'] = user['id']
    logger.info("User registered: id=%s username=%s", user['id'], username)
    return jsonify({"status": "SUCCESS", "message": "User registered successfully.", "user": user})

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Authenticates user against MySQL password hash."""
    data = request.get_json(silent=True) or {}
    username_or_email = data.get('username', '').strip()
    password = data.get('password', '')

    if not username_or_email or not password:
        return jsonify({"status": "ERROR", "message": "Username and password are required."}), 400

    user, err = database.authenticate_user(username_or_email, password)
    if err:
        logger.warning("Login failed for identifier=%s: %s", username_or_email, err)
        return jsonify({"status": "ERROR", "message": err}), 401

    session['user_id'] = user['id']
    logger.info("Login success: id=%s username=%s", user['id'], user.get('username'))
    return jsonify({"status": "SUCCESS", "message": "Login successful.", "user": user})

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """Clears user session."""
    session.pop('user_id', None)
    return jsonify({"status": "SUCCESS", "message": "Logged out successfully."})

@app.route('/api/auth/me', methods=['GET'])
def api_auth_me():
    """Returns currently authenticated user profile from MySQL."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"status": "SUCCESS", "authenticated": False, "user": None})

    user = database.get_user_by_id(user_id)
    if not user:
        session.pop('user_id', None)
        return jsonify({"status": "SUCCESS", "authenticated": False, "user": None})

    return jsonify({"status": "SUCCESS", "authenticated": True, "user": user})

# ============================================================================
# REAL TELEMETRY & DATABASE STATS
# ============================================================================
@app.route('/api/dashboard/stats', methods=['GET'])
def api_dashboard_stats():
    """Fetches real metrics, incident stream, and threat feed from MySQL."""
    metrics = database.get_dashboard_metrics()
    recent_scans = database.get_recent_scans(limit=8)
    incidents = database.get_incidents_list()
    threat_feed = database.get_threat_feed_list()

    return jsonify({
        "status": "SUCCESS",
        "data": {
            "metrics": metrics,
            "recent_scans": recent_scans,
            "incidents": incidents,
            "threat_feed": threat_feed
        }
    })

# ============================================================================
# LEARNING ACADEMY ENDPOINTS (VIDEO COURSES, QUIZZES, CHEATSHEETS)
# ============================================================================
@app.route('/api/learning/courses', methods=['GET'])
def api_learning_courses():
    """Fetches all cybersecurity video courses."""
    courses = database.get_courses()
    return jsonify({"status": "SUCCESS", "data": courses})

@app.route('/api/learning/course/<int:course_id>', methods=['GET'])
def api_learning_course_detail(course_id):
    """Fetches details and video syllabus for a specific course."""
    course = database.get_course_by_id(course_id)
    if not course:
        return jsonify({"status": "ERROR", "message": "Course not found"}), 404
    return jsonify({"status": "SUCCESS", "data": course})

@app.route('/api/learning/quizzes', methods=['GET'])
def api_learning_quizzes():
    """Fetches available cybersecurity quizzes."""
    quizzes = database.get_quizzes()
    return jsonify({"status": "SUCCESS", "data": quizzes})

@app.route('/api/learning/quiz/<int:quiz_id>', methods=['GET'])
def api_learning_quiz_detail(quiz_id):
    """Fetches quiz questions and pass criteria."""
    quiz = database.get_quiz_by_id(quiz_id)
    if not quiz:
        return jsonify({"status": "ERROR", "message": "Quiz not found"}), 404
    return jsonify({"status": "SUCCESS", "data": quiz})

@app.route('/api/learning/quiz/submit', methods=['POST'])
def api_learning_quiz_submit():
    """Evaluates user quiz responses, returns score with explanations, and records attempt."""
    data = request.get_json(silent=True) or {}
    quiz_id = data.get('quiz_id')
    user_answers = data.get('answers', {})  # { question_id: selected_index }

    quiz = database.get_quiz_by_id(quiz_id)
    if not quiz:
        return jsonify({"status": "ERROR", "message": "Quiz not found"}), 404

    questions = quiz.get('questions', [])
    total_q = len(questions)
    correct_cnt = 0
    feedback = []

    for q in questions:
        qid_str = str(q['id'])
        user_choice = user_answers.get(qid_str)
        is_correct = (user_choice is not None and int(user_choice) == int(q['correct']))
        if is_correct:
            correct_cnt += 1
        feedback.append({
            "question_id": q['id'],
            "question": q['question'],
            "user_choice": user_choice,
            "correct_choice": q['correct'],
            "is_correct": is_correct,
            "explanation": q.get('explanation', '')
        })

    score = int((correct_cnt / max(1, total_q)) * 100)
    passed = score >= quiz.get('pass_score', 70)

    user_id = session.get('user_id')
    attempt_id = database.save_quiz_attempt(user_id, quiz_id, score, passed)

    return jsonify({
        "status": "SUCCESS",
        "data": {
            "attempt_id": attempt_id,
            "score": score,
            "passed": passed,
            "pass_score": quiz.get('pass_score', 70),
            "correct_count": correct_cnt,
            "total_questions": total_q,
            "feedback": feedback
        }
    })

@app.route('/api/learning/materials', methods=['GET'])
def api_learning_materials():
    """Fetches downloadable cybersecurity cheatsheets and field references."""
    materials = database.get_course_materials()
    return jsonify({"status": "SUCCESS", "data": materials})

# ============================================================================
# API SCAN ENDPOINTS (WITH MYSQL PERSISTENCE)
# ============================================================================
@app.route('/api/health', methods=['GET'])
def health():
    """System diagnostic and telemetry health check."""
    return jsonify({
        "status": "ONLINE",
        "service": "SafeGuard Cyber Intelligence Engine",
        "version": "2.4.0",
        "database": "MySQL / MariaDB Connected",
        "runtime": "Python/WSGI",
        "timestamp": time.time(),
        "deployment_target": "cPanel / Enterprise WSGI Ready"
    })

@app.route('/api/scan/url', methods=['POST'])
def api_scan_url():
    """Scans URL, saves results to MySQL, and returns telemetry."""
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()

    err = _validate_url(url)
    if err:
        return jsonify({"status": "ERROR", "message": err}), 400

    result = analyze_url(url)
    logger.info("url_scan: target=%s verdict=%s score=%d", result.get('hostname', url[:50]), result['verdict'], result['risk_score'])

    user_id = session.get('user_id')
    summary = f"{result['verdict']}: {len(result['indicators'])} threat indicators identified on {result['hostname']}"
    scan_id = database.save_scan(
        user_id=user_id,
        scan_type="url",
        target_input=url[:2048],
        threat_score=result['risk_score'],
        verdict=result['verdict'],
        verdict_tier=result['verdict_class'],
        summary=summary,
        details_dict=result
    )
    result['scan_id'] = scan_id
    return jsonify({"status": "SUCCESS", "data": result})

@app.route('/api/scan/message', methods=['POST'])
def api_scan_message():
    """Analyzes message body, saves to MySQL, and returns detected vectors."""
    data = request.get_json(silent=True) or {}
    text = data.get('text', '').strip()

    err = _validate_text(text)
    if err:
        return jsonify({"status": "ERROR", "message": err}), 400

    result = analyze_message(text)
    logger.info("message_scan: length=%d verdict=%s score=%d", len(text), result['verdict'], result['threat_score'])

    user_id = session.get('user_id')
    summary = f"{result['verdict']}: {len(result.get('vectors_detected', []))} social engineering attack vectors"
    scan_id = database.save_scan(
        user_id=user_id,
        scan_type="message",
        target_input=text[:200] + ('...' if len(text) > 200 else ''),
        threat_score=result['threat_score'],
        verdict=result['verdict'],
        verdict_tier=result['verdict_class'],
        summary=summary,
        details_dict=result
    )
    result['scan_id'] = scan_id
    return jsonify({"status": "SUCCESS", "data": result})

@app.route('/api/scan/email', methods=['POST'])
def api_scan_email():
    """Audits email address, saves result to MySQL, and returns exposure status."""
    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip()

    err = _validate_email(email)
    if err:
        return jsonify({"status": "ERROR", "message": err}), 400

    result = audit_email(email)
    if "error" in result:
        logger.warning("email_audit error: %s", result["error"])
        return jsonify({"status": "ERROR", "message": result["error"]}), 400
    logger.info("email_audit: domain=%s disposable=%s risk=%s", result['domain'], result['is_disposable'], result['risk_level'])

    user_id = session.get('user_id')
    tier = 'critical' if result['breaches_detected'] > 0 else (
        'warning' if result['is_disposable'] else 'safe'
    )
    summary = f"{result['risk_level']}: disposable={result['is_disposable']}"
    scan_id = database.save_scan(
        user_id=user_id,
        scan_type="email",
        target_input=email,
        threat_score=result['risk_score'],
        verdict=result['risk_level'],
        verdict_tier=tier,
        summary=summary,
        details_dict=result
    )
    result['scan_id'] = scan_id
    return jsonify({"status": "SUCCESS", "data": result})

@app.route('/api/audit/password', methods=['POST'])
def api_audit_password():
    """Evaluates password entropy and crack times (password text never saved in DB, only entropy score)."""
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    err = _validate_password(password)
    if err:
        return jsonify({"status": "ERROR", "message": err}), 400

    result = audit_password(password)
    logger.info("password_audit: length=%d verdict=%s score=%d pwned=%s",
                result['length'], result['verdict'], result['score'],
                result.get('pwned_check', {}).get('pwned', 'unknown'))

    user_id = session.get('user_id')
    summary = f"{result['verdict']}: {result['entropy_bits']} bits entropy | pool {result['pool_size']}"
    database.save_scan(
        user_id=user_id,
        scan_type="password",
        target_input=f"Password Audit (length: {result['length']})",
        threat_score=100 - result['score'],
        verdict=result['verdict'],
        verdict_tier=result['tier'],
        summary=summary,
        details_dict={"entropy_bits": result['entropy_bits'], "crack_times": result['crack_times'], "score": result['score']}
    )
    return jsonify({"status": "SUCCESS", "data": result})

@app.route('/api/audit/headers', methods=['POST'])
def api_audit_headers():
    """Live audit of target HTTP security headers and saves result to MySQL."""
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()

    err = _validate_url(url)
    if err:
        return jsonify({"status": "ERROR", "message": err}), 400

    result = inspect_headers(url)
    logger.info("header_audit: target=%s live=%s grade=%s score=%s",
                url[:80], result.get('live_connection'), result.get('security_grade'), result.get('security_score'))

    # If live connection failed, return the error result without saving a scan
    if not result.get('live_connection') and result.get('security_score') is None:
        return jsonify({"status": "ERROR", "data": result,
                        "message": result.get('note', 'Live connection failed.')}), 502

    user_id = session.get('user_id')
    summary = f"Grade {result['security_grade']}: Score {result['security_score']}/100"
    database.save_scan(
        user_id=user_id,
        scan_type="headers",
        target_input=url[:2048],
        threat_score=100 - result['security_score'],
        verdict=f"Security Grade {result['security_grade']}",
        verdict_tier=result['tier'],
        summary=summary,
        details_dict=result
    )
    return jsonify({"status": "SUCCESS", "data": result})

@app.route('/api/audit/ip', methods=['POST'])
def api_audit_ip():
    """Evaluates IP address risk, saves to MySQL, and returns network routing."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()

    err = _validate_ip(ip)
    if err:
        return jsonify({"status": "ERROR", "message": err}), 400

    result = audit_ip(ip)
    if "error" in result:
        logger.warning("ip_audit error: ip=%s error=%s", ip, result["error"])
        return jsonify({"status": "ERROR", "message": result["error"]}), 400
    logger.info("ip_audit: ip=%s verdict=%s score=%s live=%s",
                ip, result['verdict'], result['threat_score'], result.get('live_lookup'))

    user_id = session.get('user_id')
    threat_score = result['threat_score'] if result['threat_score'] is not None else 0
    summary = f"{result['verdict']}: {result['category']}"
    database.save_scan(
        user_id=user_id,
        scan_type="ip",
        target_input=ip,
        threat_score=threat_score,
        verdict=result['verdict'],
        verdict_tier=result['tier'],
        summary=summary,
        details_dict=result
    )
    return jsonify({"status": "SUCCESS", "data": result})

@app.route('/api/crypto/hashes', methods=['POST'])
def api_crypto_hashes():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    if not text:
        return jsonify({"status": "ERROR", "message": "Input text is required."}), 400
    return jsonify({"status": "SUCCESS", "data": compute_hashes(text)})

@app.route('/api/crypto/identify', methods=['POST'])
def api_crypto_identify():
    data = request.get_json(silent=True) or {}
    hash_str = data.get('hash', '').strip()
    if not hash_str:
        return jsonify({"status": "ERROR", "message": "Hash string is required."}), 400
    result = analyze_hash(hash_str)
    if "error" in result:
        return jsonify({"status": "ERROR", "message": result["error"]}), 400
    return jsonify({"status": "SUCCESS", "data": result})

@app.route('/api/crypto/transform', methods=['POST'])
def api_crypto_transform():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    operation = data.get('operation', '')
    result = encode_decode_payload(text, operation)
    if "error" in result:
        return jsonify({"status": "ERROR", "message": result["error"]}), 400
    return jsonify({"status": "SUCCESS", "data": result})

@app.route('/api/threat-intel/feed', methods=['GET'])
def api_threat_feed():
    return jsonify({"status": "SUCCESS", "data": get_threat_intel_snapshot()})

@app.route('/api/threat-intel/playbooks', methods=['GET'])
def api_playbooks():
    return jsonify({"status": "SUCCESS", "data": INCIDENT_PLAYBOOKS})

# ============================================================================
# ERROR HANDLERS
# ============================================================================
@app.errorhandler(404)
def handle_404(e):
    if request.path.startswith('/api/'):
        return jsonify({"status": "ERROR", "code": 404, "message": "Requested endpoint not found."}), 404
    return render_template('index.html'), 404

@app.errorhandler(500)
def handle_500(e):
    logger.error("Internal server error: %s", e, exc_info=True)
    return jsonify({"status": "ERROR", "code": 500, "message": "Internal cybersecurity engine fault."}), 500

# WSGI Application reference for Passenger
application = app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

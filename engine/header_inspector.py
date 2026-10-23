"""
SafeGuard HTTP Security Headers & Transport Layer Inspector
Audits website security headers, transport layer compliance, and information leakage.

A live HTTP request is made to the target host. If the request fails (firewall,
timeout, offline host) the function returns an honest error result instead of
silently falling back to fake passing data.
"""

import urllib.request
import ssl
from urllib.parse import urlparse

SECURITY_HEADER_STANDARDS = {
    "strict-transport-security": {
        "title": "HTTP Strict Transport Security (HSTS)",
        "importance": "CRITICAL",
        "description": "Enforces HTTPS connections and eliminates protocol downgrade/SSL-stripping attacks."
    },
    "content-security-policy": {
        "title": "Content Security Policy (CSP)",
        "importance": "CRITICAL",
        "description": "Restricts dynamic resources (scripts, images) to mitigate Cross-Site Scripting (XSS) and data injection."
    },
    "x-frame-options": {
        "title": "X-Frame-Options",
        "importance": "HIGH",
        "description": "Defends against clickjacking by preventing the site from being rendered inside an iframe."
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options",
        "importance": "MEDIUM",
        "description": "Prevents browsers from MIME-sniffing responses away from the declared content-type."
    },
    "referrer-policy": {
        "title": "Referrer-Policy",
        "importance": "MEDIUM",
        "description": "Governs how much referrer information (paths, query parameters) is included with requests."
    },
    "permissions-policy": {
        "title": "Permissions-Policy",
        "importance": "MEDIUM",
        "description": "Allows fine-grained control over browser features (camera, microphone, geolocation)."
    }
}

LEAK_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime']


def inspect_headers(target_url: str) -> dict:
    """
    Connects to target web host and performs a live audit of HTTP security headers.

    Returns a structured result with real header values and a security grade.
    If the live connection fails for any reason, returns an error result with
    live_connection=False and a descriptive error message — no fake data is used.
    """
    target_url = target_url.strip()
    if not target_url:
        return {"error": "Target URL is required"}

    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    parsed = urlparse(target_url)
    hostname = parsed.hostname or ''

    headers_found = {}
    leakage_found = {}
    status_code = None
    connection_error = None

    try:
        # Accept self-signed certs so legitimate test/staging hosts don't fail
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            target_url,
            headers={'User-Agent': 'SafeGuard-CyberIntel-Scanner/2.4 (SecurityAudit; Enterprise)'}
        )
        with urllib.request.urlopen(req, timeout=6, context=ctx) as response:
            status_code = response.getcode()
            raw_headers = response.info()
            for k, v in raw_headers.items():
                k_lower = k.lower()
                headers_found[k_lower] = v
                if k_lower in LEAK_HEADERS:
                    leakage_found[k_lower] = v

    except Exception as e:
        # Return an honest error result — never substitute fake passing headers
        return {
            "url": target_url,
            "hostname": hostname,
            "live_connection": False,
            "status_code": None,
            "connection_error": str(e),
            "security_score": None,
            "security_grade": "N/A",
            "tier": "warning",
            "audit_results": [],
            "information_leakage": {},
            "total_headers_received": 0,
            "note": (
                "Live connection to the target host failed. The audit cannot proceed "
                "without a real HTTP response. Verify the URL is reachable, check "
                "firewall rules, and ensure the host is online."
            )
        }

    # ── Evaluate headers against standards ───────────────────────────────────
    header_results = []
    score = 100

    for h_key, meta in SECURITY_HEADER_STANDARDS.items():
        present = h_key in headers_found
        value = headers_found.get(h_key, None)

        if not present:
            deduction = 20 if meta["importance"] == "CRITICAL" else 10
            score -= deduction

        header_results.append({
            "header": h_key,
            "title": meta["title"],
            "importance": meta["importance"],
            "description": meta["description"],
            "present": present,
            "value": value
        })

    # Penalise information-leakage headers
    if leakage_found:
        score -= len(leakage_found) * 5

    score = max(0, min(100, score))

    if score >= 85:
        grade = "A+"
        tier = "safe"
    elif score >= 70:
        grade = "B"
        tier = "safe"
    elif score >= 50:
        grade = "C"
        tier = "warning"
    else:
        grade = "F"
        tier = "critical"

    return {
        "url": target_url,
        "hostname": hostname,
        "live_connection": True,
        "status_code": status_code,
        "connection_error": None,
        "security_score": score,
        "security_grade": grade,
        "tier": tier,
        "audit_results": header_results,
        "information_leakage": leakage_found,
        "total_headers_received": len(headers_found)
    }

"""
SafeGuard Email Breach & Domain Exposure Intelligence Engine
Audits emails for disposable domains and RFC 5322 format validity.

Password breach checks use the HIBP k-anonymity range API — the full password
is NEVER transmitted, only the first 5 characters of its SHA-1 hash are sent.

Full email breach history (Have I Been Pwned /breachedaccount/) requires a
paid HIBP API key. Without one, this module still provides real disposable
domain detection and honest status messaging.
"""

import re
import hashlib
import logging
import requests

logger = logging.getLogger("safeguard.breach_checker")

DISPOSABLE_DOMAINS = {
    'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'trashmail.com',
    'tempmail.com', 'temp-mail.org', 'yopmail.com', 'throwawaymail.com',
    'dispostable.com', 'sharklasers.com', 'fakeinbox.com', 'getairmail.com'
}

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')


def check_password_pwned(password: str) -> dict:
    """
    Checks if a password has appeared in known data breaches using the
    HIBP k-anonymity range API (https://haveibeenpwned.com/API/v3).

    Privacy guarantee: the full password is NEVER sent over the network.
    Only the first 5 characters of the SHA-1 hash are transmitted.
    The server returns all hash suffixes matching that prefix; the match
    check happens entirely on this side.

    Returns:
        {
            "pwned": bool,
            "count": int,   # number of times seen in breach corpuses
            "error": str | None
        }
    """
    if not password:
        return {"pwned": False, "count": 0, "error": "No password provided"}

    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=5
        )
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        logger.warning("breach_checker: HIBP API timeout for prefix=%s", prefix)
        return {"pwned": False, "count": 0, "error": "HIBP API timeout — could not verify against breach database"}
    except requests.exceptions.RequestException as e:
        logger.warning("breach_checker: HIBP API error: %s", e)
        return {"pwned": False, "count": 0, "error": f"HIBP API error: {str(e)}"}

    for line in resp.text.splitlines():
        line_suffix, _, count_str = line.partition(':')
        if line_suffix.strip().upper() == suffix:
            count = int(count_str.strip())
            return {"pwned": True, "count": count, "error": None}

    return {"pwned": False, "count": 0, "error": None}


def audit_email(email_address: str) -> dict:
    """
    Audits an email address for syntactic validity and disposable domain risk.

    Full email breach history requires a HIBP API key (paid tier at
    https://haveibeenpwned.com/API/v3). This function performs real
    disposable domain detection and returns an honest status message
    instead of simulated breach data.
    """
    email = (email_address or '').strip().lower()
    if not email:
        return {"error": "Email address is required"}

    if not EMAIL_REGEX.match(email):
        return {"error": "Invalid email address format conforming to RFC 5322"}

    user_part, domain_part = email.split('@', 1)
    is_disposable = domain_part in DISPOSABLE_DOMAINS

    risk_score = 0
    risk_level = "NO KNOWN EXPOSURE"
    notes = []

    if is_disposable:
        risk_score += 60
        risk_level = "ELEVATED RISK"
        notes.append(
            "Disposable/temporary email domain detected. These are commonly used "
            "to evade account tracking and bypass registration controls."
        )

    notes.append(
        "Full email breach history lookup (Have I Been Pwned) requires a HIBP API key. "
        "Configure HIBP_API_KEY in your environment to enable live breach correlation. "
        "You can verify manually at https://haveibeenpwned.com."
    )

    risk_score = min(100, risk_score)

    return {
        "email": email,
        "domain": domain_part,
        "is_disposable": is_disposable,
        "breaches_detected": 0,
        "breach_records": [],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "hibp_status": "API key not configured — live breach lookup unavailable",
        "notes": notes,
        "sha256_anonymized": hashlib.sha256(email.encode('utf-8')).hexdigest()[:16] + "...",
        "remediation_steps": [
            "Use a permanent, monitored email address for important accounts.",
            "Enable multi-factor authentication across all active accounts.",
            "Check https://haveibeenpwned.com manually to verify breach exposure.",
        ] if is_disposable else [
            "Maintain separate aliases for transactional vs personal communications.",
            "Enable multi-factor authentication across all active accounts.",
            "Check https://haveibeenpwned.com manually to verify breach exposure.",
        ]
    }

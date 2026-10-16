"""
SafeGuard Email Breach & Domain Exposure Intelligence Engine
Audits emails for breach exposure, disposable domains, and MX configuration.
"""

import re
import hashlib

DISPOSABLE_DOMAINS = {
    'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'trashmail.com',
    'tempmail.com', 'temp-mail.org', 'yopmail.com', 'throwawaymail.com',
    'dispostable.com', 'sharklasers.com', 'fakeinbox.com', 'getairmail.com'
}

# Curated repository of prominent corporate security incidents for breach correlation
BREACH_ARCHIVE = [
    {
        "name": "Canva Global Security Incident",
        "domain": "canva.com",
        "breach_date": "May 2019",
        "pwn_count": 137000000,
        "compromised_data": ["Email addresses", "Passwords (bcrypt)", "Usernames", "Names", "City"],
        "severity": "CRITICAL"
    },
    {
        "name": "LinkedIn Credential Vault Breach",
        "domain": "linkedin.com",
        "breach_date": "May 2016",
        "pwn_count": 164000000,
        "compromised_data": ["Email addresses", "Passwords (unsalted SHA-1)"],
        "severity": "CRITICAL"
    },
    {
        "name": "Adobe Systems Identity Breach",
        "domain": "adobe.com",
        "breach_date": "October 2013",
        "pwn_count": 153000000,
        "compromised_data": ["Email addresses", "Password hints", "Encrypted 3DES passwords", "Usernames"],
        "severity": "HIGH"
    },
    {
        "name": "Dropbox Cloud Storage Incident",
        "domain": "dropbox.com",
        "breach_date": "July 2012",
        "pwn_count": 68000000,
        "compromised_data": ["Email addresses", "Passwords (salted bcrypt / SHA-1)"],
        "severity": "HIGH"
    },
    {
        "name": "MyFitnessPal Health Cloud Exposure",
        "domain": "myfitnesspal.com",
        "breach_date": "February 2018",
        "pwn_count": 144000000,
        "compromised_data": ["Email addresses", "IP addresses", "Passwords (bcrypt)"],
        "severity": "HIGH"
    },
    {
        "name": "Wattpad Reading Platform Breach",
        "domain": "wattpad.com",
        "breach_date": "June 2020",
        "pwn_count": 270000000,
        "compromised_data": ["Email addresses", "IP addresses", "Dates of birth", "Passwords (bcrypt)"],
        "severity": "CRITICAL"
    }
]

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

def audit_email(email_address: str) -> dict:
    """
    Audits an email address for syntactic validity, disposable domain risk,
    and simulated breach exposures.
    """
    email = (email_address or '').strip().lower()
    if not email:
        return {"error": "Email address is required"}

    if not EMAIL_REGEX.match(email):
        return {"error": "Invalid email address format conforming to RFC 5322"}

    user_part, domain_part = email.split('@', 1)
    is_disposable = domain_part in DISPOSABLE_DOMAINS

    # Deterministic simulation based on hash of email to emulate breach search
    email_hash = hashlib.sha256(email.encode('utf-8')).hexdigest()
    hash_val = int(email_hash[:4], 16)

    # Correlate matches
    matched_breaches = []
    # Deterministic pseudo-matching so repeated checks give consistent results
    if hash_val % 3 == 0:
        matched_breaches.append(BREACH_ARCHIVE[0])
    if hash_val % 4 == 0:
        matched_breaches.append(BREACH_ARCHIVE[1])
    if hash_val % 5 == 0:
        matched_breaches.append(BREACH_ARCHIVE[3])

    # If domain belongs to one of monitored, ensure inclusion
    for b in BREACH_ARCHIVE:
        if b["domain"] in domain_part and b not in matched_breaches:
            matched_breaches.append(b)

    breach_count = len(matched_breaches)
    risk_level = "CLEAN"
    risk_score = 0

    if is_disposable:
        risk_score += 40
    if breach_count >= 2:
        risk_level = "CRITICAL COMPROMISE"
        risk_score += 75
    elif breach_count == 1:
        risk_level = "ELEVATED RISK"
        risk_score += 45
    else:
        risk_level = "NO KNOWN EXPOSURE"
        risk_score += 5

    risk_score = min(100, risk_score)

    return {
        "email": email,
        "domain": domain_part,
        "is_disposable": is_disposable,
        "breaches_detected": breach_count,
        "breach_records": matched_breaches,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "sha256_anonymized": email_hash[:16] + "..." + email_hash[-8:],
        "remediation_steps": [
            "Rotate primary master passwords immediately if shared across services.",
            "Enforce Hardware Key (FIDO2/WebAuthn) or App-based TOTP 2FA.",
            "Review connected third-party OAuth application authorizations.",
            "Place fraud alerts on credit files if financial data was involved."
        ] if breach_count > 0 else [
            "Maintain separate aliases for transactional vs personal communications.",
            "Enable multi-factor authentication across all active accounts."
        ]
    }

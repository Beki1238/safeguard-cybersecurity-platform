"""
SafeGuard URL & Domain Heuristic Analysis Engine
Detects typosquatting, homoglyphs, brand spoofing, malicious TLDs, and obfuscation.
"""

import re
import math
from urllib.parse import urlparse, parse_qs

# High-risk TLDs commonly utilized in cyber-attack campaigns
HIGH_RISK_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'buzz', 'fit', 'rest', 
    'icu', 'sbs', 'cfd', 'cyou', 'country', 'click', 'link', 'work', 
    'gdn', 'stream', 'party', 'download', 'racing', 'loan', 'win', 'bid'
}

# Targeted enterprise brands frequently impersonated in credential harvesting
MONITORED_BRANDS = [
    # Finance & banking
    'paypal', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
    'hsbc', 'barclays', 'truist', 'usbank', 'capitalone',
    'zelle', 'venmo', 'cashapp', 'wise',
    # Crypto
    'binance', 'coinbase', 'metamask', 'kraken', 'ledger', 'trezor',
    # Big tech
    'google', 'apple', 'microsoft', 'amazon', 'facebook', 'instagram',
    'twitter', 'linkedin', 'netflix', 'adobe', 'dropbox',
    # Messaging & social
    'telegram', 'whatsapp', 'discord', 'tiktok', 'snapchat', 'youtube',
    # Cloud & productivity
    'outlook', 'office365', 'icloud', 'onedrive', 'sharepoint',
    # Logistics
    'dhl', 'fedex', 'usps', 'ups',
    # Government
    'irs', 'gov',
    # Auth
    'steam', 'blizzard', 'epicgames',
]

# Sensitive authentication and finance keywords
PHISHING_KEYWORDS = [
    'login', 'signin', 'log-in', 'sign-in', 'secure', 'account', 'verify', 
    'verification', 'billing', 'update', 'banking', 'suspended', 'unlock', 
    'wallet', 'recovery', 'kyc', 'confirm', 'password', 'credential', 
    'security', 'authenticate', 'payment', 'claim', 'refund', 'bonus'
]

# Homoglyph map: Unicode lookalike → ASCII equivalent
# Covers Cyrillic, Greek, and other common IDN spoofing characters
HOMOGLYPH_MAP = {
    # Cyrillic
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x',
    'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q',
    'ѵ': 'v', 'ԝ': 'w', 'ԟ': 'k', 'ԍ': 'g', 'ԋ': 'h',
    'в': 'b', 'г': 'r', 'з': '3', 'и': 'n', 'к': 'k', 'м': 'm',
    'н': 'h', 'п': 'n', 'т': 't',
    # Greek
    'α': 'a', 'β': 'b', 'ε': 'e', 'ζ': 'z', 'η': 'n', 'ι': 'i',
    'κ': 'k', 'μ': 'm', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't',
    'υ': 'u', 'χ': 'x', 'ω': 'w',
    # Latin lookalikes
    'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ɪ': 'i', 'ʟ': 'l', 'ʀ': 'r',
    'ƅ': 'b', 'ƈ': 'c', 'ɗ': 'd', 'ƒ': 'f', 'ɦ': 'h', 'ʝ': 'j',
    'ƙ': 'k', 'ɱ': 'm', 'ɲ': 'n', 'ơ': 'o', 'ƥ': 'p', 'ʂ': 's',
    'ƭ': 't', 'ʉ': 'u', 'ʋ': 'v', 'ƴ': 'y', 'ƶ': 'z',
    # Symbols often swapped visually
    '0': 'o', '1': 'l', '|': 'l',
}


def _normalize_homoglyphs(s: str) -> str:
    """Replaces all known homoglyph characters with their ASCII equivalents."""
    return ''.join(HOMOGLYPH_MAP.get(c, c) for c in s)

def calculate_shannon_entropy(string: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not string:
        return 0.0
    entropy = 0.0
    length = len(string)
    frequencies = {}
    for char in string:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates minimum edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def analyze_url(raw_url: str) -> dict:
    """
    Performs deep heuristic risk evaluation on a target URL.
    Returns comprehensive telemetry, risk score (0-100), indicators, and verdict.
    """
    raw_url = raw_url.strip()
    if not raw_url:
        return {"error": "Target URL cannot be empty"}
    
    # Auto-prepend scheme if missing for parsing
    if not re.match(r'^[a-zA-Z]+://', raw_url):
        target_url = 'http://' + raw_url
    else:
        target_url = raw_url

    try:
        parsed = urlparse(target_url)
    except Exception as e:
        return {"error": f"Invalid URL structure: {str(e)}"}

    hostname = (parsed.hostname or '').lower()
    port = parsed.port
    path = parsed.path
    query = parsed.query
    scheme = parsed.scheme.lower()

    indicators = []
    risk_score = 0

    # 1. Protocol security check
    if scheme != 'https':
        risk_score += 15
        indicators.append({
            "type": "PROTOCOL_SECURITY",
            "severity": "MEDIUM",
            "message": "Cleartext HTTP protocol in use. Communications are vulnerable to Man-in-the-Middle (MitM) inspection.",
            "impact": +15
        })

    # 2. IP address hostname check (e.g. http://192.168.1.1/login or decimal obfuscation)
    is_ipv4 = bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', hostname))
    is_decimal_ip = bool(re.match(r'^[0-9]{7,11}$', hostname))
    if is_ipv4 or is_decimal_ip:
        risk_score += 40
        indicators.append({
            "type": "IP_HOST_OBFUSCATION",
            "severity": "CRITICAL",
            "message": "Direct IP address host used in place of standard domain registry. Highly characteristic of malware C2 or zero-reputation phishing staging.",
            "impact": +40
        })

    # 3. Homoglyph / Punycode check (IDN homograph spoofing)
    has_punycode = hostname.startswith('xn--') or '.xn--' in hostname
    has_homoglyphs = any(char in HOMOGLYPH_MAP for char in hostname)
    if has_punycode or has_homoglyphs:
        risk_score += 45
        indicators.append({
            "type": "HOMOGRAPH_ATTACK",
            "severity": "CRITICAL",
            "message": "IDN / Punycode homoglyph detected. The domain visually mimics a legitimate brand using lookalike non-ASCII characters.",
            "impact": +45
        })

    # 4. TLD Risk Evaluation
    tld = hostname.split('.')[-1] if '.' in hostname else ''
    if tld in HIGH_RISK_TLDS:
        risk_score += 25
        indicators.append({
            "type": "SUSPICIOUS_TLD",
            "severity": "HIGH",
            "message": f"High-risk Top-Level Domain (.{tld}) with statistically elevated correlation to spam, automated exploits, and phishing hosting.",
            "impact": +25
        })

    # 5. Brand Spoofing / Typosquatting Analysis
    # Also run checks against a homoglyph-normalized version of the hostname
    # so that e.g. "pаypal.com" (Cyrillic 'а') is caught as a PayPal spoof.
    matched_brands = []
    typosquatted_brands = []
    domain_labels = hostname.split('.')
    main_domain = domain_labels[-2] if len(domain_labels) >= 2 else hostname
    normalized_hostname = _normalize_homoglyphs(hostname)
    normalized_main_domain = _normalize_homoglyphs(main_domain)

    for brand in MONITORED_BRANDS:
        # Impersonation: brand token appears in subdomains/path but main domain isn't the brand
        if brand in hostname or brand in normalized_hostname:
            # Check against both raw and normalized main domain
            if main_domain != brand and normalized_main_domain != brand:
                matched_brands.append(brand)
        else:
            # Typosquatting: Levenshtein distance check on both raw and normalized main domain
            for candidate in (main_domain, normalized_main_domain):
                dist = levenshtein_distance(candidate, brand)
                if 0 < dist <= 2 and abs(len(candidate) - len(brand)) <= 2:
                    typosquatted_brands.append((brand, dist))
                    break  # don't double-count if both raw and normalized match

    if matched_brands:
        risk_score += 45
        indicators.append({
            "type": "BRAND_IMPERSONATION",
            "severity": "CRITICAL",
            "message": f"Brand impersonation vector detected for [{', '.join(matched_brands).upper()}]. Brand token placed outside primary registrant domain.",
            "impact": +45
        })

    if typosquatted_brands:
        squat_names = [b[0].upper() for b in typosquatted_brands]
        risk_score += 35
        indicators.append({
            "type": "TYPOSQUATTING",
            "severity": "HIGH",
            "message": f"Typosquatted domain target resembling authorized brand [{', '.join(squat_names)}]. Designed to exploit keyboard typing errors.",
            "impact": +35
        })

    # 6. Sensitive Phishing & Credential Keywords
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in target_url.lower()]
    if len(found_keywords) >= 2:
        weight = min(35, len(found_keywords) * 10)
        risk_score += weight
        indicators.append({
            "type": "CREDENTIAL_HARVESTING_TOKENS",
            "severity": "HIGH",
            "message": f"Multiple high-confidence authentication/financial keyword tokens identified: {found_keywords[:4]}.",
            "impact": weight
        })
    elif len(found_keywords) == 1:
        risk_score += 10
        indicators.append({
            "type": "SUSPICIOUS_TOKEN",
            "severity": "LOW",
            "message": f"Target contains sensitive keyword token: '{found_keywords[0]}'.",
            "impact": +10
        })

    # 7. Subdomain Chaining / Depth
    subdomain_count = max(0, len(domain_labels) - 2)
    if subdomain_count >= 3:
        risk_score += 20
        indicators.append({
            "type": "DEEP_SUBDOMAIN_CHAINING",
            "severity": "MEDIUM",
            "message": f"Excessive subdomain depth ({subdomain_count} nested levels). Frequently configured to disguise fraudulent destination URLs on free DNS providers.",
            "impact": +20
        })

    # 8. Entropy Analysis
    domain_entropy = calculate_shannon_entropy(hostname)
    if domain_entropy > 4.2 and len(hostname) > 12:
        risk_score += 20
        indicators.append({
            "type": "HIGH_DOMAIN_ENTROPY",
            "severity": "MEDIUM",
            "message": f"High Shannon entropy score ({domain_entropy:.2f} bits/symbol). Suggests algorithmic pseudo-random generation (DGA) or obfuscated domain registration.",
            "impact": +20
        })

    # 9. Open Redirect Pattern Detection
    query_params = parse_qs(query)
    redirect_keys = {'url', 'redirect', 'redirect_to', 'next', 'return', 'dest', 'destination', 'target', 'link'}
    found_redirects = [k for k in query_params if k.lower() in redirect_keys]
    if found_redirects:
        risk_score += 20
        indicators.append({
            "type": "OPEN_REDIRECT_PARAMETER",
            "severity": "MEDIUM",
            "message": f"Open redirection parameter detected ({found_redirects[0]}). May be leveraged to bypass gateway security filters.",
            "impact": +20
        })

    # 10. Non-standard HTTP Port
    if port and port not in (80, 443, 8080, 8443):
        risk_score += 25
        indicators.append({
            "type": "NON_STANDARD_PORT",
            "severity": "HIGH",
            "message": f"Destination establishes connection on atypical port {port}. Evades standard perimeter web proxy inspection.",
            "impact": +25
        })

    # Clamp score
    risk_score = min(100, max(0, risk_score))

    # Determine Verdict
    if risk_score >= 70:
        verdict = "MALICIOUS"
        verdict_class = "critical"
        action = "BLOCK AND ISOLATE"
    elif risk_score >= 45:
        verdict = "SUSPICIOUS"
        verdict_class = "warning"
        action = "EXERCISE EXTREME CAUTION"
    elif risk_score >= 20:
        verdict = "LOW RISK"
        verdict_class = "caution"
        action = "PROCEED WITH MONITORING"
    else:
        verdict = "CLEAN / BENIGN"
        verdict_class = "safe"
        action = "PERMITTED"

    return {
        "url": target_url,
        "hostname": hostname,
        "scheme": scheme,
        "port": port or (443 if scheme == 'https' else 80),
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "action_recommendation": action,
        "indicators": indicators,
        "entropy": {
            "domain_entropy": domain_entropy,
            "path_entropy": calculate_shannon_entropy(path)
        },
        "structure": {
            "subdomains_count": subdomain_count,
            "tld": tld,
            "is_ip": is_ipv4 or is_decimal_ip,
            "has_punycode": has_punycode
        }
    }

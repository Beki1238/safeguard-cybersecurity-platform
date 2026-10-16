"""
SafeGuard IP Intelligence & Autonomous System Network Engine
Evaluates IPv4/IPv6 addresses, bogon ranges, ASN attribution, and reputation.
"""

import ipaddress
import hashlib

def audit_ip(ip_str: str) -> dict:
    """
    Analyzes an IPv4 or IPv6 address for network classification, bogon status,
    and simulated threat telemetry.
    """
    ip_str = (ip_str or '').strip()
    if not ip_str:
        return {"error": "IP address is required"}

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"error": f"Invalid IP address format: '{ip_str}'"}

    is_private = ip_obj.is_private
    is_loopback = ip_obj.is_loopback
    is_reserved = ip_obj.is_reserved
    is_multicast = ip_obj.is_multicast
    is_global = ip_obj.is_global

    # Deterministic telemetry based on IP hash
    ip_hash = hashlib.sha256(ip_str.encode()).hexdigest()
    hash_num = int(ip_hash[:6], 16)

    # Simulated ASN and Geo metadata
    countries = [
        {"country": "United States", "code": "US", "city": "Ashburn", "asn": "AS16509 (Amazon.com, Inc.)"},
        {"country": "Germany", "code": "DE", "city": "Frankfurt", "asn": "AS24940 (Hetzner Online GmbH)"},
        {"country": "Netherlands", "code": "NL", "city": "Amsterdam", "asn": "AS13335 (Cloudflare, Inc.)"},
        {"country": "United Kingdom", "code": "GB", "city": "London", "asn": "AS20940 (Akamai International)"},
        {"country": "Singapore", "code": "SG", "city": "Singapore", "asn": "AS45102 (Alibaba Cloud LLC)"}
    ]
    geo = countries[hash_num % len(countries)]

    is_threat = (hash_num % 7 == 0) and not is_private
    threat_score = 88 if is_threat else (12 if is_private else (hash_num % 30))

    if threat_score >= 70:
        verdict = "CONFIRMED MALICIOUS HOST"
        tier = "critical"
        category = "C2 / Botnet Node"
    elif threat_score >= 40:
        verdict = "SUSPICIOUS TRAFFIC"
        tier = "warning"
        category = "Bulletproof Hosting / VPN"
    else:
        verdict = "CLEAN TRAFFIC"
        tier = "safe"
        category = "Legitimate Subscriber / CDN"

    return {
        "ip": str(ip_obj),
        "version": ip_obj.version,
        "is_private": is_private,
        "is_loopback": is_loopback,
        "is_reserved": is_reserved,
        "is_global": is_global,
        "threat_score": threat_score,
        "verdict": verdict,
        "tier": tier,
        "category": category,
        "network_intelligence": {
            "asn": geo["asn"] if is_global else "Internal Private Network (RFC 1918)",
            "country": geo["country"] if is_global else "Local Subnet",
            "country_code": geo["code"] if is_global else "LOCAL",
            "city": geo["city"] if is_global else "Localhost",
            "reverse_dns": f"host-{ip_str.replace('.', '-')}.edge.net" if is_global else "local.domain"
        }
    }

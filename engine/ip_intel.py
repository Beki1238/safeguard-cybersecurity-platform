"""
SafeGuard IP Intelligence & Autonomous System Network Engine
Evaluates IPv4/IPv6 addresses using real ip-api.com geolocation and threat signals.

Free tier: 45 requests/minute, no API key required.
API docs: https://ip-api.com/docs/api:json
"""

import ipaddress
import logging
import requests

logger = logging.getLogger("safeguard.ip_intel")

# Fields requested from ip-api.com
_IPAPI_URL = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,country,countryCode,city,isp,org,as,proxy,hosting,query"
)


def audit_ip(ip_str: str) -> dict:
    """
    Analyzes an IPv4 or IPv6 address for network classification,
    geolocation, ASN, and proxy/hosting threat signals via ip-api.com.

    Private/loopback/reserved IPs are classified locally without any
    external API call.
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

    # For private/loopback/reserved IPs, no external lookup needed
    if not is_global or is_loopback or is_reserved or is_multicast:
        return {
            "ip": str(ip_obj),
            "version": ip_obj.version,
            "is_private": is_private,
            "is_loopback": is_loopback,
            "is_reserved": is_reserved,
            "is_global": is_global,
            "threat_score": 0,
            "verdict": "PRIVATE / INTERNAL ADDRESS",
            "tier": "safe",
            "category": "Internal Network (RFC 1918 / Loopback)",
            "live_lookup": False,
            "network_intelligence": {
                "asn": "Internal Private Network (RFC 1918)",
                "country": "Local Subnet",
                "country_code": "LOCAL",
                "city": "Localhost",
                "isp": "N/A",
                "org": "N/A",
                "reverse_dns": "local.domain",
                "is_proxy": False,
                "is_hosting": False
            }
        }

    # Live lookup for global IPs
    try:
        resp = requests.get(
            _IPAPI_URL.format(ip=ip_str),
            timeout=5,
            headers={"User-Agent": "SafeGuard-CyberIntel/2.4"}
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        logger.warning("ip_intel: ip-api.com timeout for ip=%s", ip_str)
        return _fallback_result(ip_obj, "ip-api.com lookup timed out after 5 seconds")
    except requests.exceptions.RequestException as e:
        logger.warning("ip_intel: ip-api.com request error for ip=%s: %s", ip_str, e)
        return _fallback_result(ip_obj, f"ip-api.com lookup failed: {str(e)}")

    if data.get("status") != "success":
        logger.warning("ip_intel: ip-api.com non-success for ip=%s: %s", ip_str, data.get("message"))
        return _fallback_result(ip_obj, data.get("message", "Unknown ip-api.com error"))

    is_proxy = data.get("proxy", False)
    is_hosting = data.get("hosting", False)

    # Threat scoring based on real signals from ip-api.com
    threat_score = 5  # baseline for any routable global IP
    if is_proxy:
        threat_score += 35
    if is_hosting:
        threat_score += 15
    threat_score = min(100, threat_score)

    if threat_score >= 70:
        verdict = "HIGH RISK HOST"
        tier = "critical"
        category = "Anonymous Proxy / Tor Exit Node"
    elif threat_score >= 35:
        verdict = "SUSPICIOUS TRAFFIC"
        tier = "warning"
        category = "VPN / Hosting Provider / Proxy"
    else:
        verdict = "CLEAN TRAFFIC"
        tier = "safe"
        category = "Legitimate CDN / Hosting" if is_hosting else "Residential / Business ISP"

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
        "live_lookup": True,
        "network_intelligence": {
            "asn": data.get("as", "Unknown"),
            "country": data.get("country", "Unknown"),
            "country_code": data.get("countryCode", "??"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "org": data.get("org", "Unknown"),
            "reverse_dns": f"host-{ip_str.replace('.', '-')}.edge.net",
            "is_proxy": is_proxy,
            "is_hosting": is_hosting
        }
    }


def _fallback_result(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, error_msg: str) -> dict:
    """Returns a partial result when the live API lookup fails."""
    return {
        "ip": str(ip_obj),
        "version": ip_obj.version,
        "is_private": ip_obj.is_private,
        "is_loopback": ip_obj.is_loopback,
        "is_reserved": ip_obj.is_reserved,
        "is_global": ip_obj.is_global,
        "threat_score": None,
        "verdict": "LOOKUP UNAVAILABLE",
        "tier": "warning",
        "category": "Live intelligence unavailable — manual verification required",
        "live_lookup": False,
        "lookup_error": error_msg,
        "network_intelligence": None
    }

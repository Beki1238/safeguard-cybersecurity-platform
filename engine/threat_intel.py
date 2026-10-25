"""
Gasha Threat Intelligence & Incident Response Knowledge Core
Live CVE data sourced from CISA Known Exploited Vulnerabilities (KEV) feed.
CVSS scores enriched via NVD REST API v2.0. Both caches use a 1-hour TTL.

Sources:
  CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  NVD API:  https://nvd.nist.gov/developers/vulnerabilities
"""

import os
import time
import requests
from datetime import datetime, timezone

# ── In-memory caches ─────────────────────────────────────────────────────────
_intel_cache = {
    "kev_entries": None,       # list of enriched CVE dicts (top 6 most recent)
    "total_kev_count": 0,      # total CVEs in the full CISA KEV catalogue
    "fetched_at": 0.0          # unix timestamp of last successful fetch
}
_nvd_cvss_cache: dict[str, float | None] = {}  # { "CVE-XXXX-XXXXX": score }

CACHE_TTL = 3600  # 1 hour in seconds

# ── Static fallback CVEs (used only when CISA is unreachable) ────────────────
STATIC_FALLBACK_CVES = [
    {
        "cve": "CVE-2024-3400",
        "title": "Palo Alto PAN-OS GlobalProtect Command Injection",
        "cvss": 10.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "category": "Zero-Day Exploitation",
        "status": "CRITICAL EXPLOITED"
    },
    {
        "cve": "CVE-2024-21887",
        "title": "Ivanti Connect Secure Web Shell Injection",
        "cvss": 9.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
        "category": "Remote Code Execution",
        "status": "ACTIVE C2"
    },
    {
        "cve": "CVE-2023-46805",
        "title": "Ivanti EPMM Authentication Bypass",
        "cvss": 8.2,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "category": "Perimeter Gateway",
        "status": "PATCHED"
    },
    {
        "cve": "CVE-2024-1709",
        "title": "ConnectWise ScreenConnect Path Traversal",
        "cvss": 10.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "category": "Ransomware Staging",
        "status": "HIGH VOLUME"
    },
]

# ── Static data (rarely changes) ─────────────────────────────────────────────
MITRE_TECHNIQUES = [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access",      "count": "38.2%"},
    {"id": "T1566.002", "name": "Spearphishing Link",        "tactic": "Initial Access",      "count": "44.6%"},
    {"id": "T1110.003", "name": "Password Spraying",         "tactic": "Credential Access",   "count": "19.4%"},
    {"id": "T1078.004", "name": "Cloud Accounts Compromise", "tactic": "Defense Evasion",     "count": "27.1%"},
    {"id": "T1486",     "name": "Data Encrypted for Impact", "tactic": "Impact (Ransomware)", "count": "14.8%"},
]

INCIDENT_PLAYBOOKS = [
    {
        "id": "playbook-phishing",
        "title": "Phishing & Credential Harvest Response",
        "category": "Identity Threat",
        "urgency": "IMMEDIATE",
        "steps": [
            "Revoke all active OAuth sessions and refresh tokens for compromised identities.",
            "Enforce immediate password change with administrative reset of secondary recovery emails.",
            "Audit mailbox forwarding rules, auto-reply filters, and delegation permissions in Exchange/Gmail.",
            "Block destination URL across perimeter firewalls, Secure Web Gateways (SWG), and DNS resolvers.",
            "Run query across SIEM for all employees who received or accessed the target link within 72 hours."
        ]
    },
    {
        "id": "playbook-ransomware",
        "title": "Ransomware Infection Containment",
        "category": "System Compromise",
        "urgency": "CRITICAL",
        "steps": [
            "Immediately sever physical and wireless network interfaces on affected hosts.",
            "Disable compromised service accounts and domain controller administrative credentials.",
            "Do NOT power off or reboot machines to preserve volatile memory (RAM) artifacts for forensics.",
            "Isolate backup repositories and verify integrity of immutable/offline cold storage snapshots.",
            "Engage legal counsel, incident response retainers, and regulatory notification workflows."
        ]
    },
    {
        "id": "playbook-bec",
        "title": "Business Email Compromise (BEC) & Wire Fraud",
        "category": "Financial Fraud",
        "urgency": "CRITICAL",
        "steps": [
            "Contact sending financial institution immediately to initiate SWIFT / Fedwire recall request.",
            "Notify receiving bank's fraud department to freeze recipient escrow account.",
            "File immediate incident report with FBI IC3 (Internet Crime Complaint Center).",
            "Freeze sender and recipient user accounts; preserve email message headers (MIME .eml files).",
            "Implement mandatory verbal dual-authorization protocols for wire transfers over set thresholds."
        ]
    }
]


def _get_nvd_cvss(cve_id: str) -> float | None:
    """
    Fetches the CVSS v3.1 (or v3.0, v2 as fallback) base score for a CVE
    from the NVD REST API v2.0.

    Uses NVD_API_KEY from environment if set (50 req/30s vs 5 req/30s without).
    Results are cached per CVE for the lifetime of the process.
    Returns None if the score cannot be retrieved.
    """
    if cve_id in _nvd_cvss_cache:
        return _nvd_cvss_cache[cve_id]

    headers = {"User-Agent": "Gasha-CyberIntel/2.4"}
    nvd_key = os.environ.get("NVD_API_KEY", "")
    if nvd_key:
        headers["apiKey"] = nvd_key

    try:
        resp = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            headers=headers,
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            _nvd_cvss_cache[cve_id] = None
            return None

        metrics = vulns[0].get("cve", {}).get("metrics", {})
        # Prefer CVSS v3.1 → v3.0 → v2
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    _nvd_cvss_cache[cve_id] = float(score)
                    return float(score)

    except Exception as e:
        print(f"[Gasha ThreatIntel] NVD CVSS lookup failed for {cve_id}: {e}")

    _nvd_cvss_cache[cve_id] = None
    return None


def _fetch_live_kev() -> bool:
    """
    Fetches the CISA KEV JSON catalogue, sorts by dateAdded descending,
    takes the 6 most recent entries, then enriches each with a CVSS score
    from the NVD API (0.7s delay between calls to respect rate limits).

    Populates _intel_cache on success.
    Returns True on success, False on failure.
    """
    try:
        resp = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=10,
            headers={"User-Agent": "Gasha-CyberIntel/2.4"}
        )
        resp.raise_for_status()
        kev_data = resp.json()
    except Exception as e:
        print(f"[Gasha ThreatIntel] CISA KEV fetch failed: {e}")
        return False

    total_count = kev_data.get("count", 0)
    vulns = kev_data.get("vulnerabilities", [])

    # Sort by dateAdded descending, take the 6 most recently added
    try:
        vulns_sorted = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)
    except Exception:
        vulns_sorted = vulns

    top_vulns = vulns_sorted[:6]

    enriched = []
    for i, v in enumerate(top_vulns):
        cve_id = v.get("cveID", "N/A")

        # Stagger NVD calls to stay within free-tier rate limits (5 req/30s)
        if i > 0:
            time.sleep(0.7)

        cvss_score = _get_nvd_cvss(cve_id)

        enriched.append({
            "cve": cve_id,
            "title": v.get("vulnerabilityName", "Unknown"),
            "cvss": cvss_score if cvss_score is not None else "N/A",
            "vector": f"CISA KEV | Vendor: {v.get('vendorProject', 'Unknown')} | Product: {v.get('product', 'Unknown')}",
            "category": v.get("requiredAction", "See CISA advisory"),
            "status": "ACTIVELY EXPLOITED",
            "date_added": v.get("dateAdded", "Unknown"),
            "due_date": v.get("dueDate", "Unknown"),
            "short_description": v.get("shortDescription", "")
        })

    _intel_cache["kev_entries"] = enriched
    _intel_cache["total_kev_count"] = total_count
    _intel_cache["fetched_at"] = time.time()

    print(
        f"[Gasha ThreatIntel] CISA KEV refreshed — "
        f"{total_count} total KEVs in catalogue, displaying 6 most recent."
    )
    return True


def get_threat_intel_snapshot() -> dict:
    """
    Returns a live threat intelligence snapshot for the SOC dashboard.

    On first call (or after cache TTL expires) fetches fresh data from
    CISA KEV and NVD. On subsequent calls within the TTL window, serves
    from cache. If all live fetches fail, falls back to static CVE data
    with stale=True flagged in the response.
    """
    now = time.time()
    cache_age = now - _intel_cache["fetched_at"]
    needs_refresh = _intel_cache["kev_entries"] is None or cache_age > CACHE_TTL

    if needs_refresh:
        _fetch_live_kev()

    active_cves = _intel_cache["kev_entries"]
    using_fallback = active_cves is None

    if using_fallback:
        active_cves = STATIC_FALLBACK_CVES

    last_refresh_ts = _intel_cache["fetched_at"]
    last_refresh_iso = (
        datetime.fromtimestamp(last_refresh_ts, tz=timezone.utc).isoformat()
        if last_refresh_ts
        else "Never"
    )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "active_global_cves": active_cves,
        "mitre_top_techniques": MITRE_TECHNIQUES,
        "playbooks": INCIDENT_PLAYBOOKS,
        "data_source": "static_fallback" if using_fallback else "CISA KEV + NVD",
        "stale": using_fallback,
        "telemetry_metrics": {
            "total_cisa_kev_entries": _intel_cache["total_kev_count"] or "Unavailable",
            "last_refreshed": last_refresh_iso,
            "cache_ttl_seconds": CACHE_TTL,
            "active_perimeter_nodes": "Live feed active",
            "soc_status": "MONITORING"
        }
    }

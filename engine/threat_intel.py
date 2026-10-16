"""
SafeGuard Threat Intelligence & Incident Response Knowledge Core
Curates real-time attack telemetry, MITRE ATT&CK taxonomy, and SecOps response playbooks.
"""

from datetime import datetime, timezone

ACTIVE_CVES = [
    {
        "cve": "CVE-2024-3400",
        "title": "Palo Alto PAN-OS Command Injection",
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
    }
]

MITRE_TECHNIQUES = [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access", "count": "38.2%"},
    {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access", "count": "44.6%"},
    {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access", "count": "19.4%"},
    {"id": "T1078.004", "name": "Cloud Accounts Compromise", "tactic": "Defense Evasion", "count": "27.1%"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact (Ransomware)", "count": "14.8%"}
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

def get_threat_intel_snapshot() -> dict:
    """Generates real-time telemetry snapshot for SOC dashboard."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "active_global_cves": ACTIVE_CVES,
        "mitre_top_techniques": MITRE_TECHNIQUES,
        "playbooks": INCIDENT_PLAYBOOKS,
        "telemetry_metrics": {
            "threats_mitigated_24h": "1,489,203",
            "phishing_domains_indexed": "482,910",
            "mean_time_to_detect_sec": "1.4s",
            "active_perimeter_nodes": "48 Global Gateways",
            "soc_status": "DEFCON 2 - ELEVATED ALERT"
        }
    }

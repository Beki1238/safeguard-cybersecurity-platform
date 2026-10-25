"""
Gasha Social Engineering & Phishing NLP Heuristic Engine
Analyzes messages, emails, and SMS for psychological manipulation, credential harvesting, and scam patterns.
"""

import re

# High-confidence attack intent dictionaries
INTENT_PATTERNS = {
    "URGENCY_PRESSURE": {
        "weight": 25,
        "severity": "HIGH",
        "description": "Urgency manipulation designed to induce panic and bypass logical scrutiny.",
        "patterns": [
            r'\bimmediate(?:ly)?\b', r'\bwithin\s+(?:24|12|48)\s+hours?\b', r'\baction\s+required\b',
            r'\baccount\s+(?:suspended|restricted|disabled|locked)\b', r'\burgent(?:ly)?\b',
            r'\bfinal\s+notice\b', r'\bexpires?\s+today\b', r'\blast\s+warning\b',
            r'\bdeactivated\s+permanently\b', r'\btake\s+action\s+now\b'
        ]
    },
    "CREDENTIAL_HARVEST": {
        "weight": 35,
        "severity": "CRITICAL",
        "description": "Direct solicitation of authentication credentials, OTP tokens, or recovery seeds.",
        "patterns": [
            r'\bverify\s+(?:your\s+)?(?:identity|account|credentials|password)\b',
            r'\bconfirm\s+(?:your\s+)?(?:password|pin|security\s+code|ssn)\b',
            r'\benter\s+(?:your\s+)?(?:otp|2fa|one[- ]time\s+code)\b',
            r'\breset\s+(?:your\s+)?password\b', r'\bupdate\s+(?:your\s+)?billing\b',
            r'\blogin\s+to\s+(?:restore|unlock|keep)\b', r'\bclick\s+here\s+to\s+(?:verify|log\s*in)\b',
            r'\bseed\s+phrase\b', r'\bprivate\s+key\b'
        ]
    },
    "FINANCIAL_LURE": {
        "weight": 25,
        "severity": "HIGH",
        "description": "Monetary bait (fake lottery, tax refund, crypto bounty, or unearned windfall).",
        "patterns": [
            r'\b(?:refund|rebate|reimbursement)\s+of\s+[\$€£]?\d+\b',
            r'\bcongratulations[!]?\s+you(?:\'ve|\s+have)\s+won\b',
            r'\b(?:claim|collect)\s+your\s+(?:prize|reward|grant|funds|airdrop)\b',
            r'\bbitcoin\s+(?:reward|giveaway|transferred)\b',
            r'\binvestment\s+(?:profit|roi|yield)\b', r'\bunclaimed\s+funds\b',
            r'\bwire\s+transfer\s+(?:pending|failed)\b'
        ]
    },
    "AUTHORITY_COERCION": {
        "weight": 30,
        "severity": "CRITICAL",
        "description": "Impersonation of law enforcement, government revenue agencies (IRS/HMRC), or executive management.",
        "patterns": [
            r'\b(?:irs|fbi|police|customs|interpol)\s+notice\b',
            r'\blegal\s+(?:action|proceedings|charges)\b',
            r'\bwarrant\s+for\s+arrest\b', r'\bcourt\s+subpoena\b',
            r'\bexecutive\s+office\b', r'\bceo\s+(?:confidential|directive)\b'
        ]
    },
    "PACKAGE_DELIVERY_SCAM": {
        "weight": 25,
        "severity": "HIGH",
        "description": "Smishing pretext regarding fictitious package deliveries with unpaid customs or invalid addresses.",
        "patterns": [
            r'\bpackage\s+(?:delayed|cannot\s+be\s+delivered|held)\b',
            r'\bcustoms\s+fee\s+unpaid\b', r'\bupdate\s+delivery\s+address\b',
            r'\btracking\s+number:\s*#?\w+\b', r'\bpostal\s+service\s+alert\b',
            r'\busps|fedex|dhl|ups\s+(?:shipment|notice)\b'
        ]
    }
}

URL_REGEX = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')
PHONE_REGEX = re.compile(r'\+?\d{1,4}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}')
CRYPTO_REGEX = re.compile(r'\b(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b|0x[a-fA-F0-9]{40}')

def analyze_message(text: str) -> dict:
    """
    Evaluates message text for social engineering vectors, psychological coercion,
    and credential harvesting patterns.
    """
    text = (text or '').strip()
    if not text:
        return {"error": "Message content cannot be empty"}

    indicators = []
    matched_vectors = []
    total_score = 0
    text_lower = text.lower()

    # 1. Detect Intent Vectors
    for category, config in INTENT_PATTERNS.items():
        found_matches = []
        for pat in config["patterns"]:
            matches = re.findall(pat, text_lower)
            if matches:
                found_matches.extend(matches)
        
        if found_matches:
            unique_matches = list(set(found_matches))[:3]
            matched_vectors.append({
                "category": category,
                "severity": config["severity"],
                "description": config["description"],
                "matches": unique_matches
            })
            total_score += config["weight"]
            indicators.append({
                "type": category,
                "severity": config["severity"],
                "message": f"{config['description']} Identified phrases: {unique_matches}",
                "impact": config["weight"]
            })

    # 2. Extract IOCs
    embedded_urls = URL_REGEX.findall(text)
    phone_numbers = PHONE_REGEX.findall(text)
    crypto_addresses = CRYPTO_REGEX.findall(text)

    if embedded_urls:
        total_score += 15
        indicators.append({
            "type": "EMBEDDED_LINK_DETECTED",
            "severity": "HIGH",
            "message": f"Contains {len(embedded_urls)} external link(s). Primary target: {embedded_urls[0]}",
            "impact": +15
        })

    if crypto_addresses:
        total_score += 20
        indicators.append({
            "type": "CRYPTOCURRENCY_ADDRESS",
            "severity": "HIGH",
            "message": f"Identified cryptocurrency wallet address. Common in extortion/ransomware demands.",
            "impact": +20
        })

    # 3. Excessive Capitalization & Exclamations (emotional agitation)
    words = text.split()
    caps_words = [w for w in words if w.isupper() and len(w) > 3]
    if len(caps_words) >= 4 or text.count('!') >= 4:
        total_score += 10
        indicators.append({
            "type": "AGGRESSIVE_STYLING",
            "severity": "LOW",
            "message": "Aggressive capitalization and exclamation pattern designed to provoke emotional reaction.",
            "impact": +10
        })

    # Clamp score
    threat_score = min(100, max(0, total_score))

    # Verdict
    if threat_score >= 65:
        verdict = "MALICIOUS SOCIAL ENGINEERING"
        verdict_class = "critical"
        action = "DO NOT RESPOND. FLAG AND DELETE IMMEDIATELY."
    elif threat_score >= 35:
        verdict = "SUSPICIOUS CONTENT"
        verdict_class = "warning"
        action = "DO NOT CLICK ANY EMBEDDED LINKS. VERIFY VIA OUT-OF-BAND CHANNEL."
    else:
        verdict = "LOW RISK"
        verdict_class = "safe"
        action = "NO CRITICAL SOCIAL ENGINEERING PATTERNS IDENTIFIED."

    return {
        "text_length": len(text),
        "word_count": len(words),
        "threat_score": threat_score,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "action_recommendation": action,
        "vectors_detected": matched_vectors,
        "indicators": indicators,
        "extracted_iocs": {
            "urls": embedded_urls,
            "phone_numbers": phone_numbers,
            "crypto_wallets": crypto_addresses
        }
    }

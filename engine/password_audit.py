"""
SafeGuard Password Security & Entropy Audit Engine
Evaluates entropy, NIST SP 800-63B compliance, brute-force resistance,
pattern penalties (keyboard walks, leet substitutions, repetition),
and real breach exposure via HIBP k-anonymity range API.
"""

import math
import re
from engine.breach_checker import check_password_pwned

COMMON_PASSWORDS = {
    '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234',
    '111111', '1234567', 'dragon', 'welcome', 'admin', 'iloveyou', 'sunshine',
    'princess', 'football', 'monkey', 'master', 'charlie', 'shadow', 'superman',
    'secret', 'pass123', 'root', 'login', 'testing', 'hunter2', 'trustno1'
}

# Common keyboard walk sequences (rows on a QWERTY layout)
_KEYBOARD_WALKS = [
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
    'qwerty', 'asdfgh', 'zxcvbn',
    '1234567890', '0987654321',
    'qazwsx', 'wsxedc', 'edcrfv',
]

# Leet-speak substitution map (attacker reverses these before dictionary attack)
_LEET_MAP = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '@': 'a',
    '$': 's', '!': 'i', '+': 't',
})


def _count_pattern_penalties(password: str) -> tuple[int, list[str]]:
    """
    Detects weak structural patterns and returns a penalty score plus
    a list of human-readable findings.

    Patterns checked:
      - 3+ consecutive repeated characters (aaa, 111)
      - Keyboard walk sequences of 4+ chars
      - Leet-speak variants of common passwords
      - Simple base-word + digits suffix (password123, admin2024)
    """
    penalty = 0
    findings = []
    lower = password.lower()
    de_leeted = lower.translate(_LEET_MAP)

    # 1. Consecutive repetition (aaa, 1111)
    if re.search(r'(.)\1{2,}', password):
        penalty += 15
        findings.append("Contains 3+ consecutive repeated characters.")

    # 2. Keyboard walk (qwerty, asdfgh, 12345)
    for walk in _KEYBOARD_WALKS:
        for length in range(min(len(password), len(walk)), 3, -1):
            for start in range(len(walk) - length + 1):
                chunk = walk[start:start + length]
                if chunk in lower or chunk[::-1] in lower:
                    penalty += min(20, length * 4)
                    findings.append(f"Keyboard walk pattern detected: '{chunk}'.")
                    break
            else:
                continue
            break

    # 3. Leet-speak variant of a known-weak word
    if de_leeted in COMMON_PASSWORDS:
        penalty += 25
        findings.append("Leet-speak substitution of a common dictionary password.")

    # 4. Base word + digits suffix/prefix pattern (password123, 2024admin)
    base_word = re.sub(r'^\d+|\d+$', '', lower).strip()
    if len(base_word) >= 4 and base_word in COMMON_PASSWORDS:
        penalty += 20
        findings.append(f"Common base word with appended digits: '{base_word}'.")

    return penalty, findings

def audit_password(password: str) -> dict:
    """
    Evaluates password strength using information-theoretic entropy,
    NIST guidelines, and brute-force time complexity equations.
    """
    if not password:
        return {"error": "Password input cannot be empty"}

    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digits = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    # Calculate character pool size (N)
    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_special:
        pool_size += 33

    # Theoretical Entropy E = L * log2(R)
    entropy_bits = round(length * math.log2(max(pool_size, 2)), 2)

    # NIST SP 800-63B guidelines checks
    nist_checks = {
        "min_length_8": length >= 8,
        "recommended_length_14": length >= 14,
        "not_in_common_dictionary": password.lower() not in COMMON_PASSWORDS,
        "no_sequential_repetition": not bool(re.search(r'(.)\1{2,}', password)),
        "max_length_compliant": length <= 64
    }

    is_common = password.lower() in COMMON_PASSWORDS
    consecutive_repeat = bool(re.search(r'(.)\1{2,}', password))

    # Brute Force Time Equations (Total Combinations = R^L)
    # Average combinations to crack is R^L / 2
    combinations = (pool_size ** length) if pool_size > 0 else 0
    avg_attempts = combinations / 2 if combinations > 0 else 0

    # Crack times at different compute speeds:
    # 1. Desktop CPU: ~10^7 hashes/sec (10 MH/s)
    # 2. Modern GPU Rig (8x RTX 4090): ~1.5 * 10^11 hashes/sec (150 GH/s for fast hashes like MD5/NTLM)
    # 3. Distributed Cluster: ~10^13 hashes/sec (10 TH/s)
    speed_cpu = 1e7
    speed_gpu_rig = 1.5e11
    speed_cluster = 1e13

    time_cpu_sec = avg_attempts / speed_cpu if speed_cpu > 0 else 0
    time_gpu_sec = avg_attempts / speed_gpu_rig if speed_gpu_rig > 0 else 0
    time_cluster_sec = avg_attempts / speed_cluster if speed_cluster > 0 else 0

    def format_time(seconds: float) -> str:
        if is_common:
            return "Instantaneous (< 1 millisecond)"
        if seconds < 1:
            return "Instant (< 1 second)"
        elif seconds < 60:
            return f"{round(seconds)} seconds"
        elif seconds < 3600:
            return f"{round(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{round(seconds / 3600, 1)} hours"
        elif seconds < 31536000:
            return f"{round(seconds / 86400)} days"
        elif seconds < 31536000 * 1000:
            return f"{round(seconds / 31536000, 1)} years"
        elif seconds < 31536000 * 1e6:
            return f"{round(seconds / (31536000 * 1000))} thousand years"
        elif seconds < 31536000 * 1e9:
            return f"{round(seconds / (31536000 * 1e6))} million years"
        else:
            return "Centuries / Practically Uncrackable"

    # Score (0 - 100)
    score = 0
    if not is_common:
        score += min(50, length * 3.5)
        if pool_size >= 62:
            score += 25
        elif pool_size >= 36:
            score += 15
        if entropy_bits >= 70:
            score += 25
        elif entropy_bits >= 50:
            score += 15
    else:
        score = 5

    score = min(100, max(5, round(score)))

    # Pattern penalty: keyboard walks, leet-speak, repetition, base-word+digits
    pattern_penalty, pattern_findings = _count_pattern_penalties(password)
    score = max(5, score - pattern_penalty)

    if score >= 80:
        verdict = "FORTIFIED DEFENSE"
        tier = "safe"
    elif score >= 50:
        verdict = "MODERATE RESISTANCE"
        tier = "warning"
    else:
        verdict = "CRITICALLY VULNERABLE"
        tier = "critical"

    # Real HIBP k-anonymity check — only a 5-char SHA-1 prefix is transmitted,
    # the full password never leaves this machine.
    pwned_result = check_password_pwned(password)
    if pwned_result.get("pwned"):
        score = min(score, 10)
        verdict = "CRITICALLY VULNERABLE"
        tier = "critical"

    return {
        "length": length,
        "pool_size": pool_size,
        "entropy_bits": entropy_bits,
        "score": score,
        "verdict": verdict,
        "tier": tier,
        "is_common_dictionary": is_common,
        "nist_compliance": nist_checks,
        "crack_times": {
            "desktop_cpu": format_time(time_cpu_sec),
            "gpu_rig_rtx4090": format_time(time_gpu_sec),
            "distributed_cluster": format_time(time_cluster_sec)
        },
        "character_breakdown": {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "numbers": has_digits,
            "symbols": has_special
        },
        "pattern_findings": pattern_findings,
        "pwned_check": pwned_result
    }

"""
SafeGuard Password Security & Entropy Audit Engine
Evaluates entropy, NIST SP 800-63B compliance, and brute-force resistance.
"""

import math
import re

COMMON_PASSWORDS = {
    '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234',
    '111111', '1234567', 'dragon', 'welcome', 'admin', 'iloveyou', 'sunshine',
    'princess', 'football', 'monkey', 'master', 'charlie', 'shadow', 'superman',
    'secret', 'pass123', 'root', 'login', 'testing', 'hunter2', 'trustno1'
}

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

    if score >= 80:
        verdict = "FORTIFIED DEFENSE"
        tier = "safe"
    elif score >= 50:
        verdict = "MODERATE RESISTANCE"
        tier = "warning"
    else:
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
        }
    }

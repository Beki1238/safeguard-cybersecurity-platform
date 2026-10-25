"""
Gasha Cryptographic Primitives & Hashing Toolkit
Generates cryptographically secure hashes, analyzes digests, and handles encodings.
"""

import hashlib
import base64
import urllib.parse
import secrets

def compute_hashes(data_str: str) -> dict:
    """Computes multiple hash digests for provided plaintext."""
    if not data_str:
        return {"error": "Input data cannot be empty"}

    encoded = data_str.encode('utf-8')
    return {
        "input_length_bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "sha512": hashlib.sha512(encoded).hexdigest(),
        "sha3_256": hashlib.sha3_256(encoded).hexdigest(),
        "blake2b": hashlib.blake2b(encoded).hexdigest(),
        "legacy_md5": {
            "digest": hashlib.md5(encoded).hexdigest(),
            "status": "DEPRECATED (Vulnerable to collision attacks)"
        },
        "legacy_sha1": {
            "digest": hashlib.sha1(encoded).hexdigest(),
            "status": "DEPRECATED (Cryptographically compromised)"
        }
    }

def analyze_hash(hash_str: str) -> dict:
    """Identifies candidate cryptographic algorithms from an unknown hash digest."""
    clean_hash = hash_str.strip().lower()
    length = len(clean_hash)
    
    # Check if hexadecimal
    is_hex = all(c in '0123456789abcdef' for c in clean_hash)
    if not is_hex:
        return {"error": "Input is not a valid hexadecimal hash string"}

    candidates = []
    if length == 32:
        candidates.append({"algo": "MD5", "status": "Insecure / Obsolete", "bit_length": 128})
        candidates.append({"algo": "NTLM", "status": "Legacy Windows Hash", "bit_length": 128})
    elif length == 40:
        candidates.append({"algo": "SHA-1", "status": "Insecure (Collisions possible)", "bit_length": 160})
        candidates.append({"algo": "RIPEMD-160", "status": "Rarely used", "bit_length": 160})
    elif length == 56:
        candidates.append({"algo": "SHA-224", "status": "Secure", "bit_length": 224})
        candidates.append({"algo": "SHA3-224", "status": "Secure", "bit_length": 224})
    elif length == 64:
        candidates.append({"algo": "SHA-256", "status": "Standard Enterprise Benchmark", "bit_length": 256})
        candidates.append({"algo": "SHA3-256", "status": "NIST Keccak Standard", "bit_length": 256})
        candidates.append({"algo": "BLAKE2s", "status": "High-Performance Modern", "bit_length": 256})
    elif length == 128:
        candidates.append({"algo": "SHA-512", "status": "Military / High-Assurance", "bit_length": 512})
        candidates.append({"algo": "BLAKE2b", "status": "Modern Cryptographic Hash", "bit_length": 512})
    else:
        return {"error": f"Unknown hash length ({length} hex characters)"}

    return {
        "hash": clean_hash,
        "length_chars": length,
        "bit_length": length * 4,
        "potential_algorithms": candidates
    }

def encode_decode_payload(text: str, operation: str) -> dict:
    """Encodes or decodes text across Base64, Hex, and URL encodings."""
    try:
        if operation == "b64_encode":
            result = base64.b64encode(text.encode()).decode()
        elif operation == "b64_decode":
            result = base64.b64decode(text.encode()).decode('utf-8', errors='replace')
        elif operation == "hex_encode":
            result = text.encode().hex()
        elif operation == "hex_decode":
            result = bytes.fromhex(text.strip()).decode('utf-8', errors='replace')
        elif operation == "url_encode":
            result = urllib.parse.quote(text)
        elif operation == "url_decode":
            result = urllib.parse.unquote(text)
        else:
            return {"error": f"Unknown operation: {operation}"}
        return {"result": result, "operation": operation}
    except Exception as e:
        return {"error": f"Encoding failure: {str(e)}"}

def generate_secure_token(bytes_length: int = 32) -> str:
    """Generates cryptographically strong random token."""
    return secrets.token_hex(bytes_length)

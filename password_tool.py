"""
Password and Bcrypt Hashing Tool
Implements:
1. Cryptographically secure random 64-character alphanumeric password generation.
2. Bcrypt password hashing compatible with PHP's password_hash($password, PASSWORD_BCRYPT).
3. Password verification compatible with PHP's password_verify($password, $hash).
"""

import secrets
import string
from typing import Dict, Any, Optional
import bcrypt

ALPHANUMERIC_CHARS = string.ascii_letters + string.digits  # a-z, A-Z, 0-9 (62 characters)

def generate_password(length: int = 64) -> str:
    """
    Generate a cryptographically secure random alphanumeric password.
    Default length is 64 characters.
    Uses Python's secrets module (system CSPRNG).
    """
    if length <= 0:
        raise ValueError("Password length must be greater than 0.")
    return "".join(secrets.choice(ALPHANUMERIC_CHARS) for _ in range(length))


def hash_password(
    password: str,
    cost: int = 10,
    prefix: str = "2y"
) -> str:
    """
    Generate a bcrypt hash compatible with PHP's:
    password_hash($password, PASSWORD_BCRYPT, ['cost' => $cost])

    - password: Plaintext password string (UTF-8)
    - cost: Logarithmic cost factor (4 to 31, default 10 matching PHP)
    - prefix: '2y' (standard PHP PASSWORD_BCRYPT) or '2b' (standard bcrypt)
    """
    if not (4 <= cost <= 31):
        raise ValueError(f"Cost factor must be between 4 and 31. Got {cost}.")

    if prefix not in ("2y", "2b", "2a"):
        raise ValueError(f"Unsupported prefix: {prefix}. Allowed: '2y', '2b', '2a'.")

    # Generate salt with cost factor
    salt = bcrypt.gensalt(rounds=cost, prefix=b"2b")
    raw_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    # Replace prefix with requested prefix (e.g. $2y$ for PHP)
    if prefix != "2b":
        return f"${prefix}${raw_hash[4:]}"
    return raw_hash


def verify_password(password: str, hash_str: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.
    Compatible with PHP's password_verify($password, $hash).
    Seamlessly handles $2y$, $2b$, and $2a$ prefixes.
    """
    if not hash_str:
        return False

    # Normalize $2y$ to $2b$ for python bcrypt verification
    norm_hash = hash_str
    if hash_str.startswith("$2y$"):
        norm_hash = "$2b$" + hash_str[4:]

    try:
        return bcrypt.checkpw(password.encode("utf-8"), norm_hash.encode("utf-8"))
    except Exception:
        return False


def generate_and_hash(
    length: int = 64,
    cost: int = 10,
    prefix: str = "2y"
) -> Dict[str, Any]:
    """
    Convenience function: generate a random password and its PHP PASSWORD_BCRYPT hash.
    """
    pwd = generate_password(length)
    h = hash_password(pwd, cost=cost, prefix=prefix)
    return {
        "password": pwd,
        "hash": h,
        "length": len(pwd),
        "cost": cost,
        "prefix": prefix,
        "algorithm": "PASSWORD_BCRYPT (PHP compatible)"
    }

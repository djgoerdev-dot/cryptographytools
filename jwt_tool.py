"""
JSON Web Token (JWT) Tool (RFC 7519)
Supports:
- Encoding, Decoding, and Signing JWTs
- Algorithms:
  - RS256, RS384, RS512 (RSA PKCS#1 v1.5 with SHA-2)
  - PS256, PS384, PS512 (RSA PSS with SHA-2)
  - HS256, HS384, HS512 (HMAC with SHA-2)
  - none (Unsigned)
- Verification of token signature and expiration (exp)
- Integration with RSA keypair management
"""

import base64
import json
import time
import hmac
import hashlib
from typing import Dict, Any, Optional, Tuple, Union
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def base64url_encode(data: bytes) -> str:
    """Base64URL encode bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def base64url_decode(s: str) -> bytes:
    """Base64URL decode string with padding recovery."""
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))

def _get_hash_algorithm(alg_name: str):
    """Map algorithm suffix to cryptography hash object."""
    if alg_name.endswith("256"):
        return hashes.SHA256(), hashlib.sha256
    elif alg_name.endswith("384"):
        return hashes.SHA384(), hashlib.sha384
    elif alg_name.endswith("512"):
        return hashes.SHA512(), hashlib.sha512
    else:
        raise ValueError(f"Unsupported hash size in algorithm: {alg_name}")

def _load_private_key(key_input: Union[str, bytes, rsa.RSAPrivateKey]) -> rsa.RSAPrivateKey:
    if isinstance(key_input, rsa.RSAPrivateKey):
        return key_input
    key_bytes = key_input.encode("utf-8") if isinstance(key_input, str) else key_input
    key = serialization.load_pem_private_key(key_bytes, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Key is not an RSA private key")
    return key

def _load_public_key(key_input: Union[str, bytes, rsa.RSAPublicKey]) -> rsa.RSAPublicKey:
    if isinstance(key_input, rsa.RSAPublicKey):
        return key_input
    key_bytes = key_input.encode("utf-8") if isinstance(key_input, str) else key_input
    key = serialization.load_pem_public_key(key_bytes)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Key is not an RSA public key")
    return key

def encode_jwt(
    payload: Dict[str, Any],
    key: Optional[Union[str, bytes, rsa.RSAPrivateKey]] = None,
    algorithm: str = "RS256",
    headers: Optional[Dict[str, Any]] = None,
    add_timestamps: bool = False,
    expires_in: int = 3600
) -> str:
    """
    Encode and sign a JSON Web Token.
    """
    alg = algorithm.upper()
    header_data = {"alg": alg, "typ": "JWT"}
    if headers:
        header_data.update(headers)
        header_data["alg"] = alg

    payload_data = dict(payload)
    if add_timestamps:
        ts = generate_timestamps(expires_in=expires_in)
        if "iat" not in payload_data:
            payload_data["iat"] = ts["iat"]
        if "exp" not in payload_data:
            payload_data["exp"] = ts["exp"]

    h_json = json.dumps(header_data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    p_json = json.dumps(payload_data, separators=(",", ":"), sort_keys=True).encode("utf-8")

    header_b64 = base64url_encode(h_json)
    payload_b64 = base64url_encode(p_json)
    signing_input = f"{header_b64}.{payload_b64}"
    signing_bytes = signing_input.encode("ascii")

    if alg == "NONE":
        return f"{signing_input}."

    if not key:
        raise ValueError(f"Signing key is required for algorithm {alg}")

    # RSA PKCS#1 v1.5 (RS256, RS384, RS512)
    if alg.startswith("RS"):
        priv_key = _load_private_key(key)
        hash_obj, _ = _get_hash_algorithm(alg)
        sig = priv_key.sign(signing_bytes, padding.PKCS1v15(), hash_obj)
        return f"{signing_input}.{base64url_encode(sig)}"

    # RSA PSS (PS256, PS384, PS512)
    elif alg.startswith("PS"):
        priv_key = _load_private_key(key)
        hash_obj, _ = _get_hash_algorithm(alg)
        sig = priv_key.sign(
            signing_bytes,
            padding.PSS(mgf=padding.MGF1(hash_obj), salt_length=padding.PSS.MAX_LENGTH),
            hash_obj
        )
        return f"{signing_input}.{base64url_encode(sig)}"

    # HMAC (HS256, HS384, HS512)
    elif alg.startswith("HS"):
        secret_bytes = key.encode("utf-8") if isinstance(key, str) else key
        _, py_hash = _get_hash_algorithm(alg)
        sig = hmac.new(secret_bytes, signing_bytes, py_hash).digest()
        return f"{signing_input}.{base64url_encode(sig)}"

    else:
        raise ValueError(f"Unsupported JWT signing algorithm: {alg}")

def generate_timestamps(
    expires_in: int = 3600,
    issued_at: Optional[int] = None,
    include_nbf: bool = False
) -> Dict[str, int]:
    """
    Generate standard JWT timestamps for 'iat' (issued at) and 'exp' (expiration).
    :param expires_in: Duration in seconds from issued_at until expiration (default: 3600 = 1 hour).
    :param issued_at: Optional custom epoch seconds for 'iat' (default: current UTC epoch).
    :param include_nbf: If True, also includes 'nbf' set equal to 'iat'.
    :return: dict with 'iat', 'exp', and optionally 'nbf'.
    """
    now = int(time.time()) if issued_at is None else int(issued_at)
    res = {
        "iat": now,
        "exp": now + int(expires_in)
    }
    if include_nbf:
        res["nbf"] = now
    return res

def decode_jwt(
    token: str,
    key: Optional[Union[str, bytes, rsa.RSAPublicKey]] = None,
    verify: bool = True
) -> Dict[str, Any]:
    """
    Decode and optionally verify a JWT token.
    Returns:
    {
        "valid": bool,
        "header": dict,
        "payload": dict,
        "signature_b64": str,
        "error": str or None,
        "expired": bool
    }
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {
            "valid": False,
            "error": f"Invalid JWT structure: expected 3 dot-separated parts, got {len(parts)}",
            "header": {},
            "payload": {},
            "signature_b64": "",
            "expired": False
        }

    try:
        header_raw = base64url_decode(parts[0])
        header = json.loads(header_raw.decode("utf-8"))
    except Exception as e:
        return {
            "valid": False,
            "error": f"Failed to parse JWT Header: {e}",
            "header": {},
            "payload": {},
            "signature_b64": parts[2],
            "expired": False
        }

    try:
        payload_raw = base64url_decode(parts[1])
        payload = json.loads(payload_raw.decode("utf-8"))
    except Exception as e:
        return {
            "valid": False,
            "error": f"Failed to parse JWT Payload: {e}",
            "header": header,
            "payload": {},
            "signature_b64": parts[2],
            "expired": False
        }

    sig_b64 = parts[2]
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    alg = header.get("alg", "").upper()

    # Check expiration claim if present
    now = time.time()
    expired = False
    if "exp" in payload and isinstance(payload["exp"], (int, float)):
        if payload["exp"] < now:
            expired = True

    if not verify:
        return {
            "valid": True,
            "unverified": True,
            "header": header,
            "payload": payload,
            "signature_b64": sig_b64,
            "error": None,
            "expired": expired
        }

    # Verification requested
    if alg == "NONE":
        if sig_b64 != "":
            return {
                "valid": False,
                "unverified": False,
                "error": "Algorithm is 'none' but signature is not empty",
                "header": header,
                "payload": payload,
                "signature_b64": sig_b64,
                "expired": expired
            }
        return {
            "valid": True,
            "unverified": False,
            "header": header,
            "payload": payload,
            "signature_b64": "",
            "error": None,
            "expired": expired
        }

    if not key:
        return {
            "valid": False,
            "unverified": True,
            "error": f"Verification key is required for algorithm {alg} (claims decoded without verification)",
            "header": header,
            "payload": payload,
            "signature_b64": sig_b64,
            "expired": expired
        }

    try:
        sig_bytes = base64url_decode(sig_b64)
    except Exception as e:
        return {
            "valid": False,
            "error": f"Invalid base64url signature encoding: {e}",
            "header": header,
            "payload": payload,
            "signature_b64": sig_b64,
            "expired": expired
        }

    # Verify RS
    if alg.startswith("RS"):
        try:
            pub_key = _load_public_key(key)
            hash_obj, _ = _get_hash_algorithm(alg)
            pub_key.verify(sig_bytes, signing_input, padding.PKCS1v15(), hash_obj)
            return {
                "valid": True,
                "header": header,
                "payload": payload,
                "signature_b64": sig_b64,
                "error": None,
                "expired": expired
            }
        except Exception as e:
            return {
                "valid": False,
                "error": f"RS signature verification failed: {e}",
                "header": header,
                "payload": payload,
                "signature_b64": sig_b64,
                "expired": expired
            }

    # Verify PS
    elif alg.startswith("PS"):
        try:
            pub_key = _load_public_key(key)
            hash_obj, _ = _get_hash_algorithm(alg)
            pub_key.verify(
                sig_bytes,
                signing_input,
                padding.PSS(mgf=padding.MGF1(hash_obj), salt_length=padding.PSS.MAX_LENGTH),
                hash_obj
            )
            return {
                "valid": True,
                "header": header,
                "payload": payload,
                "signature_b64": sig_b64,
                "error": None,
                "expired": expired
            }
        except Exception as e:
            return {
                "valid": False,
                "error": f"PS signature verification failed: {e}",
                "header": header,
                "payload": payload,
                "signature_b64": sig_b64,
                "expired": expired
            }

    # Verify HS
    elif alg.startswith("HS"):
        try:
            secret_bytes = key.encode("utf-8") if isinstance(key, str) else key
            _, py_hash = _get_hash_algorithm(alg)
            expected_sig = hmac.new(secret_bytes, signing_input, py_hash).digest()
            if hmac.compare_digest(sig_bytes, expected_sig):
                return {
                    "valid": True,
                    "header": header,
                    "payload": payload,
                    "signature_b64": sig_b64,
                    "error": None,
                    "expired": expired
                }
            else:
                return {
                    "valid": False,
                    "error": "Invalid HMAC signature (secret key mismatch)",
                    "header": header,
                    "payload": payload,
                    "signature_b64": sig_b64,
                    "expired": expired
                }
        except Exception as e:
            return {
                "valid": False,
                "error": f"HMAC verification error: {e}",
                "header": header,
                "payload": payload,
                "signature_b64": sig_b64,
                "expired": expired
            }

    else:
        return {
            "valid": False,
            "error": f"Unsupported verification algorithm: {alg}",
            "header": header,
            "payload": payload,
            "signature_b64": sig_b64,
            "expired": expired
        }

"""
Core RSA Encryption and Decryption engine.
Supports:
- Private Key Encryption with PKCS#1 v1.5 padding (Block Type 1 & 2)
- Public Key Decryption with PKCS#1 v1.5 padding
- Public Key Encryption & Private Key Decryption (standard RSAES-PKCS1-V1_5)
- Automatic chunking (multi-block) for long data
- Key generation (PKCS#1 and PKCS#8 PEM formats)
"""

import os
import base64
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_key_pair(key_size: int = 2048, pkcs8: bool = True) -> Tuple[str, str]:
    """
    Generate an RSA key pair.
    Returns: (private_key_pem, public_key_pem)
    """
    if key_size not in (1024, 2048, 3072, 4096):
        raise ValueError(f"Unsupported key size: {key_size}. Supported sizes: 1024, 2048, 3072, 4096.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    if pkcs8:
        priv_format = serialization.PrivateFormat.PKCS8
        pub_format = serialization.PublicFormat.SubjectPublicKeyInfo
    else:
        priv_format = serialization.PrivateFormat.TraditionalOpenSSL
        pub_format = serialization.PublicFormat.PKCS1

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=priv_format,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=pub_format
    ).decode("utf-8")

    return priv_pem, pub_pem


def load_private_key(pem_data: str, password: Optional[str] = None):
    """
    Load an RSA private key from PEM string or bytes.
    Supports PKCS#1 (-----BEGIN RSA PRIVATE KEY-----)
    and PKCS#8 (-----BEGIN PRIVATE KEY-----).
    """
    if isinstance(pem_data, str):
        pem_bytes = pem_data.strip().encode("utf-8")
    else:
        pem_bytes = pem_data

    pass_bytes = password.encode("utf-8") if password else None
    key = serialization.load_pem_private_key(pem_bytes, password=pass_bytes)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Key is not an RSA private key")
    return key


def load_public_key(pem_data: str):
    """
    Load an RSA public key from PEM string or bytes.
    Supports PKCS#1 (-----BEGIN RSA PUBLIC KEY-----)
    and SPKI (-----BEGIN PUBLIC KEY-----).
    """
    if isinstance(pem_data, str):
        pem_bytes = pem_data.strip().encode("utf-8")
    else:
        pem_bytes = pem_data

    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Key is not an RSA public key")
    return key


def pkcs1_pad(data: bytes, k: int, block_type: int = 1) -> bytes:
    """
    Format data block into PKCS#1 v1.5 padding block (length k octets).
    EB = 00 || BT || PS || 00 || D
    """
    max_payload = k - 11
    if len(data) > max_payload:
        raise ValueError(
            f"Data length ({len(data)} bytes) exceeds maximum payload ({max_payload} bytes) "
            f"for RSA modulus size ({k * 8} bits)."
        )

    pad_len = k - 3 - len(data)
    if pad_len < 8:
        raise ValueError(f"Padding length ({pad_len}) is less than required minimum of 8 octets.")

    if block_type == 1:
        # BT 01: PS is all 0xFF bytes (signature / private encrypt standard)
        ps = b"\xff" * pad_len
    elif block_type == 2:
        # BT 02: PS is non-zero pseudorandom bytes (RSAES-PKCS1-v1_5 encryption standard)
        ps = bytearray()
        while len(ps) < pad_len:
            rand_bytes = os.urandom(pad_len - len(ps))
            # Filter out 0x00 bytes
            rand_bytes = rand_bytes.replace(b"\x00", b"\x01")
            ps.extend(rand_bytes)
        ps = bytes(ps)
    else:
        raise ValueError(f"Invalid PKCS#1 block type: {block_type}. Must be 1 or 2.")

    return b"\x00" + bytes([block_type]) + ps + b"\x00" + data


def pkcs1_unpad(eb: bytes, expected_bt: Optional[int] = None) -> bytes:
    """
    Unpad PKCS#1 v1.5 block EB and extract data D.
    """
    if len(eb) < 11:
        raise ValueError(f"Block length ({len(eb)}) is too short for PKCS#1 padding (min 11 bytes).")

    if eb[0] != 0:
        raise ValueError("Invalid PKCS#1 v1.5 padding: initial octet is not 0x00.")

    bt = eb[1]
    if expected_bt is not None and bt != expected_bt:
        raise ValueError(f"Block type mismatch: expected 0x0{expected_bt}, got 0x0{bt}.")

    if bt not in (1, 2):
        raise ValueError(f"Invalid PKCS#1 block type: 0x{bt:02x}. Expected 0x01 or 0x02.")

    # Find 0x00 delimiter starting from index 2
    sep_idx = eb.find(b"\x00", 2)
    if sep_idx == -1:
        raise ValueError("Invalid PKCS#1 v1.5 padding: 0x00 delimiter separating PS from data not found.")

    if sep_idx < 10:
        raise ValueError(f"Invalid PKCS#1 v1.5 padding: padding string PS too short ({sep_idx - 2} octets, minimum 8).")

    if bt == 1:
        # Verify that all PS bytes are 0xFF
        ps = eb[2:sep_idx]
        if any(b != 0xff for b in ps):
            raise ValueError("Invalid PKCS#1 v1.5 Block Type 1: PS octets must all be 0xFF.")

    return eb[sep_idx + 1:]


def encrypt_private(
    data: bytes,
    private_key: rsa.RSAPrivateKey,
    block_type: int = 1,
    chunk: bool = True
) -> bytes:
    """
    Encrypt data using RSA private key:
    C = (EB)^d mod n
    """
    priv_nums = private_key.private_numbers()
    pub_nums = priv_nums.public_numbers
    n = pub_nums.n
    d = priv_nums.d
    k = (n.bit_length() + 7) // 8
    max_payload = k - 11

    if not chunk:
        if len(data) > max_payload:
            raise ValueError(
                f"Data length ({len(data)} bytes) exceeds single-block maximum payload ({max_payload} bytes). "
                f"Enable chunking mode to encrypt larger data."
            )
        chunks = [data]
    else:
        if len(data) == 0:
            chunks = [b""]
        else:
            chunks = [data[i:i + max_payload] for i in range(0, len(data), max_payload)]

    cipher_blocks = []
    for piece in chunks:
        eb = pkcs1_pad(piece, k, block_type=block_type)
        m_int = int.from_bytes(eb, "big")
        c_int = pow(m_int, d, n)
        c_bytes = c_int.to_bytes(k, "big")
        cipher_blocks.append(c_bytes)

    return b"".join(cipher_blocks)


def decrypt_public(
    ciphertext: bytes,
    public_key: rsa.RSAPublicKey,
    expected_bt: Optional[int] = None
) -> bytes:
    """
    Decrypt ciphertext using RSA public key:
    EB = (C)^e mod n
    """
    pub_nums = public_key.public_numbers()
    n = pub_nums.n
    e = pub_nums.e
    k = (n.bit_length() + 7) // 8

    if len(ciphertext) == 0:
        raise ValueError("Ciphertext is empty.")

    if len(ciphertext) % k != 0:
        raise ValueError(
            f"Ciphertext length ({len(ciphertext)} bytes) is not a multiple of the RSA key modulus size "
            f"({k} bytes / {k * 8} bits). Please verify the ciphertext or key size."
        )

    recovered = []
    for i in range(0, len(ciphertext), k):
        c_block = ciphertext[i:i + k]
        c_int = int.from_bytes(c_block, "big")
        if c_int >= n:
            raise ValueError("Ciphertext representative is greater than or equal to RSA modulus.")

        eb_int = pow(c_int, e, n)
        eb = eb_int.to_bytes(k, "big")
        piece = pkcs1_unpad(eb, expected_bt=expected_bt)
        recovered.append(piece)

    return b"".join(recovered)


def encrypt_public(
    data: bytes,
    public_key: rsa.RSAPublicKey,
    block_type: int = 2,
    chunk: bool = True
) -> bytes:
    """
    Standard RSAES-PKCS1-V1_5 public key encryption:
    C = (EB)^e mod n
    """
    pub_nums = public_key.public_numbers()
    n = pub_nums.n
    e = pub_nums.e
    k = (n.bit_length() + 7) // 8
    max_payload = k - 11

    if not chunk:
        if len(data) > max_payload:
            raise ValueError(f"Data length ({len(data)} bytes) exceeds single-block maximum ({max_payload} bytes).")
        chunks = [data]
    else:
        if len(data) == 0:
            chunks = [b""]
        else:
            chunks = [data[i:i + max_payload] for i in range(0, len(data), max_payload)]

    cipher_blocks = []
    for piece in chunks:
        eb = pkcs1_pad(piece, k, block_type=block_type)
        m_int = int.from_bytes(eb, "big")
        c_int = pow(m_int, e, n)
        c_bytes = c_int.to_bytes(k, "big")
        cipher_blocks.append(c_bytes)

    return b"".join(cipher_blocks)


def decrypt_private(
    ciphertext: bytes,
    private_key: rsa.RSAPrivateKey,
    expected_bt: Optional[int] = None
) -> bytes:
    """
    Standard RSAES-PKCS1-V1_5 private key decryption:
    EB = (C)^d mod n
    """
    priv_nums = private_key.private_numbers()
    n = priv_nums.public_numbers.n
    d = priv_nums.d
    k = (n.bit_length() + 7) // 8

    if len(ciphertext) == 0:
        raise ValueError("Ciphertext is empty.")

    if len(ciphertext) % k != 0:
        raise ValueError(
            f"Ciphertext length ({len(ciphertext)} bytes) is not a multiple of the RSA modulus ({k} bytes)."
        )

    recovered = []
    for i in range(0, len(ciphertext), k):
        c_block = ciphertext[i:i + k]
        c_int = int.from_bytes(c_block, "big")
        if c_int >= n:
            raise ValueError("Ciphertext representative is greater than or equal to RSA modulus.")

        eb_int = pow(c_int, d, n)
        eb = eb_int.to_bytes(k, "big")
        piece = pkcs1_unpad(eb, expected_bt=expected_bt)
        recovered.append(piece)

    return b"".join(recovered)

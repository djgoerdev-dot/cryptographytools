#!/usr/bin/env python3
"""
RSA Encryption / Decryption CLI Tool
Allows encrypting with RSA Private Key and decrypting with RSA Public Key
using RSAES-PKCS1-V1_5 padding (Block Type 1 & Type 2).
"""

import os
import sys
import argparse
import base64
import rsa_crypto

def read_key_input(key_arg: str) -> str:
    """Reads key content whether passed as a file path or a raw PEM string."""
    if os.path.exists(key_arg):
        with open(key_arg, "r", encoding="utf-8") as f:
            return f.read()
    return key_arg

def read_payload_bytes(args, default_in_format: str) -> bytes:
    """Reads input payload from file, argument, or stdin."""
    if hasattr(args, "file") and args.file:
        with open(args.file, "rb") as f:
            raw = f.read()
            if getattr(args, "in_format", default_in_format) == "text":
                return raw
            # If in_format is base64 or hex, parse the text content of file
            text = raw.decode("utf-8").strip()
    elif hasattr(args, "input") and args.input is not None:
        text = args.input
    else:
        # Check if stdin has data
        if not sys.stdin.isatty():
            text = sys.stdin.read().strip()
        else:
            raise ValueError("No input provided. Use -i/--in, -f/--file, or pipe via stdin.")

    in_format = getattr(args, "in_format", default_in_format)
    if in_format == "text":
        return text.encode("utf-8") if isinstance(text, str) else text
    elif in_format == "base64":
        return base64.b64decode(text)
    elif in_format == "hex":
        return bytes.fromhex(text.replace(" ", "").replace("\n", ""))
    elif in_format == "raw":
        return text if isinstance(text, bytes) else text.encode("utf-8")
    else:
        raise ValueError(f"Unknown input format: {in_format}")

def format_output_bytes(data: bytes, out_format: str, out_file: str = None):
    """Outputs data to file or stdout in specified format."""
    if out_format == "base64":
        res = base64.b64encode(data).decode("utf-8")
    elif out_format == "hex":
        res = data.hex()
    elif out_format == "text":
        try:
            res = data.decode("utf-8")
        except UnicodeDecodeError:
            res = f"[Binary data, {len(data)} bytes, cannot display as UTF-8. Base64: {base64.b64encode(data).decode('utf-8')}]"
    elif out_format == "raw":
        res = data
    else:
        raise ValueError(f"Unknown output format: {out_format}")

    if out_file:
        mode = "wb" if out_format == "raw" else "w"
        encoding = None if out_format == "raw" else "utf-8"
        with open(out_file, mode, encoding=encoding) as f:
            f.write(res)
        print(f"Output successfully written to: {out_file}", file=sys.stderr)
    else:
        if out_format == "raw":
            sys.stdout.buffer.write(res)
        else:
            print(res)

def cmd_gen_keys(args):
    pkcs8 = (args.format.lower() == "pkcs8")
    priv_pem, pub_pem = rsa_crypto.generate_key_pair(args.size, pkcs8=pkcs8)

    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        priv_path = os.path.join(args.out_dir, "private_key.pem")
        pub_path = os.path.join(args.out_dir, "public_key.pem")
        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(priv_pem)
        with open(pub_path, "w", encoding="utf-8") as f:
            f.write(pub_pem)
        print(f"Generated {args.size}-bit RSA keypair in {args.out_dir}:")
        print(f"  Private Key: {priv_path}")
        print(f"  Public Key:  {pub_path}")
    elif args.priv_out or args.pub_out:
        if args.priv_out:
            with open(args.priv_out, "w", encoding="utf-8") as f:
                f.write(priv_pem)
            print(f"Private Key saved to: {args.priv_out}")
        if args.pub_out:
            with open(args.pub_out, "w", encoding="utf-8") as f:
                f.write(pub_pem)
            print(f"Public Key saved to: {args.pub_out}")
    else:
        print("=== RSA PRIVATE KEY ===")
        print(priv_pem)
        print("=== RSA PUBLIC KEY ===")
        print(pub_pem)

def cmd_encrypt(args):
    key_pem = read_key_input(args.key)
    chunk = not args.no_chunk

    if args.mode == "private":
        priv_key = rsa_crypto.load_private_key(key_pem, password=args.password)
        payload = read_payload_bytes(args, default_in_format="text")
        ciphertext = rsa_crypto.encrypt_private(payload, priv_key, block_type=args.block_type, chunk=chunk)
    else:
        pub_key = rsa_crypto.load_public_key(key_pem)
        payload = read_payload_bytes(args, default_in_format="text")
        ciphertext = rsa_crypto.encrypt_public(payload, pub_key, block_type=args.block_type, chunk=chunk)

    format_output_bytes(ciphertext, args.out_format, args.out_file)

def cmd_decrypt(args):
    key_pem = read_key_input(args.key)
    bt = None if args.block_type == "auto" else int(args.block_type)

    if args.mode == "public":
        pub_key = rsa_crypto.load_public_key(key_pem)
        ciphertext = read_payload_bytes(args, default_in_format="base64")
        plaintext = rsa_crypto.decrypt_public(ciphertext, pub_key, expected_bt=bt)
    else:
        priv_key = rsa_crypto.load_private_key(key_pem, password=args.password)
        ciphertext = read_payload_bytes(args, default_in_format="base64")
        plaintext = rsa_crypto.decrypt_private(ciphertext, priv_key, expected_bt=bt)

    format_output_bytes(plaintext, args.out_format, args.out_file)

def cmd_test(args):
    print("Running RSA Private Encrypt / Public Decrypt self-test...")
    priv_pem, pub_pem = rsa_crypto.generate_key_pair(2048)
    priv_key = rsa_crypto.load_private_key(priv_pem)
    pub_key = rsa_crypto.load_public_key(pub_pem)

    test_msg = "Hello RSA! This message was encrypted with a Private Key and decrypted with a Public Key."
    print(f"\n[1] Original Plaintext:\n    \"{test_msg}\"")

    cipher = rsa_crypto.encrypt_private(test_msg.encode("utf-8"), priv_key, block_type=1)
    b64_cipher = base64.b64encode(cipher).decode("utf-8")
    print(f"\n[2] Encrypted with Private Key (PKCS#1 v1.5 Type 1, Base64):\n    {b64_cipher[:64]}... ({len(cipher)} bytes)")

    decrypted = rsa_crypto.decrypt_public(cipher, pub_key)
    rec_text = decrypted.decode("utf-8")
    print(f"\n[3] Decrypted with Public Key:\n    \"{rec_text}\"")

    assert rec_text == test_msg
    print("\n[SUCCESS] Self-test passed! Encryption and Decryption verified.")

def cmd_password(args):
    import password_tool
    import json

    if args.verify:
        pwd = args.password
        if not pwd:
            if not sys.stdin.isatty():
                pwd = sys.stdin.read().strip()
            else:
                raise ValueError("Password is required for verification. Use -p/--password or pipe via stdin.")
        is_valid = password_tool.verify_password(pwd, args.verify)
        if is_valid:
            print("[SUCCESS] Password matches the bcrypt hash! (PHP password_verify == true)")
            sys.exit(0)
        else:
            print("[FAILED] Password does NOT match the bcrypt hash!", file=sys.stderr)
            sys.exit(1)

    # Generate or use provided password
    if args.password:
        pwd = args.password
    else:
        pwd = password_tool.generate_password(args.length)

    if args.no_hash:
        print(pwd)
        return

    # Hash with Bcrypt (PHP compatible)
    pwd_hash = password_tool.hash_password(pwd, cost=args.cost, prefix=args.prefix)

    if args.json:
        print(json.dumps({
            "password": pwd,
            "hash": pwd_hash,
            "length": len(pwd),
            "cost": args.cost,
            "prefix": args.prefix,
            "algorithm": "PASSWORD_BCRYPT"
        }, indent=2))
    else:
        print("=== Generated Alphanumeric Password ===")
        print(f"Password ({len(pwd)} chars): {pwd}")
        print("\n=== PHP PASSWORD_BCRYPT Hash ===")
        print(f"Hash ({len(pwd_hash)} chars): {pwd_hash}")
def cmd_jwt_sign(args):
    import jwt_tool
    import json

    if args.payload:
        payload = json.loads(args.payload)
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            payload = json.load(f)
    else:
        if not sys.stdin.isatty():
            payload = json.loads(sys.stdin.read().strip())
        else:
            raise ValueError("Payload is required. Use -p/--payload or -f/--file.")

    key = read_key_input(args.key) if args.key else None
    headers = json.loads(args.header) if args.header else None
    add_ts = args.add_timestamps or (args.expires_in is not None)
    exp_secs = args.expires_in if args.expires_in is not None else 3600

    token = jwt_tool.encode_jwt(
        payload,
        key=key,
        algorithm=args.alg,
        headers=headers,
        add_timestamps=add_ts,
        expires_in=exp_secs
    )
    if args.json:
        print(json.dumps({
            "token": token,
            "algorithm": args.alg,
            "payload": payload
        }, indent=2))
    else:
        print(token)

def cmd_jwt_verify(args):
    import jwt_tool
    import json

    if args.token:
        token = args.token.strip()
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            token = f.read().strip()
    else:
        if not sys.stdin.isatty():
            token = sys.stdin.read().strip()
        else:
            raise ValueError("Token is required. Use -t/--token or -f/--file.")

    key = read_key_input(args.key) if args.key else None
    verify = not args.no_verify

    res = jwt_tool.decode_jwt(token, key=key, verify=verify)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print("=== JWT Header ===")
        print(json.dumps(res["header"], indent=2))
        print("\n=== JWT Payload ===")
        print(json.dumps(res["payload"], indent=2))
        print("\n=== Verification Status ===")
        if res.get("valid"):
            print("Status: VALID (Signature verified successfully)")
        elif res.get("unverified"):
            print("Status: UNVERIFIED (No verification key provided - claims decoded without verification)")
        else:
            print(f"Status: INVALID ({res.get('error')})")
        if res.get("expired"):
            print("Notice: Token is EXPIRED (exp claim is in the past)")

def cmd_gui(args):
    import server
    server.start_server(host=args.host, port=args.port, open_browser=not args.no_browser)

def main():
    parser = argparse.ArgumentParser(
        description="RSA Private Key Encryption & Public Key Decryption Tool (PKCS#1 v1.5)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 2048-bit RSA keys
  python rsa_tool.py gen-keys --size 2048 --out-dir ./keys

  # Encrypt text using Private Key (output as Base64)
  python rsa_tool.py encrypt --key ./keys/private_key.pem -i "Secret message"

  # Decrypt Base64 ciphertext using Public Key
  python rsa_tool.py decrypt --key ./keys/public_key.pem -i "<base64_string>"

  # Launch Interactive Web GUI
  python rsa_tool.py gui
        """
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # gen-keys
    p_gen = subparsers.add_parser("gen-keys", help="Generate RSA keypair")
    p_gen.add_argument("--size", type=int, default=2048, choices=[1024, 2048, 3072, 4096], help="Key size in bits (default: 2048)")
    p_gen.add_argument("--format", choices=["pkcs8", "pkcs1"], default="pkcs8", help="PEM format: PKCS#8 or PKCS#1 (default: pkcs8)")
    p_gen.add_argument("--out-dir", help="Directory to save private_key.pem and public_key.pem")
    p_gen.add_argument("--priv-out", help="File path to save private key")
    p_gen.add_argument("--pub-out", help="File path to save public key")
    p_gen.set_defaults(func=cmd_gen_keys)

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt data (default: using Private Key)")
    p_enc.add_argument("-k", "--key", required=True, help="Path to PEM key file or PEM string")
    p_enc.add_argument("-i", "--in", dest="input", help="Text/data to encrypt")
    p_enc.add_argument("-f", "--file", help="Input file path")
    p_enc.add_argument("--in-format", choices=["text", "hex", "base64", "raw"], default="text", help="Input format (default: text)")
    p_enc.add_argument("--out-format", choices=["base64", "hex", "raw"], default="base64", help="Output format (default: base64)")
    p_enc.add_argument("-o", "--out-file", help="Output file path (default: stdout)")
    p_enc.add_argument("--block-type", type=int, default=1, choices=[1, 2], help="PKCS#1 block type: 1 (standard for private encrypt) or 2")
    p_enc.add_argument("--mode", choices=["private", "public"], default="private", help="Encryption key type (default: private)")
    p_enc.add_argument("--password", help="Password for encrypted private key (if any)")
    p_enc.add_argument("--no-chunk", action="store_true", help="Disable multi-block chunking for messages > max block payload")
    p_enc.set_defaults(func=cmd_encrypt)

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Decrypt data (default: using Public Key)")
    p_dec.add_argument("-k", "--key", required=True, help="Path to PEM key file or PEM string")
    p_dec.add_argument("-i", "--in", dest="input", help="Ciphertext data to decrypt")
    p_dec.add_argument("-f", "--file", help="Input ciphertext file path")
    p_dec.add_argument("--in-format", choices=["base64", "hex", "raw"], default="base64", help="Input format (default: base64)")
    p_dec.add_argument("--out-format", choices=["text", "hex", "base64", "raw"], default="text", help="Output format (default: text)")
    p_dec.add_argument("-o", "--out-file", help="Output file path (default: stdout)")
    p_dec.add_argument("--block-type", default="auto", choices=["auto", "1", "2"], help="Expected PKCS#1 block type (default: auto)")
    p_dec.add_argument("--mode", choices=["public", "private"], default="public", help="Decryption key type (default: public)")
    p_dec.add_argument("--password", help="Password for encrypted private key (if mode=private)")
    p_dec.set_defaults(func=cmd_decrypt)

    # password / bcrypt generator
    p_pwd = subparsers.add_parser("password", aliases=["pwd", "gen-pwd"], help="Generate 64-char random alphanumeric password and PHP-compatible PASSWORD_BCRYPT hash")
    p_pwd.add_argument("-l", "--length", type=int, default=64, help="Password length in characters (default: 64)")
    p_pwd.add_argument("-c", "--cost", type=int, default=10, help="Bcrypt cost factor (4-31, default: 10, matches PHP)")
    p_pwd.add_argument("--prefix", choices=["2y", "2b", "2a"], default="2y", help="Bcrypt prefix: 2y (PHP standard) or 2b (default: 2y)")
    p_pwd.add_argument("-p", "--password", help="Custom password to hash instead of generating random")
    p_pwd.add_argument("--verify", help="Verify password against this bcrypt hash")
    p_pwd.add_argument("--no-hash", action="store_true", help="Only output the generated password without hashing")
    p_pwd.add_argument("--json", action="store_true", help="Output results as JSON")
    # jwt-sign
    p_jwt_sign = subparsers.add_parser("jwt-sign", aliases=["jwt-encode"], help="Encode and sign a JSON Web Token (JWT)")
    p_jwt_sign.add_argument("-k", "--key", help="Private key PEM (for RS/PS) or secret string (for HS)")
    p_jwt_sign.add_argument("-p", "--payload", help="JSON payload string")
    p_jwt_sign.add_argument("-f", "--file", help="Path to JSON file containing payload")
    p_jwt_sign.add_argument("--alg", default="RS256", choices=["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512", "none"], help="Signing algorithm (default: RS256)")
    p_jwt_sign.add_argument("--header", help="Optional JSON string for custom headers")
    p_jwt_sign.add_argument("--add-timestamps", action="store_true", help="Automatically generate 'iat' (now) and 'exp' (now + 1 hour)")
    p_jwt_sign.add_argument("--expires-in", type=int, default=None, help="Set expiration duration in seconds from now (e.g. 900, 3600, 86400)")
    p_jwt_sign.add_argument("--json", action="store_true", help="Output result as JSON object")
    p_jwt_sign.set_defaults(func=cmd_jwt_sign)

    # jwt-verify
    p_jwt_verify = subparsers.add_parser("jwt-verify", aliases=["jwt-decode"], help="Decode and verify a JSON Web Token (JWT)")
    p_jwt_verify.add_argument("-t", "--token", help="JWT token string")
    p_jwt_verify.add_argument("-f", "--file", help="Path to file containing JWT token")
    p_jwt_verify.add_argument("-k", "--key", help="Public key PEM (for RS/PS) or secret string (for HS)")
    p_jwt_verify.add_argument("--no-verify", action="store_true", help="Decode without verifying signature")
    p_jwt_verify.add_argument("--json", action="store_true", help="Output result as JSON")
    p_jwt_verify.set_defaults(func=cmd_jwt_verify)

    # test
    p_test = subparsers.add_parser("test", help="Run quick end-to-end self-test")
    p_test.set_defaults(func=cmd_test)

    # gui / serve
    p_gui = subparsers.add_parser("gui", aliases=["serve"], help="Launch interactive Web GUI")
    p_gui.add_argument("--port", type=int, default=5000, help="Web server port (default: 5000)")
    p_gui.add_argument("--host", default="127.0.0.1", help="Web server host (default: 127.0.0.1)")
    p_gui.add_argument("--no-browser", action="store_true", help="Do not automatically open default browser")
    p_gui.set_defaults(func=cmd_gui)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    try:
        args.func(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

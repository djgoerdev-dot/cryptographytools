#!/usr/bin/env python3
"""
Lightweight Web Server & API for RSA Private Encrypt / Public Decrypt Tool.
Uses standard library http.server and rsa_crypto.py. Zero pip dependencies needed.
"""

import os
import sys
import json
import base64
import webbrowser
try:
    from http.server import ThreadingHTTPServer as ServerClass
except ImportError:
    from http.server import HTTPServer as ServerClass
from http.server import SimpleHTTPRequestHandler
import rsa_crypto
import password_tool
import jwt_tool

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

class RSAHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        super().end_headers()

    def log_message(self, format, *args):
        # Concise logging
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

    def send_json(self, status_code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path.split("?")[0] == "/api/health":
            return self.send_json(200, {"status": "ok", "app": "RSA & JWT Studio"})
        super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            req = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception as e:
            return self.send_json(400, {"success": False, "error": f"Invalid JSON payload: {e}"})

        path = self.path.split("?")[0]

        if path == "/api/generate-keys":
            try:
                size = int(req.get("size", 2048))
                pkcs8 = bool(req.get("pkcs8", True))
                priv_pem, pub_pem = rsa_crypto.generate_key_pair(size, pkcs8=pkcs8)
                return self.send_json(200, {
                    "success": True,
                    "key_size": size,
                    "private_key": priv_pem,
                    "public_key": pub_pem
                })
            except Exception as e:
                return self.send_json(400, {"success": False, "error": str(e)})

        elif path == "/api/validate-key":
            try:
                key_text = req.get("key", "").strip()
                if not key_text:
                    return self.send_json(400, {"success": False, "error": "No key provided"})

                if "PRIVATE KEY" in key_text:
                    priv = rsa_crypto.load_private_key(key_text)
                    return self.send_json(200, {
                        "success": True,
                        "type": "private",
                        "size": priv.key_size,
                        "format": "PKCS#8" if "BEGIN PRIVATE KEY" in key_text else "PKCS#1"
                    })
                elif "PUBLIC KEY" in key_text:
                    pub = rsa_crypto.load_public_key(key_text)
                    return self.send_json(200, {
                        "success": True,
                        "type": "public",
                        "size": pub.key_size,
                        "format": "SPKI (PKCS#8)" if "BEGIN PUBLIC KEY" in key_text else "PKCS#1"
                    })
                else:
                    return self.send_json(400, {"success": False, "error": "Key must contain PEM headers (BEGIN PRIVATE/PUBLIC KEY)"})
            except Exception as e:
                return self.send_json(400, {"success": False, "error": f"Invalid key: {str(e)}"})

        elif path == "/api/encrypt":
            try:
                key_pem = req.get("key", "").strip()
                data_str = req.get("data", "")
                in_format = req.get("in_format", "text")
                mode = req.get("mode", "private") # "private" or "public"
                block_type = int(req.get("block_type", 1))
                chunk = bool(req.get("chunk", True))
                password = req.get("password") or None

                if in_format == "text":
                    data_bytes = data_str.encode("utf-8")
                elif in_format == "base64":
                    data_bytes = base64.b64decode(data_str.strip())
                elif in_format == "hex":
                    clean_hex = data_str.replace(" ", "").replace("\n", "").replace(":", "")
                    data_bytes = bytes.fromhex(clean_hex)
                else:
                    return self.send_json(400, {"success": False, "error": f"Invalid in_format: {in_format}"})

                if mode == "private":
                    priv_key = rsa_crypto.load_private_key(key_pem, password=password)
                    ciphertext = rsa_crypto.encrypt_private(data_bytes, priv_key, block_type=block_type, chunk=chunk)
                    k = priv_key.key_size // 8
                else:
                    pub_key = rsa_crypto.load_public_key(key_pem)
                    ciphertext = rsa_crypto.encrypt_public(data_bytes, pub_key, block_type=block_type, chunk=chunk)
                    k = pub_key.key_size // 8

                return self.send_json(200, {
                    "success": True,
                    "base64": base64.b64encode(ciphertext).decode("utf-8"),
                    "hex": ciphertext.hex(),
                    "total_bytes": len(ciphertext),
                    "blocks": len(ciphertext) // k if k > 0 else 1
                })
            except Exception as e:
                return self.send_json(400, {"success": False, "error": str(e)})

        elif path == "/api/decrypt":
            try:
                key_pem = req.get("key", "").strip()
                data_str = req.get("data", "").strip()
                in_format = req.get("in_format", "base64")
                mode = req.get("mode", "public") # "public" or "private"
                bt_raw = req.get("block_type", "auto")
                expected_bt = None if bt_raw == "auto" else int(bt_raw)
                password = req.get("password") or None

                if in_format == "base64":
                    cipher_bytes = base64.b64decode(data_str)
                elif in_format == "hex":
                    clean_hex = data_str.replace(" ", "").replace("\n", "").replace(":", "")
                    cipher_bytes = bytes.fromhex(clean_hex)
                else:
                    return self.send_json(400, {"success": False, "error": f"Invalid in_format: {in_format}"})

                if mode == "public":
                    pub_key = rsa_crypto.load_public_key(key_pem)
                    plaintext = rsa_crypto.decrypt_public(cipher_bytes, pub_key, expected_bt=expected_bt)
                else:
                    priv_key = rsa_crypto.load_private_key(key_pem, password=password)
                    plaintext = rsa_crypto.decrypt_private(cipher_bytes, priv_key, expected_bt=expected_bt)

                # Format plaintext
                try:
                    text_res = plaintext.decode("utf-8")
                    is_utf8 = True
                except UnicodeDecodeError:
                    text_res = "[Binary data - non UTF-8]"
                    is_utf8 = False

                return self.send_json(200, {
                    "success": True,
                    "text": text_res,
                    "is_utf8": is_utf8,
                    "base64": base64.b64encode(plaintext).decode("utf-8"),
                    "hex": plaintext.hex(),
                    "total_bytes": len(plaintext)
                })
            except Exception as e:
                return self.send_json(400, {"success": False, "error": str(e)})

        elif path == "/api/generate-password":
            try:
                length = int(req.get("length", 64))
                pwd = password_tool.generate_password(length)
                return self.send_json(200, {
                    "success": True,
                    "password": pwd,
                    "length": len(pwd)
                })
            except Exception as e:
                return self.send_json(400, {"success": False, "error": str(e)})

        elif path == "/api/hash-password":
            try:
                pwd = req.get("password", "")
                if not pwd:
                    return self.send_json(400, {"success": False, "error": "Password cannot be empty"})
                cost = int(req.get("cost", 10))
                prefix = req.get("prefix", "2y")
                h = password_tool.hash_password(pwd, cost=cost, prefix=prefix)
                return self.send_json(200, {
                    "success": True,
                    "hash": h,
                    "cost": cost,
                    "prefix": prefix,
                    "algorithm": "PASSWORD_BCRYPT"
                })
            except Exception as e:
                return self.send_json(400, {"success": False, "error": str(e)})

        elif path == "/api/verify-password":
            try:
                pwd = req.get("password", "")
                h = req.get("hash", "")
                is_valid = password_tool.verify_password(pwd, h)
                return self.send_json(200, {
                    "success": True,
                    "valid": is_valid
                })
            except Exception as e:
                return self.send_json(400, {"success": False, "error": str(e)})

        elif path == "/api/generate-and-hash":
            try:
                length = int(req.get("length", 64))
                cost = int(req.get("cost", 10))
                prefix = req.get("prefix", "2y")
                res = password_tool.generate_and_hash(length=length, cost=cost, prefix=prefix)
                res["success"] = True
                return self.send_json(200, res)
            except Exception as e:
                return self.send_json(400, {"success": False, "error": str(e)})

        elif path == "/api/jwt/encode":
            try:
                payload = req.get("payload", {})
                if isinstance(payload, str):
                    payload = json.loads(payload)
                headers = req.get("headers", {})
                if isinstance(headers, str):
                    headers = json.loads(headers) if headers.strip() else None
                key = req.get("key", "").strip() or None
                alg = req.get("algorithm", "RS256")
                token = jwt_tool.encode_jwt(payload, key=key, algorithm=alg, headers=headers)
                return self.send_json(200, {
                    "success": True,
                    "token": token,
                    "algorithm": alg
                })
            except Exception as e:
                return self.send_json(400, {"success": False, "error": str(e)})

        elif path == "/api/jwt/decode":
            try:
                token = req.get("token", "").strip()
                key = req.get("key", "").strip() or None
                verify = bool(req.get("verify", True))
                res = jwt_tool.decode_jwt(token, key=key, verify=verify)
                res["success"] = True
                return self.send_json(200, res)
            except Exception as e:
                return self.send_json(400, {"success": False, "error": str(e)})

        else:
            return self.send_json(404, {"success": False, "error": "Endpoint not found"})

def start_server(host=None, port=None, open_browser=False):
    if host is None:
        host = os.environ.get("HOST", "0.0.0.0")
    if port is None:
        port = int(os.environ.get("PORT", 5000))

    os.makedirs(WEB_DIR, exist_ok=True)
    server = ServerClass((host, port), RSAHandler)
    url = f"http://{host}:{port}"
    print(f"\n=======================================================")
    print(f" RSA & JWT Studio Web Server (Production Ready)")
    print(f" Running at: {url}")
    print(f" Server Class: {server.__class__.__name__}")
    print(f" Press Ctrl+C to stop.")
    print(f"=======================================================\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.server_close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Start RSA & JWT Web GUI server")
    default_host = os.environ.get("HOST", "0.0.0.0")
    default_port = int(os.environ.get("PORT", 5000))
    parser.add_argument("--host", default=default_host, help=f"Host to bind (default: {default_host})")
    parser.add_argument("--port", type=int, default=default_port, help=f"Port to bind (default: {default_port})")
    parser.add_argument("--browser", action="store_true", help="Open browser automatically")
    args = parser.parse_args()

    start_server(host=args.host, port=args.port, open_browser=args.browser)

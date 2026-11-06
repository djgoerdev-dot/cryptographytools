# 🔐 Comprehensive Security & Cryptographic Toolkit

An all-in-one cryptographic suite featuring **RSA Private Key Encryption & Public Key Decryption** (`RSAES-PKCS1-V1_5`), a **64-Character Alphanumeric Password Generator with PHP-compatible `PASSWORD_BCRYPT` Hasher**, and a full-featured **JWT Studio** for signing, verifying, timestamp generating (`iat`/`exp`), and inspecting JSON Web Tokens.

Available as an **Interactive Web GUI** (port 5000), a fast **Command-Line Interface (CLI)** in both Python and Node.js, and clean **modular Python libraries**.

---

## 📑 Table of Contents

- [Key Capabilities](#-key-capabilities)
- [Prerequisites & Installation](#-prerequisites--installation)
- [Quick Start](#-quick-start)
- [Interactive Web GUI](#-interactive-web-gui)
  - [1. RSA Encrypt & Decrypt (Dual-Mode)](#1-rsa-encrypt--decrypt-dual-mode)
  - [2. 64-Char Password & Bcrypt Studio](#2-64-char-password--bcrypt-studio)
  - [3. JWT Studio (Sign, Verify & Inspect)](#3-jwt-studio-sign-verify--inspect)
  - [4. RSA Key Generator & Manager](#4-rsa-key-generator--manager)
  - [5. Step-by-Step Visualizer](#5-step-by-step-visualizer)
- [Command Line Interface (CLI)](#-command-line-interface-cli)
  - [RSA Key Generation](#rsa-key-generation)
  - [RSA Encryption & Decryption](#rsa-encryption--decryption)
  - [64-Character Password & Bcrypt](#64-character-password--bcrypt)
  - [JWT Sign & Verify](#jwt-sign--verify)
- [Python API Reference](#-python-api-reference)
  - [RSA Cryptography (`rsa_crypto.py`)](#rsa-cryptography-rsa_cryptopy)
  - [Password & Bcrypt Tool (`password_tool.py`)](#password--bcrypt-tool-password_toolpy)
  - [JWT Engine (`jwt_tool.py`)](#jwt-engine-jwt_toolpy)
- [REST API Reference](#-rest-api-reference)
- [Cross-Language Interoperability](#-cross-language-interoperability)
- [Project Structure](#-project-structure)
- [Automated Verification Tests](#-automated-verification-tests)
- [Git & Version Control](#-git--version-control)

---

## 🚀 Key Capabilities

1. **RSA Private Key Encryption / Public Key Decryption**:
   - Dedicated implementation of RFC 2313 / RFC 3447 **`RSAES-PKCS1-V1_5`**.
   - Dual-Mode support:
     - 🛡️ **Private Encrypt &rarr; Public Decrypt** *(Digital Signature / Origin Proof)*
     - 🔒 **Public Encrypt &rarr; Private Decrypt** *(Standard Confidentiality)*
   - Support for **Block Type 1** (OpenSSL/Node.js/Java standard) and **Block Type 2** (randomized padding).
   - Multi-block automatic chunking for payloads exceeding single-block modulus limit.
2. **64-Character Alphanumeric Password & PHP Bcrypt Generator**:
   - Cryptographically secure CSPRNG generator producing random 64-character passwords from `[a-zA-Z0-9]` with **~381 bits of entropy**.
   - 100% PHP-compatible `PASSWORD_BCRYPT` implementation using `$2y$` (or `$2b$`) prefix with configurable cost factor (default: 10), fully verifiable via PHP's native `password_verify()`.
3. **JWT Studio (Sign, Verify, Decode & Timestamps)**:
   - Full RFC 7519 JSON Web Token engine supporting asymmetric and symmetric algorithms:
     - **RS256, RS384, RS512** (RSA PKCS#1 v1.5)
     - **PS256, PS384, PS512** (RSA PSS)
     - **HS256, HS384, HS512** (HMAC-SHA)
     - **none** (unsigned)
   - **Zero-Latency Client-Side Breakdown**: Paste any JWT and instantly inspect its claims breakdown, RFC descriptions, formatted local timestamps, and active/expired status without needing a verification key.
   - **Timestamp Generator (`iat` & `exp`)**: Generate current epoch (`iat`) and expiration (`exp`) with presets (`15m`, `30m`, `1h`, `2h`, `4h`, `12h`, `24h`, `7d`, `30d`, `1y`), custom calendar date-time picker, and optional `nbf`.
   - **Per-Claim Copy**: 1-click copy buttons for every individual claim value, formatted date strings, payload JSON, and header JSON.

---

## 📦 Prerequisites & Installation

### Requirements
- **Python**: 3.8+ (tested on Python 3.8 - 3.13)
- **Node.js**: (Optional) Node.js 18+ if using Node CLI or Node server.
- **PHP**: (Optional) PHP 7.4+ or 8.x for cross-runtime CLI verification.

### Install Dependencies
Clone the repository and install required Python packages:

```bash
git clone https://github.com/<YOUR_USERNAME>/<REPO_NAME>.git
cd <REPO_NAME>
pip install -r requirements.txt
```

*(Dependencies: `cryptography` and `bcrypt`)*

---

## ⚡ Quick Start

### Windows 1-Click
Double-click:
```bat
start_gui.bat
```
*(Or in PowerShell: `.\start_gui.ps1`)*

### Python Server
```bash
python server.py
# or
python rsa_tool.py gui
```

### Node.js Server
```bash
node server.js
```

### 🐳 Docker Container (Production)
```bash
# Build production image
docker build -t crypto-tools .

# Run container (binds to http://localhost:5000)
docker run -d -p 5000:5000 --name crypto-toolkit crypto-tools
```

Your default web browser can access the web application at **`http://127.0.0.1:5000`** (or healthcheck probe at `http://127.0.0.1:5000/api/health`).

---

## 🖥️ Interactive Web GUI

The Web GUI is designed with a responsive, modern dark/light interface organized into tabs:

### 1. RSA Encrypt & Decrypt (Dual-Mode)
- **Workflow Preset Switcher**: Toggle between **Origin Proof Mode** (Private Encrypt &rarr; Public Decrypt) and **Confidentiality Mode** (Public Encrypt &rarr; Private Decrypt).
- **Encrypt Tab**:
  - Input: Plaintext UTF-8, Hex, Base64, or file upload.
  - Padding: PKCS#1 v1.5 Block Type 1 (`0x01`) or Block Type 2 (`0x02`).
  - Output: Base64 and Hex with copy/download buttons and **"➡️ Send to Decrypt Tab"**.
- **Decrypt Tab**:
  - Input ciphertext in Base64 or Hex.
  - Automatically identifies block structure, modulus size, and recovers plaintext.

### 2. 64-Char Password & Bcrypt Studio
- Generate 64-character alphanumeric passwords (`[a-zA-Z0-9]`) using CSPRNG.
- Generate PHP-compatible bcrypt hashes with configurable cost factor (4–31, default: 10) and prefix (`$2y$` or `$2b$`).
- Interactive test verification verifying that `password_verify($password, $hash) === true`.
- Live PHP code sample preview updated in real-time.

### 3. JWT Studio (Sign, Verify & Inspect)
- **Left Column — Encode & Sign**:
  - Select algorithm (`RS256`, `HS256`, etc.).
  - **⏱️ Timestamp Generator**: Generate `iat` (now) and `exp` with presets (`15m`, `1h`, `24h`, `7d`, `30d`, `custom date`) and optional `+ nbf`.
  - **Active Key Reuse**: 1-click **"Use Active RSA Key"** (loads active RSA private key) or **"Use 64-Char Password"** (loads random HMAC secret).
  - Live JSON syntax validation with formatted indentation.
- **Right Column — Decoded Token & Claims Breakdown**:
  - **Instant Decoding**: Paste any token and immediately view decoded header and payload claims on screen without requiring a public key.
  - **Claims Table Inspector**: Detailed table showing claim name, RFC purpose (`sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, etc.), and formatted values.
  - **Human-Readable Timestamps**: Formatted local date/time strings with dynamic countdowns (e.g. `Expires in 45m` or `Expired 2h ago`).
  - **1-Click Copy**: Copy individual claim values, formatted dates, payload JSON, or header JSON to your clipboard.
  - **Live Verification**: Paste a public key or HMAC secret to mathematically verify signature validity.

### 4. RSA Key Generator & Manager
- Generate 1024, 2048, 3072, or 4096-bit RSA keypairs.
- Export in PKCS#8 or PKCS#1 PEM formats.
- 1-click clipboard copy or `.pem` file download.

### 5. Step-by-Step Visualizer
- Interactive breakdown of the PKCS#1 block construction:
  $$EB = 0x00 \mathbin{\Vert} BT \mathbin{\Vert} PS \mathbin{\Vert} 0x00 \mathbin{\Vert} D$$
- Mathematical explanation of modular exponentiation ($C = M^d \pmod n$) and recovery ($M = C^e \pmod n$).

---

## 💻 Command Line Interface (CLI)

The CLI tool (`rsa_tool.py`) provides commands for all cryptographic operations.

### RSA Key Generation
```bash
# Generate 2048-bit keypair saved to ./keys directory
python rsa_tool.py gen-keys --size 2048 --out-dir ./keys

# PKCS#1 format with specific output filenames
python rsa_tool.py gen-keys --size 2048 --format pkcs1 --priv-out priv.pem --pub-out pub.pem
```

### RSA Encryption & Decryption
```bash
# Encrypt with Private Key (PKCS#1 v1.5, default)
python rsa_tool.py encrypt -k ./keys/private_key.pem -i "Secret text message"

# Encrypt a binary file and save Base64 output to file
python rsa_tool.py encrypt -k ./keys/private_key.pem -f document.pdf -o cipher.b64

# Decrypt Base64 ciphertext with Public Key
python rsa_tool.py decrypt -k ./keys/public_key.pem -i "<base64_string>"

# Decrypt from ciphertext file
python rsa_tool.py decrypt -k ./keys/public_key.pem -f cipher.b64
```

### 64-Character Password & Bcrypt
```bash
# Generate 64-character password + $2y$ Bcrypt hash
python rsa_tool.py password

# Custom length or cost factor:
python rsa_tool.py password --length 64 --cost 12 --prefix 2y

# Output as JSON:
python rsa_tool.py password --json

# Verify a password against a hash:
python rsa_tool.py password -p "<password>" --verify "<bcrypt_hash>"
```

### JWT Sign & Verify
```bash
# Sign with RSA Private Key (RS256) with auto-generated iat & exp (1 hour)
python rsa_tool.py jwt-sign --alg RS256 -k ./keys/private_key.pem -p '{"sub":"usr_123","role":"admin"}' --add-timestamps

# Sign with HMAC Secret (HS256) and custom expiration (24 hours = 86400s)
python rsa_tool.py jwt-sign --alg HS256 -k "my-secret-key" -p '{"sub":"usr_123"}' --expires-in 86400

# Verify with RSA Public Key
python rsa_tool.py jwt-verify -t "<token>" -k ./keys/public_key.pem

# Verify with HMAC Secret
python rsa_tool.py jwt-verify -t "<token>" -k "my-secret-key"

# Decode claims without verification key (unverified inspection)
python rsa_tool.py jwt-verify -t "<token>"

# Output verification results as JSON
python rsa_tool.py jwt-verify -t "<token>" -k ./keys/public_key.pem --json
```

---

## 🐍 Python API Reference

### RSA Cryptography (`rsa_crypto.py`)
```python
import rsa_crypto

# 1. Generate keypair
priv_pem, pub_pem = rsa_crypto.generate_key_pair(key_size=2048)

# 2. Load keys
priv = rsa_crypto.load_private_key(priv_pem)
pub = rsa_crypto.load_public_key(pub_pem)

# 3. Encrypt with Private Key (Block Type 1)
ciphertext = rsa_crypto.encrypt_private(b"Hello World", priv, block_type=1)

# 4. Decrypt with Public Key
plaintext = rsa_crypto.decrypt_public(ciphertext, pub)
print(plaintext.decode("utf-8")) # "Hello World"
```

### Password & Bcrypt Tool (`password_tool.py`)
```python
import password_tool

# 1. Generate 64-char alphanumeric password
password = password_tool.generate_password(64)

# 2. Hash with PHP PASSWORD_BCRYPT logic ($2y$)
bcrypt_hash = password_tool.hash_password(password, cost=10, prefix="2y")

# 3. Verify password
is_valid = password_tool.verify_password(password, bcrypt_hash)
print(is_valid) # True
```

### JWT Engine (`jwt_tool.py`)
```python
import jwt_tool

# 1. Standalone timestamp generator
ts = jwt_tool.generate_timestamps(expires_in=3600, include_nbf=True)
# {'iat': 1776135000, 'exp': 1776138600, 'nbf': 1776135000}

# 2. Sign token with RSA Private Key (RS256)
token = jwt_tool.encode_jwt(
    payload={"sub": "usr_123", "role": "admin"},
    key=priv_pem,
    algorithm="RS256",
    add_timestamps=True,
    expires_in=7200
)

# 3. Verify token with RSA Public Key
result = jwt_tool.decode_jwt(token, key=pub_pem, verify=True)
print("Valid:", result["valid"])
print("Payload:", result["payload"])

# 4. Decode claims without key (unverified inspection)
unverified = jwt_tool.decode_jwt(token, key=None)
print("Claims:", unverified["payload"])
```

---

## 🌐 REST API Reference

The local server exposes RESTful JSON endpoints on `http://127.0.0.1:5000`:

| Endpoint | Method | Description | Request Body Parameters |
|---|---|---|---|
| `/api/generate-keys` | `POST` | Generates RSA keypair | `{"key_size": 2048, "format": "pkcs8"}` |
| `/api/encrypt` | `POST` | Encrypts plaintext | `{"key": "PEM", "data": "text", "mode": "private", "block_type": 1}` |
| `/api/decrypt` | `POST` | Decrypts ciphertext | `{"key": "PEM", "data": "base64", "mode": "public", "in_format": "base64"}` |
| `/api/generate-password` | `POST` | Generates random password | `{"length": 64}` |
| `/api/hash-password` | `POST` | Hashes password with Bcrypt | `{"password": "str", "cost": 10, "prefix": "2y"}` |
| `/api/verify-password` | `POST` | Verifies Bcrypt hash | `{"password": "str", "hash": "str"}` |
| `/api/generate-and-hash` | `POST` | Generates password & hash | `{"length": 64, "cost": 10, "prefix": "2y"}` |
| `/api/jwt/encode` | `POST` | Signs & encodes JWT | `{"payload": {}, "key": "PEM/secret", "algorithm": "RS256", "headers": {}}` |
| `/api/jwt/decode` | `POST` | Decodes & verifies JWT | `{"token": "str", "key": "PEM/secret", "verify": true}` |

---

## 🔄 Cross-Language Interoperability

Ciphertext, hashes, and JWT tokens produced by this tool are 100% interoperable across standard runtimes:

### Node.js (RSA PKCS#1 v1.5)
```javascript
const crypto = require('crypto');
const fs = require('fs');

const privKey = fs.readFileSync('private_key.pem', 'utf8');
const pubKey = fs.readFileSync('public_key.pem', 'utf8');

// Encrypt with Private Key
const cipher = crypto.privateEncrypt({
  key: privKey,
  padding: crypto.constants.RSA_PKCS1_PADDING
}, Buffer.from('Hello World'));

// Decrypt with Public Key
const plain = crypto.publicDecrypt({
  key: pubKey,
  padding: crypto.constants.RSA_PKCS1_PADDING
}, cipher);

console.log(plain.toString()); // "Hello World"
```

### PHP (Password Bcrypt)
```php
<?php
// Hashes generated by this tool verify natively in PHP:
$hash = '$2y$10$...';
$password = '...';

$isValid = password_verify($password, $hash);
echo $isValid ? "Valid\n" : "Invalid\n"; // Valid
```

### Java (Standard SunJCE)
```java
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
cipher.init(Cipher.DECRYPT_MODE, publicKey);
byte[] plainBytes = cipher.doFinal(cipherBytes);
System.out.println(new String(plainBytes, StandardCharsets.UTF_8));
```

---

## 📁 Project Structure

```text
RSA_Encrypt_Decrypt/
├── Dockerfile             # Production multi-stage / slim Docker container
├── .dockerignore          # Docker build exclusion rules
├── rsa_crypto.py          # Core RSA PKCS#1 v1.5 encryption/decryption engine
├── password_tool.py       # 64-char CSPRNG password generator & PHP Bcrypt hasher
├── jwt_tool.py            # RFC 7519 JWT signing, verification & timestamp engine
├── rsa_tool.py            # Full-featured Python CLI application
├── rsa_tool.js            # Node.js CLI implementation
├── server.py              # Python HTTP server & REST API
├── server.js              # Node.js HTTP server & REST API
├── start_gui.bat          # Windows 1-click batch launcher
├── start_gui.ps1          # Windows PowerShell launcher
├── requirements.txt       # Python dependencies (cryptography, bcrypt)
├── test_rsa_crypto.py     # RSA unit tests & Node.js cross-verification
├── test_password_tool.py  # Password randomness, entropy & Bcrypt tests
├── test_jwt_tool.py       # JWT RFC 7519, RS256, HS256 & unverified tests
├── .gitignore             # Git exclusions (private keys, cache, logs)
└── web/                   # Web GUI Single-Page Application (SPA)
    ├── index.html         # Modern responsive HTML5 UI
    ├── style.css          # Dark/Light theme CSS & layout
    └── app.js             # Client-side UI logic & instant JWT parser
```

---

## 🧪 Automated Verification Tests

Run the full automated test suite (22 unit tests covering RSA, Bcrypt & JWT):

```bash
python -m unittest discover
```

**Output:**
```
......................
----------------------------------------------------------------------
Ran 22 tests in 1.872s

OK
```

The test suite validates:
- RSA keypair generation in PKCS#1 and PKCS#8 formats.
- PKCS#1 v1.5 Block Type 1 & 2 private encryption and public decryption round-trips.
- Multi-block automatic chunking on long payloads.
- Password generation entropy, character distribution, and 64-char length.
- PHP `PASSWORD_BCRYPT` hash verification and cost factor compliance.
- JWT encoding, RS256/384/512 and PS256 signing with RSA keys.
- JWT HS256 HMAC secret verification.
- Instant unverified claim decoding without a public key.
- Token expiration detection (`exp < now`).
- Cross-language verification against Node.js `crypto`.

---

## 🐙 Git & Version Control

To upload this repository to GitHub:

```bash
# 1. Initialize Git and stage files
git init
git branch -M main
git add .
git commit -m "Initial commit"

# 2. Link your remote repository and push
git remote add origin https://github.com/<YOUR_USERNAME>/<REPO_NAME>.git
git push -u origin main
```

Private keys and cache folders are automatically excluded by [`.gitignore`](.gitignore).

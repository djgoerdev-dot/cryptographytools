# RSA Private Encrypt & Public Decrypt Tool

A dedicated, comprehensive tool that allows you to easily **encrypt text or data using an RSA Private Key** and **decrypt it using the matching RSA Public Key**, implementing padding scheme **`RSAES-PKCS1-V1_5`** (RFC 2313 / RFC 3447).

It provides:
1. 🖥️ **Interactive Web GUI**: Visual browser-based interface with 1-click demo, live key generator, and step-by-step visualizer.
2. 💻 **Command-Line Interface (CLI)**: Fast CLI tools available in both **Python** (`rsa_tool.py`) and **Node.js** (`rsa_tool.js`).
3. 📦 **Core Cryptographic Library**: Modular engine (`rsa_crypto.py`) with support for PKCS#1 v1.5 Block Type 1 & Type 2, auto-chunking (multi-block) for payloads of arbitrary length, and PEM formats (PKCS#1 and PKCS#8).
4. 🚀 **One-Click Launchers**: Windows `start_gui.bat` and `start_gui.ps1`.

---

## Quick Start (Web GUI)

### Option A: Windows 1-Click
Double-click:
```bat
start_gui.bat
```
*(Or in PowerShell: `.\start_gui.ps1`)*

### Option B: Python Server
```bash
python server.py
# or
python rsa_tool.py gui
```

### Option C: Node.js Server
```bash
node server.js
```

Your default web browser will open to `http://127.0.0.1:5000`.

---

## Web GUI Features

- 🔄 **Workflow Mode Switcher**:
  - 🛡️ **Private Encrypt &rarr; Public Decrypt** *(Digital Signature / Origin Proof)*
  - 🔒 **Public Encrypt &rarr; Private Decrypt** *(Standard Confidentiality)*
- ⚡ **1-Click Live Demo**: Click the **⚡ 1-Click Demo** button in the top navigation to instantly generate keys, encrypt test data, decrypt, and verify round-trip.
- 🔒 **Encrypt Tab**:
  - Choose key type: **Private Key** (signature/origin mode) or **Public Key** (confidentiality mode).
  - Input formats: Plaintext UTF-8, Hex, Base64, or file upload.
  - Padding schemes:
    - **PKCS#1 v1.5 Block Type 1** (`00 01 FF...FF 00 M`): Standard for OpenSSL (`RSA_private_encrypt`), Node.js (`crypto.privateEncrypt`), and Java SunJCE.
    - **PKCS#1 v1.5 Block Type 2** (`00 02 Random 00 M`): Randomized padding.
  - Chunking mode: Automatic multi-block support for messages longer than single-block limits.
  - Output formats: Base64 and Hex, with 1-click copy and file download.
  - **➡️ Send to Decrypt Tab**: One-click transfer of ciphertext and matching key into the decrypt form.
- 🔓 **Decrypt Tab**:
  - Choose key type: **Private Key** (standard decryption) or **Public Key** (signature/origin verification).
  - Input ciphertext in Base64 or Hex.
  - Auto-detection of block type and key size.
  - Instant plaintext recovery and match verification.
- 🎫 **JWT Studio (Sign & Verify)**:
  - Full RFC 7519 JSON Web Token engine supporting asymmetric and symmetric algorithms.
  - Algorithms: **RS256 / RS384 / RS512** (RSA PKCS#1 v1.5), **PS256 / PS384 / PS512** (RSA PSS), **HS256 / HS384 / HS512** (HMAC-SHA), and **none** (unsigned).
  - ⏱️ **Timestamp Generator (`iat` & `exp`)**: One-click generation of current issue time (`iat`) and configurable expiration time (`exp`) with presets (`15m`, `30m`, `1h`, `2h`, `4h`, `12h`, `24h`, `7d`, `30d`, `1y`), custom calendar date-time picker, and optional `nbf` (not before).
  - 📋 **Payload Claims Breakdown**: Instant automatic table inspector with RFC descriptions, human-readable date conversions, one-click copy of decoded values, and view toggle between Table View and JSON View.
  - Expiration detection and color-coded 3-part token breakdown (Header &bull; Payload &bull; Signature).
- 🔑 **Key Generator & Manager**:
  - Generate 1024, 2048, 3072, or 4096-bit RSA keys.
  - Export in PKCS#8 or PKCS#1 (Traditional OpenSSL) PEM format.
  - One-click copy or download of `.pem` files.
- 🧪 **Step-by-Step Visualizer**:
  - Visual breakdown of the encryption block $EB = 0x00 \mathbin{\Vert} BT \mathbin{\Vert} PS \mathbin{\Vert} 0x00 \mathbin{\Vert} D$, modular exponentiation $C = M^d \pmod n$, and public key recovery $M = C^e \pmod n$.

---

## Command Line Usage (CLI)

### 1. Python CLI (`rsa_tool.py`)

#### Generate RSA Keypair:
```bash
python rsa_tool.py gen-keys --size 2048 --out-dir ./keys
```

#### Encrypt with Private Key:
```bash
# Output as Base64 (default)
python rsa_tool.py encrypt -k ./keys/private_key.pem -i "Secret message"

# Or encrypt a file and save ciphertext to file
python rsa_tool.py encrypt -k ./keys/private_key.pem -f message.txt -o cipher.b64
```

#### Decrypt with Public Key:
```bash
# Decrypt Base64 ciphertext
python rsa_tool.py decrypt -k ./keys/public_key.pem -i "<base64_ciphertext>"

# Or decrypt from file
python rsa_tool.py decrypt -k ./keys/public_key.pem -f cipher.b64
```

#### Run Built-in Self Test:
```bash
python rsa_tool.py test
```

#### Generate 64-Character Alphanumeric Password & PHP Bcrypt Hash:
```bash
# Generate 64-character password + $2y$ Bcrypt hash
python rsa_tool.py password

# Custom length or cost factor:
python rsa_tool.py password --length 64 --cost 10

# Output as JSON:
python rsa_tool.py password --json

# Verify a password against a hash:
python rsa_tool.py password -p "<password>" --verify "<bcrypt_hash>"
```

#### JWT Encode, Sign & Verify:
```bash
# Sign JWT using RSA Private Key (RS256) with auto-generated iat & exp (1 hour)
python rsa_tool.py jwt-sign --alg RS256 -k ./keys/private_key.pem -p '{"sub":"usr_123","role":"admin"}' --add-timestamps

# Sign JWT with custom expiration (e.g. 24 hours = 86400 seconds)
python rsa_tool.py jwt-sign --alg HS256 -k "my-secret-key-1234567890" -p '{"sub":"usr_123"}' --expires-in 86400

# Verify JWT using RSA Public Key (RS256)
python rsa_tool.py jwt-verify -t "<jwt_token>" -k ./keys/public_key.pem

# Verify JWT using HMAC secret (HS256)
python rsa_tool.py jwt-verify -t "<jwt_token>" -k "my-secret-key-1234567890"

# Decode claims without key (unverified)
python rsa_tool.py jwt-verify -t "<jwt_token>"

# Output verification results as JSON
python rsa_tool.py jwt-verify -t "<jwt_token>" -k ./keys/public_key.pem --json
```

---

### 2. Node.js CLI (`rsa_tool.js`)

```bash
# Generate keys
node rsa_tool.js gen-keys --size 2048 --out-dir ./keys

# Encrypt with Private Key
node rsa_tool.js encrypt -k ./keys/private_key.pem -i "Secret message"

# Decrypt with Public Key
node rsa_tool.js decrypt -k ./keys/public_key.pem -i "<base64_ciphertext>"

# Generate 64-char password & PHP Bcrypt hash
node rsa_tool.js password
```

---

### 3. Password Generation & PHP `PASSWORD_BCRYPT` Compatibility

Module: `password_tool.py`

* **Password Generation**: Produces random 64-character alphanumeric passwords (`[a-zA-Z0-9]`) using cryptographically secure random number generators (`secrets` module / CSPRNG) with ~381 bits of entropy.
* **PHP `PASSWORD_BCRYPT` Hash**: Generates 60-character bcrypt hashes using `$2y$` prefix (or `$2b$`) with configurable cost (default: 10), matching PHP's native:
  ```php
  $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 10]);
  $isValid = password_verify($password, $hash); // Returns true
  ```
* **Python Usage**:
  ```python
  import password_tool

  # 1. Generate 64-char password
  password = password_tool.generate_password(64)

  # 2. Hash using PHP PASSWORD_BCRYPT logic
  hashed = password_tool.hash_password(password, cost=10, prefix="2y")

  # 3. Verify
  is_valid = password_tool.verify_password(password, hashed)
  ```

## Cross-Language Compatibility

Ciphertext produced by this tool is 100% interoperable across standard cryptography runtimes:

### Node.js
```javascript
const crypto = require('crypto');
const fs = require('fs');

const privateKey = fs.readFileSync('private_key.pem', 'utf8');
const publicKey = fs.readFileSync('public_key.pem', 'utf8');

// Encrypt with Private Key (PKCS#1 v1.5)
const cipher = crypto.privateEncrypt({
  key: privateKey,
  padding: crypto.constants.RSA_PKCS1_PADDING
}, Buffer.from('Hello World'));

// Decrypt with Public Key (PKCS#1 v1.5)
const plain = crypto.publicDecrypt({
  key: publicKey,
  padding: crypto.constants.RSA_PKCS1_PADDING
}, cipher);

console.log(plain.toString()); // "Hello World"
```

### Java (Standard SunJCE)
```java
import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.nio.charset.StandardCharsets;

Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

// Encrypt with PrivateKey
cipher.init(Cipher.ENCRYPT_MODE, privateKey);
byte[] ciphertext = cipher.doFinal("Hello World".getBytes(StandardCharsets.UTF_8));

// Decrypt with PublicKey
cipher.init(Cipher.DECRYPT_MODE, publicKey);
byte[] plaintext = cipher.doFinal(ciphertext);

System.out.println(new String(plaintext, StandardCharsets.UTF_8)); // "Hello World"
```

### Python API

#### RSA Private Encryption & Public Decryption
```python
import rsa_crypto

priv = rsa_crypto.load_private_key(open("keys/private_key.pem").read())
pub = rsa_crypto.load_public_key(open("keys/public_key.pem").read())

# Encrypt with Private Key
ciphertext = rsa_crypto.encrypt_private(b"Hello World", priv, block_type=1)

# Decrypt with Public Key
plaintext = rsa_crypto.decrypt_public(ciphertext, pub)
print(plaintext.decode("utf-8")) # "Hello World"
```

#### JWT Encode, Sign & Verify
```python
import jwt_tool

# Asymmetric Signing with RSA (RS256)
token = jwt_tool.encode_jwt(
    payload={"sub": "user_42", "name": "Alice", "role": "admin"},
    key=open("keys/private_key.pem").read(),
    algorithm="RS256"
)

# Verification with RSA Public Key
result = jwt_tool.decode_jwt(token, key=open("keys/public_key.pem").read())
print(result["valid"])    # True
print(result["payload"])  # {'sub': 'user_42', 'name': 'Alice', 'role': 'admin'}

# Symmetric Signing with HMAC (HS256)
secret = "my-super-secret-key-1234567890"
token_hmac = jwt_tool.encode_jwt({"sub": "user_42"}, key=secret, algorithm="HS256")
res_hmac = jwt_tool.decode_jwt(token_hmac, key=secret)
print(res_hmac["valid"])  # True
```

---

## Cryptographic Design Notes

- **Mathematical Foundations**:
  - RSA modular exponentiation is fundamentally symmetric:
    $$\left(M^d\right)^e \equiv M \pmod n \quad \text{and} \quad \left(M^e\right)^d \equiv M \pmod n$$
  - When encrypting with a private key, the system pads message $D$ into an encryption block $EB$ of length $k = \lceil \text{modulus bits} / 8 \rceil$, then computes $C = (EB)^d \pmod n$.
  - When decrypting with a public key, the system computes $EB = (C)^e \pmod n$, validates the padding bytes, and strips the prefix to extract $D$.
- **PKCS#1 v1.5 Format**:
  $$EB = 0x00 \mathbin{\Vert} BT \mathbin{\Vert} PS \mathbin{\Vert} 0x00 \mathbin{\Vert} D$$
  - **Block Type 1 (`BT = 0x01`)**: $PS$ is filled with octets of value `0xFF` (at least 8 bytes). Standard across OpenSSL, Node.js `crypto.privateEncrypt`, and Java.
  - **Block Type 2 (`BT = 0x02`)**: $PS$ is filled with pseudo-random non-zero octets.
- **Payload Capacity**:
  - For a 2048-bit key ($k = 256$ bytes), maximum single-block payload is $256 - 11 = 245$ bytes.
  - In multi-block (chunked) mode, payloads of any size are automatically partitioned, encrypted in blocks of 256 bytes, and concatenated.

---

## Automated Verification Tests

Run the full test suite (20 tests covering RSA, Bcrypt & JWT):
```bash
python -m unittest discover
```
Output:
```
Ran 20 tests in 1.066s
OK
```
Test modules:
- `test_rsa_crypto.py`: Key generation, PKCS#1 v1.5 Block Type 1 & 2, chunking, Node.js `crypto` interop.
- `test_password_tool.py`: 64-char randomness & entropy, PHP `PASSWORD_BCRYPT` compatibility, cost factors.
- `test_jwt_tool.py`: RFC 7519 compliance, RS256/384/512, PS256/384/512, HS256/384/512, `none`, invalid signature rejection, token expiration detection, cross-validation with Node.js `crypto`.

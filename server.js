/**
 * Lightweight Node.js Web Server & API for RSA Private Encrypt / Public Decrypt Tool.
 * Zero npm dependencies required.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');

const PORT = parseInt(process.env.PORT || '5000', 10);
const HOST = process.env.HOST || '127.0.0.1';
const WEB_DIR = path.join(__dirname, 'web');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon'
};

function sendJson(res, statusCode, data) {
  const body = Buffer.from(JSON.stringify(data));
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  const urlPath = req.url.split('?')[0];

  // API Endpoints
  if (req.method === 'POST') {
    let body = [];
    req.on('data', chunk => body.push(chunk));
    req.on('end', () => {
      let data = {};
      try {
        if (body.length > 0) {
          data = JSON.parse(Buffer.concat(body).toString());
        }
      } catch (err) {
        return sendJson(res, 400, { success: false, error: 'Invalid JSON payload' });
      }

      try {
        if (urlPath === '/api/generate-keys') {
          const size = parseInt(data.size || '2048', 10);
          const pkcs8 = data.pkcs8 !== false;
          const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: size,
            publicKeyEncoding: { type: pkcs8 ? 'spki' : 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: pkcs8 ? 'pkcs8' : 'pkcs1', format: 'pem' }
          });
          return sendJson(res, 200, {
            success: true,
            key_size: size,
            private_key: privateKey,
            public_key: publicKey
          });
        }

        if (urlPath === '/api/validate-key') {
          const keyText = (data.key || '').trim();
          if (!keyText) return sendJson(res, 400, { success: false, error: 'Empty key' });

          if (keyText.includes('PRIVATE KEY')) {
            const keyObj = crypto.createPrivateKey(keyText);
            return sendJson(res, 200, {
              success: true,
              type: 'private',
              size: keyObj.asymmetricKeyDetails.modulusLength,
              format: keyText.includes('BEGIN PRIVATE KEY') ? 'PKCS#8' : 'PKCS#1'
            });
          } else if (keyText.includes('PUBLIC KEY')) {
            const keyObj = crypto.createPublicKey(keyText);
            return sendJson(res, 200, {
              success: true,
              type: 'public',
              size: keyObj.asymmetricKeyDetails.modulusLength,
              format: keyText.includes('BEGIN PUBLIC KEY') ? 'SPKI (PKCS#8)' : 'PKCS#1'
            });
          }
          return sendJson(res, 400, { success: false, error: 'Invalid PEM header' });
        }

        if (urlPath === '/api/encrypt') {
          const key = (data.key || '').trim();
          const inFormat = data.in_format || 'text';
          const mode = data.mode || 'private'; // 'private' or 'public'
          const chunk = data.chunk !== false;
          let buf;

          if (inFormat === 'text') buf = Buffer.from(data.data || '', 'utf8');
          else if (inFormat === 'base64') buf = Buffer.from(data.data || '', 'base64');
          else if (inFormat === 'hex') buf = Buffer.from((data.data || '').replace(/\s+/g, ''), 'hex');
          else throw new Error('Invalid in_format');

          const keyObj = (mode === 'public') ? crypto.createPublicKey(key) : crypto.createPrivateKey(key);
          const k = keyObj.asymmetricKeyDetails.modulusLength / 8;
          const maxPayload = k - 11;
          const encFn = (m) => (mode === 'public')
            ? crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, m)
            : crypto.privateEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, m);

          let ciphertext;
          if (!chunk) {
            if (buf.length > maxPayload) throw new Error(`Payload exceeds single-block size (${maxPayload} bytes)`);
            ciphertext = encFn(buf);
          } else {
            const chunks = [];
            if (buf.length === 0) {
              chunks.push(encFn(Buffer.alloc(0)));
            } else {
              for (let i = 0; i < buf.length; i += maxPayload) {
                const slice = buf.subarray(i, i + maxPayload);
                chunks.push(encFn(slice));
              }
            }
            ciphertext = Buffer.concat(chunks);
          }

          return sendJson(res, 200, {
            success: true,
            base64: ciphertext.toString('base64'),
            hex: ciphertext.toString('hex'),
            total_bytes: ciphertext.length,
            blocks: ciphertext.length / k
          });
        }

        if (urlPath === '/api/decrypt') {
          const key = (data.key || '').trim();
          const inFormat = data.in_format || 'base64';
          const mode = data.mode || 'public'; // 'public' or 'private'
          let cipherBuf;

          if (inFormat === 'base64') cipherBuf = Buffer.from(data.data || '', 'base64');
          else if (inFormat === 'hex') cipherBuf = Buffer.from((data.data || '').replace(/\s+/g, ''), 'hex');
          else throw new Error('Invalid in_format');

          const keyObj = (mode === 'private') ? crypto.createPrivateKey(key) : crypto.createPublicKey(key);
          const k = keyObj.asymmetricKeyDetails.modulusLength / 8;

          if (cipherBuf.length % k !== 0) {
            throw new Error(`Ciphertext length (${cipherBuf.length}) is not a multiple of RSA key size (${k} bytes).`);
          }

          const decFn = (b) => (mode === 'private')
            ? crypto.privateDecrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, b)
            : crypto.publicDecrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, b);

          const decChunks = [];
          for (let i = 0; i < cipherBuf.length; i += k) {
            const block = cipherBuf.subarray(i, i + k);
            decChunks.push(decFn(block));
          }
          const plainBuf = Buffer.concat(decChunks);

          return sendJson(res, 200, {
            success: true,
            text: plainBuf.toString('utf8'),
            is_utf8: true,
            base64: plainBuf.toString('base64'),
            hex: plainBuf.toString('hex'),
            total_bytes: plainBuf.length
          });
        }

        if (urlPath === '/api/generate-password') {
          const len = parseInt(data.length || '64', 10);
          const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
          let pwd = '';
          const randomBytes = crypto.randomBytes(len);
          for (let i = 0; i < len; i++) {
            pwd += chars[randomBytes[i] % chars.length];
          }
          return sendJson(res, 200, { success: true, password: pwd, length: pwd.length });
        }

        if (urlPath === '/api/generate-and-hash') {
          const { execSync } = require('child_process');
          const len = parseInt(data.length || '64', 10);
          const cost = parseInt(data.cost || '10', 10);
          const prefix = data.prefix || '2y';
          const out = execSync(`python -c "import password_tool, json; print(json.dumps(password_tool.generate_and_hash(${len}, ${cost}, '${prefix}')))"`, { encoding: 'utf8' });
          const parsed = JSON.parse(out.trim());
          parsed.success = true;
          return sendJson(res, 200, parsed);
        }

        if (urlPath === '/api/hash-password') {
          const { execSync } = require('child_process');
          const pwdEsc = JSON.stringify(data.password || '');
          const cost = parseInt(data.cost || '10', 10);
          const prefix = data.prefix || '2y';
          const out = execSync(`python -c "import password_tool, json; print(json.dumps({'hash': password_tool.hash_password(${pwdEsc}, ${cost}, '${prefix}')}))"`, { encoding: 'utf8' });
          const parsed = JSON.parse(out.trim());
          return sendJson(res, 200, { success: true, hash: parsed.hash, cost, prefix });
        }

        if (urlPath === '/api/verify-password') {
          const { execSync } = require('child_process');
          const pwdEsc = JSON.stringify(data.password || '');
          const hashEsc = JSON.stringify(data.hash || '');
          const out = execSync(`python -c "import password_tool, json; print(json.dumps({'valid': password_tool.verify_password(${pwdEsc}, ${hashEsc})}))"`, { encoding: 'utf8' });
          const parsed = JSON.parse(out.trim());
          return sendJson(res, 200, { success: true, valid: parsed.valid });
        }

        if (urlPath === '/api/jwt/encode') {
          const { execSync } = require('child_process');
          const payloadEsc = JSON.stringify(JSON.stringify(data.payload || {}));
          const keyEsc = JSON.stringify(data.key || '');
          const algEsc = JSON.stringify(data.algorithm || 'RS256');
          const headersEsc = JSON.stringify(data.headers ? JSON.stringify(data.headers) : 'null');
          const pyCmd = `python -c "import jwt_tool, json; print(json.dumps({'token': jwt_tool.encode_jwt(json.loads(${payloadEsc}), ${keyEsc} or None, ${algEsc}, json.loads(${headersEsc}) if ${headersEsc} != 'null' else None)}))"`;
          const out = execSync(pyCmd, { encoding: 'utf8' });
          const parsed = JSON.parse(out.trim());
          return sendJson(res, 200, { success: true, token: parsed.token, algorithm: data.algorithm || 'RS256' });
        }

        if (urlPath === '/api/jwt/decode') {
          const { execSync } = require('child_process');
          const tokenEsc = JSON.stringify(data.token || '');
          const keyEsc = JSON.stringify(data.key || '');
          const verifyEsc = data.verify !== false ? 'True' : 'False';
          const pyCmd = `python -c "import jwt_tool, json; print(json.dumps(jwt_tool.decode_jwt(${tokenEsc}, ${keyEsc} or None, verify=${verifyEsc})))"`;
          const out = execSync(pyCmd, { encoding: 'utf8' });
          const parsed = JSON.parse(out.trim());
          parsed.success = true;
          return sendJson(res, 200, parsed);
        }

        sendJson(res, 404, { success: false, error: 'Endpoint not found' });
      } catch (err) {
        sendJson(res, 400, { success: false, error: err.message });
      }
    });
    return;
  }

  // Static File Serving
  let filePath = path.join(WEB_DIR, urlPath === '/' ? 'index.html' : urlPath);
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(WEB_DIR, 'index.html');
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(500);
      res.end('Server error');
      return;
    }
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    res.end(content);
  });
});

server.listen(PORT, HOST, () => {
  const url = `http://${HOST}:${PORT}`;
  console.log(`=======================================================`);
  console.log(` RSA Private Encrypt / Public Decrypt Web UI`);
  console.log(` Running at: ${url}`);
  console.log(`=======================================================`);

  // Open default browser on Windows
  if (process.platform === 'win32') {
    exec(`start ${url}`);
  }
});

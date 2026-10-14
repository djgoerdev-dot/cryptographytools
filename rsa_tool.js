#!/usr/bin/env node
/**
 * Node.js CLI for RSA Private Key Encryption & Public Key Decryption (PKCS#1 v1.5)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function parseArgs() {
  const args = process.argv.slice(2);
  const command = args[0];
  const options = {};
  
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith('-')) {
        options[key] = next;
        i++;
      } else {
        options[key] = true;
      }
    } else if (arg.startsWith('-')) {
      const key = arg.slice(1);
      const next = args[i + 1];
      if (next && !next.startsWith('-')) {
        options[key] = next;
        i++;
      } else {
        options[key] = true;
      }
    }
  }
  return { command, options };
}

function readKey(keyArg) {
  if (!keyArg) throw new Error('Key argument is required (-k or --key)');
  if (fs.existsSync(keyArg)) {
    return fs.readFileSync(keyArg, 'utf8');
  }
  return keyArg;
}

function readInput(options, defaultFormat = 'text') {
  let raw;
  if (options.file || options.f) {
    const filePath = options.file || options.f;
    raw = fs.readFileSync(filePath);
  } else if (options.input !== undefined || options.i !== undefined) {
    raw = Buffer.from(options.input || options.i, 'utf8');
  } else {
    try {
      raw = fs.readFileSync(0); // read from stdin
    } catch {
      throw new Error('No input provided. Use -i/--input, -f/--file, or pipe via stdin.');
    }
  }

  const inFormat = options['in-format'] || defaultFormat;
  if (inFormat === 'base64') {
    return Buffer.from(raw.toString('utf8').trim(), 'base64');
  } else if (inFormat === 'hex') {
    return Buffer.from(raw.toString('utf8').trim().replace(/\s+/g, ''), 'hex');
  }
  return raw;
}

function outputData(buf, options, defaultFormat = 'base64') {
  const outFormat = options['out-format'] || defaultFormat;
  let res;
  if (outFormat === 'base64') {
    res = buf.toString('base64');
  } else if (outFormat === 'hex') {
    res = buf.toString('hex');
  } else if (outFormat === 'text') {
    res = buf.toString('utf8');
  } else {
    res = buf;
  }

  const outFile = options['out-file'] || options.o;
  if (outFile) {
    fs.writeFileSync(outFile, res);
    console.error(`Output written to: ${outFile}`);
  } else {
    if (Buffer.isBuffer(res) && outFormat === 'raw') {
      process.stdout.write(res);
    } else {
      console.log(res.toString());
    }
  }
}

function cmdGenKeys(options) {
  const size = parseInt(options.size || '2048', 10);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: size,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  if (options['out-dir']) {
    fs.mkdirSync(options['out-dir'], { recursive: true });
    fs.writeFileSync(path.join(options['out-dir'], 'private_key.pem'), privateKey);
    fs.writeFileSync(path.join(options['out-dir'], 'public_key.pem'), publicKey);
    console.log(`Generated ${size}-bit RSA keypair in ${options['out-dir']}:`);
    console.log(`  Private Key: ${path.join(options['out-dir'], 'private_key.pem')}`);
    console.log(`  Public Key:  ${path.join(options['out-dir'], 'public_key.pem')}`);
  } else {
    console.log('=== RSA PRIVATE KEY ===\n' + privateKey);
    console.log('=== RSA PUBLIC KEY ===\n' + publicKey);
  }
}

function cmdEncrypt(options) {
  const key = readKey(options.key || options.k);
  const input = readInput(options, 'text');
  
  // Calculate key size
  const keyObj = crypto.createPrivateKey(key);
  const keyModulusBytes = keyObj.asymmetricKeyDetails.modulusLength / 8;
  const maxPayload = keyModulusBytes - 11;

  let ciphertext;
  if (options['no-chunk']) {
    ciphertext = crypto.privateEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, input);
  } else {
    // Multi-block chunking
    const chunks = [];
    for (let i = 0; i < input.length; i += maxPayload) {
      const piece = input.subarray(i, i + maxPayload);
      const encPiece = crypto.privateEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, piece);
      chunks.push(encPiece);
    }
    ciphertext = Buffer.concat(chunks);
  }

  outputData(ciphertext, options, 'base64');
}

function cmdDecrypt(options) {
  const key = readKey(options.key || options.k);
  const input = readInput(options, 'base64');

  const keyObj = crypto.createPublicKey(key);
  const keyModulusBytes = keyObj.asymmetricKeyDetails.modulusLength / 8;

  if (input.length % keyModulusBytes !== 0) {
    throw new Error(`Ciphertext length (${input.length} bytes) is not a multiple of RSA key size (${keyModulusBytes} bytes).`);
  }

  const recovered = [];
  for (let i = 0; i < input.length; i += keyModulusBytes) {
    const block = input.subarray(i, i + keyModulusBytes);
    const dec = crypto.publicDecrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, block);
    recovered.push(dec);
  }

  const plaintext = Buffer.concat(recovered);
  outputData(plaintext, options, 'text');
}

function cmdPassword(options) {
  const { execSync } = require('child_process');
  const len = parseInt(options.length || options.l || '64', 10);
  const cost = parseInt(options.cost || options.c || '10', 10);
  const prefix = options.prefix || '2y';
  const out = execSync(`python -c "import password_tool, json; print(json.dumps(password_tool.generate_and_hash(${len}, ${cost}, '${prefix}')))"`, { encoding: 'utf8' });
  const parsed = JSON.parse(out.trim());

  if (options.json) {
    console.log(JSON.stringify(parsed, null, 2));
  } else {
    console.log(`=== Generated Alphanumeric Password ===`);
    console.log(`Password (${parsed.length} chars): ${parsed.password}`);
    console.log(`\n=== PHP PASSWORD_BCRYPT Hash ===`);
    console.log(`Hash (${parsed.hash.length} chars): ${parsed.hash}`);
    console.log(`\nCost factor: ${parsed.cost} | Prefix: $${parsed.prefix}$ | Equivalent to: password_hash($password, PASSWORD_BCRYPT, ['cost' => ${parsed.cost}])`);
  }
}

function main() {
  const { command, options } = parseArgs();

  if (!command || command === 'help' || options.help || options.h) {
    console.log(`
RSA Private Key Encrypt & Public Key Decrypt CLI Tool (PKCS#1 v1.5)

Usage:
  node rsa_tool.js <command> [options]

Commands:
  gen-keys    Generate an RSA key pair
              Options: --size (1024, 2048, 4096), --out-dir <directory>

  encrypt     Encrypt with RSA Private Key
              Options: -k, --key <file|pem> (required)
                       -i, --input <string> or -f, --file <path>
                       --in-format <text|hex|base64> (default: text)
                       --out-format <base64|hex|raw> (default: base64)
                       -o, --out-file <path>
                       --no-chunk (force single block)

  decrypt     Decrypt with RSA Public Key
              Options: -k, --key <file|pem> (required)
                       -i, --input <string> or -f, --file <path>
                       --in-format <base64|hex|raw> (default: base64)
                       --out-format <text|hex|base64|raw> (default: text)
                       -o, --out-file <path>

  password    Generate 64-char random alphanumeric password & PHP PASSWORD_BCRYPT hash
              Options: -l, --length (default: 64)
                       -c, --cost (default: 10)
                       --prefix (default: 2y)
                       --json
    `);
    process.exit(0);
  }

  try {
    if (command === 'gen-keys') cmdGenKeys(options);
    else if (command === 'encrypt') cmdEncrypt(options);
    else if (command === 'decrypt') cmdDecrypt(options);
    else if (command === 'password' || command === 'pwd') cmdPassword(options);
    else throw new Error(`Unknown command: ${command}`);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main();

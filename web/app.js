// RSA Private Encrypt & Public Decrypt Application Logic
// Supports both:
// 1. Private Encrypt ➔ Public Decrypt (Origin Proof / Digital Signature)
// 2. Public Encrypt ➔ Private Decrypt (Standard Confidentiality)

let activeKeypair = {
  privateKey: '',
  publicKey: ''
};

let lastEncryptedCiphertext = {
  base64: '',
  hex: '',
  bytes: 0,
  blocks: 0
};

let lastDecryptedPlaintext = {
  text: '',
  hex: '',
  base64: '',
  bytes: 0
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupThemeToggle();
  setupWorkflowSwitcher();
  setupKeyManager();
  setupEncryptionTab();
  setupDecryptionTab();
  setupVisualizer();
  setupQuickDemo();
  setupJwtTab();

  // Auto-generate fresh 2048-bit keypair on initial load
  generateKeys(2048, true).catch(() => {
    console.log('Backend ready.');
  });
});

// Toast notification helper
function showToast(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.remove('hidden');
  setTimeout(() => {
    toast.classList.add('hidden');
  }, 2500);
}

// Navigation Tabs
function setupNavigation() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetId = tab.getAttribute('data-tab');
      document.getElementById(targetId).classList.add('active');
    });
  });
}

function switchTab(tabId) {
  const tabBtn = document.querySelector(`.nav-tab[data-tab="${tabId}"]`);
  if (tabBtn) tabBtn.click();
}

// Theme Toggle
function setupThemeToggle() {
  const btn = document.getElementById('btnThemeToggle');
  btn.addEventListener('click', () => {
    if (document.body.classList.contains('dark-theme')) {
      document.body.classList.remove('dark-theme');
      document.body.classList.add('light-theme');
    } else {
      document.body.classList.remove('light-theme');
      document.body.classList.add('dark-theme');
    }
  });
}

// Workflow Mode Quick Switcher
function setupWorkflowSwitcher() {
  const btnOrigin = document.getElementById('btnModePrivateOrigin');
  const btnStandard = document.getElementById('btnModePublicStandard');

  btnOrigin.addEventListener('click', () => {
    btnOrigin.classList.add('active');
    btnStandard.classList.remove('active');
    setWorkflowMode('private-origin');
    showToast('Workflow: Private Encrypt ➔ Public Decrypt (Origin / Signature)');
  });

  btnStandard.addEventListener('click', () => {
    btnStandard.classList.add('active');
    btnOrigin.classList.remove('active');
    setWorkflowMode('public-standard');
    showToast('Workflow: Public Encrypt ➔ Private Decrypt (Standard)');
  });
}

function setWorkflowMode(mode) {
  if (mode === 'private-origin') {
    // Encrypt with Private, Decrypt with Public
    const encPrivateRadio = document.querySelector('input[name="encKeyMode"][value="private"]');
    if (encPrivateRadio) {
      encPrivateRadio.checked = true;
      encPrivateRadio.dispatchEvent(new Event('change'));
    }
    const decPublicRadio = document.querySelector('input[name="decKeyMode"][value="public"]');
    if (decPublicRadio) {
      decPublicRadio.checked = true;
      decPublicRadio.dispatchEvent(new Event('change'));
    }
  } else if (mode === 'public-standard') {
    // Encrypt with Public, Decrypt with Private
    const encPublicRadio = document.querySelector('input[name="encKeyMode"][value="public"]');
    if (encPublicRadio) {
      encPublicRadio.checked = true;
      encPublicRadio.dispatchEvent(new Event('change'));
    }
    const decPrivateRadio = document.querySelector('input[name="decKeyMode"][value="private"]');
    if (decPrivateRadio) {
      decPrivateRadio.checked = true;
      decPrivateRadio.dispatchEvent(new Event('change'));
    }
  }
}

// API Helper
async function callApi(endpoint, data) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });

  const resJson = await response.json();
  if (!resJson.success) {
    throw new Error(resJson.error || 'Request failed');
  }
  return resJson;
}

// Key Generator & Manager
function setupKeyManager() {
  const btnGen = document.getElementById('btnGenerateNewKeys');
  const btnGenHeader = document.getElementById('btnGenKeyHeader');
  const btnApply = document.getElementById('btnApplyKeysToTabs');
  const sizeSelect = document.getElementById('keySizeSelect');
  const formatSelect = document.getElementById('keyFormatSelect');

  const privArea = document.getElementById('mgrPrivateKey');
  const pubArea = document.getElementById('mgrPublicKey');

  const handleGen = async () => {
    const size = parseInt(sizeSelect.value, 10);
    const pkcs8 = formatSelect.value === 'pkcs8';
    btnGen.textContent = 'Generating...';
    btnGen.disabled = true;

    try {
      const res = await callApi('/api/generate-keys', { size, pkcs8 });
      privArea.value = res.private_key;
      pubArea.value = res.public_key;
      activeKeypair.privateKey = res.private_key;
      activeKeypair.publicKey = res.public_key;
      applyKeysToCurrentInputs();
      showToast(`Generated ${size}-bit RSA keypair!`);
    } catch (err) {
      alert(`Key generation failed: ${err.message}`);
    } finally {
      btnGen.textContent = '⚡ Generate New Keypair';
      btnGen.disabled = false;
    }
  };

  btnGen.addEventListener('click', handleGen);
  btnGenHeader.addEventListener('click', () => {
    switchTab('tab-keys');
    handleGen();
  });

  btnApply.addEventListener('click', () => {
    const priv = privArea.value.trim();
    const pub = pubArea.value.trim();
    if (!priv || !pub) {
      alert('Please generate or paste keys first.');
      return;
    }
    activeKeypair.privateKey = priv;
    activeKeypair.publicKey = pub;
    applyKeysToCurrentInputs();
    showToast('Keys loaded into Encrypt and Decrypt tabs!');
  });

  document.getElementById('btnCopyPrivKey').addEventListener('click', () => {
    navigator.clipboard.writeText(privArea.value);
    showToast('Private key copied to clipboard');
  });

  document.getElementById('btnCopyPubKey').addEventListener('click', () => {
    navigator.clipboard.writeText(pubArea.value);
    showToast('Public key copied to clipboard');
  });

  document.getElementById('btnDownloadPrivKey').addEventListener('click', () => {
    downloadFile('private_key.pem', privArea.value);
  });

  document.getElementById('btnDownloadPubKey').addEventListener('click', () => {
    downloadFile('public_key.pem', pubArea.value);
  });
}

function applyKeysToCurrentInputs() {
  const encKeyMode = document.querySelector('input[name="encKeyMode"]:checked')?.value || 'private';
  const decKeyMode = document.querySelector('input[name="decKeyMode"]:checked')?.value || 'public';

  const encKeyElem = document.getElementById('encPrivateKey');
  const decKeyElem = document.getElementById('decKey');

  if (encKeyElem) {
    encKeyElem.value = (encKeyMode === 'private') ? activeKeypair.privateKey : activeKeypair.publicKey;
    validateKeyInput('encPrivateKey', 'encKeyBadge');
  }

  if (decKeyElem) {
    decKeyElem.value = (decKeyMode === 'public') ? activeKeypair.publicKey : activeKeypair.privateKey;
    validateKeyInput('decKey', 'decKeyBadge');
  }
}

async function generateKeys(size = 2048, pkcs8 = true) {
  const res = await callApi('/api/generate-keys', { size, pkcs8 });
  document.getElementById('mgrPrivateKey').value = res.private_key;
  document.getElementById('mgrPublicKey').value = res.public_key;
  activeKeypair.privateKey = res.private_key;
  activeKeypair.publicKey = res.public_key;

  applyKeysToCurrentInputs();
  return res;
}

// Encryption Tab
function setupEncryptionTab() {
  const keyInput = document.getElementById('encPrivateKey');
  const plainInput = document.getElementById('encPlaintext');
  const btnEncrypt = document.getElementById('btnExecuteEncrypt');
  const btnSample = document.getElementById('btnSampleEncrypt');
  const encKeyFile = document.getElementById('encKeyFile');
  const encDataFile = document.getElementById('encDataFile');

  const cipherOutput = document.getElementById('encCiphertextOutput');
  const outputStats = document.getElementById('encOutputStats');
  const inputStats = document.getElementById('encInputStats');

  // Handle Encrypt Key Mode Radios (Private vs Public)
  const encRadios = document.querySelectorAll('input[name="encKeyMode"]');
  encRadios.forEach(radio => {
    radio.addEventListener('change', () => {
      const mode = radio.value;
      const lblPriv = document.getElementById('lblEncPrivate');
      const lblPub = document.getElementById('lblEncPublic');

      if (mode === 'private') {
        lblPriv.classList.add('active');
        lblPub.classList.remove('active');
        document.querySelector('label[for="encPrivateKey"]').textContent = 'RSA Private Key (PEM)';
        keyInput.placeholder = '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----';
        btnEncrypt.textContent = '🔒 Encrypt with Private Key';
        document.getElementById('encBlockType').value = '1';
        if (activeKeypair.privateKey) keyInput.value = activeKeypair.privateKey;
      } else {
        lblPub.classList.add('active');
        lblPriv.classList.remove('active');
        document.querySelector('label[for="encPrivateKey"]').textContent = 'RSA Public Key (PEM)';
        keyInput.placeholder = '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----';
        btnEncrypt.textContent = '🔒 Encrypt with Public Key';
        document.getElementById('encBlockType').value = '2';
        if (activeKeypair.publicKey) keyInput.value = activeKeypair.publicKey;
      }
      validateKeyInput('encPrivateKey', 'encKeyBadge');
    });
  });

  keyInput.addEventListener('input', () => validateKeyInput('encPrivateKey', 'encKeyBadge'));

  plainInput.addEventListener('input', () => {
    const text = plainInput.value;
    const bytes = new TextEncoder().encode(text).length;
    inputStats.textContent = `${text.length} characters • ${bytes} bytes`;
  });

  encKeyFile.addEventListener('change', (e) => {
    readFile(e.target.files[0], (content) => {
      keyInput.value = content;
      validateKeyInput('encPrivateKey', 'encKeyBadge');
    });
  });

  encDataFile.addEventListener('change', (e) => {
    readFile(e.target.files[0], (content) => {
      plainInput.value = content;
      plainInput.dispatchEvent(new Event('input'));
    });
  });

  btnSample.addEventListener('click', async () => {
    const mode = document.querySelector('input[name="encKeyMode"]:checked').value;
    if (!keyInput.value.trim()) {
      if (!activeKeypair.privateKey) await generateKeys(2048, true);
      keyInput.value = (mode === 'private') ? activeKeypair.privateKey : activeKeypair.publicKey;
    }
    plainInput.value = `Test message: RSA encryption using ${mode} key! Random token: ` + Math.random().toString(36).substring(2);
    plainInput.dispatchEvent(new Event('input'));
    validateKeyInput('encPrivateKey', 'encKeyBadge');
    showToast(`Loaded sample input for ${mode} key encryption`);
  });

  btnEncrypt.addEventListener('click', async () => {
    const key = keyInput.value.trim();
    const data = plainInput.value;
    const mode = document.querySelector('input[name="encKeyMode"]:checked').value;
    if (!key) return alert(`Please enter or generate an RSA ${mode === 'private' ? 'Private' : 'Public'} Key.`);
    if (!data) return alert('Please enter data to encrypt.');

    const inFormat = document.querySelector('input[name="encInFormat"]:checked').value;
    const blockType = parseInt(document.getElementById('encBlockType').value, 10);
    const chunk = document.getElementById('encChunking').value === 'true';

    btnEncrypt.textContent = 'Encrypting...';
    btnEncrypt.disabled = true;

    try {
      const res = await callApi('/api/encrypt', {
        key,
        data,
        in_format: inFormat,
        block_type: blockType,
        chunk,
        mode
      });

      lastEncryptedCiphertext = {
        base64: res.base64,
        hex: res.hex,
        bytes: res.total_bytes,
        blocks: res.blocks
      };

      const activeFormat = document.querySelector('.subtab-btn.active').getAttribute('data-format');
      cipherOutput.value = lastEncryptedCiphertext[activeFormat];
      outputStats.textContent = `${res.total_bytes} bytes • ${res.blocks} block(s)`;
      showToast('Encryption successful!');
    } catch (err) {
      alert(`Encryption Error: ${err.message}`);
    } finally {
      btnEncrypt.textContent = (mode === 'private') ? '🔒 Encrypt with Private Key' : '🔒 Encrypt with Public Key';
      btnEncrypt.disabled = false;
    }
  });

  // Output format toggle (Base64 vs Hex)
  document.querySelectorAll('.subtab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.subtab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const fmt = btn.getAttribute('data-format');
      if (lastEncryptedCiphertext[fmt]) {
        cipherOutput.value = lastEncryptedCiphertext[fmt];
      }
    });
  });

  document.getElementById('btnCopyCiphertext').addEventListener('click', () => {
    if (!cipherOutput.value) return;
    navigator.clipboard.writeText(cipherOutput.value);
    showToast('Ciphertext copied to clipboard');
  });

  document.getElementById('btnDownloadCiphertext').addEventListener('click', () => {
    if (!cipherOutput.value) return;
    const fmt = document.querySelector('.subtab-btn.active').getAttribute('data-format');
    downloadFile(`ciphertext_${fmt}.txt`, cipherOutput.value);
  });

  document.getElementById('btnSendToDecrypt').addEventListener('click', () => {
    if (!lastEncryptedCiphertext.base64) {
      return alert('Encrypt some data first.');
    }
    const encMode = document.querySelector('input[name="encKeyMode"]:checked').value;
    
    // Set Decrypt tab values
    document.getElementById('decCiphertext').value = lastEncryptedCiphertext.base64;
    document.querySelector('input[name="decInFormat"][value="base64"]').checked = true;

    if (encMode === 'private') {
      // If encrypted with Private Key, decrypt must be with Public Key
      const pubRadio = document.querySelector('input[name="decKeyMode"][value="public"]');
      if (pubRadio) {
        pubRadio.checked = true;
        pubRadio.dispatchEvent(new Event('change'));
      }
      if (activeKeypair.publicKey) document.getElementById('decKey').value = activeKeypair.publicKey;
    } else {
      // If encrypted with Public Key, decrypt must be with Private Key
      const privRadio = document.querySelector('input[name="decKeyMode"][value="private"]');
      if (privRadio) {
        privRadio.checked = true;
        privRadio.dispatchEvent(new Event('change'));
      }
      if (activeKeypair.privateKey) document.getElementById('decKey').value = activeKeypair.privateKey;
    }

    validateKeyInput('decKey', 'decKeyBadge');
    document.getElementById('decCiphertext').dispatchEvent(new Event('input'));
    switchTab('tab-decrypt');
    showToast('Transferred ciphertext and matching key to Decrypt tab!');
  });
}

// Decryption Tab
function setupDecryptionTab() {
  const keyInput = document.getElementById('decKey');
  const cipherInput = document.getElementById('decCiphertext');
  const btnDecrypt = document.getElementById('btnExecuteDecrypt');
  const btnSample = document.getElementById('btnSampleDecrypt');
  const decKeyFile = document.getElementById('decKeyFile');
  const decDataFile = document.getElementById('decDataFile');

  const plainOutput = document.getElementById('decPlaintextOutput');
  const outputStats = document.getElementById('decOutputStats');
  const inputStats = document.getElementById('decInputStats');
  const statusBadge = document.getElementById('decStatusBadge');
  const alertIcon = document.getElementById('decInfoAlertIcon');
  const alertText = document.getElementById('decInfoAlertText');

  // Handle Decrypt Key Mode Radios (Public vs Private)
  const decRadios = document.querySelectorAll('input[name="decKeyMode"]');
  decRadios.forEach(radio => {
    radio.addEventListener('change', () => {
      const mode = radio.value;
      const lblPub = document.getElementById('lblDecPublic');
      const lblPriv = document.getElementById('lblDecPrivate');

      if (mode === 'public') {
        lblPub.classList.add('active');
        lblPriv.classList.remove('active');
        document.getElementById('decKeyLabel').textContent = 'RSA Public Key (PEM)';
        keyInput.placeholder = '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----';
        btnDecrypt.textContent = '🔓 Decrypt with Public Key';
        if (alertIcon) alertIcon.textContent = '🛡️';
        if (alertText) {
          alertText.innerHTML = '<strong>Verification Notice:</strong> Because this is decrypted using the RSA <em>Public Key</em>, successful decryption proves mathematically that the message was encrypted by the holder of the matching <em>Private Key</em> without tampering.';
        }
        if (activeKeypair.publicKey) keyInput.value = activeKeypair.publicKey;
      } else {
        lblPriv.classList.add('active');
        lblPub.classList.remove('active');
        document.getElementById('decKeyLabel').textContent = 'RSA Private Key (PEM)';
        keyInput.placeholder = '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----';
        btnDecrypt.textContent = '🔓 Decrypt with Private Key';
        if (alertIcon) alertIcon.textContent = '🔒';
        if (alertText) {
          alertText.innerHTML = '<strong>Confidentiality Notice:</strong> Because this is decrypted using your secret <em>Private Key</em>, you are reading a confidential message that was encrypted with your Public Key. Only you can read it.';
        }
        if (activeKeypair.privateKey) keyInput.value = activeKeypair.privateKey;
      }
      validateKeyInput('decKey', 'decKeyBadge');
    });
  });

  keyInput.addEventListener('input', () => validateKeyInput('decKey', 'decKeyBadge'));

  cipherInput.addEventListener('input', () => {
    const len = cipherInput.value.trim().length;
    inputStats.textContent = `${len} characters input`;
  });

  decKeyFile.addEventListener('change', (e) => {
    readFile(e.target.files[0], (content) => {
      keyInput.value = content;
      validateKeyInput('decKey', 'decKeyBadge');
    });
  });

  decDataFile.addEventListener('change', (e) => {
    readFile(e.target.files[0], (content) => {
      cipherInput.value = content;
      cipherInput.dispatchEvent(new Event('input'));
    });
  });

  btnSample.addEventListener('click', () => {
    if (!lastEncryptedCiphertext.base64) {
      alert('Please run "Load Sample Input" on the Encrypt tab first and encrypt, or click "⚡ 1-Click Demo" at the top.');
      return;
    }
    document.getElementById('btnSendToDecrypt').click();
  });

  btnDecrypt.addEventListener('click', async () => {
    const key = keyInput.value.trim();
    const data = cipherInput.value.trim();
    const mode = document.querySelector('input[name="decKeyMode"]:checked').value;
    if (!key) return alert(`Please enter an RSA ${mode === 'public' ? 'Public' : 'Private'} Key.`);
    if (!data) return alert('Please enter ciphertext to decrypt.');

    const inFormat = document.querySelector('input[name="decInFormat"]:checked').value;
    const blockType = document.getElementById('decBlockType').value;

    btnDecrypt.textContent = 'Decrypting...';
    btnDecrypt.disabled = true;

    try {
      const res = await callApi('/api/decrypt', {
        key,
        data,
        in_format: inFormat,
        block_type: blockType,
        mode
      });

      lastDecryptedPlaintext = {
        text: res.text,
        hex: res.hex,
        base64: res.base64,
        bytes: res.total_bytes
      };

      const activeFormat = document.querySelector('.subtab-btn-dec.active').getAttribute('data-format');
      plainOutput.value = lastDecryptedPlaintext[activeFormat];
      outputStats.textContent = `${res.text.length} characters • ${res.total_bytes} bytes`;
      statusBadge.classList.remove('hidden');
      showToast('Decryption successful!');
    } catch (err) {
      statusBadge.classList.add('hidden');
      alert(`Decryption Error: ${err.message}`);
    } finally {
      btnDecrypt.textContent = (mode === 'public') ? '🔓 Decrypt with Public Key' : '🔓 Decrypt with Private Key';
      btnDecrypt.disabled = false;
    }
  });

  // Decrypt output format tabs
  document.querySelectorAll('.subtab-btn-dec').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.subtab-btn-dec').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const fmt = btn.getAttribute('data-format');
      if (lastDecryptedPlaintext[fmt] !== undefined) {
        plainOutput.value = lastDecryptedPlaintext[fmt];
      }
    });
  });

  document.getElementById('btnCopyPlaintext').addEventListener('click', () => {
    if (!plainOutput.value) return;
    navigator.clipboard.writeText(plainOutput.value);
    showToast('Plaintext copied to clipboard');
  });

  document.getElementById('btnDownloadPlaintext').addEventListener('click', () => {
    if (!plainOutput.value) return;
    downloadFile('decrypted_plaintext.txt', plainOutput.value);
  });
}

// Step-by-Step Visualizer
function setupVisualizer() {
  const btnRun = document.getElementById('btnRunVisualizer');
  btnRun.addEventListener('click', async () => {
    btnRun.textContent = 'Running...';
    btnRun.disabled = true;

    try {
      if (!activeKeypair.privateKey || !activeKeypair.publicKey) {
        await generateKeys(2048, true);
      }

      const testMsg = "Hello RSA! Tested at " + new Date().toLocaleTimeString();
      document.getElementById('vizPlaintext').textContent = testMsg;
      document.getElementById('vizPlainStats').textContent = `${testMsg.length} chars (${new TextEncoder().encode(testMsg).length} bytes)`;

      const msgBytes = new TextEncoder().encode(testMsg);
      const k = 256;
      const padLen = k - 3 - msgBytes.length;
      document.getElementById('vizPaddingBlock').textContent =
        `00 || 01 || [${padLen} octets of 0xFF] || 00 || "${testMsg}"\nTotal Block Length: 256 octets (2048 bits)`;
      document.getElementById('vizPaddingStats').textContent = `Block size: 256 bytes (Header: 2B, Padding: ${padLen}B, Delimiter: 1B, Data: ${msgBytes.length}B)`;

      const encRes = await callApi('/api/encrypt', {
        key: activeKeypair.privateKey,
        data: testMsg,
        in_format: 'text',
        block_type: 1,
        chunk: true,
        mode: 'private'
      });

      document.getElementById('vizCiphertext').textContent = encRes.base64;
      document.getElementById('vizCipherStats').textContent = `Encrypted with Private Key exponent (d). Length: ${encRes.total_bytes} bytes.`;

      const decRes = await callApi('/api/decrypt', {
        key: activeKeypair.publicKey,
        data: encRes.base64,
        in_format: 'base64',
        block_type: 1,
        mode: 'public'
      });

      document.getElementById('vizDecrypted').textContent = decRes.text;
      const isMatch = (decRes.text === testMsg);
      document.getElementById('vizDecStats').textContent = isMatch ? '✓ VERIFIED MATCH: Decrypted message matches original plaintext!' : 'Mismatch';

      showToast('Visualizer execution completed successfully!');
    } catch (err) {
      alert(`Visualizer Error: ${err.message}`);
    } finally {
      btnRun.textContent = '▶ Run Live Step-by-Step Test';
      btnRun.disabled = false;
    }
  });
}

// 1-Click Demo
function setupQuickDemo() {
  document.getElementById('btnQuickDemo').addEventListener('click', async () => {
    switchTab('tab-demo');
    document.getElementById('btnRunVisualizer').click();
  });
}

// Helpers
async function validateKeyInput(textareaId, badgeId) {
  const elem = document.getElementById(textareaId);
  const badge = document.getElementById(badgeId);
  if (!elem || !badge) return;
  const text = elem.value.trim();

  if (!text) {
    badge.textContent = 'No Key';
    badge.className = 'badge badge-neutral';
    return;
  }

  try {
    const res = await callApi('/api/validate-key', { key: text });
    badge.textContent = `${res.size}-bit ${res.type} (${res.format})`;
    badge.className = 'badge badge-success';
  } catch {
    badge.textContent = 'Invalid PEM';
    badge.className = 'badge badge-warning';
  }
}

function readFile(file, callback) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => callback(e.target.result);
  reader.readAsText(file);
}

function downloadFile(filename, content) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// JWT Studio Tab (Encode, Decode, Sign, Verify & Instant Claims Breakdown)
function setupJwtTab() {
  const algSelect = document.getElementById('jwtAlgorithm');
  const headerInput = document.getElementById('jwtHeaderInput');
  const payloadInput = document.getElementById('jwtPayloadInput');
  const signKeyInput = document.getElementById('jwtSignKey');
  const signKeyLabel = document.getElementById('jwtSignKeyLabel');
  const signKeySection = document.getElementById('jwtSignKeySection');

  const verifyKeyInput = document.getElementById('jwtVerifyKey');
  const verifyKeyLabel = document.getElementById('jwtVerifyKeyLabel');
  const verifyKeySection = document.getElementById('jwtVerifyKeySection');

  const rawTokenInput = document.getElementById('jwtRawToken');
  const tokenPartsBadge = document.getElementById('jwtTokenPartsBadge');

  const verifyAlert = document.getElementById('jwtVerifyAlert');
  const verifyIcon = document.getElementById('jwtVerifyIcon');
  const verifyStatusText = document.getElementById('jwtVerifyStatusText');
  const expiryBadge = document.getElementById('jwtExpiryBadge');

  const btnEncodeSign = document.getElementById('btnEncodeAndSignJwt');
  const btnVerify = document.getElementById('btnVerifyJwt');
  const btnCopyToken = document.getElementById('btnCopyJwtToken');
  const btnClearToken = document.getElementById('btnClearJwtToken');
  const btnSample = document.getElementById('btnSampleJwt');
  const btnGenIatExp = document.getElementById('btnGenIatExp');
  const btnAddIatOnly = document.getElementById('btnAddIatOnly');
  const btnAddExpOnly = document.getElementById('btnAddExpOnly');
  const expDurationSelect = document.getElementById('jwtExpDurationSelect');
  const customExpRow = document.getElementById('jwtCustomExpRow');
  const customExpInput = document.getElementById('jwtCustomExpInput');
  const chkIncludeNbf = document.getElementById('chkIncludeNbf');
  const timestampPreviewText = document.getElementById('jwtTimestampPreviewText');

  const btnUseActivePriv = document.getElementById('btnUseActivePrivForJwt');
  const btnUseActivePub = document.getElementById('btnUseActivePubForJwt');
  const btnUsePwdSecret = document.getElementById('btnUsePwdAsSecretForJwt');
  const btnUsePwdSecretForVerify = document.getElementById('btnUsePwdAsSecretForVerify');

  // Claims Breakdown Elements
  const btnViewTable = document.getElementById('btnJwtViewTable');
  const btnViewJson = document.getElementById('btnJwtViewJson');
  const btnSyncToEditor = document.getElementById('btnJwtSyncToEditor');
  const claimsTableView = document.getElementById('jwtClaimsTableView');
  const claimsJsonView = document.getElementById('jwtClaimsJsonView');
  const claimsTableBody = document.getElementById('jwtClaimsTableBody');
  const claimsJsonContent = document.getElementById('jwtClaimsJsonContent');
  const headerJsonContent = document.getElementById('jwtHeaderJsonContent');
  const headerSummary = document.getElementById('jwtHeaderSummary');
  const claimsCountBadge = document.getElementById('jwtClaimsCountBadge');
  const algBadge = document.getElementById('jwtAlgBadge');
  const expiryBanner = document.getElementById('jwtExpiryBanner');
  const expiryBannerIcon = document.getElementById('jwtExpiryBannerIcon');
  const expiryBannerText = document.getElementById('jwtExpiryBannerText');

  const btnHeader = document.getElementById('btnJwtHeader');
  if (btnHeader) {
    btnHeader.addEventListener('click', () => {
      switchTab('tab-jwt');
    });
  }

  // RFC Standard Claims Dictionary
  const RFC_CLAIMS_MAP = {
    iss: { label: 'Issuer', desc: 'Identifies the principal that issued the JWT' },
    sub: { label: 'Subject', desc: 'Identifies the principal that is the subject of the JWT (e.g. User ID)' },
    aud: { label: 'Audience', desc: 'Identifies the recipients that the JWT is intended for' },
    exp: { label: 'Expiration Time', desc: 'Expiration Unix timestamp after which the JWT must not be accepted' },
    nbf: { label: 'Not Before', desc: 'Time before which the JWT must not be accepted' },
    iat: { label: 'Issued At', desc: 'Time at which the JWT was issued' },
    jti: { label: 'JWT ID', desc: 'Unique identifier for the token' },
    name: { label: 'Full Name', desc: 'User full display name' },
    email: { label: 'Email Address', desc: 'User email address' },
    role: { label: 'Role', desc: 'Assigned authorization role' },
    roles: { label: 'Roles', desc: 'List of assigned authorization roles' },
    admin: { label: 'Administrator', desc: 'Administrative privilege flag' },
    scope: { label: 'Scope', desc: 'OAuth 2.0 authorization scopes granted' }
  };

  const escapeHtml = (str) => {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  };

  // Base64URL Local Decoder (Instant decode with zero latency)
  const decodeJwtLocally = (token) => {
    if (!token || typeof token !== 'string') return null;
    const parts = token.trim().split('.');
    if (parts.length < 2) return null;

    const b64UrlDecode = (str) => {
      let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4 !== 0) b64 += '=';
      const binary = atob(b64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return new TextDecoder('utf-8').decode(bytes);
    };

    try {
      const headerStr = b64UrlDecode(parts[0]);
      const payloadStr = b64UrlDecode(parts[1]);
      const header = JSON.parse(headerStr);
      const payload = JSON.parse(payloadStr);
      return {
        header,
        payload,
        signatureB64: parts[2] || '',
        partsCount: parts.length
      };
    } catch {
      return null;
    }
  };

  // Time Formatter
  const formatUnixTimestamp = (ts) => {
    if (typeof ts !== 'number' || isNaN(ts)) return null;
    const d = new Date(ts * 1000);
    const now = Math.floor(Date.now() / 1000);
    const diff = ts - now;

    const dateStr = d.toLocaleString();
    const formatSecs = (s) => {
      const abs = Math.abs(s);
      if (abs < 60) return `${abs}s`;
      if (abs < 3600) return `${Math.floor(abs / 60)}m ${abs % 60}s`;
      if (abs < 86400) return `${Math.floor(abs / 3600)}h ${Math.floor((abs % 3600) / 60)}m`;
      return `${Math.floor(abs / 86400)}d ${Math.floor((abs % 86400) / 3600)}h`;
    };

    const isExpired = diff < 0;
    const relStr = isExpired ? `Expired ${formatSecs(diff)} ago` : `Expires in ${formatSecs(diff)}`;
    return { dateStr, isExpired, relStr };
  };

  // Render Claims Breakdown Table & JSON
  const renderClaimsBreakdown = (header, payload) => {
    const alg = (header && header.alg) || 'none';
    if (algBadge) algBadge.textContent = alg;
    if (headerSummary) headerSummary.textContent = `alg: ${alg}${header && header.typ ? ', typ: ' + header.typ : ''}`;
    if (headerJsonContent) headerJsonContent.textContent = JSON.stringify(header || {}, null, 2);

    if (claimsJsonContent) claimsJsonContent.textContent = JSON.stringify(payload || {}, null, 2);

    const keys = Object.keys(payload || {});
    if (claimsCountBadge) claimsCountBadge.textContent = `${keys.length} Claim${keys.length === 1 ? '' : 's'}`;

    // Expiration Banner
    if (payload && 'exp' in payload && typeof payload.exp === 'number') {
      const timeInfo = formatUnixTimestamp(payload.exp);
      if (expiryBanner) {
        expiryBanner.classList.remove('hidden');
        if (timeInfo.isExpired) {
          expiryBanner.className = 'jwt-claim-banner banner-expired';
          if (expiryBannerIcon) expiryBannerIcon.textContent = '❌';
          if (expiryBannerText) expiryBannerText.innerHTML = `<strong>Token Expired:</strong> Expired on ${timeInfo.dateStr} (${timeInfo.relStr})`;
        } else {
          expiryBanner.className = 'jwt-claim-banner banner-active';
          if (expiryBannerIcon) expiryBannerIcon.textContent = '⏳';
          if (expiryBannerText) expiryBannerText.innerHTML = `<strong>Token Active:</strong> Valid until ${timeInfo.dateStr} (${timeInfo.relStr})`;
        }
      }
    } else {
      if (expiryBanner) expiryBanner.classList.add('hidden');
    }

    if (!claimsTableBody) return;

    if (keys.length === 0) {
      claimsTableBody.innerHTML = `
        <tr>
          <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">
            Empty payload (0 claims).
          </td>
        </tr>
      `;
      return;
    }

    let rowsHtml = '';
    keys.forEach(k => {
      const val = payload[k];
      const isStandard = k in RFC_CLAIMS_MAP;
      const meta = RFC_CLAIMS_MAP[k] || { label: 'Custom Claim', desc: 'Application-defined custom claim property' };

      let valDisplay = '';
      let dateExtra = '';

      if ((k === 'exp' || k === 'iat' || k === 'nbf') && typeof val === 'number') {
        const timeInfo = formatUnixTimestamp(val);
        if (timeInfo) {
          valDisplay = `<code>${val}</code>`;
          const dateClass = (k === 'exp' && timeInfo.isExpired) ? 'jwt-claim-date date-expired' : 'jwt-claim-date';
          dateExtra = `<span class="${dateClass}" data-date-str="${escapeHtml(timeInfo.dateStr)}" title="Click to copy formatted date">📅 ${timeInfo.dateStr} &bull; ${timeInfo.relStr} 📋</span>`;
        } else {
          valDisplay = `<code>${val}</code>`;
        }
      } else if (typeof val === 'object' && val !== null) {
        valDisplay = `<pre style="margin: 0; font-size: 0.75rem; background: var(--bg-secondary); padding: 0.35rem 0.5rem; border-radius: 4px;">${escapeHtml(JSON.stringify(val, null, 2))}</pre>`;
      } else if (typeof val === 'boolean') {
        valDisplay = `<code style="color: ${val ? '#10b981' : '#ef4444'}; font-weight: bold;">${val}</code>`;
      } else {
        valDisplay = `<code>${escapeHtml(String(val))}</code>`;
      }

      rowsHtml += `
        <tr>
          <td>
            <div class="jwt-claim-name">
              <span>${escapeHtml(k)}</span>
              <span class="jwt-claim-tag ${isStandard ? 'tag-standard' : 'tag-custom'}">${isStandard ? 'Standard' : 'Custom'}</span>
            </div>
          </td>
          <td>
            <div class="jwt-claim-desc">
              <strong>${escapeHtml(meta.label)}</strong><br>
              <span>${escapeHtml(meta.desc)}</span>
            </div>
          </td>
          <td>
            <div class="jwt-claim-val">
              ${valDisplay}
              ${dateExtra}
            </div>
          </td>
          <td style="text-align: center; vertical-align: middle;">
            <button type="button" class="btn btn-sm btn-secondary btn-copy-claim-val" data-claim-key="${escapeHtml(k)}" title="Copy decoded value of ${escapeHtml(k)}">
              📋 Copy
            </button>
          </td>
        </tr>
      `;
    });

    claimsTableBody.innerHTML = rowsHtml;

    // Attach Click Handlers for Claim Copy Buttons
    claimsTableBody.querySelectorAll('.btn-copy-claim-val').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-claim-key');
        if (payload && key in payload) {
          const rawVal = payload[key];
          const textToCopy = (typeof rawVal === 'object' && rawVal !== null)
            ? JSON.stringify(rawVal, null, 2)
            : String(rawVal);

          navigator.clipboard.writeText(textToCopy);
          showToast(`Copied claim "${key}" value to clipboard!`);

          const origHtml = btn.innerHTML;
          btn.innerHTML = '✓ Copied!';
          btn.classList.add('btn-accent');
          btn.classList.remove('btn-secondary');
          setTimeout(() => {
            btn.innerHTML = origHtml;
            btn.classList.remove('btn-accent');
            btn.classList.add('btn-secondary');
          }, 1500);
        }
      });
    });

    // Attach Click Handlers for Formatted Date Pills
    claimsTableBody.querySelectorAll('.jwt-claim-date').forEach(dateSpan => {
      dateSpan.addEventListener('click', () => {
        const text = dateSpan.getAttribute('data-date-str') || dateSpan.textContent;
        navigator.clipboard.writeText(text);
        showToast('Copied formatted date to clipboard!');
      });
    });
  };

  // Copy Whole Claims JSON button
  const btnCopyClaimsJson = document.getElementById('btnCopyClaimsJson');
  if (btnCopyClaimsJson) {
    btnCopyClaimsJson.addEventListener('click', () => {
      if (!claimsJsonContent || !claimsJsonContent.textContent.trim()) {
        showToast('No claims to copy.');
        return;
      }
      navigator.clipboard.writeText(claimsJsonContent.textContent);
      showToast('Copied decoded Payload JSON to clipboard!');
    });
  }

  // Copy Whole Header JSON button
  const btnCopyHeaderJson = document.getElementById('btnCopyHeaderJson');
  if (btnCopyHeaderJson) {
    btnCopyHeaderJson.addEventListener('click', () => {
      if (!headerJsonContent || !headerJsonContent.textContent.trim()) {
        showToast('No header to copy.');
        return;
      }
      navigator.clipboard.writeText(headerJsonContent.textContent);
      showToast('Copied decoded JOSE Header JSON to clipboard!');
    });
  }

  // View Switcher (Table vs JSON)
  if (btnViewTable && btnViewJson && claimsTableView && claimsJsonView) {
    btnViewTable.addEventListener('click', () => {
      btnViewTable.classList.add('active');
      btnViewJson.classList.remove('active');
      claimsTableView.classList.remove('hidden');
      claimsJsonView.classList.add('hidden');
    });

    btnViewJson.addEventListener('click', () => {
      btnViewJson.classList.add('active');
      btnViewTable.classList.remove('active');
      claimsJsonView.classList.remove('hidden');
      claimsTableView.classList.add('hidden');
    });
  }

  // Sync / Load into Signer
  if (btnSyncToEditor) {
    btnSyncToEditor.addEventListener('click', () => {
      const token = rawTokenInput.value.trim();
      const parsed = decodeJwtLocally(token);
      if (parsed) {
        headerInput.value = JSON.stringify(parsed.header, null, 2);
        payloadInput.value = JSON.stringify(parsed.payload, null, 2);
        if (parsed.header && parsed.header.alg && [...algSelect.options].some(o => o.value === parsed.header.alg)) {
          algSelect.value = parsed.header.alg;
          updateKeyInputsForAlg();
        }
        showToast('Loaded claims into Encoder form on left!');
      } else {
        alert('Please paste or generate a valid JWT token first.');
      }
    });
  }

  // Clear Token
  if (btnClearToken) {
    btnClearToken.addEventListener('click', () => {
      rawTokenInput.value = '';
      tokenPartsBadge.textContent = '0 Parts';
      if (claimsTableBody) {
        claimsTableBody.innerHTML = `
          <tr>
            <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">
              Paste a JWT token above to view its claims breakdown automatically.
            </td>
          </tr>
        `;
      }
      if (claimsJsonContent) claimsJsonContent.textContent = '';
      if (headerJsonContent) headerJsonContent.textContent = '';
      if (claimsCountBadge) claimsCountBadge.textContent = '0 Claims';
      if (expiryBanner) expiryBanner.classList.add('hidden');
      verifyAlert.className = 'info-alert info-alert-neutral';
      verifyIcon.textContent = 'ℹ️';
      verifyStatusText.innerHTML = 'Paste a JWT token above to decode claims and inspect signature.';
      expiryBadge.classList.add('hidden');
      showToast('Cleared JWT token input.');
    });
  }

  // Handle Algorithm Switch
  const updateKeyInputsForAlg = () => {
    const alg = algSelect.value;

    try {
      const hObj = JSON.parse(headerInput.value || '{}');
      hObj.alg = alg;
      if (!hObj.typ) hObj.typ = 'JWT';
      headerInput.value = JSON.stringify(hObj, null, 2);
    } catch {
      headerInput.value = JSON.stringify({ alg, typ: 'JWT' }, null, 2);
    }

    if (alg === 'none') {
      signKeySection.classList.add('hidden');
      verifyKeySection.classList.add('hidden');
    } else if (alg.startsWith('RS') || alg.startsWith('PS')) {
      signKeySection.classList.remove('hidden');
      verifyKeySection.classList.remove('hidden');
      signKeyLabel.textContent = `Signing Key (RSA Private Key PEM for ${alg})`;
      verifyKeyLabel.textContent = `Verification Key (RSA Public Key PEM for ${alg})`;
      signKeyInput.placeholder = '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----';
      verifyKeyInput.placeholder = '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----';
      btnUseActivePriv.classList.remove('hidden');
      btnUseActivePub.classList.remove('hidden');
      btnUsePwdSecret.classList.add('hidden');
      if (btnUsePwdSecretForVerify) btnUsePwdSecretForVerify.classList.add('hidden');

      if (!signKeyInput.value.trim() && activeKeypair.privateKey) {
        signKeyInput.value = activeKeypair.privateKey;
      }
      if (!verifyKeyInput.value.trim() && activeKeypair.publicKey) {
        verifyKeyInput.value = activeKeypair.publicKey;
      }
    } else if (alg.startsWith('HS')) {
      signKeySection.classList.remove('hidden');
      verifyKeySection.classList.remove('hidden');
      signKeyLabel.textContent = `Secret Key (HMAC Secret for ${alg})`;
      verifyKeyLabel.textContent = `Secret Key (HMAC Secret for ${alg})`;
      signKeyInput.placeholder = 'Enter HMAC secret string...';
      verifyKeyInput.placeholder = 'Enter HMAC secret string...';
      btnUseActivePriv.classList.add('hidden');
      btnUseActivePub.classList.add('hidden');
      btnUsePwdSecret.classList.remove('hidden');
      if (btnUsePwdSecretForVerify) btnUsePwdSecretForVerify.classList.remove('hidden');

      if (!signKeyInput.value.trim() || signKeyInput.value.includes('BEGIN')) {
        signKeyInput.value = 'your-256-bit-secret-key-1234567890';
      }
      if (!verifyKeyInput.value.trim() || verifyKeyInput.value.includes('BEGIN')) {
        verifyKeyInput.value = signKeyInput.value;
      }
    }
  };

  algSelect.addEventListener('change', () => {
    updateKeyInputsForAlg();
    handleEncodeAndSign(false);
  });

  btnUseActivePriv.addEventListener('click', () => {
    if (activeKeypair.privateKey) {
      signKeyInput.value = activeKeypair.privateKey;
      showToast('Loaded active RSA Private Key into JWT Signer');
    } else {
      alert('Please generate or load an RSA keypair in Key Manager first.');
    }
  });

  btnUseActivePub.addEventListener('click', () => {
    if (activeKeypair.publicKey) {
      verifyKeyInput.value = activeKeypair.publicKey;
      showToast('Loaded active RSA Public Key into JWT Verifier');
      handleRawTokenInput(true);
    } else {
      alert('Please generate or load an RSA keypair in Key Manager first.');
    }
  });

  const generateSecureSecret = (len = 64) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = new Uint8Array(len);
    window.crypto.getRandomValues(bytes);
    let result = '';
    for (let i = 0; i < len; i++) {
      result += chars[bytes[i] % chars.length];
    }
    return result;
  };

  btnUsePwdSecret.addEventListener('click', () => {
    const secret = generateSecureSecret(64);
    signKeyInput.value = secret;
    verifyKeyInput.value = secret;
    showToast('Generated 64-char random HMAC secret!');
    handleEncodeAndSign(false);
  });

  if (btnUsePwdSecretForVerify) {
    btnUsePwdSecretForVerify.addEventListener('click', () => {
      const secret = generateSecureSecret(64);
      verifyKeyInput.value = secret;
      showToast('Generated 64-char random HMAC secret for verification!');
      handleRawTokenInput(true);
    });
  }

  const loadSampleData = () => {
    headerInput.value = JSON.stringify({ alg: algSelect.value, typ: 'JWT' }, null, 2);
    const now = Math.floor(Date.now() / 1000);
    payloadInput.value = JSON.stringify({
      sub: 'usr_123456789',
      name: 'John Doe',
      role: 'admin',
      iat: now,
      exp: now + 3600
    }, null, 2);
    updateKeyInputsForAlg();
  };

  btnSample.addEventListener('click', () => {
    loadSampleData();
    handleEncodeAndSign(true);
  });

  // Timestamp Generator Functions
  const updateTimestampPreview = () => {
    if (!timestampPreviewText || !expDurationSelect) return;
    const now = Math.floor(Date.now() / 1000);
    const selVal = expDurationSelect.value;
    let exp = now + 3600;
    let label = '1 Hour (Default)';

    if (selVal === 'custom') {
      if (customExpInput && customExpInput.value) {
        const customDate = new Date(customExpInput.value);
        exp = Math.floor(customDate.getTime() / 1000);
        label = `Custom: ${customDate.toLocaleString()}`;
      } else {
        label = 'Custom (pick a date)';
      }
    } else {
      const secs = parseInt(selVal, 10);
      exp = now + secs;
      const opt = expDurationSelect.options[expDurationSelect.selectedIndex];
      if (opt) label = opt.textContent;
    }

    const nbfText = chkIncludeNbf && chkIncludeNbf.checked ? ` &bull; <code>nbf: ${now}</code>` : '';
    timestampPreviewText.innerHTML = `Preview: <code>iat: ${now}</code> (${new Date(now * 1000).toLocaleTimeString()}) &bull; <code>exp: ${exp}</code> (${new Date(exp * 1000).toLocaleTimeString()}, ${label})${nbfText}`;
  };

  if (expDurationSelect) {
    expDurationSelect.addEventListener('change', () => {
      if (expDurationSelect.value === 'custom') {
        if (customExpRow) customExpRow.classList.remove('hidden');
        if (customExpInput && !customExpInput.value) {
          const defaultDate = new Date(Date.now() + 3600000 - new Date().getTimezoneOffset() * 60000);
          customExpInput.value = defaultDate.toISOString().slice(0, 16);
        }
      } else {
        if (customExpRow) customExpRow.classList.add('hidden');
      }
      updateTimestampPreview();
    });
  }

  if (customExpInput) {
    customExpInput.addEventListener('input', updateTimestampPreview);
  }

  if (chkIncludeNbf) {
    chkIncludeNbf.addEventListener('change', updateTimestampPreview);
  }

  const getTargetExpSeconds = (baseNow) => {
    if (expDurationSelect && expDurationSelect.value === 'custom') {
      if (customExpInput && customExpInput.value) {
        const customDate = new Date(customExpInput.value);
        return Math.floor(customDate.getTime() / 1000);
      }
    }
    const secs = parseInt((expDurationSelect && expDurationSelect.value) || '3600', 10);
    return baseNow + secs;
  };

  const getDurationLabel = () => {
    if (expDurationSelect && expDurationSelect.value === 'custom') {
      if (customExpInput && customExpInput.value) {
        return new Date(customExpInput.value).toLocaleString();
      }
      return 'custom date';
    }
    if (expDurationSelect) {
      const opt = expDurationSelect.options[expDurationSelect.selectedIndex];
      return opt ? opt.textContent : '1 hour';
    }
    return '1 hour';
  };

  if (btnGenIatExp) {
    btnGenIatExp.addEventListener('click', () => {
      let obj = {};
      try {
        obj = JSON.parse(payloadInput.value || '{}');
      } catch (e) {
        alert('Invalid JSON in payload: ' + e.message);
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      const exp = getTargetExpSeconds(now);
      const label = getDurationLabel();

      obj.iat = now;
      obj.exp = exp;
      if (chkIncludeNbf && chkIncludeNbf.checked) {
        obj.nbf = now;
      }

      payloadInput.value = JSON.stringify(obj, null, 2);

      const nbfMsg = (chkIncludeNbf && chkIncludeNbf.checked) ? ` &bull; <code>nbf: ${now}</code>` : '';
      if (timestampPreviewText) {
        timestampPreviewText.innerHTML = `<strong>✓ Timestamps Applied:</strong> <code>iat: ${now}</code> (${new Date(now * 1000).toLocaleTimeString()}) &bull; <code>exp: ${exp}</code> (${new Date(exp * 1000).toLocaleString()}, valid for ${label})${nbfMsg}`;
      }

      showToast(`Generated iat (${now}) and exp (${label})!`);
    });
  }

  if (btnAddIatOnly) {
    btnAddIatOnly.addEventListener('click', () => {
      let obj = {};
      try {
        obj = JSON.parse(payloadInput.value || '{}');
      } catch (e) {
        alert('Invalid JSON in payload: ' + e.message);
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      obj.iat = now;
      payloadInput.value = JSON.stringify(obj, null, 2);

      if (timestampPreviewText) {
        timestampPreviewText.innerHTML = `<strong>✓ iat Applied:</strong> <code>iat: ${now}</code> (${new Date(now * 1000).toLocaleString()})`;
      }

      showToast(`Updated iat claim to ${now} (current timestamp)!`);
    });
  }

  if (btnAddExpOnly) {
    btnAddExpOnly.addEventListener('click', () => {
      let obj = {};
      try {
        obj = JSON.parse(payloadInput.value || '{}');
      } catch (e) {
        alert('Invalid JSON in payload: ' + e.message);
        return;
      }

      const baseNow = (typeof obj.iat === 'number') ? obj.iat : Math.floor(Date.now() / 1000);
      const exp = getTargetExpSeconds(baseNow);
      const label = getDurationLabel();

      obj.exp = exp;
      payloadInput.value = JSON.stringify(obj, null, 2);

      if (timestampPreviewText) {
        timestampPreviewText.innerHTML = `<strong>✓ exp Applied:</strong> <code>exp: ${exp}</code> (${new Date(exp * 1000).toLocaleString()}, ${label})`;
      }

      showToast(`Updated exp claim to ${exp} (${label})!`);
    });
  }

  updateTimestampPreview();

  // Encode & Sign
  const handleEncodeAndSign = async (notify = true) => {
    let payloadObj, headerObj;
    try {
      payloadObj = JSON.parse(payloadInput.value);
    } catch (e) {
      if (notify) alert('Invalid JSON in Payload: ' + e.message);
      return;
    }

    try {
      headerObj = JSON.parse(headerInput.value);
    } catch (e) {
      if (notify) alert('Invalid JSON in Header: ' + e.message);
      return;
    }

    const alg = algSelect.value;
    const key = signKeyInput.value.trim();

    if (alg !== 'none' && !key) {
      if (notify) alert('Please provide a signing key for algorithm ' + alg);
      return;
    }

    btnEncodeSign.textContent = 'Signing...';
    btnEncodeSign.disabled = true;

    try {
      const res = await callApi('/api/jwt/encode', {
        payload: payloadObj,
        headers: headerObj,
        key,
        algorithm: alg
      });

      rawTokenInput.value = res.token;
      tokenPartsBadge.textContent = `${res.token.split('.').length} Parts (${res.token.length} chars)`;

      // Render claims breakdown immediately
      renderClaimsBreakdown(headerObj, payloadObj);

      const verifyKey = verifyKeyInput.value.trim() || key;
      await handleVerify(false, verifyKey);

      if (notify) showToast('JWT signed & encoded successfully!');
    } catch (err) {
      if (notify) alert('JWT Signing Error: ' + err.message);
    } finally {
      btnEncodeSign.textContent = '⚡ Sign & Encode JWT';
      btnEncodeSign.disabled = false;
    }
  };

  btnEncodeSign.addEventListener('click', () => handleEncodeAndSign(true));

  // Centralized Token Input / Paste Handler:
  // Decodes claims instantly without requiring public key!
  const handleRawTokenInput = async (verifySignature = false) => {
    const token = rawTokenInput.value.trim();
    if (!token) {
      tokenPartsBadge.textContent = '0 Parts';
      if (claimsTableBody) {
        claimsTableBody.innerHTML = `
          <tr>
            <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">
              Paste a JWT token above to view its claims breakdown automatically.
            </td>
          </tr>
        `;
      }
      if (claimsJsonContent) claimsJsonContent.textContent = '';
      if (headerJsonContent) headerJsonContent.textContent = '';
      if (claimsCountBadge) claimsCountBadge.textContent = '0 Claims';
      if (expiryBanner) expiryBanner.classList.add('hidden');
      verifyAlert.className = 'info-alert info-alert-neutral';
      verifyIcon.textContent = 'ℹ️';
      verifyStatusText.innerHTML = 'Paste or enter a token above to decode claims and verify signature.';
      expiryBadge.classList.add('hidden');
      return;
    }

    const parts = token.split('.');
    tokenPartsBadge.textContent = `${parts.length} Part${parts.length === 1 ? '' : 's'} (${token.length} chars)`;

    // 1. Instant Local Decode: Parse and show claims breakdown immediately
    const localParsed = decodeJwtLocally(token);
    if (localParsed) {
      renderClaimsBreakdown(localParsed.header, localParsed.payload);

      // Auto-sync alg in selector if recognized
      if (localParsed.header && localParsed.header.alg && localParsed.header.alg !== algSelect.value) {
        if ([...algSelect.options].some(o => o.value === localParsed.header.alg)) {
          algSelect.value = localParsed.header.alg;
          updateKeyInputsForAlg();
        }
      }
    } else {
      if (token.includes('.')) {
        if (claimsTableBody) {
          claimsTableBody.innerHTML = `
            <tr>
              <td colspan="4" style="text-align: center; color: #ef4444; padding: 1.5rem;">
                ⚠️ Malformed token. Ensure it contains valid Base64URL-encoded JSON parts separated by dots.
              </td>
            </tr>
          `;
        }
      }
    }

    // 2. Cryptographic signature check:
    const key = verifyKeyInput.value.trim();
    if (key) {
      // Key is provided -> perform signature verification
      try {
        const res = await callApi('/api/jwt/decode', {
          token,
          key,
          verify: true
        });

        if (res.valid) {
          verifyAlert.className = 'info-alert info-alert-valid';
          verifyIcon.textContent = '✓';
          verifyStatusText.innerHTML = '<strong>Signature Verified:</strong> Token signature is cryptographically valid and matches the provided verification key!';
        } else {
          verifyAlert.className = 'info-alert info-alert-invalid';
          verifyIcon.textContent = '✗';
          verifyStatusText.innerHTML = `<strong>Invalid Signature:</strong> ${res.error || 'Signature does not match key'}`;
        }

        if (res.expired) {
          expiryBadge.classList.remove('hidden');
        } else {
          expiryBadge.classList.add('hidden');
        }
      } catch (err) {
        verifyAlert.className = 'info-alert info-alert-invalid';
        verifyIcon.textContent = '✗';
        verifyStatusText.innerHTML = `<strong>Verification Error:</strong> ${err.message}`;
      }
    } else {
      // No verification key provided: Show clear, friendly unverified status
      verifyAlert.className = 'info-alert info-alert-neutral';
      verifyIcon.textContent = 'ℹ️';
      verifyStatusText.innerHTML = '<strong>Claims Decoded (Unverified):</strong> Claims are displayed above directly from the token payload. To cryptographically verify that the signature is authentic, enter the verification key below.';

      if (localParsed && localParsed.payload && typeof localParsed.payload.exp === 'number' && localParsed.payload.exp < Math.floor(Date.now() / 1000)) {
        expiryBadge.classList.remove('hidden');
      } else {
        expiryBadge.classList.add('hidden');
      }
    }
  };

  // Explicit Verify Button Click
  const handleVerify = async (notify = true, customKey = null) => {
    const token = rawTokenInput.value.trim();
    if (!token) {
      if (notify) alert('Please enter or paste a JWT token first.');
      return;
    }

    const key = customKey !== null ? customKey : verifyKeyInput.value.trim();
    if (!key) {
      if (notify) {
        showToast('Decoded claims without verification (no key provided).');
      }
      handleRawTokenInput(false);
      return;
    }

    btnVerify.textContent = 'Verifying...';
    btnVerify.disabled = true;

    try {
      const res = await callApi('/api/jwt/decode', {
        token,
        key: key || null,
        verify: true
      });

      if (res.header && res.payload) {
        renderClaimsBreakdown(res.header, res.payload);
      }

      if (res.valid) {
        verifyAlert.className = 'info-alert info-alert-valid';
        verifyIcon.textContent = '✓';
        verifyStatusText.innerHTML = '<strong>Signature Verified:</strong> Token signature is cryptographically valid and matches the provided verification key!';
      } else {
        verifyAlert.className = 'info-alert info-alert-invalid';
        verifyIcon.textContent = '✗';
        verifyStatusText.innerHTML = `<strong>Invalid Signature:</strong> ${res.error || 'Verification failed'}`;
      }

      if (res.expired) {
        expiryBadge.classList.remove('hidden');
      } else {
        expiryBadge.classList.add('hidden');
      }

      if (notify) showToast(res.valid ? 'Token verified: Valid signature!' : 'Token verification failed: Invalid signature');
    } catch (err) {
      if (notify) alert('JWT Verification Error: ' + err.message);
    } finally {
      btnVerify.textContent = '✓ Verify Token Signature';
      btnVerify.disabled = false;
    }
  };

  btnVerify.addEventListener('click', () => handleVerify(true));

  // Live Listeners on rawTokenInput for paste, typing, and changes
  rawTokenInput.addEventListener('input', () => handleRawTokenInput(false));
  rawTokenInput.addEventListener('paste', () => {
    setTimeout(() => handleRawTokenInput(false), 50);
  });
  rawTokenInput.addEventListener('change', () => handleRawTokenInput(false));

  // Also listen for key input changes to re-verify live if key is entered
  verifyKeyInput.addEventListener('input', () => {
    if (rawTokenInput.value.trim()) {
      handleRawTokenInput(false);
    }
  });

  btnCopyToken.addEventListener('click', () => {
    if (!rawTokenInput.value) return;
    navigator.clipboard.writeText(rawTokenInput.value);
    showToast('JWT token copied to clipboard!');
  });

  loadSampleData();
  setTimeout(() => {
    if (!rawTokenInput.value) {
      handleEncodeAndSign(false);
    }
  }, 100);
}

import unittest
import base64
import subprocess
import json
import rsa_crypto

class TestRSACrypto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv_pem, cls.pub_pem = rsa_crypto.generate_key_pair(2048, pkcs8=True)
        cls.priv_key = rsa_crypto.load_private_key(cls.priv_pem)
        cls.pub_key = rsa_crypto.load_public_key(cls.pub_pem)

    def test_key_generation_and_loading(self):
        priv_pkcs1, pub_pkcs1 = rsa_crypto.generate_key_pair(1024, pkcs8=False)
        self.assertIn("BEGIN RSA PRIVATE KEY", priv_pkcs1)
        self.assertIn("BEGIN RSA PUBLIC KEY", pub_pkcs1)

        k1 = rsa_crypto.load_private_key(priv_pkcs1)
        p1 = rsa_crypto.load_public_key(pub_pkcs1)
        self.assertEqual(k1.key_size, 1024)
        self.assertEqual(p1.key_size, 1024)

    def test_private_encrypt_public_decrypt_bt1(self):
        message = b"Confidential message encrypted with private key (BT1)!"
        ciphertext = rsa_crypto.encrypt_private(message, self.priv_key, block_type=1)
        decrypted = rsa_crypto.decrypt_public(ciphertext, self.pub_key, expected_bt=1)
        self.assertEqual(message, decrypted)

    def test_private_encrypt_public_decrypt_bt2(self):
        message = b"Confidential message encrypted with private key (BT2)!"
        ciphertext = rsa_crypto.encrypt_private(message, self.priv_key, block_type=2)
        decrypted = rsa_crypto.decrypt_public(ciphertext, self.pub_key, expected_bt=2)
        self.assertEqual(message, decrypted)

    def test_chunked_encryption_decryption(self):
        long_message = ("This is a long test payload " * 50).encode("utf-8") # ~1400 bytes > 245 bytes
        ciphertext = rsa_crypto.encrypt_private(long_message, self.priv_key, block_type=1, chunk=True)
        # Block size is 256 bytes for 2048-bit key
        self.assertEqual(len(ciphertext) % 256, 0)
        self.assertGreater(len(ciphertext), 256)

        decrypted = rsa_crypto.decrypt_public(ciphertext, self.pub_key)
        self.assertEqual(long_message, decrypted)

    def test_single_block_overflow_raises_error(self):
        long_message = b"X" * 300 # Exceeds 245 max payload for 2048-bit key
        with self.assertRaises(ValueError):
            rsa_crypto.encrypt_private(long_message, self.priv_key, block_type=1, chunk=False)

    def test_public_encrypt_private_decrypt(self):
        message = b"Standard RSA public encrypt / private decrypt"
        ciphertext = rsa_crypto.encrypt_public(message, self.pub_key, block_type=2)
        decrypted = rsa_crypto.decrypt_private(ciphertext, self.priv_key, expected_bt=2)
        self.assertEqual(message, decrypted)

    def test_interop_with_node_crypto(self):
        """Verify python ciphertext can be decrypted by Node.js crypto and vice versa."""
        test_msg = "Hello Node from Python test!"
        py_cipher = rsa_crypto.encrypt_private(test_msg.encode("utf-8"), self.priv_key, block_type=1)
        py_b64 = base64.b64encode(py_cipher).decode("utf-8")

        node_script = f"""
        const crypto = require('crypto');
        const pubKey = {json.dumps(self.pub_pem)};
        const cipher = Buffer.from({json.dumps(py_b64)}, 'base64');
        const dec = crypto.publicDecrypt({{ key: pubKey, padding: crypto.constants.RSA_PKCS1_PADDING }}, cipher);
        process.stdout.write(dec.toString());
        """
        res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
        self.assertEqual(res.stdout, test_msg)

        # Node encrypt -> Python decrypt
        node_encrypt_script = f"""
        const crypto = require('crypto');
        const privKey = {json.dumps(self.priv_pem)};
        const enc = crypto.privateEncrypt({{ key: privKey, padding: crypto.constants.RSA_PKCS1_PADDING }}, Buffer.from('Node encrypted message'));
        process.stdout.write(enc.toString('base64'));
        """
        res_enc = subprocess.run(["node", "-e", node_encrypt_script], capture_output=True, text=True, check=True)
        node_cipher = base64.b64decode(res_enc.stdout)
        py_dec = rsa_crypto.decrypt_public(node_cipher, self.pub_key)
        self.assertEqual(py_dec, b"Node encrypted message")

if __name__ == "__main__":
    unittest.main()

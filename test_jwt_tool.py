import unittest
import time
import subprocess
import json
import jwt_tool
import rsa_crypto

class TestJWTTool(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv_pem, cls.pub_pem = rsa_crypto.generate_key_pair(2048)

    def test_rs256_encode_and_verify(self):
        payload = {"sub": "user123", "name": "Alice", "admin": True}
        token = jwt_tool.encode_jwt(payload, self.priv_pem, algorithm="RS256")
        self.assertEqual(len(token.split(".")), 3)

        # Verify with public key
        res = jwt_tool.decode_jwt(token, self.pub_pem, verify=True)
        self.assertTrue(res["valid"])
        self.assertEqual(res["payload"]["sub"], "user123")
        self.assertEqual(res["header"]["alg"], "RS256")
        self.assertFalse(res["expired"])

    def test_rs512_and_ps256(self):
        payload = {"sub": "user456"}
        for alg in ["RS512", "PS256"]:
            token = jwt_tool.encode_jwt(payload, self.priv_pem, algorithm=alg)
            res = jwt_tool.decode_jwt(token, self.pub_pem, verify=True)
            self.assertTrue(res["valid"])
            self.assertEqual(res["header"]["alg"], alg)

    def test_hs256_encode_and_verify(self):
        secret = "super-secret-key-12345"
        payload = {"sub": "bob", "role": "editor"}
        token = jwt_tool.encode_jwt(payload, secret, algorithm="HS256")

        # Valid secret
        res = jwt_tool.decode_jwt(token, secret, verify=True)
        self.assertTrue(res["valid"])
        self.assertEqual(res["payload"]["sub"], "bob")

        # Wrong secret
        res_bad = jwt_tool.decode_jwt(token, "wrong-secret", verify=True)
        self.assertFalse(res_bad["valid"])

    def test_tamper_detection(self):
        payload = {"sub": "alice", "admin": False}
        token = jwt_tool.encode_jwt(payload, self.priv_pem, algorithm="RS256")
        parts = token.split(".")

        # Tamper payload
        tampered_payload = jwt_tool.base64url_encode(b'{"sub":"alice","admin":true}')
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        res = jwt_tool.decode_jwt(tampered_token, self.pub_pem, verify=True)
        self.assertFalse(res["valid"])

    def test_exp_claim(self):
        # Expired token
        past_exp = int(time.time()) - 3600
        token_expired = jwt_tool.encode_jwt({"sub": "user", "exp": past_exp}, self.priv_pem, algorithm="RS256")
        res = jwt_tool.decode_jwt(token_expired, self.pub_pem, verify=True)
        self.assertTrue(res["valid"])
        self.assertTrue(res["expired"])

        # Future token
        future_exp = int(time.time()) + 3600
        token_future = jwt_tool.encode_jwt({"sub": "user", "exp": future_exp}, self.priv_pem, algorithm="RS256")
        res2 = jwt_tool.decode_jwt(token_future, self.pub_pem, verify=True)
        self.assertTrue(res2["valid"])
        self.assertFalse(res2["expired"])

    def test_none_algorithm(self):
        token = jwt_tool.encode_jwt({"sub": "guest"}, algorithm="none")
        self.assertTrue(token.endswith("."))
        res = jwt_tool.decode_jwt(token, verify=True)
        self.assertTrue(res["valid"])
        self.assertEqual(res["header"]["alg"], "NONE")

    def test_node_cross_verification(self):
        payload = {"sub": "node-verify-test"}
        token = jwt_tool.encode_jwt(payload, self.priv_pem, algorithm="RS256")

        node_script = f"""
        const crypto = require('crypto');
        const token = {json.dumps(token)};
        const pubKey = {json.dumps(self.pub_pem)};

        const parts = token.split('.');
        const data = Buffer.from(parts[0] + '.' + parts[1]);
        let sigB64 = parts[2].replace(/-/g, '+').replace(/_/g, '/');
        while (sigB64.length % 4) sigB64 += '=';
        const sig = Buffer.from(sigB64, 'base64');

        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(data);
        const ok = verifier.verify(pubKey, sig);
        process.stdout.write(ok ? 'VERIFIED' : 'FAILED');
        """
        proc = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
        self.assertEqual(proc.stdout.strip(), "VERIFIED")

    def test_decode_without_key(self):
        payload = {"sub": "user_no_key", "role": "viewer", "custom_id": 999}
        token = jwt_tool.encode_jwt(payload, self.priv_pem, algorithm="RS256")

        # Decode without providing any public key
        res = jwt_tool.decode_jwt(token, key=None, verify=True)
        self.assertTrue(res["unverified"])
        self.assertEqual(res["header"]["alg"], "RS256")
        self.assertEqual(res["payload"]["sub"], "user_no_key")
        self.assertEqual(res["payload"]["custom_id"], 999)

        # Decode with verify=False
        res_no_verify = jwt_tool.decode_jwt(token, key=None, verify=False)
        self.assertTrue(res_no_verify["unverified"])
        self.assertEqual(res_no_verify["payload"]["role"], "viewer")

    def test_generate_timestamps(self):
        ts = jwt_tool.generate_timestamps(expires_in=1800, include_nbf=True)
        self.assertIn("iat", ts)
        self.assertIn("exp", ts)
        self.assertIn("nbf", ts)
        self.assertEqual(ts["exp"] - ts["iat"], 1800)
        self.assertEqual(ts["nbf"], ts["iat"])

        # Test in encode_jwt
        token = jwt_tool.encode_jwt({"sub": "auto_ts"}, self.priv_pem, algorithm="RS256", add_timestamps=True, expires_in=7200)
        decoded = jwt_tool.decode_jwt(token, self.pub_pem, verify=True)
        self.assertEqual(decoded["payload"]["exp"] - decoded["payload"]["iat"], 7200)

if __name__ == "__main__":
    unittest.main()

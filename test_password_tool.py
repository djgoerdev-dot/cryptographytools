import unittest
import string
import subprocess
import password_tool

class TestPasswordTool(unittest.TestCase):
    def test_generate_password_length_and_charset(self):
        pwd = password_tool.generate_password(64)
        self.assertEqual(len(pwd), 64)
        allowed = set(string.ascii_letters + string.digits)
        self.assertTrue(all(c in allowed for c in pwd))

    def test_randomness(self):
        p1 = password_tool.generate_password(64)
        p2 = password_tool.generate_password(64)
        self.assertNotEqual(p1, p2)

    def test_hash_format_and_verification(self):
        pwd = password_tool.generate_password(64)
        h = password_tool.hash_password(pwd, cost=10, prefix="2y")
        self.assertEqual(len(h), 60)
        self.assertTrue(h.startswith("$2y$10$"))

        # Verify matching password
        self.assertTrue(password_tool.verify_password(pwd, h))

        # Verify mismatched password
        self.assertFalse(password_tool.verify_password(pwd + "x", h))

    def test_custom_cost_and_prefix(self):
        pwd = "SimplePassword123"
        h = password_tool.hash_password(pwd, cost=8, prefix="2b")
        self.assertTrue(h.startswith("$2b$08$"))
        self.assertTrue(password_tool.verify_password(pwd, h))

    def test_php_cross_verification(self):
        """Verify that PHP's native password_verify function validates our hash."""
        pwd = password_tool.generate_password(64)
        h = password_tool.hash_password(pwd, cost=10, prefix="2y")

        php_script = f"""
        $pwd = '{pwd}';
        $hash = '{h}';
        if (password_verify($pwd, $hash)) {{
            echo "VERIFIED";
        }} else {{
            echo "FAILED";
        }}
        """
        proc = subprocess.run(["php", "-r", php_script], capture_output=True, text=True, check=True)
        self.assertEqual(proc.stdout.strip(), "VERIFIED")

    def test_php_hash_verified_by_python(self):
        """Verify that Python's verify_password validates a hash produced by PHP."""
        pwd = password_tool.generate_password(64)
        php_script = f"""
        $pwd = '{pwd}';
        echo password_hash($pwd, PASSWORD_BCRYPT, ['cost' => 10]);
        """
        proc = subprocess.run(["php", "-r", php_script], capture_output=True, text=True, check=True)
        php_hash = proc.stdout.strip()

        self.assertTrue(php_hash.startswith("$2y$10$"))
        self.assertTrue(password_tool.verify_password(pwd, php_hash))

if __name__ == "__main__":
    unittest.main()

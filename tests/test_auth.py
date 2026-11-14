import json
import tempfile
import unittest
from pathlib import Path

from app.auth import create_admin, hash_password, validate_password, validate_username, verify_password


class AuthTests(unittest.TestCase):
    def test_password_policy_and_hash(self):
        with self.assertRaises(ValueError):
            validate_password("too-short")
        record = {"password": hash_password("Correct-Horse-42!")}
        self.assertTrue(verify_password("Correct-Horse-42!", record))
        self.assertFalse(verify_password("Wrong-Horse-42!", record))

    def test_username_policy(self):
        self.assertEqual(validate_username("archive.admin"), "archive.admin")
        with self.assertRaises(ValueError):
            validate_username("no spaces allowed")

    def test_first_setup_cannot_overwrite_account(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.json"
            create_admin(path, "archive-admin", "Correct-Horse-42!")
            stored = json.loads(path.read_text())
            self.assertEqual(stored["username"], "archive-admin")
            self.assertNotIn("Correct-Horse-42!", path.read_text())
            with self.assertRaises(ValueError):
                create_admin(path, "another-admin", "Another-Good-42!")


if __name__ == "__main__":
    unittest.main()

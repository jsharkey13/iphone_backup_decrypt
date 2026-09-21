import unittest
from unittest.mock import patch

from iphone_backup_decrypt import utils


class KeybagIterationLimitTests(unittest.TestCase):
    @staticmethod
    def keybag(*, dpic=10_000_000, iterations=10_000):
        keybag = utils.BackupKeyBag.__new__(utils.BackupKeyBag)
        keybag.attrs = {
            b"DPSL": b"dpsl",
            b"DPIC": dpic,
            b"SALT": b"salt",
            b"ITER": iterations,
        }
        keybag.classes_data = {}
        keybag.classes_keys = {}
        return keybag

    def test_accepts_expected_iteration_counts(self):
        keybag = self.keybag()
        with patch.object(utils, "pbkdf2_hmac", return_value=b"k" * 32) as pbkdf2:
            self.assertTrue(keybag.unlock_with_passphrase(b"password"))
        self.assertEqual(pbkdf2.call_count, 2)

    def test_rejects_excessive_dpic_before_running_pbkdf2(self):
        keybag = self.keybag(dpic=utils._MAX_DPIC_ITERATIONS + 1)
        with patch.object(utils, "pbkdf2_hmac") as pbkdf2:
            with self.assertRaisesRegex(ValueError, "DPIC"):
                keybag.unlock_with_passphrase(b"password")
        pbkdf2.assert_not_called()

    def test_rejects_excessive_iter_before_running_pbkdf2(self):
        keybag = self.keybag(iterations=utils._MAX_ITER_ITERATIONS + 1)
        with patch.object(utils, "pbkdf2_hmac") as pbkdf2:
            with self.assertRaisesRegex(ValueError, "ITER"):
                keybag.unlock_with_passphrase(b"password")
        pbkdf2.assert_not_called()

    def test_rejects_nonpositive_or_noninteger_counts(self):
        for field, value in (("dpic", 0), ("iterations", -1), ("dpic", "10000")):
            with self.subTest(field=field, value=value):
                keybag = self.keybag(**{field: value})
                with patch.object(utils, "pbkdf2_hmac") as pbkdf2:
                    with self.assertRaises(ValueError):
                        keybag.unlock_with_passphrase(b"password")
                pbkdf2.assert_not_called()


if __name__ == "__main__":
    unittest.main()

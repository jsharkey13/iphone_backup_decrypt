import os
import unittest
from unittest.mock import patch

from iphone_backup_decrypt.utils import backup_file_path


class BackupFilePathTests(unittest.TestCase):
    def test_accepts_lowercase_sha1_file_id(self):
        backup_folder = os.path.abspath("backup")
        file_id = "a" * 40
        self.assertEqual(
            backup_file_path(backup_folder, file_id),
            os.path.realpath(os.path.join(backup_folder, "aa", file_id)),
        )

    def test_rejects_manifest_path_instead_of_file_id(self):
        backup_folder = os.path.abspath("backup")
        for file_id in ("../../secrets.db", "/etc/shadow", r"C:\Users\victim\data.db"):
            with self.subTest(file_id=file_id):
                with self.assertRaises(ValueError):
                    backup_file_path(backup_folder, file_id)

    def test_rejects_noncanonical_file_ids(self):
        backup_folder = os.path.abspath("backup")
        for file_id in ("a" * 39, "a" * 41, "A" * 40, "g" * 40, None, b"a" * 40):
            with self.subTest(file_id=file_id):
                with self.assertRaises(ValueError):
                    backup_file_path(backup_folder, file_id)

    def test_rejects_resolved_path_that_escapes_backup(self):
        backup_folder = os.path.abspath("backup")
        outside_file = os.path.abspath("outside.db")
        file_id = "a" * 40
        with patch(
            "iphone_backup_decrypt.utils.os.path.realpath",
            side_effect=(backup_folder, outside_file),
        ):
            with self.assertRaises(ValueError):
                backup_file_path(backup_folder, file_id)


if __name__ == "__main__":
    unittest.main()

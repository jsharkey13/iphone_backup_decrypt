import os
import unittest

from iphone_backup_decrypt.utils import safe_output_path


class SafeOutputPathTests(unittest.TestCase):
    output_folder = os.path.abspath("test-output")

    def test_allows_path_below_output_folder(self):
        result = safe_output_path(self.output_folder, "HomeDomain", "Library", "file.db")
        self.assertEqual(
            result,
            os.path.realpath(os.path.join(self.output_folder, "HomeDomain", "Library", "file.db")),
        )

    def test_rejects_parent_traversal(self):
        with self.assertRaises(ValueError):
            safe_output_path(self.output_folder, os.pardir, "outside", "file.db")

    def test_rejects_absolute_path(self):
        unsafe_path = os.path.join(os.path.abspath(os.sep), "outside", "file.db")
        with self.assertRaises(ValueError):
            safe_output_path(self.output_folder, unsafe_path)


if __name__ == "__main__":
    unittest.main()

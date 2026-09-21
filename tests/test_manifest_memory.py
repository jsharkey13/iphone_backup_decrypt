import io
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import Crypto.Cipher.AES

from iphone_backup_decrypt import utils
from iphone_backup_decrypt.iphone_backup import EncryptedBackup


class NonClosingBytesIO(io.BytesIO):
    def close(self):
        pass


class RecordingBytesIO(NonClosingBytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.read_sizes = []

    def read(self, size=-1):
        self.read_sizes.append(size)
        return super().read(size)


class ManifestMemoryTests(unittest.TestCase):
    def test_manifest_cbc_decryption_reads_bounded_chunks(self):
        key = b"k" * 32
        plaintext = b"p" * (utils._CHUNK_SIZE + 32)
        padding = b"\x10"*16
        encrypted = Crypto.Cipher.AES.new(
            key, Crypto.Cipher.AES.MODE_CBC, iv=b"\x00" * 16
        ).encrypt(plaintext + padding)
        encrypted_file = RecordingBytesIO(encrypted)
        decrypted_file = NonClosingBytesIO()
        decrypted_file.name = "fake-filename"

        with patch("builtins.open", side_effect=(encrypted_file,)):
            with patch("tempfile.NamedTemporaryFile", side_effect=(decrypted_file,)):
                with patch("os.replace"):
                    utils.aes_decrypt_chunked(
                        in_filename="Manifest.db",
                        key=key,
                        out_filepath="decrypted.db",
                    )

        self.assertEqual(decrypted_file.getvalue(), plaintext)
        self.assertTrue(encrypted_file.read_sizes)
        self.assertLessEqual(max(encrypted_file.read_sizes), utils._CHUNK_SIZE)

    def test_bulk_extraction_iterates_cursor_without_fetchall(self):
        rows = [
            ("a" * 40, "HomeDomain", "Library/one.db", b"plist-one"),
            ("b" * 40, "HomeDomain", "Library/two.db", b"plist-two"),
        ]
        cursor1 = MagicMock()
        cursor1.fetchone.return_value = (len(rows),)
        cursor2 = MagicMock()
        cursor2.__iter__.return_value = iter(rows)
        connection = MagicMock()
        connection.cursor.side_effect = (cursor1, cursor2)

        backup = EncryptedBackup.__new__(EncryptedBackup)
        backup._temp_manifest_db_conn = connection
        backup.keybag = MagicMock()
        backup._cleanup = lambda: None

        file_plist = MagicMock(mtime=None, protection_class=1, encryption_key=b"key")
        with (
            patch("iphone_backup_decrypt.iphone_backup.os.makedirs"),
            patch("iphone_backup_decrypt.iphone_backup.utils.FilePlist", return_value=file_plist),
            patch.object(backup, "_decrypt_file_to_disk") as decrypt_file,
        ):
            extracted = backup.extract_files(relative_paths_like="%", output_folder="output")

        self.assertEqual(extracted, len(rows))
        self.assertEqual(decrypt_file.call_count, len(rows))
        cursor2.fetchall.assert_not_called()
        cursor1.close.assert_called_once()
        cursor2.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()

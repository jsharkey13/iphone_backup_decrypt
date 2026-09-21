import os
import plistlib
import re
import struct
import tempfile

import Crypto.Cipher.AES

try:
    # Prefer a fast, pure C++ implementation:
    from fastpbkdf2 import pbkdf2_hmac
except ImportError:
    # Otherwise, use pycryptodome - wrapping it to look like the standard library method signature.
    # It is 2-3x faster than the standard library 'hashlib.pbkdf2_hmac' method, but still 2x slower than fastpbkdf2.
    import Crypto.Hash
    import Crypto.Protocol.KDF
    HASH_FNS = {"sha1": Crypto.Hash.SHA1, "sha256": Crypto.Hash.SHA256}

    def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
        return Crypto.Protocol.KDF.PBKDF2(password, salt, dklen, iterations, hmac_hash_module=HASH_FNS[hash_name])


__all__ = ["BackupKeyBag", "DomainLike", "FilePlist", "MatchFiles", "RelativePath", "RelativePathsLike",
           "aes_decrypt_cbc", "aes_decrypt_chunked", "aes_unwrap",
           "backup_file_path", "safe_output_path"]


_AES_BLOCK_SIZE = Crypto.Cipher.AES.block_size
_CHUNK_SIZE = 1024**2  # 1MB blocks, must be a multiple of 16 bytes.
_FILE_ID_PATTERN = re.compile(r"[0-9a-f]{40}")
_MAX_DPIC_ITERATIONS = 20_000_000
_MAX_ITER_ITERATIONS = 1_000_000


class RelativePath:
    """Relative paths for commonly accessed files."""

    # Standard iOS file locations:
    ADDRESS_BOOK = "Library/AddressBook/AddressBook.sqlitedb"
    TEXT_MESSAGES = "Library/SMS/sms.db"
    CALL_HISTORY = "Library/CallHistoryDB/CallHistory.storedata"
    NOTES = "Library/Notes/notes.sqlite"
    CALENDARS = "Library/Calendar/Calendar.sqlitedb"
    HEALTH = "Health/healthdb.sqlite"
    HEALTH_SECURE = "Health/healthdb_secure.sqlite"
    SAFARI_HISTORY = "Library/Safari/History.db"
    SAFARI_BOOKMARKS = "Library/Safari/Bookmarks.db"

    # Very common external files:
    WHATSAPP_MESSAGES = "ChatStorage.sqlite"
    WHATSAPP_CONTACTS = "ContactsV2.sqlite"


class RelativePathsLike:
    """Relative path wildcards for commonly accessed groups of files."""

    # A wildcard, use at own risk:
    ALL_FILES = "%"

    # Standard iOS file locations:
    CAMERA_ROLL = "Media/DCIM/%APPLE/IMG%.%"
    ICLOUD_PHOTOS = "Media/PhotoData/CPLAssets/group%/%.%"
    SMS_ATTACHMENTS = "Library/SMS/Attachments/%.%"
    VOICEMAILS = "Library/Voicemail/%.amr"
    VOICE_RECORDINGS = "Library/Recordings/%"
    ICLOUD_LOCAL_FILES = "Library/Mobile Documents/com~apple~CloudDocs/%"

    # WhatsApp makes .thumb files for every media item, so maybe specifically extract JPG or MP4:
    WHATSAPP_ATTACHED_IMAGES = "Message/Media/%.jpg"
    WHATSAPP_ATTACHED_VIDEOS = "Message/Media/%.mp4"
    # But allow full export if desired:
    WHATSAPP_ATTACHMENTS = "Message/Media/%.%"


class DomainLike:
    """Domain wildcards for commonly accessed apps and services."""

    # Standard iOS domains:
    HOME_DOMAIN = "HomeDomain"
    CAMERA_ROLL = "CameraRollDomain"
    FILES_ON_IPHONE = "AppDomainGroup-group.com.apple.FileProvider.LocalStorage"

    # Third party apps:
    WHATSAPP = "%net.whatsapp.%"  # WhatsApp has several domains, all with this common section.


class MatchFiles:
    """Paired relative paths and domains for more complex matching.

       Use items from this class with EncryptedBackup.extract_files, e.g:
           backup.extract_files(**MatchFiles.CAMERA_ROLL, output_folder="./output")
    """

    CAMERA_ROLL = {"relative_paths_like": RelativePathsLike.CAMERA_ROLL, "domain_like": DomainLike.CAMERA_ROLL}
    ICLOUD_PHOTOS = {"relative_paths_like": RelativePathsLike.ICLOUD_PHOTOS, "domain_like": DomainLike.CAMERA_ROLL}
    CHROME_DOWNLOADS = {"relative_paths_like": "Documents/%", "domain_like": "AppDomain-com.google.chrome.ios"}
    STRAVA_WORKOUTS = {"relative_paths_like": "Documents/%.fit", "domain_like": "AppDomain-com.strava.stravaride"}
    WHATSAPP_ATTACHMENTS = {"relative_paths_like": RelativePathsLike.WHATSAPP_ATTACHMENTS,
                            "domain_like": DomainLike.WHATSAPP}
    WHATSAPP_CONTACT_PHOTOS = {"relative_paths_like": "Media/Profile/%.jpg", "domain_like": DomainLike.WHATSAPP}


class FilePlist:

    def __init__(self, bplist_bytes):
        """
        Represent a Manifest.db file-record PList object in an easily accessible manner.

        :param bplist_bytes:
            The binary PList data extracted from the relevant row of the Manifest database.
        """
        # Parse the actual binary PList object:
        self.plist = plistlib.loads(bplist_bytes)
        # Common and useful attributes:
        self._data = self.plist['$objects'][self.plist['$top']['root'].data]
        self.created = self._data.get("Birth")
        self.mtime = self._data.get("LastModified")
        self.filesize = int(self._data.get("Size"))
        self.protection_class = self._data['ProtectionClass']
        self.encryption_key = self.plist['$objects'][self._data['EncryptionKey'].data]['NS.data'][4:] if 'EncryptionKey' in self._data else None
        self.target = self.plist['$objects'][self._data['Target'].data] if 'Target' in self._data else None
        self.mode = f"{self._data.get('Mode', 0):06o}"  # Store as string in octal form.


class BackupKeyBag:

    _WRAP_PASSPHRASE = 2

    def __init__(self, keybag_bytes):
        """
        Load BackupKeyBag data from Manifest.plist into a usable form.

        The BackupKeyBag data is protected by a key derived from the user's backup passphrase.
        The individual protection class keys must be unwrapped by unlocking the KeyBag with this key
        before 'unwrap_key_for_class()' can be called.

        :param keybag_bytes:
            The bytes from Manifest.plist's 'BackupKeyBag' object.
        """
        self.unlocked = False
        self.type = None
        self.uuid = None
        self.wrap = None
        self.attrs = {}
        self.classes_data = {}
        self.classes_keys = {}
        self.passphrase_key = None
        self._parse_bytes(keybag_bytes)

    @staticmethod
    def _get_tlv_blocks(tlv_bytes):
        block_start = 0
        while (block_end := block_start + 8) <= len(tlv_bytes):
            tag = tlv_bytes[block_start:block_start+4]
            length = struct.unpack(">L", tlv_bytes[block_start+4:block_end])[0]
            data = tlv_bytes[block_end:block_end+length]
            yield tag, data
            block_start = block_end + length

    @staticmethod
    def _validate_iterations(value, field_name, maximum):
        if not isinstance(value, int) or value < 1 or value > maximum:
            raise ValueError(f"Invalid BackupKeybag {field_name} iteration count {repr(value)};" +
                             f" expected an integer between 1 and {maximum}!")
        return value

    def _parse_bytes(self, keybag_bytes):
        current_class_key = None

        for tag, data in BackupKeyBag._get_tlv_blocks(keybag_bytes):
            if len(data) == 4:
                data = struct.unpack(">L", data)[0]
            if tag == b"TYPE":
                self.type = int(data)
                if self.type > 3:
                    raise ValueError(f"Unexpected BackupKeyBag type! ({self.type} > 3)")
            elif tag == b"UUID" and self.uuid is None:
                # First UUID is global.
                self.uuid = data
            elif tag == b"WRAP" and self.wrap is None:
                # First WRAP is global.
                self.wrap = data
            elif tag == b"UUID":
                # Further UUIDs mark start of new class key block; store old one and start a new one:
                if current_class_key:
                    self.classes_data[current_class_key[b"CLAS"]] = current_class_key
                current_class_key = {b"UUID": data}
            elif tag in [b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"]:
                if current_class_key:
                    current_class_key[tag] = data
                else:
                    raise ValueError("Unexpected BackupKeyBag format!")
            else:
                self.attrs[tag] = data
        if current_class_key:
            self.classes_data[current_class_key[b"CLAS"]] = current_class_key

    def unlock_with_key(self, passphrase_key):
        """
        Unlock the BackupKeyBag with the passphrase-derived key directly.

        This is faster than deriving the key from the passphrase in 'unlock_with_passphrase()'.

        :param passphrase_key:
            The derived key bytes.

        :return: whether all protection class keys were successfully unlocked.
        """
        self.passphrase_key = passphrase_key
        for protection_class, class_data in self.classes_data.items():
            if b"WPKY" not in class_data:
                continue
            if class_data[b"WRAP"] & BackupKeyBag._WRAP_PASSPHRASE:
                try:
                    self.classes_keys[protection_class] = aes_unwrap(key_encryption_key=self.passphrase_key,
                                                                     wrapped_key=class_data[b"WPKY"])
                except ValueError:
                    return False
        self.unlocked = True
        return True

    def unlock_with_passphrase(self, passphrase):
        """
        Unlock the BackupKeyBag with the backup encryption passphrase.

        This is slower than deriving the key from the passphrase in 'unlock_with_key()';
        if the passphrase will not change, consider recording the 'passphrase_key' attribute
        after successful unlock and using that for future unlocking.

        :param passphrase:
            The passphrase chosen when the encrypted backup was first created, as a string.

        :return: whether all protection class keys were successfully unlocked.
        """
        # Validate iteration counts before attempting to use them:
        dpic_iterations = BackupKeyBag._validate_iterations(self.attrs[b"DPIC"], "DPIC", _MAX_DPIC_ITERATIONS)
        iter_iterations = BackupKeyBag._validate_iterations(self.attrs[b"ITER"], "ITER", _MAX_ITER_ITERATIONS)
        # Decrypt main backup key:
        passphrase_round1 = pbkdf2_hmac('sha256', passphrase, self.attrs[b"DPSL"], dpic_iterations, 32)
        passphrase_key = pbkdf2_hmac('sha1', passphrase_round1, self.attrs[b"SALT"], iter_iterations, 32)
        return self.unlock_with_key(passphrase_key)

    def unwrap_key_for_class(self, protection_class, wrapped_file_key):
        """
        Use the protection class keys to unwrap a wrapped file key from Manifest.db.

        The BackupKeyBag must be unlocked before using this method.

        The decryption keys in Manifest.db are wrapped using protection class specific keys using
        the RFC3394 Key Wrap Algorithm, and so must be unwrapped using the keys stored in
        this KeyBag. The keys in this KeyBag are themselves wrapped using a key derived from the
        user's backup passphrase.
        The returned unwrapped key can be used to decrypt the file directly using 'aes_decrypt_cbc()'
        or 'aes_decrypt_chunked()'.

        :param protection_class:
            The protection class of the file of interest.
        :param wrapped_file_key:
            The key found in the binary PList data in Manifest.db for the file of interest.

        :return: the unwrapped file key.
        """
        if not self.unlocked:
            raise ValueError("BackupKeyBag must be unlocked before using this method!")
        class_key = self.classes_keys.get(protection_class)
        if class_key is None:
            raise RuntimeError(f"Key for protection class {protection_class} not present in BackupKeyBag!")
        if len(wrapped_file_key) != 0x28:
            raise ValueError("Invalid wrapped file key length!")
        return aes_unwrap(key_encryption_key=class_key, wrapped_key=wrapped_file_key)


def _safe_path_join(root_folder, *untrusted_parts):
    """
    Join untrusted file paths to a root folder preventing path traversal outside the root.

    :param root_folder:
        The base folder that generated file paths must not escape.
    :param *untrusted_parts:
        The untrusted path segments to join underneath the root folder.

    :return: a safe absolute filepath.
    :raises ValueError:
        If the untrusted parts lead to directory traversal outside the root folder.
    """
    if not all(isinstance(part, str) for part in untrusted_parts):
        raise ValueError("Path components must be strings!")

    true_root = os.path.realpath(os.path.abspath(root_folder))
    joined_path = os.path.realpath(os.path.abspath(os.path.join(true_root, *untrusted_parts)))
    try:
        is_within_output = os.path.commonpath((true_root, joined_path)) == true_root
    except ValueError:
        is_within_output = False
    if not is_within_output:
        path_items = (root_folder,) + untrusted_parts
        raise ValueError(f"Unsafe path join {repr(path_items)} leads to {repr(joined_path)}!")
    return joined_path


def backup_file_path(backup_folder, file_id):
    """
    Generate the filepath for a file in the backup by file ID.

    :param backup_folder:
        The backup folder root.
    :param file_id:
        The file ID.

    :return: a safe absolute filepath to that file in the backup.
    :raises ValueError:
        If the generated path leads to directory traversal outside backup_folder.
    """
    if not isinstance(file_id, str) or _FILE_ID_PATTERN.fullmatch(file_id) is None:
        raise ValueError(f"Invalid backup file ID: {repr(file_id)}")

    try:
        return _safe_path_join(backup_folder, file_id[:2], file_id)
    except ValueError as e:
        raise ValueError("Backup file path escapes backup folder!") from e


def safe_output_path(output_folder, *untrusted_parts):
    """
    Generate an output path safely contained inside output_folder.

    :param output_folder:
        The output folder that generated file paths must not escape.
    :param *untrusted_parts:
        The untrusted path segments to join underneath the output folder.

    :return: a safe absolute filepath.
    :raises ValueError:
        If the untrusted parts lead to directory traversal outside the root directory.
    """
    try:
        return _safe_path_join(output_folder, *untrusted_parts)
    except ValueError as e:
        raise ValueError("Generated output path escapes output folder!") from e


def aes_unwrap(*, key_encryption_key, wrapped_key):
    """
    Unwrap a key wrapped using RFC3394 Key Wrap Algorithm.

    :param key_encryption_key:
        The outer encryption key used to wrap the inner key.
    :param wrapped_key:
        The wrapped key to unwrap.
    :return: the bytes of the unwrapped key.
    """
    return Crypto.Cipher.AES.new(key_encryption_key, Crypto.Cipher.AES.MODE_KW).unseal(wrapped_key)


def aes_decrypt_cbc(*, data, key):
    """
    Decrypt a block of AES encrypted data in CBC mode.

    :param data:
        The bytes to decrypt.
    :param key:
        The symmetric key to decrypt the data with.

    :return: the bytes of the decrypted data.
    """
    if len(data) % _AES_BLOCK_SIZE != 0:
        raise ValueError(f"Data for AES decryption length not a multiple of {_AES_BLOCK_SIZE}!")
    return Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv=b"\x00" * _AES_BLOCK_SIZE).decrypt(data)


def aes_decrypt_chunked(*, in_filename, key, out_filepath):
    """
    Decrypt an AES encrypted file in chunks, to avoid memory exhaustion.

    :param in_filename:
        The filename to open and read the encrypted bytes from.
    :param key:
        The symmetric key to decrypt the file with.
    :param out_filepath:
        The filename to write the decrypted bytes to.

    :return: the final size of the decrypted file.
    """
    # Initialise AES cipher:
    aes_cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv=b"\x00" * _AES_BLOCK_SIZE)
    # Open the input and output files:
    output_directory = os.path.dirname(out_filepath)
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)
    with open(in_filename, 'rb') as enc_filehandle:
        # Check total size of file is correct, padded to multiple of _AES_BLOCK_SIZE:
        enc_filehandle.seek(0, os.SEEK_END)
        enc_size = enc_filehandle.tell()
        if enc_size % _AES_BLOCK_SIZE != 0:
            raise ValueError(f"Data for AES decryption length not a multiple of {_AES_BLOCK_SIZE}!")
        # Decrypt chunks from input file, write to output, remove trailing padding.
        # This avoids having the whole file in-memory at one time; essential for large files!
        # Use a temporary file and create the true output file only on success.
        enc_filehandle.seek(0)
        dec_size = 0
        temp_filehandle = tempfile.NamedTemporaryFile(dir=os.path.dirname(out_filepath), delete=False)
        try:
            with temp_filehandle:
                while enc_data := enc_filehandle.read(_CHUNK_SIZE):
                    dec_data = aes_cipher.decrypt(enc_data)
                    if enc_filehandle.tell() == enc_size:
                        # This is the last chunk, which should have padding.
                        #  (c.f. google_iphone_dataprotection.removePadding)
                        n = int(dec_data[-1])  # RFC 1423, final byte contains number of padding bytes.
                        # Check padding is valid (n sensible, last n bytes identical):
                        n_invalid = n == 0 or n > _AES_BLOCK_SIZE or n > len(dec_data)
                        padding_invalid = dec_data[-1:]*n != dec_data[-n:]
                        if n_invalid or padding_invalid:
                            raise ValueError('Invalid CBC padding on decrypted data!')
                        # Remove the padding:
                        dec_data = dec_data[:-n]
                    temp_filehandle.write(dec_data)
                # Track the final decrypted size:
                dec_size = temp_filehandle.tell()
            # Move the temporary file to the intended output filepath atomically:
            os.replace(temp_filehandle.name, out_filepath)
        except Exception:
            if os.path.exists(temp_filehandle.name):
                os.remove(temp_filehandle.name)
            raise
        # Return the size of the decrypted file:
        return dec_size


def remove_cbc_padding(data, blocksize=_AES_BLOCK_SIZE):
    """
    Remove the padding from CBC mode decrypted data.

    Based on google_iphone_dataprotection.removePadding,
    but validating that the padding is present and in the
    format expected.

    :param data:
        The decrypted bytes, which ought to end with block padding.
    :param blocksize:
        The size of the CBC block.

    :return: the data with the padding removed.
    """
    # Modified version of the original function above to check padding validity.
    n = int(data[-1])  # RFC 1423, final byte contains number of padding bytes.
    # Check padding is valid (n sensible, last n bytes identical):
    n_invalid = n == 0 or n > blocksize or n > len(data)
    padding_invalid = data[-1:]*n != data[-n:]
    if n_invalid or padding_invalid:
        raise ValueError('Invalid CBC padding on decrypted data!')
    return data[:-n]

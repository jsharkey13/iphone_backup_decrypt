import os
import plistlib

import Crypto.Cipher.AES

__all__ = ["RelativePath", "RelativePathsLike", "DomainLike", "MatchFiles", "FilePlist", "aes_decrypt_chunked"]


_CBC_BLOCK_SIZE = 16  # bytes.
_CHUNK_SIZE = 100 * 1024**2  # 100MB blocks, must be a multiple of 16 bytes.


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
        self.data = self.plist['$objects'][self.plist['$top']['root'].data]
        self.mtime = self.data.get("LastModified")
        self.filesize = int(self.data.get("Size"))
        self.protection_class = self.data['ProtectionClass']
        self.encryption_key = self.plist['$objects'][self.data['EncryptionKey'].data]['NS.data'][4:] if 'EncryptionKey' in self.data else None


def aes_decrypt_chunked(*, in_filename, file_plist, key, out_filepath):
    """
    Decrypt a large iOS backup file in chunks, to avoid memory exhaustion.

    :param in_filename:
        The filename to open and read the encrypted bytes from, should be inside the backup directory.
    :param file_plist:
        The FilePlist object containing important metadata about the encrypted file.
    :param key:
        The derived symmetric key to decrypt the file with.
    :param out_filepath:
        The filename to write the decrypted bytes to.
    """
    # Initialise AES cipher:
    aes_cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv=b"\x00" * 16)
    # Open the input and output files:
    output_directory = os.path.dirname(out_filepath)
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)
    enc_filehandle = open(in_filename, 'rb')
    dec_filehandle = open(out_filepath, 'wb')
    # Check total size of file is correct, padded to multiple of 16:
    enc_filehandle.seek(0, os.SEEK_END)
    enc_size = enc_filehandle.tell()
    if enc_size % _CBC_BLOCK_SIZE:
        raise ValueError("AES decrypt: data length not /16!")
    # Decrypt chunks from input file, write to output, remove trailing padding.
    # This avoids having the whole file in-memory at one time; essential for large files!
    enc_filehandle.seek(0)
    while enc_data := enc_filehandle.read(_CHUNK_SIZE):
        dec_data = aes_cipher.decrypt(enc_data)
        if enc_filehandle.tell() == enc_size:
            # This is the last chunk, remove any padding (c.f. google_iphone_dataprotection.removePadding):
            n = int(dec_data[-1])  # RFC 1423, final byte contains number of padding bytes.
            if n > _CBC_BLOCK_SIZE or n > len(dec_data):
                raise ValueError('AES decrypt: invalid CBC padding')
            dec_data = dec_data[:-n]
        dec_filehandle.write(dec_data)
    # Check output size:
    if dec_filehandle.tell() != file_plist.filesize:
        print(f"WARN: decrypted {dec_filehandle.tell()} bytes of '{out_filepath}', expected {file_plist.size} bytes!")
    # Close filehandles:
    enc_filehandle.close()
    dec_filehandle.close()
    # Set the correct last_modified time on the output file, if possible:
    if file_plist.mtime:
        os.utime(out_filepath, times=(file_plist.mtime, file_plist.mtime))

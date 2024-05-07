import os
import plistlib

import Crypto.Cipher.AES

__all__ = ["FilePlist", "aes_decrypt_chunked"]


_CBC_BLOCK_SIZE = 16  # bytes.
_CHUNK_SIZE = 100 * 1024**2  # 100MB blocks, must be a multiple of 16 bytes.


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

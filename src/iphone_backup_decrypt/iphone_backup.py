import os.path
import plistlib
import shutil
import sqlite3
import struct
import tempfile
from contextlib import contextmanager

from . import utils

__all__ = ["EncryptedBackup"]


# Based on https://stackoverflow.com/questions/1498342/how-to-decrypt-an-encrypted-apple-itunes-iphone-backup
# and code sample provided by @andrewdotn in this answer: https://stackoverflow.com/a/13793043
class EncryptedBackup:

    def __init__(self, *, backup_directory, passphrase):
        """
        Decrypt an iOS encrypted backup using the passphrase chosen in iTunes.

        The passphrase and decryption keys will be stored in memory whilst using this code,
        and a temporary decrypted copy of the Manifest database containing a list of all files
        in the backup will be created in a temporary folder. If run on a machine without full-disk
        encryption, this may leak the keys and reduce the overall security of the backup.
        If an exception occurs during program execution, there is a chance this decrypted Manifest
        database will not be removed. Its location is stored in '_temp_decrypted_manifest_db_path'
        which can be printed and manually inspected if desired.

        :param backup_directory:
            The path to the backup directory on disk. On Windows, this is either:
              - '%AppData%\\Apple Computer\\MobileSync\\Backup\\[device-specific-hash]'
              or, for iTunes installed via the Windows Store:
              - '%UserProfile%\\Apple\\MobileSync\\Backup\\[device-specific-hash]'
            The folder should contain 'Manifest.db' and 'Manifest.plist' if it contains a valid backup.
        :param passphrase:
            The passphrase chosen in iTunes when first choosing to encrypt backups.
            If it requires an encoding other than ASCII or UTF-8, a bytes object must be provided.
        """
        # Public state:
        self.decrypted = False
        # Keep track of the backup directory, and more dangerously, keep the backup passphrase as bytes until used:
        self._backup_directory = os.path.expandvars(backup_directory)
        self._passphrase = passphrase if isinstance(passphrase, bytes) else passphrase.encode("utf-8")
        # Internals for unlocking the Keybag:
        self._manifest_plist_path = os.path.join(self._backup_directory, 'Manifest.plist')
        self._manifest_plist = None
        self._manifest_db_path = os.path.join(self._backup_directory, 'Manifest.db')
        self._keybag = None
        self._unlocked = False
        # We need a temporary file for the decrypted database, because SQLite can't open bytes in memory as a database:
        self._temporary_folder = tempfile.mkdtemp()
        self._temp_decrypted_manifest_db_path = os.path.join(self._temporary_folder, 'Manifest.db')
        # We can keep a connection to the index SQLite database open:
        self._temp_manifest_db_conn = None

    def __del__(self):
        self._cleanup()

    def _cleanup(self):
        try:
            if self._temp_manifest_db_conn is not None:
                self._temp_manifest_db_conn.close()
            shutil.rmtree(self._temporary_folder)
        except Exception:
            print("WARN: Cleanup failed. You may want to delete the decrypted temporary file found at:")
            print(f"    '{self._temp_decrypted_manifest_db_path}'")
            raise

    def _read_and_unlock_keybag(self):
        if self._unlocked:
            return self._unlocked
        # Open the Manifest.plist file we need to access the Keybag:
        with open(self._manifest_plist_path, 'rb') as infile:
            self._manifest_plist = plistlib.load(infile)
        # Is this an encrypted backup?
        if not self._manifest_plist.get("IsEncrypted"):
            raise ValueError("Backup does not look like an encrypted iOS backup!")
        # Load and unlock the keybag data:
        self._keybag = utils.BackupKeyBag(self._manifest_plist['BackupKeyBag'])
        self._unlocked = self._keybag.unlock_with_passphrase(self._passphrase)
        if not self._unlocked:
            raise ValueError("Failed to decrypt keys: incorrect passphrase?")
        # No need to keep the passphrase now:
        self._passphrase = None
        return True

    def _open_temp_database(self):
        # Check that we have successfully decrypted the file:
        if not os.path.exists(self._temp_decrypted_manifest_db_path):
            raise ValueError("Temporary Manifest.db file does not exist!")
        try:
            # Connect to the decrypted Manifest.db database if necessary:
            if self._temp_manifest_db_conn is None:
                self._temp_manifest_db_conn = sqlite3.connect(self._temp_decrypted_manifest_db_path)
            # Check that it has the expected table structure and a list of files:
            cur = self._temp_manifest_db_conn.cursor()
            # Check no huge entries in Manifest list:
            cur.execute("SELECT max(length(file)) FROM Files;")
            max_size = cur.fetchone()[0]
            cur.close()
            if max_size is None:
                # Either no valid file PList blobs, or no rows:
                raise ValueError("Manifest.db file does not contain any data!")
            if max_size > 100*1024:
                # Most blobs are around 1-3KB in size, so a 100KB limit seems sensible.
                raise ValueError("Manifest.db file contains unexpectedly huge file blobs!")
        except sqlite3.Error as e:
            raise ValueError("Fatal error whilst querying Manifest.db file!") from e

    def _decrypt_manifest_db_file(self):
        if os.path.exists(self._temp_decrypted_manifest_db_path):
            return
        # Ensure we've already unlocked the Keybag:
        self._read_and_unlock_keybag()
        # Decrypt the Manifest.db index database:
        manifest_key = self._manifest_plist['ManifestKey'][4:]
        manifest_class = struct.unpack('<l', self._manifest_plist['ManifestKey'][:4])[0]
        key = self._keybag.unwrap_key_for_class(manifest_class, manifest_key)
        utils.aes_decrypt_chunked(in_filename=self._manifest_db_path, out_filepath=self._temp_decrypted_manifest_db_path, key=key)
        # Open the temporary database to verify decryption success:
        self._open_temp_database()
        self.decrypted = True

    def _file_metadata_from_manifest(self, relative_path, domain_like=None):
        # Check arguments:
        if relative_path is None:
            raise ValueError("A relative_path must be provided!")
        # Ensure that we've initialised everything:
        if self._temp_manifest_db_conn is None:
            self._decrypt_manifest_db_file()
        # Use Manifest.db to find the on-disk filename and file metadata, including the keys, for the file.
        # The metadata is contained in the 'file' column, as a binary PList file:
        try:
            cur = self._temp_manifest_db_conn.cursor()
            if domain_like is None:
                domain_like = "%"
            query = """
                SELECT fileID, file
                FROM Files
                WHERE relativePath = ?
                AND domain LIKE ?
                AND flags=1
                ORDER BY domain, relativePath
                LIMIT 1;
            """
            cur.execute(query, (relative_path, domain_like))
            result = cur.fetchone()
        except sqlite3.Error as e:
            raise RuntimeError("Error querying Manifest database!") from e
        if not result:
            raise FileNotFoundError
        file_id, file_bplist = result
        return file_id, file_bplist

    def _get_manifest_rows_generator(self, *, relative_paths_like=None, domain_like=None, flags=None):
        # Ensure that we've initialised everything:
        if self._temp_manifest_db_conn is None:
            self._decrypt_manifest_db_file()
        # Use default values:
        if relative_paths_like is None:
            relative_paths_like = "%"
        if domain_like is None:
            domain_like = "%"
        if flags is None:
            flags = "%"
        # Get the row data from the Manifest.db file:
        try:
            cur = self._temp_manifest_db_conn.cursor()
            query = """
                SELECT fileID, domain, relativePath, file
                FROM Files
                WHERE relativePath LIKE ?
                AND domain LIKE ?
                AND flags LIKE ?
                ORDER BY domain, relativePath;
            """
            cur.execute(query, (relative_paths_like, domain_like, flags))
        except sqlite3.Error as e:
            raise RuntimeError("Error querying Manifest database!") from e
        # Loop through the results:
        for file_id, domain, matched_relative_path, file_bplist in cur:
            file_plist = utils.FilePlist(file_bplist)
            yield file_id, domain, matched_relative_path, file_plist
        # Close the cursor once the generator is done:
        cur.close()

    def _decrypt_inner_file(self, *, file_id, file_bplist):
        # Ensure we've already unlocked the Keybag:
        self._read_and_unlock_keybag()
        # Read the plist data:
        file_plist = utils.FilePlist(file_bplist)
        # Extract the decryption key from the PList data:
        if file_plist.encryption_key is None:
            raise ValueError("Path is not an encrypted file.")  # File is not encrypted; either a directory or empty.
        inner_key = self._keybag.unwrap_key_for_class(file_plist.protection_class, file_plist.encryption_key)
        # Find the encrypted version of the file on disk and decrypt it:
        filename_in_backup = utils.backup_file_path(self._backup_directory, file_id)
        with open(filename_in_backup, 'rb') as encrypted_file_filehandle:
            encrypted_data = encrypted_file_filehandle.read()
        # Decrypt the file contents:
        decrypted_data = utils.aes_decrypt_cbc(data=encrypted_data, key=inner_key)
        # Remove any padding introduced by the CBC encryption:
        file_bytes = utils.remove_cbc_padding(decrypted_data)
        # Check the data is as expected and return it:
        # Note to user if decrypted size does not match Manifest prediction.
        # See comment in _decrypt_file_to_disk below.
        if len(file_bytes) != file_plist.filesize:
            print(f"INFO: decrypted {len(file_bytes)} bytes, iOS claimed {file_plist.filesize} bytes.")
        return file_bytes

    def _decrypt_file_to_disk(self, *, file_id, key, file_plist, output_filepath):
        # Find the name of the file on disk:
        filename_in_backup = utils.backup_file_path(self._backup_directory, file_id)
        # Decrypt it to the output location:
        decrypted_size = utils.aes_decrypt_chunked(in_filename=filename_in_backup, out_filepath=output_filepath, key=key)
        # Check output size. The Manifest entry routinely reports filesizes that do not match decrypted sizes,
        # particularly for database and other 'live' filetypes. This might be an iOS bug or race condition?
        # Either way, the user should likely be made aware just in case:
        if decrypted_size != file_plist.filesize:
            print(f"INFO: decrypted {decrypted_size} bytes to '{output_filepath}', iOS claimed {file_plist.filesize} bytes.")
        # Set the correct last_modified time on the output file, if possible:
        if file_plist.mtime:
            os.utime(output_filepath, times=(file_plist.mtime, file_plist.mtime))

    def test_decryption(self):
        """Validate that the backup can be decrypted successfully."""
        # Ensure that we've initialised everything:
        if self._temp_manifest_db_conn is None:
            self._decrypt_manifest_db_file()
        return True

    def save_manifest_file(self, output_filename):
        """Save a permanent copy of the decrypted Manifest SQLite database."""
        # Ensure that we've decrypted the manifest file:
        self._decrypt_manifest_db_file()
        # Copy the decrypted file to the output:
        output_directory = os.path.dirname(output_filename)
        if output_directory:
            os.makedirs(output_directory, exist_ok=True)
        shutil.copy(self._temp_decrypted_manifest_db_path, output_filename)

    @contextmanager
    def manifest_db_cursor(self):
        """Get a cursor into the temporary copy of the Manifest file.

        The cursor is intended only for read-only querying, since the
        underlying connection object is not returned and will not
        commit the changes by default.

        Example usage:

        with backup.manifest_db_cursor() as cur:
            cur.execute("SELECT count(*) FROM Files;")
            print(cur.fetchone()[0])
        """
        # Ensure that we've decrypted the manifest file:
        self._decrypt_manifest_db_file()
        # Get and yield a cursor:
        temp_cur = self._temp_manifest_db_conn.cursor()
        yield temp_cur
        # Close it when we're done:
        temp_cur.close()

    def extract_file_as_bytes(self, relative_path, *, domain_like=None):
        """
        Decrypt a single named file and return the bytes.

        This method decrypts the file contents in-memory, and can require up to 3x the file size of free
        memory to function. If you see errors extracting the bytes of very large files, try using extract_file
        or extract_files to write the output to disk to avoid storing the encrypted and decrypted versions of
        the file in-memory at the same time.

        :param relative_path:
            The iOS 'relativePath' of the file to be decrypted. Common relative paths are provided by the
            'RelativePath' class, otherwise these can be found by opening the decrypted Manifest.db file
            and examining the Files table.
        :param domain_like:
            Optional. The iOS 'domain' for the file to be decrypted, containing '%' or '_' SQL LIKE wildcards.
            If 'relative_path' is not globally unique, a domain can be provided to restrict matching.
            Common domain wildcards are provided by the 'DomainLike' class, otherwise these can be found by opening the
            decrypted Manifest.db file and examining the Files table.

        :return: decrypted bytes of the file.
        """
        # Extract the required metadata:
        file_id, file_bplist = self._file_metadata_from_manifest(relative_path, domain_like)
        # Decrypt the requested file:
        file_bytes = self._decrypt_inner_file(file_id=file_id, file_bplist=file_bplist)
        return file_bytes

    def extract_file(self, *, relative_path, domain_like=None, output_filename):
        """
        Decrypt a single named file and save it to disk.

        This is a helper method and is exactly equivalent to extract_file_as_bytes(...) and then
        writing that data to a file.

        :param relative_path:
            The iOS 'relativePath' of the file to be decrypted. Common relative paths are provided by the
            'RelativePath' class, otherwise these can be found by opening the decrypted Manifest.db file
            and examining the Files table.
        :param domain_like:
            Optional. The iOS 'domain' for the file to be decrypted, containing '%' or '_' SQL LIKE wildcards.
            If 'relative_path' is not globally unique, a domain can be provided to restrict matching.
            Common domain wildcards are provided by the 'DomainLike' class, otherwise these can be found by opening the
            decrypted Manifest.db file and examining the Files table.
        :param output_filename:
            The filename to write the decrypted file contents to.
        """
        # Extract the required metadata:
        file_id, file_bplist = self._file_metadata_from_manifest(relative_path, domain_like)
        file_plist = utils.FilePlist(file_bplist)
        inner_key = self._keybag.unwrap_key_for_class(file_plist.protection_class, file_plist.encryption_key)
        # Decrypt the requested file:
        self._decrypt_file_to_disk(file_id=file_id, file_plist=file_plist, key=inner_key, output_filepath=output_filename)

    def extract_files(self, *, relative_paths_like=None, domain_like=None, output_folder,
                      preserve_folders=False, domain_subfolders=False, incremental=False,
                      filter_callback=None):
        """
        Decrypt files matching a relative path query and output them to a folder.

        This method is not really designed to match very loose relative paths like '%' or '%.jpg',
        but using 'preserve_folders' and 'domain_subfolders' may mitigate this.

        :param relative_paths_like:
            Optional. An iOS 'relativePath' of the files to be decrypted, containing '%' or '_' SQL LIKE wildcards.
            Common relative path wildcards are provided by the 'RelativePathsLike' class, otherwise these can be found
            by opening the decrypted Manifest.db file and examining the Files table.
            One of 'relative_paths_like' or 'domain_like' must be provided.
        :param domain_like:
            Optional. An iOS 'domain' for the files to be decrypted, containing '%' or '_' SQL LIKE wildcards.
            If a domain is provided, only files from that domain will be extracted, which can be useful for non-unique
            relative paths.
            Common domain wildcards are provided by the 'DomainLike' class, otherwise these can be found by opening the
            decrypted Manifest.db file and examining the Files table.
            One of 'relative_paths_like' or 'domain_like' must be provided.
        :param output_folder:
            The folder to write output files into. Files will be named with their internal iOS filenames and will
            overwrite anything in the output folder with that name.
        :param preserve_folders:
            If True, preserve any folder structure present in matched files, creating subfolders of
            'output_folder' as necessary. If not provided or False, file paths will be flattened to the
            single 'output_folder', which may not preserve different files with the same name.
        :param domain_subfolders:
            If True, extracted files will be split into domain subfolders inside 'output_folder'.
            This can be useful when extracting multiple domains which may have files with identical
            internal iOS filenames.
            If 'preserve_folders' is also True, the folder structure will appear underneath the domain subfolder.
            If not provided or False, files from different domains will not be separated.
        :param incremental:
            When True, if the file already exists in the output folder it will only be overwritten if the iOS
            last modification time is after the local filesystem modification time. This may avoid unnecessary
            disk IO and computation to decrypt the files.
            Note that if files in the output folder are modified after extraction, it may prevent newer versions
            being extracted from the backup!
            If False or not provided, files are always written to disk, overwriting any existing files.
        :param filter_callback
            Optional. If provided, this function will be called before each matching file is decrypted, with
            all available metadata about the file from the Manifest.db.
            If it returns True, the file will be decrypted; if it returns False or None, the file will be skipped.
            If it returns a string, that string will be used as the output filename; this replaces the generated
            output filename value provided to the callback function. If this rename functionality is used, the
            returned value will be used as-is without any checks and is not constrained to be inside 'output_folder';
            consider using 'utils.safe_output_path(...)' to create a safe path to return here.
            Note that the filtering this callback enables is performed after filtering based on 'relative_paths_like'
            and 'domain_like', but before any filtering caused by 'incremental=True' and will not override that.
            This can be used to perform more complex file extraction than wildcard matching by relativePath and domain.
            The callback can also be used to deduce progress information, since the function is provided with
            data about the index of the current file and the total number of matched files.
            Excluding files in bulk using this filter will be slower than filtering using relativePath and
            domain, due to the filesystem checks performed to create the generated safe output filename.
            An example including the callback function signature (including '**kwargs' is strongly recommended for
            forwards-compatibility):

                def f(*, n, total_files, file_id, relative_path, domain, file_plist, output_filename, **kwargs):
                    return True

                backup.decrypt_files(..., filter_callback=f)

        :return: number of files extracted.
            If this number does not match the number of files created on disk, then some duplicate filenames may have
            been overwritten. If 'incremental' enabled and some files already existed in the output folder,
            the number returned will be the number of files modified or created, excluding those skipped because they
            had not changed since the last extraction.
        """
        # Ensure that we've initialised everything:
        if self._temp_manifest_db_conn is None:
            self._decrypt_manifest_db_file()
        # Check the provided arguments and replace missing ones with wildcards:
        if relative_paths_like is None and domain_like is None:
            # If someone _really_ wants to try and extract everything, then setting both to '%' should be enough.
            raise ValueError("At least one of 'relative_paths_like' or 'domain_like' must be specified!")
        elif relative_paths_like is None and domain_like is not None:
            relative_paths_like = "%"
        elif relative_paths_like is not None and domain_like is None:
            domain_like = "%"
        # If the filter function is not provided, default to including everything:
        _include_fn = filter_callback if callable(filter_callback) else (lambda **kwargs: True)
        # Get the total number of matching results:
        try:
            cur = self._temp_manifest_db_conn.cursor()
            count_query = """
                SELECT count(*)
                FROM Files
                WHERE relativePath LIKE ?
                AND domain LIKE ?
                AND flags=1;
            """
            cur.execute(count_query, (relative_paths_like, domain_like))
            total_files = cur.fetchone()[0]
            cur.close()
        except sqlite3.Error as e:
            raise RuntimeError("Error querying Manifest database!") from e
        # Get the full data from the Manifest file:
        rows = self._get_manifest_rows_generator(relative_paths_like=relative_paths_like, domain_like=domain_like, flags=1)
        n_files = 0
        for n, (file_id, domain, matched_relative_path, file_plist) in enumerate(rows):
            # Build the output file path:
            _output_path = []
            if domain_subfolders:
                _output_path.append(domain)
            if preserve_folders:
                _output_path.append(os.path.dirname(matched_relative_path))
            filename = os.path.basename(matched_relative_path)
            output_filepath = utils.safe_output_path(output_folder, *_output_path, filename)
            # Check filter function result for excluded or renamed files:
            filter_result = _include_fn(file_id=file_id, domain=domain, relative_path=matched_relative_path,
                                        file_plist=file_plist, output_filename=output_filepath,
                                        n=n, total_files=total_files)
            if filter_result is None or filter_result is False:
                continue
            elif isinstance(filter_result, str):
                output_filepath = filter_result
            elif filter_result is not True:
                print(f"WARN: Unexpected return type {type(filter_result)} from 'filter_callback'!")
            # Check if file already exists and we are doing an incremental extraction:
            if incremental and os.path.exists(output_filepath):
                existing_mtime = os.path.getmtime(output_filepath)
                if file_plist.mtime <= existing_mtime:
                    # Skip re-writing this file to disk since it has not changed.
                    continue
            # Decrypt the file to disk:
            inner_key = self._keybag.unwrap_key_for_class(file_plist.protection_class, file_plist.encryption_key)
            self._decrypt_file_to_disk(file_id=file_id, key=inner_key, file_plist=file_plist,
                                       output_filepath=output_filepath)
            n_files += 1
        # Return how many files were extracted:
        return n_files

    def get_folders(self, *, relative_paths_like=None, domain_like=None):
        """
        Create a generator returning data on folders contained in the backup.

        The 'extract_files' method can preserve the folder structure seen in the relativePath values in the backup,
        when 'preserve_folders' is True. However, empty folders are not included in the extraction and the creation
        and last modification time of the folders is not loaded; this method can be used to obtain that data.
        This method returns a generator which yields tuples of (file_id, domain, relative_path, file_plist)
        using the 'utils.FilePlist' class to store the 'file_plist' data.

        :param relative_paths_like:
            Optional. An iOS 'relativePath' of the folder(s) of interest, containing '%' or '_' SQL LIKE wildcards.
        :param domain_like:
            Optional. An iOS 'domain' for the folders of interest, containing '%' or '_' SQL LIKE wildcards.

        Example usage:

        for file_id, domain, relative_path, file_plist in backup.get_folders():
            print(domain, relative_path, file_plist.created, file_plist.mtime)
        """
        return self._get_manifest_rows_generator(relative_paths_like=relative_paths_like,
                                                 domain_like=domain_like, flags=2)

    def get_symlinks(self, *, relative_paths_like=None, domain_like=None):
        """
        Create a generator returning data on symlinks contained in the backup.

        The iOS filesystem can contain symbolic links from one path to another path, these are backed up only as
        records inside the Manifest.db file. This method returns a generator which yields tuples of
        (file_id, domain, relative_path, file_plist) using the 'utils.FilePlist' class to store the 'file_plist' data.
        Note that these symlinks are often to files which are not contained in the backup, and are relative to the
        iOS-internal filesystem.

        :param relative_paths_like:
            Optional. An iOS 'relativePath' of the symlink(s) of interest, containing '%' or '_' SQL LIKE wildcards.
        :param domain_like:
            Optional. An iOS 'domain' for the symlink(s) of interest, containing '%' or '_' SQL LIKE wildcards.

        Example usage:

        for file_id, domain, relative_path, file_plist in backup.get_symlinks():
            print(domain, relative_path, file_plist.target)
        """
        return self._get_manifest_rows_generator(relative_paths_like=relative_paths_like,
                                                 domain_like=domain_like, flags=4)

# iphone-backup-decrypt

Decrypt an encrypted, local (i.e. non-iCloud), iPhone backup created from iOS13.
This code is mainly a [wrapper for this StackOverflow answer](https://stackoverflow.com/a/13793043),
itself based on the [iphone-dataprotection](https://code.google.com/p/iphone-dataprotection/) code.

## Install

Requires [Python 3.4](https://www.python.org/) or higher.

The code requires a cryptographic library providing the `Crypto` name. 
Use `pycryptodome`, unless `pycrypto` is already installed (the latter is older and can be hard to install, anyway).

The backup decryption keys are protected using 10 million rounds of PBKDF2 with SHA256, then 10 thousand further iterations of PBKDF2 with SHA-1.
To speed up decryption, `fastpbkdf2` is desirable; otherwise the code will fall back to using standard library functions.
The fallback is much slower, but does not require the complicated build and install of `fastpbkdf2`.

Ideal dependencies:
```shell script
pip install biplist pycryptodome fastpbkdf2
```

Minimal required dependencies (as in `requirements.txt`):
```shell script
pip install biplist pycryptodome
```

Then clone this repository, or just download the two required Python files.

## Usage

This code decrypts the backup using the passphrase chosen when encrypted backups were enabled in iTunes.

The `relativePath` of the file(s) to be decrypted also needs to be known.
Very common files, like those for the call history or text message databases, can be found in the `RelativePath` class: e.g. use `RelativePath.CALL_HISTORY` instead of the full `Library/CallHistoryDB/CallHistory.storedata`.

If the relative path is not known, you can manually open the `Manifest.db` SQLite database and explore the `Files` table to find those of interest.
After creating the class, use the `EncryptedBackup.save_manifest_file(...)` method to store a decrypted version.

A minimal example to decrypt and extract the call history SQLite database might look like:
```python
from iphone_backup import EncryptedBackup, RelativePath

passphrase = "..."  # Or load passphrase more securely from stdin, or a file, etc.
backup_path = "%AppData%\\Apple Computer\\MobileSync\\Backup\\[device-specific-hash]"

backup = EncryptedBackup(backup_directory=backup_path, passphrase=passphrase)

backup.extract_file(relative_path=RelativePath.CALL_HISTORY, 
                    output_filename="./output/call_history.sqlite")
```
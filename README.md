# iphone-backup-decrypt

Decrypt an encrypted, local (i.e. non-iCloud), iPhone backup created from iOS13 or newer.
This code is mainly a [wrapper for this StackOverflow answer](https://stackoverflow.com/a/13793043),
itself based on the [iphone-dataprotection](https://code.google.com/p/iphone-dataprotection/) code.

## Install

Requires [Python 3.8](https://www.python.org/) or higher.

The backup decryption keys are protected using 10 million rounds of PBKDF2 with SHA256, then 10 thousand further iterations of PBKDF2 with SHA-1.
To speed up decryption, `fastpbkdf2` is desirable; otherwise the code will fall back to using `pycryptodome`'s implementation.
The fallback is ~50% slower at the initial backup decryption step, but does not require the complicated build and install of `fastpbkdf2`.

Install via `pip`:
```shell script
pip install iphone_backup_decrypt
# Optionally:
pip install fastpbkdf2
```

## Usage

This code decrypts the backup using the passphrase chosen when encrypted backups were enabled in iTunes.

The `relativePath` of the file(s) to be decrypted also needs to be known.
Very common files, like those for the call history or text message databases, can be found in the `RelativePath` class: e.g. use `RelativePath.CALL_HISTORY` instead of the full `Library/CallHistoryDB/CallHistory.storedata`.

More complex matching, particularly for non-unique filenames, may require specifying the `domain` of the files. The `DomainLike` and `MatchFiles` classes contain common domains and domain-path pairings. 

If the relative path is not known, you can manually open the `Manifest.db` SQLite database and explore the `Files` table to find those of interest.
After creating the class, use the `EncryptedBackup.save_manifest_file(...)` method to store a decrypted version.

A minimal example to decrypt and extract some files might look like:
```python
from iphone_backup_decrypt import EncryptedBackup, RelativePath, MatchFiles

passphrase = "..."  # Or load passphrase more securely from stdin, or a file, etc.
backup_path = "%AppData%\\Apple Computer\\MobileSync\\Backup\\[device-specific-hash]"

backup = EncryptedBackup(backup_directory=backup_path, passphrase=passphrase)

# Extract the call history SQLite database:
backup.extract_file(relative_path=RelativePath.CALL_HISTORY, 
                    output_filename="./output/call_history.sqlite")

# Extract the camera roll, using MatchFiles for combined path and domain matching:
backup.extract_files(**MatchFiles.CAMERA_ROLL, output_folder="./output/camera_roll")

# Extract WhatsApp SQLite database and attachments:
backup.extract_file(relative_path=RelativePath.WHATSAPP_MESSAGES,
                    output_filename="./output/whatsapp.sqlite")
backup.extract_files(**MatchFiles.WHATSAPP_ATTACHMENTS,
                     output_folder="./output/whatsapp", preserve_folders=False)

# Extract Strava workouts:
backup.extract_files(**MatchFiles.STRAVA_WORKOUTS, output_folder="./output")
```

## Alternatives

This library aims to be minimal, providing only what is necessary to extract encrypted files. There are alternatives which claim to offer similar or more advanced functionality:

 - [KnugiHK/iphone_backup_decrypt](https://github.com/KnugiHK/iphone_backup_decrypt/tree/master), a fork of this library and part of [Whatsapp-Chat-Exporter](https://github.com/KnugiHK/Whatsapp-Chat-Exporter).
 - [jfarley248/iTunes_Backup_Reader](https://github.com/jfarley248/iTunes_Backup_Reader), which uses an older version of this library.
 - [datatags/mount-ios-backup](https://github.com/datatags/mount-ios-backup), which uses an older version of this library.
 - [avibrazil/iOSbackup](https://github.com/avibrazil/iOSbackup) a similar Python library with a friendlier interface for exploring a backup.
 - [MaxiHuHe04/iTunes-Backup-Explorer](https://github.com/MaxiHuHe04/iTunes-Backup-Explorer), a Java based alternative with a GUI.

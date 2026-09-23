
class NotABackupFolderError(FileNotFoundError):
    """Exception raised when backup directory does not contain expected files."""

class BackupNotEncryptedError(ValueError):
    """Exception raised when a backup is not marked as being encrypted."""

class IncorrectPassphraseError(ValueError):
    """Exception raised when backup passphrase appears to be incorrect."""

class UnsafeBackupError(ValueError):
    """Exception raised when a backup appears malicious."""

class BackupKeyBagNotUnlockedError(ValueError):
    """Exception raised if trying to use a locked BackupKeyBag."""

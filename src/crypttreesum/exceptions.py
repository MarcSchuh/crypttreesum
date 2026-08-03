"""Package exceptions."""


class CryptTreeSumError(Exception):
    """Base error for crypttreesum."""


class ScanError(CryptTreeSumError):
    """Raised when a tree scan fails."""


class ManifestError(CryptTreeSumError):
    """Raised when a manifest cannot be read or written."""

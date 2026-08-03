"""crypttreesum - inventory and verify gocryptfs encrypted/decrypted trees."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("crypttreesum")
except PackageNotFoundError:  # pragma: no cover - raw checkout without install
    __version__ = "0.0.0.dev0"

__all__ = ["__version__"]

"""Manage SSL decryption bypasses on Palo Alto Networks firewalls through Strata Cloud Manager."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("panos-decrypt-bypass")
except PackageNotFoundError:  # running from a source checkout without installing
    __version__ = "0.0.0+unknown"

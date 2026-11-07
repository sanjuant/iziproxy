"""
IziProxy - gestion simplifiée des proxys d'entreprise pour Python.
"""

try:
    from importlib.metadata import PackageNotFoundError, version

    try:
        __version__ = version("iziproxy")
    except PackageNotFoundError:  # exécution depuis les sources
        __version__ = "0.0.0+unknown"
except ImportError:  # pragma: no cover
    __version__ = "0.0.0+unknown"

from .bootstrap import Installation, current, install, uninstall
from .local_proxy import LocalProxy
from .ntlm_auth import NtlmAuthenticationError, is_ntlm_auth_available
from .proxy_manager import IziProxy
from .secure_config import SecurePassword, SecureProxyConfig

__all__ = [
    "install",
    "uninstall",
    "current",
    "Installation",
    "IziProxy",
    "LocalProxy",
    "SecurePassword",
    "SecureProxyConfig",
    "NtlmAuthenticationError",
    "is_ntlm_auth_available",
    "__version__",
]

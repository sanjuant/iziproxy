"""
IziProxy - Une bibliothèque Python pour la gestion simplifiée des proxys d'entreprise
"""

try:
    from importlib.metadata import version, PackageNotFoundError
    try:
        __version__ = version("iziproxy")
    except PackageNotFoundError:
        __version__ = "0.3.0"  # Version par défaut en développement
except ImportError:
    # Python < 3.8
    try:
        from importlib_metadata import version, PackageNotFoundError
        try:
            __version__ = version("iziproxy")
        except PackageNotFoundError:
            __version__ = "0.3.0"  # Version par défaut en développement
    except ImportError:
        __version__ = "0.3.0"  # Fallback si importlib_metadata n'est pas disponible

from .proxy_manager import IziProxy
from .secure_config import SecurePassword, SecureProxyConfig

__all__ = ["IziProxy", "SecurePassword", "SecureProxyConfig"]
"""
Protection des mots de passe en mémoire et dans les affichages.
"""

import re
from urllib.parse import quote, unquote

from cryptography.fernet import Fernet

MASK = "***********"
_URL_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://(.*)$", re.DOTALL)


class SecurePassword:
    """
    Mot de passe chiffré en mémoire et masqué dans str()/repr().

    Le chiffrement évite que le mot de passe apparaisse en clair dans un
    vidage mémoire ou un journal ; get_password() le restitue.
    """

    __slots__ = ("_SecurePassword__key", "_SecurePassword__token")

    def __init__(self, password):
        """
        Args:
            password (str|SecurePassword): Mot de passe en clair
        """
        if isinstance(password, SecurePassword):
            self.__key = password._SecurePassword__key
            self.__token = password._SecurePassword__token
        else:
            self.__key = Fernet.generate_key()
            self.__token = Fernet(self.__key).encrypt(str(password).encode("utf-8"))

    def __str__(self):
        return MASK

    def __repr__(self):
        return f"SecurePassword('{MASK}')"

    def __eq__(self, other):
        if isinstance(other, SecurePassword):
            return self.get_password() == other.get_password()
        return NotImplemented

    def __hash__(self):
        return hash(self.get_password())

    def __bool__(self):
        return bool(self.get_password())

    def get_password(self):
        """
        Returns:
            str: Le mot de passe en clair
        """
        return Fernet(self.__key).decrypt(self.__token).decode("utf-8")


def _split_auth(url):
    """
    Sépare une URL en (schéma, utilisateur, mot_de_passe, reste).

    Le dernier « @ » de l'autorité sépare les identifiants de l'hôte, ce qui
    tolère un « @ » non encodé dans le mot de passe.

    Returns:
        tuple: (scheme, username, password, rest) ; username None sans identifiants
    """
    match = _URL_RE.match(url or "")
    if not match:
        return None, None, None, url
    scheme, remainder = match.groups()
    at = remainder.rfind("@")
    if at == -1:
        return scheme, None, None, remainder
    auth, rest = remainder[:at], remainder[at + 1:]
    username, sep, password = auth.partition(":")
    return scheme, username, (unquote(password) if sep else None), rest


class SecureProxyConfig(dict):
    """
    Dictionnaire de proxys dont les mots de passe sont masqués.

    Les valeurs exposées contiennent « *********** » à la place du mot de
    passe ; get_real_config() restitue les URLs utilisables par requests.
    """

    def __init__(self, proxy_dict=None):
        """
        Args:
            proxy_dict (dict): Ex. {'http': 'http://user:pass@proxy:8080'}
        """
        super().__init__()
        self._secure_passwords = {}
        for key, url in (proxy_dict or {}).items():
            masked, secret = self._secure_url(url)
            self[key] = masked
            if secret is not None:
                self._secure_passwords[key] = secret

    def __str__(self):
        return str(dict(self))

    def __repr__(self):
        return f"SecureProxyConfig({dict(self)})"

    @staticmethod
    def _secure_url(url):
        """
        Returns:
            tuple: (URL masquée, SecurePassword|None)
        """
        if not isinstance(url, str):
            return url, None
        scheme, username, password, rest = _split_auth(url)
        if username is None or not password:
            return url, None
        return f"{scheme}://{username}:{MASK}@{rest}", SecurePassword(password)

    @staticmethod
    def _mask_url_password(url):
        """Masque le mot de passe d'une URL."""
        if not isinstance(url, str):
            return url
        scheme, username, password, rest = _split_auth(url)
        if username is None or not password:
            return url
        return f"{scheme}://{username}:{MASK}@{rest}"

    @staticmethod
    def _mask_passwords(obj):
        """Masque les mots de passe d'un dict ou d'une chaîne."""
        if isinstance(obj, dict):
            return {k: SecureProxyConfig._mask_url_password(v) for k, v in obj.items()}
        return SecureProxyConfig._mask_url_password(obj)

    def get_real_config(self):
        """
        Returns:
            dict: Proxys avec les mots de passe réels (encodés pour l'URL)
        """
        real = {}
        for key, url in self.items():
            secret = self._secure_passwords.get(key)
            if secret is None:
                real[key] = url
                continue
            scheme, username, _, rest = _split_auth(url)
            real[key] = f"{scheme}://{username}:{quote(secret.get_password(), safe='')}@{rest}"
        return real

    def get_credentials(self, proxy_type="http"):
        """
        Returns:
            tuple: (username décodé, SecurePassword) ou (None, None)
        """
        url = self.get(proxy_type)
        if not isinstance(url, str):
            return None, None
        _, username, _, _ = _split_auth(url)
        if username is None:
            return None, None
        return unquote(username), self._secure_passwords.get(proxy_type)

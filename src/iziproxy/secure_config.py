"""
Module de gestion sécurisée des mots de passe et des configurations de proxy
"""

import re
from urllib.parse import unquote, quote

from cryptography.fernet import Fernet


class SecurePassword:
    """
    Classe qui encapsule un mot de passe avec chiffrement en mémoire pour éviter
    l'exposition en clair dans la mémoire ou les logs.
    
    Cette classe permet de manipuler des mots de passe de manière sécurisée en:
    - Chiffrant le mot de passe en mémoire
    - Masquant le mot de passe dans les représentations string/repr
    - Permettant un accès contrôlé au mot de passe en clair
    """

    def __init__(self, password):
        """
        Initialise un mot de passe sécurisé en le chiffrant en mémoire
        
        Args:
            password (str): Le mot de passe en clair à sécuriser
        """
        self._SecurePassword__encrypted_password = None
        self._SecurePassword__cipher = None
        self._SecurePassword__key = None
        if isinstance(password, SecurePassword):
            # Si on passe déjà un SecurePassword, on récupère ses attributs
            self.__key = password._SecurePassword__key
            self.__cipher = password._SecurePassword__cipher
            self.__encrypted_password = password._SecurePassword__encrypted_password
        else:
            # Sinon, on chiffre le nouveau mot de passe
            self.__key = Fernet.generate_key()
            self.__cipher = Fernet(self.__key)
            self.__encrypted_password = self.__cipher.encrypt(str(password).encode())

    def __str__(self):
        """Retourne une version masquée du mot de passe."""
        return "***********"

    def __repr__(self):
        """Retourne une version masquée du mot de passe pour le débogage."""
        return f"SecurePassword('***********')"

    def get_password(self):
        """
        Retourne le mot de passe non masqué.
        
        Returns:
            str: Le mot de passe en clair
        """
        return self.__cipher.decrypt(self.__encrypted_password).decode()


class SecureProxyConfig(dict):
    """
    Classe de configuration de proxy sécurisée qui utilise SecurePassword
    pour masquer les mots de passe dans les URLs de proxy.
    
    Cette classe permet de:
    - Stocker des configurations de proxy avec authentification
    - Masquer les mots de passe dans les représentations et logs
    - Récupérer les configurations réelles pour les requêtes HTTP
    """

    def __init__(self, proxy_dict=None):
        """
        Initialise une configuration de proxy sécurisée
        
        Args:
            proxy_dict (dict, optional): Dictionnaire de configuration de proxy
                                        (ex: {'http': 'http://user:pass@proxy:8080'})
        """
        super().__init__()
        self._secure_passwords = {}  # Pour stocker les mots de passe sécurisés

        if proxy_dict:
            # Remplace les mots de passe dans les URLs par des objets SecurePassword
            for key, url in proxy_dict.items():
                secured_url, secure_password = self._secure_url(url)
                self[key] = secured_url
                if secure_password:
                    # Stocker les mots de passe sécurisés séparément
                    self._secure_passwords[(key, url)] = secure_password

    def __str__(self):
        """Masque les mots de passe dans la représentation string."""
        return self._mask_passwords(super().__str__())

    def __repr__(self):
        """Masque les mots de passe dans la représentation repr."""
        return f"SecureProxyConfig({self._mask_passwords(dict(self))})"

    def _parse_url_with_auth(self, url):
        """
        Parse une URL en gérant correctement les caractères spéciaux dans le mot de passe,
        y compris lorsque le mot de passe contient '@' ou ':'.

        Cette méthode ne se fie pas à urlparse qui s'arrête au premier '@',
        mais utilise une approche plus robuste.

        Args:
            url (str): URL à analyser

        Returns:
            tuple: (scheme, username, password, host_with_path)
        """
        if not url or '@' not in url:
            return None, None, None, url

        # Récupérer le schéma (http, https, etc.)
        match = re.match(r'^([a-z]+)://(.*)', url)
        if not match:
            return None, None, None, url

        scheme = match.group(1)
        remainder = match.group(2)

        # Trouver le dernier '@' qui sépare les identifiants du reste de l'URL
        last_at_index = remainder.rindex('@')
        auth_part = remainder[:last_at_index]
        host_with_path = remainder[last_at_index + 1:]

        # Trouver le premier ':' qui sépare le username du password
        first_colon_index = auth_part.find(':')

        if first_colon_index == -1:
            # Pas de mot de passe, juste un nom d'utilisateur
            return scheme, auth_part, None, host_with_path

        # Extraire le nom d'utilisateur et le mot de passe
        username = auth_part[:first_colon_index]
        password = auth_part[first_colon_index + 1:]

        # Décoder le mot de passe encodé s'il y en a un
        try:
            password = unquote(password)
        except Exception:
            # Si le décodage échoue, garder le mot de passe tel quel
            pass

        return scheme, username, password, host_with_path

    def _secure_url(self, url):
        """
        Convertit les mots de passe dans les URLs en objets SecurePassword.
        Gère correctement les mots de passe contenant des caractères spéciaux comme '@' ou ':'.

        Args:
            url (str): URL de proxy, potentiellement avec authentification

        Returns:
            tuple: (URL avec mot de passe masqué, objet SecurePassword ou None)
        """
        if not url or not isinstance(url, str):
            return url, None

        # Utiliser notre parser personnalisé au lieu de urlparse
        scheme, username, password, host_with_path = self._parse_url_with_auth(url)

        if not username or not password:
            return url, None

        # Créer un objet SecurePassword pour le mot de passe
        secure_password = SecurePassword(password)

        # Reconstruire l'URL avec le mot de passe masqué
        masked_url = f"{scheme}://{username}:***********@{host_with_path}"

        return masked_url, secure_password

    @staticmethod
    def _mask_passwords(obj):
        """
        Masque les mots de passe dans les objets pour l'affichage

        Args:
            obj: Objet à masquer (dict ou str)

        Returns:
            Objet avec mots de passe masqués
        """
        if isinstance(obj, dict):
            return {k: SecureProxyConfig._mask_url_password(v) if isinstance(v, str) else v
                    for k, v in obj.items()}
        elif isinstance(obj, str):
            return SecureProxyConfig._mask_url_password(obj)
        return obj

    @staticmethod
    def _mask_url_password(url):
        """
        Masque les mots de passe dans les URLs pour l'affichage.
        Gère correctement les cas où le mot de passe contient des caractères spéciaux.

        Args:
            url (str): URL à masquer

        Returns:
            str: URL avec mot de passe masqué
        """
        if not url or not isinstance(url, str) or '@' not in url:
            return url

        # Trouver le schéma (http://, https://, etc.)
        match = re.match(r'^([a-z]+)://(.*)', url)
        if not match:
            return url

        scheme = match.group(1)
        remainder = match.group(2)

        # Trouver le dernier '@' qui sépare les identifiants du reste de l'URL
        try:
            last_at_index = remainder.rindex('@')
        except ValueError:
            return url

        auth_part = remainder[:last_at_index]
        host_with_path = remainder[last_at_index + 1:]

        # Trouver le premier ':' qui sépare le username du password
        first_colon_index = auth_part.find(':')

        if first_colon_index == -1:
            return url

        # Masquer le mot de passe
        username = auth_part[:first_colon_index]
        masked_url = f"{scheme}://{username}:***********@{host_with_path}"

        return masked_url

    def get_real_config(self):
        """
        Retourne la configuration réelle (non masquée) à utiliser dans les requêtes

        Returns:
            dict: Configuration de proxy avec mots de passe en clair et encodés
        """
        real_config = {}

        for key, url in self.items():
            try:
                if not url:
                    real_config[key] = url
                    continue

                # Utiliser notre parser personnalisé au lieu de urlparse
                scheme, username, _, host_with_path = self._parse_url_with_auth(url)

                if not username:
                    # Pas d'authentification dans l'URL
                    real_config[key] = url
                    continue

                # Chercher s'il existe un mot de passe sécurisé pour cette clé
                secure_password = None
                for (stored_key, _), stored_password in self._secure_passwords.items():
                    if key == stored_key:
                        secure_password = stored_password
                        break

                if secure_password:
                    # Récupérer le mot de passe en clair
                    password = secure_password.get_password()
                    # Encoder les caractères spéciaux du mot de passe pour l'URL
                    encoded_password = quote(password, safe='')
                    # Reconstruire l'URL avec le mot de passe encodé
                    real_config[key] = f"{scheme}://{username}:{encoded_password}@{host_with_path}"
                else:
                    # Pas de mot de passe sécurisé trouvé, utiliser l'URL telle quelle
                    real_config[key] = url
            except Exception as e:
                # En cas d'erreur, utiliser l'URL telle quelle
                real_config[key] = url

        return real_config

    def get_credentials(self, proxy_type='http'):
        """
        Récupère les identifiants (username, SecurePassword) pour un type de proxy

        Args:
            proxy_type (str): Type de proxy ('http', 'https', etc.)

        Returns:
            tuple: (username, SecurePassword) ou (None, None) si pas d'authentification
        """
        url = self.get(proxy_type)
        if not url:
            return None, None

        # Utiliser notre parser personnalisé
        _, username, _, _ = self._parse_url_with_auth(url)

        if not username:
            return None, None

        # Chercher s'il existe un mot de passe sécurisé pour ce type de proxy
        secure_password = None
        for (stored_key, _), stored_password in self._secure_passwords.items():
            if proxy_type == stored_key:
                secure_password = stored_password
                break

        return username, secure_password
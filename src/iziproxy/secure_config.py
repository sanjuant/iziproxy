"""
Module de gestion sécurisée des mots de passe et des configurations de proxy
"""

import re
from urllib.parse import urlparse, urlunparse

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
        if proxy_dict:
            # Remplace les mots de passe dans les URLs par des objets SecurePassword
            for key, url in proxy_dict.items():
                self[key] = self._secure_url(url)

    def __str__(self):
        """Masque les mots de passe dans la représentation string."""
        return self._mask_passwords(super().__str__())

    def __repr__(self):
        """Masque les mots de passe dans la représentation repr."""
        return f"SecureProxyConfig({self._mask_passwords(dict(self))})"

    def _secure_url(self, url):
        """
        Convertit les mots de passe dans les URLs en objets SecurePassword
        
        Args:
            url (str): URL de proxy, potentiellement avec authentification
            
        Returns:
            str: URL avec le mot de passe remplacé par un objet SecurePassword
        """
        if not url or not isinstance(url, str) or '@' not in url:
            return url

        parsed = urlparse(url)
        if '@' not in parsed.netloc:
            return url
            
        auth_part, server_part = parsed.netloc.split('@', 1)

        if ':' in auth_part:
            username, password = auth_part.split(':', 1)
            secure_password = SecurePassword(password)
            # Reconstruire l'URL avec le mot de passe sécurisé
            secure_netloc = f"{username}:{secure_password}@{server_part}"
            secure_parts = parsed._replace(netloc=secure_netloc)
            return urlunparse(secure_parts)

        return url

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
        Masque les mots de passe dans les URLs pour l'affichage
        
        Args:
            url (str): URL à masquer
            
        Returns:
            str: URL avec mot de passe masqué
        """
        if not url or not isinstance(url, str):
            return url

        if '@' not in url:
            return url

        return re.sub(r'(https?://[^:]+:)([^@]+)(@[^/]+)', r'\1***********\3', url)

    def get_real_config(self):
        """
        Retourne la configuration réelle (non masquée) à utiliser dans les requêtes
        
        Returns:
            dict: Configuration de proxy avec mots de passe en clair
        """
        real_config = {}
        for key, url in self.items():
            if not url or '@' not in url:
                real_config[key] = url
                continue

            parsed = urlparse(url)
            if '@' not in parsed.netloc:
                real_config[key] = url
                continue
                
            auth_part, server_part = parsed.netloc.split('@', 1)

            if ':' in auth_part:
                username, password_obj = auth_part.split(':', 1)
                
                # Si le mot de passe est un SecurePassword, récupérer sa valeur réelle
                if isinstance(password_obj, SecurePassword):
                    password = password_obj.get_password()
                    netloc = f"{username}:{password}@{server_part}"
                    real_url = urlunparse(parsed._replace(netloc=netloc))
                    real_config[key] = real_url
                else:
                    real_config[key] = url
            else:
                real_config[key] = url

        return real_config

    def get_credentials(self, proxy_type='http'):
        """
        Récupère les identifiants (username, password) pour un type de proxy
        
        Args:
            proxy_type (str): Type de proxy ('http', 'https', etc.)
            
        Returns:
            tuple: (username, password) ou (None, None) si pas d'authentification
        """
        url = self.get(proxy_type)
        if not url or '@' not in url:
            return None, None

        parsed = urlparse(url)
        if '@' not in parsed.netloc:
            return None, None
            
        auth_part, _ = parsed.netloc.split('@', 1)

        if ':' in auth_part:
            username, password_obj = auth_part.split(':', 1)
            
            if isinstance(password_obj, SecurePassword):
                password = password_obj.get_password()
            else:
                password = password_obj
                
            return username, password

        return auth_part, None
